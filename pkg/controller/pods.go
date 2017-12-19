// Copyright 2016 Cisco Systems, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Handlers for pod updates.  Pods map to opflex endpoints

package controller

import (
	"encoding/json"
	"net/http"
	"reflect"

	"github.com/Sirupsen/logrus"

	appsv1beta2 "k8s.io/api/apps/v1beta2"
	v1 "k8s.io/api/core/v1"
	v1net "k8s.io/api/networking/v1"
	kubeerr "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"github.com/noironetworks/aci-containers/pkg/apicapi"
	"github.com/noironetworks/aci-containers/pkg/metadata"
)

func (cont *AciController) initPodInformerFromClient(
	kubeClient kubernetes.Interface) {

	cont.initPodInformerBase(
		cache.NewListWatchFromClient(
			kubeClient.CoreV1().RESTClient(), "pods",
			metav1.NamespaceAll, fields.Everything()))
}

func (cont *AciController) initPodInformerBase(listWatch *cache.ListWatch) {
	cont.podIndexer, cont.podInformer = cache.NewIndexerInformer(
		listWatch, &v1.Pod{}, 0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				cont.podAdded(obj)
			},
			UpdateFunc: func(oldobj interface{}, newobj interface{}) {
				cont.podUpdated(oldobj, newobj)
			},
			DeleteFunc: func(obj interface{}) {
				cont.podDeleted(obj)
			},
		},
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
}

func podLogger(log *logrus.Logger, pod *v1.Pod) *logrus.Entry {
	return log.WithFields(logrus.Fields{
		"namespace": pod.ObjectMeta.Namespace,
		"name":      pod.ObjectMeta.Name,
		"node":      pod.Spec.NodeName,
	})
}

func podFilter(pod *v1.Pod) bool {
	if pod.Spec.HostNetwork {
		return false
	}
	return true
}

func (cont *AciController) queuePodUpdate(pod *v1.Pod) {
	podkey, err := cache.MetaNamespaceKeyFunc(pod)
	if err != nil {
		podLogger(cont.log, pod).Error("Could not create pod key: ", err)
		return
	}
	cont.podQueue.Add(podkey)
}

func addGroup(gset map[metadata.OpflexGroup]bool, g []metadata.OpflexGroup,
	tenant string, name string) []metadata.OpflexGroup {
	newg := metadata.OpflexGroup{
		PolicySpace: tenant,
		Name:        name,
	}
	if _, ok := gset[newg]; !ok {
		gset[newg] = true
		g = append(g, newg)
	}
	return g
}

func (cont *AciController) mergeNetPolSg(podkey string, pod *v1.Pod,
	namespace *v1.Namespace, sgval *string) (*string, error) {

	gset := make(map[metadata.OpflexGroup]bool)
	var g []metadata.OpflexGroup
	ptypeset := make(map[v1net.PolicyType]bool)

	// Add network policies that directly select this pod
	for _, npkey := range cont.netPolPods.GetObjForPod(podkey) {
		g = addGroup(gset, g, cont.config.AciPolicyTenant,
			cont.aciNameForKey("np", npkey))
		for _, t := range cont.getNetPolPolicyTypes(npkey) {
			ptypeset[t] = true
		}
	}

	// When the pod is not selected by any network policy, don't apply
	// any extra security groups and return the existing value from
	// the user annotation
	if len(gset) == 0 {
		return sgval, nil
	}

	// Add security groups from the user annotation
	if sgval != nil && *sgval != "" {
		userGroups := make([]metadata.OpflexGroup, 0)
		err := json.Unmarshal([]byte(*sgval), &userGroups)
		if err != nil {
			cont.log.WithFields(logrus.Fields{
				"SgAnnotation": sgval,
			}).Error("Could not decode annotation: ", err)
		}
		for _, og := range userGroups {
			gset[og] = true
			g = append(g, og)
		}
	}

	// Add network policy for accessing the pod's local node
	if pod.Spec.NodeName != "" {
		g = addGroup(gset, g, cont.config.AciPolicyTenant,
			cont.aciNameForKey("node", pod.Spec.NodeName))
	}

	// Add static-discovery network policy to allow ICMP/ARP
	g = addGroup(gset, g, cont.config.AciPolicyTenant,
		cont.aciNameForKey("np", "static-discovery"))

	if !ptypeset[v1net.PolicyTypeIngress] {
		// Add static-ingress since no policy applies to ingress
		g = addGroup(gset, g, cont.config.AciPolicyTenant,
			cont.aciNameForKey("np", "static-ingress"))
	}
	if !ptypeset[v1net.PolicyTypeEgress] {
		// Add static-egress since no policy applies to egress
		g = addGroup(gset, g, cont.config.AciPolicyTenant,
			cont.aciNameForKey("np", "static-egress"))
	}

	if len(g) == 0 {
		return sgval, nil
	}
	raw, err := json.Marshal(g)
	if err != nil {
		return sgval, err
	}
	result := string(raw)
	return &result, nil
}

func (cont *AciController) serializeGroup(g interface{}) string {
	edata, err := json.Marshal(g)
	if err != nil {
		cont.log.Error("Could not serialize group: ", err)
		return ""
	}
	return string(edata)
}

func (cont *AciController) handlePodUpdate(pod *v1.Pod) bool {
	if !podFilter(pod) {
		return false
	}
	logger := podLogger(cont.log, pod)

	podkey, err := cache.MetaNamespaceKeyFunc(pod)
	if err != nil {
		logger.Error("Could not create pod key: ", err)
		return false
	}

	cont.indexMutex.Lock()
	defer cont.indexMutex.Unlock()

	if pod.Spec.NodeName != "" {
		// note here we're assuming pods do not change nodes
		cont.addPodToNode(pod.Spec.NodeName, podkey)
	}

	// top-level default annotation
	egval := &cont.defaultEg
	sgval := &cont.defaultSg

	// configured namespace override has next-highest priority
	if nseg, ok := cont.config.NamespaceDefaultEg[pod.Namespace]; ok {
		egdata := cont.serializeGroup(nseg)
		if egdata != "" {
			egval = &egdata
		}
	}
	if nssgs, ok := cont.config.NamespaceDefaultSg[pod.Namespace]; ok {
		sgdata := cont.serializeGroup(nssgs)
		if sgdata != "" {
			sgval = &sgdata
		}
	}

	// namespace annotation has next-highest priority
	namespaceobj, exists, err :=
		cont.namespaceIndexer.GetByKey(pod.ObjectMeta.Namespace)
	var namespace *v1.Namespace
	if err != nil {
		cont.log.Error("Could not lookup namespace " +
			pod.ObjectMeta.Namespace + ": " + err.Error())
		return false
	}

	if exists && namespaceobj != nil {
		namespace = namespaceobj.(*v1.Namespace)

		if og, ok := namespace.ObjectMeta.Annotations[metadata.EgAnnotation]; ok && og != "" {
			egval = &og
		}
		if og, ok := namespace.ObjectMeta.Annotations[metadata.SgAnnotation]; ok && og != "" {
			sgval = &og
		}
	}

	// annotation on associated deployment is next-highest priority
	for _, depkey := range cont.depPods.GetObjForPod(podkey) {
		deploymentobj, exists, err :=
			cont.deploymentIndexer.GetByKey(depkey)
		if err != nil {
			cont.log.Error("Could not lookup deployment " +
				depkey + ": " + err.Error())
			continue
		}
		if exists && deploymentobj != nil {
			deployment := deploymentobj.(*appsv1beta2.Deployment)

			if og, ok := deployment.ObjectMeta.Annotations[metadata.EgAnnotation]; ok && og != "" {
				egval = &og
			}
			if og, ok := deployment.ObjectMeta.Annotations[metadata.SgAnnotation]; ok && og != "" {
				sgval = &og
			}

			// multiple deployments matching the same pod is a broken
			// configuration.  We'll just use the first one.
			break
		}
	}

	// direct pod annotation is highest priority
	if og, ok := pod.ObjectMeta.Annotations[metadata.EgAnnotation]; ok && og != "" {
		egval = &og
	}
	if og, ok := pod.ObjectMeta.Annotations[metadata.SgAnnotation]; ok && og != "" {
		sgval = &og
	}

	sgval, err = cont.mergeNetPolSg(podkey, pod, namespace, sgval)
	if err != nil {
		logger.Error("Could not generate network policy ",
			"security groups:", err)
	}

	podUpdated := false
	if pod.ObjectMeta.Annotations == nil {
		pod.ObjectMeta.Annotations = make(map[string]string)
	}
	oldegval, ok := pod.ObjectMeta.Annotations[metadata.CompEgAnnotation]
	if egval != nil && *egval != "" {
		if !ok || oldegval != *egval {
			pod.ObjectMeta.Annotations[metadata.CompEgAnnotation] = *egval
			podUpdated = true
		}
	} else {
		if ok || oldegval == "" {
			delete(pod.ObjectMeta.Annotations, metadata.CompEgAnnotation)
			podUpdated = true
		}
	}
	oldsgval, ok := pod.ObjectMeta.Annotations[metadata.CompSgAnnotation]
	if sgval != nil && *sgval != "" {
		if !ok || oldsgval != *sgval {
			pod.ObjectMeta.Annotations[metadata.CompSgAnnotation] = *sgval
			podUpdated = true
		}
	} else {
		if ok || oldsgval == "" {
			delete(pod.ObjectMeta.Annotations, metadata.CompSgAnnotation)
			podUpdated = true
		}
	}

	if podUpdated {
		_, err := cont.updatePod(pod)
		if err != nil {
			if serr, ok := err.(*kubeerr.StatusError); ok {
				if serr.ErrStatus.Code == http.StatusConflict {
					logger.Debug("Conflict updating pod; will retry")
					return true
				}
			}
			logger.Error("Failed to update pod: ", err)
			return true
		} else {
			logger.WithFields(logrus.Fields{
				"Eg": pod.ObjectMeta.Annotations[metadata.CompEgAnnotation],
				"Sg": pod.ObjectMeta.Annotations[metadata.CompSgAnnotation],
			}).Info("Updated pod annotations")
		}
	}
	return false
}

func (cont *AciController) writeApicPod(pod *v1.Pod) {
	podkey, err := cache.MetaNamespaceKeyFunc(pod)
	if err != nil {
		podLogger(cont.log, pod).Error("Could not create pod key: ", err)
		return
	}
	key := cont.aciNameForKey("pod", podkey)
	if !podFilter(pod) || pod.Spec.NodeName == "" {
		cont.apicConn.ClearApicObjects(key)
		return
	}

	aobj := apicapi.NewVmmInjectedContGrp(cont.vmmDomainProvider(),
		cont.config.AciVmmDomain, cont.config.AciVmmController,
		pod.Namespace, pod.Name)
	aobj.SetAttr("guid", string(pod.UID))
	aobj.SetAttr("hostName", pod.Spec.NodeName)
	aobj.SetAttr("computeNodeName", pod.Spec.NodeName)
	for _, or := range pod.OwnerReferences {
		if or.Kind == "ReplicaSet" && or.Name != "" {
			aobj.SetAttr("replicaSetName", or.Name)
			break
		}
	}
	cont.apicConn.WriteApicObjects(key, apicapi.ApicSlice{aobj})
}

func (cont *AciController) podAdded(obj interface{}) {
	pod := obj.(*v1.Pod)
	cont.writeApicPod(pod)
	cont.depPods.UpdatePodNoCallback(pod)
	cont.netPolPods.UpdatePodNoCallback(pod)
	cont.netPolIngressPods.UpdatePodNoCallback(pod)
	cont.netPolEgressPods.UpdatePodNoCallback(pod)
	cont.queuePodUpdate(pod)
}

func (cont *AciController) podUpdated(oldobj interface{}, newobj interface{}) {
	oldpod := oldobj.(*v1.Pod)
	newpod := newobj.(*v1.Pod)

	cont.writeApicPod(newpod)

	shouldqueue := false
	if oldpod.Status.PodIP != newpod.Status.PodIP ||
		!reflect.DeepEqual(oldpod.ObjectMeta.Labels, newpod.ObjectMeta.Labels) {
		shouldqueue =
			cont.depPods.UpdatePodNoCallback(newpod) || shouldqueue
		shouldqueue =
			cont.netPolPods.UpdatePodNoCallback(newpod) || shouldqueue
		shouldqueue =
			cont.netPolIngressPods.UpdatePodNoCallback(newpod) || shouldqueue
		shouldqueue =
			cont.netPolEgressPods.UpdatePodNoCallback(newpod) || shouldqueue
	}
	if !reflect.DeepEqual(oldpod.ObjectMeta.Annotations,
		newpod.ObjectMeta.Annotations) {
		shouldqueue = true
	} else if oldpod.Spec.NodeName != newpod.Spec.NodeName {
		shouldqueue = true
	}

	if shouldqueue {
		cont.queuePodUpdate(newpod)
	}
}

func (cont *AciController) podDeleted(obj interface{}) {
	pod := obj.(*v1.Pod)
	logger := podLogger(cont.log, pod)
	podkey, err := cache.MetaNamespaceKeyFunc(pod)
	if err != nil {
		logger.Error("Could not create pod key:" + err.Error())
		return
	}

	cont.apicConn.ClearApicObjects(cont.aciNameForKey("pod", podkey))

	cont.depPods.DeletePod(pod)
	cont.netPolPods.DeletePod(pod)
	cont.netPolIngressPods.DeletePod(pod)
	cont.netPolEgressPods.DeletePod(pod)

	cont.indexMutex.Lock()
	cont.removePodFromNode(pod.Spec.NodeName, podkey)
	cont.indexMutex.Unlock()

	logger.Debug("Pod deleted")
}
