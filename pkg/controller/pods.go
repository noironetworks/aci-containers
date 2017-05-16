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

	kubeerr "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	v1 "k8s.io/client-go/pkg/api/v1"
	v1beta1 "k8s.io/client-go/pkg/apis/extensions/v1beta1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/kubernetes/pkg/controller"

	"github.com/noironetworks/aci-containers/pkg/metadata"
)

func (cont *AciController) initPodInformerFromClient(
	kubeClient kubernetes.Interface) {

	cont.initPodInformerBase(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				return kubeClient.CoreV1().Pods(metav1.NamespaceAll).List(options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				return kubeClient.CoreV1().Pods(metav1.NamespaceAll).Watch(options)
			},
		})
}

func (cont *AciController) initPodInformerBase(listWatch *cache.ListWatch) {
	cont.podInformer = cache.NewSharedIndexInformer(
		listWatch,
		&v1.Pod{},
		controller.NoResyncPeriodFunc(),
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	cont.podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			cont.podAdded(obj)
		},
		UpdateFunc: func(oldobj interface{}, newobj interface{}) {
			cont.podUpdated(oldobj, newobj)
		},
		DeleteFunc: func(obj interface{}) {
			cont.podDeleted(obj)
		},
	})

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

func (cont *AciController) getNetPolIsolation(namespace *v1.Namespace) string {
	if p, ok := namespace.Annotations[metadata.NetworkPolicyAnnotation]; ok {
		np := &metadata.NetworkPolicy{}
		err := json.Unmarshal([]byte(p), &np)
		if err != nil {
			cont.log.WithFields(logrus.Fields{
				"Namespace":        namespace.Name,
				"NetPolAnnotation": p,
			}).Error("Could not decode annotation: ", err)
			return ""
		}

		if np.Ingress != nil {
			return np.Ingress.Isolation
		}
	}
	return ""
}

func (cont *AciController) mergeNetPolSg(podkey string, pod *v1.Pod,
	namespace *v1.Namespace, sgval *string) (*string, error) {

	// If the namespace is not isolated, network policy has no effect
	// so we set the pods in no security group to allow all traffic.
	// This can still be set by the user with specific security group
	// annotations however
	if namespace == nil || cont.getNetPolIsolation(namespace) != "DefaultDeny" {
		return sgval, nil
	}

	g := make([]metadata.OpflexGroup, 0)
	if sgval != nil && *sgval != "" {
		err := json.Unmarshal([]byte(*sgval), &g)
		if err != nil {
			cont.log.WithFields(logrus.Fields{
				"SgAnnotation": sgval,
			}).Error("Could not decode annotation: ", err)
		}
	}
	gset := make(map[metadata.OpflexGroup]bool)
	for _, og := range g {
		gset[og] = true
	}

	// Add network policies that directly select this pod
	for _, npkey := range cont.netPolPods.GetObjForPod(podkey) {
		newg := metadata.OpflexGroup{
			PolicySpace: cont.config.AciPolicyTenant,
			Name:        cont.aciNameForKey("np", npkey),
		}
		if _, ok := gset[newg]; !ok {
			gset[newg] = true
			g = append(g, newg)
		}
	}

	// Add network policy for accessing the pod's local node
	if pod.Spec.NodeName != "" {
		newg := metadata.OpflexGroup{
			PolicySpace: cont.config.AciPolicyTenant,
			Name:        cont.aciNameForKey("node", pod.Spec.NodeName),
		}
		if _, ok := gset[newg]; !ok {
			gset[newg] = true
			g = append(g, newg)
		}
	}

	// Add static network policy to allow egress traffic
	{
		newg := metadata.OpflexGroup{
			PolicySpace: cont.config.AciPolicyTenant,
			Name:        cont.aciNameForKey("np", "static"),
		}
		if _, ok := gset[newg]; !ok {
			gset[newg] = true
			g = append(g, newg)
		}
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
		cont.namespaceInformer.GetStore().GetByKey(pod.ObjectMeta.Namespace)
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
			cont.deploymentInformer.GetStore().GetByKey(depkey)
		if err != nil {
			cont.log.Error("Could not lookup deployment " +
				depkey + ": " + err.Error())
			continue
		}
		if exists && deploymentobj != nil {
			deployment := deploymentobj.(*v1beta1.Deployment)

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
		} else {
			logger.WithFields(logrus.Fields{
				"Eg": pod.ObjectMeta.Annotations[metadata.CompEgAnnotation],
				"Sg": pod.ObjectMeta.Annotations[metadata.CompSgAnnotation],
			}).Info("Updated pod annotations")
		}
	}
	return false
}

func (cont *AciController) podAdded(obj interface{}) {
	pod := obj.(*v1.Pod)
	cont.depPods.UpdatePodNoCallback(pod)
	cont.netPolPods.UpdatePodNoCallback(pod)
	cont.netPolIngressPods.UpdatePodNoCallback(pod)
	cont.queuePodUpdate(pod)
}

func (cont *AciController) podUpdated(oldobj interface{}, newobj interface{}) {
	oldpod := oldobj.(*v1.Pod)
	newpod := newobj.(*v1.Pod)

	shouldqueue := false
	if !reflect.DeepEqual(oldpod.ObjectMeta.Labels, newpod.ObjectMeta.Labels) {
		shouldqueue =
			cont.depPods.UpdatePodNoCallback(newpod) || shouldqueue
		shouldqueue =
			cont.netPolPods.UpdatePodNoCallback(newpod) || shouldqueue
		shouldqueue =
			cont.netPolIngressPods.UpdatePodNoCallback(newpod) || shouldqueue
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

	cont.depPods.DeletePod(pod)
	cont.netPolPods.DeletePod(pod)
	cont.netPolIngressPods.DeletePod(pod)

	cont.indexMutex.Lock()
	cont.removePodFromNode(pod.Spec.NodeName, podkey)
	cont.indexMutex.Unlock()

	logger.Debug("Pod deleted")
}
