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
	"reflect"

	"github.com/Sirupsen/logrus"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"github.com/noironetworks/aci-containers/pkg/apicapi"
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
