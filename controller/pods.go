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

package main

import (
	"github.com/Sirupsen/logrus"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	v1 "k8s.io/client-go/pkg/api/v1"
	v1beta1 "k8s.io/client-go/pkg/apis/extensions/v1beta1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/kubernetes/pkg/controller"

	"github.com/noironetworks/aci-containers/metadata"
)

func (cont *aciController) initPodInformerFromClient(
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

func (cont *aciController) initPodInformerBase(listWatch *cache.ListWatch) {
	cont.podInformer = cache.NewSharedIndexInformer(
		listWatch,
		&v1.Pod{},
		controller.NoResyncPeriodFunc(),
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	cont.podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			cont.podChanged(obj)
		},
		UpdateFunc: func(_ interface{}, obj interface{}) {
			cont.podChanged(obj)
		},
		DeleteFunc: func(obj interface{}) {
			cont.podDeleted(obj)
		},
	})

}

func podLogger(pod *v1.Pod) *logrus.Entry {
	return log.WithFields(logrus.Fields{
		"namespace": pod.ObjectMeta.Namespace,
		"name":      pod.ObjectMeta.Name,
		"node":      pod.Spec.NodeName,
	})
}

func podFilter(pod *v1.Pod) bool {
	// XXX TODO there seems to be no way to get the value of the
	// HostNetwork field using the versioned API?

	//if pod.Spec.SecurityContext != nil &&
	//	pod.Spec.SecurityContext.HostNetwork == true {
	//	return false
	//}
	return true
}

func (cont *aciController) podChanged(obj interface{}) {
	cont.indexMutex.Lock()
	defer cont.indexMutex.Unlock()

	cont.podChangedLocked(obj)
}

func (cont *aciController) podChangedLocked(obj interface{}) {
	pod := obj.(*v1.Pod)
	if !podFilter(pod) {
		cont.podDeletedLocked(obj)
		return
	}
	logger := podLogger(pod)

	podkey, err := cache.MetaNamespaceKeyFunc(pod)
	if err != nil {
		logger.Error("Could not create pod key:" + err.Error())
		return
	}
	if pod.Spec.NodeName != "" {
		cont.addPodToNode(pod.Spec.NodeName, podkey)
	}

	podobj, exists, err := cont.podInformer.GetStore().GetByKey(podkey)
	if err != nil {
		log.Error("Could not lookup pod:" + err.Error())
		return
	}
	if !exists || podobj == nil {
		cont.podDeletedLocked(pod)
		return
	}

	// top-level default annotation
	egval := &cont.defaultEg
	sgval := &cont.defaultSg

	// namespace annotation has next-highest priority
	namespaceobj, exists, err :=
		cont.namespaceInformer.GetStore().GetByKey(pod.ObjectMeta.Namespace)
	if err != nil {
		log.Error("Could not lookup namespace " +
			pod.ObjectMeta.Namespace + ": " + err.Error())
		return
	}
	if exists && namespaceobj != nil {
		namespace := namespaceobj.(*v1.Namespace)

		if og, ok := namespace.ObjectMeta.Annotations[metadata.EgAnnotation]; ok && og != "" {
			egval = &og
		}
		if og, ok := namespace.ObjectMeta.Annotations[metadata.SgAnnotation]; ok && og != "" {
			sgval = &og
		}
	}

	// annotation on associated deployment is next-highest priority
	if _, ok := cont.depPods[podkey]; !ok {
		if _, ok := pod.ObjectMeta.Annotations["kubernetes.io/created-by"]; ok {
			// we have no deployment for this pod but it was created
			// by something.  Update the index

			cont.updateDeploymentsForPod(pod)
		}
	}
	if depkey, ok := cont.depPods[podkey]; ok {
		deploymentobj, exists, err :=
			cont.deploymentInformer.GetStore().GetByKey(depkey)
		if err != nil {
			log.Error("Could not lookup deployment " + depkey + ": " + err.Error())
			return
		}
		if exists && deploymentobj != nil {
			deployment := deploymentobj.(*v1beta1.Deployment)

			if og, ok := deployment.ObjectMeta.Annotations[metadata.EgAnnotation]; ok && og != "" {
				egval = &og
			}
			if og, ok := deployment.ObjectMeta.Annotations[metadata.SgAnnotation]; ok && og != "" {
				sgval = &og
			}
		}
	}

	// direct pod annotation is highest priority
	if og, ok := pod.ObjectMeta.Annotations[metadata.EgAnnotation]; ok && og != "" {
		egval = &og
	}
	if og, ok := pod.ObjectMeta.Annotations[metadata.SgAnnotation]; ok && og != "" {
		sgval = &og
	}

	podUpdated := false
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
			logger.Error("Failed to update pod: " + err.Error())
		} else {
			logger.WithFields(logrus.Fields{
				"Eg": pod.ObjectMeta.Annotations[metadata.CompEgAnnotation],
				"Sg": pod.ObjectMeta.Annotations[metadata.CompSgAnnotation],
			}).Info("Updated pod annotations")
		}
	}
}

func (cont *aciController) podDeleted(obj interface{}) {
	cont.indexMutex.Lock()
	defer cont.indexMutex.Unlock()
	cont.podDeletedLocked(obj)
}

func (cont *aciController) podDeletedLocked(obj interface{}) {
	pod := obj.(*v1.Pod)
	podkey, err := cache.MetaNamespaceKeyFunc(pod)
	if err != nil {
		podLogger(pod).Error("Could not create pod key:" + err.Error())
		return
	}
	cont.removePodFromNode(pod.Spec.NodeName, podkey)
}
