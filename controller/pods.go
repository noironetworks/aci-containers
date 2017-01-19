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

	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/apis/extensions"
	"k8s.io/kubernetes/pkg/client/cache"
)

func podLogger(pod *api.Pod) *logrus.Entry {
	return log.WithFields(logrus.Fields{
		"namespace": pod.ObjectMeta.Namespace,
		"name":      pod.ObjectMeta.Name,
		"node":      pod.Spec.NodeName,
	})
}

func podFilter(pod *api.Pod) bool {
	if pod.Spec.SecurityContext != nil &&
		pod.Spec.SecurityContext.HostNetwork == true {
		return false
	}
	return true
}

func podUpdated(_ interface{}, obj interface{}) {
	podAdded(obj)
}

func podAdded(obj interface{}) {
	indexMutex.Lock()
	defer indexMutex.Unlock()

	podChangedLocked(obj)
}

func podChangedLocked(obj interface{}) {
	pod := obj.(*api.Pod)
	if !podFilter(pod) {
		podDeletedLocked(obj)
		return
	}
	logger := podLogger(pod)

	podkey, err := cache.MetaNamespaceKeyFunc(pod)
	if err != nil {
		logger.Error("Could not create pod key:" + err.Error())
		return
	}

	podobj, exists, err := podInformer.GetStore().GetByKey(podkey)
	if err != nil {
		log.Error("Could not lookup pod:" + err.Error())
		return
	}
	if !exists || podobj == nil {
		podDeletedLocked(pod)
	}

	const EgAnnotation = "opflex.cisco.com/endpoint-group"
	const SgAnnotation = "opflex.cisco.com/security-group"
	const CompEgAnnotation = "opflex.cisco.com/computed-endpoint-group"
	const CompSgAnnotation = "opflex.cisco.com/computed-security-group"

	// top-level default annotation
	egval := defaultEg
	sgval := defaultSg

	// namespace annotation has next-highest priority
	namespaceobj, exists, err :=
		namespaceInformer.GetStore().GetByKey(pod.ObjectMeta.Namespace)
	if err != nil {
		log.Error("Could not lookup namespace " +
			pod.ObjectMeta.Namespace + ": " + err.Error())
		return
	}
	if exists && namespaceobj != nil {
		namespace := namespaceobj.(*api.Namespace)

		if og, ok := namespace.ObjectMeta.Annotations[EgAnnotation]; ok {
			egval = &og
		}
		if og, ok := namespace.ObjectMeta.Annotations[SgAnnotation]; ok {
			sgval = &og
		}
	}

	// annotation on associated deployment is next-highest priority
	if _, ok := depPods[podkey]; !ok {
		if _, ok := pod.ObjectMeta.Annotations["kubernetes.io/created-by"]; ok {
			// we have no deployment for this pod but it was created
			// by something.  Update the index

			updateDeploymentsForPod(pod)
		}
	}
	if depkey, ok := depPods[podkey]; ok {
		deploymentobj, exists, err :=
			deploymentInformer.GetStore().GetByKey(depkey)
		if err != nil {
			log.Error("Could not lookup deployment " + depkey + ": " + err.Error())
			return
		}
		if exists && deploymentobj != nil {
			deployment := deploymentobj.(*extensions.Deployment)

			if og, ok := deployment.ObjectMeta.Annotations[EgAnnotation]; ok {
				egval = &og
			}
			if og, ok := deployment.ObjectMeta.Annotations[SgAnnotation]; ok {
				sgval = &og
			}
		}
	}

	// direct pod annotation is highest priority
	if og, ok := pod.ObjectMeta.Annotations[EgAnnotation]; ok {
		egval = &og
	}
	if og, ok := pod.ObjectMeta.Annotations[SgAnnotation]; ok {
		sgval = &og
	}

	podUpdated := false
	oldegval, ok := pod.ObjectMeta.Annotations[CompEgAnnotation]
	if egval != nil && *egval != "" {
		if !ok || oldegval != *egval {
			pod.ObjectMeta.Annotations[CompEgAnnotation] = *egval
			podUpdated = true
		}
	} else {
		if ok {
			delete(pod.ObjectMeta.Annotations, CompEgAnnotation)
			podUpdated = true
		}
	}
	oldsgval, ok := pod.ObjectMeta.Annotations[CompSgAnnotation]
	if sgval != nil && *sgval != "" {
		if !ok || oldsgval != *sgval {
			pod.ObjectMeta.Annotations[CompSgAnnotation] = *sgval
			podUpdated = true
		}
	} else {
		if ok {
			delete(pod.ObjectMeta.Annotations, CompSgAnnotation)
			podUpdated = true
		}
	}

	if podUpdated {
		_, err := kubeClient.Core().Pods(pod.ObjectMeta.Namespace).Update(pod)
		if err != nil {
			logger.Error("Failed to update pod: " + err.Error())
		} else {
			logger.WithFields(logrus.Fields{
				"EgAnnotation": *egval,
				"SgAnnotation": *sgval,
			}).Info("Updated pod annotations")
		}
	}
}

func podDeleted(obj interface{}) {
	indexMutex.Lock()
	defer indexMutex.Unlock()

	podDeletedLocked(obj)
}

func podDeletedLocked(obj interface{}) {
	//	pod := obj.(*api.Pod)

}
