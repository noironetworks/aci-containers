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

// Handlers for namespace updates.  Keeps an index of namespace
// annotations

package main

import (
	"github.com/Sirupsen/logrus"

	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/api/unversioned"
	"k8s.io/kubernetes/pkg/apis/extensions"
	"k8s.io/kubernetes/pkg/client/cache"
	"k8s.io/kubernetes/pkg/labels"
)

func deploymentLogger(dep *extensions.Deployment) *logrus.Entry {
	return log.WithFields(logrus.Fields{
		"namespace": dep.ObjectMeta.Namespace,
		"name":      dep.ObjectMeta.Name,
	})
}

// must hold index lock
func checkDeploymentForPod(dep *extensions.Deployment, pod *api.Pod) {
	podkey, err := cache.MetaNamespaceKeyFunc(pod)
	if err != nil {
		deploymentLogger(dep).
			Error("Could not create pod key:" + err.Error())
		return
	}
	depkey, err := cache.MetaNamespaceKeyFunc(dep)
	if err != nil {
		deploymentLogger(dep).Error("Could not create key:" + err.Error())
		return
	}
	selector, err :=
		unversioned.LabelSelectorAsSelector(dep.Spec.Selector)
	if err != nil {
		deploymentLogger(dep).Error("Could not create selector:" + err.Error())
		return
	}

	if dep.ObjectMeta.Namespace == pod.ObjectMeta.Namespace &&
		selector.Matches(labels.Set(pod.ObjectMeta.Labels)) {
		depPods[podkey] = depkey
		podChangedLocked(pod)
	} else if val, ok := depPods[podkey]; ok && val == depkey {
		delete(depPods, podkey)
		podChangedLocked(pod)
	}
}

// must hold index lock
func updateDeploymentsForPod(pod *api.Pod) {
	deployments := deploymentInformer.GetStore().List()

	for _, depobj := range deployments {
		dep := depobj.(*extensions.Deployment)
		checkDeploymentForPod(dep, pod)
	}
}

func deploymentUpdated(_ interface{}, obj interface{}) {
	deploymentAdded(obj)
}

func deploymentAdded(obj interface{}) {
	indexMutex.Lock()
	defer indexMutex.Unlock()

	dep := obj.(*extensions.Deployment)
	pods := podInformer.GetStore().List()

	for _, podobj := range pods {
		pod := podobj.(*api.Pod)
		if !podFilter(pod) {
			continue
		}

		checkDeploymentForPod(dep, pod)
	}
}

func deploymentDeleted(obj interface{}) {
	indexMutex.Lock()
	defer indexMutex.Unlock()

	dep := obj.(*extensions.Deployment)
	key, err := cache.MetaNamespaceKeyFunc(dep)
	if err != nil {
		deploymentLogger(dep).Error("Could not create key:" + err.Error())
		return
	}

	for podkey, val := range depPods {
		if val == key {
			delete(depPods, podkey)

			podobj, exists, err := podInformer.GetStore().GetByKey(podkey)
			if err != nil {
				deploymentLogger(dep).Error("Could not lookup pod:" + err.Error())
				continue
			}
			if !exists || podobj == nil {
				continue
			}
			pod := podobj.(*api.Pod)
			podChangedLocked(pod)
		}
	}
}
