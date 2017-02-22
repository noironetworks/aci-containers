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

package controller

import (
	"github.com/Sirupsen/logrus"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	v1 "k8s.io/client-go/pkg/api/v1"
	v1beta1 "k8s.io/client-go/pkg/apis/extensions/v1beta1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/kubernetes/pkg/controller"
)

func (cont *AciController) initDeploymentInformerFromClient(
	kubeClient kubernetes.Interface) {

	cont.initDeploymentInformerBase(&cache.ListWatch{
		ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
			return kubeClient.ExtensionsV1beta1().Deployments(metav1.NamespaceAll).List(options)
		},
		WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
			return kubeClient.ExtensionsV1beta1().Deployments(metav1.NamespaceAll).Watch(options)
		},
	})
}

func (cont *AciController) initDeploymentInformerBase(listWatch *cache.ListWatch) {
	cont.deploymentInformer = cache.NewSharedIndexInformer(
		listWatch,
		&v1beta1.Deployment{},
		controller.NoResyncPeriodFunc(),
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	cont.deploymentInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			cont.deploymentChanged(obj)
		},
		UpdateFunc: func(_ interface{}, obj interface{}) {
			cont.deploymentChanged(obj)
		},
		DeleteFunc: func(obj interface{}) {
			cont.deploymentDeleted(obj)
		},
	})

}

func deploymentLogger(log *logrus.Logger, dep *v1beta1.Deployment) *logrus.Entry {
	return log.WithFields(logrus.Fields{
		"namespace": dep.ObjectMeta.Namespace,
		"name":      dep.ObjectMeta.Name,
	})
}

// must hold index lock
func (cont *AciController) checkDeploymentForPod(dep *v1beta1.Deployment, pod *v1.Pod) bool {
	podkey, err := cache.MetaNamespaceKeyFunc(pod)
	if err != nil {
		deploymentLogger(cont.log, dep).
			Error("Could not create pod key:" + err.Error())
		return false
	}
	depkey, err := cache.MetaNamespaceKeyFunc(dep)
	if err != nil {
		deploymentLogger(cont.log, dep).Error("Could not create key:" + err.Error())
		return false
	}
	selector, err :=
		metav1.LabelSelectorAsSelector(dep.Spec.Selector)
	if err != nil {
		deploymentLogger(cont.log, dep).Error("Could not create selector:" + err.Error())
		return false
	}

	if dep.ObjectMeta.Namespace == pod.ObjectMeta.Namespace &&
		selector.Matches(labels.Set(pod.ObjectMeta.Labels)) {
		cont.depPods[podkey] = depkey
		return true
	} else if val, ok := cont.depPods[podkey]; ok && val == depkey {
		delete(cont.depPods, podkey)
		return true
	}

	return false
}

// must hold index lock
func (cont *AciController) updateDeploymentsForPod(pod *v1.Pod) bool {
	deployments := cont.deploymentInformer.GetStore().List()

	result := false
	for _, depobj := range deployments {
		dep := depobj.(*v1beta1.Deployment)
		if cont.checkDeploymentForPod(dep, pod) {
			result = true
		}
	}
	return result
}

func (cont *AciController) deploymentChanged(obj interface{}) {
	dep := obj.(*v1beta1.Deployment)
	pods := cont.podInformer.GetStore().List()

	cont.indexMutex.Lock()
	defer cont.indexMutex.Unlock()

	for _, podobj := range pods {
		pod := podobj.(*v1.Pod)

		if cont.checkDeploymentForPod(dep, pod) {
			cont.queuePodUpdate(pod)
		}
	}
}

func (cont *AciController) deploymentDeleted(obj interface{}) {
	dep := obj.(*v1beta1.Deployment)
	key, err := cache.MetaNamespaceKeyFunc(dep)
	if err != nil {
		deploymentLogger(cont.log,
			dep).Error("Could not create key:" + err.Error())
		return
	}

	var toupdate []string
	cont.indexMutex.Lock()
	for podkey, val := range cont.depPods {
		if val == key {
			toupdate = append(toupdate, podkey)
			delete(cont.depPods, podkey)
		}
	}
	cont.indexMutex.Unlock()

	for _, podkey := range toupdate {
		podobj, exists, err := cont.podInformer.GetStore().GetByKey(podkey)
		if err != nil {
			cont.log.Error("Could not lookup pod:" + err.Error())
			continue
		}
		if !exists || podobj == nil {
			continue
		}
		cont.queuePodUpdate(podobj.(*v1.Pod))
	}
}
