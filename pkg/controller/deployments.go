// Copyright 2016,2017 Cisco Systems, Inc.
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
	"reflect"
	"strconv"

	"github.com/Sirupsen/logrus"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	v1 "k8s.io/client-go/pkg/api/v1"
	v1beta1 "k8s.io/client-go/pkg/apis/extensions/v1beta1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/kubernetes/pkg/controller"

	"github.com/noironetworks/aci-containers/pkg/apicapi"
	"github.com/noironetworks/aci-containers/pkg/index"
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
			cont.deploymentAdded(obj)
		},
		UpdateFunc: func(oldobj interface{}, newobj interface{}) {
			cont.deploymentChanged(oldobj, newobj)
		},
		DeleteFunc: func(obj interface{}) {
			cont.deploymentDeleted(obj)
		},
	})

}

func (cont *AciController) initDepPodIndex() {
	cont.depPods = index.NewPodSelectorIndex(
		cont.log, cont.podInformer,
		cont.namespaceInformer, cont.deploymentInformer,
		cache.MetaNamespaceKeyFunc,
		func(obj interface{}) []index.PodSelector {
			dep := obj.(*v1beta1.Deployment)
			return index.PodSelectorFromNsAndSelector(dep.ObjectMeta.Namespace,
				dep.Spec.Selector)
		},
	)
	cont.depPods.SetPodUpdateCallback(func(podkey string) {
		podobj, exists, err :=
			cont.podInformer.GetStore().GetByKey(podkey)
		if exists && err == nil {
			cont.queuePodUpdate(podobj.(*v1.Pod))
		}
	})
}

func deploymentLogger(log *logrus.Logger, dep *v1beta1.Deployment) *logrus.Entry {
	return log.WithFields(logrus.Fields{
		"namespace": dep.ObjectMeta.Namespace,
		"name":      dep.ObjectMeta.Name,
	})
}

func (cont *AciController) writeApicDepl(dep *v1beta1.Deployment) {
	depkey, err :=
		cache.MetaNamespaceKeyFunc(dep)
	if err != nil {
		deploymentLogger(cont.log, dep).
			Error("Could not create key: ", err)
		return
	}
	key := cont.aciNameForKey("deployment", depkey)

	aobj := apicapi.NewVmmInjectedDepl("Kubernetes",
		cont.config.AciVmmDomain, cont.config.AciVmmController,
		dep.Namespace, dep.Name)
	aobj.SetAttr("guid", string(dep.UID))
	if dep.Spec.Replicas != nil {
		aobj.SetAttr("replicas", strconv.Itoa(int(*dep.Spec.Replicas)))
	} else {
		aobj.SetAttr("replicas", "1")
	}
	cont.apicConn.WriteApicObjects(key, apicapi.ApicSlice{aobj})
}

func (cont *AciController) deploymentAdded(obj interface{}) {
	cont.writeApicDepl(obj.(*v1beta1.Deployment))
	cont.depPods.UpdateSelectorObj(obj)
}

func (cont *AciController) deploymentChanged(oldobj interface{},
	newobj interface{}) {

	olddep := oldobj.(*v1beta1.Deployment)
	newdep := newobj.(*v1beta1.Deployment)

	cont.writeApicDepl(newdep)

	if !reflect.DeepEqual(olddep.Spec.Selector, newdep.Spec.Selector) {
		cont.depPods.UpdateSelectorObj(newobj)
	}
	if !reflect.DeepEqual(olddep.ObjectMeta.Annotations,
		newdep.ObjectMeta.Annotations) {
		depkey, err :=
			cache.MetaNamespaceKeyFunc(newdep)
		if err != nil {
			deploymentLogger(cont.log, newdep).
				Error("Could not create key: ", err)
			return
		}
		for _, podkey := range cont.depPods.GetPodForObj(depkey) {
			podobj, exists, err :=
				cont.podInformer.GetStore().GetByKey(podkey)
			if exists && err == nil {
				cont.queuePodUpdate(podobj.(*v1.Pod))
			}
		}
	}

}

func (cont *AciController) deploymentDeleted(obj interface{}) {
	dep := obj.(*v1beta1.Deployment)
	depkey, err :=
		cache.MetaNamespaceKeyFunc(dep)
	if err != nil {
		deploymentLogger(cont.log, dep).
			Error("Could not create key: ", err)
	} else {
		key := cont.aciNameForKey("deployment", depkey)
		cont.apicConn.ClearApicObjects(key)
	}
	cont.depPods.DeleteSelectorObj(obj)
}
