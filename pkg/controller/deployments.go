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

	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"github.com/noironetworks/aci-containers/pkg/apicapi"
	"github.com/noironetworks/aci-containers/pkg/index"
)

func (cont *AciController) initDeploymentInformerFromClient(
	kubeClient kubernetes.Interface) {

	cont.initDeploymentInformerBase(
		cache.NewListWatchFromClient(
			kubeClient.AppsV1().RESTClient(), "deployments",
			metav1.NamespaceAll, fields.Everything()))
}

func (cont *AciController) initDeploymentInformerBase(listWatch *cache.ListWatch) {
	cont.deploymentIndexer, cont.deploymentInformer = cache.NewIndexerInformer(
		listWatch,
		&appsv1.Deployment{}, 0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				cont.deploymentAdded(obj)
			},
			UpdateFunc: func(oldobj interface{}, newobj interface{}) {
				cont.deploymentChanged(oldobj, newobj)
			},
			DeleteFunc: func(obj interface{}) {
				cont.deploymentDeleted(obj)
			},
		},
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
}

func (cont *AciController) initDepPodIndex() {
	cont.depPods = index.NewPodSelectorIndex(cont.log,
		cont.podIndexer, cont.namespaceIndexer, cont.deploymentIndexer,
		cache.MetaNamespaceKeyFunc,
		func(obj interface{}) []index.PodSelector {
			dep := obj.(*appsv1.Deployment)
			return index.PodSelectorFromNsAndSelector(dep.ObjectMeta.Namespace,
				dep.Spec.Selector)
		},
	)
	cont.depPods.SetPodUpdateCallback(func(podkey string) {
		podobj, exists, err := cont.podIndexer.GetByKey(podkey)
		if exists && err == nil {
			cont.queuePodUpdate(podobj.(*v1.Pod))
		}
	})
}

func deploymentLogger(log *logrus.Logger, dep *appsv1.Deployment) *logrus.Entry {
	return log.WithFields(logrus.Fields{
		"namespace": dep.ObjectMeta.Namespace,
		"name":      dep.ObjectMeta.Name,
	})
}

func (cont *AciController) writeApicDepl(dep *appsv1.Deployment) {
	depkey, err :=
		cache.MetaNamespaceKeyFunc(dep)
	if err != nil {
		deploymentLogger(cont.log, dep).
			Error("Could not create key: ", err)
		return
	}
	key := cont.aciNameForKey("deployment", depkey)

	aobj := apicapi.NewVmmInjectedDepl(cont.vmmDomainProvider(),
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
	cont.writeApicDepl(obj.(*appsv1.Deployment))
	cont.depPods.UpdateSelectorObj(obj)
}

func (cont *AciController) deploymentChanged(oldobj interface{},
	newobj interface{}) {

	olddep := oldobj.(*appsv1.Deployment)
	newdep := newobj.(*appsv1.Deployment)

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
				cont.podIndexer.GetByKey(podkey)
			if exists && err == nil {
				cont.queuePodUpdate(podobj.(*v1.Pod))
			}
		}
	}

}

func (cont *AciController) deploymentDeleted(obj interface{}) {
	dep := obj.(*appsv1.Deployment)
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
