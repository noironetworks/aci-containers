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
	"reflect"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	v1 "k8s.io/client-go/pkg/api/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/kubernetes/pkg/controller"

	"github.com/noironetworks/aci-containers/pkg/apicapi"
)

func (cont *AciController) initNamespaceInformerFromClient(
	kubeClient kubernetes.Interface) {

	cont.initNamespaceInformerBase(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				return kubeClient.CoreV1().Namespaces().List(options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				return kubeClient.CoreV1().Namespaces().Watch(options)
			},
		})
}

func (cont *AciController) initNamespaceInformerBase(listWatch *cache.ListWatch) {
	cont.namespaceInformer = cache.NewSharedIndexInformer(
		listWatch,
		&v1.Namespace{},
		controller.NoResyncPeriodFunc(),
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	cont.namespaceInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			cont.namespaceAdded(obj)
		},
		UpdateFunc: func(oldobj interface{}, newobj interface{}) {
			cont.namespaceChanged(oldobj, newobj)
		},
		DeleteFunc: func(obj interface{}) {
			cont.namespaceDeleted(obj)
		},
	})

}

func (cont *AciController) updatePodsForNamespace(ns string) {
	cache.ListAllByNamespace(cont.podInformer.GetIndexer(), ns, labels.Everything(),
		func(podobj interface{}) {
			cont.queuePodUpdate(podobj.(*v1.Pod))
		})
}

func (cont *AciController) writeApicNs(ns *v1.Namespace) {
	aobj := apicapi.NewVmmInjectedNs("Kubernetes",
		cont.config.AciVmmDomain, cont.config.AciVmmController,
		ns.Name)
	cont.apicConn.WriteApicContainer(cont.aciNameForKey("ns", ns.Name),
		apicapi.ApicSlice{aobj})
}

func (cont *AciController) namespaceAdded(obj interface{}) {
	ns := obj.(*v1.Namespace)
	cont.writeApicNs(ns)
	cont.depPods.UpdateNamespace(ns)
	cont.updatePodsForNamespace(ns.ObjectMeta.Name)
}

func (cont *AciController) namespaceChanged(oldobj interface{},
	newobj interface{}) {

	oldns := oldobj.(*v1.Namespace)
	newns := newobj.(*v1.Namespace)

	cont.writeApicNs(newns)

	if !reflect.DeepEqual(oldns.ObjectMeta.Labels, newns.ObjectMeta.Labels) {
		cont.depPods.UpdateNamespace(newns)
		cont.netPolPods.UpdateNamespace(newns)
		cont.netPolIngressPods.UpdateNamespace(newns)
	}
	if !reflect.DeepEqual(oldns.ObjectMeta.Annotations,
		newns.ObjectMeta.Annotations) {
		cont.updatePodsForNamespace(newns.ObjectMeta.Name)
	}
}

func (cont *AciController) namespaceDeleted(obj interface{}) {
	ns := obj.(*v1.Namespace)
	cont.apicConn.ClearApicObjects(cont.aciNameForKey("ns", ns.Name))
	cont.depPods.DeleteNamespace(ns)
	cont.netPolPods.DeleteNamespace(ns)
	cont.netPolIngressPods.DeleteNamespace(ns)
	cont.updatePodsForNamespace(ns.ObjectMeta.Name)
}
