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

	"github.com/noironetworks/aci-containers/pkg/metadata"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"github.com/noironetworks/aci-containers/pkg/apicapi"
)

func (cont *AciController) initNamespaceInformerFromClient(
	kubeClient kubernetes.Interface) {

	cont.initNamespaceInformerBase(
		cache.NewListWatchFromClient(
			kubeClient.CoreV1().RESTClient(), "namespaces",
			metav1.NamespaceAll, fields.Everything()))
}

func (cont *AciController) initNamespaceInformerBase(listWatch *cache.ListWatch) {
	cont.namespaceIndexer, cont.namespaceInformer = cache.NewIndexerInformer(
		listWatch, &v1.Namespace{}, 0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				cont.namespaceAdded(obj)
			},
			UpdateFunc: func(oldobj interface{}, newobj interface{}) {
				cont.namespaceChanged(oldobj, newobj)
			},
			DeleteFunc: func(obj interface{}) {
				cont.namespaceDeleted(obj)
			},
		},
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
}

func (cont *AciController) updatePodsForNamespace(ns string) {
	cache.ListAllByNamespace(cont.podIndexer, ns, labels.Everything(),
		func(podobj interface{}) {
			cont.queuePodUpdate(podobj.(*v1.Pod))
		})
}

func (cont *AciController) writeApicNs(ns *v1.Namespace) {
	aobj := apicapi.NewVmmInjectedNs(cont.vmmDomainProvider(),
		cont.config.AciVmmDomain, cont.config.AciVmmController,
		ns.Name)
	if cont.config.EnableVmmInjectedLabels && ns.ObjectMeta.Labels != nil && apicapi.ApicVersion >= "5.2" {
		for key, val := range ns.ObjectMeta.Labels {
			newLabelKey := cont.aciNameForKey("label", key)
			label := apicapi.NewVmmInjectedLabel(aobj.GetDn(),
				newLabelKey, val)
			aobj.AddChild(label)
		}
	}
	cont.apicConn.WriteApicContainer(cont.aciNameForKey("ns", ns.Name),
		apicapi.ApicSlice{aobj})
}

func (cont *AciController) namespaceAdded(obj interface{}) {
	ns := obj.(*v1.Namespace)
	cont.writeApicNs(ns)
	cont.depPods.UpdateNamespace(ns)
	cont.netPolPods.UpdateNamespace(ns)
	cont.netPolIngressPods.UpdateNamespace(ns)
	cont.updatePodsForNamespace(ns.ObjectMeta.Name)
	cont.checkIfEpgExistNs(ns)
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
	cont.checkIfEpgExistNs(newns)
}

func (cont *AciController) namespaceDeleted(obj interface{}) {
	ns, isNamespace := obj.(*v1.Namespace)
	if !isNamespace {
		deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			cont.log.Error("Received unexpected object: ", obj)
			return
		}
		ns, ok = deletedState.Obj.(*v1.Namespace)
		if !ok {
			cont.log.Error("DeletedFinalStateUnknown contained non-Namespace object: ", deletedState.Obj)
			return
		}
	}
	cont.apicConn.ClearApicObjects(cont.aciNameForKey("ns", ns.Name))
	cont.apicConn.ClearApicObjects(cont.aciNameForKey("nsfs", ns.Name))
	cont.depPods.DeleteNamespace(ns)
	cont.netPolPods.DeleteNamespace(ns)
	cont.netPolIngressPods.DeleteNamespace(ns)
	cont.updatePodsForNamespace(ns.ObjectMeta.Name)
	if cont.apicConn.HppRemoteIpCont {
		cont.apicConn.ClearApicObjects(cont.aciNameForKey("hostprot-ns-", ns.Name))
	}
}

func (cont *AciController) checkIfEpgExistNs(ns *v1.Namespace) {

	nskey := cont.aciNameForKey("nsfs", ns.Name)
	if nskey == "" {
		cont.log.Error("Could not retrieve namespace key")
		return
	}
	epGroup, ok := ns.ObjectMeta.Annotations[metadata.EgAnnotation]
	if ok {
		severity := critical
		cont.handleEpgAnnotationUpdate(nskey, nsFaultCode, severity, ns.Name, epGroup)
	}

	return
}
