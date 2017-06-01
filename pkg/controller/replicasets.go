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
	"github.com/Sirupsen/logrus"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	v1beta1 "k8s.io/client-go/pkg/apis/extensions/v1beta1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/kubernetes/pkg/controller"

	"github.com/noironetworks/aci-containers/pkg/apicapi"
)

func (cont *AciController) initReplicaSetInformerFromClient(
	kubeClient kubernetes.Interface) {

	cont.initReplicaSetInformerBase(&cache.ListWatch{
		ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
			return kubeClient.ExtensionsV1beta1().ReplicaSets(metav1.NamespaceAll).List(options)
		},
		WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
			return kubeClient.ExtensionsV1beta1().ReplicaSets(metav1.NamespaceAll).Watch(options)
		},
	})
}

func (cont *AciController) initReplicaSetInformerBase(listWatch *cache.ListWatch) {
	cont.replicaSetInformer = cache.NewSharedIndexInformer(
		listWatch,
		&v1beta1.ReplicaSet{},
		controller.NoResyncPeriodFunc(),
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	cont.replicaSetInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			cont.replicaSetAdded(obj)
		},
		UpdateFunc: func(oldobj interface{}, newobj interface{}) {
			cont.replicaSetChanged(oldobj, newobj)
		},
		DeleteFunc: func(obj interface{}) {
			cont.replicaSetDeleted(obj)
		},
	})

}

func replicaSetLogger(log *logrus.Logger, rs *v1beta1.ReplicaSet) *logrus.Entry {
	return log.WithFields(logrus.Fields{
		"namespace": rs.ObjectMeta.Namespace,
		"name":      rs.ObjectMeta.Name,
	})
}

func (cont *AciController) writeApicRs(rs *v1beta1.ReplicaSet) {
	rskey, err :=
		cache.MetaNamespaceKeyFunc(rs)
	if err != nil {
		replicaSetLogger(cont.log, rs).
			Error("Could not create key: ", err)
		return
	}
	key := cont.aciNameForKey("replicaSet", rskey)

	aobj := apicapi.NewVmmInjectedReplSet("Kubernetes",
		cont.config.AciVmmDomain, cont.config.AciVmmController,
		rs.Namespace, rs.Name)
	aobj.SetAttr("guid", string(rs.UID))
	for _, or := range rs.OwnerReferences {
		if or.Kind == "Deployment" && or.Name != "" {
			aobj.SetAttr("deploymentName", or.Name)
			break
		}
	}
	cont.apicConn.WriteApicObjects(key, apicapi.ApicSlice{aobj})
}

func (cont *AciController) replicaSetAdded(obj interface{}) {
	cont.writeApicRs(obj.(*v1beta1.ReplicaSet))
}

func (cont *AciController) replicaSetChanged(oldobj interface{},
	newobj interface{}) {
	newrs := newobj.(*v1beta1.ReplicaSet)

	cont.writeApicRs(newrs)
}

func (cont *AciController) replicaSetDeleted(obj interface{}) {
	rs := obj.(*v1beta1.ReplicaSet)
	rskey, err :=
		cache.MetaNamespaceKeyFunc(rs)
	if err != nil {
		replicaSetLogger(cont.log, rs).
			Error("Could not create key: ", err)
		return
	}

	key := cont.aciNameForKey("replicaSet", rskey)
	cont.apicConn.ClearApicObjects(key)
}
