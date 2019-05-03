// Copyright 2018 Cisco Systems, Inc.
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

package hostagent

import (
	"reflect"

	"github.com/Sirupsen/logrus"
	"github.com/noironetworks/aci-containers/pkg/index"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	v1net "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/kubernetes/pkg/controller"
)

func (agent *HostAgent) initNamespaceInformerFromClient(
	kubeClient kubernetes.Interface) {

	agent.initNamespaceInformerBase(
		cache.NewListWatchFromClient(
			kubeClient.CoreV1().RESTClient(), "namespaces",
			metav1.NamespaceAll, fields.Everything()))
}

func (agent *HostAgent) initNamespaceInformerBase(listWatch *cache.ListWatch) {
	agent.nsInformer = cache.NewSharedIndexInformer(
		listWatch, &v1.Namespace{}, controller.NoResyncPeriodFunc(),
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)

	agent.nsInformer.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				agent.namespaceAdded(obj)
			},
			UpdateFunc: func(oldobj interface{}, newobj interface{}) {
				agent.namespaceChanged(oldobj, newobj)
			},
			DeleteFunc: func(obj interface{}) {
				agent.namespaceDeleted(obj)
			},
		})
}

func (agent *HostAgent) updatePodsForNamespace(ns string) {
	cache.ListAllByNamespace(agent.podInformer.GetIndexer(), ns, labels.Everything(),
		func(podobj interface{}) {
			pod := podobj.(*v1.Pod)
			if pod.Spec.NodeName == agent.config.NodeName {
				agent.podUpdated(pod)
			}
		})
}

func (agent *HostAgent) namespaceAdded(obj interface{}) {
	ns := obj.(*v1.Namespace)
	agent.log.Infof("Namespace %+v added", ns)
	agent.netPolPods.UpdateNamespace(ns)
	agent.updatePodsForNamespace(ns.ObjectMeta.Name)
}

func (agent *HostAgent) namespaceChanged(oldobj interface{},
	newobj interface{}) {

	oldns := oldobj.(*v1.Namespace)
	newns := newobj.(*v1.Namespace)
	agent.log.Infof("Namespace %+v changed", oldns)

	if !reflect.DeepEqual(oldns.ObjectMeta.Labels, newns.ObjectMeta.Labels) {
		agent.netPolPods.UpdateNamespace(newns)
	}
	if !reflect.DeepEqual(oldns.ObjectMeta.Annotations,
		newns.ObjectMeta.Annotations) {
		agent.updatePodsForNamespace(newns.ObjectMeta.Name)
	}
}

func (agent *HostAgent) namespaceDeleted(obj interface{}) {
	ns := obj.(*v1.Namespace)
	agent.netPolPods.DeleteNamespace(ns)
}

func (agent *HostAgent) initNetworkPolicyInformerFromClient(
	kubeClient kubernetes.Interface) {

	agent.initNetworkPolicyInformerBase(
		cache.NewListWatchFromClient(
			kubeClient.NetworkingV1().RESTClient(), "networkpolicies",
			metav1.NamespaceAll, fields.Everything()))
}

func (agent *HostAgent) initNetworkPolicyInformerBase(listWatch *cache.ListWatch) {
	agent.netPolInformer =
		cache.NewSharedIndexInformer(
			listWatch, &v1net.NetworkPolicy{}, 0,
			cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
		)

	agent.netPolInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			agent.networkPolicyAdded(obj)
		},
		UpdateFunc: func(oldobj interface{}, newobj interface{}) {
			agent.networkPolicyChanged(oldobj, newobj)
		},
		DeleteFunc: func(obj interface{}) {
			agent.networkPolicyDeleted(obj)
		},
	},
	)
}

func (agent *HostAgent) networkPolicyAdded(obj interface{}) {
	agent.netPolPods.UpdateSelectorObj(obj)
}

func (agent *HostAgent) networkPolicyChanged(oldobj, newobj interface{}) {
	oldnp := oldobj.(*v1net.NetworkPolicy)
	newnp := newobj.(*v1net.NetworkPolicy)
	if !reflect.DeepEqual(oldnp.Spec.PodSelector, newnp.Spec.PodSelector) {
		agent.netPolPods.UpdateSelectorObjNoCallback(newobj)
	}

	npkey, err := cache.MetaNamespaceKeyFunc(newnp)
	if err != nil {
		logrus.Error("Could not create network policy key: ", err)
		return
	}

	if !reflect.DeepEqual(oldnp.Spec.PolicyTypes, newnp.Spec.PolicyTypes) {
		peerPodKeys := agent.netPolPods.GetPodForObj(npkey)
		for _, podkey := range peerPodKeys {
			agent.podChanged(&podkey)
		}
	}
}

func (agent *HostAgent) networkPolicyDeleted(obj interface{}) {
	agent.netPolPods.DeleteSelectorObj(obj)
}

func (agent *HostAgent) initNetPolPodIndex() {
	agent.netPolPods = index.NewPodSelectorIndex(
		agent.log,
		agent.podInformer.GetIndexer(), agent.nsInformer.GetIndexer(), agent.netPolInformer.GetIndexer(),
		cache.MetaNamespaceKeyFunc,
		func(obj interface{}) []index.PodSelector {
			np := obj.(*v1net.NetworkPolicy)
			return index.PodSelectorFromNsAndSelector(np.ObjectMeta.Namespace,
				&np.Spec.PodSelector)
		},
	)
	agent.netPolPods.SetPodUpdateCallback(func(podkey string) {
		podobj, exists, err := agent.podInformer.GetIndexer().GetByKey(podkey)
		if exists && err == nil {
			agent.podUpdated(podobj.(*v1.Pod))
		}
	})
}

func (agent *HostAgent) initDeploymentInformerFromClient(
	kubeClient kubernetes.Interface) {

	agent.initDeploymentInformerBase(
		cache.NewListWatchFromClient(
			kubeClient.AppsV1().RESTClient(), "deployments",
			metav1.NamespaceAll, fields.Everything()))
}

func (agent *HostAgent) initDeploymentInformerBase(listWatch *cache.ListWatch) {
	agent.depInformer = cache.NewSharedIndexInformer(
		listWatch, &appsv1.Deployment{}, controller.NoResyncPeriodFunc(),
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)

	agent.depInformer.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				agent.deploymentAdded(obj)
			},
			UpdateFunc: func(oldobj interface{}, newobj interface{}) {
				agent.deploymentChanged(oldobj, newobj)
			},
			DeleteFunc: func(obj interface{}) {
				agent.deploymentDeleted(obj)
			},
		})
}

func (agent *HostAgent) initDepPodIndex() {
	agent.depPods = index.NewPodSelectorIndex(agent.log,
		agent.podInformer.GetIndexer(),
		agent.nsInformer.GetIndexer(),
		agent.depInformer.GetIndexer(),
		cache.MetaNamespaceKeyFunc,
		func(obj interface{}) []index.PodSelector {
			dep := obj.(*appsv1.Deployment)
			return index.PodSelectorFromNsAndSelector(dep.ObjectMeta.Namespace,
				dep.Spec.Selector)
		},
	)
	agent.depPods.SetPodUpdateCallback(func(podkey string) {
		agent.podChanged(&podkey)
	})
}

func deploymentLogger(log *logrus.Logger, dep *appsv1.Deployment) *logrus.Entry {
	return log.WithFields(logrus.Fields{
		"namespace": dep.ObjectMeta.Namespace,
		"name":      dep.ObjectMeta.Name,
	})
}

func (agent *HostAgent) deploymentAdded(obj interface{}) {
	agent.log.Infof("deploymentAdded => ")
	agent.depPods.UpdateSelectorObj(obj)
}

// deploymentChanged - callback for deployment change. Trigger pod update
// in order to handle any changes to annotations, also keep the indexer
// in sync
func (agent *HostAgent) deploymentChanged(oldobj interface{},
	newobj interface{}) {

	olddep := oldobj.(*appsv1.Deployment)
	newdep := newobj.(*appsv1.Deployment)

	if !reflect.DeepEqual(olddep.Spec.Selector, newdep.Spec.Selector) {
		agent.depPods.UpdateSelectorObj(newobj)
	}
	if !reflect.DeepEqual(olddep.ObjectMeta.Annotations,
		newdep.ObjectMeta.Annotations) {
		depkey, err :=
			cache.MetaNamespaceKeyFunc(newdep)
		if err != nil {
			deploymentLogger(agent.log, newdep).
				Error("Could not create key: ", err)
			return
		}
		for _, podkey := range agent.depPods.GetPodForObj(depkey) {
			agent.podChanged(&podkey)
		}
	}
}

func (agent *HostAgent) deploymentDeleted(obj interface{}) {
	agent.depPods.DeleteSelectorObj(obj)
}

func (agent *HostAgent) initRCInformerFromClient(
	kubeClient kubernetes.Interface) {

	agent.initRCInformerBase(
		cache.NewListWatchFromClient(
			kubeClient.CoreV1().RESTClient(), "replicationcontrollers",
			metav1.NamespaceAll, fields.Everything()))
}

func (agent *HostAgent) initRCInformerBase(listWatch *cache.ListWatch) {
	agent.rcInformer = cache.NewSharedIndexInformer(
		listWatch, &v1.ReplicationController{}, controller.NoResyncPeriodFunc(),
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)

	agent.rcInformer.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				agent.rcAdded(obj)
			},
			UpdateFunc: func(oldobj interface{}, newobj interface{}) {
				agent.rcChanged(oldobj, newobj)
			},
			DeleteFunc: func(obj interface{}) {
				agent.rcDeleted(obj)
			},
		})
}

func (agent *HostAgent) initRCPodIndex() {
	agent.rcPods = index.NewPodSelectorIndex(agent.log,
		agent.podInformer.GetIndexer(),
		agent.nsInformer.GetIndexer(),
		agent.rcInformer.GetIndexer(),
		cache.MetaNamespaceKeyFunc,
		func(obj interface{}) []index.PodSelector {
			rc := obj.(*v1.ReplicationController)
			labels := rc.Spec.Selector
			if len(labels) == 0 {
				agent.log.Infof("RC %s/%s has no selector. Using template", rc.ObjectMeta.Namespace, rc.ObjectMeta.Name)
				labels = rc.Spec.Template.Labels
			}
			ls := &metav1.LabelSelector{MatchLabels: labels}
			return index.PodSelectorFromNsAndSelector(rc.ObjectMeta.Namespace, ls)
		},
	)
	agent.rcPods.SetPodUpdateCallback(func(podkey string) {
		agent.podChanged(&podkey)
	})
}

func rcLogger(log *logrus.Logger, rc *v1.ReplicationController) *logrus.Entry {
	return log.WithFields(logrus.Fields{
		"namespace": rc.ObjectMeta.Namespace,
		"name":      rc.ObjectMeta.Name,
	})
}

func (agent *HostAgent) rcAdded(obj interface{}) {
	agent.log.Infof("rcAdded => ")
	agent.rcPods.UpdateSelectorObj(obj)
}

// rcChanged - callback for replicationController change. Trigger pod update
// in order to handle any changes to annotations, also keep the indexer
// in sync
func (agent *HostAgent) rcChanged(oldobj interface{},
	newobj interface{}) {

	oldrc := oldobj.(*v1.ReplicationController)
	newrc := newobj.(*v1.ReplicationController)

	if !reflect.DeepEqual(oldrc.Spec.Selector, newrc.Spec.Selector) {
		agent.rcPods.UpdateSelectorObj(newobj)
	}
	if !reflect.DeepEqual(oldrc.ObjectMeta.Annotations,
		newrc.ObjectMeta.Annotations) {
		rckey, err :=
			cache.MetaNamespaceKeyFunc(newrc)
		if err != nil {
			rcLogger(agent.log, newrc).
				Error("Could not create key: ", err)
			return
		}
		for _, podkey := range agent.rcPods.GetPodForObj(rckey) {
			agent.podChanged(&podkey)
		}
	}
}

func (agent *HostAgent) rcDeleted(obj interface{}) {
	agent.rcPods.DeleteSelectorObj(obj)
}
