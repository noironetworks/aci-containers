// Copyright 2017 Cisco Systems, Inc.
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
	"fmt"
	"reflect"

	"github.com/Sirupsen/logrus"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/pkg/api"
	v1 "k8s.io/client-go/pkg/api/v1"
	v1beta1 "k8s.io/client-go/pkg/apis/extensions/v1beta1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/kubernetes/pkg/controller"

	"github.com/noironetworks/aci-containers/pkg/index"
)

func ConfigureNetPolClient(config *rest.Config) {
	gv, err := schema.ParseGroupVersion("extensions/v1beta1")
	if err != nil {
		panic(err)
	}
	// if extensions/v1beta1 is not enabled, return an error
	if !api.Registry.IsEnabledVersion(gv) {
		panic(fmt.Errorf("extensions/v1beta1 is not enabled"))
	}
	config.APIPath = "/apis"
	if config.UserAgent == "" {
		config.UserAgent = rest.DefaultKubernetesUserAgent()
	}
	copyGroupVersion := gv
	config.GroupVersion = &copyGroupVersion

	config.NegotiatedSerializer =
		serializer.DirectCodecFactory{CodecFactory: api.Codecs}
}

func (cont *AciController) initNetworkPolicyInformerFromRest(
	restClient rest.Interface) {

	cont.initNetworkPolicyInformerBase(&cache.ListWatch{
		ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
			result := &v1beta1.NetworkPolicyList{}
			err := restClient.Get().
				Namespace(metav1.NamespaceAll).
				Resource("networkpolicies").
				VersionedParams(&options, api.ParameterCodec).
				Do().
				Into(result)
			return result, err
		},
		WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
			return restClient.Get().
				Prefix("watch").
				Namespace(metav1.NamespaceAll).
				Resource("networkpolicies").
				VersionedParams(&options, api.ParameterCodec).
				Watch()
		},
	})
}

func (cont *AciController) initNetworkPolicyInformerBase(listWatch *cache.ListWatch) {
	cont.networkPolicyInformer = cache.NewSharedIndexInformer(
		listWatch,
		&v1beta1.NetworkPolicy{},
		controller.NoResyncPeriodFunc(),
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	cont.networkPolicyInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			cont.networkPolicyAdded(obj)
		},
		UpdateFunc: func(oldobj interface{}, newobj interface{}) {
			cont.networkPolicyChanged(oldobj, newobj)
		},
		DeleteFunc: func(obj interface{}) {
			cont.networkPolicyDeleted(obj)
		},
	})

}

func (cont *AciController) ingressPodSelector(np *v1beta1.NetworkPolicy) []index.PodSelector {
	var ret []index.PodSelector

	for _, ingress := range np.Spec.Ingress {
		for _, peer := range ingress.From {
			if peer.PodSelector != nil {
				selector, err :=
					metav1.LabelSelectorAsSelector(peer.PodSelector)
				if err != nil {
					networkPolicyLogger(cont.log, np).
						Error("Could not create selector: ", err)
					continue
				}

				ret = append(ret, index.PodSelector{
					Namespace:   &np.ObjectMeta.Namespace,
					PodSelector: selector,
				})
			} else if peer.NamespaceSelector != nil {
				selector, err := metav1.
					LabelSelectorAsSelector(peer.NamespaceSelector)
				if err != nil {
					networkPolicyLogger(cont.log, np).
						Error("Could not create selector: ", err)
					continue
				}

				ret = append(ret, index.PodSelector{
					NsSelector:  selector,
					PodSelector: labels.Everything(),
				})
			}
		}
	}

	return ret
}

func (cont *AciController) initNetPolPodIndex() {
	cont.netPolPods = index.NewPodSelectorIndex(
		cont.log,
		cont.podInformer,
		cont.namespaceInformer,
		cont.networkPolicyInformer,
		cache.MetaNamespaceKeyFunc,
		func(obj interface{}) []index.PodSelector {
			np := obj.(*v1beta1.NetworkPolicy)
			return index.PodSelectorFromNsAndSelector(np.ObjectMeta.Namespace,
				&np.Spec.PodSelector)
		},
	)
	cont.netPolPods.SetPodUpdateCallback(func(podkey string) {
		podobj, exists, err :=
			cont.podInformer.GetStore().GetByKey(podkey)
		if exists && err == nil {
			cont.queuePodUpdate(podobj.(*v1.Pod))
		}
	})

	cont.netPolIngressPods = index.NewPodSelectorIndex(
		cont.log,
		cont.podInformer,
		cont.namespaceInformer,
		cont.networkPolicyInformer,
		cache.MetaNamespaceKeyFunc,
		func(obj interface{}) []index.PodSelector {
			return cont.ingressPodSelector(obj.(*v1beta1.NetworkPolicy))
		},
	)
}

func networkPolicyLogger(log *logrus.Logger, np *v1beta1.NetworkPolicy) *logrus.Entry {
	return log.WithFields(logrus.Fields{
		"namespace": np.ObjectMeta.Namespace,
		"name":      np.ObjectMeta.Name,
	})
}

func (cont *AciController) networkPolicyAdded(obj interface{}) {
	cont.log.Info("added")
	cont.netPolPods.UpdateSelectorObj(obj)
	cont.netPolIngressPods.UpdateSelectorObj(obj)
}

func (cont *AciController) networkPolicyChanged(oldobj interface{},
	newobj interface{}) {

	oldnp := oldobj.(*v1beta1.NetworkPolicy)
	newnp := newobj.(*v1beta1.NetworkPolicy)

	if !reflect.DeepEqual(&oldnp.Spec.PodSelector, newnp.Spec.PodSelector) {
		cont.netPolPods.UpdateSelectorObj(newobj)
	}
	if !reflect.DeepEqual(oldnp.Spec.Ingress, newnp.Spec.Ingress) {
		cont.netPolIngressPods.UpdateSelectorObj(newobj)
	}
	if !reflect.DeepEqual(oldnp.ObjectMeta.Annotations,
		newnp.ObjectMeta.Annotations) {
		npkey, err :=
			cache.MetaNamespaceKeyFunc(newnp)
		if err != nil {
			networkPolicyLogger(cont.log, newnp).
				Error("Could not create key: ", err)
			return
		}
		for _, podkey := range cont.netPolPods.GetPodForObj(npkey) {
			podobj, exists, err :=
				cont.podInformer.GetStore().GetByKey(podkey)
			if exists && err == nil {
				cont.queuePodUpdate(podobj.(*v1.Pod))
			}
		}
	}

}

func (cont *AciController) networkPolicyDeleted(obj interface{}) {
	cont.netPolPods.DeleteSelectorObj(obj)
	cont.netPolIngressPods.DeleteSelectorObj(obj)
}
