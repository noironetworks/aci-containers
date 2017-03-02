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
	"sort"
	"strconv"
	"strings"

	"github.com/Sirupsen/logrus"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/intstr"
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

func (cont *AciController) queueNetPolUpdate(netpol *v1beta1.NetworkPolicy) {
	key, err := cache.MetaNamespaceKeyFunc(netpol)
	if err != nil {
		networkPolicyLogger(cont.log, netpol).
			Error("Could not create network policy key: ", err)
		return
	}
	cont.netPolQueue.Add(key)
}

func getOpflexGroupNameForNetPol(npkey string) string {
	return strings.Replace(npkey, "/", "_", -1)
}

func (cont *AciController) peerMatchesPod(npNs string,
	peer *v1beta1.NetworkPolicyPeer, pod *v1.Pod, podNs *v1.Namespace) bool {
	if peer.PodSelector != nil && npNs == pod.ObjectMeta.Namespace {
		selector, err :=
			metav1.LabelSelectorAsSelector(peer.PodSelector)
		if err != nil {
			cont.log.Error("Could not parse pod selector: ", err)
		} else {
			return selector.Matches(labels.Set(pod.ObjectMeta.Labels))
		}
	} else if peer.NamespaceSelector != nil {
		selector, err :=
			metav1.LabelSelectorAsSelector(peer.NamespaceSelector)
		if err != nil {
			cont.log.Error("Could not parse namespace selector: ", err)
		} else {
			return selector.Matches(labels.Set(podNs.ObjectMeta.Labels))
		}
	}
	return false
}

func ipsForPod(pod *v1.Pod) []string {
	if pod.Status.PodIP != "" {
		return []string{pod.Status.PodIP}
	}
	return nil
}

func (cont *AciController) handleNetPolUpdate(np *v1beta1.NetworkPolicy) bool {
	key, err := cache.MetaNamespaceKeyFunc(np)
	logger := networkPolicyLogger(cont.log, np)
	if err != nil {
		logger.Error("Could not create network policy key: ", err)
		return false
	}

	peerPodKeys := cont.netPolIngressPods.GetPodForObj(key)
	var peerPods []*v1.Pod
	peerNs := make(map[string]*v1.Namespace)
	for _, podkey := range peerPodKeys {
		podobj, exists, err :=
			cont.podInformer.GetStore().GetByKey(podkey)
		if exists && err == nil {
			pod := podobj.(*v1.Pod)
			if _, nsok := peerNs[pod.ObjectMeta.Namespace]; !nsok {
				nsobj, exists, err :=
					cont.namespaceInformer.GetStore().
						GetByKey(pod.ObjectMeta.Namespace)

				if !exists || err != nil {
					continue
				}
				peerNs[pod.ObjectMeta.Namespace] = nsobj.(*v1.Namespace)
			}
			peerPods = append(peerPods, pod)
		}
	}

	var netPolObjs aciSlice
	labelKey := strings.Replace(key, "/", "_", -1)
	netPolObjs = append(netPolObjs,
		NewSecurityGroup(cont.config.AciTenant, labelKey))
	netPolObjs = append(netPolObjs,
		NewSecurityGroupSubject(cont.config.AciTenant, labelKey, "NetworkPolicy"))
	netPolObjs = append(netPolObjs,
		NewSecurityGroupSubject(cont.config.AciTenant, labelKey, "Egress"))
	outbound := NewSecurityGroupRule(cont.config.AciTenant, labelKey,
		"Egress", "allow-all-reflexive")
	outbound.Spec.SecurityGroupRule.Direction = "egress"
	netPolObjs = append(netPolObjs, outbound)

	for i, ingress := range np.Spec.Ingress {
		var remoteIps []string
		if ingress.From != nil {
			// only applies to matching pods
			for _, pod := range peerPods {
				for _, from := range ingress.From {
					if ns, ok := peerNs[pod.ObjectMeta.Namespace]; ok &&
						cont.peerMatchesPod(np.ObjectMeta.Namespace,
							&from, pod, ns) {
						remoteIps = append(remoteIps, ipsForPod(pod)...)
					}
				}
			}
			sort.Strings(remoteIps)
		}

		if ingress.Ports == nil {
			rule := NewSecurityGroupRule(cont.config.AciTenant, labelKey,
				"NetworkPolicy", strconv.Itoa(i))
			rule.Spec.SecurityGroupRule.Direction = "ingress"
			rule.Spec.SecurityGroupRule.RemoteIps = remoteIps
			netPolObjs = append(netPolObjs, rule)
		} else {
			for j, p := range ingress.Ports {
				proto := "tcp"
				if p.Protocol != nil && *p.Protocol == v1.ProtocolUDP {
					proto = "udp"
				}
				rule := NewSecurityGroupRule(cont.config.AciTenant, labelKey,
					"NetworkPolicy", strconv.Itoa(i)+"_"+strconv.Itoa(j))
				rule.Spec.SecurityGroupRule.Direction = "ingress"
				rule.Spec.SecurityGroupRule.RemoteIps = remoteIps
				rule.Spec.SecurityGroupRule.Ethertype = "ip"
				rule.Spec.SecurityGroupRule.IpProtocol = proto

				if p.Port != nil {
					if p.Port.Type == intstr.Int {
						rule.Spec.SecurityGroupRule.ToPort =
							p.Port.String()
					} else {
						// the spec says that this field can be either
						// an integer or a "named port on a pod".
						// What does it mean for it to be a named
						// port?  On what pod?
						cont.log.Warning("Unsupported use of named "+
							"port in network policy ", key)
						continue
					}
				}
				netPolObjs = append(netPolObjs, rule)
			}
		}

	}

	cont.writeAimObjects("netpol", labelKey, netPolObjs)
	return false
}

func (cont *AciController) networkPolicyAdded(obj interface{}) {
	cont.netPolPods.UpdateSelectorObj(obj)
	cont.netPolIngressPods.UpdateSelectorObj(obj)
	cont.queueNetPolUpdate(obj.(*v1beta1.NetworkPolicy))
}

func (cont *AciController) networkPolicyChanged(oldobj interface{},
	newobj interface{}) {

	oldnp := oldobj.(*v1beta1.NetworkPolicy)
	newnp := newobj.(*v1beta1.NetworkPolicy)

	shouldqueue := false
	if !reflect.DeepEqual(&oldnp.Spec.PodSelector, newnp.Spec.PodSelector) {
		shouldqueue =
			cont.netPolPods.UpdateSelectorObjNoCallback(newobj) || shouldqueue
	}
	if !reflect.DeepEqual(oldnp.Spec.Ingress, newnp.Spec.Ingress) {
		shouldqueue =
			cont.netPolIngressPods.UpdateSelectorObjNoCallback(newobj) ||
				shouldqueue
	}
	if !reflect.DeepEqual(oldnp.ObjectMeta.Annotations,
		newnp.ObjectMeta.Annotations) {
		shouldqueue = true
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
	} else if !reflect.DeepEqual(oldnp.Spec, newnp.Spec) {
		shouldqueue = true
	}

	if shouldqueue {
		cont.queueNetPolUpdate(newnp)
	}
}

func (cont *AciController) networkPolicyDeleted(obj interface{}) {
	cont.netPolPods.DeleteSelectorObj(obj)
	cont.netPolIngressPods.DeleteSelectorObj(obj)

	key, err := cache.MetaNamespaceKeyFunc(obj)
	if err != nil {
		networkPolicyLogger(cont.log, obj.(*v1beta1.NetworkPolicy)).
			Error("Could not create network policy key: ", err)
		return
	}
	cont.clearAimObjects("netpol", strings.Replace(key, "/", "_", -1))
}
