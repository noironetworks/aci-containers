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

// Handlers for network policy updates.  Generate ACI security groups
// based on Kubernetes network policies.

package controller

import (
	"fmt"
	"reflect"
	"sort"
	"strconv"

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

	"github.com/noironetworks/aci-containers/pkg/apicapi"
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

func (cont *AciController) staticNetPolObjs() apicapi.ApicSlice {
	staticName := cont.aciNameForKey("np", "static")
	hpp := apicapi.NewHostprotPol(cont.config.AciPolicyTenant, staticName)
	hppDn := hpp.GetDn()
	{
		egressSubj := apicapi.NewHostprotSubj(hppDn, "egress")
		{
			outbound := apicapi.NewHostprotRule(egressSubj.GetDn(),
				"allow-all-reflexive")
			outbound.SetAttr("direction", "egress")
			outbound.SetAttr("ethertype", "ipv4")
			egressSubj.AddChild(outbound)
		}
		hpp.AddChild(egressSubj)
	}
	{
		discSubj := apicapi.NewHostprotSubj(hppDn, "discovery")
		discDn := discSubj.GetDn()
		{
			arpin := apicapi.NewHostprotRule(discDn, "arp-ingress")
			arpin.SetAttr("direction", "ingress")
			arpin.SetAttr("ethertype", "arp")
			arpin.SetAttr("connTrack", "normal")
			discSubj.AddChild(arpin)
		}
		{
			arpout := apicapi.NewHostprotRule(discDn, "arp-egress")
			arpout.SetAttr("direction", "egress")
			arpout.SetAttr("ethertype", "arp")
			arpout.SetAttr("connTrack", "normal")
			discSubj.AddChild(arpout)
		}
		{
			icmpin := apicapi.NewHostprotRule(discDn, "icmp-ingress")
			icmpin.SetAttr("direction", "ingress")
			icmpin.SetAttr("ethertype", "ipv4")
			icmpin.SetAttr("protocol", "icmp")
			discSubj.AddChild(icmpin)
		}

		hpp.AddChild(discSubj)
	}

	return apicapi.ApicSlice{hpp}
}

func (cont *AciController) initStaticNetPolObjs() {
	cont.apicConn.WriteApicObjects(cont.config.AciPrefix+"_np_static",
		cont.staticNetPolObjs())
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

	labelKey := cont.aciNameForKey("np", key)
	hpp := apicapi.NewHostprotPol(cont.config.AciPolicyTenant, labelKey)
	subj := apicapi.NewHostprotSubj(hpp.GetDn(), "networkpolicy")

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
			rule := apicapi.NewHostprotRule(subj.GetDn(), strconv.Itoa(i))
			rule.SetAttr("direction", "ingress")
			rule.SetAttr("ethertype", "ipv4")
			for _, ip := range remoteIps {
				rule.AddChild(apicapi.NewHostprotRemoteIp(rule.GetDn(), ip))
			}
			subj.AddChild(rule)
		} else {
			for j, p := range ingress.Ports {
				proto := "tcp"
				if p.Protocol != nil && *p.Protocol == v1.ProtocolUDP {
					proto = "udp"
				}

				rule := apicapi.NewHostprotRule(subj.GetDn(),
					strconv.Itoa(i)+"_"+strconv.Itoa(j))
				rule.SetAttr("direction", "ingress")
				rule.SetAttr("ethertype", "ipv4")
				rule.SetAttr("protocol", proto)
				for _, ip := range remoteIps {
					rule.AddChild(apicapi.NewHostprotRemoteIp(rule.GetDn(), ip))
				}

				if p.Port != nil {
					if p.Port.Type == intstr.Int {
						rule.SetAttr("toPort", p.Port.String())
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
				subj.AddChild(rule)
			}
		}

	}

	hpp.AddChild(subj)
	cont.apicConn.WriteApicObjects(labelKey, apicapi.ApicSlice{hpp})
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

	if !reflect.DeepEqual(&oldnp.Spec.PodSelector, newnp.Spec.PodSelector) {
		cont.netPolPods.UpdateSelectorObjNoCallback(newobj)
	}
	if !reflect.DeepEqual(oldnp.Spec.Ingress, newnp.Spec.Ingress) {
		cont.netPolIngressPods.UpdateSelectorObjNoCallback(newobj)
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
	cont.apicConn.ClearApicObjects(cont.aciNameForKey("np", key))
}
