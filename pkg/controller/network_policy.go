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
	"reflect"
	"sort"
	"strconv"

	"github.com/Sirupsen/logrus"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	v1 "k8s.io/client-go/pkg/api/v1"
	v1net "k8s.io/client-go/pkg/apis/networking/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/noironetworks/aci-containers/pkg/apicapi"
	"github.com/noironetworks/aci-containers/pkg/index"
)

func (cont *AciController) initNetworkPolicyInformerFromClient(
	kubeClient kubernetes.Interface) {

	cont.initNetworkPolicyInformerBase(
		cache.NewListWatchFromClient(
			kubeClient.NetworkingV1().RESTClient(), "networkpolicies",
			metav1.NamespaceAll, fields.Everything()))
}

func (cont *AciController) initNetworkPolicyInformerBase(listWatch *cache.ListWatch) {
	cont.networkPolicyIndexer, cont.networkPolicyInformer =
		cache.NewIndexerInformer(
			listWatch, &v1net.NetworkPolicy{}, 0,
			cache.ResourceEventHandlerFuncs{
				AddFunc: func(obj interface{}) {
					cont.networkPolicyAdded(obj)
				},
				UpdateFunc: func(oldobj interface{}, newobj interface{}) {
					cont.networkPolicyChanged(oldobj, newobj)
				},
				DeleteFunc: func(obj interface{}) {
					cont.networkPolicyDeleted(obj)
				},
			},
			cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
		)
}

func (cont *AciController) ingressPodSelector(np *v1net.NetworkPolicy) []index.PodSelector {
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
			}
			if peer.NamespaceSelector != nil {
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
		cont.podIndexer, cont.namespaceIndexer, cont.networkPolicyIndexer,
		cache.MetaNamespaceKeyFunc,
		func(obj interface{}) []index.PodSelector {
			np := obj.(*v1net.NetworkPolicy)
			return index.PodSelectorFromNsAndSelector(np.ObjectMeta.Namespace,
				&np.Spec.PodSelector)
		},
	)
	cont.netPolPods.SetPodUpdateCallback(func(podkey string) {
		podobj, exists, err :=
			cont.podIndexer.GetByKey(podkey)
		if exists && err == nil {
			cont.queuePodUpdate(podobj.(*v1.Pod))
		}
	})

	cont.netPolIngressPods = index.NewPodSelectorIndex(
		cont.log,
		cont.podIndexer, cont.namespaceIndexer, cont.networkPolicyIndexer,
		cache.MetaNamespaceKeyFunc,
		func(obj interface{}) []index.PodSelector {
			return cont.ingressPodSelector(obj.(*v1net.NetworkPolicy))
		},
	)
	cont.netPolIngressPods.SetObjUpdateCallback(func(npkey string) {
		npobj, exists, err := cont.networkPolicyIndexer.GetByKey(npkey)
		if exists && err == nil {
			cont.queueNetPolUpdate(npobj.(*v1net.NetworkPolicy))
		}
	})
	cont.netPolIngressPods.SetPodHashFunc(func(pod *v1.Pod) string {
		return pod.Status.PodIP
	})
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
			icmpin.SetAttr("connTrack", "normal")
			discSubj.AddChild(icmpin)
		}
		{
			icmpout := apicapi.NewHostprotRule(discDn, "icmp-egress")
			icmpout.SetAttr("direction", "egress")
			icmpout.SetAttr("ethertype", "ipv4")
			icmpout.SetAttr("protocol", "icmp")
			icmpout.SetAttr("connTrack", "normal")
			discSubj.AddChild(icmpout)
		}

		hpp.AddChild(discSubj)
	}

	return apicapi.ApicSlice{hpp}
}

func (cont *AciController) initStaticNetPolObjs() {
	cont.apicConn.WriteApicObjects(cont.config.AciPrefix+"_np_static",
		cont.staticNetPolObjs())
}

func networkPolicyLogger(log *logrus.Logger, np *v1net.NetworkPolicy) *logrus.Entry {
	return log.WithFields(logrus.Fields{
		"namespace": np.ObjectMeta.Namespace,
		"name":      np.ObjectMeta.Name,
	})
}

func (cont *AciController) queueNetPolUpdate(netpol *v1net.NetworkPolicy) {
	key, err := cache.MetaNamespaceKeyFunc(netpol)
	if err != nil {
		networkPolicyLogger(cont.log, netpol).
			Error("Could not create network policy key: ", err)
		return
	}
	cont.netPolQueue.Add(key)
}

func (cont *AciController) peerMatchesPod(npNs string,
	peer *v1net.NetworkPolicyPeer, pod *v1.Pod, podNs *v1.Namespace) bool {
	if peer.PodSelector != nil && npNs == pod.ObjectMeta.Namespace {
		selector, err :=
			metav1.LabelSelectorAsSelector(peer.PodSelector)
		if err != nil {
			cont.log.Error("Could not parse pod selector: ", err)
		} else {
			return selector.Matches(labels.Set(pod.ObjectMeta.Labels))
		}
	}
	if peer.NamespaceSelector != nil {
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

func (cont *AciController) handleNetPolUpdate(np *v1net.NetworkPolicy) bool {
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
		podobj, exists, err := cont.podIndexer.GetByKey(podkey)
		if exists && err == nil {
			pod := podobj.(*v1.Pod)
			if _, nsok := peerNs[pod.ObjectMeta.Namespace]; !nsok {
				nsobj, exists, err :=
					cont.namespaceIndexer.GetByKey(pod.ObjectMeta.Namespace)

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
		ipMap := make(map[string]bool)
		if ingress.From != nil {
			// only applies to matching pods
			for _, pod := range peerPods {
				for _, from := range ingress.From {
					if ns, ok := peerNs[pod.ObjectMeta.Namespace]; ok &&
						cont.peerMatchesPod(np.ObjectMeta.Namespace,
							&from, pod, ns) {
						podIps := ipsForPod(pod)
						for _, ip := range podIps {
							if _, exists := ipMap[ip]; !exists {
								ipMap[ip] = true
								remoteIps = append(remoteIps, ip)
							}
						}
					}
				}
			}
			if len(remoteIps) == 0 {
				// ingress matches no pods; don't create the rule
				continue
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
	cont.queueNetPolUpdate(obj.(*v1net.NetworkPolicy))
}

func (cont *AciController) networkPolicyChanged(oldobj interface{},
	newobj interface{}) {

	oldnp := oldobj.(*v1net.NetworkPolicy)
	newnp := newobj.(*v1net.NetworkPolicy)

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
		networkPolicyLogger(cont.log, obj.(*v1net.NetworkPolicy)).
			Error("Could not create network policy key: ", err)
		return
	}
	cont.apicConn.ClearApicObjects(cont.aciNameForKey("np", key))
}
