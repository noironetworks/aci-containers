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
	"net"
	"reflect"
	"sort"
	"strconv"

	"github.com/Sirupsen/logrus"

	v1 "k8s.io/api/core/v1"
	v1net "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"github.com/noironetworks/aci-containers/pkg/apicapi"
	"github.com/noironetworks/aci-containers/pkg/index"
	"github.com/noironetworks/aci-containers/pkg/ipam"
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

func (cont *AciController) getNetPolPolicyTypes(key string) []v1net.PolicyType {
	npobj, exists, err := cont.networkPolicyIndexer.GetByKey(key)
	if !exists || err != nil {
		return nil
	}
	np := npobj.(*v1net.NetworkPolicy)
	if len(np.Spec.PolicyTypes) > 0 {
		cont.log.Info("using policy value ", key, ": ", np.Spec.PolicyTypes)
		return np.Spec.PolicyTypes
	}
	cont.log.Info("using implied ", key, ": ", len(np.Spec.Egress))
	if len(np.Spec.Egress) > 0 {
		return []v1net.PolicyType{
			v1net.PolicyTypeIngress,
			v1net.PolicyTypeEgress,
		}
	} else {
		return []v1net.PolicyType{v1net.PolicyTypeIngress}
	}
}

func (cont *AciController) peerPodSelector(np *v1net.NetworkPolicy,
	peers []v1net.NetworkPolicyPeer) []index.PodSelector {

	var ret []index.PodSelector
	for _, peer := range peers {
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

	return ret
}

func (cont *AciController) egressPodSelector(np *v1net.NetworkPolicy) []index.PodSelector {
	var ret []index.PodSelector

	for _, egress := range np.Spec.Egress {
		ret = append(ret, cont.peerPodSelector(np, egress.To)...)
	}

	return ret
}

func (cont *AciController) ingressPodSelector(np *v1net.NetworkPolicy) []index.PodSelector {
	var ret []index.PodSelector

	for _, ingress := range np.Spec.Ingress {
		ret = append(ret, cont.peerPodSelector(np, ingress.From)...)
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
		podobj, exists, err := cont.podIndexer.GetByKey(podkey)
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
	cont.netPolEgressPods = index.NewPodSelectorIndex(
		cont.log,
		cont.podIndexer, cont.namespaceIndexer, cont.networkPolicyIndexer,
		cache.MetaNamespaceKeyFunc,
		func(obj interface{}) []index.PodSelector {
			return cont.egressPodSelector(obj.(*v1net.NetworkPolicy))
		},
	)
	npupdate := func(npkey string) {
		npobj, exists, err := cont.networkPolicyIndexer.GetByKey(npkey)
		if exists && err == nil {
			cont.queueNetPolUpdate(npobj.(*v1net.NetworkPolicy))
		}
	}
	nphash := func(pod *v1.Pod) string {
		return pod.Status.PodIP
	}
	cont.netPolIngressPods.SetObjUpdateCallback(npupdate)
	cont.netPolIngressPods.SetPodHashFunc(nphash)
	cont.netPolEgressPods.SetObjUpdateCallback(npupdate)
	cont.netPolEgressPods.SetPodHashFunc(nphash)
}

func (cont *AciController) staticNetPolObjs() apicapi.ApicSlice {
	hppIngress :=
		apicapi.NewHostprotPol(cont.config.AciPolicyTenant,
			cont.aciNameForKey("np", "static-ingress"))
	{
		ingressSubj := apicapi.NewHostprotSubj(hppIngress.GetDn(), "ingress")
		{
			outbound := apicapi.NewHostprotRule(ingressSubj.GetDn(),
				"allow-all-reflexive")
			outbound.SetAttr("direction", "ingress")
			outbound.SetAttr("ethertype", "ipv4")
			ingressSubj.AddChild(outbound)
		}
		hppIngress.AddChild(ingressSubj)
	}

	hppEgress :=
		apicapi.NewHostprotPol(cont.config.AciPolicyTenant,
			cont.aciNameForKey("np", "static-egress"))
	{
		egressSubj := apicapi.NewHostprotSubj(hppEgress.GetDn(), "egress")
		{
			outbound := apicapi.NewHostprotRule(egressSubj.GetDn(),
				"allow-all-reflexive")
			outbound.SetAttr("direction", "egress")
			outbound.SetAttr("ethertype", "ipv4")
			egressSubj.AddChild(outbound)
		}
		hppEgress.AddChild(egressSubj)
	}

	hppDiscovery :=
		apicapi.NewHostprotPol(cont.config.AciPolicyTenant,
			cont.aciNameForKey("np", "static-discovery"))
	{
		discSubj := apicapi.NewHostprotSubj(hppDiscovery.GetDn(), "discovery")
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

		hppDiscovery.AddChild(discSubj)
	}

	return apicapi.ApicSlice{hppEgress, hppDiscovery}
}

func (cont *AciController) initStaticNetPolObjs() {
	cont.apicConn.WriteApicObjects(cont.config.AciPrefix+"_np_static",
		cont.staticNetPolObjs())
}

func networkPolicyLogger(log *logrus.Logger,
	np *v1net.NetworkPolicy) *logrus.Entry {
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

func ipBlockToSubnets(ipblock *v1net.IPBlock) ([]string, error) {
	_, nw, err := net.ParseCIDR(ipblock.CIDR)
	if err != nil {
		return nil, err
	}
	ips := ipam.New()
	ips.AddSubnet(nw)
	for _, except := range ipblock.Except {
		_, nw, err = net.ParseCIDR(except)
		if err != nil {
			return nil, err
		}
		ips.RemoveSubnet(nw)
	}
	var subnets []string
	for _, r := range ips.FreeList {
		ipnets := ipam.Range2Cidr(r.Start, r.End)
		for _, n := range ipnets {
			subnets = append(subnets, n.String())
		}
	}
	return subnets, nil
}

func (cont *AciController) buildNetPolSubj(i int,
	subj apicapi.ApicObject, direction string,
	ports []v1net.NetworkPolicyPort, peers []v1net.NetworkPolicyPeer,
	namespace string, peerPods []*v1.Pod, peerNs map[string]*v1.Namespace,
	logger *logrus.Entry) {

	var remoteIps []string
	ipMap := make(map[string]bool)
	if peers != nil {
		// only applies to matching pods
		for _, pod := range peerPods {
			for _, peer := range peers {
				if ns, ok := peerNs[pod.ObjectMeta.Namespace]; ok &&
					cont.peerMatchesPod(namespace,
						&peer, pod, ns) {
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
		for _, peer := range peers {
			if peer.IPBlock == nil {
				continue
			}
			subs, err := ipBlockToSubnets(peer.IPBlock)
			if err != nil {
				logger.Warning("Invalid IPBlock in network policy rule: ", err)
			} else {
				remoteIps = append(remoteIps, subs...)
			}
		}
		if len(remoteIps) == 0 {
			// nonempty Peer matches no pods or IPBlocks; don't
			// create the rule
			return
		}
		sort.Strings(remoteIps)
	}

	if len(ports) == 0 {
		rule := apicapi.NewHostprotRule(subj.GetDn(), strconv.Itoa(i))
		rule.SetAttr("direction", direction)
		rule.SetAttr("ethertype", "ipv4")
		for _, ip := range remoteIps {
			rule.AddChild(apicapi.NewHostprotRemoteIp(rule.GetDn(), ip))
		}
		subj.AddChild(rule)
	} else {
		for j, p := range ports {
			proto := "tcp"
			if p.Protocol != nil && *p.Protocol == v1.ProtocolUDP {
				proto = "udp"
			}

			rule := apicapi.NewHostprotRule(subj.GetDn(),
				strconv.Itoa(i)+"_"+strconv.Itoa(j))
			rule.SetAttr("direction", direction)
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
					logger.Warning("Unsupported use of named " +
						"port in network policy")
					continue
				}
			}
			subj.AddChild(rule)
		}
	}
}

func (cont *AciController) handleNetPolUpdate(np *v1net.NetworkPolicy) bool {
	key, err := cache.MetaNamespaceKeyFunc(np)
	logger := networkPolicyLogger(cont.log, np)
	if err != nil {
		logger.Error("Could not create network policy key: ", err)
		return false
	}

	peerPodKeys := cont.netPolIngressPods.GetPodForObj(key)
	peerPodKeys =
		append(peerPodKeys, cont.netPolEgressPods.GetPodForObj(key)...)
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
	ptypeset := make(map[v1net.PolicyType]bool)
	for _, t := range np.Spec.PolicyTypes {
		ptypeset[t] = true
	}

	labelKey := cont.aciNameForKey("np", key)
	hpp := apicapi.NewHostprotPol(cont.config.AciPolicyTenant, labelKey)

	if np.Spec.PolicyTypes == nil || ptypeset[v1net.PolicyTypeIngress] {
		subjIngress :=
			apicapi.NewHostprotSubj(hpp.GetDn(), "networkpolicy-ingress")
		for i, ingress := range np.Spec.Ingress {
			cont.buildNetPolSubj(i, subjIngress, "ingress",
				ingress.Ports, ingress.From, np.Namespace,
				peerPods, peerNs, logger)
		}
		hpp.AddChild(subjIngress)
	}

	if np.Spec.PolicyTypes == nil || ptypeset[v1net.PolicyTypeEgress] {
		subjEgress :=
			apicapi.NewHostprotSubj(hpp.GetDn(), "networkpolicy-egress")
		for i, egress := range np.Spec.Egress {
			cont.buildNetPolSubj(i, subjEgress, "egress",
				egress.Ports, egress.To, np.Namespace,
				peerPods, peerNs, logger)
		}
		hpp.AddChild(subjEgress)
	}

	cont.apicConn.WriteApicObjects(labelKey, apicapi.ApicSlice{hpp})
	return false
}

func (cont *AciController) networkPolicyAdded(obj interface{}) {
	cont.netPolPods.UpdateSelectorObj(obj)
	cont.netPolIngressPods.UpdateSelectorObj(obj)
	cont.netPolEgressPods.UpdateSelectorObj(obj)
	cont.queueNetPolUpdate(obj.(*v1net.NetworkPolicy))
}

func (cont *AciController) networkPolicyChanged(oldobj interface{},
	newobj interface{}) {

	oldnp := oldobj.(*v1net.NetworkPolicy)
	newnp := newobj.(*v1net.NetworkPolicy)

	if !reflect.DeepEqual(oldnp.Spec.PodSelector, newnp.Spec.PodSelector) {
		cont.netPolPods.UpdateSelectorObjNoCallback(newobj)
	}
	if !reflect.DeepEqual(oldnp.Spec.PolicyTypes, newnp.Spec.PolicyTypes) {
		key, err := cache.MetaNamespaceKeyFunc(newnp)
		if err != nil {
			networkPolicyLogger(cont.log, newnp).
				Error("Could not create network policy key: ", err)
		} else {
			peerPodKeys := cont.netPolPods.GetPodForObj(key)
			for _, podkey := range peerPodKeys {
				cont.podQueue.Add(podkey)
			}
		}
	}
	var queue bool
	if !reflect.DeepEqual(oldnp.Spec.Ingress, newnp.Spec.Ingress) {
		cont.netPolIngressPods.UpdateSelectorObjNoCallback(newobj)
		queue = true
	}
	if !reflect.DeepEqual(oldnp.Spec.Egress, newnp.Spec.Egress) {
		cont.netPolEgressPods.UpdateSelectorObjNoCallback(newobj)
		queue = true
	}
	if queue {
		cont.queueNetPolUpdate(newnp)
	}
}

func (cont *AciController) networkPolicyDeleted(obj interface{}) {
	cont.netPolPods.DeleteSelectorObj(obj)
	cont.netPolIngressPods.DeleteSelectorObj(obj)
	cont.netPolEgressPods.DeleteSelectorObj(obj)

	key, err := cache.MetaNamespaceKeyFunc(obj)
	if err != nil {
		networkPolicyLogger(cont.log, obj.(*v1net.NetworkPolicy)).
			Error("Could not create network policy key: ", err)
		return
	}
	cont.apicConn.ClearApicObjects(cont.aciNameForKey("np", key))
}
