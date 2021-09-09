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
	"bytes"
	"fmt"
	"github.com/sirupsen/logrus"
	"github.com/yl2chen/cidranger"
	"net"
	"reflect"
	"sort"
	"strconv"
	"strings"

	v1betadnsntp "github.com/noironetworks/aci-containers/pkg/dnsnetworkpolicy/apis/dnsnetpolicy/v1beta"
	v1netpol "github.com/noironetworks/aci-containers/pkg/networkpolicy/apis/netpolicy/v1"
	v1 "k8s.io/api/core/v1"
	v1net "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	k8util "k8s.io/kubectl/pkg/util"

	"github.com/noironetworks/aci-containers/pkg/apicapi"
	dnsnetpolclientset "github.com/noironetworks/aci-containers/pkg/dnsnetworkpolicy/clientset/versioned"
	"github.com/noironetworks/aci-containers/pkg/index"
	"github.com/noironetworks/aci-containers/pkg/ipam"
	netpolclientset "github.com/noironetworks/aci-containers/pkg/networkpolicy/clientset/versioned"
	"github.com/noironetworks/aci-containers/pkg/util"
	v1beta "k8s.io/api/discovery/v1beta1"
	"k8s.io/apimachinery/pkg/api/errors"
)

const (
	dnsNetpolCRDName = "dnsnetworkpolicies.aci.dnsnetpol"
)

func dnsnetpolInit(cont *AciController, stopCh <-chan struct{}) {
	cont.log.Debug("Initializing Dns client")
	restconfig := cont.env.RESTConfig()
	dnsNetpolClient, err := dnsnetpolclientset.NewForConfig(restconfig)
	if err != nil {
		cont.log.Errorf("Failed to intialize erspan client")
		return
	}
	cont.initDnsNetworkPolicyInformerFromClient(dnsNetpolClient)
	go cont.dnsNetworkPolicyInformer.Run(stopCh)
	cache.WaitForCacheSync(stopCh, cont.dnsNetworkPolicyInformer.HasSynced)
}

func (cont *AciController) initNetworkPolicyInformerFromClient(
	kubeClient kubernetes.Interface) {
	cont.initk8sNetworkPolicyInformerBase(
		cache.NewListWatchFromClient(
			kubeClient.NetworkingV1().RESTClient(), "networkpolicies",
			metav1.NamespaceAll, fields.Everything()))
}

func (cont *AciController) initInternalNetworkPolicyInformerFromClient(
	netPolClient *netpolclientset.Clientset) {
	cont.initInternalNetworkPolicyInformerBase(
		cache.NewListWatchFromClient(
			netPolClient.AciV1().RESTClient(), "networkpolicies",
			metav1.NamespaceAll, fields.Everything()))
}

func (cont *AciController) initDnsNetworkPolicyInformerFromClient(
	netPolClient *dnsnetpolclientset.Clientset) {
	cont.initdnsNetworkPolicyInformerBase(
		cache.NewListWatchFromClient(
			netPolClient.AciV1beta().RESTClient(), "dnsnetworkpolicies",
			metav1.NamespaceAll, fields.Everything()))
}

func (cont *AciController) initk8sNetworkPolicyInformerBase(listWatch *cache.ListWatch) {
	cont.k8sNetworkPolicyIndexer, cont.k8sNetworkPolicyInformer =
		cache.NewIndexerInformer(
			listWatch, &v1net.NetworkPolicy{}, 0,
			cache.ResourceEventHandlerFuncs{
				AddFunc: func(obj interface{}) {
					cont.k8sNetworkPolicyAdded(obj)
				},
				UpdateFunc: func(_, newobj interface{}) {
					cont.k8sNetworkPolicyUpdated(newobj)
				},
				DeleteFunc: func(obj interface{}) {
					cont.k8sNetworkPolicyDeleted(obj)
				},
			},
			cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
		)
}

func (cont *AciController) initInternalNetworkPolicyInformerBase(listWatch *cache.ListWatch) {
	cont.networkPolicyIndexer, cont.networkPolicyInformer =
		cache.NewIndexerInformer(
			listWatch, &v1netpol.NetworkPolicy{}, 0,
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

func (cont *AciController) initdnsNetworkPolicyInformerBase(listWatch *cache.ListWatch) {
	cont.dnsNetworkPolicyIndexer, cont.dnsNetworkPolicyInformer =
		cache.NewIndexerInformer(
			listWatch, &v1betadnsntp.DnsNetworkPolicy{}, 0,
			cache.ResourceEventHandlerFuncs{
				AddFunc: func(obj interface{}) {
					cont.dnsNetworkPolicyAdded(obj)
				},
				UpdateFunc: func(oldobj interface{}, newobj interface{}) {
					cont.dnsNetworkPolicyUpdated(newobj)
				},
				DeleteFunc: func(obj interface{}) {
					cont.dnsNetworkPolicyDeleted(obj)
				},
			},
			cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
		)
}

func (cont *AciController) getNetPolPolicyTypes(key string) []v1net.PolicyType {
	return util.GetNetPolPolicyTypes(cont.networkPolicyIndexer, key)
}

func (cont *AciController) peerPodSelector(np *v1netpol.NetworkPolicy,
	peers []v1netpol.NetworkPolicyPeer) []index.PodSelector {

	var ret []index.PodSelector
	for _, peer := range peers {
		podselector, err :=
			metav1.LabelSelectorAsSelector(peer.PodSelector)
		if err != nil {
			networkPolicyLogger(cont.log, np).
				Error("Could not create selector: ", err)
			continue
		}
		nsselector, err := metav1.
			LabelSelectorAsSelector(peer.NamespaceSelector)
		if err != nil {
			networkPolicyLogger(cont.log, np).
				Error("Could not create selector: ", err)
			continue
		}

		switch {
		case peer.PodSelector != nil && peer.NamespaceSelector != nil:
			ret = append(ret, index.PodSelector{
				NsSelector:  nsselector,
				PodSelector: podselector,
			})
		case peer.PodSelector != nil:
			ret = append(ret, index.PodSelector{
				Namespace:   &np.ObjectMeta.Namespace,
				PodSelector: podselector,
			})
		case peer.NamespaceSelector != nil:
			ret = append(ret, index.PodSelector{
				NsSelector:  nsselector,
				PodSelector: labels.Everything(),
			})

		}

	}
	return ret
}

func (cont *AciController) egressPodSelector(np *v1netpol.NetworkPolicy) []index.PodSelector {
	var ret []index.PodSelector

	for _, egress := range np.Spec.Egress {
		ret = append(ret, cont.peerPodSelector(np, egress.To)...)
	}

	return ret
}

func (cont *AciController) ingressPodSelector(np *v1netpol.NetworkPolicy) []index.PodSelector {
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
			np := obj.(*v1netpol.NetworkPolicy)
			return index.PodSelectorFromNsAndSelector(np.ObjectMeta.Namespace,
				np.Spec.AppliedTo.PodSelector)
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
			return cont.ingressPodSelector(obj.(*v1netpol.NetworkPolicy))
		},
	)
	cont.netPolEgressPods = index.NewPodSelectorIndex(
		cont.log,
		cont.podIndexer, cont.namespaceIndexer, cont.networkPolicyIndexer,
		cache.MetaNamespaceKeyFunc,
		func(obj interface{}) []index.PodSelector {
			return cont.egressPodSelector(obj.(*v1netpol.NetworkPolicy))
		},
	)
	npupdate := func(npkey string) {
		npobj, exists, err := cont.networkPolicyIndexer.GetByKey(npkey)
		if exists && err == nil {
			cont.queueNetPolUpdate(npobj.(*v1netpol.NetworkPolicy))
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
			if !cont.configuredPodNetworkIps.V6.Empty() {
				outbound := apicapi.NewHostprotRule(ingressSubj.GetDn(),
					"allow-all-reflexive-v6")
				outbound.SetAttr("direction", "ingress")
				outbound.SetAttr("ethertype", "ipv6")
				ingressSubj.AddChild(outbound)
			}
			if !cont.configuredPodNetworkIps.V4.Empty() {
				outbound := apicapi.NewHostprotRule(ingressSubj.GetDn(),
					"allow-all-reflexive")
				outbound.SetAttr("direction", "ingress")
				outbound.SetAttr("ethertype", "ipv4")
				ingressSubj.AddChild(outbound)
			}
		}
		hppIngress.AddChild(ingressSubj)
	}

	hppEgress :=
		apicapi.NewHostprotPol(cont.config.AciPolicyTenant,
			cont.aciNameForKey("np", "static-egress"))
	{
		egressSubj := apicapi.NewHostprotSubj(hppEgress.GetDn(), "egress")
		{
			if !cont.configuredPodNetworkIps.V6.Empty() {
				outbound := apicapi.NewHostprotRule(egressSubj.GetDn(),
					"allow-all-reflexive-v6")
				outbound.SetAttr("direction", "egress")
				outbound.SetAttr("ethertype", "ipv6")
				egressSubj.AddChild(outbound)
			}
			if !cont.configuredPodNetworkIps.V4.Empty() {
				outbound := apicapi.NewHostprotRule(egressSubj.GetDn(),
					"allow-all-reflexive")
				outbound.SetAttr("direction", "egress")
				outbound.SetAttr("ethertype", "ipv4")
				egressSubj.AddChild(outbound)
			}
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
			if !cont.configuredPodNetworkIps.V4.Empty() {
				icmpin := apicapi.NewHostprotRule(discDn, "icmp-ingress")
				icmpin.SetAttr("direction", "ingress")
				icmpin.SetAttr("ethertype", "ipv4")
				icmpin.SetAttr("protocol", "icmp")
				icmpin.SetAttr("connTrack", "normal")
				discSubj.AddChild(icmpin)
			}

			if !cont.configuredPodNetworkIps.V6.Empty() {
				icmpin := apicapi.NewHostprotRule(discDn, "icmpv6-ingress")
				icmpin.SetAttr("direction", "ingress")
				icmpin.SetAttr("ethertype", "ipv6")
				icmpin.SetAttr("protocol", "icmpv6")
				icmpin.SetAttr("connTrack", "normal")
				discSubj.AddChild(icmpin)
			}
		}
		{
			if !cont.configuredPodNetworkIps.V4.Empty() {
				icmpout := apicapi.NewHostprotRule(discDn, "icmp-egress")
				icmpout.SetAttr("direction", "egress")
				icmpout.SetAttr("ethertype", "ipv4")
				icmpout.SetAttr("protocol", "icmp")
				icmpout.SetAttr("connTrack", "normal")
				discSubj.AddChild(icmpout)
			}

			if !cont.configuredPodNetworkIps.V6.Empty() {
				icmpout := apicapi.NewHostprotRule(discDn, "icmpv6-egress")
				icmpout.SetAttr("direction", "egress")
				icmpout.SetAttr("ethertype", "ipv6")
				icmpout.SetAttr("protocol", "icmpv6")
				icmpout.SetAttr("connTrack", "normal")
				discSubj.AddChild(icmpout)
			}
		}

		hppDiscovery.AddChild(discSubj)
	}

	return apicapi.ApicSlice{hppIngress, hppEgress, hppDiscovery}
}

func (cont *AciController) initStaticNetPolObjs() {
	cont.apicConn.WriteApicObjects(cont.config.AciPrefix+"_np_static",
		cont.staticNetPolObjs())
}

func networkPolicyLogger(log *logrus.Logger,
	np *v1netpol.NetworkPolicy) *logrus.Entry {
	return log.WithFields(logrus.Fields{
		"namespace": np.ObjectMeta.Namespace,
		"name":      np.ObjectMeta.Name,
	})
}

func dnsNetworkPolicyLogger(log *logrus.Logger,
	np *v1betadnsntp.DnsNetworkPolicy) *logrus.Entry {
	return log.WithFields(logrus.Fields{
		"namespace": np.ObjectMeta.Namespace,
		"name":      np.ObjectMeta.Name,
	})
}

func k8sNetworkPolicyLogger(log *logrus.Logger,
	np *v1net.NetworkPolicy) *logrus.Entry {
	return log.WithFields(logrus.Fields{
		"namespace": np.ObjectMeta.Namespace,
		"name":      np.ObjectMeta.Name,
	})
}

func (cont *AciController) queueNetPolUpdateByKey(key string) {
	cont.netPolQueue.Add(key)
}

func (cont *AciController) queueNetPolUpdate(netpol *v1netpol.NetworkPolicy) {
	key, err := cache.MetaNamespaceKeyFunc(netpol)
	if err != nil {
		networkPolicyLogger(cont.log, netpol).
			Error("Could not create network policy key: ", err)
		return
	}
	cont.netPolQueue.Add(key)
}

func (cont *AciController) peerMatchesPod(npNs string,
	peer *v1netpol.NetworkPolicyPeer, pod *v1.Pod, podNs *v1.Namespace) bool {
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

func parseCIDR(sub string) *net.IPNet {
	_, netw, err := net.ParseCIDR(sub)
	if err == nil {
		return netw
	}
	ip := net.ParseIP(sub)
	if ip == nil {
		return nil
	}
	var mask net.IPMask
	if ip.To4() != nil {
		mask = net.CIDRMask(32, 32)
	} else if ip.To16() != nil {
		mask = net.CIDRMask(128, 128)
	} else {
		return nil
	}
	return &net.IPNet{
		IP:   ip,
		Mask: mask,
	}
}

func netEqual(a net.IPNet, b net.IPNet) bool {
	return a.IP.Equal(b.IP) && bytes.Equal(a.Mask, b.Mask)
}

func (cont *AciController) updateIpIndexEntry(index cidranger.Ranger,
	subnetStr string, key string, add bool) bool {

	net := parseCIDR(subnetStr)
	if net == nil {
		cont.log.WithFields(logrus.Fields{
			"subnet": subnetStr,
			"netpol": key,
		}).Warning("Invalid subnet or IP")
	}

	entries, err := index.CoveredNetworks(*net)
	if err != nil {
		cont.log.Error("Corrupted subnet index: ", err)
		return false
	}
	if add {
		for _, entryObj := range entries {
			if netEqual(entryObj.Network(), *net) {
				entry := entryObj.(*ipIndexEntry)
				existing := entry.keys[key]
				entry.keys[key] = true
				return !existing
			}
		}

		entry := &ipIndexEntry{
			ipNet: *net,
			keys: map[string]bool{
				key: true,
			},
		}
		index.Insert(entry)
		return true
	} else {
		var existing bool
		for _, entryObj := range entries {
			entry := entryObj.(*ipIndexEntry)
			if entry.keys[key] {
				existing = true
				delete(entry.keys, key)
			}
			if len(entry.keys) == 0 {
				index.Remove(entry.Network())
			}
		}
		return existing
	}
}

func (cont *AciController) updateIpIndex(index cidranger.Ranger,
	oldSubnets map[string]bool, newSubnets map[string]bool, key string) {

	for subStr := range oldSubnets {
		if newSubnets[subStr] {
			continue
		}
		cont.updateIpIndexEntry(index, subStr, key, false)
	}
	for subStr := range newSubnets {
		if oldSubnets[subStr] {
			continue
		}
		cont.updateIpIndexEntry(index, subStr, key, true)
	}
}

func (cont *AciController) updateTargetPortIndex(service bool, key string,
	oldPorts map[string]targetPort, newPorts map[string]targetPort) {
	for portkey := range oldPorts {
		if _, ok := newPorts[portkey]; ok {
			continue
		}

		entry, ok := cont.targetPortIndex[portkey]
		if !ok {
			continue
		}

		if service {
			delete(entry.serviceKeys, key)
		} else {
			delete(entry.networkPolicyKeys, key)
		}
		if len(entry.serviceKeys) == 0 && len(entry.networkPolicyKeys) == 0 {
			delete(cont.targetPortIndex, portkey)
		}
	}
	for portkey, port := range newPorts {
		if _, ok := oldPorts[portkey]; ok {
			continue
		}
		entry := cont.targetPortIndex[portkey]
		if entry == nil {
			entry = &portIndexEntry{
				port:              port,
				serviceKeys:       make(map[string]bool),
				networkPolicyKeys: make(map[string]bool),
			}
			cont.targetPortIndex[portkey] = entry
		} else {
			entry.port.ports = port.ports
		}

		if service {
			entry.serviceKeys[key] = true
		} else {
			entry.networkPolicyKeys[key] = true
		}
	}
}
func (cont *AciController) getPortNumsFromPortName(podKeys []string, portName string) []int {
	var ports []int
	portmap := make(map[int]bool)
	for _, podkey := range podKeys {
		podobj, exists, err := cont.podIndexer.GetByKey(podkey)
		if exists && err == nil {
			pod := podobj.(*v1.Pod)
			port, err := k8util.LookupContainerPortNumberByName(*pod, portName)
			if err != nil {
				continue
			}
			if _, ok := portmap[int(port)]; !ok {
				ports = append(ports, int(port))
				portmap[int(port)] = true
			}
		}
	}
	if len(ports) == 0 {
		cont.log.Infof("No matching portnumbers for portname %s: ", portName)
	}
	cont.log.Debug("PortName: ", portName, "Mapping port numbers: ", ports)
	return ports
}

// get a map of target ports for egress rules that have no "To" clause
func (cont *AciController) getNetPolTargetPorts(np *v1netpol.NetworkPolicy) map[string]targetPort {
	ports := make(map[string]targetPort)
	for _, egress := range np.Spec.Egress {
		if len(egress.To) != 0 && !isNamedPortPresenInNp(np) {
			continue
		}
		for _, port := range egress.Ports {
			if port.Port == nil {
				continue
			}
			proto := v1.ProtocolTCP
			if port.Protocol != nil {
				proto = *port.Protocol
			}
			npKey, _ := cache.MetaNamespaceKeyFunc(np)
			var key string
			var portnums []int
			if port.Port.Type == intstr.Int {
				key = portProto(&proto) + "-num-" + port.Port.String()
				portnums = append(portnums, port.Port.IntValue())
			} else {
				if len(egress.To) != 0 {
					// TODO optimize this code instead going through all matching pods every time
					podKeys := cont.netPolEgressPods.GetPodForObj(npKey)
					portnums = cont.getPortNumsFromPortName(podKeys, port.Port.String())
				} else {
					ctrNmpEntry, ok := cont.ctrPortNameCache[port.Port.String()]
					if ok {
						for key := range ctrNmpEntry.ctrNmpToPods {
							val := strings.Split(key, "-")
							if len(val) != 2 {
								continue
							}
							if val[0] == portProto(&proto) {
								port, _ := strconv.Atoi(val[1])
								portnums = append(portnums, port)
							}
						}
					}
				}
				if len(portnums) == 0 {
					continue
				}
				key = portProto(&proto) + "-name-" + port.Port.String()
			}
			ports[key] = targetPort{
				proto: proto,
				ports: portnums,
			}
		}
	}
	return ports
}

func (cont *AciController) getPeerRemoteSubnets(peers []v1netpol.NetworkPolicyPeer,
	namespace string, peerPods []*v1.Pod, peerNs map[string]*v1.Namespace,
	logger *logrus.Entry) ([]string, map[string]bool) {

	var remoteSubnets []string
	subnetMap := make(map[string]bool)
	if len(peers) > 0 {
		// only applies to matching pods
		for _, pod := range peerPods {
			for _, peer := range peers {
				if ns, ok := peerNs[pod.ObjectMeta.Namespace]; ok &&
					cont.peerMatchesPod(namespace,
						&peer, pod, ns) {
					podIps := ipsForPod(pod)
					for _, ip := range podIps {
						if _, exists := subnetMap[ip]; !exists {
							subnetMap[ip] = true
							remoteSubnets = append(remoteSubnets, ip)
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
				for _, subnet := range subs {
					subnetMap[subnet] = true
				}
				remoteSubnets = append(remoteSubnets, subs...)
			}
		}
	}
	sort.Strings(remoteSubnets)
	return remoteSubnets, subnetMap
}

func buildNetPolSubjRule(subj apicapi.ApicObject, ruleName string,
	direction string, ethertype string, proto string, port string,
	remoteSubnets []string) {

	rule := apicapi.NewHostprotRule(subj.GetDn(), ruleName)
	rule.SetAttr("direction", direction)
	rule.SetAttr("ethertype", ethertype)
	if proto != "" {
		rule.SetAttr("protocol", proto)
	}
	for _, ip := range remoteSubnets {
		rule.AddChild(apicapi.NewHostprotRemoteIp(rule.GetDn(), ip))
	}
	if port != "" {
		rule.SetAttr("toPort", port)
	}

	subj.AddChild(rule)
}

///PolicyUniverse/PolicySpace/test/GbpSecGroup/sec1/GbpSecGroupSubject/sec1_sub1/GbpSecGroupRule/sec1_sub1_rule1/GbpDnsName/google.com
func (cont *AciController) buildNetPolDnsSubjRules(subj apicapi.ApicObject, direction string,
	logger *logrus.Entry, np *v1netpol.NetworkPolicy) {

	if !cont.configuredPodNetworkIps.V4.Empty() {
		buildNetPolSubjDnsRule(subj, strconv.Itoa(0), direction,
			"ipv4", np.Spec.Egress[0].ToFqdn.MatchNames)
		cont.log.Info("buildNetPolSubjDnsRule#: ", subj)
	}
	if !cont.configuredPodNetworkIps.V6.Empty() {
		buildNetPolSubjDnsRule(subj, strconv.Itoa(0), direction,
			"ipv6", np.Spec.Egress[0].ToFqdn.MatchNames)
	}
}

func buildNetPolSubjDnsRule(subj apicapi.ApicObject, ruleName string,
	direction string, ethertype string, dnsNames []string) {
	rule := apicapi.NewHostprotRule(subj.GetDn(), ruleName)
	rule.SetAttr("direction", direction)
	rule.SetAttr("ethertype", ethertype)
	for _, dnsName := range dnsNames {
		rule.AddChild(apicapi.NewHostprotDnsName(rule.GetDn(), dnsName))
	}
	subj.AddChild(rule)
}

func (cont *AciController) buildNetPolSubjRules(ruleName string,
	subj apicapi.ApicObject, direction string, peers []v1netpol.NetworkPolicyPeer,
	remoteSubnets []string, ports []v1netpol.NetworkPolicyPort,
	logger *logrus.Entry, npKey string, np *v1netpol.NetworkPolicy) {

	if len(peers) > 0 && len(remoteSubnets) == 0 {
		// nonempty From matches no pods or IPBlocks; don't
		// create the rule
		return
	}

	if len(ports) == 0 {
		if !cont.configuredPodNetworkIps.V4.Empty() {
			buildNetPolSubjRule(subj, ruleName, direction,
				"ipv4", "", "", remoteSubnets)
		}
		if !cont.configuredPodNetworkIps.V6.Empty() {
			buildNetPolSubjRule(subj, ruleName, direction,
				"ipv6", "", "", remoteSubnets)
		}
	} else {
		for j, p := range ports {
			proto := portProto(p.Protocol)
			var ports []string

			if p.Port != nil {
				if p.Port.Type == intstr.Int {
					ports = append(ports, p.Port.String())
				} else {
					var portnums []int
					if direction == "egress" {
						portnums = append(portnums, cont.getPortNums(&p)...)
					} else {
						// TODO need to handle empty Pod Selector
						if reflect.DeepEqual(np.Spec.AppliedTo.PodSelector, metav1.LabelSelector{}) {
							logger.Warning("Empty PodSelctor for NamedPort is not supported in ingress direction"+
								"port in network policy: ", p.Port.String())
							continue
						}
						podKeys := cont.netPolPods.GetPodForObj(npKey)
						portnums = cont.getPortNumsFromPortName(podKeys, p.Port.String())
					}
					if len(portnums) == 0 {
						logger.Warning("There is no matching  ports in ingress/egress direction "+
							"port in network policy: ", p.Port.String())
						continue
					}
					for _, portnum := range portnums {
						ports = append(ports, strconv.Itoa(portnum))
					}
				}
			}
			for i, port := range ports {
				if !cont.configuredPodNetworkIps.V4.Empty() {
					buildNetPolSubjRule(subj, ruleName+"_"+strconv.Itoa(i+j), direction,
						"ipv4", proto, port, remoteSubnets)
				}
				if !cont.configuredPodNetworkIps.V6.Empty() {
					buildNetPolSubjRule(subj, ruleName+"_"+strconv.Itoa(i+j), direction,
						"ipv6", proto, port, remoteSubnets)
				}
			}
		}
	}
}

func (cont *AciController) getPortNums(port *v1netpol.NetworkPolicyPort) []int {
	portkey := portKey(port)
	cont.indexMutex.Lock()
	defer cont.indexMutex.Unlock()
	cont.log.Debug("PortKey1: ", portkey)
	entry, _ := cont.targetPortIndex[portkey]
	var length int
	if entry == nil || len(entry.port.ports) == 0 {
		return []int{}
	}
	length = len(entry.port.ports)
	ports := make([]int, length)
	if entry != nil {
		copy(ports, entry.port.ports)
	}
	return ports
}
func portProto(protocol *v1.Protocol) string {
	proto := "tcp"
	if protocol != nil && *protocol == v1.ProtocolUDP {
		proto = "udp"
	} else if protocol != nil && *protocol == v1.ProtocolSCTP {
		proto = "sctp"
	}
	return proto
}

func portKey(p *v1netpol.NetworkPolicyPort) string {
	portType := ""
	port := ""
	if p != nil && p.Port != nil {
		if p.Port.Type == intstr.Int {
			portType = "num"
		} else {
			portType = "name"
		}
		port = p.Port.String()
		return portProto(p.Protocol) + "-" + portType + "-" + port
	}
	return ""
}

func checkEndpoints(subnetIndex cidranger.Ranger,
	addresses []v1.EndpointAddress) bool {

	for _, addr := range addresses {
		ip := net.ParseIP(addr.IP)
		if ip == nil {
			return false
		}
		contains, err := subnetIndex.Contains(ip)
		if err != nil || !contains {
			return false
		}
	}

	return true
}
func checkEndpointslices(subnetIndex cidranger.Ranger,
	addresses []string) bool {

	for _, addr := range addresses {
		ip := net.ParseIP(addr)
		if ip == nil {
			return false
		}
		contains, err := subnetIndex.Contains(ip)
		if err != nil || !contains {
			return false
		}
	}
	return true
}

type portRemoteSubnet struct {
	port           *v1netpol.NetworkPolicyPort
	subnetMap      map[string]bool
	hasNamedTarget bool
}

func updatePortRemoteSubnets(portRemoteSubs map[string]*portRemoteSubnet,
	portkey string, port *v1netpol.NetworkPolicyPort, subnetMap map[string]bool,
	hasNamedTarget bool) {

	if prs, ok := portRemoteSubs[portkey]; ok {
		for s := range subnetMap {
			prs.subnetMap[s] = true
		}
		prs.hasNamedTarget = hasNamedTarget || prs.hasNamedTarget
	} else {
		portRemoteSubs[portkey] = &portRemoteSubnet{
			port:           port,
			subnetMap:      subnetMap,
			hasNamedTarget: hasNamedTarget,
		}
	}
}

func portServiceAugmentKey(proto string, port string) string {
	return proto + "-" + port
}

type portServiceAugment struct {
	proto string
	port  string
	ipMap map[string]bool
}

func updateServiceAugment(portAugments map[string]*portServiceAugment,
	proto string, port string, ip string) {
	key := portServiceAugmentKey(proto, port)
	if psa, ok := portAugments[key]; ok {
		psa.ipMap[ip] = true
	} else {
		portAugments[key] = &portServiceAugment{
			proto: proto,
			port:  port,
			ipMap: map[string]bool{ip: true},
		}
	}
}

func updateServiceAugmentForService(portAugments map[string]*portServiceAugment,
	proto string, port string, service *v1.Service) {

	if service.Spec.ClusterIP != "" {
		updateServiceAugment(portAugments,
			proto, port, service.Spec.ClusterIP)
	}
	for _, ig := range service.Status.LoadBalancer.Ingress {
		if ig.IP == "" {
			continue
		}
		updateServiceAugment(portAugments,
			proto, port, ig.IP)
	}

}

// build service augment by matching peers against the endpoints ip
// index
func (cont *AciController) getServiceAugmentBySubnet(subj apicapi.ApicObject,
	prs *portRemoteSubnet, portAugments map[string]*portServiceAugment,
	logger *logrus.Entry) {

	matchedServices := make(map[string]bool)
	subnetIndex := cidranger.NewPCTrieRanger()

	// find candidate service endpoints objects that include
	// endpoints selected by the egress rule
	cont.indexMutex.Lock()
	for sub := range prs.subnetMap {
		net := parseCIDR(sub)
		if net == nil {
			continue
		}
		subnetIndex.Insert(cidranger.NewBasicRangerEntry(*net))

		entries, err := cont.endpointsIpIndex.CoveredNetworks(*net)
		if err != nil {
			logger.Error("endpointsIpIndex corrupted: ", err)
			continue
		}
		for _, entry := range entries {
			e := entry.(*ipIndexEntry)
			for servicekey := range e.keys {
				matchedServices[servicekey] = true
			}
		}
	}
	cont.indexMutex.Unlock()

	// if all endpoints are selected by egress rule, allow egress
	// to the service cluster IP as well as to the endpoints
	// themselves
	for servicekey := range matchedServices {
		serviceobj, _, err := cont.serviceIndexer.GetByKey(servicekey)
		if err != nil {
			logger.Error("Could not lookup service for "+
				servicekey+": ", err.Error())
			continue
		}
		if serviceobj == nil {
			continue
		}
		service := serviceobj.(*v1.Service)
		cont.serviceEndPoints.SetNpServiceAugmentForService(servicekey, service,
			prs, portAugments, subnetIndex, logger)
	}
}

// build service augment by matching against services with a given
// target port
func (cont *AciController) getServiceAugmentByPort(subj apicapi.ApicObject,
	prs *portRemoteSubnet, portAugments map[string]*portServiceAugment,
	logger *logrus.Entry) {

	// nil port means it matches against all ports.  If we're here, it
	// means this is a rule that matches all ports with all
	// destinations, so there's no need to augment anything.
	if prs.port == nil ||
		prs.port.Port == nil {
		return
	}

	portkey := portKey(prs.port)
	cont.indexMutex.Lock()
	//var serviceKeys []string
	entries := make(map[string]*portIndexEntry)
	entry, _ := cont.targetPortIndex[portkey]
	if entry != nil && prs.port.Port.Type == intstr.String {
		for _, port := range entry.port.ports {
			portstring := strconv.Itoa(port)
			key := portProto(prs.port.Protocol) + "-" + "num" + "-" + portstring
			portEntry, _ := cont.targetPortIndex[key]
			if portEntry != nil {
				entries[portstring] = portEntry
			}
		}
	} else if entry != nil {
		if len(entry.port.ports) > 0 {
			entries[strconv.Itoa(entry.port.ports[0])] = entry
		}
	}
	for key, portentry := range entries {
		for servicekey := range portentry.serviceKeys {
			serviceobj, _, err := cont.serviceIndexer.GetByKey(servicekey)
			if err != nil {
				logger.Error("Could not lookup service for "+
					servicekey+": ", err.Error())
				continue
			}
			if serviceobj == nil {
				continue
			}
			service := serviceobj.(*v1.Service)

			for _, svcPort := range service.Spec.Ports {
				if svcPort.Protocol != *prs.port.Protocol ||
					svcPort.TargetPort.String() !=
						key {
					continue
				}
				proto := portProto(&svcPort.Protocol)
				port := strconv.Itoa(int(svcPort.Port))

				updateServiceAugmentForService(portAugments,
					proto, port, service)

				logger.WithFields(logrus.Fields{
					"proto":   proto,
					"port":    port,
					"service": servicekey,
				}).Debug("Allowing egress for service by port")
			}
		}
	}
	cont.indexMutex.Unlock()
}

// The egress NetworkPolicy API were designed with the iptables
// implementation in mind and don't contemplate that the layer 4 load
// balancer could happen separately from the policy.  In particular,
// it expects load balancer operations to be applied before the policy
// is applied in both directions, so network policies would apply only
// to pods and not to service IPs. This presents a problem for egress
// policies on ACI since the security groups are applied before load
// balancer operations when egressing, and after when ingressing.
//
// To solve this problem, we use some indexes to discover situations
// when an egress policy covers all the endpoints associated with a
// particular service, and automatically add a rule that allows egress
// to the corresponding service cluster IP and ports.
//
// Note that this differs slightly from the behavior you'd see if you
// applied the load balancer rule first: If the egress policy allows
// access to a subset of the allowed IPs you'd see random failures
// depending on which destination is chosen, while with this approach
// it's all or nothing.  This should not impact any correctly-written
// network policies.
//
// To do this, we work first from the set of pods and subnets matches
// by the egress policy.  We use this to find using the
// endpointsIpIndex all services that contain at least one of the
// matched pods or subnets.  For each of these candidate services, we
// find service ports for which _all_ referenced endpoints are allowed
// by the egress policy.  Note that a service will have the service
// port and the target port; the NetworkPolicy (confusingly) refers to
// the target port.
//
// Once confirmed matches are found, we augment the egress policy with
// extra rules to allow egress to the service IPs and service ports.
//
// As a special case, for rules that match everything, we also have a
// backup index that works through ports which should allow more
// efficient matching when allowing egress to all.
func (cont *AciController) buildServiceAugment(subj apicapi.ApicObject,
	portRemoteSubs map[string]*portRemoteSubnet, logger *logrus.Entry) {

	portAugments := make(map[string]*portServiceAugment)
	for _, prs := range portRemoteSubs {
		// TODO ipv6
		if prs.subnetMap["0.0.0.0/0"] {
			cont.getServiceAugmentByPort(subj, prs, portAugments, logger)
		} else {
			cont.getServiceAugmentBySubnet(subj, prs, portAugments, logger)
		}
	}
	for _, augment := range portAugments {
		var remoteIpsv4 []string
		var remoteIpsv6 []string
		for ipstr := range augment.ipMap {
			ip := net.ParseIP(ipstr)
			if ip == nil {
				continue
			} else if ip.To4() != nil {
				remoteIpsv4 = append(remoteIpsv4, ipstr)
			} else if ip.To16() != nil {
				remoteIpsv6 = append(remoteIpsv6, ipstr)
			}
		}
		cont.log.Debug("Service Augment: ", augment)
		if len(remoteIpsv4) > 0 {
			buildNetPolSubjRule(subj,
				"service_"+augment.proto+"_"+augment.port,
				"egress", "ipv4", augment.proto, augment.port, remoteIpsv4)
		}
		if len(remoteIpsv6) > 0 {
			buildNetPolSubjRule(subj,
				"service_"+augment.proto+"_"+augment.port,
				"egress", "ipv6", augment.proto, augment.port, remoteIpsv6)
		}
	}
}

func (cont *AciController) handleNetPolUpdate(np *v1netpol.NetworkPolicy) bool {
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
	// Generate ingress policies
	if (np.Spec.PolicyTypes == nil || ptypeset[v1net.PolicyTypeIngress]) &&
		(np.Spec.Type != v1netpol.DnsAwareNetworkPolicy) {
		subjIngress :=
			apicapi.NewHostprotSubj(hpp.GetDn(), "networkpolicy-ingress")
		for i, ingress := range np.Spec.Ingress {
			remoteSubnets, _ := cont.getPeerRemoteSubnets(ingress.From,
				np.Namespace, peerPods, peerNs, logger)
			cont.buildNetPolSubjRules(strconv.Itoa(i), subjIngress,
				"ingress", ingress.From, remoteSubnets, ingress.Ports, logger, key, np)
		}
		hpp.AddChild(subjIngress)
	}
	// Generate egress policies
	if np.Spec.PolicyTypes == nil || ptypeset[v1net.PolicyTypeEgress] {
		subjEgress :=
			apicapi.NewHostprotSubj(hpp.GetDn(), "networkpolicy-egress")
		if np.Spec.Type == v1netpol.DnsAwareNetworkPolicy {
			cont.buildNetPolDnsSubjRules(subjEgress, "egress", logger, np)
		} else {
			portRemoteSubs := make(map[string]*portRemoteSubnet)

			for i, egress := range np.Spec.Egress {
				remoteSubnets, subnetMap := cont.getPeerRemoteSubnets(egress.To,
					np.Namespace, peerPods, peerNs, logger)
				cont.buildNetPolSubjRules(strconv.Itoa(i), subjEgress,
					"egress", egress.To, remoteSubnets, egress.Ports, logger, key, np)

				// creating a rule to egress to all on a given port needs
				// to enable access to any service IPs/ports that have
				// that port as their target port.
				if len(egress.To) == 0 {
					subnetMap = map[string]bool{
						"0.0.0.0/0": true,
					}
				}
				for _, p := range egress.Ports {
					portkey := portKey(&p)
					port := p
					updatePortRemoteSubnets(portRemoteSubs, portkey, &port, subnetMap,
						p.Port != nil && p.Port.Type == intstr.Int)
				}
				if len(egress.Ports) == 0 {
					updatePortRemoteSubnets(portRemoteSubs, "", nil, subnetMap,
						false)
				}
			}
			cont.buildServiceAugment(subjEgress, portRemoteSubs, logger)
		}
		hpp.AddChild(subjEgress)
	}
	cont.log.Info("HPP ##: ", hpp)
	cont.apicConn.WriteApicObjects(labelKey, apicapi.ApicSlice{hpp})
	return false
}

func getNetworkPolicyEgressIpBlocks(np *v1netpol.NetworkPolicy) map[string]bool {
	subnets := make(map[string]bool)

	for _, egress := range np.Spec.Egress {
		for _, to := range egress.To {
			if to.IPBlock != nil && to.IPBlock.CIDR != "" {
				subnets[to.IPBlock.CIDR] = true
			}
		}
	}
	return subnets
}

func (cont *AciController) k8sNetworkPolicyAdded(obj interface{}) {
	np := obj.(*v1net.NetworkPolicy)
	_, err := cache.MetaNamespaceKeyFunc(np)
	if err != nil {
		//networkPolicyLogger(cont.log, np).
		//	Error("Could not create network policy key: ", err)
		return
	}
	cont.createInternalNetPol(np)
}

func (cont *AciController) k8sNetworkPolicyUpdated(obj interface{}) {
	np := obj.(*v1net.NetworkPolicy)
	_, err := cache.MetaNamespaceKeyFunc(np)
	if err != nil {
		//networkPolicyLogger(cont.log, np).
		//	Error("Could not create network policy key: ", err)
		return
	}
	cont.updateInternalNetPol(np)
}

func (cont *AciController) createInternalNetPol(obj interface{}) {
	np := util.GetInternalPolicy(obj)
	err := util.GetNetPol(cont.env.(*K8sEnvironment).netPolClient, np.ObjectMeta.Namespace, np.ObjectMeta.Name)
	if errors.IsNotFound(err) {
		err := util.CreateNetPol(cont.env.(*K8sEnvironment).netPolClient, np)
		if err != nil {
			cont.log.Error("Failed to Create Internal Policy#: ", err)
			// requeue
		}
	} else {
		err := util.UpdateNetPol(cont.env.(*K8sEnvironment).netPolClient, np)
		if err != nil {
			// requeue
		}
	}
}

func (cont *AciController) updateInternalNetPol(obj interface{}) {
	err := util.UpdateNetPol(cont.env.(*K8sEnvironment).netPolClient, util.GetInternalPolicy(obj))
	if err != nil {
		// requeue
	}
}

func (cont *AciController) deleteInternalNetPol(obj interface{}) {
	object := util.GetInternalPolicy(obj)
	err := util.DeleteNetPol(cont.env.(*K8sEnvironment).netPolClient, object.ObjectMeta.Name, object.ObjectMeta.Namespace)
	if err != nil {
		// requeue
	}
}

func (cont *AciController) k8sNetworkPolicyDeleted(obj interface{}) {
	np, isNetworkpolicy := obj.(*v1net.NetworkPolicy)
	if !isNetworkpolicy {
		deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			k8sNetworkPolicyLogger(cont.log, np).
				Error("Received unexpected object: ", obj)
			return
		}
		np, ok = deletedState.Obj.(*v1net.NetworkPolicy)
		if !ok {
			k8sNetworkPolicyLogger(cont.log, np).
				Error("DeletedFinalStateUnknown contained non-Networkpolicy object: ", deletedState.Obj)
			return
		}
	}
	_, err := cache.MetaNamespaceKeyFunc(np)
	if err != nil {
		k8sNetworkPolicyLogger(cont.log, np).
			Error("Could not create network policy key: ", err)
		return
	}
	cont.deleteInternalNetPol(obj)
}
func (cont *AciController) dnsNetworkPolicyAdded(obj interface{}) {
	np := obj.(*v1betadnsntp.DnsNetworkPolicy)
	_, err := cache.MetaNamespaceKeyFunc(np)
	if err != nil {
		//networkPolicyLogger(cont.log, np).
		//	Error("Could not create network policy key: ", err)
		return
	}
	cont.createInternalNetPol(np)
	cont.log.Info("DNSpolicy Created#: ", np.Spec)
}

func (cont *AciController) dnsNetworkPolicyUpdated(obj interface{}) {
	np := obj.(*v1betadnsntp.DnsNetworkPolicy)
	_, err := cache.MetaNamespaceKeyFunc(np)
	if err != nil {
		//networkPolicyLogger(cont.log, np).
		//	Error("Could not create network policy key: ", err)
		return
	}
	cont.updateInternalNetPol(np)
	cont.log.Info("DNSpolicy Upated #: ", np.Spec)
}

func (cont *AciController) dnsNetworkPolicyDeleted(obj interface{}) {
	np, isNetworkpolicy := obj.(*v1betadnsntp.DnsNetworkPolicy)
	if !isNetworkpolicy {
		deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			dnsNetworkPolicyLogger(cont.log, np).
				Error("Received unexpected object: ", obj)
			return
		}
		np, ok = deletedState.Obj.(*v1betadnsntp.DnsNetworkPolicy)
		if !ok {
			dnsNetworkPolicyLogger(cont.log, np).
				Error("DeletedFinalStateUnknown contained non-Networkpolicy object: ", deletedState.Obj)
			return
		}
	}
	_, err := cache.MetaNamespaceKeyFunc(np)
	if err != nil {
		dnsNetworkPolicyLogger(cont.log, np).
			Error("Could not create network policy key: ", err)
		return
	}
	cont.deleteInternalNetPol(obj)
}

func (cont *AciController) networkPolicyAdded(obj interface{}) {
	np := obj.(*v1netpol.NetworkPolicy)
	npkey, err := cache.MetaNamespaceKeyFunc(np)
	if err != nil {
		networkPolicyLogger(cont.log, np).
			Error("Could not create network policy key: ", err)
		return
	}
	cont.writeApicNP(npkey, np)
	cont.netPolPods.UpdateSelectorObj(obj)
	if np.Spec.Type != v1netpol.DnsAwareNetworkPolicy {
		cont.netPolIngressPods.UpdateSelectorObj(obj)
		cont.netPolEgressPods.UpdateSelectorObj(obj)
		cont.indexMutex.Lock()
		subnets := getNetworkPolicyEgressIpBlocks(np)
		cont.updateIpIndex(cont.netPolSubnetIndex, nil, subnets, npkey)

		ports := cont.getNetPolTargetPorts(np)
		cont.updateTargetPortIndex(false, npkey, nil, ports)
		if isNamedPortPresenInNp(np) {
			cont.nmPortNp[npkey] = true
		}
		cont.indexMutex.Unlock()
	}
	cont.queueNetPolUpdateByKey(npkey)
}

func (cont *AciController) writeApicNP(npKey string, np *v1netpol.NetworkPolicy) {
	if cont.config.LBType == lbTypeAci {
		return
	}

	npObj := apicapi.NewVmmInjectedNwPol(cont.vmmDomainProvider(),
		cont.config.AciVmmDomain, cont.config.AciVmmController,
		np.ObjectMeta.Namespace, np.ObjectMeta.Name)
	setAttr := func(name, attr string) {
		if attr != "" {
			npObj.SetAttr(name, attr)
		}
	}
	setAttr("ingress", ingressStr(np))
	setAttr("egress", egressStr(np))
	key := cont.aciNameForKey("NwPol", npKey)
	cont.log.Debugf("Writing %s %+v", key, npObj)
	cont.apicConn.WriteApicObjects(key, apicapi.ApicSlice{npObj})
}

func peersToStr(peers []v1netpol.NetworkPolicyPeer) string {
	pStr := "["
	for _, p := range peers {
		if p.IPBlock != nil {
			pStr += p.IPBlock.CIDR
			if len(p.IPBlock.Except) != 0 {
				pStr += "[except"
				for _, e := range p.IPBlock.Except {
					pStr += fmt.Sprintf("-%s", e)
				}
				pStr += "]"
			}
			pStr += "+"
		}
	}

	pStr = strings.TrimSuffix(pStr, "+")
	pStr += "]"
	return pStr
}

func portsToStr(ports []v1netpol.NetworkPolicyPort) string {
	pStr := "["

	for _, p := range ports {
		if p.Protocol != nil {
			pStr += string(*p.Protocol)
		}
		if p.Port != nil {
			pStr += ":" + p.Port.String()
		}
		pStr += "+"
	}

	pStr = strings.TrimSuffix(pStr, "+")
	pStr += "]"
	return pStr

}

func ingressStr(np *v1netpol.NetworkPolicy) string {
	iStr := ""
	for _, rule := range np.Spec.Ingress {
		iStr += peersToStr(rule.From)
		iStr += ":" + portsToStr(rule.Ports)
		iStr += "+"
	}
	iStr = strings.TrimSuffix(iStr, "+")
	return iStr
}

func egressStr(np *v1netpol.NetworkPolicy) string {
	eStr := ""
	for _, rule := range np.Spec.Egress {
		eStr += peersToStr(rule.To)
		eStr += ":" + portsToStr(rule.Ports)
		eStr += "+"
	}
	eStr = strings.TrimSuffix(eStr, "+")
	return eStr
}

func (cont *AciController) networkPolicyChanged(oldobj interface{},
	newobj interface{}) {

	oldnp := oldobj.(*v1netpol.NetworkPolicy)
	newnp := newobj.(*v1netpol.NetworkPolicy)
	npkey, err := cache.MetaNamespaceKeyFunc(newnp)
	if err != nil {
		networkPolicyLogger(cont.log, newnp).
			Error("Could not create network policy key: ", err)
		return
	}

	cont.writeApicNP(npkey, newnp)
	cont.indexMutex.Lock()
	oldSubnets := getNetworkPolicyEgressIpBlocks(oldnp)
	newSubnets := getNetworkPolicyEgressIpBlocks(newnp)
	cont.updateIpIndex(cont.netPolSubnetIndex, oldSubnets, newSubnets, npkey)

	oldPorts := cont.getNetPolTargetPorts(oldnp)
	newPorts := cont.getNetPolTargetPorts(newnp)
	cont.updateTargetPortIndex(false, npkey, oldPorts, newPorts)
	cont.indexMutex.Unlock()

	if !reflect.DeepEqual(oldnp.Spec.AppliedTo, newnp.Spec.AppliedTo) {
		cont.netPolPods.UpdateSelectorObjNoCallback(newobj)
	}
	if !reflect.DeepEqual(oldnp.Spec.PolicyTypes, newnp.Spec.PolicyTypes) {
		peerPodKeys := cont.netPolPods.GetPodForObj(npkey)
		for _, podkey := range peerPodKeys {
			cont.podQueue.Add(podkey)
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
		cont.queueNetPolUpdateByKey(npkey)
	}
}

func (cont *AciController) networkPolicyDeleted(obj interface{}) {
	np, isNetworkpolicy := obj.(*v1netpol.NetworkPolicy)
	if !isNetworkpolicy {
		deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			networkPolicyLogger(cont.log, np).
				Error("Received unexpected object: ", obj)
			return
		}
		np, ok = deletedState.Obj.(*v1netpol.NetworkPolicy)
		if !ok {
			networkPolicyLogger(cont.log, np).
				Error("DeletedFinalStateUnknown contained non-Networkpolicy object: ", deletedState.Obj)
			return
		}
	}
	npkey, err := cache.MetaNamespaceKeyFunc(np)
	if err != nil {
		networkPolicyLogger(cont.log, np).
			Error("Could not create network policy key: ", err)
		return
	}

	if cont.config.LBType != lbTypeAci {
		cont.apicConn.ClearApicObjects(cont.aciNameForKey("NwPol", npkey))
	}
	cont.indexMutex.Lock()
	subnets := getNetworkPolicyEgressIpBlocks(np)
	cont.updateIpIndex(cont.netPolSubnetIndex, subnets, nil, npkey)

	ports := cont.getNetPolTargetPorts(np)
	cont.updateTargetPortIndex(false, npkey, ports, nil)
	if isNamedPortPresenInNp(np) {
		delete(cont.nmPortNp, npkey)
	}
	cont.indexMutex.Unlock()

	cont.netPolPods.DeleteSelectorObj(obj)
	cont.netPolIngressPods.DeleteSelectorObj(obj)
	cont.netPolEgressPods.DeleteSelectorObj(obj)
	cont.apicConn.ClearApicObjects(cont.aciNameForKey("np", npkey))
}

func (sep *serviceEndpoint) SetNpServiceAugmentForService(servicekey string, service *v1.Service, prs *portRemoteSubnet,
	portAugments map[string]*portServiceAugment, subnetIndex cidranger.Ranger, logger *logrus.Entry) {
	cont := sep.cont
	endpointsobj, _, err := cont.endpointsIndexer.GetByKey(servicekey)
	if err != nil {
		logger.Error("Could not lookup endpoints for "+
			servicekey+": ", err.Error())
		return
	}
	if endpointsobj == nil {
		return
	}
	endpoints := endpointsobj.(*v1.Endpoints)
	portstrings := make(map[string]bool)
	ports := cont.getPortNums(prs.port)
	for _, port := range ports {
		portstrings[strconv.Itoa(port)] = true
	}
	for _, svcPort := range service.Spec.Ports {
		_, ok := portstrings[svcPort.TargetPort.String()]
		if prs.port != nil &&
			(svcPort.Protocol != *prs.port.Protocol || !ok) {
			// egress rule does not match service target port
			continue
		}
		for _, subset := range endpoints.Subsets {
			var foundEpPort *v1.EndpointPort
			for _, endpointPort := range subset.Ports {
				if endpointPort.Name == svcPort.Name ||
					(len(service.Spec.Ports) == 1 &&
						endpointPort.Name == "") {
					foundEpPort = &endpointPort
					break
				}
			}
			if foundEpPort == nil {
				continue
			}

			incomplete := false
			incomplete = incomplete ||
				!checkEndpoints(subnetIndex, subset.Addresses)
			incomplete = incomplete || !checkEndpoints(subnetIndex,
				subset.NotReadyAddresses)

			if incomplete {
				continue
			}

			proto := portProto(&foundEpPort.Protocol)
			port := strconv.Itoa(int(svcPort.Port))
			updateServiceAugmentForService(portAugments,
				proto, port, service)

			logger.WithFields(logrus.Fields{
				"proto":   proto,
				"port":    port,
				"service": servicekey,
			}).Debug("Allowing egress for service by subnet match")
		}
	}
}

func (seps *serviceEndpointSlice) SetNpServiceAugmentForService(servicekey string, service *v1.Service,
	prs *portRemoteSubnet, portAugments map[string]*portServiceAugment,
	subnetIndex cidranger.Ranger, logger *logrus.Entry) {
	cont := seps.cont
	portstrings := make(map[string]bool)
	ports := cont.getPortNums(prs.port)
	for _, port := range ports {
		portstrings[strconv.Itoa(port)] = true
	}
	label := map[string]string{"kubernetes.io/service-name": service.ObjectMeta.Name}
	selector := labels.SelectorFromSet(labels.Set(label))
	cache.ListAllByNamespace(cont.endpointSliceIndexer, service.ObjectMeta.Namespace, selector,
		func(endpointSliceobj interface{}) {
			endpointSlices := endpointSliceobj.(*v1beta.EndpointSlice)
			for _, svcPort := range service.Spec.Ports {
				_, ok := portstrings[svcPort.TargetPort.String()]
				if prs.port != nil &&
					(svcPort.Protocol != *prs.port.Protocol || !ok) {
					// egress rule does not match service target port
					continue
				}
				var foundEpPort *v1beta.EndpointPort
				for _, endpointPort := range endpointSlices.Ports {
					if *endpointPort.Name == svcPort.Name ||
						(len(service.Spec.Ports) == 1 &&
							*endpointPort.Name == "") {
						foundEpPort = &endpointPort
						cont.log.Debug("Found EpPort: ", foundEpPort)
						break
					}
				}
				if foundEpPort == nil {
					return
				}
				// @FIXME for non ready address
				incomplete := false
				for _, endpoint := range endpointSlices.Endpoints {
					incomplete = incomplete || !checkEndpointslices(subnetIndex, endpoint.Addresses)
				}
				if incomplete {
					continue
				}
				proto := portProto(foundEpPort.Protocol)
				port := strconv.Itoa(int(svcPort.Port))
				cont.log.Debug("updateServiceAugmentForService: ", service)
				updateServiceAugmentForService(portAugments,
					proto, port, service)

				logger.WithFields(logrus.Fields{
					"proto":   proto,
					"port":    port,
					"service": servicekey,
				}).Debug("Allowing egress for service by subnet match")
			}
		})
}

func isNamedPortPresenInNp(np *v1netpol.NetworkPolicy) bool {
	for _, egress := range np.Spec.Egress {
		for _, p := range egress.Ports {
			if p.Port.Type == intstr.String {
				return true
			}
		}
	}
	return false
}

func (cont *AciController) checkPodNmpMatchesNp(npkey, podkey string) bool {
	podobj, exists, err := cont.podIndexer.GetByKey(podkey)
	if err != nil {
		return false
	}
	if !exists || podobj == nil {
		return false
	}
	pod := podobj.(*v1.Pod)
	npobj, npexists, nperr := cont.networkPolicyIndexer.GetByKey(npkey)
	if npexists && nperr == nil && npobj != nil {
		np := npobj.(*v1netpol.NetworkPolicy)
		for _, egress := range np.Spec.Egress {
			for _, p := range egress.Ports {
				if p.Port.Type == intstr.String {
					_, err := k8util.LookupContainerPortNumberByName(*pod, p.Port.String())
					if err == nil {
						return true
					}
				}
			}
		}
	}
	return false
}
