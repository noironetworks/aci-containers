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
	"net"
	"reflect"
	"sort"
	"strconv"

	"github.com/Sirupsen/logrus"
	"github.com/yl2chen/cidranger"

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
	"github.com/noironetworks/aci-containers/pkg/util"
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
	return util.GetNetPolPolicyTypes(cont.networkPolicyIndexer, key)
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
	np *v1net.NetworkPolicy) *logrus.Entry {
	return log.WithFields(logrus.Fields{
		"namespace": np.ObjectMeta.Namespace,
		"name":      np.ObjectMeta.Name,
	})
}

func (cont *AciController) queueNetPolUpdateByKey(key string) {
	cont.netPolQueue.Add(key)
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
		}

		if service {
			entry.serviceKeys[key] = true
		} else {
			entry.networkPolicyKeys[key] = true
		}
	}
}

// get a map of target ports for egress rules that have no "To" clause
func getNetPolTargetPorts(np *v1net.NetworkPolicy) map[string]targetPort {
	ports := make(map[string]targetPort)
	for _, egress := range np.Spec.Egress {
		if len(egress.To) != 0 {
			continue
		}
		for _, port := range egress.Ports {
			if port.Port == nil || port.Port.Type != intstr.Int {
				continue
			}
			proto := v1.ProtocolTCP
			if port.Protocol != nil {
				proto = *port.Protocol
			}
			key := portProto(&proto) + "-num-" + port.Port.String()
			ports[key] = targetPort{
				proto: proto,
				port:  port.Port.IntValue(),
			}
		}
	}
	return ports
}

func (cont *AciController) getPeerRemoteSubnets(peers []v1net.NetworkPolicyPeer,
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

func (cont *AciController) buildNetPolSubjRules(ruleName string,
	subj apicapi.ApicObject, direction string, peers []v1net.NetworkPolicyPeer,
	remoteSubnets []string, ports []v1net.NetworkPolicyPort,
	logger *logrus.Entry) {

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
			port := ""

			if p.Port != nil {
				if p.Port.Type == intstr.Int {
					port = p.Port.String()
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
			if !cont.configuredPodNetworkIps.V4.Empty() {
				buildNetPolSubjRule(subj, ruleName+"_"+strconv.Itoa(j), direction,
					"ipv4", proto, port, remoteSubnets)
			}
			if !cont.configuredPodNetworkIps.V6.Empty() {
				buildNetPolSubjRule(subj, ruleName+"_"+strconv.Itoa(j), direction,
					"ipv6", proto, port, remoteSubnets)
			}
		}
	}
}

func portProto(protocol *v1.Protocol) string {
	proto := "tcp"
	if protocol != nil && *protocol == v1.ProtocolUDP {
		proto = "udp"
	}
	return proto
}

func portKey(p *v1net.NetworkPolicyPort) string {
	portType := ""
	port := ""
	if p.Port != nil {
		if p.Port.Type == intstr.Int {
			portType = "num"
		} else {
			portType = "name"
		}
		port = p.Port.String()
	}
	return portProto(p.Protocol) + "-" + portType + "-" + port
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

type portRemoteSubnet struct {
	port           *v1net.NetworkPolicyPort
	subnetMap      map[string]bool
	hasNamedTarget bool
}

func updatePortRemoteSubnets(portRemoteSubs map[string]*portRemoteSubnet,
	portkey string, port *v1net.NetworkPolicyPort, subnetMap map[string]bool,
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
		endpointsobj, _, err := cont.endpointsIndexer.GetByKey(servicekey)
		if err != nil {
			logger.Error("Could not lookup endpoints for "+
				servicekey+": ", err.Error())
			continue
		}
		if serviceobj == nil || endpointsobj == nil {
			continue
		}
		service := serviceobj.(*v1.Service)
		endpoints := endpointsobj.(*v1.Endpoints)

		for _, svcPort := range service.Spec.Ports {
			if prs.port != nil &&
				(svcPort.Protocol != *prs.port.Protocol ||
					svcPort.TargetPort.String() !=
						prs.port.Port.String()) {
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
		prs.port.Port == nil || prs.port.Port.Type != intstr.Int {
		return
	}

	portkey := portKey(prs.port)
	cont.indexMutex.Lock()
	entry, _ := cont.targetPortIndex[portkey]
	if entry != nil {
		for servicekey := range entry.serviceKeys {
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
						prs.port.Port.String() {
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

	// Generate ingress policies
	if np.Spec.PolicyTypes == nil || ptypeset[v1net.PolicyTypeIngress] {
		subjIngress :=
			apicapi.NewHostprotSubj(hpp.GetDn(), "networkpolicy-ingress")
		for i, ingress := range np.Spec.Ingress {
			remoteSubnets, _ := cont.getPeerRemoteSubnets(ingress.From,
				np.Namespace, peerPods, peerNs, logger)
			cont.buildNetPolSubjRules(strconv.Itoa(i), subjIngress,
				"ingress", ingress.From, remoteSubnets, ingress.Ports, logger)
		}
		hpp.AddChild(subjIngress)
	}

	// Generate egress policies
	if np.Spec.PolicyTypes == nil || ptypeset[v1net.PolicyTypeEgress] {
		subjEgress :=
			apicapi.NewHostprotSubj(hpp.GetDn(), "networkpolicy-egress")

		portRemoteSubs := make(map[string]*portRemoteSubnet)

		for i, egress := range np.Spec.Egress {
			remoteSubnets, subnetMap := cont.getPeerRemoteSubnets(egress.To,
				np.Namespace, peerPods, peerNs, logger)
			cont.buildNetPolSubjRules(strconv.Itoa(i), subjEgress,
				"egress", egress.To, remoteSubnets, egress.Ports, logger)

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
				updatePortRemoteSubnets(portRemoteSubs, portkey, &p, subnetMap,
					p.Port != nil && p.Port.Type == intstr.Int)
			}
			if len(egress.Ports) == 0 {
				updatePortRemoteSubnets(portRemoteSubs, "", nil, subnetMap,
					false)
			}
		}
		cont.buildServiceAugment(subjEgress, portRemoteSubs, logger)

		hpp.AddChild(subjEgress)
	}
	cont.apicConn.WriteApicObjects(labelKey, apicapi.ApicSlice{hpp})
	return false
}

func getNetworkPolicyEgressIpBlocks(np *v1net.NetworkPolicy) map[string]bool {
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

func (cont *AciController) networkPolicyAdded(obj interface{}) {
	np := obj.(*v1net.NetworkPolicy)
	npkey, err := cache.MetaNamespaceKeyFunc(np)
	if err != nil {
		networkPolicyLogger(cont.log, np).
			Error("Could not create network policy key: ", err)
		return
	}

	cont.indexMutex.Lock()
	subnets := getNetworkPolicyEgressIpBlocks(np)
	cont.updateIpIndex(cont.netPolSubnetIndex, nil, subnets, npkey)

	ports := getNetPolTargetPorts(np)
	cont.updateTargetPortIndex(false, npkey, nil, ports)
	cont.indexMutex.Unlock()

	cont.netPolPods.UpdateSelectorObj(obj)
	cont.netPolIngressPods.UpdateSelectorObj(obj)
	cont.netPolEgressPods.UpdateSelectorObj(obj)
	cont.queueNetPolUpdateByKey(npkey)
}

func (cont *AciController) networkPolicyChanged(oldobj interface{},
	newobj interface{}) {

	oldnp := oldobj.(*v1net.NetworkPolicy)
	newnp := newobj.(*v1net.NetworkPolicy)
	npkey, err := cache.MetaNamespaceKeyFunc(newnp)
	if err != nil {
		networkPolicyLogger(cont.log, newnp).
			Error("Could not create network policy key: ", err)
		return
	}

	cont.indexMutex.Lock()
	oldSubnets := getNetworkPolicyEgressIpBlocks(oldnp)
	newSubnets := getNetworkPolicyEgressIpBlocks(newnp)
	cont.updateIpIndex(cont.netPolSubnetIndex, oldSubnets, newSubnets, npkey)

	oldPorts := getNetPolTargetPorts(oldnp)
	newPorts := getNetPolTargetPorts(newnp)
	cont.updateTargetPortIndex(false, npkey, oldPorts, newPorts)
	cont.indexMutex.Unlock()

	if !reflect.DeepEqual(oldnp.Spec.PodSelector, newnp.Spec.PodSelector) {
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
	np := obj.(*v1net.NetworkPolicy)
	npkey, err := cache.MetaNamespaceKeyFunc(np)
	if err != nil {
		networkPolicyLogger(cont.log, np).
			Error("Could not create network policy key: ", err)
		return
	}

	cont.indexMutex.Lock()
	subnets := getNetworkPolicyEgressIpBlocks(np)
	cont.updateIpIndex(cont.netPolSubnetIndex, subnets, nil, npkey)

	ports := getNetPolTargetPorts(np)
	cont.updateTargetPortIndex(false, npkey, ports, nil)
	cont.indexMutex.Unlock()

	cont.netPolPods.DeleteSelectorObj(obj)
	cont.netPolIngressPods.DeleteSelectorObj(obj)
	cont.netPolEgressPods.DeleteSelectorObj(obj)
	cont.apicConn.ClearApicObjects(cont.aciNameForKey("np", npkey))
}
