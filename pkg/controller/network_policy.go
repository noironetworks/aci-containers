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
	"context"
	"fmt"
	"maps"
	"net"
	"os"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/yl2chen/cidranger"

	v1 "k8s.io/api/core/v1"
	v1net "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	k8util "k8s.io/kubectl/pkg/util"

	"github.com/noironetworks/aci-containers/pkg/apicapi"
	hppv1 "github.com/noironetworks/aci-containers/pkg/hpp/apis/aci.hpp/v1"
	hppclset "github.com/noironetworks/aci-containers/pkg/hpp/clientset/versioned"
	"github.com/noironetworks/aci-containers/pkg/index"
	"github.com/noironetworks/aci-containers/pkg/ipam"
	"github.com/noironetworks/aci-containers/pkg/util"
	discovery "k8s.io/api/discovery/v1"
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

func (cont *AciController) peerPodSelector(np *v1net.NetworkPolicy,
	peers []v1net.NetworkPolicyPeer) []index.PodSelector {
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

	remipupdate := func(pod *v1.Pod, deleted bool) {
		cont.queueRemoteIpConUpdate(pod, deleted)
	}

	cont.netPolIngressPods.SetObjUpdateCallback(npupdate)
	cont.netPolIngressPods.SetRemIpUpdateCallback(remipupdate)
	cont.netPolIngressPods.SetPodHashFunc(nphash)
	cont.netPolEgressPods.SetObjUpdateCallback(npupdate)
	cont.netPolEgressPods.SetRemIpUpdateCallback(remipupdate)
	cont.netPolEgressPods.SetPodHashFunc(nphash)
}

func (cont *AciController) staticNetPolObjs() apicapi.ApicSlice {
	hppIngress :=
		apicapi.NewHostprotPol(cont.config.AciPolicyTenant,
			cont.aciNameForKey("np", "static-ingress"))
	{
		ingressSubj := apicapi.NewHostprotSubj(hppIngress.GetDn(), "ingress")
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
		hppIngress.AddChild(ingressSubj)
	}

	hppEgress :=
		apicapi.NewHostprotPol(cont.config.AciPolicyTenant,
			cont.aciNameForKey("np", "static-egress"))
	{
		egressSubj := apicapi.NewHostprotSubj(hppEgress.GetDn(), "egress")
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

		hppDiscovery.AddChild(discSubj)
	}

	return apicapi.ApicSlice{hppIngress, hppEgress, hppDiscovery}
}

func (cont *AciController) getHppClient() (hppclset.Interface, bool) {
	env := cont.env.(*K8sEnvironment)
	hppcl := env.hppClient
	if hppcl == nil {
		cont.log.Error("hpp client not found")
		return nil, false
	}
	return hppcl, true
}

func (cont *AciController) validateHppCr(hpp *hppv1.HostprotPol) bool {
	allowedProtocols := map[string]bool{
		"tcp":         true,
		"udp":         true,
		"icmp":        true,
		"icmpv6":      true,
		"unspecified": true,
	}

	for _, subj := range hpp.Spec.HostprotSubj {
		for _, rule := range subj.HostprotRule {
			if rule.Protocol != "" {
				if !allowedProtocols[rule.Protocol] {
					cont.log.Error("unknown protocol value: ", rule.Protocol, ", hostprotPol CR: ", hpp)
					return false
				}
			}
		}
	}
	return true
}

func (cont *AciController) createHostprotPol(hpp *hppv1.HostprotPol, ns string) bool {
	if !cont.validateHppCr(hpp) {
		return false
	}
	hppcl, ok := cont.getHppClient()
	if !ok {
		return false
	}

	cont.log.Debug("Creating HPP CR: ", hpp)
	_, err := hppcl.AciV1().HostprotPols(ns).Create(context.TODO(), hpp, metav1.CreateOptions{})
	if err != nil {
		cont.log.Error("Error creating HPP CR: ", err)
		return false
	}

	return true
}

func (cont *AciController) updateHostprotPol(hpp *hppv1.HostprotPol, ns string) bool {
	if !cont.validateHppCr(hpp) {
		cont.deleteHostprotPol(hpp.Name, hpp.Namespace)
		return false
	}
	hppcl, ok := cont.getHppClient()
	if !ok {
		return false
	}

	cont.log.Debug("Updating HPP CR: ", hpp)
	_, err := hppcl.AciV1().HostprotPols(ns).Update(context.TODO(), hpp, metav1.UpdateOptions{})
	if err != nil {
		cont.log.Error("Error updating HPP CR: ", err)
		return false
	}

	return true
}

func (cont *AciController) deleteAllHostprotPol() error {
	sysNs := os.Getenv("SYSTEM_NAMESPACE")
	hppcl, ok := cont.getHppClient()
	if !ok {
		cont.log.Error("Failed to delete HostprotPol CRs")
		return fmt.Errorf("HppClient not initialized")
	}

	cont.log.Debug("Deleting all HostprotPol CRs")
	err := hppcl.AciV1().HostprotPols(sysNs).DeleteCollection(context.TODO(), metav1.DeleteOptions{}, metav1.ListOptions{})
	if err != nil {
		cont.log.Error("Failed to delete HostprotPol CRs: ", err)
	}
	return err
}

func (cont *AciController) deleteHostprotPol(hppName string, ns string) bool {
	hppcl, ok := cont.getHppClient()
	if !ok {
		return false
	}

	cont.log.Debug("Deleting HPP CR: ", hppName)
	err := hppcl.AciV1().HostprotPols(ns).Delete(context.TODO(), hppName, metav1.DeleteOptions{})
	if err != nil {
		cont.log.Error("Error deleting HPP CR: ", err)
		return false
	}

	return true
}

func (cont *AciController) getHostprotPol(hppName string, ns string) (*hppv1.HostprotPol, error) {
	hppcl, ok := cont.getHppClient()
	if !ok {
		return nil, fmt.Errorf("hpp client not found")
	}

	hpp, err := hppcl.AciV1().HostprotPols(ns).Get(context.TODO(), hppName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	cont.log.Debug("HPP CR found: ", hpp)
	return hpp, nil
}

func (cont *AciController) getHostprotRemoteIpContainer(name, ns string) (*hppv1.HostprotRemoteIpContainer, error) {
	hppcl, ok := cont.getHppClient()
	if !ok {
		return nil, fmt.Errorf("hpp client not found")
	}

	hpp, err := hppcl.AciV1().HostprotRemoteIpContainers(ns).Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		cont.log.Error("Error getting HostprotRemoteIpContainers CR: ", err)
		return nil, err
	}
	cont.log.Debug("HostprotRemoteIpContainers CR found: ", hpp)
	return hpp, nil
}

func (cont *AciController) createHostprotRemoteIpContainer(hppIpCont *hppv1.HostprotRemoteIpContainer, ns string) bool {
	hppcl, ok := cont.getHppClient()
	if !ok {
		return false
	}

	cont.log.Debug("Creating HostprotRemoteIpContainer CR: ", hppIpCont)
	_, err := hppcl.AciV1().HostprotRemoteIpContainers(ns).Create(context.TODO(), hppIpCont, metav1.CreateOptions{})
	if err != nil {
		cont.log.Error("Error creating HostprotRemoteIpContainer CR: ", err)
		return false
	}

	return true
}

func (cont *AciController) updateHostprotRemoteIpContainer(hppIpCont *hppv1.HostprotRemoteIpContainer, ns string) bool {
	hppcl, ok := cont.getHppClient()
	if !ok {
		return false
	}

	cont.log.Debug("Updating HostprotRemoteIpContainer CR: ", hppIpCont)
	_, err := hppcl.AciV1().HostprotRemoteIpContainers(ns).Update(context.TODO(), hppIpCont, metav1.UpdateOptions{})
	if err != nil {
		cont.log.Error("Error updating HostprotRemoteIpContainer CR: ", err)
		return false
	}

	return true
}

func (cont *AciController) deleteAllHostprotRemoteIpContainers() error {
	sysNs := os.Getenv("SYSTEM_NAMESPACE")
	hppcl, ok := cont.getHppClient()
	if !ok {
		cont.log.Error("Failed to delete HostprotRemoteIpContainer CRs")
		return fmt.Errorf("HppClient not initialized")
	}

	cont.log.Debug("Deleting all HostprotRemoteIpContainer CRs")
	err := hppcl.AciV1().HostprotRemoteIpContainers(sysNs).DeleteCollection(context.TODO(), metav1.DeleteOptions{}, metav1.ListOptions{})
	if err != nil {
		cont.log.Error("Failed to delete HostprotRemoteIpContainer CRs: ", err)
	}
	return err
}

func (cont *AciController) deleteHostprotRemoteIpContainer(hppIpContName string, ns string) bool {
	hppcl, ok := cont.getHppClient()
	if !ok {
		return false
	}

	cont.log.Debug("Deleting HostprotRemoteIpContainer CR: ", hppIpContName)
	err := hppcl.AciV1().HostprotRemoteIpContainers(ns).Delete(context.TODO(), hppIpContName, metav1.DeleteOptions{})
	if err != nil {
		cont.log.Error("Error deleting HostprotRemoteIpContainer CR: ", err)
		return false
	}

	return true
}

func (cont *AciController) listHostprotPol(ns string) (*hppv1.HostprotPolList, error) {
	hppcl, ok := cont.getHppClient()
	if !ok {
		return nil, fmt.Errorf("hpp client not found")
	}

	hpps, err := hppcl.AciV1().HostprotPols(ns).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		cont.log.Error("Error listing HPP CR: ", err)
		return nil, err
	}
	return hpps, nil
}

func (cont *AciController) listHostprotRemoteIpContainers(ns string) (*hppv1.HostprotRemoteIpContainerList, error) {
	hppcl, ok := cont.getHppClient()
	if !ok {
		return nil, fmt.Errorf("hpp client not found")
	}

	hpRemoteIpConts, err := hppcl.AciV1().HostprotRemoteIpContainers(ns).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		cont.log.Error("Error getting HostprotRemoteIpContainers CRs: ", err)
		return nil, err
	}
	return hpRemoteIpConts, nil
}

func (cont *AciController) createStaticNetPolCrs() bool {
	ns := os.Getenv("SYSTEM_NAMESPACE")

	createPol := func(labelKey, subjName, direction string, rules []hppv1.HostprotRule) bool {
		hppName := strings.ReplaceAll(labelKey, "_", "-")
		if _, err := cont.getHostprotPol(hppName, ns); errors.IsNotFound(err) {
			hpp := &hppv1.HostprotPol{
				ObjectMeta: metav1.ObjectMeta{
					Name:      hppName,
					Namespace: ns,
				},
				Spec: hppv1.HostprotPolSpec{
					Name:            labelKey,
					NetworkPolicies: []string{labelKey},
					HostprotSubj: []hppv1.HostprotSubj{
						{
							Name:         subjName,
							HostprotRule: rules,
						},
					},
				},
			}
			if !cont.createHostprotPol(hpp, ns) {
				return false
			}
		}
		return true
	}

	if !createPol(cont.aciNameForKey("np", "static-ingress"), "ingress", "ingress", cont.getHostprotRules("ingress")) {
		return false
	}
	if !createPol(cont.aciNameForKey("np", "static-egress"), "egress", "egress", cont.getHostprotRules("egress")) {
		return false
	}
	if !createPol(cont.aciNameForKey("np", "static-discovery"), "discovery", "discovery", cont.getDiscoveryRules()) {
		return false
	}

	return true
}

func (cont *AciController) getHostprotRules(direction string) []hppv1.HostprotRule {
	var rules []hppv1.HostprotRule
	outbound := hppv1.HostprotRule{
		ConnTrack: "reflexive",
		Protocol:  "unspecified",
		FromPort:  "unspecified",
		ToPort:    "unspecified",
		Direction: direction,
	}

	if !cont.configuredPodNetworkIps.V6.Empty() {
		outbound.Name = "allow-all-reflexive-v6"
		outbound.Ethertype = "ipv6"
		rules = append(rules, outbound)
	}
	if !cont.configuredPodNetworkIps.V4.Empty() {
		outbound.Name = "allow-all-reflexive"
		outbound.Ethertype = "ipv4"
		rules = append(rules, outbound)
	}

	return rules
}

func (cont *AciController) getDiscoveryRules() []hppv1.HostprotRule {
	rules := []hppv1.HostprotRule{
		{
			Name:      "arp-ingress",
			Direction: "ingress",
			Ethertype: "arp",
			ConnTrack: "normal",
		},
		{
			Name:      "arp-egress",
			Direction: "egress",
			Ethertype: "arp",
			ConnTrack: "normal",
		},
	}

	if !cont.configuredPodNetworkIps.V4.Empty() {
		rules = append(rules,
			hppv1.HostprotRule{
				Name:      "icmp-ingress",
				Direction: "ingress",
				Ethertype: "ipv4",
				Protocol:  "icmp",
				ConnTrack: "normal",
			},
			hppv1.HostprotRule{
				Name:      "icmp-egress",
				Direction: "egress",
				Ethertype: "ipv4",
				Protocol:  "icmp",
				ConnTrack: "normal",
			},
		)
	}

	if !cont.configuredPodNetworkIps.V6.Empty() {
		rules = append(rules,
			hppv1.HostprotRule{
				Name:      "icmpv6-ingress",
				Direction: "ingress",
				Ethertype: "ipv6",
				Protocol:  "icmpv6",
				ConnTrack: "normal",
			},
			hppv1.HostprotRule{
				Name:      "icmpv6-egress",
				Direction: "egress",
				Ethertype: "ipv6",
				Protocol:  "icmpv6",
				ConnTrack: "normal",
			},
		)
	}

	return rules
}

func (cont *AciController) cleanStaleHppCrs() {
	sysNs := os.Getenv("SYSTEM_NAMESPACE")
	npNames := make(map[string]struct{})

	namespaces, err := cont.listNamespaces()
	if err != nil {
		cont.log.Error("Error listing namespaces: ", err)
		return
	}

	for _, ns := range namespaces.Items {
		netpols, err := cont.listNetworkPolicies(ns.Name)
		if err != nil {
			cont.log.Error("Error listing network policies in namespace ", ns.Name, ": ", err)
			continue
		}
		for _, np := range netpols.Items {
			nsName := np.ObjectMeta.Namespace + "/" + np.ObjectMeta.Name
			npNames[nsName] = struct{}{}
		}
	}

	hpps, err := cont.listHostprotPol(sysNs)
	if err != nil {
		cont.log.Error("Error listing HostprotPols: ", err)
		return
	}

	for _, hpp := range hpps.Items {
		for _, npName := range hpp.Spec.NetworkPolicies {
			if _, exists := npNames[npName]; !exists {
				if !cont.deleteHostprotPol(hpp.ObjectMeta.Name, sysNs) {
					cont.log.Error("Error deleting stale HostprotPol: ", hpp.ObjectMeta.Name)
				}
			}
		}
	}
}

func (cont *AciController) cleanStaleHostprotRemoteIpContainers() {
	sysNs := os.Getenv("SYSTEM_NAMESPACE")
	nsNames := make(map[string]struct{})

	namespaces, err := cont.listNamespaces()
	if err != nil {
		cont.log.Error("Error listing namespaces: ", err)
		return
	}

	for _, ns := range namespaces.Items {
		nsNames[ns.Name] = struct{}{}
	}

	hpRemIpConts, err := cont.listHostprotRemoteIpContainers(sysNs)
	if err != nil {
		cont.log.Error("Error listing HostprotRemoteIpContainers: ", err)
		return
	}

	for _, hpRemIpCont := range hpRemIpConts.Items {
		if _, exists := nsNames[hpRemIpCont.ObjectMeta.Name]; !exists {
			if !cont.deleteHostprotRemoteIpContainer(hpRemIpCont.ObjectMeta.Name, sysNs) {
				cont.log.Error("Error deleting stale HostprotRemoteIpContainer: ", hpRemIpCont.ObjectMeta.Name)
			}
		}
	}
}

func (cont *AciController) initStaticNetPolObjs() {
	if cont.config.EnableHppDirect {
		cont.cleanStaleHostprotRemoteIpContainers()
		cont.cleanStaleHppCrs()

		if !cont.createStaticNetPolCrs() {
			cont.log.Error("Error creating static HPP CRs")
		}
		return
	} else {
		cont.deleteAllHostprotPol()
		cont.deleteAllHostprotRemoteIpContainers()
	}

	cont.apicConn.WriteApicObjects(cont.config.AciPrefix+"_np_static", cont.staticNetPolObjs())
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

func (cont *AciController) queueRemoteIpConUpdate(pod *v1.Pod, deleted bool) {
	cont.hppMutex.Lock()
	update := cont.updateNsRemoteIpCont(pod, deleted)
	if update {
		podns := pod.ObjectMeta.Namespace
		cont.remIpContQueue.Add(podns)
	}
	cont.hppMutex.Unlock()
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
			match := selector.Matches(labels.Set(podNs.ObjectMeta.Labels))
			if match && peer.PodSelector != nil {
				podSelector, err :=
					metav1.LabelSelectorAsSelector(peer.PodSelector)
				if err != nil {
					cont.log.Error("Could not parse pod selector: ", err)
				} else {
					return podSelector.Matches(labels.Set(pod.ObjectMeta.Labels))
				}
			}
			return match
		}
	}
	return false
}

func ipsForPod(pod *v1.Pod) []string {
	var ips []string
	podIPsField := reflect.ValueOf(pod.Status).FieldByName("PodIPs")
	if podIPsField.IsValid() {
		if len(pod.Status.PodIPs) > 0 {
			for _, ip := range pod.Status.PodIPs {
				ips = append(ips, ip.IP)
			}
			return ips
		}
	}
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

func netEqual(a, b net.IPNet) bool {
	return a.IP.Equal(b.IP) && bytes.Equal(a.Mask, b.Mask)
}

func (cont *AciController) updateIpIndexEntry(index cidranger.Ranger,
	subnetStr string, key string, add bool) bool {
	cidr := parseCIDR(subnetStr)
	if cidr == nil {
		cont.log.WithFields(logrus.Fields{
			"subnet": subnetStr,
			"netpol": key,
		}).Warning("Invalid subnet or IP")
		return false
	}

	entries, err := index.CoveredNetworks(*cidr)
	if err != nil {
		cont.log.Error("Corrupted subnet index: ", err)
		return false
	}
	if add {
		for _, entryObj := range entries {
			if netEqual(entryObj.Network(), *cidr) {
				entry := entryObj.(*ipIndexEntry)
				existing := entry.keys[key]
				entry.keys[key] = true
				return !existing
			}
		}

		entry := &ipIndexEntry{
			ipNet: *cidr,
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

// resolvedPeerPorts holds the fully-resolved peer+port data for one NP
// ingress/egress rule. Peer IP resolution and named port resolution are
// performed together so that each resolvedPortEntry carries the exact set of
// remote IPs to which the port applies.
type resolvedPeerPorts struct {
	// entries is the list of port-scoped IP groups. Each entry becomes one
	// or more APIC/HPP rules (split by ethertype).
	entries []resolvedPortEntry

	// subnetMap is the set of all matched peer IPs + IPBlock subnets.
	subnetMap map[string]bool
	// ipBlockSubs is the sorted list of IPBlock-derived subnets only.
	ipBlockSubs []string

	// HPP-Direct metadata
	peerNsList   []string
	podSelectors []*metav1.LabelSelector

	// noPeers is true when there are no peer selectors (egress no-To / ingress no-From).
	noPeers bool
	// addPodSubnetAsRemIp is true when the rule allows all namespaces.
	addPodSubnetAsRemIp bool
	// hasNamedPort is true when the rule contains at least one named port.
	hasNamedPort bool
}

// resolvedPortEntry is a single port (or port range) with its associated remote IPs.
type resolvedPortEntry struct {
	proto    string
	fromPort string
	toPort   string
	// ips contains the remote IPs for this entry. For non-port-scoped entries
	// this is the full set of matched peer IPs (pod IPs + IPBlock CIDRs). For
	// port-scoped entries (portScoped=true) this is the subset of pod IPs that
	// define the named port at a specific number.
	ips []string
	// portScoped is true when ips contains only the pod IPs that define a named
	// port at a specific number, rather than the full peer IP set. When true,
	// consumption sites must also include ipBlockSubs alongside ips.
	portScoped bool
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
			entry.removeServiceKey(key)
		} else {
			delete(entry.networkPolicyKeys, key)
		}
		if !entry.hasServiceKeys() && len(entry.networkPolicyKeys) == 0 {
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
				portMapping:       port,
				networkPolicyKeys: make(map[string]bool),
			}
			cont.targetPortIndex[portkey] = entry
		} else {
			for p, svcKeys := range port.portServiceMap {
				if entry.portMapping.portServiceMap[p] == nil {
					entry.portMapping.portServiceMap[p] = svcKeys
				} else if svcKeys != nil {
					for sk := range svcKeys {
						entry.portMapping.portServiceMap[p][sk] = true
					}
				}
			}
		}

		if !service {
			entry.networkPolicyKeys[key] = true
		}
	}
}

func (cont *AciController) getPortNumsFromPortName(podKeys []string, portName string) map[int]bool {
	ports := make(map[int]bool)
	for _, podkey := range podKeys {
		podobj, exists, err := cont.podIndexer.GetByKey(podkey)
		if exists && err == nil {
			pod := podobj.(*v1.Pod)
			port, err := k8util.LookupContainerPortNumberByName(*pod, portName)
			if err != nil {
				continue
			}
			ports[int(port)] = true
		}
	}
	if len(ports) == 0 {
		cont.log.Infof("No matching portnumbers for portname %s: ", portName)
	}
	cont.log.Debug("PortName: ", portName, "Mapping port numbers: ", ports)
	return ports
}

// get a map of target ports for egress rules that have no "To" clause
func (cont *AciController) getNetPolTargetPorts(np *v1net.NetworkPolicy) map[string]targetPort {
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
			portnums := make(map[int]map[string]bool)
			if port.Port.Type == intstr.Int {
				key = portProto(&proto) + "-num-" + port.Port.String()
				portnums[port.Port.IntValue()] = nil
			} else {
				if len(egress.To) != 0 {
					// TODO optimize this code instead going through all matching pods every time
					podKeys := cont.netPolEgressPods.GetPodForObj(npKey)
					numericPorts := cont.getPortNumsFromPortName(podKeys, port.Port.String())
					for p := range numericPorts {
						portnums[p] = nil
					}
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
								portnums[port] = nil
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
				proto:          proto,
				portServiceMap: portnums,
			}
		}
	}
	return ports
}

// resolveNetPolPeersAndPorts resolves NP peers and ports together in a single
// pass over matched pods. For egress named ports, port resolution is performed
// during pod iteration so that each resolvedPortEntry carries the exact IPs
// that define the named port at that number. This avoids repeated pod lookups.
func (cont *AciController) resolveNetPolPeersAndPorts(
	direction string,
	peers []v1net.NetworkPolicyPeer,
	ports []v1net.NetworkPolicyPort,
	peerPods []*v1.Pod,
	peerNs map[string]*v1.Namespace,
	np *v1net.NetworkPolicy,
	logger *logrus.Entry,
) *resolvedPeerPorts {
	namespace := np.Namespace
	result := &resolvedPeerPorts{
		subnetMap:           make(map[string]bool),
		addPodSubnetAsRemIp: isAllowAllForAllNamespaces(peers),
		noPeers:             len(peers) == 0,
	}

	// Collect HPP-Direct pod selectors from peers (independent of pod iteration).
	if cont.config.EnableHppDirect {
		for i := range peers {
			if peers[i].PodSelector != nil &&
				!cont.isPodSelectorPresent(result.podSelectors, peers[i].PodSelector) {
				result.podSelectors = append(result.podSelectors, peers[i].PodSelector)
			}
		}
	}

	// --- Phase 1: Resolve peers to IPs ---
	var namedPortIps map[string]map[int][]string
	var allRemoteIps []string
	if result.addPodSubnetAsRemIp {
		// Allow-all: peers match all pods in all namespaces. Skip per-pod
		// iteration — individual IPs are not needed (pod subnets are used
		// instead) and namespace list can be derived from peerNs directly.
		result.subnetMap["0.0.0.0/0"] = true
		for nsName := range peerNs {
			result.peerNsList = append(result.peerNsList, nsName)
		}
	} else {
		// For egress with specific peers, track named port → pod IP
		// mappings during peer iteration to avoid repeated pod lookups later.
		if direction == "egress" && len(peers) > 0 {
			for _, p := range ports {
				if p.Port != nil && p.Port.Type == intstr.String {
					if namedPortIps == nil {
						namedPortIps = make(map[string]map[int][]string)
					}
					namedPortIps[p.Port.String()] = make(map[int][]string)
				}
			}
		}
		for _, pod := range peerPods {
			podNs, ok := peerNs[pod.ObjectMeta.Namespace]
			if !ok {
				continue
			}
			for peerIx := range peers {
				if !cont.peerMatchesPod(namespace, &peers[peerIx], pod, podNs) {
					continue
				}
				podIps := ipsForPod(pod)
				if len(podIps) == 0 || result.subnetMap[podIps[0]] {
					break // pod already processed or has no IPs
				}
				for _, ip := range podIps {
					result.subnetMap[ip] = true
				}
				allRemoteIps = append(allRemoteIps, podIps...)
				if !slices.Contains(result.peerNsList, pod.ObjectMeta.Namespace) {
					result.peerNsList = append(result.peerNsList, pod.ObjectMeta.Namespace)
				}
				// Resolve named ports on this pod — port number is pod-level,
				// so look it up once and associate all of the pod's IPs.
				for portName, portMap := range namedPortIps {
					if portNum, err := k8util.LookupContainerPortNumberByName(*pod, portName); err == nil {
						portMap[int(portNum)] = append(portMap[int(portNum)], podIps...)
					}
				}
				break // pod matched this peer; no need to check remaining peers
			}
		}
	}

	// IPBlock peers.
	for i := range peers {
		if peers[i].IPBlock == nil {
			continue
		}
		subs, err := ipBlockToSubnets(peers[i].IPBlock)
		if err != nil {
			logger.Warning("Invalid IPBlock in network policy rule: ", err)
			continue
		}
		for _, subnet := range subs {
			result.subnetMap[subnet] = true
		}
		allRemoteIps = append(allRemoteIps, subs...)
		result.ipBlockSubs = append(result.ipBlockSubs, subs...)
	}
	sort.Strings(allRemoteIps)

	// --- Phase 2: Build port entries ---
	if len(ports) == 0 {
		result.entries = []resolvedPortEntry{{ips: allRemoteIps}}
		return result
	}

	for j := range ports {
		proto := portProto(ports[j].Protocol)

		if ports[j].Port == nil {
			result.entries = append(result.entries, resolvedPortEntry{proto: proto, ips: allRemoteIps})
			continue
		}

		if ports[j].Port.Type == intstr.Int {
			entry := resolvedPortEntry{
				proto:    proto,
				fromPort: ports[j].Port.String(),
				ips:      allRemoteIps,
			}
			if ports[j].EndPort != nil {
				entry.toPort = strconv.Itoa(int(*ports[j].EndPort))
			}
			result.entries = append(result.entries, entry)
			continue
		}

		// Named port resolution.
		portName := ports[j].Port.String()
		result.hasNamedPort = true

		if direction == "ingress" {
			var portMap map[int]bool
			if reflect.DeepEqual(np.Spec.PodSelector, metav1.LabelSelector{}) {
				// Empty PodSelector = all pods in namespace. Use ctrPortNameCache
				// filtered to the NP namespace to find port numbers efficiently.
				portMap = cont.getNamedPortNumsForNs(portName, namespace)
			} else {
				npKey := np.Namespace + "/" + np.Name
				podKeys := cont.netPolPods.GetPodForObj(npKey)
				portMap = cont.getPortNumsFromPortName(podKeys, portName)
			}
			if len(portMap) > 1 {
				resolved := make([]int, 0, len(portMap))
				for p := range portMap {
					resolved = append(resolved, p)
				}
				logger.WithFields(logrus.Fields{
					"namedPort":     portName,
					"resolvedPorts": resolved,
				}).Warning("Ingress named port resolves to multiple port numbers " +
					"across subject pods; rules will be over-permissive. " +
					"Use numeric ports in this NetworkPolicy to avoid ambiguity.")
			}
			for portNum := range portMap {
				result.entries = append(result.entries, resolvedPortEntry{
					proto:    proto,
					fromPort: strconv.Itoa(portNum),
					ips:      allRemoteIps,
				})
			}
			continue
		}

		// Egress named port: resolve portMap and determine scope.
		// Three cases unified: with-peers (namedPortIps), allow-all, no-To (global cache).
		var portMap map[int][]string
		portScoped := true
		switch {
		case namedPortIps != nil:
			portMap = namedPortIps[portName]
		case result.addPodSubnetAsRemIp:
			portScoped = false
			portNums := cont.getPortNums(&ports[j])
			portMap = make(map[int][]string, len(portNums))
			for num := range portNums {
				portMap[num] = allRemoteIps
			}
		default:
			portMap = cont.getNamedPortIPMap(portName)
		}
		for portNum, ips := range portMap {
			if portScoped {
				sort.Strings(ips)
			}
			result.entries = append(result.entries, resolvedPortEntry{
				proto:      proto,
				fromPort:   strconv.Itoa(portNum),
				ips:        ips,
				portScoped: portScoped,
			})
		}
	}

	// Warn if egress has IPBlock CIDRs alongside port-scoped (named port) entries.
	if direction == "egress" && len(result.ipBlockSubs) > 0 {
		for _, e := range result.entries {
			if e.portScoped {
				logger.WithFields(logrus.Fields{
					"ipBlocks":  result.ipBlockSubs,
					"namedPort": e.fromPort,
				}).Warning("Egress rule has IPBlock peers with named ports; " +
					"named ports cannot be resolved for IPBlock destinations. " +
					"Traffic to IPBlock CIDRs will be blocked by this policy rule.")
				break
			}
		}
	}

	return result
}

func (cont *AciController) ipInPodSubnet(ip net.IP) bool {
	for _, podsubnet := range cont.config.PodSubnet {
		_, subnet, err := net.ParseCIDR(podsubnet)
		if err == nil && subnet != nil {
			if subnet.Contains(ip) {
				return true
			}
		}
	}
	return false
}

func (cont *AciController) buildNetPolSubjRule(subj apicapi.ApicObject, ruleName,
	direction, ethertype, proto, port string, endPort string, remoteSubnets []string,
	addPodSubnetAsRemIp bool) {
	rule := apicapi.NewHostprotRule(subj.GetDn(), ruleName)
	rule.SetAttr("direction", direction)
	rule.SetAttr("ethertype", ethertype)
	if proto != "" {
		rule.SetAttr("protocol", proto)
	}

	if addPodSubnetAsRemIp {
		for _, podsubnet := range cont.config.PodSubnet {
			_, subnet, err := net.ParseCIDR(podsubnet)
			if err == nil && subnet != nil {
				if (ethertype == "ipv4" && subnet.IP.To4() != nil) || (ethertype == "ipv6" && subnet.IP.To4() == nil) {
					rule.AddChild(apicapi.NewHostprotRemoteIp(rule.GetDn(), podsubnet))
				}
			}
		}
	}
	for _, subnetStr := range remoteSubnets {
		_, subnet, err := net.ParseCIDR(subnetStr)
		if err == nil && subnet != nil {
			// subnetStr is a valid CIDR notation, check its IP version and add the subnet to the rule
			if (ethertype == "ipv4" && subnet.IP.To4() != nil) || (ethertype == "ipv6" && subnet.IP.To4() == nil) {
				rule.AddChild(apicapi.NewHostprotRemoteIp(rule.GetDn(), subnetStr))
			}
		} else if ip := net.ParseIP(subnetStr); ip != nil {
			if addPodSubnetAsRemIp && cont.ipInPodSubnet(ip) {
				continue
			}
			if ethertype == "ipv6" && (ip.To16() != nil && ip.To4() == nil) || ethertype == "ipv4" && ip.To4() != nil {
				rule.AddChild(apicapi.NewHostprotRemoteIp(rule.GetDn(), subnetStr))
			}
		}
	}
	if port != "" {
		rule.SetAttr("fromPort", port)
		if endPort != "" {
			rule.SetAttr("toPort", endPort)
		}
	}

	subj.AddChild(rule)
}

func (cont *AciController) isPodSelectorPresent(podSelectors []*metav1.LabelSelector,
	podSelector *metav1.LabelSelector) bool {

	present := false
	for _, selector := range podSelectors {
		if reflect.DeepEqual(selector, podSelector) {
			present = true
			break
		}
	}
	return present
}

func (cont *AciController) buildLocalNetPolSubjRule(subj *hppv1.HostprotSubj, ruleName,
	direction, ethertype, proto, port, endPort string, remoteNs []string,
	podSelectors []*metav1.LabelSelector, remoteSubnets []string) {
	rule := hppv1.HostprotRule{
		ConnTrack: "reflexive",
		Direction: "ingress",
		Ethertype: "undefined",
		Protocol:  "unspecified",
		FromPort:  "unspecified",
		ToPort:    "unspecified",
	}
	rule.Direction = direction
	rule.Ethertype = ethertype
	if proto != "" {
		rule.Protocol = proto
	}
	rule.Name = ruleName

	rule.RsRemoteIpContainer = remoteNs
	var remoteSubnetsCidr []hppv1.HostprotRemoteIp
	for _, subnetStr := range remoteSubnets {
		_, subnet, err := net.ParseCIDR(subnetStr)
		if err == nil && subnet != nil {
			if (ethertype == "ipv4" && subnet.IP.To4() != nil) || (ethertype == "ipv6" && subnet.IP.To4() == nil) {
				remIpObj := hppv1.HostprotRemoteIp{
					Addr: subnetStr,
				}
				remoteSubnetsCidr = append(remoteSubnetsCidr, remIpObj)
			}
		}
	}
	if len(remoteSubnetsCidr) > 0 {
		rule.HostprotRemoteIp = remoteSubnetsCidr
	}

	var filterContainers []hppv1.HostprotFilterContainer
	for _, podSelector := range podSelectors {
		filterContainer := hppv1.HostprotFilterContainer{}
		for key, val := range podSelector.MatchLabels {
			filter := hppv1.HostprotFilter{
				Key: key,
			}
			filter.Values = append(filter.Values, val)
			filter.Operator = "Equals"
			filterContainer.HostprotFilter = append(filterContainer.HostprotFilter, filter)
		}
		for _, expressions := range podSelector.MatchExpressions {
			filter := hppv1.HostprotFilter{
				Key:      expressions.Key,
				Values:   expressions.Values,
				Operator: string(expressions.Operator),
			}
			filterContainer.HostprotFilter = append(filterContainer.HostprotFilter, filter)
		}
		filterContainers = append(filterContainers, filterContainer)
	}

	if len(filterContainers) > 0 {
		rule.HostprotFilterContainer = filterContainers
	}

	if port != "" {
		rule.FromPort = port
		if endPort != "" {
			rule.ToPort = endPort
		}
	}

	cont.log.Debug(direction)
	if len(remoteSubnets) != 0 && direction == "egress" {
		cont.log.Debug("HostprotServiceRemoteIps")
		rule.HostprotServiceRemoteIps = remoteSubnets
	}

	subj.HostprotRule = append(subj.HostprotRule, rule)
}

func (cont *AciController) buildNetPolSubjRules(ruleName string,
	subj apicapi.ApicObject, direction string,
	resolved *resolvedPeerPorts, np *v1net.NetworkPolicy) {
	if !resolved.noPeers && len(resolved.subnetMap) == 0 {
		// Peers specified but match nothing; don't create rules.
		return
	}
	hasV4 := !cont.configuredPodNetworkIps.V4.Empty()
	hasV6 := !cont.configuredPodNetworkIps.V6.Empty()
	ruleCounter := 0
	for _, entry := range resolved.entries {
		addPodSubnet := resolved.addPodSubnetAsRemIp
		if entry.portScoped {
			// Port-scoped: only pod IPs that define the named port.
			addPodSubnet = false
		}

		if entry.proto == "" && entry.fromPort == "" {
			if hasV4 {
				policyRuleName := util.AciNameForKey(ruleName+"-ipv4", "", np.Name)
				cont.buildNetPolSubjRule(subj, policyRuleName, direction,
					"ipv4", "", "", "", entry.ips, addPodSubnet)
			}
			if hasV6 {
				policyRuleName := util.AciNameForKey(ruleName+"-ipv6", "", np.Name)
				cont.buildNetPolSubjRule(subj, policyRuleName, direction,
					"ipv6", "", "", "", entry.ips, addPodSubnet)
			}
		} else {
			if hasV4 {
				prefix := fmt.Sprintf("%s_%d-ipv4", ruleName, ruleCounter)
				policyRuleName := util.AciNameForKey(prefix, "", np.Name)
				cont.buildNetPolSubjRule(subj, policyRuleName, direction,
					"ipv4", entry.proto, entry.fromPort, entry.toPort, entry.ips, addPodSubnet)
			}
			if hasV6 {
				prefix := fmt.Sprintf("%s_%d-ipv6", ruleName, ruleCounter)
				policyRuleName := util.AciNameForKey(prefix, "", np.Name)
				cont.buildNetPolSubjRule(subj, policyRuleName, direction,
					"ipv6", entry.proto, entry.fromPort, entry.toPort, entry.ips, addPodSubnet)
			}
			ruleCounter++
		}
	}
}

func (cont *AciController) buildLocalNetPolSubjRules(ruleName string,
	subj *hppv1.HostprotSubj, direction string,
	resolved *resolvedPeerPorts, np *v1net.NetworkPolicy) {
	hasV4 := !cont.configuredPodNetworkIps.V4.Empty()
	hasV6 := !cont.configuredPodNetworkIps.V6.Empty()
	ruleCounter := 0
	peerNsList := resolved.peerNsList
	for _, entry := range resolved.entries {
		peerIpBlock := resolved.ipBlockSubs
		if entry.portScoped {
			// Port-scoped: IPBlock CIDRs excluded for named ports.
			peerIpBlock = nil
		}

		if entry.proto == "" && entry.fromPort == "" {
			if hasV4 {
				policyRuleName := util.AciNameForKey(ruleName+"-ipv4", "", np.Name)
				cont.buildLocalNetPolSubjRule(subj, policyRuleName, direction,
					"ipv4", "", "", "", peerNsList, resolved.podSelectors, peerIpBlock)
			}
			if hasV6 {
				policyRuleName := util.AciNameForKey(ruleName+"-ipv6", "", np.Name)
				cont.buildLocalNetPolSubjRule(subj, policyRuleName, direction,
					"ipv6", "", "", "", peerNsList, resolved.podSelectors, peerIpBlock)
			}
		} else {
			if hasV4 {
				prefix := fmt.Sprintf("%s_%d-ipv4", ruleName, ruleCounter)
				policyRuleName := util.AciNameForKey(prefix, "", np.Name)
				cont.buildLocalNetPolSubjRule(subj, policyRuleName, direction,
					"ipv4", entry.proto, entry.fromPort, entry.toPort, peerNsList, resolved.podSelectors, peerIpBlock)
			}
			if hasV6 {
				prefix := fmt.Sprintf("%s_%d-ipv6", ruleName, ruleCounter)
				policyRuleName := util.AciNameForKey(prefix, "", np.Name)
				cont.buildLocalNetPolSubjRule(subj, policyRuleName, direction,
					"ipv6", entry.proto, entry.fromPort, entry.toPort, peerNsList, resolved.podSelectors, peerIpBlock)
			}
			ruleCounter++
		}
	}
}

func (cont *AciController) getPortNums(port *v1net.NetworkPolicyPort) map[int]map[string]bool {
	portkey := portKey(port)
	cont.indexMutex.Lock()
	defer cont.indexMutex.Unlock()
	cont.log.Debug("PortKey1: ", portkey)
	entry := cont.targetPortIndex[portkey]
	if entry == nil || len(entry.portMapping.portServiceMap) == 0 {
		return nil
	}
	result := make(map[int]map[string]bool, len(entry.portMapping.portServiceMap))
	for p, svcKeys := range entry.portMapping.portServiceMap {
		result[p] = maps.Clone(svcKeys)
	}
	return result
}

// getNamedPortIPMap resolves a named port to a map of portNumber -> []podIPs.
// Each pod that defines the named port contributes its IP to the list for the
// specific port number that the named port resolves to on that pod. This allows
// creating per-destination-IP scoped egress rules so that traffic is only
// allowed to a port number on pods that actually define the named port as that
// number.
func (cont *AciController) getNamedPortIPMap(portName string) map[int][]string {
	result := make(map[int][]string)
	cont.indexMutex.Lock()
	ctrNmpEntry, ok := cont.ctrPortNameCache[portName]
	if !ok {
		cont.indexMutex.Unlock()
		return result
	}
	// ctrNmpToPods maps "proto-portnum" -> set of pod keys
	for key, podkeys := range ctrNmpEntry.ctrNmpToPods {
		val := strings.Split(key, "-")
		if len(val) != 2 {
			continue
		}
		portNum, err := strconv.Atoi(val[1])
		if err != nil {
			continue
		}
		for podkey := range podkeys {
			podobj, exists, err := cont.podIndexer.GetByKey(podkey)
			if !exists || err != nil {
				continue
			}
			pod := podobj.(*v1.Pod)
			for _, ip := range ipsForPod(pod) {
				result[portNum] = append(result[portNum], ip)
			}
		}
	}
	cont.indexMutex.Unlock()
	return result
}

// getNamedPortNumsForNs returns the set of numeric port numbers that a named
// port resolves to on pods within a specific namespace. It uses ctrPortNameCache
// rather than iterating all pods in the namespace.
func (cont *AciController) getNamedPortNumsForNs(portName, namespace string) map[int]bool {
	result := make(map[int]bool)
	nsPrefix := namespace + "/"
	cont.indexMutex.Lock()
	ctrNmpEntry, ok := cont.ctrPortNameCache[portName]
	if !ok {
		cont.indexMutex.Unlock()
		return result
	}
	for key, podkeys := range ctrNmpEntry.ctrNmpToPods {
		val := strings.Split(key, "-")
		if len(val) != 2 {
			continue
		}
		portNum, err := strconv.Atoi(val[1])
		if err != nil {
			continue
		}
		for podkey := range podkeys {
			if strings.HasPrefix(podkey, nsPrefix) {
				result[portNum] = true
				break
			}
		}
	}
	cont.indexMutex.Unlock()
	return result
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

func portKey(p *v1net.NetworkPolicyPort) string {
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

func protoPortKey(proto, port string) string {
	return proto + "-" + port
}

type portServiceAugment struct {
	proto string
	port  string
	ipMap map[string]bool
}

func updateServiceAugment(portAugments map[string]*portServiceAugment, proto, port, ip string) {
	key := protoPortKey(proto, port)
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
	proto, port string, service *v1.Service) {
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
func (cont *AciController) getServiceAugmentBySubnet(
	prs *portRemoteSubnet, portAugments map[string]*portServiceAugment,
	logger *logrus.Entry) {
	matchedServices := make(map[string]bool)
	subnetIndex := cidranger.NewPCTrieRanger()

	// find candidate service endpoints objects that include
	// endpoints selected by the egress rule
	cont.indexMutex.Lock()
	for sub := range prs.subnetMap {
		cidr := parseCIDR(sub)
		if cidr == nil {
			continue
		}
		subnetIndex.Insert(cidranger.NewBasicRangerEntry(*cidr))

		entries, err := cont.endpointsIpIndex.CoveredNetworks(*cidr)
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

// getServiceAugmentByPort builds service augment by matching against
// services with a given target port.
func (cont *AciController) getServiceAugmentByPort(
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
	defer cont.indexMutex.Unlock()
	entries := make(map[string]map[string]bool)
	entry := cont.targetPortIndex[portkey]
	if entry == nil {
		return
	}
	if prs.port.Port.Type == intstr.String {
		// Named port in netpol
		for port, svcKeys := range entry.portMapping.portServiceMap {
			if len(svcKeys) > 0 {
				portstring := strconv.Itoa(port)
				entries[portstring] = svcKeys
			}
		}
	} else if prs.port.EndPort != nil {
		// Port Range in netpol
		startPort := prs.port.Port.IntValue()
		endPort := int(*prs.port.EndPort)
		rangeSize := endPort - startPort + 1
		proto := portProto(prs.port.Protocol)
		if rangeSize < len(cont.targetPortIndex) {
			for port := startPort; port <= endPort; port++ {
				portstring := strconv.Itoa(port)
				key := proto + "-num-" + portstring
				portEntry := cont.targetPortIndex[key]
				if portEntry != nil {
					entries[portstring] = portEntry.portMapping.portServiceMap[port]
				}
			}
		} else {
			protoPrefix := proto + "-num-"
			for portkey, portEntry := range cont.targetPortIndex {
				if !strings.HasPrefix(portkey, protoPrefix) {
					continue
				}
				portNumStr := strings.TrimPrefix(portkey, protoPrefix)
				portNum, err := strconv.Atoi(portNumStr)
				if err != nil {
					continue
				}
				if portNum >= startPort && portNum <= endPort {
					portstring := strconv.Itoa(portNum)
					entries[portstring] = portEntry.portMapping.portServiceMap[portNum]
				}
			}
		}
		// Look through services with named target ports as well.
		for serviceKey, namedSvcEntry := range cont.namedPortServiceIndex {
			for _, svcPortEntry := range *namedSvcEntry {
				// Named ports that resolve to a single port number are
				// already handled above via the -num- entries in
				// targetPortIndex.
				if len(svcPortEntry.resolvedPorts) <= 1 {
					continue
				}
				// Check if ALL resolved ports are within the range (all-or-nothing semantics)
				allInRange := true
				for resolvedPort := range svcPortEntry.resolvedPorts {
					if resolvedPort < startPort || resolvedPort > endPort {
						allInRange = false
						break
					}
				}
				if allInRange {
					portstring := svcPortEntry.targetPortName
					if _, ok := entries[portstring]; !ok {
						entries[portstring] = map[string]bool{serviceKey: true}
					} else {
						entries[portstring][serviceKey] = true
					}
				}
			}
		}
	} else if len(entry.portMapping.portServiceMap) > 0 {
		// Single numeric portNum in netpol
		portNum := prs.port.Port.IntValue()
		entries[prs.port.Port.String()] = entry.portMapping.portServiceMap[portNum]
	}
	for key, servicekeys := range entries {
		for servicekey := range servicekeys {
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
				if svcPort.Protocol != *prs.port.Protocol {
					continue
				}
				// Handle the case where the NP specifies a numeric port
				// but the service has a named targetPort. The key in
				// entries is the resolved numeric port, so it won't match
				// svcPort.TargetPort.String() directly. We check if the
				// named targetPort resolves to exactly one numeric port
				// (all-or-nothing) and whether that port matches the key.
				match := false
				if indexEntry, ok := cont.namedPortServiceIndex[servicekey]; ok {
					if svcPortIdxEntry, ok := (*indexEntry)[svcPort.Name]; ok && len(svcPortIdxEntry.resolvedPorts) == 1 {
						intKey, error := strconv.Atoi(key)
						if error == nil && svcPortIdxEntry.resolvedPorts[intKey] {
							match = true
						}
					}
				}
				svcTargetPort := svcPort.TargetPort.String()
				if !match && svcTargetPort != key && svcTargetPort != prs.port.Port.String() {
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
	localsubj *hppv1.HostprotSubj,
	portRemoteSubs map[string]*portRemoteSubnet, logger *logrus.Entry) {
	portAugments := make(map[string]*portServiceAugment)
	for _, prs := range portRemoteSubs {
		// TODO ipv6
		if prs.subnetMap["0.0.0.0/0"] {
			cont.getServiceAugmentByPort(prs, portAugments, logger)
		} else {
			cont.getServiceAugmentBySubnet(prs, portAugments, logger)
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
		if !cont.config.EnableHppDirect && subj != nil {
			if len(remoteIpsv4) > 0 {
				serviceName := fmt.Sprintf("service_%s_%s-ipv4", augment.proto, augment.port)
				cont.buildNetPolSubjRule(subj,
					serviceName,
					"egress", "ipv4", augment.proto, augment.port, "", remoteIpsv4, false)
			}
			if len(remoteIpsv6) > 0 {
				serviceName := fmt.Sprintf("service_%s_%s-ipv6", augment.proto, augment.port)
				cont.buildNetPolSubjRule(subj,
					serviceName,
					"egress", "ipv6", augment.proto, augment.port, "", remoteIpsv6, false)
			}
		} else if cont.config.EnableHppDirect && localsubj != nil {
			if len(remoteIpsv4) > 0 {
				cont.buildLocalNetPolSubjRule(localsubj,
					"service_"+augment.proto+"_"+augment.port,
					"egress", "ipv4", augment.proto, augment.port, "", nil, nil, remoteIpsv4)
			}
			if len(remoteIpsv6) > 0 {
				cont.buildLocalNetPolSubjRule(localsubj,
					"service_"+augment.proto+"_"+augment.port,
					"egress", "ipv6", augment.proto, augment.port, "", nil, nil, remoteIpsv6)
			}
		}
	}
}

func isAllowAllForAllNamespaces(peers []v1net.NetworkPolicyPeer) bool {
	addPodSubnetAsRemIp := false
	if peers != nil && len(peers) > 0 {
		var emptyPodSel, emptyNsSel bool
		emptyPodSel = true
		for _, peer := range peers {
			// namespaceSelector: {}
			if peer.NamespaceSelector != nil && peer.NamespaceSelector.MatchLabels == nil && peer.NamespaceSelector.MatchExpressions == nil {
				emptyNsSel = true
			}
			// podSelector has some fields
			if peer.PodSelector != nil && (peer.PodSelector.MatchLabels != nil || peer.PodSelector.MatchExpressions != nil) {
				emptyPodSel = false
			}
		}
		if emptyNsSel && emptyPodSel {
			addPodSubnetAsRemIp = true
		}
	}
	return addPodSubnetAsRemIp
}

func (cont *AciController) handleRemIpContUpdate(ns string) bool {
	cont.hppMutex.Lock()
	defer cont.hppMutex.Unlock()

	sysNs := os.Getenv("SYSTEM_NAMESPACE")
	aobj, err := cont.getHostprotRemoteIpContainer(ns, sysNs)
	isUpdate := err == nil

	if err != nil && !errors.IsNotFound(err) {
		cont.log.Error("Error getting HostprotRemoteIpContainers CR: ", err)
		return true
	}

	if !isUpdate {
		aobj = &hppv1.HostprotRemoteIpContainer{
			ObjectMeta: metav1.ObjectMeta{
				Name:      ns,
				Namespace: sysNs,
			},
			Spec: hppv1.HostprotRemoteIpContainerSpec{
				Name:             ns,
				HostprotRemoteIp: []hppv1.HostprotRemoteIp{},
			},
		}
	} else {
		cont.log.Debug("HostprotRemoteIpContainers CR already exists: ", aobj)
	}

	remIpCont, exists := cont.nsRemoteIpCont[ns]
	if !exists {
		if isUpdate {
			if !cont.deleteHostprotRemoteIpContainer(ns, sysNs) {
				return true
			}
		} else {
			cont.log.Error("Couldn't find the ns in nsRemoteIpCont cache: ", ns)
			return false
		}
		return false
	}

	aobj.Spec.HostprotRemoteIp = buildHostprotRemoteIpList(remIpCont)

	if isUpdate {
		if !cont.updateHostprotRemoteIpContainer(aobj, sysNs) {
			return true
		}
	} else {
		if !cont.createHostprotRemoteIpContainer(aobj, sysNs) {
			return true
		}
	}

	return false
}

func buildHostprotRemoteIpList(remIpConts map[string]remoteIpCont) []hppv1.HostprotRemoteIp {
	hostprotRemoteIpList := []hppv1.HostprotRemoteIp{}

	for _, remIpCont := range remIpConts {
		for ip, labels := range remIpCont {
			remIpObj := hppv1.HostprotRemoteIp{
				Addr: ip,
			}
			for key, val := range labels {
				remIpObj.HppEpLabel = append(remIpObj.HppEpLabel, hppv1.HppEpLabel{
					Key:   key,
					Value: val,
				})
			}
			hostprotRemoteIpList = append(hostprotRemoteIpList, remIpObj)
		}
	}

	return hostprotRemoteIpList
}

func (cont *AciController) deleteHppCr(np *v1net.NetworkPolicy) bool {
	key, err := cache.MetaNamespaceKeyFunc(np)
	logger := networkPolicyLogger(cont.log, np)
	if err != nil {
		logger.Error("Could not create network policy key: ", err)
		return false
	}
	hash, err := util.CreateHashFromNetPol(np)
	if err != nil {
		logger.Error("Could not create hash from network policy: ", err)
		return false
	}
	labelKey := cont.aciNameForKey("np", hash)
	ns := os.Getenv("SYSTEM_NAMESPACE")
	hppName := strings.ReplaceAll(labelKey, "_", "-")
	hpp, _ := cont.getHostprotPol(hppName, ns)
	if hpp == nil {
		logger.Error("Could not find hostprotPol: ", hppName)
		return false
	}
	netPols := hpp.Spec.NetworkPolicies
	newNetPols := make([]string, 0)
	for _, npName := range netPols {
		if npName != key {
			newNetPols = append(newNetPols, npName)
		}
	}

	hpp.Spec.NetworkPolicies = newNetPols

	if len(newNetPols) > 0 {
		return cont.updateHostprotPol(hpp, ns)
	} else {
		return cont.deleteHostprotPol(hppName, ns)
	}
}

func (cont *AciController) updateNodeIpsHostprotRemoteIpContainer(nodeIps map[string]bool) {
	ns := os.Getenv("SYSTEM_NAMESPACE")
	name := "nodeips"

	aobj, err := cont.getHostprotRemoteIpContainer(name, ns)
	isUpdate := err == nil

	if err != nil && !errors.IsNotFound(err) {
		cont.log.Error("Error getting HostprotRemoteIpContainers CR: ", err)
		return
	}

	if !isUpdate {
		aobj = &hppv1.HostprotRemoteIpContainer{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: ns,
			},
			Spec: hppv1.HostprotRemoteIpContainerSpec{
				Name:             name,
				HostprotRemoteIp: []hppv1.HostprotRemoteIp{},
			},
		}
	} else {
		cont.log.Debug("HostprotRemoteIpContainers CR already exists: ", aobj)
	}

	existingIps := make(map[string]bool)
	for _, ip := range aobj.Spec.HostprotRemoteIp {
		existingIps[ip.Addr] = true
	}

	for ip := range nodeIps {
		if !existingIps[ip] {
			aobj.Spec.HostprotRemoteIp = append(aobj.Spec.HostprotRemoteIp, hppv1.HostprotRemoteIp{Addr: ip})
		}
	}

	if isUpdate {
		cont.updateHostprotRemoteIpContainer(aobj, ns)
	} else {
		cont.createHostprotRemoteIpContainer(aobj, ns)
	}
}

func (cont *AciController) deleteNodeIpsHostprotRemoteIpContainer(nodeIps map[string]bool) {
	ns := os.Getenv("SYSTEM_NAMESPACE")
	name := "nodeips"

	aobj, _ := cont.getHostprotRemoteIpContainer(name, ns)
	if aobj == nil {
		return
	}

	newHostprotRemoteIps := aobj.Spec.HostprotRemoteIp[:0]
	for _, hostprotRemoteIp := range aobj.Spec.HostprotRemoteIp {
		if len(nodeIps) > 0 && !nodeIps[hostprotRemoteIp.Addr] {
			newHostprotRemoteIps = append(newHostprotRemoteIps, hostprotRemoteIp)
		}
	}

	aobj.Spec.HostprotRemoteIp = newHostprotRemoteIps

	if len(newHostprotRemoteIps) > 0 {
		cont.updateHostprotRemoteIpContainer(aobj, ns)
	} else {
		cont.deleteHostprotRemoteIpContainer(name, ns)
	}
}

func (cont *AciController) updateNodeHostprotRemoteIpContainer(name string, nodeIps map[string]bool) {
	ns := os.Getenv("SYSTEM_NAMESPACE")

	aobj, err := cont.getHostprotRemoteIpContainer(name, ns)
	isUpdate := err == nil

	if err != nil && !errors.IsNotFound(err) {
		cont.log.Error("Error getting HostprotRemoteIpContainers CR: ", err)
		return
	}

	if !isUpdate {
		aobj = &hppv1.HostprotRemoteIpContainer{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: ns,
			},
			Spec: hppv1.HostprotRemoteIpContainerSpec{
				Name:             name,
				HostprotRemoteIp: []hppv1.HostprotRemoteIp{},
			},
		}
	} else {
		cont.log.Debug("HostprotRemoteIpContainers CR already exists: ", aobj)
	}

	aobj.Spec.HostprotRemoteIp = make([]hppv1.HostprotRemoteIp, 0, len(nodeIps))
	for ip := range nodeIps {
		aobj.Spec.HostprotRemoteIp = append(aobj.Spec.HostprotRemoteIp, hppv1.HostprotRemoteIp{Addr: ip})
	}

	if isUpdate {
		cont.updateHostprotRemoteIpContainer(aobj, ns)
	} else {
		cont.createHostprotRemoteIpContainer(aobj, ns)
	}
}

func (cont *AciController) deleteNodeHostprotRemoteIpContainer(name string) {
	ns := os.Getenv("SYSTEM_NAMESPACE")

	if _, err := cont.getHostprotRemoteIpContainer(name, ns); err == nil {
		cont.deleteHostprotRemoteIpContainer(name, ns)
	}
}

func (cont *AciController) createNodeHostProtPol(name, nodeName string, nodeIps map[string]bool) {
	ns := os.Getenv("SYSTEM_NAMESPACE")
	hppName := strings.ReplaceAll(name, "_", "-")

	hpp, err := cont.getHostprotPol(hppName, ns)
	isUpdate := hpp != nil && err == nil

	if err != nil && !errors.IsNotFound(err) {
		cont.log.Error("Error getting HPP CR: ", err)
		return
	}

	if !isUpdate {
		hpp = &hppv1.HostprotPol{
			ObjectMeta: metav1.ObjectMeta{
				Name:      hppName,
				Namespace: ns,
			},
			Spec: hppv1.HostprotPolSpec{
				Name:            name,
				NetworkPolicies: []string{name},
				HostprotSubj:    []hppv1.HostprotSubj{},
			},
		}
	} else {
		cont.log.Debug("HPP CR already exists: ", hpp)
		hpp.Spec.HostprotSubj = []hppv1.HostprotSubj{}
	}

	if len(nodeIps) > 0 {
		cont.updateNodeHostprotRemoteIpContainer(nodeName, nodeIps)
		cont.updateNodeIpsHostprotRemoteIpContainer(nodeIps)

		hostprotSubj := hppv1.HostprotSubj{
			Name: "local-node",
			HostprotRule: []hppv1.HostprotRule{
				{
					Name:                "allow-all-egress",
					Direction:           "egress",
					Ethertype:           "ipv4",
					ConnTrack:           "normal",
					RsRemoteIpContainer: []string{nodeName},
				},
				{
					Name:                "allow-all-ingress",
					Direction:           "ingress",
					Ethertype:           "ipv4",
					ConnTrack:           "normal",
					RsRemoteIpContainer: []string{nodeName},
				},
			},
		}

		hpp.Spec.HostprotSubj = append(hpp.Spec.HostprotSubj, hostprotSubj)
	} else {
		cont.deleteNodeHostprotRemoteIpContainer(nodeName)
		cont.deleteNodeIpsHostprotRemoteIpContainer(nodeIps)
	}

	if isUpdate {
		cont.updateHostprotPol(hpp, ns)
	} else {
		cont.createHostprotPol(hpp, ns)
	}
}

func (cont *AciController) handleNetPolUpdate(np *v1net.NetworkPolicy) bool {
	if cont.isCNOEnabled() {
		return false
	}
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
	var labelKey string

	if !cont.config.EnableHppDirect {
		if cont.config.HppOptimization {
			hash, err := util.CreateHashFromNetPol(np)
			if err != nil {
				logger.Error("Could not create hash from network policy: ", err)
				return false
			}
			labelKey = cont.aciNameForKey("np", hash)
		} else {
			labelKey = cont.aciNameForKey("np", key)
		}
		hpp := apicapi.NewHostprotPol(cont.config.AciPolicyTenant, labelKey)

		// Generate ingress policies
		if np.Spec.PolicyTypes == nil || ptypeset[v1net.PolicyTypeIngress] {
			subjIngress :=
				apicapi.NewHostprotSubj(hpp.GetDn(), "networkpolicy-ingress")

			for i, ingress := range np.Spec.Ingress {
				resolved := cont.resolveNetPolPeersAndPorts("ingress",
					ingress.From, ingress.Ports, peerPods, peerNs, np, logger)
				cont.buildNetPolSubjRules(strconv.Itoa(i), subjIngress, "ingress", resolved, np)
			}
			hpp.AddChild(subjIngress)
		}
		// Generate egress policies
		if np.Spec.PolicyTypes == nil || ptypeset[v1net.PolicyTypeEgress] {
			subjEgress :=
				apicapi.NewHostprotSubj(hpp.GetDn(), "networkpolicy-egress")

			portRemoteSubs := make(map[string]*portRemoteSubnet)

			for i, egress := range np.Spec.Egress {
				resolved := cont.resolveNetPolPeersAndPorts("egress",
					egress.To, egress.Ports, peerPods, peerNs, np, logger)
				cont.buildNetPolSubjRules(strconv.Itoa(i), subjEgress, "egress", resolved, np)

				subnetMap := resolved.subnetMap
				if len(egress.To) == 0 {
					subnetMap = map[string]bool{
						"0.0.0.0/0": true,
					}
				}
				for idx := range egress.Ports {
					port := egress.Ports[idx]
					portkey := portKey(&port)
					updatePortRemoteSubnets(portRemoteSubs, portkey, &port, subnetMap,
						port.Port != nil && port.Port.Type == intstr.Int)
				}
				if len(egress.Ports) == 0 {
					updatePortRemoteSubnets(portRemoteSubs, "", nil, subnetMap,
						false)
				}
			}

			cont.buildServiceAugment(subjEgress, nil, portRemoteSubs, logger)
			hpp.AddChild(subjEgress)
		}
		if cont.config.HppOptimization {
			cont.addToHppCache(labelKey, key, apicapi.ApicSlice{hpp}, &hppv1.HostprotPol{})
		}
		cont.apicConn.WriteApicObjects(labelKey, apicapi.ApicSlice{hpp})
	} else {
		hash, err := util.CreateHashFromNetPol(np)
		if err != nil {
			logger.Error("Could not create hash from network policy: ", err)
			return false
		}
		labelKey = cont.aciNameForKey("np", hash)
		ns := os.Getenv("SYSTEM_NAMESPACE")
		hppName := strings.ReplaceAll(labelKey, "_", "-")
		hpp, err := cont.getHostprotPol(hppName, ns)
		isUpdate := err == nil

		if err != nil && !errors.IsNotFound(err) {
			logger.Error("Error getting HPP CR: ", err)
			return false
		}

		if isUpdate {
			logger.Debug("HPP CR already exists: ", hpp)
			if !slices.Contains(hpp.Spec.NetworkPolicies, key) {
				hpp.Spec.NetworkPolicies = append(hpp.Spec.NetworkPolicies, key)
			}
			hpp.Spec.HostprotSubj = nil
		} else {
			hpp = &hppv1.HostprotPol{
				ObjectMeta: metav1.ObjectMeta{
					Name:      hppName,
					Namespace: ns,
				},
				Spec: hppv1.HostprotPolSpec{
					Name:            labelKey,
					NetworkPolicies: []string{key},
					HostprotSubj:    nil,
				},
			}
		}

		// Generate ingress policies
		if np.Spec.PolicyTypes == nil || ptypeset[v1net.PolicyTypeIngress] {
			subjIngress := &hppv1.HostprotSubj{
				Name:         "networkpolicy-ingress",
				HostprotRule: []hppv1.HostprotRule{},
			}

			for i, ingress := range np.Spec.Ingress {
				resolved := cont.resolveNetPolPeersAndPorts("ingress",
					ingress.From, ingress.Ports, peerPods, peerNs, np, logger)
				if isAllowAllForAllNamespaces(ingress.From) {
					if !slices.Contains(resolved.peerNsList, "nodeips") {
						resolved.peerNsList = append(resolved.peerNsList, "nodeips")
					}
				}
				if !(!resolved.noPeers && len(resolved.subnetMap) == 0) {
					cont.buildLocalNetPolSubjRules(strconv.Itoa(i), subjIngress, "ingress", resolved, np)
				}
			}
			hpp.Spec.HostprotSubj = append(hpp.Spec.HostprotSubj, *subjIngress)
		}

		if np.Spec.PolicyTypes == nil || ptypeset[v1net.PolicyTypeEgress] {
			subjEgress := &hppv1.HostprotSubj{
				Name:         "networkpolicy-egress",
				HostprotRule: []hppv1.HostprotRule{},
			}

			portRemoteSubs := make(map[string]*portRemoteSubnet)

			for i, egress := range np.Spec.Egress {
				resolved := cont.resolveNetPolPeersAndPorts("egress",
					egress.To, egress.Ports, peerPods, peerNs, np, logger)
				if isAllowAllForAllNamespaces(egress.To) {
					if !slices.Contains(resolved.peerNsList, "nodeips") {
						resolved.peerNsList = append(resolved.peerNsList, "nodeips")
					}
				}
				if !(!resolved.noPeers && len(resolved.subnetMap) == 0) {
					cont.buildLocalNetPolSubjRules(strconv.Itoa(i), subjEgress, "egress", resolved, np)
				}

				subnetMap := resolved.subnetMap
				if len(egress.To) == 0 {
					subnetMap = map[string]bool{"0.0.0.0/0": true}
				}
				for idx := range egress.Ports {
					port := egress.Ports[idx]
					portkey := portKey(&port)
					updatePortRemoteSubnets(portRemoteSubs, portkey, &port, subnetMap,
						port.Port != nil && port.Port.Type == intstr.Int)
				}
				if len(egress.Ports) == 0 {
					updatePortRemoteSubnets(portRemoteSubs, "", nil, subnetMap,
						false)
				}
			}

			cont.buildServiceAugment(nil, subjEgress, portRemoteSubs, logger)
			hpp.Spec.HostprotSubj = append(hpp.Spec.HostprotSubj, *subjEgress)
		}

		cont.addToHppCache(labelKey, key, apicapi.ApicSlice{}, hpp)

		if isUpdate {
			cont.updateHostprotPol(hpp, ns)
		} else {
			cont.createHostprotPol(hpp, ns)
		}
	}
	return false
}

func (cont *AciController) updateNsRemoteIpCont(pod *v1.Pod, deleted bool) bool {
	podips := ipsForPod(pod)
	podns := pod.ObjectMeta.Namespace
	podname := pod.ObjectMeta.Name
	podlabels := pod.ObjectMeta.Labels
	remipconts, ok := cont.nsRemoteIpCont[podns]

	if deleted {
		if !ok {
			return true
		}

		present := false
		if remipcont, remipcontok := remipconts[podname]; remipcontok {
			for _, ip := range podips {
				if _, ipok := remipcont[ip]; ipok {
					delete(remipcont, ip)
					present = true
				}
			}
			if len(remipcont) < 1 {
				delete(remipconts, podname)
			}
		}

		if len(remipconts) < 1 {
			delete(cont.nsRemoteIpCont, podns)
			cont.apicConn.ClearApicObjects(cont.aciNameForKey("hostprot-ns-", podns))
			return false
		}

		if !present {
			return false
		}
	} else {
		if !ok {
			remipconts = make(remoteIpConts)
			cont.nsRemoteIpCont[podns] = remipconts
		}

		remipcont, remipcontok := remipconts[podname]
		if !remipcontok {
			remipcont = make(remoteIpCont)
		}
		for _, ip := range podips {
			remipcont[ip] = podlabels
		}
		remipconts[podname] = remipcont
	}

	return true
}

func (cont *AciController) addToHppCache(labelKey, key string, hpp apicapi.ApicSlice, hppcr *hppv1.HostprotPol) {
	cont.indexMutex.Lock()
	hppRef, ok := cont.hppRef[labelKey]
	if ok {
		var found bool
		for _, npkey := range hppRef.Npkeys {
			if npkey == key {
				found = true
				break
			}
		}
		if !found {
			hppRef.RefCount++
			hppRef.Npkeys = append(hppRef.Npkeys, key)
		}
		hppRef.HppObj = hpp
		hppRef.HppCr = *hppcr
		cont.hppRef[labelKey] = hppRef
	} else {
		var newHppRef hppReference
		newHppRef.RefCount++
		newHppRef.HppObj = hpp
		newHppRef.HppCr = *hppcr
		newHppRef.Npkeys = append(newHppRef.Npkeys, key)
		cont.hppRef[labelKey] = newHppRef
	}
	cont.indexMutex.Unlock()
}

func (cont *AciController) removeFromHppCache(np *v1net.NetworkPolicy, key string) (string, bool) {
	var labelKey string
	var noRef bool
	hash, err := util.CreateHashFromNetPol(np)
	if err != nil {
		cont.log.Error("Could not create hash from network policy: ", err)
		cont.log.Error("Failed to remove np from hpp cache")
		return labelKey, noRef
	}
	labelKey = cont.aciNameForKey("np", hash)
	cont.indexMutex.Lock()
	hppRef, ok := cont.hppRef[labelKey]
	if ok {
		for i, npkey := range hppRef.Npkeys {
			if npkey == key {
				hppRef.Npkeys = append(hppRef.Npkeys[:i], hppRef.Npkeys[i+1:]...)
				hppRef.RefCount--
				break
			}
		}
		if hppRef.RefCount > 0 {
			cont.hppRef[labelKey] = hppRef
		} else {
			delete(cont.hppRef, labelKey)
			noRef = true
		}
	}
	cont.indexMutex.Unlock()
	return labelKey, noRef
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
	if cont.isCNOEnabled() {
		return
	}
	cont.netPolPods.UpdateSelectorObj(obj)
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

	if cont.config.HppOptimization || cont.config.EnableHppDirect {
		if !reflect.DeepEqual(oldnp.Spec, newnp.Spec) {
			cont.removeFromHppCache(oldnp, npkey)
		}
	}

	cont.indexMutex.Lock()
	oldSubnets := getNetworkPolicyEgressIpBlocks(oldnp)
	newSubnets := getNetworkPolicyEgressIpBlocks(newnp)
	cont.updateIpIndex(cont.netPolSubnetIndex, oldSubnets, newSubnets, npkey)

	oldPorts := cont.getNetPolTargetPorts(oldnp)
	newPorts := cont.getNetPolTargetPorts(newnp)
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
	if cont.config.EnableHppDirect && !reflect.DeepEqual(oldnp.Spec, newnp.Spec) {
		cont.deleteHppCr(oldnp)
		queue = true
	}
	if queue {
		cont.queueNetPolUpdateByKey(npkey)
	}
}

func (cont *AciController) networkPolicyDeleted(obj interface{}) {
	np, isNetworkpolicy := obj.(*v1net.NetworkPolicy)
	if !isNetworkpolicy {
		deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			networkPolicyLogger(cont.log, np).
				Error("Received unexpected object: ", obj)
			return
		}
		np, ok = deletedState.Obj.(*v1net.NetworkPolicy)
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

	var labelKey string
	var noHppRef bool
	if cont.config.HppOptimization || cont.config.EnableHppDirect {
		labelKey, noHppRef = cont.removeFromHppCache(np, npkey)
	} else {
		labelKey = cont.aciNameForKey("np", npkey)
		noHppRef = true
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
	if noHppRef && labelKey != "" {
		cont.apicConn.ClearApicObjects(labelKey)
	}
	if cont.config.EnableHppDirect {
		cont.deleteHppCr(np)
	}
}

func (seps *serviceEndpointSlice) SetNpServiceAugmentForService(servicekey string, service *v1.Service,
	prs *portRemoteSubnet, portAugments map[string]*portServiceAugment,
	subnetIndex cidranger.Ranger, logger *logrus.Entry) {
	cont := seps.cont
	npTargetPortsMap := cont.getPortNums(prs.port)

	// Helper function to check if a numeric port matches the NetworkPolicy port spec
	checkNumericPortMatchesNetpol := func(port int) bool {
		if prs.port.EndPort != nil {
			// Port range matching: port must be within [Port, EndPort]
			return port >= prs.port.Port.IntValue() && port <= int(*prs.port.EndPort)
		}
		// Single port matching: check if port is in the target ports map
		// and was registered by this service
		svcKeys, ok := npTargetPortsMap[port]
		if !ok {
			return false
		}
		return svcKeys == nil || svcKeys[servicekey]
	}

	label := map[string]string{discovery.LabelServiceName: service.ObjectMeta.Name}
	selector := labels.SelectorFromSet(label)

	endpointSliceList, err := cont.endpointSliceIndexer.ByIndex("namespace", service.ObjectMeta.Namespace)
	if err != nil {
		logger.Error("Could not list endpoint slices: ", err)
		return
	}
	for _, svcPort := range service.Spec.Ports {
		incomplete := false
		hasValidatedSlice := false
		if prs.port != nil &&
			(svcPort.Protocol != *prs.port.Protocol) {
			// egress rule does not match service target port
			continue
		}
		// Match any port if no port is specified in the np
		portMatched := prs.port == nil || prs.port.Port == nil

		if !portMatched {
			if svcPort.TargetPort.Type == intstr.String {
				if prs.port.Port.Type == intstr.String {
					if prs.port.Port.String() != svcPort.TargetPort.String() {
						continue
					}
					portMatched = true
				}
			} else {
				if !checkNumericPortMatchesNetpol(svcPort.TargetPort.IntValue()) {
					continue
				}
				portMatched = true
			}
		}

		for _, endpointSliceobj := range endpointSliceList {
			endpointSlices := endpointSliceobj.(*discovery.EndpointSlice)
			if !selector.Matches(labels.Set(endpointSlices.Labels)) {
				continue
			}

			var foundEpPort *discovery.EndpointPort
			for ix := range endpointSlices.Ports {
				if endpointSlices.Ports[ix].Name != nil && *endpointSlices.Ports[ix].Name == svcPort.Name ||
					(len(service.Spec.Ports) == 1 &&
						endpointSlices.Ports[ix].Name != nil && *endpointSlices.Ports[ix].Name == "") {
					foundEpPort = &endpointSlices.Ports[ix]
					cont.log.Debug("Found EpPort: ", foundEpPort)
					break
				}
			}

			if foundEpPort == nil {
				continue
			}
			if !portMatched && (foundEpPort.Port == nil || !checkNumericPortMatchesNetpol(int(*foundEpPort.Port))) {
				incomplete = true
				break
			}
			// @FIXME for non ready address
			for _, endpoint := range endpointSlices.Endpoints {
				incomplete = incomplete || !checkEndpointslices(subnetIndex, endpoint.Addresses)
			}
			if incomplete {
				break
			}
			hasValidatedSlice = true
		}
		if !incomplete && hasValidatedSlice {
			proto := portProto(&svcPort.Protocol)
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
	}
}

func isNamedPortPresenInNp(np *v1net.NetworkPolicy) bool {
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
		np := npobj.(*v1net.NetworkPolicy)
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
