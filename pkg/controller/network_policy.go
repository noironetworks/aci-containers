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

type peerRemoteInfo struct {
	remotePods  []*v1.Pod
	podSelector *metav1.LabelSelector
}

func (cont *AciController) getPeerRemoteSubnets(peers []v1net.NetworkPolicyPeer,
	namespace string, peerPods []*v1.Pod, peerNs map[string]*v1.Namespace,
	logger *logrus.Entry) ([]string, []string, peerRemoteInfo, map[string]bool, []string) {
	var remoteSubnets []string
	var peerremote peerRemoteInfo
	subnetMap := make(map[string]bool)
	var peerNsList []string
	var ipBlockSubs []string
	if len(peers) > 0 {
		// only applies to matching pods
		for _, pod := range peerPods {
			for peerIx, peer := range peers {
				if ns, ok := peerNs[pod.ObjectMeta.Namespace]; ok &&
					cont.peerMatchesPod(namespace,
						&peers[peerIx], pod, ns) {
					podIps := ipsForPod(pod)
					for _, ip := range podIps {
						if _, exists := subnetMap[ip]; !exists {
							subnetMap[ip] = true
							if cont.config.EnableHppDirect {
								peerremote.remotePods = append(peerremote.remotePods, pod)
								if !slices.Contains(peerNsList, pod.ObjectMeta.Namespace) {
									peerNsList = append(peerNsList, pod.ObjectMeta.Namespace)
								}
							}
							remoteSubnets = append(remoteSubnets, ip)
						}
					}
				}
				if cont.config.EnableHppDirect && peer.PodSelector != nil {
					peerremote.podSelector = peer.PodSelector
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
				ipBlockSubs = append(ipBlockSubs, subs...)
			}
		}
	}
	sort.Strings(remoteSubnets)
	return remoteSubnets, peerNsList, peerremote, subnetMap, ipBlockSubs
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
	direction, ethertype, proto, port string, remoteSubnets []string,
	addPodSubnetAsRemIp bool) {
	ruleNameWithEtherType := fmt.Sprintf("%s-%s", ruleName, ethertype)
	rule := apicapi.NewHostprotRule(subj.GetDn(), ruleNameWithEtherType)
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
		rule.SetAttr("toPort", port)
	}

	subj.AddChild(rule)
}

func (cont *AciController) buildLocalNetPolSubjRule(subj *hppv1.HostprotSubj, ruleName,
	direction, ethertype, proto, port string, remoteNs []string,
	podSelector *metav1.LabelSelector, remoteSubnets []string) {
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

	if podSelector != nil {
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
		rule.HostprotFilterContainer = filterContainer
	}

	if port != "" {
		rule.ToPort = port
	}

	cont.log.Debug(direction)
	if len(remoteSubnets) != 0 && direction == "egress" {
		cont.log.Debug("HostprotServiceRemoteIps")
		rule.HostprotServiceRemoteIps = remoteSubnets
	}

	subj.HostprotRule = append(subj.HostprotRule, rule)
}

func (cont *AciController) buildNetPolSubjRules(ruleName string,
	subj apicapi.ApicObject, direction string, peers []v1net.NetworkPolicyPeer,
	remoteSubnets []string, ports []v1net.NetworkPolicyPort,
	logger *logrus.Entry, npKey string, np *v1net.NetworkPolicy,
	addPodSubnetAsRemIp bool) {
	if len(peers) > 0 && len(remoteSubnets) == 0 {
		// nonempty From matches no pods or IPBlocks; don't
		// create the rule
		return
	}
	if len(ports) == 0 {
		if !cont.configuredPodNetworkIps.V4.Empty() {
			cont.buildNetPolSubjRule(subj, ruleName, direction,
				"ipv4", "", "", remoteSubnets, addPodSubnetAsRemIp)
		}
		if !cont.configuredPodNetworkIps.V6.Empty() {
			cont.buildNetPolSubjRule(subj, ruleName, direction,
				"ipv6", "", "", remoteSubnets, addPodSubnetAsRemIp)
		}
	} else {
		for j := range ports {
			proto := portProto(ports[j].Protocol)
			var portList []string

			if ports[j].Port != nil {
				if ports[j].Port.Type == intstr.Int {
					portList = append(portList, ports[j].Port.String())
				} else {
					var portnums []int
					if direction == "egress" {
						portnums = append(portnums, cont.getPortNums(&ports[j])...)
					} else {
						// TODO need to handle empty Pod Selector
						if reflect.DeepEqual(np.Spec.PodSelector, metav1.LabelSelector{}) {
							logger.Warning("Empty PodSelctor for NamedPort is not supported in ingress direction"+
								"port in network policy: ", ports[j].Port.String())
							continue
						}
						podKeys := cont.netPolPods.GetPodForObj(npKey)
						portnums = cont.getPortNumsFromPortName(podKeys, ports[j].Port.String())
					}
					if len(portnums) == 0 {
						logger.Warning("There is no matching  ports in ingress/egress direction "+
							"port in network policy: ", ports[j].Port.String())
						continue
					}
					for _, portnum := range portnums {
						portList = append(portList, strconv.Itoa(portnum))
					}
				}
			}
			for i, port := range portList {
				if !cont.configuredPodNetworkIps.V4.Empty() {
					cont.buildNetPolSubjRule(subj, ruleName+"_"+strconv.Itoa(i+j), direction,
						"ipv4", proto, port, remoteSubnets, addPodSubnetAsRemIp)
				}
				if !cont.configuredPodNetworkIps.V6.Empty() {
					cont.buildNetPolSubjRule(subj, ruleName+"_"+strconv.Itoa(i+j), direction,
						"ipv6", proto, port, remoteSubnets, addPodSubnetAsRemIp)
				}
			}
			if len(portList) == 0 && proto != "" {
				if !cont.configuredPodNetworkIps.V4.Empty() {
					cont.buildNetPolSubjRule(subj, ruleName+"_"+strconv.Itoa(j), direction,
						"ipv4", proto, "", remoteSubnets, addPodSubnetAsRemIp)
				}
				if !cont.configuredPodNetworkIps.V6.Empty() {
					cont.buildNetPolSubjRule(subj, ruleName+"_"+strconv.Itoa(j), direction,
						"ipv6", proto, "", remoteSubnets, addPodSubnetAsRemIp)
				}
			}
		}
	}
}

func (cont *AciController) buildLocalNetPolSubjRules(ruleName string,
	subj *hppv1.HostprotSubj, direction string, peerNs []string,
	podSelector *metav1.LabelSelector, ports []v1net.NetworkPolicyPort,
	logger *logrus.Entry, npKey string, np *v1net.NetworkPolicy, peerIpBlock []string) {
	if len(ports) == 0 {
		if !cont.configuredPodNetworkIps.V4.Empty() {
			cont.buildLocalNetPolSubjRule(subj, ruleName+"-ipv4", direction,
				"ipv4", "", "", peerNs, podSelector, peerIpBlock)
		}
		if !cont.configuredPodNetworkIps.V6.Empty() {
			cont.buildLocalNetPolSubjRule(subj, ruleName+"-ipv6", direction,
				"ipv6", "", "", peerNs, podSelector, peerIpBlock)
		}
	} else {
		for j := range ports {
			proto := portProto(ports[j].Protocol)
			var portList []string

			if ports[j].Port != nil {
				if ports[j].Port.Type == intstr.Int {
					portList = append(portList, ports[j].Port.String())
				} else {
					var portnums []int
					if direction == "egress" {
						portnums = append(portnums, cont.getPortNums(&ports[j])...)
					} else {
						// TODO need to handle empty Pod Selector
						if reflect.DeepEqual(np.Spec.PodSelector, metav1.LabelSelector{}) {
							logger.Warning("Empty PodSelctor for NamedPort is not supported in ingress direction"+
								"port in network policy: ", ports[j].Port.String())
							continue
						}
						podKeys := cont.netPolPods.GetPodForObj(npKey)
						portnums = cont.getPortNumsFromPortName(podKeys, ports[j].Port.String())
					}
					if len(portnums) == 0 {
						logger.Warning("There is no matching  ports in ingress/egress direction "+
							"port in network policy: ", ports[j].Port.String())
						continue
					}
					for _, portnum := range portnums {
						portList = append(portList, strconv.Itoa(portnum))
					}
				}
			}
			for i, port := range portList {
				if !cont.configuredPodNetworkIps.V4.Empty() {
					cont.buildLocalNetPolSubjRule(subj, ruleName+"_"+strconv.Itoa(i+j)+"-ipv4", direction,
						"ipv4", proto, port, peerNs, podSelector, peerIpBlock)
				}
				if !cont.configuredPodNetworkIps.V6.Empty() {
					cont.buildLocalNetPolSubjRule(subj, ruleName+"_"+strconv.Itoa(i+j)+"-ipv6", direction,
						"ipv6", proto, port, peerNs, podSelector, peerIpBlock)
				}
			}
			if len(portList) == 0 && proto != "" {
				if !cont.configuredPodNetworkIps.V4.Empty() {
					cont.buildLocalNetPolSubjRule(subj, ruleName+"_"+strconv.Itoa(j)+"-ipv4", direction,
						"ipv4", proto, "", peerNs, podSelector, peerIpBlock)
				}
				if !cont.configuredPodNetworkIps.V6.Empty() {
					cont.buildLocalNetPolSubjRule(subj, ruleName+"_"+strconv.Itoa(j)+"-ipv6", direction,
						"ipv6", proto, "", peerNs, podSelector, peerIpBlock)
				}
			}
		}
	}
}

func (cont *AciController) getPortNums(port *v1net.NetworkPolicyPort) []int {
	portkey := portKey(port)
	cont.indexMutex.Lock()
	defer cont.indexMutex.Unlock()
	cont.log.Debug("PortKey1: ", portkey)
	entry := cont.targetPortIndex[portkey]
	var length int
	if entry == nil || len(entry.port.ports) == 0 {
		return []int{}
	}
	length = len(entry.port.ports)
	ports := make([]int, length)
	copy(ports, entry.port.ports)
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

func portServiceAugmentKey(proto, port string) string {
	return proto + "-" + port
}

type portServiceAugment struct {
	proto string
	port  string
	ipMap map[string]bool
}

func updateServiceAugment(portAugments map[string]*portServiceAugment, proto, port, ip string) {
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

// build service augment by matching against services with a given
// target port
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
	entries := make(map[string]*portIndexEntry)
	entry := cont.targetPortIndex[portkey]
	if entry != nil && prs.port.Port.Type == intstr.String {
		for _, port := range entry.port.ports {
			portstring := strconv.Itoa(port)
			key := portProto(prs.port.Protocol) + "-" + "num" + "-" + portstring
			portEntry := cont.targetPortIndex[key]
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
				cont.buildNetPolSubjRule(subj,
					"service_"+augment.proto+"_"+augment.port,
					"egress", "ipv4", augment.proto, augment.port, remoteIpsv4, false)
			}
			if len(remoteIpsv6) > 0 {
				cont.buildNetPolSubjRule(subj,
					"service_"+augment.proto+"_"+augment.port,
					"egress", "ipv6", augment.proto, augment.port, remoteIpsv6, false)
			}
		} else if cont.config.EnableHppDirect && localsubj != nil {
			if len(remoteIpsv4) > 0 {
				cont.buildLocalNetPolSubjRule(localsubj,
					"service_"+augment.proto+"_"+augment.port,
					"egress", "ipv4", augment.proto, augment.port, nil, nil, remoteIpsv4)
			}
			if len(remoteIpsv6) > 0 {
				cont.buildLocalNetPolSubjRule(localsubj,
					"service_"+augment.proto+"_"+augment.port,
					"egress", "ipv6", augment.proto, augment.port, nil, nil, remoteIpsv6)
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

func buildHostprotRemoteIpList(remIpCont map[string]map[string]string) []hppv1.HostprotRemoteIp {
	hostprotRemoteIpList := []hppv1.HostprotRemoteIp{}

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
	if cont.config.ChainedMode {
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
				addPodSubnetAsRemIp := isAllowAllForAllNamespaces(ingress.From)
				remoteSubnets, _, _, _, _ := cont.getPeerRemoteSubnets(ingress.From,
					np.Namespace, peerPods, peerNs, logger)
				cont.buildNetPolSubjRules(strconv.Itoa(i), subjIngress,
					"ingress", ingress.From, remoteSubnets, ingress.Ports, logger, key, np, addPodSubnetAsRemIp)
			}
			hpp.AddChild(subjIngress)
		}
		// Generate egress policies
		if np.Spec.PolicyTypes == nil || ptypeset[v1net.PolicyTypeEgress] {
			subjEgress :=
				apicapi.NewHostprotSubj(hpp.GetDn(), "networkpolicy-egress")

			portRemoteSubs := make(map[string]*portRemoteSubnet)

			for i, egress := range np.Spec.Egress {
				addPodSubnetAsRemIp := isAllowAllForAllNamespaces(egress.To)
				remoteSubnets, _, _, subnetMap, _ := cont.getPeerRemoteSubnets(egress.To,
					np.Namespace, peerPods, peerNs, logger)
				cont.buildNetPolSubjRules(strconv.Itoa(i), subjEgress,
					"egress", egress.To, remoteSubnets, egress.Ports, logger, key, np, addPodSubnetAsRemIp)

				// creating a rule to egress to all on a given port needs
				// to enable access to any service IPs/ports that have
				// that port as their target port.
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
				remoteSubnets, peerNsList, peerremote, _, peerIpBlock := cont.getPeerRemoteSubnets(ingress.From,
					np.Namespace, peerPods, peerNs, logger)
				if isAllowAllForAllNamespaces(ingress.From) {
					peerNsList = append(peerNsList, "nodeips")
				}
				if !(len(ingress.From) > 0 && len(remoteSubnets) == 0) {
					cont.buildLocalNetPolSubjRules(strconv.Itoa(i), subjIngress,
						"ingress", peerNsList, peerremote.podSelector, ingress.Ports,
						logger, key, np, peerIpBlock)
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
				remoteSubnets, peerNsList, peerremote, subnetMap, peerIpBlock := cont.getPeerRemoteSubnets(egress.To,
					np.Namespace, peerPods, peerNs, logger)
				if isAllowAllForAllNamespaces(egress.To) {
					peerNsList = append(peerNsList, "nodeips")
				}
				if !(len(egress.To) > 0 && len(remoteSubnets) == 0) {
					cont.buildLocalNetPolSubjRules(strconv.Itoa(i), subjEgress,
						"egress", peerNsList, peerremote.podSelector, egress.Ports, logger, key, np, peerIpBlock)
				}

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
	podlabels := pod.ObjectMeta.Labels
	remipcont, ok := cont.nsRemoteIpCont[podns]

	if deleted {
		if !ok {
			return true
		}

		present := false
		for _, ip := range podips {
			if _, ipok := remipcont[ip]; ipok {
				delete(remipcont, ip)
				present = true
			}
		}

		if len(remipcont) < 1 {
			delete(cont.nsRemoteIpCont, podns)
			cont.apicConn.ClearApicObjects(cont.aciNameForKey("hostprot-ns-", podns))
			return false
		}

		if !present {
			return false
		}
	} else {
		if !ok {
			remipcont = make(remoteIpCont)
			cont.nsRemoteIpCont[podns] = remipcont
		}

		for _, ip := range podips {
			remipcont[ip] = podlabels
		}
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
	if cont.config.ChainedMode {
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
	if cont.config.EnableHppDirect {
		cont.deleteHppCr(oldnp)
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
			for ix := range subset.Ports {
				if subset.Ports[ix].Name == svcPort.Name ||
					(len(service.Spec.Ports) == 1 &&
						subset.Ports[ix].Name == "") {
					foundEpPort = &subset.Ports[ix]
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
	label := map[string]string{discovery.LabelServiceName: service.ObjectMeta.Name}
	selector := labels.SelectorFromSet(label)
	cache.ListAllByNamespace(cont.endpointSliceIndexer, service.ObjectMeta.Namespace, selector,
		func(endpointSliceobj interface{}) {
			endpointSlices := endpointSliceobj.(*discovery.EndpointSlice)
			for _, svcPort := range service.Spec.Ports {
				_, ok := portstrings[svcPort.TargetPort.String()]
				if prs.port != nil &&
					(svcPort.Protocol != *prs.port.Protocol || !ok) {
					// egress rule does not match service target port
					continue
				}
				var foundEpPort *discovery.EndpointPort
				for ix := range endpointSlices.Ports {
					if *endpointSlices.Ports[ix].Name == svcPort.Name ||
						(len(service.Spec.Ports) == 1 &&
							*endpointSlices.Ports[ix].Name == "") {
						foundEpPort = &endpointSlices.Ports[ix]
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
