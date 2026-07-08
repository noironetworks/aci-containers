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
	if cont.hppInformer == nil {
		return nil, fmt.Errorf("HPP informer not initialized")
	}
	key := ns + "/" + hppName
	obj, exists, err := cont.hppInformer.GetIndexer().GetByKey(key)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(v1net.Resource("hostprotpol"), hppName)
	}
	hpp, ok := obj.(*hppv1.HostprotPol)
	if !ok {
		return nil, fmt.Errorf("failed to cast object to HostprotPol")
	}
	cont.log.Debug("HPP CR found: ", hpp)
	return hpp, nil
}

func (cont *AciController) getHostprotRemoteIpContainer(name string, ns string) (*hppv1.HostprotRemoteIpContainer, error) {
	if cont.hppRemoteIpInformer == nil {
		return nil, fmt.Errorf("HPP RemoteIp informer not initialized")
	}
	key := ns + "/" + name
	obj, exists, err := cont.hppRemoteIpInformer.GetIndexer().GetByKey(key)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(v1net.Resource("hostprotremoteipcontainer"), name)
	}
	hppRIC, ok := obj.(*hppv1.HostprotRemoteIpContainer)
	if !ok {
		return nil, fmt.Errorf("failed to cast object to HostprotRemoteIpContainer")
	}
	cont.log.Debug("HostprotRemoteIpContainers CR found: ", hppRIC)
	return hppRIC, nil
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
		cont.log.Error("Can't get HPP client. Failed to delete HostprotRemoteIpContainer CR: ", hppIpContName)
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

func (cont *AciController) createStaticNetPolCrs() {
	ns := os.Getenv("SYSTEM_NAMESPACE")

	createPol := func(labelKey, subjName string, rules []hppv1.HostprotRule) {
		hppName := strings.ReplaceAll(labelKey, "_", "-")
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
		cont.addToHppDirCache(hppName, labelKey, hpp, nil)
		cont.queueHppUpdateByKey(hppName)
	}

	createPol(cont.aciNameForKey("np", "static-ingress"), "ingress", cont.getStaticHostprotRules("ingress"))
	createPol(cont.aciNameForKey("np", "static-egress"), "egress", cont.getStaticHostprotRules("egress"))
	createPol(cont.aciNameForKey("np", "static-discovery"), "discovery", cont.getDiscoveryRules())
}

func (cont *AciController) getStaticHostprotRules(direction string) []hppv1.HostprotRule {
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
		cont.createStaticNetPolCrs()
		return
	}
	cont.deleteAllHostprotPol()
	cont.deleteAllHostprotRemoteIpContainers()
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

func (cont *AciController) queueRemoteIpConUpdateByKey(ricName string) {
	cont.remIpContQueue.Add(ricName)
}

func (cont *AciController) queueHppUpdateByKey(labelKey string) {
	cont.hppQueue.Add(labelKey)
}

// removeRemoteIpCacheEntry removes the desired state for a RIC and enqueues
// it for reconciliation. The handler will see no desired state and delete the
// CR if it exists in the informer cache.
// Caller must hold hppMutex.
func (cont *AciController) removeRemoteIpCacheEntry(ricName string) {
	_, exists := cont.remoteIpCache[ricName]
	if !exists {
		return
	}
	delete(cont.remoteIpCache, ricName)

	cont.remIpContQueue.Add(ricName)
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
	// ipBlockSubsV4/V6 are the IPBlock-derived subnets split by address family.
	ipBlockSubsV4 []string
	ipBlockSubsV6 []string

	// noPeers is true when there are no peer selectors (egress no-To / ingress no-From).
	noPeers bool
	// addPodSubnetAsRemIp is true when the rule allows all namespaces.
	addPodSubnetAsRemIp bool
	// hasNamedPort is true when the rule contains at least one named port.
	hasNamedPort bool
	// hasIpBlocks is true when there are IPBlock peers in this rule.
	hasIpBlocks bool
}

// resolvedPortEntry is a single port (or port range) with its associated remote IPs.
type resolvedPortEntry struct {
	proto    string
	fromPort string
	toPort   string
	// ipsV4/ipsV6 contain the remote IPs for this entry split by address family.
	ipsV4 []string
	ipsV6 []string
	// portScoped is true when ipsV4/ipsV6 contain only the pod IPs that
	// define a named port at a specific number, rather than the full peer IP
	// set. When true, consumption sites must also include ipBlockSubsV4/V6.
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

	// --- Phase 1: Resolve peers to IPs ---
	hasV4 := !cont.configuredPodNetworkIps.V4.Empty()
	hasV6 := !cont.configuredPodNetworkIps.V6.Empty()
	var namedPortIps map[string]map[int][]string
	var allRemoteIpsV4, allRemoteIpsV6 []string
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
			for _, ip := range podIps {
				if parsedIP := net.ParseIP(ip); parsedIP != nil {
					if hasV4 && parsedIP.To4() != nil {
						allRemoteIpsV4 = append(allRemoteIpsV4, ip)
					} else if hasV6 && parsedIP.To4() == nil {
						allRemoteIpsV6 = append(allRemoteIpsV6, ip)
					}
				}
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
		result.hasIpBlocks = true
		for _, sub := range subs {
			if _, cidr, err2 := net.ParseCIDR(sub); err2 == nil && cidr != nil {
				if hasV4 && cidr.IP.To4() != nil {
					allRemoteIpsV4 = append(allRemoteIpsV4, sub)
					result.ipBlockSubsV4 = append(result.ipBlockSubsV4, sub)
				} else if hasV6 && cidr.IP.To4() == nil {
					allRemoteIpsV6 = append(allRemoteIpsV6, sub)
					result.ipBlockSubsV6 = append(result.ipBlockSubsV6, sub)
				}
			}
		}
	}
	sort.Strings(allRemoteIpsV4)
	sort.Strings(allRemoteIpsV6)

	// --- Phase 2: Build port entries ---
	if len(ports) == 0 {
		result.entries = []resolvedPortEntry{{ipsV4: allRemoteIpsV4, ipsV6: allRemoteIpsV6}}
		return result
	}

	for j := range ports {
		proto := portProto(ports[j].Protocol)

		if ports[j].Port == nil {
			result.entries = append(result.entries, resolvedPortEntry{proto: proto, ipsV4: allRemoteIpsV4, ipsV6: allRemoteIpsV6})
			continue
		}

		if ports[j].Port.Type == intstr.Int {
			entry := resolvedPortEntry{
				proto:    proto,
				fromPort: ports[j].Port.String(),
				ipsV4:    allRemoteIpsV4,
				ipsV6:    allRemoteIpsV6,
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
					ipsV4:    allRemoteIpsV4,
					ipsV6:    allRemoteIpsV6,
				})
			}
			continue
		}

		// Egress named port: always resolve to per-pod-IP scoped entries so a
		// named port only permits traffic to pods that actually expose it, on
		// the specific number each pod maps it to. This applies even to
		// allow-all-for-all-namespaces rules: those allow all pod IPs but must
		// still honor the named port and must not blanket-allow every resolved
		// number to the whole pod subnet (which would let a pod be reached on a
		// number it never mapped the named port to). Two sources: with specific
		// peers (namedPortIps built during peer iteration) and no-To / allow-all
		// (global ctrPortNameCache, which covers all namespaces).
		var portMap map[int][]string
		if namedPortIps != nil {
			portMap = namedPortIps[portName]
		} else {
			portMap = cont.getNamedPortIPMap(portName)
		}
		for portNum, ips := range portMap {
			var ipsV4, ipsV6 []string
			for _, ip := range ips {
				if parsedIP := net.ParseIP(ip); parsedIP != nil {
					if hasV4 && parsedIP.To4() != nil {
						ipsV4 = append(ipsV4, ip)
					} else if hasV6 && parsedIP.To4() == nil {
						ipsV6 = append(ipsV6, ip)
					}
				}
			}
			sort.Strings(ipsV4)
			sort.Strings(ipsV6)
			result.entries = append(result.entries, resolvedPortEntry{
				proto:      proto,
				fromPort:   strconv.Itoa(portNum),
				ipsV4:      ipsV4,
				ipsV6:      ipsV6,
				portScoped: true,
			})
		}
	}

	// Warn if egress has IPBlock CIDRs alongside port-scoped (named port) entries.
	if direction == "egress" && result.hasIpBlocks {
		for _, e := range result.entries {
			if e.portScoped {
				logger.WithFields(logrus.Fields{
					"namedPort": e.fromPort,
				}).Warning("Egress rule has IPBlock peers with named ports; " +
					"named ports cannot be resolved for IPBlock destinations. " +
					"Traffic to IPBlock CIDRs named ports will be blocked by this policy rule.")
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

func (cont *AciController) buildLocalNetPolSubjRule(subj *hppv1.HostprotSubj, ruleName,
	direction, ethertype, proto, port, endPort, rsRemoteIpContainer string, serviceRemoteIps []string) {
	rule := hppv1.HostprotRule{
		Name:                ruleName,
		ConnTrack:           "reflexive",
		Direction:           direction,
		Ethertype:           ethertype,
		Protocol:            "unspecified",
		FromPort:            "unspecified",
		ToPort:              "unspecified",
		RsRemoteIpContainer: rsRemoteIpContainer,
	}
	if proto != "" {
		rule.Protocol = proto
	}
	if port != "" {
		rule.FromPort = port
		if endPort != "" {
			rule.ToPort = endPort
		}
	}
	if len(serviceRemoteIps) > 0 {
		rule.HostprotServiceRemoteIps = serviceRemoteIps
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
		// In HPP-opt mode the HPP is shared across sibling NPs with the same
		// spec hash. Using np.Name in rule names would cause gratuitous renames
		// whenever a different sibling triggers the rebuild. Use proto-port
		// instead to keep names stable and unique per port entry.
		entryName := np.Name
		if cont.config.HppOptimization {
			if entry.proto != "" {
				entryName = protoPortKey(entry.proto, entry.fromPort)
			} else {
				entryName = "unspecified"
			}
		}

		if entry.proto == "" && entry.fromPort == "" {
			if hasV4 {
				policyRuleName := util.AciNameForKey(ruleName+"-ipv4", "", entryName)
				cont.buildNetPolSubjRule(subj, policyRuleName, direction,
					"ipv4", "", "", "", entry.ipsV4, addPodSubnet)
			}
			if hasV6 {
				policyRuleName := util.AciNameForKey(ruleName+"-ipv6", "", entryName)
				cont.buildNetPolSubjRule(subj, policyRuleName, direction,
					"ipv6", "", "", "", entry.ipsV6, addPodSubnet)
			}
		} else {
			if hasV4 {
				var prefix string
				if cont.config.HppOptimization {
					prefix = ruleName + "-ipv4"
				} else {
					prefix = fmt.Sprintf("%s_%d-ipv4", ruleName, ruleCounter)
				}
				policyRuleName := util.AciNameForKey(prefix, "", entryName)
				cont.buildNetPolSubjRule(subj, policyRuleName, direction,
					"ipv4", entry.proto, entry.fromPort, entry.toPort, entry.ipsV4, addPodSubnet)
			}
			if hasV6 {
				var prefix string
				if cont.config.HppOptimization {
					prefix = ruleName + "-ipv6"
				} else {
					prefix = fmt.Sprintf("%s_%d-ipv6", ruleName, ruleCounter)
				}
				policyRuleName := util.AciNameForKey(prefix, "", entryName)
				cont.buildNetPolSubjRule(subj, policyRuleName, direction,
					"ipv6", entry.proto, entry.fromPort, entry.toPort, entry.ipsV6, addPodSubnet)
			}
			ruleCounter++
		}
	}
}

// stripHppRuleIndex removes a leading "<digits>-" sequential-index prefix
// (added by canonicalizeHppRules) from a HostprotRule name, recovering the
// original base name. mergeHppDirectIngressRules needs this because
// siblingNames (cached by cacheNpDirIngressRules) always holds raw,
// pre-canonicalization names, while the rules it's matching against come
// from the stored HPP CR (hppDirRef.HppCr), which always carries the index
// prefix from the last canonicalizeHppRules call that wrote it. Without
// stripping, the lookup would never match.
func stripHppRuleIndex(name string) string {
	idx := strings.Index(name, "-")
	if idx <= 0 {
		return name
	}
	for _, r := range name[:idx] {
		if r < '0' || r > '9' {
			return name
		}
	}
	return name[idx+1:]
}

// canonicalizeHppRules sorts rules deterministically regardless of NP spec
// rule ordering, then prepends a sequential index to guarantee uniqueness.
func canonicalizeHppRules(rules []hppv1.HostprotRule) {
	sort.SliceStable(rules, func(i, j int) bool {
		if rules[i].Name != rules[j].Name {
			return rules[i].Name < rules[j].Name
		}
		return rules[i].RsRemoteIpContainer < rules[j].RsRemoteIpContainer
	})
	for i := range rules {
		rules[i].Name = strconv.Itoa(i) + "-" + rules[i].Name
	}
}

func (cont *AciController) buildPodSubnetRemoteIps(ips []string, ipBlockSubs []string, ethertype string) []string {
	var podSubnetRemoteIps []string
	for _, podsubnet := range cont.config.PodSubnet {
		_, subnet, err := net.ParseCIDR(podsubnet)
		if err == nil && subnet != nil {
			if (ethertype == "ipv4" && subnet.IP.To4() != nil) || (ethertype == "ipv6" && subnet.IP.To4() == nil) {
				podSubnetRemoteIps = append(podSubnetRemoteIps, podsubnet)
			}
		}
	}
	podSubnetRemoteIps = append(podSubnetRemoteIps, ipBlockSubs...)
	for _, ip := range ips {
		if netIP := net.ParseIP(ip); netIP != nil && !cont.ipInPodSubnet(netIP) {
			podSubnetRemoteIps = append(podSubnetRemoteIps, ip)
		}
	}
	return podSubnetRemoteIps
}

func (cont *AciController) buildLocalNetPolSubjRules(
	subj *hppv1.HostprotSubj, direction string,
	resolved *resolvedPeerPorts, peers []v1net.NetworkPolicyPeer, netPolNs string, rics map[string]bool) {
	hasV4 := !cont.configuredPodNetworkIps.V4.Empty()
	hasV6 := !cont.configuredPodNetworkIps.V6.Empty()
	for _, entry := range resolved.entries {
		ricSuffix := ""
		if entry.portScoped {
			ricSuffix = entry.fromPort
		}
		entryName := "unspecified"
		if entry.proto != "" {
			entryName = protoPortKey(entry.proto, entry.fromPort)
		}
		// A rule with no peer selector at all (ingress: - {} / egress: - {})
		// has no remote-IP restriction to express: its resolved IP lists are
		// structurally always empty, not just currently empty. Omit
		// RsRemoteIpContainer entirely in that case, consistent with the
		// static/discovery allow-all rules, instead of referencing a RIC
		// that will forever hold zero IPs. Named-port entries are exempt:
		// they carry a real, pod-specific IP restriction even when the rule
		// itself has no From/To (see resolveNetPolPeersAndPorts).
		noRic := resolved.noPeers && !entry.portScoped

		if hasV4 {
			namePrefix := "ipv4"
			var ricNameV4 string
			if !noRic {
				var ricIpsV4 []string
				if resolved.addPodSubnetAsRemIp && !entry.portScoped {
					ricIpsV4 = cont.buildPodSubnetRemoteIps(entry.ipsV4, resolved.ipBlockSubsV4, "ipv4")
				} else {
					ricIpsV4 = entry.ipsV4
				}
				ricNameV4 = util.CreateHashFromNetPolPeers(peers, netPolNs, ricSuffix) + "-ipv4"
				namePrefix = ricNameV4
				cont.hppMutex.Lock()
				cont.remoteIpCache[ricNameV4] = ricIpsV4
				cont.queueRemoteIpConUpdateByKey(ricNameV4)
				rics[ricNameV4] = true
				cont.hppMutex.Unlock()
			}
			policyRuleName := util.AciNameForKey(namePrefix, "", entryName)
			if entry.proto == "" && entry.fromPort == "" {
				cont.buildLocalNetPolSubjRule(subj, policyRuleName, direction,
					"ipv4", "", "", "", ricNameV4, nil)
			} else {
				cont.buildLocalNetPolSubjRule(subj, policyRuleName, direction,
					"ipv4", entry.proto, entry.fromPort, entry.toPort, ricNameV4, nil)
			}
		}
		if hasV6 {
			namePrefix := "ipv6"
			var ricNameV6 string
			if !noRic {
				var ricIpsV6 []string
				if resolved.addPodSubnetAsRemIp && !entry.portScoped {
					ricIpsV6 = cont.buildPodSubnetRemoteIps(entry.ipsV6, resolved.ipBlockSubsV6, "ipv6")
				} else {
					ricIpsV6 = entry.ipsV6
				}
				ricNameV6 = util.CreateHashFromNetPolPeers(peers, netPolNs, ricSuffix) + "-ipv6"
				namePrefix = ricNameV6
				cont.hppMutex.Lock()
				cont.remoteIpCache[ricNameV6] = ricIpsV6
				cont.queueRemoteIpConUpdateByKey(ricNameV6)
				rics[ricNameV6] = true
				cont.hppMutex.Unlock()
			}
			policyRuleName := util.AciNameForKey(namePrefix, "", entryName)
			if entry.proto == "" && entry.fromPort == "" {
				cont.buildLocalNetPolSubjRule(subj, policyRuleName, direction,
					"ipv6", "", "", "", ricNameV6, nil)
			} else {
				cont.buildLocalNetPolSubjRule(subj, policyRuleName, direction,
					"ipv6", entry.proto, entry.fromPort, entry.toPort, ricNameV6, nil)
			}
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
				sort.Strings(remoteIpsv4)
				cont.buildLocalNetPolSubjRule(localsubj,
					"service_"+augment.proto+"_"+augment.port,
					"egress", "ipv4", augment.proto, augment.port, "", "", remoteIpsv4)
			}
			if len(remoteIpsv6) > 0 {
				sort.Strings(remoteIpsv6)
				cont.buildLocalNetPolSubjRule(localsubj,
					"service_"+augment.proto+"_"+augment.port,
					"egress", "ipv6", augment.proto, augment.port, "", "", remoteIpsv6)
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

func (cont *AciController) handleRemIpContUpdate(ricName string) bool {
	ns := os.Getenv("SYSTEM_NAMESPACE")
	// Read desired state
	cont.hppMutex.Lock()
	desiredIps, desiredExists := cont.remoteIpCache[ricName]
	cont.hppMutex.Unlock()

	// Read actual state from informer cache
	actual, err := cont.getHostprotRemoteIpContainer(ricName, ns)
	actualExists := err == nil

	if err != nil && !errors.IsNotFound(err) {
		cont.log.Error("Error getting HostprotRemoteIpContainer from cache: ", err)
		return true // requeue
	}

	// Reconcile: desired vs actual
	switch {
	case !desiredExists && !actualExists:
		// Nothing to do
		return false

	case !desiredExists && actualExists:
		if !cont.netPolSyncEnabled.Load() {
			return true // requeue until NP sync completes
		}
		// Desired state removed — delete the CR
		cont.log.Debug("Deleting HostprotRemoteIpContainer (no desired state): ", ricName)
		return !cont.deleteHostprotRemoteIpContainer(ricName, ns)

	case desiredExists && !actualExists:
		// CR doesn't exist yet — create it
		obj := &hppv1.HostprotRemoteIpContainer{
			ObjectMeta: metav1.ObjectMeta{
				Name:      ricName,
				Namespace: ns,
			},
			Spec: hppv1.HostprotRemoteIpContainerSpec{
				HostprotRemoteIps: desiredIps,
			},
		}
		cont.log.Debug("Creating HostprotRemoteIpContainer: ", ricName)
		return !cont.createHostprotRemoteIpContainer(obj, ns)

	default:
		// Both exist — compare and update if changed
		if slices.Equal(actual.Spec.HostprotRemoteIps, desiredIps) {
			return false // no-op
		}
		actual = actual.DeepCopy()
		actual.Spec.HostprotRemoteIps = desiredIps
		cont.log.Debug("Updating HostprotRemoteIpContainer: ", ricName)
		return !cont.updateHostprotRemoteIpContainer(actual, ns)
	}
}

func (cont *AciController) handleHppUpdate(hppName string) bool {
	ns := os.Getenv("SYSTEM_NAMESPACE")

	// Read desired state from the NP-derived cache.
	cont.hppMutex.Lock()
	ref, desiredExists := cont.hppDirRef[hppName]
	var desired *hppv1.HostprotPol
	if desiredExists {
		desired = ref.HppCr.DeepCopy()
	}
	cont.hppMutex.Unlock()

	// Read actual state from the informer cache.
	actual, err := cont.getHostprotPol(hppName, ns)
	actualExists := err == nil
	if err != nil && !errors.IsNotFound(err) {
		cont.log.Error("Error getting HostprotPol from cache: ", err)
		return true // requeue
	}

	switch {
	case !desiredExists && !actualExists:
		// Nothing to do.
		return false

	case !desiredExists && actualExists:
		if !cont.netPolSyncEnabled.Load() {
			return true // requeue until NP sync completes
		}
		// Desired state removed — delete the CR.
		cont.log.Debug("Deleting HostprotPol (no desired state): ", hppName)
		return !cont.deleteHostprotPol(hppName, ns)

	case desiredExists && !actualExists:
		// CR doesn't exist yet — create it.
		cont.log.Debug("Creating HostprotPol: ", hppName)
		return !cont.createHostprotPol(desired, ns)

	default:
		// Both exist — compare and update if changed.
		if reflect.DeepEqual(actual.Spec, desired.Spec) {
			return false // no-op
		}
		updated := actual.DeepCopy()
		updated.Spec = desired.Spec
		cont.log.Debug("Updating HostprotPol: ", hppName)
		return !cont.updateHostprotPol(updated, ns)
	}
}

// func (cont *AciController) updateNodeIpsHostprotRemoteIpContainer(nodeIps map[string]bool) {
// 	name := "nodeips"
// 	cont.hppMutex.Lock()
// 	existing := cont.remoteIpCache[name]
// 	existingSet := make(map[string]bool, len(existing))
// 	for _, ip := range existing {
// 		existingSet[ip] = true
// 	}
// 	for ip := range nodeIps {
// 		if !existingSet[ip] {
// 			existing = append(existing, ip)
// 		}
// 	}
// 	cont.remoteIpCache[name] = existing
// 	cont.hppMutex.Unlock()
// 	cont.queueRemoteIpConUpdateByKey(name)
// }

// func (cont *AciController) deleteNodeIpsHostprotRemoteIpContainer(nodeIps map[string]bool) {
// 	name := "nodeips"
// 	cont.hppMutex.Lock()
// 	existing := cont.remoteIpCache[name]
// 	if existing == nil {
// 		cont.hppMutex.Unlock()
// 		return
// 	}
// 	newIps := existing[:0]
// 	for _, ip := range existing {
// 		if !nodeIps[ip] {
// 			newIps = append(newIps, ip)
// 		}
// 	}
// 	if len(newIps) > 0 {
// 		cont.remoteIpCache[name] = newIps
// 	} else {
// 		delete(cont.remoteIpCache, name)
// 	}
// 	cont.hppMutex.Unlock()
// 	cont.queueRemoteIpConUpdateByKey(name)
// }

func (cont *AciController) updateNodeHostprotRemoteIpContainer(name string, nodeIps map[string]bool) {
	ips := make([]string, 0, len(nodeIps))
	for ip := range nodeIps {
		ips = append(ips, ip)
	}
	slices.Sort(ips)
	cont.hppMutex.Lock()
	cont.remoteIpCache[name] = ips
	cont.hppMutex.Unlock()
	cont.queueRemoteIpConUpdateByKey(name)
}

// clearNodeHostprotRemoteIps sets the RIC's IPs to empty but keeps the
// cache entry so the CR is updated (not deleted). The HPP still references
// this RIC by name.
func (cont *AciController) clearNodeHostprotRemoteIps(name string) {
	cont.hppMutex.Lock()
	cont.remoteIpCache[name] = nil
	cont.hppMutex.Unlock()
	cont.queueRemoteIpConUpdateByKey(name)
}

func (cont *AciController) createNodeHostProtPol(name, nodeName string, nodeIps map[string]bool) {
	ns := os.Getenv("SYSTEM_NAMESPACE")
	hppName := strings.ReplaceAll(name, "_", "-")

	hpp := &hppv1.HostprotPol{
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

	if len(nodeIps) > 0 {
		cont.updateNodeHostprotRemoteIpContainer(nodeName, nodeIps)
		// cont.updateNodeIpsHostprotRemoteIpContainer(nodeIps)

		hpp.Spec.HostprotSubj = append(hpp.Spec.HostprotSubj, hppv1.HostprotSubj{
			Name: "local-node",
			HostprotRule: []hppv1.HostprotRule{
				{
					Name:                "allow-all-egress",
					Direction:           "egress",
					Ethertype:           "ipv4",
					ConnTrack:           "normal",
					RsRemoteIpContainer: nodeName,
				},
				{
					Name:                "allow-all-ingress",
					Direction:           "ingress",
					Ethertype:           "ipv4",
					ConnTrack:           "normal",
					RsRemoteIpContainer: nodeName,
				},
			},
		})
	} else {
		cont.clearNodeHostprotRemoteIps(nodeName)
		// cont.deleteNodeIpsHostprotRemoteIpContainer(nodeIps)
	}

	cont.addToHppDirCache(hppName, name, hpp, nil)
	cont.queueHppUpdateByKey(hppName)
}

func (cont *AciController) deleteNodeHostProtPol(name, nodeName string) {
	hppName := strings.ReplaceAll(name, "_", "-")

	cont.hppMutex.Lock()
	cont.removeRemoteIpCacheEntry(nodeName)
	if _, ok := cont.hppDirRef[hppName]; ok {
		delete(cont.hppDirRef, hppName)
	}
	cont.hppMutex.Unlock()
	cont.queueHppUpdateByKey(hppName)
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

	if !cont.config.EnableHppDirect {
		var labelKey string
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

		var hasNamedPorts bool

		// Generate ingress policies
		if np.Spec.PolicyTypes == nil || ptypeset[v1net.PolicyTypeIngress] {
			subjIngress :=
				apicapi.NewHostprotSubj(hpp.GetDn(), "networkpolicy-ingress")

			for i, ingress := range np.Spec.Ingress {
				resolved := cont.resolveNetPolPeersAndPorts("ingress",
					ingress.From, ingress.Ports, peerPods, peerNs, np, logger)
				cont.buildNetPolSubjRules(strconv.Itoa(i), subjIngress, "ingress", resolved, np)
				if resolved.hasNamedPort {
					hasNamedPorts = true
				}
			}

			// Merge sibling NPs' named port resolutions into this subject.
			// Rule names encode the ingress-rule index + proto-port so siblings
			// produce identically-named rules. Cache full rule names and pull
			// missing ones from the previously-written HPP object.
			if cont.config.HppOptimization && hasNamedPorts {
				ruleNames := make(map[string]bool)
				for _, body := range subjIngress {
					for _, rule := range body.Children {
						name := rule.GetAttrStr("name")
						if name != "" {
							ruleNames[name] = true
						}
					}
				}
				cont.cacheNpOptIngressRules(labelKey, key, ruleNames)
				cont.mergeHppOptIngressRules(labelKey, key, ruleNames, subjIngress)
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
			cont.addToHppOptCache(labelKey, key, apicapi.ApicSlice{hpp})
		}
		cont.apicConn.WriteApicObjects(labelKey, apicapi.ApicSlice{hpp})
	} else {
		var hppACIName string
		hash, err := util.CreateCanonicalHashFromNetPol(np)
		if err != nil {
			logger.Error("Could not create hash from network policy: ", err)
			return false
		}
		hppACIName = cont.aciNameForKey("np", hash)
		ns := os.Getenv("SYSTEM_NAMESPACE")
		hppName := strings.ReplaceAll(hppACIName, "_", "-")

		hpp := &hppv1.HostprotPol{
			ObjectMeta: metav1.ObjectMeta{
				Name:      hppName,
				Namespace: ns,
			},
			Spec: hppv1.HostprotPolSpec{
				Name:            hppACIName,
				NetworkPolicies: []string{key},
				HostprotSubj:    nil,
			},
		}
		var rics = make(map[string]bool)

		var hasNamedPorts bool

		// Generate ingress policies
		if np.Spec.PolicyTypes == nil || ptypeset[v1net.PolicyTypeIngress] {
			subjIngress := &hppv1.HostprotSubj{
				Name:         "networkpolicy-ingress",
				HostprotRule: []hppv1.HostprotRule{},
			}

			for _, ingress := range np.Spec.Ingress {
				resolved := cont.resolveNetPolPeersAndPorts("ingress",
					ingress.From, ingress.Ports, peerPods, peerNs, np, logger)
				if resolved.hasNamedPort {
					hasNamedPorts = true
				}
				// if isAllowAllForAllNamespaces(ingress.From) {
				// 	if !slices.Contains(resolved.peerNsList, "nodeips") {
				// 		resolved.peerNsList = append(resolved.peerNsList, "nodeips")
				// 	}
				// }
				if !(!resolved.noPeers && len(resolved.subnetMap) == 0) {
					cont.buildLocalNetPolSubjRules(subjIngress, "ingress", resolved, ingress.From, np.ObjectMeta.Namespace, rics)
				}
			}

			// Merge sibling NPs' named port resolutions into this subject.
			// Cache full rule names and pull missing ones from the HPP CR.
			if hasNamedPorts {
				ruleNames := make(map[string]bool)
				for _, rule := range subjIngress.HostprotRule {
					if rule.Name != "" {
						ruleNames[rule.Name] = true
					}
				}
				cont.cacheNpDirIngressRules(hppName, key, ruleNames)
				cont.mergeHppDirectIngressRules(hppName, key, ruleNames, subjIngress)
			}
			canonicalizeHppRules(subjIngress.HostprotRule)
			hpp.Spec.HostprotSubj = append(hpp.Spec.HostprotSubj, *subjIngress)
		}

		if np.Spec.PolicyTypes == nil || ptypeset[v1net.PolicyTypeEgress] {
			subjEgress := &hppv1.HostprotSubj{
				Name:         "networkpolicy-egress",
				HostprotRule: []hppv1.HostprotRule{},
			}

			portRemoteSubs := make(map[string]*portRemoteSubnet)

			for _, egress := range np.Spec.Egress {
				resolved := cont.resolveNetPolPeersAndPorts("egress",
					egress.To, egress.Ports, peerPods, peerNs, np, logger)
				// if isAllowAllForAllNamespaces(egress.To) {
				// 	if !slices.Contains(resolved.peerNsList, "nodeips") {
				// 		resolved.peerNsList = append(resolved.peerNsList, "nodeips")
				// 	}
				// }
				if !(!resolved.noPeers && len(resolved.subnetMap) == 0) {
					cont.buildLocalNetPolSubjRules(subjEgress, "egress", resolved, egress.To, np.ObjectMeta.Namespace, rics)
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
			canonicalizeHppRules(subjEgress.HostprotRule)
			hpp.Spec.HostprotSubj = append(hpp.Spec.HostprotSubj, *subjEgress)
		}

		cont.addToHppDirCache(hppName, key, hpp, rics)
		cont.queueHppUpdateByKey(hppName)
	}
	return false
}

// mergeHppOptIngressRules merges missing ingress rules from sibling NPs into
// the current subject. It compares full rule names (which encode the ingress
// rule index + proto-port) to avoid false positives from overlapping ports
// in different ingress rules. Rules present in the HPP object but missing
// from the current NP are added if claimed by a sibling's cached rule names.
func (cont *AciController) mergeHppOptIngressRules(labelKey, key string,
	ruleNames map[string]bool, subjIngress apicapi.ApicObject) {
	cont.indexMutex.Lock()
	defer cont.indexMutex.Unlock()

	hppRef, ok := cont.hppOptRef[labelKey]
	if !ok {
		return
	}

	// Collect all rule names claimed by siblings but not in current NP.
	siblingNames := make(map[string]bool)
	for _, npKey := range hppRef.Npkeys {
		if npKey == key {
			continue
		}
		for name := range hppRef.NpIngressRules[npKey] {
			if !ruleNames[name] {
				siblingNames[name] = true
			}
		}
	}
	if len(siblingNames) == 0 {
		return
	}

	// Find rules in the HPP object whose names are claimed by siblings.
	for _, hppObj := range hppRef.HppObj {
		hppBody, ok := hppObj["hostprotPol"]
		if !ok || hppBody == nil {
			continue
		}
		for _, child := range hppBody.Children {
			subj, ok := child["hostprotSubj"]
			if !ok || subj == nil || subj.Attributes["name"] != "networkpolicy-ingress" {
				continue
			}
			for _, ruleChild := range subj.Children {
				rule, ok := ruleChild["hostprotRule"]
				if !ok || rule == nil {
					continue
				}
				name, _ := rule.Attributes["name"].(string)
				if siblingNames[name] {
					subjIngress.AddChild(ruleChild)
					delete(siblingNames, name)
				}
			}
		}
	}
}

// mergeHppDirectIngressRules merges missing ingress rules from sibling NPs
// into the current HPP-Direct subject. Same approach as mergeHppIngressRules
// but operates on the HPP CR struct instead of the APIC object tree.
func (cont *AciController) mergeHppDirectIngressRules(labelKey, key string,
	ruleNames map[string]bool, subjIngress *hppv1.HostprotSubj) {
	cont.hppMutex.Lock()
	defer cont.hppMutex.Unlock()

	hppRef, ok := cont.hppDirRef[labelKey]
	if !ok {
		return
	}

	// Collect all rule names claimed by siblings but not in current NP.
	siblingNames := make(map[string]bool)
	for _, npKey := range hppRef.Npkeys {
		if npKey == key {
			continue
		}
		for name := range hppRef.NpIngressRules[npKey] {
			if !ruleNames[name] {
				siblingNames[name] = true
			}
		}
	}
	if len(siblingNames) == 0 {
		return
	}

	// Find rules in the HPP CR whose names are claimed by siblings.
	for i := range hppRef.HppCr.Spec.HostprotSubj {
		subj := &hppRef.HppCr.Spec.HostprotSubj[i]
		if subj.Name != "networkpolicy-ingress" {
			continue
		}
		for _, rule := range subj.HostprotRule {
			// Stored rule names are already canonicalized (carry a
			// sequential index prefix), while siblingNames holds raw,
			// pre-canonicalization names cached by cacheNpDirIngressRules.
			// Compare base names so the lookup isn't defeated by the index
			// prefix.
			baseName := stripHppRuleIndex(rule.Name)
			if siblingNames[baseName] {
				subjIngress.HostprotRule = append(subjIngress.HostprotRule, rule)
				delete(siblingNames, baseName)
			}
		}
	}
}

func (cont *AciController) cacheNpOptIngressRules(labelKey, npKey string, names map[string]bool) {
	cont.indexMutex.Lock()
	defer cont.indexMutex.Unlock()
	ref := cont.hppOptRef[labelKey]
	if ref.NpIngressRules == nil {
		ref.NpIngressRules = make(map[string]map[string]bool)
	}
	ref.NpIngressRules[npKey] = names
	cont.hppOptRef[labelKey] = ref
}

func (cont *AciController) cacheNpDirIngressRules(labelKey, npKey string, names map[string]bool) {
	cont.hppMutex.Lock()
	defer cont.hppMutex.Unlock()
	ref := cont.hppDirRef[labelKey]
	if ref.NpIngressRules == nil {
		ref.NpIngressRules = make(map[string]map[string]bool)
	}
	ref.NpIngressRules[npKey] = names
	cont.hppDirRef[labelKey] = ref
}

func (cont *AciController) addToHppOptCache(labelKey, key string, hpp apicapi.ApicSlice) {
	cont.indexMutex.Lock()
	ref, ok := cont.hppOptRef[labelKey]
	if ok {
		var found bool
		for _, npkey := range ref.Npkeys {
			if npkey == key {
				found = true
				break
			}
		}
		if !found {
			ref.RefCount++
			ref.Npkeys = append(ref.Npkeys, key)
		}
		ref.HppObj = hpp
		cont.hppOptRef[labelKey] = ref
	} else {
		cont.hppOptRef[labelKey] = hppOptReference{
			RefCount: 1,
			Npkeys:   []string{key},
			HppObj:   hpp,
		}
	}
	cont.indexMutex.Unlock()
}

func (cont *AciController) addToHppDirCache(hppName, key string, hppcr *hppv1.HostprotPol, newRicNames map[string]bool) {
	cont.hppMutex.Lock()
	ref, ok := cont.hppDirRef[hppName]
	if ok {
		pos, found := slices.BinarySearch(ref.Npkeys, key)
		if !found {
			ref.Npkeys = slices.Insert(ref.Npkeys, pos, key)
			ref.RefCount++
		}
		ref.HppCr = *hppcr
	} else {
		ref = hppDirReference{
			RefCount: 1,
			Npkeys:   []string{key},
			HppCr:    *hppcr,
		}
	}
	ref.HppCr.Spec.NetworkPolicies = ref.Npkeys

	// Update RIC reverse index: remove stale, add new.
	oldRicNames := ref.RicNames
	for ric := range oldRicNames {
		if !newRicNames[ric] {
			if hpps := cont.ricRefCount[ric]; hpps != nil {
				delete(hpps, hppName)
				if len(hpps) == 0 {
					delete(cont.ricRefCount, ric)
					cont.removeRemoteIpCacheEntry(ric)
				}
			}
		}
	}
	for ric := range newRicNames {
		if !oldRicNames[ric] {
			if cont.ricRefCount[ric] == nil {
				cont.ricRefCount[ric] = make(map[string]bool)
			}
			cont.ricRefCount[ric][hppName] = true
		}
	}
	ref.RicNames = newRicNames

	cont.hppDirRef[hppName] = ref
	cont.hppMutex.Unlock()
}

func (cont *AciController) removeFromHppDirCache(np *v1net.NetworkPolicy, key string) (string, bool) {
	hash, err := util.CreateCanonicalHashFromNetPol(np)
	if err != nil {
		cont.log.Error("Could not create hash from network policy: ", err)
		cont.log.Error("Failed to remove np from hpp cache")
		return "", false
	}
	hppACIName := cont.aciNameForKey("np", hash)
	hppName := strings.ReplaceAll(hppACIName, "_", "-")
	var noRef bool
	cont.hppMutex.Lock()
	ref, ok := cont.hppDirRef[hppName]
	if ok {
		pos, found := slices.BinarySearch(ref.Npkeys, key)
		if found {
			ref.Npkeys = slices.Delete(ref.Npkeys, pos, pos+1)
			ref.RefCount--
		}
		_, hadRuleCache := ref.NpIngressRules[key]
		delete(ref.NpIngressRules, key)
		if ref.RefCount > 0 {
			ref.HppCr.Spec.NetworkPolicies = ref.Npkeys
			cont.hppDirRef[hppName] = ref
			if hadRuleCache {
				cont.queueNetPolUpdateByKey(ref.Npkeys[0])
			} else {
				// NetworkPolicies list changed; reconcile the HPP CR.
				cont.queueHppUpdateByKey(hppName)
			}
		} else {
			// Clean up RIC reverse index for this HPP.
			for ric := range ref.RicNames {
				if hpps := cont.ricRefCount[ric]; hpps != nil {
					delete(hpps, hppName)
					if len(hpps) == 0 {
						delete(cont.ricRefCount, ric)
						cont.removeRemoteIpCacheEntry(ric)
					}
				}
			}
			delete(cont.hppDirRef, hppName)
			noRef = true
			// Desired state gone — reconcile to delete the HPP CR.
			cont.queueHppUpdateByKey(hppName)
		}
	}
	cont.hppMutex.Unlock()
	return hppACIName, noRef
}

func (cont *AciController) removeFromHppOptCache(np *v1net.NetworkPolicy, key string) (string, bool) {
	hash, err := util.CreateHashFromNetPol(np)
	if err != nil {
		cont.log.Error("Could not create hash from network policy: ", err)
		cont.log.Error("Failed to remove np from hpp cache")
		return "", false
	}
	labelKey := cont.aciNameForKey("np", hash)
	var noRef bool
	cont.indexMutex.Lock()
	ref, ok := cont.hppOptRef[labelKey]
	if ok {
		for i, npkey := range ref.Npkeys {
			if npkey == key {
				ref.Npkeys = append(ref.Npkeys[:i], ref.Npkeys[i+1:]...)
				ref.RefCount--
				break
			}
		}
		_, hadRuleCache := ref.NpIngressRules[key]
		delete(ref.NpIngressRules, key)
		if ref.RefCount > 0 {
			cont.hppOptRef[labelKey] = ref
			if hadRuleCache {
				cont.queueNetPolUpdateByKey(ref.Npkeys[0])
			}
		} else {
			delete(cont.hppOptRef, labelKey)
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

	if cont.config.EnableHppDirect {
		if !reflect.DeepEqual(oldnp.Spec, newnp.Spec) {
			cont.removeFromHppDirCache(oldnp, npkey)
		}
	} else if cont.config.HppOptimization {
		if !reflect.DeepEqual(oldnp.Spec, newnp.Spec) {
			labelKey, noHppRef := cont.removeFromHppOptCache(oldnp, npkey)
			if noHppRef && labelKey != "" {
				cont.apicConn.ClearApicObjects(labelKey)
			}
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
		// The old spec was removed from its HPP by removeFromHppCache above
		// (which reconciles the old HPP CR). Reprocess the NP so the new spec
		// is rendered into its (possibly different) HPP.
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
			cont.log.Error("DeletedFinalStateUnknown contained non-Networkpolicy object: ", deletedState.Obj)
			return
		}
	}
	npkey, err := cache.MetaNamespaceKeyFunc(np)
	if err != nil {
		networkPolicyLogger(cont.log, np).
			Error("Could not create network policy key: ", err)
		return
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

	if cont.config.HppOptimization {
		labelKey, noHppRef := cont.removeFromHppOptCache(np, npkey)
		if noHppRef && labelKey != "" {
			cont.apicConn.ClearApicObjects(labelKey)
		}
	} else if cont.config.EnableHppDirect {
		// HPP obj delete handled by removeFromHppDirCache, skip setting labelKey and noHppRef for clearApicObjects
		cont.removeFromHppDirCache(np, npkey)
	} else {
		labelKey := cont.aciNameForKey("np", npkey)
		cont.apicConn.ClearApicObjects(labelKey)
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
