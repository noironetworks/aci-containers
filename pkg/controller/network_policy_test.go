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

package controller

import (
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	v1 "k8s.io/api/core/v1"
	v1net "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/tools/cache"

	"github.com/noironetworks/aci-containers/pkg/apicapi"
	hppv1 "github.com/noironetworks/aci-containers/pkg/hpp/apis/aci.hpp/v1"
	"github.com/noironetworks/aci-containers/pkg/hpp/clientset/versioned/fake"
	"github.com/noironetworks/aci-containers/pkg/ipam"
	tu "github.com/noironetworks/aci-containers/pkg/testutil"
	"github.com/noironetworks/aci-containers/pkg/util"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	discovery "k8s.io/api/discovery/v1"
)

var tcp = "TCP"
var udp = "UDP"
var sctp = "SCTP"
var port80 = 80
var eport90 = int32(90)
var port443 = 443

func port(proto *string, port *int) v1net.NetworkPolicyPort {
	var portv intstr.IntOrString
	var protov v1.Protocol
	if port != nil {
		portv = intstr.FromInt(*port)
	}
	if proto != nil {
		protov = v1.Protocol(*proto)
	}
	return v1net.NetworkPolicyPort{
		Protocol: &protov,
		Port:     &portv,
	}
}

func rangedPort(proto *string, port *int, endport *int32) v1net.NetworkPolicyPort {
	var portv intstr.IntOrString
	var porte *int32
	var protov v1.Protocol
	if port != nil {
		portv = intstr.FromInt(*port)
	}
	if endport != nil {
		porte = endport
	}
	if proto != nil {
		protov = v1.Protocol(*proto)
	}
	return v1net.NetworkPolicyPort{
		Protocol: &protov,
		Port:     &portv,
		EndPort:  porte,
	}
}

func servicePort(name string, proto v1.Protocol, port int32, targetPort int) v1.ServicePort {
	return v1.ServicePort{
		Name:       name,
		Protocol:   proto,
		Port:       port,
		TargetPort: intstr.FromInt(targetPort),
	}
}

func servicePortNamed(name string, proto v1.Protocol, port int32, targetPortName string) v1.ServicePort {
	return v1.ServicePort{
		Name:       name,
		Protocol:   proto,
		Port:       port,
		TargetPort: intstr.FromString(targetPortName),
	}
}

func endpointPort(proto v1.Protocol, port int32, name string) v1.EndpointPort {
	return v1.EndpointPort{
		Name:     name,
		Protocol: proto,
		Port:     port,
	}
}
func endpointSlicePort(proto v1.Protocol, port int32, name string) discovery.EndpointPort {
	return discovery.EndpointPort{
		Name:     func() *string { a := name; return &a }(),
		Protocol: func() *v1.Protocol { a := proto; return &a }(),
		Port:     func() *int32 { a := port; return &a }(),
	}
}

func peer(podSelector *metav1.LabelSelector,
	nsSelector *metav1.LabelSelector) v1net.NetworkPolicyPeer {
	return v1net.NetworkPolicyPeer{
		PodSelector:       podSelector,
		NamespaceSelector: nsSelector,
	}
}

func peerIpBlock(peer v1net.NetworkPolicyPeer,
	cidr string, except []string) v1net.NetworkPolicyPeer {
	peer.IPBlock = &v1net.IPBlock{
		CIDR:   cidr,
		Except: except,
	}
	return peer
}

func ingressRule(ports []v1net.NetworkPolicyPort,
	from []v1net.NetworkPolicyPeer) v1net.NetworkPolicyIngressRule {
	return v1net.NetworkPolicyIngressRule{
		Ports: ports,
		From:  from,
	}
}

func egressRule(ports []v1net.NetworkPolicyPort,
	to []v1net.NetworkPolicyPeer) v1net.NetworkPolicyEgressRule {
	return v1net.NetworkPolicyEgressRule{
		Ports: ports,
		To:    to,
	}
}

var allPolicyTypes = []v1net.PolicyType{
	v1net.PolicyTypeIngress,
	v1net.PolicyTypeEgress,
}

func netpol(namespace string, name string, podSelector *metav1.LabelSelector,
	irules []v1net.NetworkPolicyIngressRule,
	erules []v1net.NetworkPolicyEgressRule,
	ptypes []v1net.PolicyType) *v1net.NetworkPolicy {
	return &v1net.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: v1net.NetworkPolicySpec{
			PolicyTypes: ptypes,
			PodSelector: *podSelector,
			Ingress:     irules,
			Egress:      erules,
		},
	}
}

func npservice(namespace string, name string,
	clusterIP string, ports []v1.ServicePort) *v1.Service {
	service := service(namespace, name, "")
	service.Spec.ClusterIP = clusterIP
	service.Spec.Ports = ports
	return service
}

type npTestAugment struct {
	endpoints      []*v1.Endpoints
	services       []*v1.Service
	endpointslices []*discovery.EndpointSlice
}

type npTest struct {
	netPol  *v1net.NetworkPolicy
	aciObj  apicapi.ApicObject
	augment *npTestAugment
	desc    string
}

func staticNetPolKey() string {
	return "kube_np_static"
}

func addPods(cont *testAciController, incIps bool, ips []string, ipv4 bool) {
	var pods []*v1.Pod
	if ipv4 {
		pods = []*v1.Pod{
			podLabel("testns", "pod1", map[string]string{"l1": "v1"}),
			podLabel("testns", "pod2", map[string]string{"l1": "v2"}),
		}
	} else {
		pods = []*v1.Pod{
			podLabel("testnsv6", "pod1", map[string]string{"l1": "v1"}),
			podLabel("testnsv6", "pod2", map[string]string{"l1": "v2"}),
		}
	}
	pods = append(pods, podLabel("ns1", "pod3", map[string]string{"l1": "v1"}),
		podLabel("ns1", "pod4", map[string]string{"l1": "v2"}),
		podLabel("ns2", "pod5", map[string]string{"l1": "v1"}),
		podLabel("ns2", "pod6", map[string]string{"l1": "v2"}))
	if incIps {
		for i := range pods {
			pods[i].Status.PodIP = ips[i]
		}
	}
	for _, pod := range pods {
		cont.fakePodSource.Add(pod)
	}
}

func addServices(cont *testAciController, augment *npTestAugment) {
	if augment == nil {
		return
	}
	for _, s := range augment.services {
		cont.fakeServiceSource.Add(s)
	}
	for _, e := range augment.endpoints {
		cont.fakeEndpointsSource.Add(e)
	}
	for _, e := range augment.endpointslices {
		cont.fakeEndpointSliceSource.Add(e)
	}
}

func makeNp(ingress apicapi.ApicSlice,
	egress apicapi.ApicSlice, name string) apicapi.ApicObject {
	np1 := apicapi.NewHostprotPol("test-tenant", name)
	np1SubjI :=
		apicapi.NewHostprotSubj(np1.GetDn(), "networkpolicy-ingress")
	np1.AddChild(np1SubjI)
	for _, r := range ingress {
		np1SubjI.AddChild(r)
	}
	np1SubjE :=
		apicapi.NewHostprotSubj(np1.GetDn(), "networkpolicy-egress")
	for _, r := range egress {
		np1SubjE.AddChild(r)
	}
	np1.AddChild(np1SubjE)
	return np1
}

func makeEps(namespace string, name string,
	addrs []v1.EndpointAddress, ports []v1.EndpointPort) *v1.Endpoints {
	return &v1.Endpoints{
		Subsets: []v1.EndpointSubset{
			{
				Addresses: addrs,
				Ports:     ports,
			},
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   namespace,
			Name:        name,
			Annotations: map[string]string{},
		},
	}
}

// endpointslice.
func makeEpSlice(namespace string, name string, endpoints []discovery.Endpoint,
	ports []discovery.EndpointPort, servicename string) *discovery.EndpointSlice {
	return &discovery.EndpointSlice{
		AddressType: discovery.AddressTypeIPv4,
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   namespace,
			Labels:      map[string]string{discovery.LabelServiceName: servicename},
			Annotations: map[string]string{},
		},
		Endpoints: endpoints,
		Ports:     ports,
	}
}

func checkNp(t *testing.T, nt *npTest, category string, cont *testAciController) {
	tu.WaitFor(t, category+"/"+nt.desc, 3500*time.Millisecond,
		func(last bool) (bool, error) {
			slice := apicapi.ApicSlice{nt.aciObj}
			var key string
			if cont.config.HppOptimization {
				hash, _ := util.CreateHashFromNetPol(nt.netPol)
				key = cont.aciNameForKey("np", hash)
			} else {
				key = cont.aciNameForKey("np",
					nt.netPol.Namespace+"/"+nt.netPol.Name)
			}
			apicapi.PrepareApicSlice(slice, "kube", key)
			if !tu.WaitEqual(t, last, slice,
				cont.apicConn.GetDesiredState(key), nt.desc, key) {
				return false, nil
			}
			return true, nil
		})
}

func checkDelete(t *testing.T, nt npTest, cont *testAciController) {
	tu.WaitFor(t, "delete", 500*time.Millisecond,
		func(last bool) (bool, error) {
			key := cont.aciNameForKey("np",
				nt.netPol.Namespace+"_"+nt.netPol.Name)
			if !tu.WaitEqual(t, last, 0,
				len(cont.apicConn.GetDesiredState(key)), "delete") {
				return false, nil
			}
			return true, nil
		})
}

func createRule(name string, ingress bool, attr map[string]string,
	rulename string) apicapi.ApicObject {
	var np1SDn string
	baseDn := makeNp(nil, nil, name).GetDn()
	if ingress {
		np1SDn = fmt.Sprintf("%s/subj-networkpolicy-ingress", baseDn)
	} else {
		np1SDn = fmt.Sprintf("%s/subj-networkpolicy-egress", baseDn)
	}
	rule := apicapi.NewHostprotRule(np1SDn, rulename)
	for k, v := range attr {
		rule.SetAttr(k, v)
	}
	return rule
}

func TestNetworkPolicy(t *testing.T) {
	name := "kube_np_testns_np1"
	baseDn := makeNp(nil, nil, name).GetDn()
	np1SDnI := fmt.Sprintf("%s/subj-networkpolicy-ingress", baseDn)
	np1SDnE := fmt.Sprintf("%s/subj-networkpolicy-egress", baseDn)

	rule_0_0 := apicapi.NewHostprotRule(np1SDnI, "0-ipv4__np1")
	rule_0_0.SetAttr("direction", "ingress")
	rule_0_0.SetAttr("ethertype", "ipv4")

	rule_1_0 := apicapi.NewHostprotRule(np1SDnI, "0_0-ipv4__np1")
	rule_1_0.SetAttr("direction", "ingress")
	rule_1_0.SetAttr("ethertype", "ipv4")
	rule_1_0.SetAttr("protocol", "tcp")
	rule_1_0.SetAttr("fromPort", "80")

	rule_1_0_1 := apicapi.NewHostprotRule(np1SDnI, "0_0-ipv4__np1")
	rule_1_0_1.SetAttr("direction", "ingress")
	rule_1_0_1.SetAttr("ethertype", "ipv4")
	rule_1_0_1.SetAttr("protocol", "tcp")
	rule_1_0_1.SetAttr("fromPort", "80")
	rule_1_0_1.SetAttr("toPort", "90")

	rule_2_0 := apicapi.NewHostprotRule(np1SDnI, "0_0-ipv4__np1")
	rule_2_0.SetAttr("direction", "ingress")
	rule_2_0.SetAttr("ethertype", "ipv4")
	rule_2_0.SetAttr("protocol", "tcp")
	rule_2_0.SetAttr("fromPort", "80")
	rule_2_0.AddChild(
		apicapi.NewHostprotRemoteIp(rule_2_0.GetDn(), "8.8.8.0/29"))
	rule_2_0.AddChild(
		apicapi.NewHostprotRemoteIp(rule_2_0.GetDn(), "8.8.8.10/31"))
	rule_2_0.AddChild(
		apicapi.NewHostprotRemoteIp(rule_2_0.GetDn(), "8.8.8.12/30"))
	rule_2_0.AddChild(
		apicapi.NewHostprotRemoteIp(rule_2_0.GetDn(), "8.8.8.128/25"))
	rule_2_0.AddChild(
		apicapi.NewHostprotRemoteIp(rule_2_0.GetDn(), "8.8.8.16/28"))
	rule_2_0.AddChild(
		apicapi.NewHostprotRemoteIp(rule_2_0.GetDn(), "8.8.8.32/27"))
	rule_2_0.AddChild(
		apicapi.NewHostprotRemoteIp(rule_2_0.GetDn(), "8.8.8.64/26"))

	rule_3_0 := apicapi.NewHostprotRule(np1SDnI, "0_0-ipv4__np1")
	rule_3_0.SetAttr("direction", "ingress")
	rule_3_0.SetAttr("ethertype", "ipv4")
	rule_3_0.SetAttr("protocol", "udp")
	rule_3_0.SetAttr("fromPort", "80")

	rule_3_1 := apicapi.NewHostprotRule(np1SDnI, "0_0-ipv4__np1")
	rule_3_1.SetAttr("direction", "ingress")
	rule_3_1.SetAttr("ethertype", "ipv4")
	rule_3_1.SetAttr("protocol", "udp")
	rule_3_1.SetAttr("toPort", "unspecified")

	rule_4_1 := apicapi.NewHostprotRule(np1SDnI, "0_1-ipv4__np1")
	rule_4_1.SetAttr("direction", "ingress")
	rule_4_1.SetAttr("ethertype", "ipv4")
	rule_4_1.SetAttr("protocol", "tcp")
	rule_4_1.SetAttr("fromPort", "443")

	rule_5_0 := apicapi.NewHostprotRule(np1SDnI, "0-ipv4__np1")
	rule_5_0.SetAttr("direction", "ingress")
	rule_5_0.SetAttr("ethertype", "ipv4")
	rule_5_0.AddChild(apicapi.NewHostprotRemoteIp(rule_5_0.GetDn(), "1.1.1.1"))
	rule_5_0.AddChild(apicapi.NewHostprotRemoteIp(rule_5_0.GetDn(), "1.1.1.2"))

	rule_6_0 := apicapi.NewHostprotRule(np1SDnI, "0-ipv4__np1")
	rule_6_0.SetAttr("direction", "ingress")
	rule_6_0.SetAttr("ethertype", "ipv4")
	rule_6_0.AddChild(apicapi.NewHostprotRemoteIp(rule_6_0.GetDn(), "1.1.1.3"))
	rule_6_0.AddChild(apicapi.NewHostprotRemoteIp(rule_6_0.GetDn(), "1.1.1.4"))
	rule_6_0.AddChild(apicapi.NewHostprotRemoteIp(rule_6_0.GetDn(), "1.1.1.5"))

	rule_7_0 := apicapi.NewHostprotRule(np1SDnI, "0-ipv4__np1")
	rule_7_0.SetAttr("direction", "ingress")
	rule_7_0.SetAttr("ethertype", "ipv4")
	rule_7_0.AddChild(apicapi.NewHostprotRemoteIp(rule_7_0.GetDn(), "1.1.1.1"))

	rule_8_0 := apicapi.NewHostprotRule(np1SDnI, "0_0-ipv4__np1")
	rule_8_0.SetAttr("direction", "ingress")
	rule_8_0.SetAttr("ethertype", "ipv4")
	rule_8_0.SetAttr("protocol", "tcp")
	rule_8_0.SetAttr("fromPort", "80")
	rule_8_0.AddChild(apicapi.NewHostprotRemoteIp(rule_8_0.GetDn(), "1.1.1.1"))
	rule_8_1 := apicapi.NewHostprotRule(np1SDnI, "1_0-ipv4__np1")
	rule_8_1.SetAttr("direction", "ingress")
	rule_8_1.SetAttr("ethertype", "ipv4")
	rule_8_1.SetAttr("protocol", "tcp")
	rule_8_1.SetAttr("fromPort", "443")
	rule_8_1.AddChild(apicapi.NewHostprotRemoteIp(rule_8_1.GetDn(), "1.1.1.2"))

	rule_9_0 := apicapi.NewHostprotRule(np1SDnI, "0-ipv4__np1")
	rule_9_0.SetAttr("direction", "ingress")
	rule_9_0.SetAttr("ethertype", "ipv4")
	rule_9_0.AddChild(apicapi.NewHostprotRemoteIp(rule_9_0.GetDn(), "1.1.1.3"))
	rule_9_0.AddChild(apicapi.NewHostprotRemoteIp(rule_9_0.GetDn(), "1.1.1.5"))

	rule_10_0 := apicapi.NewHostprotRule(np1SDnE, "0-ipv4__np1")
	rule_10_0.SetAttr("direction", "egress")
	rule_10_0.SetAttr("ethertype", "ipv4")
	rule_10_0.AddChild(apicapi.NewHostprotRemoteIp(rule_10_0.GetDn(), "1.1.1.3"))
	rule_10_0.AddChild(apicapi.NewHostprotRemoteIp(rule_10_0.GetDn(), "1.1.1.5"))

	rule_11_0 := apicapi.NewHostprotRule(np1SDnE, "0_0-ipv4__np1")
	rule_11_0.SetAttr("direction", "egress")
	rule_11_0.SetAttr("ethertype", "ipv4")
	rule_11_0.SetAttr("protocol", "tcp")
	rule_11_0.SetAttr("fromPort", "80")
	rule_11_0.AddChild(apicapi.NewHostprotRemoteIp(rule_11_0.GetDn(), "1.1.1.1"))

	rule_11_s := apicapi.NewHostprotRule(np1SDnE, "service_tcp_8080-ipv4")
	rule_11_s.SetAttr("direction", "egress")
	rule_11_s.SetAttr("ethertype", "ipv4")
	rule_11_s.SetAttr("protocol", "tcp")
	rule_11_s.SetAttr("fromPort", "8080")
	rule_11_s.AddChild(apicapi.NewHostprotRemoteIp(rule_11_s.GetDn(), "9.0.0.42"))

	rule_12_0 := apicapi.NewHostprotRule(np1SDnE, "0-ipv4__np1")
	rule_12_0.SetAttr("direction", "egress")
	rule_12_0.SetAttr("ethertype", "ipv4")
	rule_12_0.AddChild(apicapi.NewHostprotRemoteIp(rule_12_0.GetDn(),
		"1.1.1.0/24"))

	rule_12_s_0 := apicapi.NewHostprotRule(np1SDnE, "service_tcp_8080-ipv4")
	rule_12_s_0.SetAttr("direction", "egress")
	rule_12_s_0.SetAttr("ethertype", "ipv4")
	rule_12_s_0.SetAttr("protocol", "tcp")
	rule_12_s_0.SetAttr("fromPort", "8080")
	rule_12_s_0.AddChild(apicapi.NewHostprotRemoteIp(rule_12_s_0.GetDn(),
		"9.0.0.44"))

	rule_12_s_1 := apicapi.NewHostprotRule(np1SDnE, "service_tcp_8443-ipv4")
	rule_12_s_1.SetAttr("direction", "egress")
	rule_12_s_1.SetAttr("ethertype", "ipv4")
	rule_12_s_1.SetAttr("protocol", "tcp")
	rule_12_s_1.SetAttr("fromPort", "8443")
	rule_12_s_1.AddChild(apicapi.NewHostprotRemoteIp(rule_12_s_1.GetDn(),
		"9.0.0.44"))

	rule_13_0 := apicapi.NewHostprotRule(np1SDnE, "0-ipv4__np1")
	rule_13_0.SetAttr("direction", "egress")
	rule_13_0.SetAttr("ethertype", "ipv4")

	rule_14_0 := apicapi.NewHostprotRule(np1SDnE, "0_0-ipv4__np1")
	rule_14_0.SetAttr("direction", "egress")
	rule_14_0.SetAttr("ethertype", "ipv4")
	rule_14_0.SetAttr("protocol", "tcp")
	rule_14_0.SetAttr("fromPort", "80")

	rule_14_s := apicapi.NewHostprotRule(np1SDnE, "service_tcp_8080-ipv4")
	rule_14_s.SetAttr("direction", "egress")
	rule_14_s.SetAttr("ethertype", "ipv4")
	rule_14_s.SetAttr("protocol", "tcp")
	rule_14_s.SetAttr("fromPort", "8080")
	rule_14_s.AddChild(apicapi.NewHostprotRemoteIp(rule_14_s.GetDn(), "9.0.0.42"))

	rule_15_0 := apicapi.NewHostprotRule(np1SDnI, "0_0-ipv4__np1")
	rule_15_0.SetAttr("direction", "ingress")
	rule_15_0.SetAttr("ethertype", "ipv4")
	rule_15_0.SetAttr("protocol", "sctp")
	rule_15_0.SetAttr("fromPort", "80")

	rule_11_0_portrange := apicapi.NewHostprotRule(np1SDnE, "0_0-ipv4__np1")
	rule_11_0_portrange.SetAttr("direction", "egress")
	rule_11_0_portrange.SetAttr("ethertype", "ipv4")
	rule_11_0_portrange.SetAttr("protocol", "tcp")
	rule_11_0_portrange.SetAttr("fromPort", "80")
	rule_11_0_portrange.SetAttr("toPort", "90")
	rule_11_0_portrange.AddChild(apicapi.NewHostprotRemoteIp(rule_11_0_portrange.GetDn(), "1.1.1.1"))

	rule_11_s_portrange := apicapi.NewHostprotRule(np1SDnE, "service_tcp_8080-ipv4")
	rule_11_s_portrange.SetAttr("direction", "egress")
	rule_11_s_portrange.SetAttr("ethertype", "ipv4")
	rule_11_s_portrange.SetAttr("protocol", "tcp")
	rule_11_s_portrange.SetAttr("fromPort", "8080")
	rule_11_s_portrange.AddChild(apicapi.NewHostprotRemoteIp(rule_11_s_portrange.GetDn(), "9.0.0.42"))

	udp_proto := v1.Protocol(udp)
	var npTests = []npTest{
		{netpol("testns", "np1", &metav1.LabelSelector{},
			[]v1net.NetworkPolicyIngressRule{ingressRule(nil, nil)},
			nil, allPolicyTypes),
			makeNp(apicapi.ApicSlice{rule_0_0}, nil, name),
			nil, "allow-all"},
		{netpol("testns", "np1", &metav1.LabelSelector{},
			[]v1net.NetworkPolicyIngressRule{
				ingressRule([]v1net.NetworkPolicyPort{port(&tcp, &port80)},
					nil)}, nil, allPolicyTypes),
			makeNp(apicapi.ApicSlice{rule_1_0}, nil, name),
			nil, "allow-http"},
		{netpol("testns", "np1", &metav1.LabelSelector{},
			[]v1net.NetworkPolicyIngressRule{
				ingressRule([]v1net.NetworkPolicyPort{rangedPort(&tcp, &port80, &eport90)},
					nil)}, nil, allPolicyTypes),
			makeNp(apicapi.ApicSlice{rule_1_0_1}, nil, name),
			nil, "allow-http-portrange"},
		{netpol("testns", "np1", &metav1.LabelSelector{},
			[]v1net.NetworkPolicyIngressRule{
				ingressRule([]v1net.NetworkPolicyPort{port(&tcp, &port80)},
					[]v1net.NetworkPolicyPeer{
						peerIpBlock(peer(nil, nil),
							"8.8.8.8/24", []string{"8.8.8.9/31"}),
					},
				)}, nil, allPolicyTypes),
			makeNp(apicapi.ApicSlice{rule_2_0}, nil, name),
			nil, "allow-http-from"},
		{netpol("testns", "np1", &metav1.LabelSelector{},
			[]v1net.NetworkPolicyIngressRule{
				ingressRule([]v1net.NetworkPolicyPort{
					port(nil, &port80)}, nil)}, nil, allPolicyTypes),
			makeNp(apicapi.ApicSlice{rule_1_0}, nil, name),
			nil, "allow-http-defproto"},
		{netpol("testns", "np1", &metav1.LabelSelector{},
			[]v1net.NetworkPolicyIngressRule{
				ingressRule([]v1net.NetworkPolicyPort{
					port(&udp, &port80)}, nil)}, nil, allPolicyTypes),
			makeNp(apicapi.ApicSlice{rule_3_0}, nil, name),
			nil, "allow-80-udp"},
		{netpol("testns", "np1", &metav1.LabelSelector{},
			[]v1net.NetworkPolicyIngressRule{
				ingressRule([]v1net.NetworkPolicyPort{
					port(&udp, nil)}, nil)}, nil, allPolicyTypes),
			makeNp(apicapi.ApicSlice{rule_3_1}, nil, name),
			nil, "allow-udp"},
		{netpol("testns", "np1", &metav1.LabelSelector{},
			[]v1net.NetworkPolicyIngressRule{
				ingressRule([]v1net.NetworkPolicyPort{
					{
						Protocol: &udp_proto,
						Port:     nil,
					}}, nil)}, nil, allPolicyTypes),
			makeNp(apicapi.ApicSlice{rule_3_1}, nil, name),
			nil, "allow-udp"},
		{netpol("testns", "np1", &metav1.LabelSelector{},
			[]v1net.NetworkPolicyIngressRule{
				ingressRule([]v1net.NetworkPolicyPort{
					port(&sctp, &port80)}, nil)}, nil, allPolicyTypes),
			makeNp(apicapi.ApicSlice{rule_15_0}, nil, name),
			nil, "allow-80-sctp"},
		{netpol("testns", "np1", &metav1.LabelSelector{},
			[]v1net.NetworkPolicyIngressRule{
				ingressRule([]v1net.NetworkPolicyPort{
					port(nil, &port80), port(nil, &port443),
				}, nil)}, nil, allPolicyTypes),
			makeNp(apicapi.ApicSlice{rule_1_0, rule_4_1}, nil, name),
			nil, "allow-http-https"},
		{netpol("testns", "np1", &metav1.LabelSelector{},
			[]v1net.NetworkPolicyIngressRule{ingressRule(nil,
				[]v1net.NetworkPolicyPeer{peer(nil,
					&metav1.LabelSelector{
						MatchLabels: map[string]string{"test": "testv"},
					}),
				}),
			}, nil, allPolicyTypes),
			makeNp(apicapi.ApicSlice{rule_5_0}, nil, name),
			nil, "allow-all-from-ns"},
		{netpol("testns", "np1", &metav1.LabelSelector{},
			[]v1net.NetworkPolicyIngressRule{ingressRule(nil,
				[]v1net.NetworkPolicyPeer{peer(nil,
					&metav1.LabelSelector{
						MatchLabels: map[string]string{"test": "notathing"},
					}),
				}),
			}, nil, allPolicyTypes),
			makeNp(nil, nil, name),
			nil, "allow-all-from-ns-no-match"},
		{netpol("testns", "np1", &metav1.LabelSelector{},
			[]v1net.NetworkPolicyIngressRule{ingressRule(nil,
				[]v1net.NetworkPolicyPeer{peer(nil,
					&metav1.LabelSelector{
						MatchLabels: map[string]string{"nl": "nv"},
					}),
				}),
			}, nil, allPolicyTypes),
			makeNp(apicapi.ApicSlice{rule_6_0}, nil, name),
			nil, "allow-all-from-multiple-ns"},
		{netpol("testns", "np1", &metav1.LabelSelector{},
			[]v1net.NetworkPolicyIngressRule{ingressRule(nil,
				[]v1net.NetworkPolicyPeer{
					peer(&metav1.LabelSelector{
						MatchLabels: map[string]string{"l1": "v1"},
					}, nil),
				}),
			}, nil, allPolicyTypes),
			makeNp(apicapi.ApicSlice{rule_7_0}, nil, name),
			nil, "allow-all-select-pods"},
		{netpol("testns", "np1", &metav1.LabelSelector{},
			[]v1net.NetworkPolicyIngressRule{ingressRule(nil,
				[]v1net.NetworkPolicyPeer{
					peer(&metav1.LabelSelector{
						MatchLabels: map[string]string{"l1": "v1"},
					}, &metav1.LabelSelector{
						MatchLabels: map[string]string{"nl": "nv"},
					}),
				}),
			}, nil, allPolicyTypes),
			makeNp(apicapi.ApicSlice{rule_9_0}, nil, name),
			nil, "allow-all-select-pods-and-ns"},
		{netpol("testns", "np1", &metav1.LabelSelector{},
			[]v1net.NetworkPolicyIngressRule{
				ingressRule([]v1net.NetworkPolicyPort{
					port(nil, &port80),
				}, []v1net.NetworkPolicyPeer{
					peer(&metav1.LabelSelector{
						MatchLabels: map[string]string{"l1": "v1"},
					}, nil),
				}),
				ingressRule([]v1net.NetworkPolicyPort{
					port(nil, &port443),
				}, []v1net.NetworkPolicyPeer{
					peer(&metav1.LabelSelector{
						MatchLabels: map[string]string{"l1": "v2"},
					}, nil),
				}),
			}, nil, allPolicyTypes),
			makeNp(apicapi.ApicSlice{rule_8_0, rule_8_1}, nil, name),
			nil, "multiple-from"},
		{netpol("testns", "np1", &metav1.LabelSelector{MatchLabels: map[string]string{"l1": "v1"}},
			[]v1net.NetworkPolicyIngressRule{
				ingressRule([]v1net.NetworkPolicyPort{
					{
						Port: &intstr.IntOrString{Type: intstr.String, StrVal: "serve-80"},
					},
				}, []v1net.NetworkPolicyPeer{
					peer(&metav1.LabelSelector{
						MatchLabels: map[string]string{"l1": "v1"},
					}, nil),
				}),
				ingressRule([]v1net.NetworkPolicyPort{
					port(nil, &port443),
				}, []v1net.NetworkPolicyPeer{
					peer(&metav1.LabelSelector{
						MatchLabels: map[string]string{"l1": "v2"},
					}, nil),
				}),
			}, nil, allPolicyTypes),
			makeNp(apicapi.ApicSlice{rule_8_0, rule_8_1}, nil, name),
			nil, "multiple-from-name"},
		{netpol("testns", "np1", &metav1.LabelSelector{},
			nil, []v1net.NetworkPolicyEgressRule{
				egressRule(nil,
					[]v1net.NetworkPolicyPeer{
						peer(&metav1.LabelSelector{
							MatchLabels: map[string]string{"l1": "v1"},
						}, &metav1.LabelSelector{
							MatchLabels: map[string]string{"nl": "nv"},
						}),
					}),
			}, allPolicyTypes),
			makeNp(nil, apicapi.ApicSlice{rule_10_0}, name),
			nil, "egress-allow-all-select-pods-and-ns"},
		{netpol("testns", "np1", &metav1.LabelSelector{},
			nil, []v1net.NetworkPolicyEgressRule{
				egressRule([]v1net.NetworkPolicyPort{port(&tcp, &port80)},
					[]v1net.NetworkPolicyPeer{
						peer(&metav1.LabelSelector{
							MatchLabels: map[string]string{"l1": "v1"},
						}, nil),
					}),
			}, allPolicyTypes),
			makeNp(nil, apicapi.ApicSlice{rule_11_0}, name),
			nil, "egress-allow-http-select-pods"},
		{netpol("testns", "np1", &metav1.LabelSelector{},
			nil, []v1net.NetworkPolicyEgressRule{
				egressRule([]v1net.NetworkPolicyPort{port(&tcp, &port80)},
					[]v1net.NetworkPolicyPeer{
						peer(&metav1.LabelSelector{
							MatchLabels: map[string]string{"l1": "v1"},
						}, nil),
					}),
			}, allPolicyTypes),
			makeNp(nil, apicapi.ApicSlice{rule_11_0, rule_11_s}, name),
			&npTestAugment{
				[]*v1.Endpoints{
					makeEps("testns", "service1",
						[]v1.EndpointAddress{
							{
								IP: "1.1.1.1",
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "testns",
									Name:      "pod1",
								},
							},
						},
						[]v1.EndpointPort{
							endpointPort(v1.ProtocolTCP, 80, ""),
						}),
					makeEps("testns", "service2",
						[]v1.EndpointAddress{
							{
								IP: "2.2.2.2",
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "testns",
									Name:      "pod2",
								},
							},
						},
						[]v1.EndpointPort{
							endpointPort(v1.ProtocolTCP, 80, ""),
						}),
					makeEps("testns", "service3",
						[]v1.EndpointAddress{
							{
								IP: "1.1.1.1",
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "testns",
									Name:      "pod1",
								},
							},
							{
								IP: "2.2.2.2",
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "testns",
									Name:      "pod2",
								},
							},
						},
						[]v1.EndpointPort{
							endpointPort(v1.ProtocolTCP, 80, ""),
						}),
				},
				[]*v1.Service{
					npservice("testns", "service1", "9.0.0.42",
						[]v1.ServicePort{
							servicePort("", v1.ProtocolTCP, 8080, 80),
						}),
					npservice("testns", "service2", "9.0.0.99",
						[]v1.ServicePort{
							servicePort("", v1.ProtocolTCP, 8080, 80),
						}), // should not match (no matching IPs)
					npservice("testns", "service3", "9.0.0.98",
						[]v1.ServicePort{
							servicePort("", v1.ProtocolTCP, 8080, 80),
						}), // should not match (incomplete IPs)
				},
				[]*discovery.EndpointSlice{},
			}, "egress-allow-http-augment"},
		{netpol("testns", "np1", &metav1.LabelSelector{},
			nil, []v1net.NetworkPolicyEgressRule{
				egressRule([]v1net.NetworkPolicyPort{
					{Protocol: func() *v1.Protocol { a := v1.ProtocolTCP; return &a }(),
						Port: &intstr.IntOrString{Type: intstr.String, StrVal: "serve-80"},
					},
				},
					[]v1net.NetworkPolicyPeer{
						peer(&metav1.LabelSelector{
							MatchLabels: map[string]string{"l1": "v1"},
						}, nil),
					}),
			}, allPolicyTypes),
			makeNp(nil, apicapi.ApicSlice{rule_11_0, rule_11_s}, name),
			&npTestAugment{
				[]*v1.Endpoints{
					makeEps("testns", "service1",
						[]v1.EndpointAddress{
							{
								IP: "1.1.1.1",
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "testns",
									Name:      "pod1",
								},
							},
						},
						[]v1.EndpointPort{
							endpointPort(v1.ProtocolTCP, 80, ""),
						}),
					makeEps("testns", "service2",
						[]v1.EndpointAddress{
							{
								IP: "2.2.2.2",
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "testns",
									Name:      "pod2",
								},
							},
						},
						[]v1.EndpointPort{
							endpointPort(v1.ProtocolTCP, 80, ""),
						}),
				},
				[]*v1.Service{
					npservice("testns", "service1", "9.0.0.42",
						[]v1.ServicePort{
							servicePort("", v1.ProtocolTCP, 8080, 80),
						}),
					npservice("testns", "service2", "9.0.0.99",
						[]v1.ServicePort{
							servicePort("", v1.ProtocolTCP, 8080, 80),
						}), // should not match (no matching IPs)
				},
				[]*discovery.EndpointSlice{},
			}, "egress-allow-http-augment-namedport"},
		{netpol("testns", "np1", &metav1.LabelSelector{},
			nil, []v1net.NetworkPolicyEgressRule{
				egressRule([]v1net.NetworkPolicyPort{port(&tcp, &port80)},
					nil),
			}, allPolicyTypes),
			makeNp(nil, apicapi.ApicSlice{rule_14_0, rule_14_s}, name),
			&npTestAugment{
				[]*v1.Endpoints{
					makeEps("testns", "service1",
						[]v1.EndpointAddress{
							{
								IP: "1.1.1.1",
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "testns",
									Name:      "pod1",
								},
							},
						},
						[]v1.EndpointPort{
							endpointPort(v1.ProtocolTCP, 80, ""),
						}),
					makeEps("testns", "service2",
						[]v1.EndpointAddress{
							{
								IP: "2.2.2.2",
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "testns",
									Name:      "pod2",
								},
							},
						},
						[]v1.EndpointPort{
							endpointPort(v1.ProtocolTCP, 81, ""),
						}),
				},
				[]*v1.Service{
					npservice("testns", "service1", "9.0.0.42",
						[]v1.ServicePort{
							servicePort("", v1.ProtocolTCP, 8080, 80),
						}),
					npservice("testns", "service2", "9.0.0.99",
						[]v1.ServicePort{
							servicePort("", v1.ProtocolTCP, 8080, 81),
						}), // should not match (port wrong)
				},
				[]*discovery.EndpointSlice{},
			}, "egress-allow-http-all-augment"},
		{netpol("testns", "np1", &metav1.LabelSelector{},
			nil, []v1net.NetworkPolicyEgressRule{
				egressRule(nil,
					[]v1net.NetworkPolicyPeer{
						peerIpBlock(peer(nil, nil), "1.1.1.0/24", nil),
					}),
			}, allPolicyTypes),
			makeNp(nil,
				apicapi.ApicSlice{rule_12_0, rule_12_s_0, rule_12_s_1}, name),
			&npTestAugment{
				[]*v1.Endpoints{
					makeEps("testns", "service1",
						[]v1.EndpointAddress{
							{
								IP: "1.1.1.3",
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "ns1",
									Name:      "pod3",
								},
							},
							{
								IP: "1.1.1.4",
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "ns1",
									Name:      "pod4",
								},
							},
							{
								IP: "1.1.1.5",
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "ns2",
									Name:      "pod5",
								},
							},
						},
						[]v1.EndpointPort{
							endpointPort(v1.ProtocolTCP, 80, "http"),
							endpointPort(v1.ProtocolTCP, 443, "https"),
						}),
				},
				[]*v1.Service{
					npservice("testns", "service1", "9.0.0.44",
						[]v1.ServicePort{
							servicePort("http", v1.ProtocolTCP, 8080, 80),
							servicePort("https", v1.ProtocolTCP, 8443, 443),
						}),
				},
				[]*discovery.EndpointSlice{},
			}, "egress-allow-subnet-augment"},
		{netpol("testns", "np1", &metav1.LabelSelector{},
			nil, []v1net.NetworkPolicyEgressRule{
				egressRule(nil, nil),
			}, allPolicyTypes),
			makeNp(nil, apicapi.ApicSlice{rule_13_0}, name),
			&npTestAugment{
				[]*v1.Endpoints{
					makeEps("testns", "service1",
						[]v1.EndpointAddress{
							{
								IP: "1.1.1.1",
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "testns",
									Name:      "pod1",
								},
							},
						},
						[]v1.EndpointPort{
							endpointPort(v1.ProtocolTCP, 80, ""),
						}),
				},
				[]*v1.Service{
					npservice("testns", "service1", "9.0.0.42",
						[]v1.ServicePort{
							servicePort("", v1.ProtocolTCP, 8080, 80),
						}),
				},
				[]*discovery.EndpointSlice{},
			}, "egress-allow-all-augment"},
		{netpol("testns", "np1", &metav1.LabelSelector{},
			nil, []v1net.NetworkPolicyEgressRule{
				egressRule([]v1net.NetworkPolicyPort{rangedPort(&tcp, &port80, &eport90)},
					[]v1net.NetworkPolicyPeer{
						peer(&metav1.LabelSelector{
							MatchLabels: map[string]string{"l1": "v1"},
						}, nil),
					}),
			}, allPolicyTypes),
			makeNp(nil, apicapi.ApicSlice{rule_11_0_portrange, rule_11_s_portrange}, name),
			&npTestAugment{
				[]*v1.Endpoints{
					makeEps("testns", "service1",
						[]v1.EndpointAddress{
							{
								IP: "1.1.1.1",
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "testns",
									Name:      "pod1",
								},
							},
						},
						[]v1.EndpointPort{
							endpointPort(v1.ProtocolTCP, 80, ""),
						}),
					makeEps("testns", "service2",
						[]v1.EndpointAddress{
							{
								IP: "2.2.2.2",
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "testns",
									Name:      "pod2",
								},
							},
						},
						[]v1.EndpointPort{
							endpointPort(v1.ProtocolTCP, 80, ""),
						}),
				},
				[]*v1.Service{
					npservice("testns", "service1", "9.0.0.42",
						[]v1.ServicePort{
							servicePort("", v1.ProtocolTCP, 8080, 80),
						}),
					npservice("testns", "service2", "9.0.0.99",
						[]v1.ServicePort{
							servicePort("", v1.ProtocolTCP, 8080, 80),
						}), // should not match (no matching IPs)
				},
				[]*discovery.EndpointSlice{},
			}, "egress-allow-http-portrange-augment"},
	}
	initCont := func() *testAciController {
		cont := testController()
		cont.config.AciPolicyTenant = "test-tenant"
		cont.config.NodeServiceIpPool = []ipam.IpRange{
			{Start: net.ParseIP("10.1.1.2"), End: net.ParseIP("10.1.1.3")},
		}
		cont.config.PodIpPool = []ipam.IpRange{
			{Start: net.ParseIP("10.1.1.2"), End: net.ParseIP("10.1.255.254")},
		}
		cont.AciController.initIpam()

		cont.fakeNamespaceSource.Add(namespaceLabel("testns",
			map[string]string{"test": "testv"}))
		cont.fakeNamespaceSource.Add(namespaceLabel("ns1",
			map[string]string{"nl": "nv"}))
		cont.fakeNamespaceSource.Add(namespaceLabel("ns2",
			map[string]string{"nl": "nv"}))

		return cont
	}

	{
		cont := testController()
		cont.run()
		static := cont.staticNetPolObjs()
		apicapi.PrepareApicSlice(static, "kube", staticNetPolKey())
		assert.Equal(t, static,
			cont.apicConn.GetDesiredState(staticNetPolKey()), staticNetPolKey())
		cont.stop()
	}

	ips := []string{
		"1.1.1.1", "1.1.1.2", "1.1.1.3", "1.1.1.4", "1.1.1.5", "",
	}
	for ix := range npTests {
		cont := initCont()
		cont.log.Info("Starting podsfirst ", npTests[ix].desc)
		addPods(cont, true, ips, true)
		addServices(cont, npTests[ix].augment)
		cont.run()
		cont.fakeNetworkPolicySource.Add(npTests[ix].netPol)
		checkNp(t, &npTests[ix], "podsfirst", cont)

		cont.log.Info("Starting delete ", npTests[ix].desc)
		cont.fakeNetworkPolicySource.Delete(npTests[ix].netPol)
		checkDelete(t, npTests[0], cont)
		cont.stop()
	}
	for ix := range npTests {
		cont := initCont()
		cont.log.Info("Starting npfirst ", npTests[ix].desc)
		cont.fakeNetworkPolicySource.Add(npTests[ix].netPol)
		cont.run()
		addServices(cont, npTests[ix].augment)
		addPods(cont, false, ips, true)
		addPods(cont, true, ips, true)
		checkNp(t, &npTests[ix], "npfirst", cont)
		cont.stop()
	}
}

func TestNetworkPolicyWithLongName(t *testing.T) {
	longPolicyName := "this-is-a-very-long-policy-name-designed-to-exceed-the-aci-character-limit-for-testing"
	npKey := "testns/" + longPolicyName

	name := util.AciNameForKey("kube", "np", npKey)
	baseDn := makeNp(nil, nil, name).GetDn()

	np1SDnI := fmt.Sprintf("%s/subj-networkpolicy-ingress", baseDn)
	np1SDnE := fmt.Sprintf("%s/subj-networkpolicy-egress", baseDn)

	ruleName := util.AciNameForKey("0-ipv4", "", longPolicyName)
	rule_0_0 := apicapi.NewHostprotRule(np1SDnI, fmt.Sprintf("%s", ruleName))
	rule_0_0.SetAttr("direction", "ingress")
	rule_0_0.SetAttr("ethertype", "ipv4")

	rule_1_0 := apicapi.NewHostprotRule(np1SDnE, fmt.Sprintf("%s", ruleName))
	rule_1_0.SetAttr("direction", "egress")
	rule_1_0.SetAttr("ethertype", "ipv4")
	rule_1_0.AddChild(apicapi.NewHostprotRemoteIp(rule_1_0.GetDn(), "1.1.1.3"))
	rule_1_0.AddChild(apicapi.NewHostprotRemoteIp(rule_1_0.GetDn(), "1.1.1.5"))

	ruleName = util.AciNameForKey("0_0-ipv4", "", longPolicyName)
	rule_2_0 := apicapi.NewHostprotRule(np1SDnI, fmt.Sprintf("%s", ruleName))
	rule_2_0.SetAttr("direction", "ingress")
	rule_2_0.SetAttr("ethertype", "ipv4")
	rule_2_0.SetAttr("protocol", "tcp")
	rule_2_0.SetAttr("fromPort", "80")

	rule_3_0 := apicapi.NewHostprotRule(np1SDnE, fmt.Sprintf("%s", ruleName))
	rule_3_0.SetAttr("direction", "egress")
	rule_3_0.SetAttr("ethertype", "ipv4")
	rule_3_0.SetAttr("protocol", "tcp")
	rule_3_0.SetAttr("fromPort", "80")
	rule_3_0.AddChild(apicapi.NewHostprotRemoteIp(rule_3_0.GetDn(), "1.1.1.1"))

	var npTests = []npTest{
		{netpol("testns", longPolicyName, &metav1.LabelSelector{},
			[]v1net.NetworkPolicyIngressRule{ingressRule(nil, nil)},
			nil, allPolicyTypes),
			makeNp(apicapi.ApicSlice{rule_0_0}, nil, name),
			nil, "long-name-allow-all"},
		{netpol("testns", longPolicyName, &metav1.LabelSelector{},
			[]v1net.NetworkPolicyIngressRule{
				ingressRule([]v1net.NetworkPolicyPort{port(&tcp, &port80)},
					nil)}, nil, allPolicyTypes),
			makeNp(apicapi.ApicSlice{rule_2_0}, nil, name),
			nil, "allow-http"},
		{netpol("testns", longPolicyName, &metav1.LabelSelector{},
			nil, []v1net.NetworkPolicyEgressRule{
				egressRule(nil,
					[]v1net.NetworkPolicyPeer{
						peer(&metav1.LabelSelector{
							MatchLabels: map[string]string{"l1": "v1"},
						}, &metav1.LabelSelector{
							MatchLabels: map[string]string{"nl": "nv"},
						}),
					}),
			}, allPolicyTypes),
			makeNp(nil, apicapi.ApicSlice{rule_1_0}, name),
			nil, "egress-allow-all-select-pods-and-ns"},
		{netpol("testns", longPolicyName, &metav1.LabelSelector{},
			nil, []v1net.NetworkPolicyEgressRule{
				egressRule([]v1net.NetworkPolicyPort{port(&tcp, &port80)},
					[]v1net.NetworkPolicyPeer{
						peer(&metav1.LabelSelector{
							MatchLabels: map[string]string{"l1": "v1"},
						}, nil),
					}),
			}, allPolicyTypes),
			makeNp(nil, apicapi.ApicSlice{rule_3_0}, name),
			nil, "egress-allow-http-select-pods"},
	}

	initCont := func() *testAciController {
		cont := testController()
		cont.config.AciPolicyTenant = "test-tenant"
		cont.config.NodeServiceIpPool = []ipam.IpRange{
			{Start: net.ParseIP("10.1.1.2"), End: net.ParseIP("10.1.1.3")},
		}
		cont.config.PodIpPool = []ipam.IpRange{
			{Start: net.ParseIP("10.1.1.2"), End: net.ParseIP("10.1.255.254")},
		}
		cont.AciController.initIpam()

		cont.fakeNamespaceSource.Add(namespaceLabel("testns",
			map[string]string{"test": "testv"}))
		cont.fakeNamespaceSource.Add(namespaceLabel("ns1",
			map[string]string{"nl": "nv"}))
		cont.fakeNamespaceSource.Add(namespaceLabel("ns2",
			map[string]string{"nl": "nv"}))

		return cont
	}

	{
		cont := testController()
		cont.run()
		static := cont.staticNetPolObjs()
		apicapi.PrepareApicSlice(static, "kube", staticNetPolKey())
		assert.Equal(t, static,
			cont.apicConn.GetDesiredState(staticNetPolKey()), staticNetPolKey())
		cont.stop()
	}

	ips := []string{
		"1.1.1.1", "1.1.1.2", "1.1.1.3", "1.1.1.4", "1.1.1.5", "",
	}
	for ix := range npTests {
		cont := initCont()
		cont.log.Info("Starting podsfirst ", npTests[ix].desc)
		addPods(cont, true, ips, true)
		addServices(cont, npTests[ix].augment)
		cont.run()
		cont.fakeNetworkPolicySource.Add(npTests[ix].netPol)
		checkNp(t, &npTests[ix], "podsfirst", cont)

		cont.log.Info("Starting delete ", npTests[ix].desc)
		cont.fakeNetworkPolicySource.Delete(npTests[ix].netPol)
		checkDelete(t, npTests[0], cont)
		cont.stop()
	}
	for ix := range npTests {
		cont := initCont()
		cont.log.Info("Starting npfirst ", npTests[ix].desc)
		cont.fakeNetworkPolicySource.Add(npTests[ix].netPol)
		cont.run()
		addServices(cont, npTests[ix].augment)
		addPods(cont, false, ips, true)
		addPods(cont, true, ips, true)
		checkNp(t, &npTests[ix], "npfirst", cont)
		cont.stop()
	}
}

func TestNetworkPolicyHppOptimize(t *testing.T) {
	rule_0 := map[string]string{"direction": "ingress", "ethertype": "ipv4"}
	rule_1 := map[string]string{"direction": "ingress", "ethertype": "ipv4",
		"protocol": "tcp", "fromPort": "80"}
	rule_2 := map[string]string{"direction": "ingress", "ethertype": "ipv4",
		"protocol": "udp", "fromPort": "80"}
	rule_3 := map[string]string{"direction": "ingress", "ethertype": "ipv4",
		"protocol": "tcp", "fromPort": "443"}
	rule_4 := map[string]string{"direction": "ingress", "ethertype": "ipv4",
		"protocol": "sctp", "fromPort": "80"}

	rule_5 := map[string]string{"direction": "egress", "ethertype": "ipv4"}
	rule_6 := map[string]string{"direction": "egress", "ethertype": "ipv4",
		"protocol": "tcp", "fromPort": "80"}
	rule_7 := map[string]string{"direction": "egress", "ethertype": "ipv4",
		"protocol": "tcp", "fromPort": "8080"}
	rule_8 := map[string]string{"direction": "egress", "ethertype": "ipv4",
		"protocol": "tcp", "fromPort": "8443"}
	rule_9 := map[string]string{"direction": "egress", "ethertype": "ipv4",
		"protocol": "tcp", "fromPort": "80", "toPort": "90"}

	//allow-all
	test0_np := netpol("testns", "np1", &metav1.LabelSelector{},
		[]v1net.NetworkPolicyIngressRule{ingressRule(nil, nil)},
		nil, allPolicyTypes)
	hash, _ := util.CreateHashFromNetPol(test0_np)
	test0_np_name := "kube_np_" + hash
	test0_rule := createRule(test0_np_name, true, rule_0, "0-ipv4__np1")

	//allow-http
	test1_np := netpol("testns", "np1", &metav1.LabelSelector{},
		[]v1net.NetworkPolicyIngressRule{
			ingressRule([]v1net.NetworkPolicyPort{port(&tcp, &port80)},
				nil)}, nil, allPolicyTypes)
	hash, _ = util.CreateHashFromNetPol(test1_np)
	test1_np_name := "kube_np_" + hash
	test1_rule := createRule(test1_np_name, true, rule_1, "0_0-ipv4__np1")

	//allow-http-from
	test2_np := netpol("testns", "np1", &metav1.LabelSelector{},
		[]v1net.NetworkPolicyIngressRule{
			ingressRule([]v1net.NetworkPolicyPort{port(&tcp, &port80)},
				[]v1net.NetworkPolicyPeer{
					peerIpBlock(peer(nil, nil),
						"8.8.8.8/24", []string{"8.8.8.9/31"}),
				},
			)}, nil, allPolicyTypes)
	hash, _ = util.CreateHashFromNetPol(test2_np)
	test2_np_name := "kube_np_" + hash
	test2_rule := createRule(test2_np_name, true, rule_1, "0_0-ipv4__np1")
	test2_rule.AddChild(
		apicapi.NewHostprotRemoteIp(test2_rule.GetDn(), "8.8.8.0/29"))
	test2_rule.AddChild(
		apicapi.NewHostprotRemoteIp(test2_rule.GetDn(), "8.8.8.10/31"))
	test2_rule.AddChild(
		apicapi.NewHostprotRemoteIp(test2_rule.GetDn(), "8.8.8.12/30"))
	test2_rule.AddChild(
		apicapi.NewHostprotRemoteIp(test2_rule.GetDn(), "8.8.8.128/25"))
	test2_rule.AddChild(
		apicapi.NewHostprotRemoteIp(test2_rule.GetDn(), "8.8.8.16/28"))
	test2_rule.AddChild(
		apicapi.NewHostprotRemoteIp(test2_rule.GetDn(), "8.8.8.32/27"))
	test2_rule.AddChild(
		apicapi.NewHostprotRemoteIp(test2_rule.GetDn(), "8.8.8.64/26"))

	//allow-http-defproto
	test3_np := netpol("testns", "np1", &metav1.LabelSelector{},
		[]v1net.NetworkPolicyIngressRule{
			ingressRule([]v1net.NetworkPolicyPort{
				port(nil, &port80)}, nil)}, nil, allPolicyTypes)
	hash, _ = util.CreateHashFromNetPol(test3_np)
	test3_np_name := "kube_np_" + hash
	test3_rule := createRule(test3_np_name, true, rule_1, "0_0-ipv4__np1")

	//allow-80-udp
	test4_np := netpol("testns", "np1", &metav1.LabelSelector{},
		[]v1net.NetworkPolicyIngressRule{
			ingressRule([]v1net.NetworkPolicyPort{
				port(&udp, &port80)}, nil)}, nil, allPolicyTypes)
	hash, _ = util.CreateHashFromNetPol(test4_np)
	test4_np_name := "kube_np_" + hash
	test4_rule := createRule(test4_np_name, true, rule_2, "0_0-ipv4__np1")

	//allow-80-sctp
	test5_np := netpol("testns", "np1", &metav1.LabelSelector{},
		[]v1net.NetworkPolicyIngressRule{
			ingressRule([]v1net.NetworkPolicyPort{
				port(&sctp, &port80)}, nil)}, nil, allPolicyTypes)
	hash, _ = util.CreateHashFromNetPol(test5_np)
	test5_np_name := "kube_np_" + hash
	test5_rule := createRule(test5_np_name, true, rule_4, "0_0-ipv4__np1")

	//allow-http-https
	test6_np := netpol("testns", "np1", &metav1.LabelSelector{},
		[]v1net.NetworkPolicyIngressRule{
			ingressRule([]v1net.NetworkPolicyPort{
				port(nil, &port80), port(nil, &port443),
			}, nil)}, nil, allPolicyTypes)
	hash, _ = util.CreateHashFromNetPol(test6_np)
	test6_np_name := "kube_np_" + hash
	test6_rule1 := createRule(test6_np_name, true, rule_1, "0_0-ipv4__np1")
	test6_rule2 := createRule(test6_np_name, true, rule_3, "0_1-ipv4__np1")

	//allow-all-from-ns
	test7_np := netpol("testns", "np1", &metav1.LabelSelector{},
		[]v1net.NetworkPolicyIngressRule{ingressRule(nil,
			[]v1net.NetworkPolicyPeer{peer(nil,
				&metav1.LabelSelector{
					MatchLabels: map[string]string{"test": "testv"},
				}),
			}),
		}, nil, allPolicyTypes)
	hash, _ = util.CreateHashFromNetPol(test7_np)
	test7_np_name := "kube_np_" + hash
	test7_rule := createRule(test7_np_name, true, rule_0, "0-ipv4__np1")
	test7_rule.AddChild(apicapi.NewHostprotRemoteIp(test7_rule.GetDn(), "1.1.1.1"))
	test7_rule.AddChild(apicapi.NewHostprotRemoteIp(test7_rule.GetDn(), "1.1.1.2"))

	//allow-all-from-ns-no-match
	test8_np := netpol("testns", "np1", &metav1.LabelSelector{},
		[]v1net.NetworkPolicyIngressRule{ingressRule(nil,
			[]v1net.NetworkPolicyPeer{peer(nil,
				&metav1.LabelSelector{
					MatchLabels: map[string]string{"test": "notathing"},
				}),
			}),
		}, nil, allPolicyTypes)
	hash, _ = util.CreateHashFromNetPol(test8_np)
	test8_np_name := "kube_np_" + hash

	//allow-all-from-multiple-ns
	test9_np := netpol("testns", "np1", &metav1.LabelSelector{},
		[]v1net.NetworkPolicyIngressRule{ingressRule(nil,
			[]v1net.NetworkPolicyPeer{peer(nil,
				&metav1.LabelSelector{
					MatchLabels: map[string]string{"nl": "nv"},
				}),
			}),
		}, nil, allPolicyTypes)
	hash, _ = util.CreateHashFromNetPol(test9_np)
	test9_np_name := "kube_np_" + hash
	test9_rule := createRule(test9_np_name, true, rule_0, "0-ipv4__np1")
	test9_rule.AddChild(apicapi.NewHostprotRemoteIp(test9_rule.GetDn(), "1.1.1.3"))
	test9_rule.AddChild(apicapi.NewHostprotRemoteIp(test9_rule.GetDn(), "1.1.1.4"))
	test9_rule.AddChild(apicapi.NewHostprotRemoteIp(test9_rule.GetDn(), "1.1.1.5"))

	//allow-all-select-pods
	test10_np := netpol("testns", "np1", &metav1.LabelSelector{},
		[]v1net.NetworkPolicyIngressRule{ingressRule(nil,
			[]v1net.NetworkPolicyPeer{
				peer(&metav1.LabelSelector{
					MatchLabels: map[string]string{"l1": "v1"},
				}, nil),
			}),
		}, nil, allPolicyTypes)
	hash, _ = util.CreateHashFromNetPol(test10_np)
	test10_np_name := "kube_np_" + hash
	test10_rule := createRule(test10_np_name, true, rule_0, "0-ipv4__np1")
	test10_rule.AddChild(apicapi.NewHostprotRemoteIp(test10_rule.GetDn(), "1.1.1.1"))

	//allow-all-select-pods-and-ns
	test11_np := netpol("testns", "np1", &metav1.LabelSelector{},
		[]v1net.NetworkPolicyIngressRule{ingressRule(nil,
			[]v1net.NetworkPolicyPeer{
				peer(&metav1.LabelSelector{
					MatchLabels: map[string]string{"l1": "v1"},
				}, &metav1.LabelSelector{
					MatchLabels: map[string]string{"nl": "nv"},
				}),
			}),
		}, nil, allPolicyTypes)
	hash, _ = util.CreateHashFromNetPol(test11_np)
	test11_np_name := "kube_np_" + hash
	test11_rule := createRule(test11_np_name, true, rule_0, "0-ipv4__np1")
	test11_rule.AddChild(apicapi.NewHostprotRemoteIp(test11_rule.GetDn(), "1.1.1.3"))
	test11_rule.AddChild(apicapi.NewHostprotRemoteIp(test11_rule.GetDn(), "1.1.1.5"))

	//multiple-from
	test12_np := netpol("testns", "np1", &metav1.LabelSelector{},
		[]v1net.NetworkPolicyIngressRule{
			ingressRule([]v1net.NetworkPolicyPort{
				port(nil, &port80),
			}, []v1net.NetworkPolicyPeer{
				peer(&metav1.LabelSelector{
					MatchLabels: map[string]string{"l1": "v1"},
				}, nil),
			}),
			ingressRule([]v1net.NetworkPolicyPort{
				port(nil, &port443),
			}, []v1net.NetworkPolicyPeer{
				peer(&metav1.LabelSelector{
					MatchLabels: map[string]string{"l1": "v2"},
				}, nil),
			}),
		}, nil, allPolicyTypes)
	hash, _ = util.CreateHashFromNetPol(test12_np)
	test12_np_name := "kube_np_" + hash
	test12_rule1 := createRule(test12_np_name, true, rule_1, "0_0-ipv4__np1")
	test12_rule1.AddChild(apicapi.NewHostprotRemoteIp(test12_rule1.GetDn(), "1.1.1.1"))
	test12_rule2 := createRule(test12_np_name, true, rule_3, "1_0-ipv4__np1")
	test12_rule2.AddChild(apicapi.NewHostprotRemoteIp(test12_rule2.GetDn(), "1.1.1.2"))

	//multiple-from-name
	test13_np := netpol("testns", "np1", &metav1.LabelSelector{MatchLabels: map[string]string{"l1": "v1"}},
		[]v1net.NetworkPolicyIngressRule{
			ingressRule([]v1net.NetworkPolicyPort{
				{
					Port: &intstr.IntOrString{Type: intstr.String, StrVal: "serve-80"},
				},
			}, []v1net.NetworkPolicyPeer{
				peer(&metav1.LabelSelector{
					MatchLabels: map[string]string{"l1": "v1"},
				}, nil),
			}),
			ingressRule([]v1net.NetworkPolicyPort{
				port(nil, &port443),
			}, []v1net.NetworkPolicyPeer{
				peer(&metav1.LabelSelector{
					MatchLabels: map[string]string{"l1": "v2"},
				}, nil),
			}),
		}, nil, allPolicyTypes)
	hash, _ = util.CreateHashFromNetPol(test13_np)
	test13_np_name := "kube_np_" + hash
	test13_rule1 := createRule(test13_np_name, true, rule_1, "0_0-ipv4__np1")
	test13_rule1.AddChild(apicapi.NewHostprotRemoteIp(test13_rule1.GetDn(), "1.1.1.1"))
	test13_rule2 := createRule(test13_np_name, true, rule_3, "1_0-ipv4__np1")
	test13_rule2.AddChild(apicapi.NewHostprotRemoteIp(test13_rule2.GetDn(), "1.1.1.2"))

	//egress-allow-all-select-pods-and-ns
	test14_np := netpol("testns", "np1", &metav1.LabelSelector{},
		nil, []v1net.NetworkPolicyEgressRule{
			egressRule(nil,
				[]v1net.NetworkPolicyPeer{
					peer(&metav1.LabelSelector{
						MatchLabels: map[string]string{"l1": "v1"},
					}, &metav1.LabelSelector{
						MatchLabels: map[string]string{"nl": "nv"},
					}),
				}),
		}, allPolicyTypes)
	hash, _ = util.CreateHashFromNetPol(test14_np)
	test14_np_name := "kube_np_" + hash
	test14_rule := createRule(test14_np_name, false, rule_5, "0-ipv4__np1")
	test14_rule.AddChild(apicapi.NewHostprotRemoteIp(test14_rule.GetDn(), "1.1.1.3"))
	test14_rule.AddChild(apicapi.NewHostprotRemoteIp(test14_rule.GetDn(), "1.1.1.5"))

	//egress-allow-http-select-pods
	test15_np := netpol("testns", "np1", &metav1.LabelSelector{},
		nil, []v1net.NetworkPolicyEgressRule{
			egressRule([]v1net.NetworkPolicyPort{port(&tcp, &port80)},
				[]v1net.NetworkPolicyPeer{
					peer(&metav1.LabelSelector{
						MatchLabels: map[string]string{"l1": "v1"},
					}, nil),
				}),
		}, allPolicyTypes)
	hash, _ = util.CreateHashFromNetPol(test15_np)
	test15_np_name := "kube_np_" + hash
	test15_rule := createRule(test15_np_name, false, rule_6, "0_0-ipv4__np1")
	test15_rule.AddChild(apicapi.NewHostprotRemoteIp(test15_rule.GetDn(), "1.1.1.1"))

	//egress-allow-http-augment
	test16_np := netpol("testns", "np1", &metav1.LabelSelector{},
		nil, []v1net.NetworkPolicyEgressRule{
			egressRule([]v1net.NetworkPolicyPort{port(&tcp, &port80)},
				[]v1net.NetworkPolicyPeer{
					peer(&metav1.LabelSelector{
						MatchLabels: map[string]string{"l1": "v1"},
					}, nil),
				}),
		}, allPolicyTypes)
	hash, _ = util.CreateHashFromNetPol(test16_np)
	test16_np_name := "kube_np_" + hash
	test16_rule1 := createRule(test16_np_name, false, rule_6, "0_0-ipv4__np1")
	test16_rule1.AddChild(apicapi.NewHostprotRemoteIp(test16_rule1.GetDn(), "1.1.1.1"))
	test16_rule2 := createRule(test16_np_name, false, rule_7, "service_tcp_8080-ipv4")
	test16_rule2.AddChild(apicapi.NewHostprotRemoteIp(test16_rule2.GetDn(), "9.0.0.42"))

	//egress-allow-http-augment-namedport
	test17_np := netpol("testns", "np1", &metav1.LabelSelector{},
		nil, []v1net.NetworkPolicyEgressRule{
			egressRule([]v1net.NetworkPolicyPort{
				{Protocol: func() *v1.Protocol { a := v1.ProtocolTCP; return &a }(),
					Port: &intstr.IntOrString{Type: intstr.String, StrVal: "serve-80"},
				},
			},
				[]v1net.NetworkPolicyPeer{
					peer(&metav1.LabelSelector{
						MatchLabels: map[string]string{"l1": "v1"},
					}, nil),
				}),
		}, allPolicyTypes)
	hash, _ = util.CreateHashFromNetPol(test17_np)
	test17_np_name := "kube_np_" + hash
	test17_rule1 := createRule(test17_np_name, false, rule_6, "0_0-ipv4__np1")
	test17_rule1.AddChild(apicapi.NewHostprotRemoteIp(test17_rule1.GetDn(), "1.1.1.1"))
	test17_rule2 := createRule(test17_np_name, false, rule_7, "service_tcp_8080-ipv4")
	test17_rule2.AddChild(apicapi.NewHostprotRemoteIp(test17_rule2.GetDn(), "9.0.0.42"))

	//egress-allow-http-all-augment
	test18_np := netpol("testns", "np1", &metav1.LabelSelector{},
		nil, []v1net.NetworkPolicyEgressRule{
			egressRule([]v1net.NetworkPolicyPort{port(&tcp, &port80)},
				nil),
		}, allPolicyTypes)
	hash, _ = util.CreateHashFromNetPol(test18_np)
	test18_np_name := "kube_np_" + hash
	test18_rule1 := createRule(test18_np_name, false, rule_6, "0_0-ipv4__np1")
	test18_rule2 := createRule(test18_np_name, false, rule_7, "service_tcp_8080-ipv4")
	test18_rule2.AddChild(apicapi.NewHostprotRemoteIp(test18_rule2.GetDn(), "9.0.0.42"))

	//egress-allow-subnet-augment
	test19_np := netpol("testns", "np1", &metav1.LabelSelector{},
		nil, []v1net.NetworkPolicyEgressRule{
			egressRule(nil,
				[]v1net.NetworkPolicyPeer{
					peerIpBlock(peer(nil, nil), "1.1.1.0/24", nil),
				}),
		}, allPolicyTypes)
	hash, _ = util.CreateHashFromNetPol(test19_np)
	test19_np_name := "kube_np_" + hash
	test19_rule1 := createRule(test19_np_name, false, rule_5, "0-ipv4__np1")
	test19_rule1.AddChild(apicapi.NewHostprotRemoteIp(test19_rule1.GetDn(), "1.1.1.0/24"))
	test19_rule2 := createRule(test19_np_name, false, rule_7, "service_tcp_8080-ipv4")
	test19_rule2.AddChild(apicapi.NewHostprotRemoteIp(test19_rule2.GetDn(), "9.0.0.44"))
	test19_rule3 := createRule(test19_np_name, false, rule_8, "service_tcp_8443-ipv4")
	test19_rule3.AddChild(apicapi.NewHostprotRemoteIp(test19_rule3.GetDn(), "9.0.0.44"))

	//egress-allow-all-augment
	test20_np := netpol("testns", "np1", &metav1.LabelSelector{},
		nil, []v1net.NetworkPolicyEgressRule{
			egressRule(nil, nil),
		}, allPolicyTypes)
	hash, _ = util.CreateHashFromNetPol(test20_np)
	test20_np_name := "kube_np_" + hash
	test20_rule := createRule(test20_np_name, false, rule_5, "0-ipv4__np1")

	//egress-allow-http-portrange
	test21_np := netpol("testns", "np1", &metav1.LabelSelector{},
		nil, []v1net.NetworkPolicyEgressRule{
			egressRule([]v1net.NetworkPolicyPort{rangedPort(&tcp, &port80, &eport90)},
				[]v1net.NetworkPolicyPeer{
					peer(&metav1.LabelSelector{
						MatchLabels: map[string]string{"l1": "v1"},
					}, nil),
				}),
		}, allPolicyTypes)
	hash, _ = util.CreateHashFromNetPol(test21_np)
	test21_np_name := "kube_np_" + hash
	test21_rule := createRule(test21_np_name, false, rule_9, "0_0-ipv4__np1")
	test21_rule.AddChild(apicapi.NewHostprotRemoteIp(test21_rule.GetDn(), "1.1.1.1"))

	//egress-allow-http-portrange-augment
	test22_np := netpol("testns", "np1", &metav1.LabelSelector{},
		nil, []v1net.NetworkPolicyEgressRule{
			egressRule([]v1net.NetworkPolicyPort{rangedPort(&tcp, &port80, &eport90)},
				[]v1net.NetworkPolicyPeer{
					peer(&metav1.LabelSelector{
						MatchLabels: map[string]string{"l1": "v1"},
					}, nil),
				}),
		}, allPolicyTypes)
	hash, _ = util.CreateHashFromNetPol(test22_np)
	test22_np_name := "kube_np_" + hash
	test22_rule1 := createRule(test22_np_name, false, rule_9, "0_0-ipv4__np1")
	test22_rule1.AddChild(apicapi.NewHostprotRemoteIp(test22_rule1.GetDn(), "1.1.1.1"))
	test22_rule2 := createRule(test22_np_name, false, rule_7, "service_tcp_8080-ipv4")
	test22_rule2.AddChild(apicapi.NewHostprotRemoteIp(test22_rule2.GetDn(), "9.0.0.42"))

	var npTests = []npTest{
		{test0_np,
			makeNp(apicapi.ApicSlice{test0_rule}, nil, test0_np_name),
			nil, "allow-all"},
		{test1_np,
			makeNp(apicapi.ApicSlice{test1_rule}, nil, test1_np_name),
			nil, "allow-http"},
		{test2_np,
			makeNp(apicapi.ApicSlice{test2_rule}, nil, test2_np_name),
			nil, "allow-http-from"},
		{test3_np,
			makeNp(apicapi.ApicSlice{test3_rule}, nil, test3_np_name),
			nil, "allow-http-defproto"},
		{test4_np,
			makeNp(apicapi.ApicSlice{test4_rule}, nil, test4_np_name),
			nil, "allow-80-udp"},
		{test5_np,
			makeNp(apicapi.ApicSlice{test5_rule}, nil, test5_np_name),
			nil, "allow-80-sctp"},
		{test6_np,
			makeNp(apicapi.ApicSlice{test6_rule1, test6_rule2}, nil, test6_np_name),
			nil, "allow-http-https"},
		{test7_np,
			makeNp(apicapi.ApicSlice{test7_rule}, nil, test7_np_name),
			nil, "allow-all-from-ns"},
		{test8_np,
			makeNp(nil, nil, test8_np_name),
			nil, "allow-all-from-ns-no-match"},
		{test9_np,
			makeNp(apicapi.ApicSlice{test9_rule}, nil, test9_np_name),
			nil, "allow-all-from-multiple-ns"},
		{test10_np,
			makeNp(apicapi.ApicSlice{test10_rule}, nil, test10_np_name),
			nil, "allow-all-select-pods"},
		{test11_np,
			makeNp(apicapi.ApicSlice{test11_rule}, nil, test11_np_name),
			nil, "allow-all-select-pods-and-ns"},
		{test12_np,
			makeNp(apicapi.ApicSlice{test12_rule1, test12_rule2}, nil, test12_np_name),
			nil, "multiple-from"},
		{test13_np,
			makeNp(apicapi.ApicSlice{test13_rule1, test13_rule2}, nil, test13_np_name),
			nil, "multiple-from-name"},
		{test14_np,
			makeNp(nil, apicapi.ApicSlice{test14_rule}, test14_np_name),
			nil, "egress-allow-all-select-pods-and-ns"},
		{test15_np,
			makeNp(nil, apicapi.ApicSlice{test15_rule}, test15_np_name),
			nil, "egress-allow-http-select-pods"},
		{test16_np,
			makeNp(nil, apicapi.ApicSlice{test16_rule1, test16_rule2}, test16_np_name),
			&npTestAugment{
				[]*v1.Endpoints{
					makeEps("testns", "service1",
						[]v1.EndpointAddress{
							{
								IP: "1.1.1.1",
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "testns",
									Name:      "pod1",
								},
							},
						},
						[]v1.EndpointPort{
							endpointPort(v1.ProtocolTCP, 80, ""),
						}),
					makeEps("testns", "service2",
						[]v1.EndpointAddress{
							{
								IP: "2.2.2.2",
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "testns",
									Name:      "pod2",
								},
							},
						},
						[]v1.EndpointPort{
							endpointPort(v1.ProtocolTCP, 80, ""),
						}),
					makeEps("testns", "service3",
						[]v1.EndpointAddress{
							{
								IP: "1.1.1.1",
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "testns",
									Name:      "pod1",
								},
							},
							{
								IP: "2.2.2.2",
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "testns",
									Name:      "pod2",
								},
							},
						},
						[]v1.EndpointPort{
							endpointPort(v1.ProtocolTCP, 80, ""),
						}),
				},
				[]*v1.Service{
					npservice("testns", "service1", "9.0.0.42",
						[]v1.ServicePort{
							servicePort("", v1.ProtocolTCP, 8080, 80),
						}),
					npservice("testns", "service2", "9.0.0.99",
						[]v1.ServicePort{
							servicePort("", v1.ProtocolTCP, 8080, 80),
						}), // should not match (no matching IPs)
					npservice("testns", "service3", "9.0.0.98",
						[]v1.ServicePort{
							servicePort("", v1.ProtocolTCP, 8080, 80),
						}), // should not match (incomplete IPs)
				},
				[]*discovery.EndpointSlice{},
			}, "egress-allow-http-augment"},
		{test17_np,
			makeNp(nil, apicapi.ApicSlice{test17_rule1, test17_rule2}, test17_np_name),
			&npTestAugment{
				[]*v1.Endpoints{
					makeEps("testns", "service1",
						[]v1.EndpointAddress{
							{
								IP: "1.1.1.1",
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "testns",
									Name:      "pod1",
								},
							},
						},
						[]v1.EndpointPort{
							endpointPort(v1.ProtocolTCP, 80, ""),
						}),
					makeEps("testns", "service2",
						[]v1.EndpointAddress{
							{
								IP: "2.2.2.2",
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "testns",
									Name:      "pod2",
								},
							},
						},
						[]v1.EndpointPort{
							endpointPort(v1.ProtocolTCP, 80, ""),
						}),
				},
				[]*v1.Service{
					npservice("testns", "service1", "9.0.0.42",
						[]v1.ServicePort{
							servicePort("", v1.ProtocolTCP, 8080, 80),
						}),
					npservice("testns", "service2", "9.0.0.99",
						[]v1.ServicePort{
							servicePort("", v1.ProtocolTCP, 8080, 80),
						}), // should not match (no matching IPs)
				},
				[]*discovery.EndpointSlice{},
			}, "egress-allow-http-augment-namedport"},
		{test18_np,
			makeNp(nil, apicapi.ApicSlice{test18_rule1, test18_rule2}, test18_np_name),
			&npTestAugment{
				[]*v1.Endpoints{
					makeEps("testns", "service1",
						[]v1.EndpointAddress{
							{
								IP: "1.1.1.1",
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "testns",
									Name:      "pod1",
								},
							},
						},
						[]v1.EndpointPort{
							endpointPort(v1.ProtocolTCP, 80, ""),
						}),
					makeEps("testns", "service2",
						[]v1.EndpointAddress{
							{
								IP: "2.2.2.2",
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "testns",
									Name:      "pod2",
								},
							},
						},
						[]v1.EndpointPort{
							endpointPort(v1.ProtocolTCP, 81, ""),
						}),
				},
				[]*v1.Service{
					npservice("testns", "service1", "9.0.0.42",
						[]v1.ServicePort{
							servicePort("", v1.ProtocolTCP, 8080, 80),
						}),
					npservice("testns", "service2", "9.0.0.99",
						[]v1.ServicePort{
							servicePort("", v1.ProtocolTCP, 8080, 81),
						}), // should not match (port wrong)
				},
				[]*discovery.EndpointSlice{},
			}, "egress-allow-http-all-augment"},
		{test19_np,
			makeNp(nil,
				apicapi.ApicSlice{test19_rule1, test19_rule2, test19_rule3}, test19_np_name),
			&npTestAugment{
				[]*v1.Endpoints{
					makeEps("testns", "service1",
						[]v1.EndpointAddress{
							{
								IP: "1.1.1.3",
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "ns1",
									Name:      "pod3",
								},
							},
							{
								IP: "1.1.1.4",
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "ns1",
									Name:      "pod4",
								},
							},
							{
								IP: "1.1.1.5",
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "ns2",
									Name:      "pod5",
								},
							},
						},
						[]v1.EndpointPort{
							endpointPort(v1.ProtocolTCP, 80, "http"),
							endpointPort(v1.ProtocolTCP, 443, "https"),
						}),
				},
				[]*v1.Service{
					npservice("testns", "service1", "9.0.0.44",
						[]v1.ServicePort{
							servicePort("http", v1.ProtocolTCP, 8080, 80),
							servicePort("https", v1.ProtocolTCP, 8443, 443),
						}),
				},
				[]*discovery.EndpointSlice{},
			}, "egress-allow-subnet-augment"},
		{test20_np,
			makeNp(nil, apicapi.ApicSlice{test20_rule}, test20_np_name),
			&npTestAugment{
				[]*v1.Endpoints{
					makeEps("testns", "service1",
						[]v1.EndpointAddress{
							{
								IP: "1.1.1.1",
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "testns",
									Name:      "pod1",
								},
							},
						},
						[]v1.EndpointPort{
							endpointPort(v1.ProtocolTCP, 80, ""),
						}),
				},
				[]*v1.Service{
					npservice("testns", "service1", "9.0.0.42",
						[]v1.ServicePort{
							servicePort("", v1.ProtocolTCP, 8080, 80),
						}),
				},
				[]*discovery.EndpointSlice{},
			}, "egress-allow-all-augment"},
		{test21_np,
			makeNp(nil, apicapi.ApicSlice{test21_rule}, test21_np_name),
			nil, "egress-allow-http-portrange"},
		{test22_np,
			makeNp(nil, apicapi.ApicSlice{test22_rule1, test22_rule2}, test22_np_name),
			&npTestAugment{
				[]*v1.Endpoints{
					makeEps("testns", "service1",
						[]v1.EndpointAddress{
							{
								IP: "1.1.1.1",
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "testns",
									Name:      "pod1",
								},
							},
						},
						[]v1.EndpointPort{
							endpointPort(v1.ProtocolTCP, 80, ""),
						}),
					makeEps("testns", "service2",
						[]v1.EndpointAddress{
							{
								IP: "2.2.2.2",
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "testns",
									Name:      "pod2",
								},
							},
						},
						[]v1.EndpointPort{
							endpointPort(v1.ProtocolTCP, 80, ""),
						}),
				},
				[]*v1.Service{
					npservice("testns", "service1", "9.0.0.42",
						[]v1.ServicePort{
							servicePort("", v1.ProtocolTCP, 8080, 80),
						}),
					npservice("testns", "service2", "9.0.0.99",
						[]v1.ServicePort{
							servicePort("", v1.ProtocolTCP, 8080, 80),
						}), // should not match (no matching IPs)
				},
				[]*discovery.EndpointSlice{},
			}, "egress-allow-http-portrange-augment"},
	}
	initCont := func() *testAciController {
		cont := testController()
		cont.config.HppOptimization = true
		cont.config.AciPolicyTenant = "test-tenant"
		cont.config.NodeServiceIpPool = []ipam.IpRange{
			{Start: net.ParseIP("10.1.1.2"), End: net.ParseIP("10.1.1.3")},
		}
		cont.config.PodIpPool = []ipam.IpRange{
			{Start: net.ParseIP("10.1.1.2"), End: net.ParseIP("10.1.255.254")},
		}
		cont.AciController.initIpam()

		cont.fakeNamespaceSource.Add(namespaceLabel("testns",
			map[string]string{"test": "testv"}))
		cont.fakeNamespaceSource.Add(namespaceLabel("ns1",
			map[string]string{"nl": "nv"}))
		cont.fakeNamespaceSource.Add(namespaceLabel("ns2",
			map[string]string{"nl": "nv"}))

		return cont
	}

	{
		cont := testController()
		cont.run()
		cont.config.HppOptimization = true
		static := cont.staticNetPolObjs()
		apicapi.PrepareApicSlice(static, "kube", staticNetPolKey())
		assert.Equal(t, static,
			cont.apicConn.GetDesiredState(staticNetPolKey()), staticNetPolKey())
		cont.stop()
	}

	ips := []string{
		"1.1.1.1", "1.1.1.2", "1.1.1.3", "1.1.1.4", "1.1.1.5", "",
	}
	for ix := range npTests {
		cont := initCont()
		cont.log.Info("Starting podsfirst ", npTests[ix].desc)
		addPods(cont, true, ips, true)
		addServices(cont, npTests[ix].augment)
		cont.run()
		cont.fakeNetworkPolicySource.Add(npTests[ix].netPol)
		checkNp(t, &npTests[ix], "podsfirst", cont)

		cont.log.Info("Starting delete ", npTests[ix].desc)
		cont.fakeNetworkPolicySource.Delete(npTests[ix].netPol)
		checkDelete(t, npTests[0], cont)
		cont.stop()
	}
	for ix := range npTests {
		cont := initCont()
		cont.log.Info("Starting npfirst ", npTests[ix].desc)
		cont.fakeNetworkPolicySource.Add(npTests[ix].netPol)
		cont.run()
		addServices(cont, npTests[ix].augment)
		addPods(cont, false, ips, true)
		addPods(cont, true, ips, true)
		checkNp(t, &npTests[ix], "npfirst", cont)
		cont.stop()
	}
}

func TestNetworkPolicyv6(t *testing.T) {
	name := "kube_np_testnsv6_npv6"
	baseDn := makeNp(nil, nil, name).GetDn()

	npv6SDnI := fmt.Sprintf("%s/subj-networkpolicy-ingress", baseDn)
	npv6SDnE := fmt.Sprintf("%s/subj-networkpolicy-egress", baseDn)

	rule_0_0_v6 := apicapi.NewHostprotRule(npv6SDnI, "0-ipv6__npv6")
	rule_0_0_v6.SetAttr("direction", "ingress")
	rule_0_0_v6.SetAttr("ethertype", "ipv6")

	rule_1_0_v6 := apicapi.NewHostprotRule(npv6SDnI, "0_0-ipv6__npv6")
	rule_1_0_v6.SetAttr("direction", "ingress")
	rule_1_0_v6.SetAttr("ethertype", "ipv6")
	rule_1_0_v6.SetAttr("protocol", "tcp")
	rule_1_0_v6.SetAttr("fromPort", "80")

	rule_1_0_1_v6 := apicapi.NewHostprotRule(npv6SDnI, "0_0-ipv6__npv6")
	rule_1_0_1_v6.SetAttr("direction", "ingress")
	rule_1_0_1_v6.SetAttr("ethertype", "ipv6")
	rule_1_0_1_v6.SetAttr("protocol", "tcp")
	rule_1_0_1_v6.SetAttr("fromPort", "80")
	rule_1_0_1_v6.SetAttr("toPort", "90")

	rule_2_0_v6 := apicapi.NewHostprotRule(npv6SDnI, "0_0-ipv6__npv6")
	rule_2_0_v6.SetAttr("direction", "ingress")
	rule_2_0_v6.SetAttr("ethertype", "ipv6")
	rule_2_0_v6.SetAttr("protocol", "tcp")
	rule_2_0_v6.SetAttr("fromPort", "80")
	rule_2_0_v6.AddChild(
		apicapi.NewHostprotRemoteIp(rule_2_0_v6.GetDn(), "2001:db8::/128"))
	rule_2_0_v6.AddChild(
		apicapi.NewHostprotRemoteIp(rule_2_0_v6.GetDn(), "2001:db8::2/127"))
	rule_2_0_v6.AddChild(
		apicapi.NewHostprotRemoteIp(rule_2_0_v6.GetDn(), "2001:db8::4/126"))

	rule_3_0_v6 := apicapi.NewHostprotRule(npv6SDnI, "0_0-ipv6__npv6")
	rule_3_0_v6.SetAttr("direction", "ingress")
	rule_3_0_v6.SetAttr("ethertype", "ipv6")
	rule_3_0_v6.SetAttr("protocol", "udp")
	rule_3_0_v6.SetAttr("fromPort", "80")

	rule_4_1_v6 := apicapi.NewHostprotRule(npv6SDnI, "0_1-ipv6__npv6")
	rule_4_1_v6.SetAttr("direction", "ingress")
	rule_4_1_v6.SetAttr("ethertype", "ipv6")
	rule_4_1_v6.SetAttr("protocol", "tcp")
	rule_4_1_v6.SetAttr("fromPort", "443")

	rule_5_0_v6 := apicapi.NewHostprotRule(npv6SDnI, "0-ipv6__npv6")
	rule_5_0_v6.SetAttr("direction", "ingress")
	rule_5_0_v6.SetAttr("ethertype", "ipv6")
	rule_5_0_v6.AddChild(apicapi.NewHostprotRemoteIp(rule_5_0_v6.GetDn(), "2001::2"))
	rule_5_0_v6.AddChild(apicapi.NewHostprotRemoteIp(rule_5_0_v6.GetDn(), "2001::3"))

	rule_6_0_v6 := apicapi.NewHostprotRule(npv6SDnI, "0-ipv6__npv6")
	rule_6_0_v6.SetAttr("direction", "ingress")
	rule_6_0_v6.SetAttr("ethertype", "ipv6")
	rule_6_0_v6.AddChild(apicapi.NewHostprotRemoteIp(rule_6_0_v6.GetDn(), "2001::4"))
	rule_6_0_v6.AddChild(apicapi.NewHostprotRemoteIp(rule_6_0_v6.GetDn(), "2001::5"))
	rule_6_0_v6.AddChild(apicapi.NewHostprotRemoteIp(rule_6_0_v6.GetDn(), "2001::6"))

	rule_7_0_v6 := apicapi.NewHostprotRule(npv6SDnI, "0-ipv6__npv6")
	rule_7_0_v6.SetAttr("direction", "ingress")
	rule_7_0_v6.SetAttr("ethertype", "ipv6")
	rule_7_0_v6.AddChild(apicapi.NewHostprotRemoteIp(rule_7_0_v6.GetDn(), "2001::2"))

	rule_8_0_v6 := apicapi.NewHostprotRule(npv6SDnI, "0_0-ipv6__npv6")
	rule_8_0_v6.SetAttr("direction", "ingress")
	rule_8_0_v6.SetAttr("ethertype", "ipv6")
	rule_8_0_v6.SetAttr("protocol", "tcp")
	rule_8_0_v6.SetAttr("fromPort", "80")
	rule_8_0_v6.AddChild(apicapi.NewHostprotRemoteIp(rule_8_0_v6.GetDn(), "2001::2"))
	rule_8_1_v6 := apicapi.NewHostprotRule(npv6SDnI, "1_0-ipv6__npv6")
	rule_8_1_v6.SetAttr("direction", "ingress")
	rule_8_1_v6.SetAttr("ethertype", "ipv6")
	rule_8_1_v6.SetAttr("protocol", "tcp")
	rule_8_1_v6.SetAttr("fromPort", "443")
	rule_8_1_v6.AddChild(apicapi.NewHostprotRemoteIp(rule_8_1_v6.GetDn(), "2001::3"))

	rule_9_0_v6 := apicapi.NewHostprotRule(npv6SDnI, "0-ipv6__npv6")
	rule_9_0_v6.SetAttr("direction", "ingress")
	rule_9_0_v6.SetAttr("ethertype", "ipv6")
	rule_9_0_v6.AddChild(apicapi.NewHostprotRemoteIp(rule_9_0_v6.GetDn(), "2001::4"))
	rule_9_0_v6.AddChild(apicapi.NewHostprotRemoteIp(rule_9_0_v6.GetDn(), "2001::6"))

	rule_10_0_v6 := apicapi.NewHostprotRule(npv6SDnE, "0-ipv6__npv6")
	rule_10_0_v6.SetAttr("direction", "egress")
	rule_10_0_v6.SetAttr("ethertype", "ipv6")
	rule_10_0_v6.AddChild(apicapi.NewHostprotRemoteIp(rule_10_0_v6.GetDn(), "2001::4"))
	rule_10_0_v6.AddChild(apicapi.NewHostprotRemoteIp(rule_10_0_v6.GetDn(), "2001::6"))

	rule_11_0_v6 := apicapi.NewHostprotRule(npv6SDnE, "0_0-ipv6__npv6")
	rule_11_0_v6.SetAttr("direction", "egress")
	rule_11_0_v6.SetAttr("ethertype", "ipv6")
	rule_11_0_v6.SetAttr("protocol", "tcp")
	rule_11_0_v6.SetAttr("fromPort", "80")
	rule_11_0_v6.AddChild(apicapi.NewHostprotRemoteIp(rule_11_0_v6.GetDn(), "2001::2"))

	rule_11_s_v6 := apicapi.NewHostprotRule(npv6SDnE, "service_tcp_8080-ipv6")
	rule_11_s_v6.SetAttr("direction", "egress")
	rule_11_s_v6.SetAttr("ethertype", "ipv6")
	rule_11_s_v6.SetAttr("protocol", "tcp")
	rule_11_s_v6.SetAttr("fromPort", "8080")
	rule_11_s_v6.AddChild(apicapi.NewHostprotRemoteIp(rule_11_s_v6.GetDn(), "fd00::1234"))

	rule_12_0_v6 := apicapi.NewHostprotRule(npv6SDnE, "0-ipv6__npv6")
	rule_12_0_v6.SetAttr("direction", "egress")
	rule_12_0_v6.SetAttr("ethertype", "ipv6")
	rule_12_0_v6.AddChild(apicapi.NewHostprotRemoteIp(rule_12_0_v6.GetDn(),
		"2001::/64"))

	rule_12_s_0_v6 := apicapi.NewHostprotRule(npv6SDnE, "service_tcp_8080-ipv6")
	rule_12_s_0_v6.SetAttr("direction", "egress")
	rule_12_s_0_v6.SetAttr("ethertype", "ipv6")
	rule_12_s_0_v6.SetAttr("protocol", "tcp")
	rule_12_s_0_v6.SetAttr("fromPort", "8080")
	rule_12_s_0_v6.AddChild(apicapi.NewHostprotRemoteIp(rule_12_s_0_v6.GetDn(),
		"fd00::1236"))

	rule_12_s_1_v6 := apicapi.NewHostprotRule(npv6SDnE, "service_tcp_8443-ipv6")
	rule_12_s_1_v6.SetAttr("direction", "egress")
	rule_12_s_1_v6.SetAttr("ethertype", "ipv6")
	rule_12_s_1_v6.SetAttr("protocol", "tcp")
	rule_12_s_1_v6.SetAttr("fromPort", "8443")
	rule_12_s_1_v6.AddChild(apicapi.NewHostprotRemoteIp(rule_12_s_1_v6.GetDn(),
		"fd00::1236"))

	rule_13_0_v6 := apicapi.NewHostprotRule(npv6SDnE, "0-ipv6__npv6")
	rule_13_0_v6.SetAttr("direction", "egress")
	rule_13_0_v6.SetAttr("ethertype", "ipv6")

	rule_14_0_v6 := apicapi.NewHostprotRule(npv6SDnE, "0_0-ipv6__npv6")
	rule_14_0_v6.SetAttr("direction", "egress")
	rule_14_0_v6.SetAttr("ethertype", "ipv6")
	rule_14_0_v6.SetAttr("protocol", "tcp")
	rule_14_0_v6.SetAttr("fromPort", "80")

	rule_14_s_v6 := apicapi.NewHostprotRule(npv6SDnE, "service_tcp_8080-ipv6")
	rule_14_s_v6.SetAttr("direction", "egress")
	rule_14_s_v6.SetAttr("ethertype", "ipv6")
	rule_14_s_v6.SetAttr("protocol", "tcp")
	rule_14_s_v6.SetAttr("fromPort", "8080")
	rule_14_s_v6.AddChild(apicapi.NewHostprotRemoteIp(rule_14_s_v6.GetDn(), "fd00::1234"))
	var np6Tests = []npTest{
		{netpol("testnsv6", "npv6", &metav1.LabelSelector{},
			[]v1net.NetworkPolicyIngressRule{ingressRule(nil, nil)},
			nil, allPolicyTypes),
			makeNp(apicapi.ApicSlice{rule_0_0_v6}, nil, name),
			nil, "v6-np-allow-all",
		},
		{netpol("testnsv6", "npv6", &metav1.LabelSelector{},
			[]v1net.NetworkPolicyIngressRule{
				ingressRule([]v1net.NetworkPolicyPort{port(&tcp, &port80)},
					nil)}, nil, allPolicyTypes),
			makeNp(apicapi.ApicSlice{rule_1_0_v6}, nil, name),
			nil, "allow-http"},
		{netpol("testnsv6", "npv6", &metav1.LabelSelector{},
			[]v1net.NetworkPolicyIngressRule{
				ingressRule([]v1net.NetworkPolicyPort{rangedPort(&tcp, &port80, &eport90)},
					nil)}, nil, allPolicyTypes),
			makeNp(apicapi.ApicSlice{rule_1_0_1_v6}, nil, name),
			nil, "allow-http-portrange"},
		{netpol("testnsv6", "npv6", &metav1.LabelSelector{},
			[]v1net.NetworkPolicyIngressRule{
				ingressRule([]v1net.NetworkPolicyPort{port(&tcp, &port80)},
					[]v1net.NetworkPolicyPeer{
						peerIpBlock(peer(nil, nil), "2001:db8::1/125", []string{"2001:db8::1/128"}),
					},
				)}, nil, allPolicyTypes),
			makeNp(apicapi.ApicSlice{rule_2_0_v6}, nil, name),
			nil, "allow-http-from"},
		{netpol("testnsv6", "npv6", &metav1.LabelSelector{},
			[]v1net.NetworkPolicyIngressRule{
				ingressRule([]v1net.NetworkPolicyPort{
					port(nil, &port80)}, nil)}, nil, allPolicyTypes),
			makeNp(apicapi.ApicSlice{rule_1_0_v6}, nil, name),
			nil, "allow-http-defproto"},
		{netpol("testnsv6", "npv6", &metav1.LabelSelector{},
			[]v1net.NetworkPolicyIngressRule{
				ingressRule([]v1net.NetworkPolicyPort{
					port(&udp, &port80)}, nil)}, nil, allPolicyTypes),
			makeNp(apicapi.ApicSlice{rule_3_0_v6}, nil, name),
			nil, "allow-80-udp"},
		{netpol("testnsv6", "npv6", &metav1.LabelSelector{},
			[]v1net.NetworkPolicyIngressRule{
				ingressRule([]v1net.NetworkPolicyPort{
					port(nil, &port80), port(nil, &port443),
				}, nil)}, nil, allPolicyTypes),
			makeNp(apicapi.ApicSlice{rule_1_0_v6, rule_4_1_v6}, nil, name),
			nil, "allow-http-https"},
		{netpol("testnsv6", "npv6", &metav1.LabelSelector{},
			[]v1net.NetworkPolicyIngressRule{ingressRule(nil,
				[]v1net.NetworkPolicyPeer{peer(nil,
					&metav1.LabelSelector{
						MatchLabels: map[string]string{"test": "testv"},
					}),
				}),
			}, nil, allPolicyTypes),
			makeNp(apicapi.ApicSlice{rule_5_0_v6}, nil, name),
			nil, "allow-all-from-ns"},
		{netpol("testnsv6", "npv6", &metav1.LabelSelector{},
			[]v1net.NetworkPolicyIngressRule{ingressRule(nil,
				[]v1net.NetworkPolicyPeer{peer(nil,
					&metav1.LabelSelector{
						MatchLabels: map[string]string{"test": "notathing"},
					}),
				}),
			}, nil, allPolicyTypes),
			makeNp(nil, nil, name),
			nil, "allow-all-from-ns-no-match"},
		{netpol("testnsv6", "npv6", &metav1.LabelSelector{},
			[]v1net.NetworkPolicyIngressRule{
				ingressRule([]v1net.NetworkPolicyPort{
					port(&udp, &port80)}, nil)}, nil, allPolicyTypes),
			makeNp(apicapi.ApicSlice{rule_3_0_v6}, nil, name),
			nil, "allow-80-udp"},
		{netpol("testnsv6", "npv6", &metav1.LabelSelector{},
			[]v1net.NetworkPolicyIngressRule{
				ingressRule([]v1net.NetworkPolicyPort{
					port(nil, &port80), port(nil, &port443),
				}, nil)}, nil, allPolicyTypes),
			makeNp(apicapi.ApicSlice{rule_1_0_v6, rule_4_1_v6}, nil, name),
			nil, "allow-http-https"},
		{netpol("testnsv6", "npv6", &metav1.LabelSelector{},
			[]v1net.NetworkPolicyIngressRule{ingressRule(nil,
				[]v1net.NetworkPolicyPeer{peer(nil,
					&metav1.LabelSelector{
						MatchLabels: map[string]string{"test": "testv"},
					}),
				}),
			}, nil, allPolicyTypes),
			makeNp(apicapi.ApicSlice{rule_5_0_v6}, nil, name),
			nil, "allow-all-from-ns"},
		{netpol("testnsv6", "npv6", &metav1.LabelSelector{},
			[]v1net.NetworkPolicyIngressRule{ingressRule(nil,
				[]v1net.NetworkPolicyPeer{peer(nil,
					&metav1.LabelSelector{
						MatchLabels: map[string]string{"test": "notathing"},
					}),
				}),
			}, nil, allPolicyTypes),
			makeNp(nil, nil, name),
			nil, "allow-all-from-ns-no-match"},
		{netpol("testnsv6", "npv6", &metav1.LabelSelector{},
			[]v1net.NetworkPolicyIngressRule{ingressRule(nil,
				[]v1net.NetworkPolicyPeer{peer(nil,
					&metav1.LabelSelector{
						MatchLabels: map[string]string{"nl": "nv"},
					}),
				}),
			}, nil, allPolicyTypes),
			makeNp(apicapi.ApicSlice{rule_6_0_v6}, nil, name),
			nil, "allow-all-from-multiple-ns"},
		{netpol("testnsv6", "npv6", &metav1.LabelSelector{},
			[]v1net.NetworkPolicyIngressRule{ingressRule(nil,
				[]v1net.NetworkPolicyPeer{
					peer(&metav1.LabelSelector{
						MatchLabels: map[string]string{"l1": "v1"},
					}, nil),
				}),
			}, nil, allPolicyTypes),
			makeNp(apicapi.ApicSlice{rule_7_0_v6}, nil, name),
			nil, "allow-all-select-pods"},
		{netpol("testnsv6", "npv6", &metav1.LabelSelector{},
			[]v1net.NetworkPolicyIngressRule{ingressRule(nil,
				[]v1net.NetworkPolicyPeer{
					peer(&metav1.LabelSelector{
						MatchLabels: map[string]string{"l1": "v1"},
					}, &metav1.LabelSelector{
						MatchLabels: map[string]string{"nl": "nv"},
					}),
				}),
			}, nil, allPolicyTypes),
			makeNp(apicapi.ApicSlice{rule_9_0_v6}, nil, name),
			nil, "allow-all-select-pods-and-ns"},
		{netpol("testnsv6", "npv6", &metav1.LabelSelector{},
			[]v1net.NetworkPolicyIngressRule{
				ingressRule([]v1net.NetworkPolicyPort{
					port(nil, &port80),
				}, []v1net.NetworkPolicyPeer{
					peer(&metav1.LabelSelector{
						MatchLabels: map[string]string{"l1": "v1"},
					}, nil),
				}),
				ingressRule([]v1net.NetworkPolicyPort{
					port(nil, &port443),
				}, []v1net.NetworkPolicyPeer{
					peer(&metav1.LabelSelector{
						MatchLabels: map[string]string{"l1": "v2"},
					}, nil),
				}),
			}, nil, allPolicyTypes),
			makeNp(apicapi.ApicSlice{rule_8_0_v6, rule_8_1_v6}, nil, name),
			nil, "multiple-from"},
		{netpol("testnsv6", "npv6", &metav1.LabelSelector{},
			nil, []v1net.NetworkPolicyEgressRule{
				egressRule(nil,
					[]v1net.NetworkPolicyPeer{
						peer(&metav1.LabelSelector{
							MatchLabels: map[string]string{"l1": "v1"},
						}, &metav1.LabelSelector{
							MatchLabels: map[string]string{"nl": "nv"},
						}),
					}),
			}, allPolicyTypes),
			makeNp(nil, apicapi.ApicSlice{rule_10_0_v6}, name),
			nil, "egress-allow-all-select-pods-and-ns"},
		{netpol("testnsv6", "npv6", &metav1.LabelSelector{},
			nil, []v1net.NetworkPolicyEgressRule{
				egressRule([]v1net.NetworkPolicyPort{port(&tcp, &port80)},
					[]v1net.NetworkPolicyPeer{
						peer(&metav1.LabelSelector{
							MatchLabels: map[string]string{"l1": "v1"},
						}, nil),
					}),
			}, allPolicyTypes),
			makeNp(nil, apicapi.ApicSlice{rule_11_0_v6}, name),
			nil, "egress-allow-http-select-pods"},
		{netpol("testnsv6", "npv6", &metav1.LabelSelector{},
			nil, []v1net.NetworkPolicyEgressRule{
				egressRule([]v1net.NetworkPolicyPort{port(&tcp, &port80)},
					//nil),
					[]v1net.NetworkPolicyPeer{
						peer(&metav1.LabelSelector{
							MatchLabels: map[string]string{"l1": "v1"},
						}, nil),
					}),
			}, allPolicyTypes),
			makeNp(nil, apicapi.ApicSlice{rule_11_0_v6, rule_11_s_v6}, name),
			&npTestAugment{
				[]*v1.Endpoints{
					makeEps("testnsv6", "service1",
						[]v1.EndpointAddress{
							{
								IP: "2001::2",
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "testnsv6",
									Name:      "pod1",
								},
							},
						},
						[]v1.EndpointPort{
							endpointPort(v1.ProtocolTCP, 80, ""),
						}),
					makeEps("testnsv6", "service2",
						[]v1.EndpointAddress{
							{
								IP: "2002:2::2",
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "testnsv6",
									Name:      "pod2",
								},
							},
						},
						[]v1.EndpointPort{
							endpointPort(v1.ProtocolTCP, 80, ""),
						}),
					makeEps("testnsv6", "service3",
						[]v1.EndpointAddress{
							{
								IP: "2001::2",
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "testnsv6",
									Name:      "pod1",
								},
							},
							{
								IP: "2002:2::2",
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "testnsv6",
									Name:      "pod2",
								},
							},
						},
						[]v1.EndpointPort{
							endpointPort(v1.ProtocolTCP, 80, ""),
						}),
				},
				[]*v1.Service{
					npservice("testnsv6", "service1", "fd00::1234",
						[]v1.ServicePort{
							servicePort("", v1.ProtocolTCP, 8080, 80),
						}),
					npservice("testnsv6", "service2", "fd00::1235",
						[]v1.ServicePort{
							servicePort("", v1.ProtocolTCP, 8080, 80),
						}), // should not match (no matching IPs)
					npservice("testnsv6", "service3", "fd00::1236",
						[]v1.ServicePort{
							servicePort("", v1.ProtocolTCP, 8080, 80),
						}), // should not match (incomplete IPs)
				},
				[]*discovery.EndpointSlice{},
			}, "egress-allow-http-augment"},
		{netpol("testnsv6", "npv6", &metav1.LabelSelector{},
			nil, []v1net.NetworkPolicyEgressRule{
				egressRule([]v1net.NetworkPolicyPort{port(&tcp, &port80)},
					nil),
			}, allPolicyTypes),
			makeNp(nil, apicapi.ApicSlice{rule_14_0_v6, rule_14_s_v6}, name),
			&npTestAugment{
				[]*v1.Endpoints{
					makeEps("testnsv6", "service1",
						[]v1.EndpointAddress{
							{
								IP: "2001::2",
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "testns",
									Name:      "pod1",
								},
							},
						},
						[]v1.EndpointPort{
							endpointPort(v1.ProtocolTCP, 80, ""),
						}),
					makeEps("testns", "service2",
						[]v1.EndpointAddress{
							{
								IP: "2002::2",
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "testns",
									Name:      "pod2",
								},
							},
						},
						[]v1.EndpointPort{
							endpointPort(v1.ProtocolTCP, 81, ""),
						}),
				},
				[]*v1.Service{
					npservice("testns", "service1", "fd00::1234",
						[]v1.ServicePort{
							servicePort("", v1.ProtocolTCP, 8080, 80),
						}),
					npservice("testns", "service2", "fd00::1239",
						[]v1.ServicePort{
							servicePort("", v1.ProtocolTCP, 8080, 81),
						}), // should not match (port wrong)
				},
				[]*discovery.EndpointSlice{},
			}, "egress-allow-http-all-augment"},
		{netpol("testnsv6", "npv6", &metav1.LabelSelector{},
			nil, []v1net.NetworkPolicyEgressRule{
				egressRule(nil,
					[]v1net.NetworkPolicyPeer{
						peerIpBlock(peer(nil, nil), "2001::0/64", nil),
					}),
			}, allPolicyTypes),
			makeNp(nil,
				apicapi.ApicSlice{rule_12_0_v6, rule_12_s_0_v6, rule_12_s_1_v6}, name),
			&npTestAugment{
				[]*v1.Endpoints{
					makeEps("testnsv6", "service1",
						[]v1.EndpointAddress{
							{
								IP: "2001::4",
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "ns1",
									Name:      "pod3",
								},
							},
							{
								IP: "2001::5",
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "ns1",
									Name:      "pod4",
								},
							},
							{
								IP: "2001::6",
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "ns2",
									Name:      "pod5",
								},
							},
						},
						[]v1.EndpointPort{
							endpointPort(v1.ProtocolTCP, 80, "http"),
							endpointPort(v1.ProtocolTCP, 443, "https"),
						}),
				},
				[]*v1.Service{
					npservice("testnsv6", "service1", "fd00::1236",
						[]v1.ServicePort{
							servicePort("http", v1.ProtocolTCP, 8080, 80),
							servicePort("https", v1.ProtocolTCP, 8443, 443),
						}),
				},
				[]*discovery.EndpointSlice{},
			}, "egress-allow-subnet-augment"},
		{netpol("testnsv6", "npv6", &metav1.LabelSelector{},
			nil, []v1net.NetworkPolicyEgressRule{
				egressRule(nil, nil),
			}, allPolicyTypes),
			makeNp(nil, apicapi.ApicSlice{rule_13_0_v6}, name),
			&npTestAugment{
				[]*v1.Endpoints{
					makeEps("testns", "service1",
						[]v1.EndpointAddress{
							{
								IP: "2001::2",
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "testns",
									Name:      "pod1",
								},
							},
						},
						[]v1.EndpointPort{
							endpointPort(v1.ProtocolTCP, 80, ""),
						}),
				},
				[]*v1.Service{
					npservice("testns", "service1", "fd00::1234",
						[]v1.ServicePort{
							servicePort("", v1.ProtocolTCP, 8080, 80),
						}),
				},
				[]*discovery.EndpointSlice{},
			}, "egress-allow-all-augment"},
	}

	initCont := func() *testAciController {
		cont := testController()
		cont.config.AciPolicyTenant = "test-tenant"
		cont.config.NodeServiceIpPool = []ipam.IpRange{
			{Start: net.ParseIP("2002::2"), End: net.ParseIP("2002::3")},
		}
		cont.config.PodIpPool = []ipam.IpRange{
			{Start: net.ParseIP("2001::2"), End: net.ParseIP("2001::64")},
		}
		cont.AciController.initIpam()

		cont.fakeNamespaceSource.Add(namespaceLabel("testnsv6",
			map[string]string{"test": "testv"}))
		cont.fakeNamespaceSource.Add(namespaceLabel("ns1",
			map[string]string{"nl": "nv"}))
		cont.fakeNamespaceSource.Add(namespaceLabel("ns2",
			map[string]string{"nl": "nv"}))

		return cont
	}

	{
		cont := testController()
		cont.run()
		static := cont.staticNetPolObjs()
		apicapi.PrepareApicSlice(static, "kube", staticNetPolKey())
		assert.Equal(t, static,
			cont.apicConn.GetDesiredState(staticNetPolKey()), staticNetPolKey())
		cont.stop()
	}

	ips := []string{
		"2001::2", "2001::3", "2001::4", "2001::5", "2001::6", "",
	}
	for ix := range np6Tests {
		cont := initCont()
		cont.log.Info("Starting podsfirst ", np6Tests[ix].desc)
		addPods(cont, true, ips, false)
		addServices(cont, np6Tests[ix].augment)
		cont.run()
		cont.fakeNetworkPolicySource.Add(np6Tests[ix].netPol)
		checkNp(t, &np6Tests[ix], "podsfirst", cont)

		cont.log.Info("Starting delete ", np6Tests[ix].desc)
		cont.fakeNetworkPolicySource.Delete(np6Tests[ix].netPol)
		checkDelete(t, np6Tests[0], cont)
		cont.stop()
	}

	for ix := range np6Tests {
		cont := initCont()
		cont.log.Info("Starting npfirst ", np6Tests[ix].desc)
		cont.fakeNetworkPolicySource.Add(np6Tests[ix].netPol)
		cont.run()
		addServices(cont, np6Tests[ix].augment)
		addPods(cont, false, ips, false)
		addPods(cont, true, ips, false)
		checkNp(t, &np6Tests[ix], "npfirst", cont)
		cont.stop()
	}
}

func TestNetworkPolicyv6HppOptimize(t *testing.T) {
	rule_0_v6 := map[string]string{"direction": "ingress", "ethertype": "ipv6"}
	rule_1_v6 := map[string]string{"direction": "ingress", "ethertype": "ipv6",
		"protocol": "tcp", "fromPort": "80"}
	rule_2_v6 := map[string]string{"direction": "ingress", "ethertype": "ipv6",
		"protocol": "udp", "fromPort": "80"}
	rule_3_v6 := map[string]string{"direction": "ingress", "ethertype": "ipv6",
		"protocol": "tcp", "fromPort": "443"}

	rule_4_v6 := map[string]string{"direction": "egress", "ethertype": "ipv6"}
	rule_5_v6 := map[string]string{"direction": "egress", "ethertype": "ipv6",
		"protocol": "tcp", "fromPort": "80"}
	rule_6_v6 := map[string]string{"direction": "egress", "ethertype": "ipv6",
		"protocol": "tcp", "fromPort": "8080"}
	rule_7_v6 := map[string]string{"direction": "egress", "ethertype": "ipv6",
		"protocol": "tcp", "fromPort": "8443"}

	//v6-np-allow-all
	test0_np_v6 := netpol("testnsv6", "npv6", &metav1.LabelSelector{},
		[]v1net.NetworkPolicyIngressRule{ingressRule(nil, nil)},
		nil, allPolicyTypes)
	hash, _ := util.CreateHashFromNetPol(test0_np_v6)
	test0_np_name_v6 := "kube_np_" + hash
	test0_rule_v6 := createRule(test0_np_name_v6, true, rule_0_v6, "0-ipv6__npv6")

	//allow-http
	test1_np_v6 := netpol("testnsv6", "npv6", &metav1.LabelSelector{},
		[]v1net.NetworkPolicyIngressRule{
			ingressRule([]v1net.NetworkPolicyPort{port(&tcp, &port80)},
				nil)}, nil, allPolicyTypes)
	hash, _ = util.CreateHashFromNetPol(test1_np_v6)
	test1_np_name_v6 := "kube_np_" + hash
	test1_rule_v6 := createRule(test1_np_name_v6, true, rule_1_v6, "0_0-ipv6__npv6")

	//allow-http-from
	test2_np_v6 := netpol("testnsv6", "npv6", &metav1.LabelSelector{},
		[]v1net.NetworkPolicyIngressRule{
			ingressRule([]v1net.NetworkPolicyPort{port(&tcp, &port80)},
				[]v1net.NetworkPolicyPeer{
					peerIpBlock(peer(nil, nil), "2001:db8::1/125", []string{"2001:db8::1/128"}),
				},
			)}, nil, allPolicyTypes)
	hash, _ = util.CreateHashFromNetPol(test2_np_v6)
	test2_np_name_v6 := "kube_np_" + hash
	test2_rule_v6 := createRule(test2_np_name_v6, true, rule_1_v6, "0_0-ipv6__npv6")
	test2_rule_v6.AddChild(
		apicapi.NewHostprotRemoteIp(test2_rule_v6.GetDn(), "2001:db8::/128"))
	test2_rule_v6.AddChild(
		apicapi.NewHostprotRemoteIp(test2_rule_v6.GetDn(), "2001:db8::2/127"))
	test2_rule_v6.AddChild(
		apicapi.NewHostprotRemoteIp(test2_rule_v6.GetDn(), "2001:db8::4/126"))

	//allow-http-defproto
	test3_np_v6 := netpol("testnsv6", "npv6", &metav1.LabelSelector{},
		[]v1net.NetworkPolicyIngressRule{
			ingressRule([]v1net.NetworkPolicyPort{
				port(nil, &port80)}, nil)}, nil, allPolicyTypes)
	hash, _ = util.CreateHashFromNetPol(test3_np_v6)
	test3_np_name_v6 := "kube_np_" + hash
	test3_rule_v6 := createRule(test3_np_name_v6, true, rule_1_v6, "0_0-ipv6__npv6")

	//allow-80-udp
	test4_np_v6 := netpol("testnsv6", "npv6", &metav1.LabelSelector{},
		[]v1net.NetworkPolicyIngressRule{
			ingressRule([]v1net.NetworkPolicyPort{
				port(&udp, &port80)}, nil)}, nil, allPolicyTypes)
	hash, _ = util.CreateHashFromNetPol(test4_np_v6)
	test4_np_name_v6 := "kube_np_" + hash
	test4_rule_v6 := createRule(test4_np_name_v6, true, rule_2_v6, "0_0-ipv6__npv6")

	//allow-http-https
	test5_np_v6 := netpol("testnsv6", "npv6", &metav1.LabelSelector{},
		[]v1net.NetworkPolicyIngressRule{
			ingressRule([]v1net.NetworkPolicyPort{
				port(nil, &port80), port(nil, &port443),
			}, nil)}, nil, allPolicyTypes)
	hash, _ = util.CreateHashFromNetPol(test5_np_v6)
	test5_np_name_v6 := "kube_np_" + hash
	test5_rule1_v6 := createRule(test5_np_name_v6, true, rule_1_v6, "0_0-ipv6__npv6")
	test5_rule2_v6 := createRule(test5_np_name_v6, true, rule_3_v6, "0_1-ipv6__npv6")

	//allow-all-from-ns
	test6_np_v6 := netpol("testnsv6", "npv6", &metav1.LabelSelector{},
		[]v1net.NetworkPolicyIngressRule{ingressRule(nil,
			[]v1net.NetworkPolicyPeer{peer(nil,
				&metav1.LabelSelector{
					MatchLabels: map[string]string{"test": "testv"},
				}),
			}),
		}, nil, allPolicyTypes)
	hash, _ = util.CreateHashFromNetPol(test6_np_v6)
	test6_np_name_v6 := "kube_np_" + hash
	test6_rule_v6 := createRule(test6_np_name_v6, true, rule_0_v6, "0-ipv6__npv6")
	test6_rule_v6.AddChild(apicapi.NewHostprotRemoteIp(test6_rule_v6.GetDn(), "2001::2"))
	test6_rule_v6.AddChild(apicapi.NewHostprotRemoteIp(test6_rule_v6.GetDn(), "2001::3"))

	//allow-all-from-ns-no-match
	test7_np_v6 := netpol("testnsv6", "npv6", &metav1.LabelSelector{},
		[]v1net.NetworkPolicyIngressRule{ingressRule(nil,
			[]v1net.NetworkPolicyPeer{peer(nil,
				&metav1.LabelSelector{
					MatchLabels: map[string]string{"test": "notathing"},
				}),
			}),
		}, nil, allPolicyTypes)
	hash, _ = util.CreateHashFromNetPol(test7_np_v6)
	test7_np_name_v6 := "kube_np_" + hash

	//allow-all-from-multiple-ns
	test8_np_v6 := netpol("testnsv6", "npv6", &metav1.LabelSelector{},
		[]v1net.NetworkPolicyIngressRule{ingressRule(nil,
			[]v1net.NetworkPolicyPeer{peer(nil,
				&metav1.LabelSelector{
					MatchLabels: map[string]string{"nl": "nv"},
				}),
			}),
		}, nil, allPolicyTypes)
	hash, _ = util.CreateHashFromNetPol(test8_np_v6)
	test8_np_name_v6 := "kube_np_" + hash
	test8_rule_v6 := createRule(test8_np_name_v6, true, rule_0_v6, "0-ipv6__npv6")
	test8_rule_v6.AddChild(apicapi.NewHostprotRemoteIp(test8_rule_v6.GetDn(), "2001::4"))
	test8_rule_v6.AddChild(apicapi.NewHostprotRemoteIp(test8_rule_v6.GetDn(), "2001::5"))
	test8_rule_v6.AddChild(apicapi.NewHostprotRemoteIp(test8_rule_v6.GetDn(), "2001::6"))

	//allow-all-select-pods
	test9_np_v6 := netpol("testnsv6", "npv6", &metav1.LabelSelector{},
		[]v1net.NetworkPolicyIngressRule{ingressRule(nil,
			[]v1net.NetworkPolicyPeer{
				peer(&metav1.LabelSelector{
					MatchLabels: map[string]string{"l1": "v1"},
				}, nil),
			}),
		}, nil, allPolicyTypes)
	hash, _ = util.CreateHashFromNetPol(test9_np_v6)
	test9_np_name_v6 := "kube_np_" + hash
	test9_rule_v6 := createRule(test9_np_name_v6, true, rule_0_v6, "0-ipv6__npv6")
	test9_rule_v6.AddChild(apicapi.NewHostprotRemoteIp(test9_rule_v6.GetDn(), "2001::2"))

	//allow-all-select-pods-and-ns
	test10_np_v6 := netpol("testnsv6", "npv6", &metav1.LabelSelector{},
		[]v1net.NetworkPolicyIngressRule{ingressRule(nil,
			[]v1net.NetworkPolicyPeer{
				peer(&metav1.LabelSelector{
					MatchLabels: map[string]string{"l1": "v1"},
				}, &metav1.LabelSelector{
					MatchLabels: map[string]string{"nl": "nv"},
				}),
			}),
		}, nil, allPolicyTypes)
	hash, _ = util.CreateHashFromNetPol(test10_np_v6)
	test10_np_name_v6 := "kube_np_" + hash
	test10_rule_v6 := createRule(test10_np_name_v6, true, rule_0_v6, "0-ipv6__npv6")
	test10_rule_v6.AddChild(apicapi.NewHostprotRemoteIp(test10_rule_v6.GetDn(), "2001::4"))
	test10_rule_v6.AddChild(apicapi.NewHostprotRemoteIp(test10_rule_v6.GetDn(), "2001::6"))

	//multiple-from
	test11_np_v6 := netpol("testnsv6", "npv6", &metav1.LabelSelector{},
		[]v1net.NetworkPolicyIngressRule{
			ingressRule([]v1net.NetworkPolicyPort{
				port(nil, &port80),
			}, []v1net.NetworkPolicyPeer{
				peer(&metav1.LabelSelector{
					MatchLabels: map[string]string{"l1": "v1"},
				}, nil),
			}),
			ingressRule([]v1net.NetworkPolicyPort{
				port(nil, &port443),
			}, []v1net.NetworkPolicyPeer{
				peer(&metav1.LabelSelector{
					MatchLabels: map[string]string{"l1": "v2"},
				}, nil),
			}),
		}, nil, allPolicyTypes)
	hash, _ = util.CreateHashFromNetPol(test11_np_v6)
	test11_np_name_v6 := "kube_np_" + hash
	test11_rule1_v6 := createRule(test11_np_name_v6, true, rule_1_v6, "0_0-ipv6__npv6")
	test11_rule1_v6.AddChild(apicapi.NewHostprotRemoteIp(test11_rule1_v6.GetDn(), "2001::2"))
	test11_rule2_v6 := createRule(test11_np_name_v6, true, rule_3_v6, "1_0-ipv6__npv6")
	test11_rule2_v6.AddChild(apicapi.NewHostprotRemoteIp(test11_rule2_v6.GetDn(), "2001::3"))

	//egress-allow-all-select-pods-and-ns
	test12_np_v6 := netpol("testnsv6", "npv6", &metav1.LabelSelector{},
		nil, []v1net.NetworkPolicyEgressRule{
			egressRule(nil,
				[]v1net.NetworkPolicyPeer{
					peer(&metav1.LabelSelector{
						MatchLabels: map[string]string{"l1": "v1"},
					}, &metav1.LabelSelector{
						MatchLabels: map[string]string{"nl": "nv"},
					}),
				}),
		}, allPolicyTypes)
	hash, _ = util.CreateHashFromNetPol(test12_np_v6)
	test12_np_name_v6 := "kube_np_" + hash
	test12_rule_v6 := createRule(test12_np_name_v6, false, rule_4_v6, "0-ipv6__npv6")
	test12_rule_v6.AddChild(apicapi.NewHostprotRemoteIp(test12_rule_v6.GetDn(), "2001::4"))
	test12_rule_v6.AddChild(apicapi.NewHostprotRemoteIp(test12_rule_v6.GetDn(), "2001::6"))

	//egress-allow-http-select-pods
	test13_np_v6 := netpol("testnsv6", "npv6", &metav1.LabelSelector{},
		nil, []v1net.NetworkPolicyEgressRule{
			egressRule([]v1net.NetworkPolicyPort{port(&tcp, &port80)},
				[]v1net.NetworkPolicyPeer{
					peer(&metav1.LabelSelector{
						MatchLabels: map[string]string{"l1": "v1"},
					}, nil),
				}),
		}, allPolicyTypes)
	hash, _ = util.CreateHashFromNetPol(test13_np_v6)
	test13_np_name_v6 := "kube_np_" + hash
	test13_rule_v6 := createRule(test13_np_name_v6, false, rule_5_v6, "0_0-ipv6__npv6")
	test13_rule_v6.AddChild(apicapi.NewHostprotRemoteIp(test13_rule_v6.GetDn(), "2001::2"))

	//egress-allow-http-augment
	test14_np_v6 := netpol("testnsv6", "npv6", &metav1.LabelSelector{},
		nil, []v1net.NetworkPolicyEgressRule{
			egressRule([]v1net.NetworkPolicyPort{port(&tcp, &port80)},
				//nil),
				[]v1net.NetworkPolicyPeer{
					peer(&metav1.LabelSelector{
						MatchLabels: map[string]string{"l1": "v1"},
					}, nil),
				}),
		}, allPolicyTypes)
	hash, _ = util.CreateHashFromNetPol(test14_np_v6)
	test14_np_name_v6 := "kube_np_" + hash
	test14_rule1_v6 := createRule(test14_np_name_v6, false, rule_5_v6, "0_0-ipv6__npv6")
	test14_rule1_v6.AddChild(apicapi.NewHostprotRemoteIp(test14_rule1_v6.GetDn(), "2001::2"))
	test14_rule2_v6 := createRule(test14_np_name_v6, false, rule_6_v6, "service_tcp_8080-ipv6")
	test14_rule2_v6.AddChild(apicapi.NewHostprotRemoteIp(test14_rule2_v6.GetDn(), "fd00::1234"))

	//egress-allow-http-all-augment
	test15_np_v6 := netpol("testnsv6", "npv6", &metav1.LabelSelector{},
		nil, []v1net.NetworkPolicyEgressRule{
			egressRule([]v1net.NetworkPolicyPort{port(&tcp, &port80)},
				nil),
		}, allPolicyTypes)
	hash, _ = util.CreateHashFromNetPol(test15_np_v6)
	test15_np_name_v6 := "kube_np_" + hash
	test15_rule1_v6 := createRule(test15_np_name_v6, false, rule_5_v6, "0_0-ipv6__npv6")
	test15_rule2_v6 := createRule(test15_np_name_v6, false, rule_6_v6, "service_tcp_8080-ipv6")
	test15_rule2_v6.AddChild(apicapi.NewHostprotRemoteIp(test15_rule2_v6.GetDn(), "fd00::1234"))

	//egress-allow-subnet-augment
	test16_np_v6 := netpol("testnsv6", "npv6", &metav1.LabelSelector{},
		nil, []v1net.NetworkPolicyEgressRule{
			egressRule(nil,
				[]v1net.NetworkPolicyPeer{
					peerIpBlock(peer(nil, nil), "2001::0/64", nil),
				}),
		}, allPolicyTypes)
	hash, _ = util.CreateHashFromNetPol(test16_np_v6)
	test16_np_name_v6 := "kube_np_" + hash
	test16_rule1_v6 := createRule(test16_np_name_v6, false, rule_4_v6, "0-ipv6__npv6")
	test16_rule1_v6.AddChild(apicapi.NewHostprotRemoteIp(test16_rule1_v6.GetDn(), "2001::/64"))
	test16_rule2_v6 := createRule(test16_np_name_v6, false, rule_6_v6, "service_tcp_8080-ipv6")
	test16_rule2_v6.AddChild(apicapi.NewHostprotRemoteIp(test16_rule2_v6.GetDn(), "fd00::1236"))
	test16_rule3_v6 := createRule(test16_np_name_v6, false, rule_7_v6, "service_tcp_8443-ipv6")
	test16_rule3_v6.AddChild(apicapi.NewHostprotRemoteIp(test16_rule3_v6.GetDn(), "fd00::1236"))

	//egress-allow-all-augment
	test17_np_v6 := netpol("testnsv6", "npv6", &metav1.LabelSelector{},
		nil, []v1net.NetworkPolicyEgressRule{
			egressRule(nil, nil),
		}, allPolicyTypes)
	hash, _ = util.CreateHashFromNetPol(test17_np_v6)
	test17_np_name_v6 := "kube_np_" + hash
	test17_rule_v6 := createRule(test17_np_name_v6, false, rule_4_v6, "0-ipv6__npv6")

	var np6Tests = []npTest{
		{test0_np_v6,
			makeNp(apicapi.ApicSlice{test0_rule_v6}, nil, test0_np_name_v6),
			nil, "v6-np-allow-all",
		},
		{test1_np_v6,
			makeNp(apicapi.ApicSlice{test1_rule_v6}, nil, test1_np_name_v6),
			nil, "allow-http"},
		{test2_np_v6,
			makeNp(apicapi.ApicSlice{test2_rule_v6}, nil, test2_np_name_v6),
			nil, "allow-http-from"},
		{test3_np_v6,
			makeNp(apicapi.ApicSlice{test3_rule_v6}, nil, test3_np_name_v6),
			nil, "allow-http-defproto"},
		{test4_np_v6,
			makeNp(apicapi.ApicSlice{test4_rule_v6}, nil, test4_np_name_v6),
			nil, "allow-80-udp"},
		{test5_np_v6,
			makeNp(apicapi.ApicSlice{test5_rule1_v6, test5_rule2_v6}, nil, test5_np_name_v6),
			nil, "allow-http-https"},
		{test6_np_v6,
			makeNp(apicapi.ApicSlice{test6_rule_v6}, nil, test6_np_name_v6),
			nil, "allow-all-from-ns"},
		{test7_np_v6,
			makeNp(nil, nil, test7_np_name_v6),
			nil, "allow-all-from-ns-no-match"},
		{test8_np_v6,
			makeNp(apicapi.ApicSlice{test8_rule_v6}, nil, test8_np_name_v6),
			nil, "allow-all-from-multiple-ns"},
		{test9_np_v6,
			makeNp(apicapi.ApicSlice{test9_rule_v6}, nil, test9_np_name_v6),
			nil, "allow-all-select-pods"},
		{test10_np_v6,
			makeNp(apicapi.ApicSlice{test10_rule_v6}, nil, test10_np_name_v6),
			nil, "allow-all-select-pods-and-ns"},
		{test11_np_v6,
			makeNp(apicapi.ApicSlice{test11_rule1_v6, test11_rule2_v6}, nil, test11_np_name_v6),
			nil, "multiple-from"},
		{test12_np_v6,
			makeNp(nil, apicapi.ApicSlice{test12_rule_v6}, test12_np_name_v6),
			nil, "egress-allow-all-select-pods-and-ns"},
		{test13_np_v6,
			makeNp(nil, apicapi.ApicSlice{test13_rule_v6}, test13_np_name_v6),
			nil, "egress-allow-http-select-pods"},
		{test14_np_v6,
			makeNp(nil, apicapi.ApicSlice{test14_rule1_v6, test14_rule2_v6}, test14_np_name_v6),
			&npTestAugment{
				[]*v1.Endpoints{
					makeEps("testnsv6", "service1",
						[]v1.EndpointAddress{
							{
								IP: "2001::2",
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "testnsv6",
									Name:      "pod1",
								},
							},
						},
						[]v1.EndpointPort{
							endpointPort(v1.ProtocolTCP, 80, ""),
						}),
					makeEps("testnsv6", "service2",
						[]v1.EndpointAddress{
							{
								IP: "2002:2::2",
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "testnsv6",
									Name:      "pod2",
								},
							},
						},
						[]v1.EndpointPort{
							endpointPort(v1.ProtocolTCP, 80, ""),
						}),
					makeEps("testnsv6", "service3",
						[]v1.EndpointAddress{
							{
								IP: "2001::2",
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "testnsv6",
									Name:      "pod1",
								},
							},
							{
								IP: "2002:2::2",
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "testnsv6",
									Name:      "pod2",
								},
							},
						},
						[]v1.EndpointPort{
							endpointPort(v1.ProtocolTCP, 80, ""),
						}),
				},
				[]*v1.Service{
					npservice("testnsv6", "service1", "fd00::1234",
						[]v1.ServicePort{
							servicePort("", v1.ProtocolTCP, 8080, 80),
						}),
					npservice("testnsv6", "service2", "fd00::1235",
						[]v1.ServicePort{
							servicePort("", v1.ProtocolTCP, 8080, 80),
						}), // should not match (no matching IPs)
					npservice("testnsv6", "service3", "fd00::1236",
						[]v1.ServicePort{
							servicePort("", v1.ProtocolTCP, 8080, 80),
						}), // should not match (incomplete IPs)
				},
				[]*discovery.EndpointSlice{},
			}, "egress-allow-http-augment"},
		{test15_np_v6,
			makeNp(nil, apicapi.ApicSlice{test15_rule1_v6, test15_rule2_v6}, test15_np_name_v6),
			&npTestAugment{
				[]*v1.Endpoints{
					makeEps("testnsv6", "service1",
						[]v1.EndpointAddress{
							{
								IP: "2001::2",
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "testns",
									Name:      "pod1",
								},
							},
						},
						[]v1.EndpointPort{
							endpointPort(v1.ProtocolTCP, 80, ""),
						}),
					makeEps("testns", "service2",
						[]v1.EndpointAddress{
							{
								IP: "2002::2",
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "testns",
									Name:      "pod2",
								},
							},
						},
						[]v1.EndpointPort{
							endpointPort(v1.ProtocolTCP, 81, ""),
						}),
				},
				[]*v1.Service{
					npservice("testns", "service1", "fd00::1234",
						[]v1.ServicePort{
							servicePort("", v1.ProtocolTCP, 8080, 80),
						}),
					npservice("testns", "service2", "fd00::1239",
						[]v1.ServicePort{
							servicePort("", v1.ProtocolTCP, 8080, 81),
						}), // should not match (port wrong)
				},
				[]*discovery.EndpointSlice{},
			}, "egress-allow-http-all-augment"},
		{test16_np_v6,
			makeNp(nil,
				apicapi.ApicSlice{test16_rule1_v6, test16_rule2_v6, test16_rule3_v6}, test16_np_name_v6),
			&npTestAugment{
				[]*v1.Endpoints{
					makeEps("testnsv6", "service1",
						[]v1.EndpointAddress{
							{
								IP: "2001::4",
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "ns1",
									Name:      "pod3",
								},
							},
							{
								IP: "2001::5",
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "ns1",
									Name:      "pod4",
								},
							},
							{
								IP: "2001::6",
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "ns2",
									Name:      "pod5",
								},
							},
						},
						[]v1.EndpointPort{
							endpointPort(v1.ProtocolTCP, 80, "http"),
							endpointPort(v1.ProtocolTCP, 443, "https"),
						}),
				},
				[]*v1.Service{
					npservice("testnsv6", "service1", "fd00::1236",
						[]v1.ServicePort{
							servicePort("http", v1.ProtocolTCP, 8080, 80),
							servicePort("https", v1.ProtocolTCP, 8443, 443),
						}),
				},
				[]*discovery.EndpointSlice{},
			}, "egress-allow-subnet-augment"},
		{test17_np_v6,
			makeNp(nil, apicapi.ApicSlice{test17_rule_v6}, test17_np_name_v6),
			&npTestAugment{
				[]*v1.Endpoints{
					makeEps("testns", "service1",
						[]v1.EndpointAddress{
							{
								IP: "2001::2",
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "testns",
									Name:      "pod1",
								},
							},
						},
						[]v1.EndpointPort{
							endpointPort(v1.ProtocolTCP, 80, ""),
						}),
				},
				[]*v1.Service{
					npservice("testns", "service1", "fd00::1234",
						[]v1.ServicePort{
							servicePort("", v1.ProtocolTCP, 8080, 80),
						}),
				},
				[]*discovery.EndpointSlice{},
			}, "egress-allow-all-augment"},
	}

	initCont := func() *testAciController {
		cont := testController()
		cont.config.HppOptimization = true
		cont.config.AciPolicyTenant = "test-tenant"
		cont.config.NodeServiceIpPool = []ipam.IpRange{
			{Start: net.ParseIP("2002::2"), End: net.ParseIP("2002::3")},
		}
		cont.config.PodIpPool = []ipam.IpRange{
			{Start: net.ParseIP("2001::2"), End: net.ParseIP("2001::64")},
		}
		cont.AciController.initIpam()

		cont.fakeNamespaceSource.Add(namespaceLabel("testnsv6",
			map[string]string{"test": "testv"}))
		cont.fakeNamespaceSource.Add(namespaceLabel("ns1",
			map[string]string{"nl": "nv"}))
		cont.fakeNamespaceSource.Add(namespaceLabel("ns2",
			map[string]string{"nl": "nv"}))

		return cont
	}

	{
		cont := testController()
		cont.run()
		cont.config.HppOptimization = true
		static := cont.staticNetPolObjs()
		apicapi.PrepareApicSlice(static, "kube", staticNetPolKey())
		assert.Equal(t, static,
			cont.apicConn.GetDesiredState(staticNetPolKey()), staticNetPolKey())
		cont.stop()
	}

	ips := []string{
		"2001::2", "2001::3", "2001::4", "2001::5", "2001::6", "",
	}
	for ix := range np6Tests {
		cont := initCont()
		cont.log.Info("Starting podsfirst ", np6Tests[ix].desc)
		addPods(cont, true, ips, false)
		addServices(cont, np6Tests[ix].augment)
		cont.run()
		cont.fakeNetworkPolicySource.Add(np6Tests[ix].netPol)
		checkNp(t, &np6Tests[ix], "podsfirst", cont)

		cont.log.Info("Starting delete ", np6Tests[ix].desc)
		cont.fakeNetworkPolicySource.Delete(np6Tests[ix].netPol)
		checkDelete(t, np6Tests[0], cont)
		cont.stop()
	}

	for ix := range np6Tests {
		cont := initCont()
		cont.log.Info("Starting npfirst ", np6Tests[ix].desc)
		cont.fakeNetworkPolicySource.Add(np6Tests[ix].netPol)
		cont.run()
		addServices(cont, np6Tests[ix].augment)
		addPods(cont, false, ips, false)
		addPods(cont, true, ips, false)
		checkNp(t, &np6Tests[ix], "npfirst", cont)
		cont.stop()
	}
}

// Test with EndPointslices
func TestNetworkPolicyWithEndPointSlice(t *testing.T) {
	name := "kube_np_testns_np1"
	baseDn := makeNp(nil, nil, name).GetDn()
	np1SDnE := fmt.Sprintf("%s/subj-networkpolicy-egress", baseDn)

	rule_11_0 := apicapi.NewHostprotRule(np1SDnE, "0_0-ipv4__np1")
	rule_11_0.SetAttr("direction", "egress")
	rule_11_0.SetAttr("ethertype", "ipv4")
	rule_11_0.SetAttr("protocol", "tcp")
	rule_11_0.SetAttr("fromPort", "80")
	rule_11_0.AddChild(apicapi.NewHostprotRemoteIp(rule_11_0.GetDn(), "1.1.1.1"))

	rule_11_s := apicapi.NewHostprotRule(np1SDnE, "service_tcp_8080-ipv4")
	rule_11_s.SetAttr("direction", "egress")
	rule_11_s.SetAttr("ethertype", "ipv4")
	rule_11_s.SetAttr("protocol", "tcp")
	rule_11_s.SetAttr("fromPort", "8080")
	rule_11_s.AddChild(apicapi.NewHostprotRemoteIp(rule_11_s.GetDn(), "9.0.0.42"))

	rule_12_0 := apicapi.NewHostprotRule(np1SDnE, "0-ipv4__np1")
	rule_12_0.SetAttr("direction", "egress")
	rule_12_0.SetAttr("ethertype", "ipv4")
	rule_12_0.AddChild(apicapi.NewHostprotRemoteIp(rule_12_0.GetDn(),
		"1.1.1.0/24"))

	rule_12_s_0 := apicapi.NewHostprotRule(np1SDnE, "service_tcp_8080-ipv4")
	rule_12_s_0.SetAttr("direction", "egress")
	rule_12_s_0.SetAttr("ethertype", "ipv4")
	rule_12_s_0.SetAttr("protocol", "tcp")
	rule_12_s_0.SetAttr("fromPort", "8080")
	rule_12_s_0.AddChild(apicapi.NewHostprotRemoteIp(rule_12_s_0.GetDn(),
		"9.0.0.44"))

	rule_12_s_1 := apicapi.NewHostprotRule(np1SDnE, "service_tcp_8443-ipv4")
	rule_12_s_1.SetAttr("direction", "egress")
	rule_12_s_1.SetAttr("ethertype", "ipv4")
	rule_12_s_1.SetAttr("protocol", "tcp")
	rule_12_s_1.SetAttr("fromPort", "8443")
	rule_12_s_1.AddChild(apicapi.NewHostprotRemoteIp(rule_12_s_1.GetDn(),
		"9.0.0.44"))

	rule_13_0 := apicapi.NewHostprotRule(np1SDnE, "0-ipv4__np1")
	rule_13_0.SetAttr("direction", "egress")
	rule_13_0.SetAttr("ethertype", "ipv4")

	rule_14_0 := apicapi.NewHostprotRule(np1SDnE, "0_0-ipv4__np1")
	rule_14_0.SetAttr("direction", "egress")
	rule_14_0.SetAttr("ethertype", "ipv4")
	rule_14_0.SetAttr("protocol", "tcp")
	rule_14_0.SetAttr("fromPort", "80")

	rule_14_s := apicapi.NewHostprotRule(np1SDnE, "service_tcp_8080-ipv4")
	rule_14_s.SetAttr("direction", "egress")
	rule_14_s.SetAttr("ethertype", "ipv4")
	rule_14_s.SetAttr("protocol", "tcp")
	rule_14_s.SetAttr("fromPort", "8080")
	rule_14_s.AddChild(apicapi.NewHostprotRemoteIp(rule_14_s.GetDn(), "9.0.0.42"))

	var npTests = []npTest{
		{netpol("testns", "np1", &metav1.LabelSelector{},
			nil, []v1net.NetworkPolicyEgressRule{
				egressRule([]v1net.NetworkPolicyPort{port(&tcp, &port80)},
					[]v1net.NetworkPolicyPeer{
						peer(&metav1.LabelSelector{
							MatchLabels: map[string]string{"l1": "v1"},
						}, nil),
					}),
			}, allPolicyTypes),
			makeNp(nil, apicapi.ApicSlice{rule_11_0}, name),
			nil, "egress-allow-http-select-pods"},
		{netpol("testns", "np1", &metav1.LabelSelector{},
			nil, []v1net.NetworkPolicyEgressRule{
				egressRule([]v1net.NetworkPolicyPort{port(&tcp, &port80)},
					[]v1net.NetworkPolicyPeer{
						peer(&metav1.LabelSelector{
							MatchLabels: map[string]string{"l1": "v1"},
						}, nil),
					}),
			}, allPolicyTypes),
			makeNp(nil, apicapi.ApicSlice{rule_11_0, rule_11_s}, name),
			&npTestAugment{
				[]*v1.Endpoints{},
				[]*v1.Service{
					npservice("testns", "service1", "9.0.0.42",
						[]v1.ServicePort{
							servicePort("", v1.ProtocolTCP, 8080, 80),
						}),
					npservice("testns", "service2", "9.0.0.99",
						[]v1.ServicePort{
							servicePort("", v1.ProtocolTCP, 8080, 80),
						}), // should not match (no matching IPs)
					npservice("testns", "service3", "9.0.0.98",
						[]v1.ServicePort{
							servicePort("", v1.ProtocolTCP, 8080, 80),
						}), // should not match (incomplete IPs)
				},
				[]*discovery.EndpointSlice{
					makeEpSlice("testns", "service1xyz",
						[]discovery.Endpoint{
							{
								Addresses: []string{
									"1.1.1.1",
								},
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "testns",
									Name:      "pod1",
								},
							},
						}, []discovery.EndpointPort{
							endpointSlicePort(v1.ProtocolTCP, 80, ""),
						}, "service1"),
					makeEpSlice("testns", "service2xyz",
						[]discovery.Endpoint{
							{
								Addresses: []string{
									"2.2.2.2",
								},
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "testns",
									Name:      "pod2",
								},
							},
						}, []discovery.EndpointPort{
							endpointSlicePort(v1.ProtocolTCP, 80, ""),
						}, "service2"),
					makeEpSlice("testns", "service1xyz",
						[]discovery.Endpoint{
							{
								Addresses: []string{
									"1.1.1.1",
								},
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "testns",
									Name:      "pod1",
								},
							},
						}, []discovery.EndpointPort{
							endpointSlicePort(v1.ProtocolTCP, 80, ""),
						}, "service1"),
					makeEpSlice("testns", "service2xyz",
						[]discovery.Endpoint{
							{
								Addresses: []string{
									"2.2.2.2",
								},
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "testns",
									Name:      "pod2",
								},
							},
						}, []discovery.EndpointPort{
							endpointSlicePort(v1.ProtocolTCP, 80, ""),
						}, "service2"),
					makeEpSlice("testns", "service3xyz",
						[]discovery.Endpoint{
							{
								Addresses: []string{
									"1.1.1.1",
								},
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "testns",
									Name:      "pod1",
								},
							},
							{
								Addresses: []string{
									"2.2.2.2",
								},
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "testns",
									Name:      "pod2",
								},
							},
						}, []discovery.EndpointPort{
							endpointSlicePort(v1.ProtocolTCP, 80, ""),
						}, "service3"),
				},
			}, "egress-allow-http-augment"},
		{netpol("testns", "np1", &metav1.LabelSelector{},
			nil, []v1net.NetworkPolicyEgressRule{
				egressRule([]v1net.NetworkPolicyPort{
					{Protocol: func() *v1.Protocol { a := v1.ProtocolTCP; return &a }(),
						Port: &intstr.IntOrString{Type: intstr.String, StrVal: "serve-80"},
					},
				},
					[]v1net.NetworkPolicyPeer{
						peer(&metav1.LabelSelector{
							MatchLabels: map[string]string{"l1": "v1"},
						}, nil),
					}),
			}, allPolicyTypes),
			makeNp(nil, apicapi.ApicSlice{rule_11_0, rule_11_s}, name),
			&npTestAugment{
				[]*v1.Endpoints{},
				[]*v1.Service{
					npservice("testns", "service1", "9.0.0.42",
						[]v1.ServicePort{
							servicePort("", v1.ProtocolTCP, 8080, 80),
						}),
					npservice("testns", "service2", "9.0.0.99",
						[]v1.ServicePort{
							servicePort("", v1.ProtocolTCP, 8080, 80),
						}), // should not match (no matching IPs)
					npservice("testns", "service3", "9.0.0.98",
						[]v1.ServicePort{
							servicePort("", v1.ProtocolTCP, 8080, 80),
						}), // should not match (incomplete IPs)
				},
				[]*discovery.EndpointSlice{
					makeEpSlice("testns", "service1xyz",
						[]discovery.Endpoint{
							{
								Addresses: []string{
									"1.1.1.1",
								},
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "testns",
									Name:      "pod1",
								},
							},
						}, []discovery.EndpointPort{
							endpointSlicePort(v1.ProtocolTCP, 80, ""),
						}, "service1"),
					makeEpSlice("testns", "service2xyz",
						[]discovery.Endpoint{
							{
								Addresses: []string{
									"2.2.2.2",
								},
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "testns",
									Name:      "pod2",
								},
							},
						}, []discovery.EndpointPort{
							endpointSlicePort(v1.ProtocolTCP, 80, ""),
						}, "service2"),
				},
			}, "egress-allow-http-augment-namedport"},
		{netpol("testns", "np1", &metav1.LabelSelector{},
			nil, []v1net.NetworkPolicyEgressRule{
				egressRule([]v1net.NetworkPolicyPort{port(&tcp, &port80)},
					nil),
			}, allPolicyTypes),
			makeNp(nil, apicapi.ApicSlice{rule_14_0, rule_14_s}, name),
			&npTestAugment{
				[]*v1.Endpoints{},
				[]*v1.Service{
					npservice("testns", "service1", "9.0.0.42",
						[]v1.ServicePort{
							servicePort("", v1.ProtocolTCP, 8080, 80),
						}),
					npservice("testns", "service2", "9.0.0.99",
						[]v1.ServicePort{
							servicePort("", v1.ProtocolTCP, 8080, 81),
						}), // should not match (no matching IPs)
				},
				[]*discovery.EndpointSlice{
					makeEpSlice("testns", "service1xyz",
						[]discovery.Endpoint{
							{
								Addresses: []string{
									"1.1.1.1",
								},
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "testns",
									Name:      "pod1",
								},
							},
						}, []discovery.EndpointPort{
							endpointSlicePort(v1.ProtocolTCP, 80, ""),
						}, "service1"),
					makeEpSlice("testns", "service2xyz",
						[]discovery.Endpoint{
							{
								Addresses: []string{
									"2.2.2.2",
								},
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "testns",
									Name:      "pod2",
								},
							},
						}, []discovery.EndpointPort{
							endpointSlicePort(v1.ProtocolTCP, 81, ""),
						}, "service2"),
				},
			}, "egress-allow-http-all-augment"},
		{netpol("testns", "np1", &metav1.LabelSelector{},
			nil, []v1net.NetworkPolicyEgressRule{
				egressRule(nil,
					[]v1net.NetworkPolicyPeer{
						peerIpBlock(peer(nil, nil), "1.1.1.0/24", nil),
					}),
			}, allPolicyTypes),
			makeNp(nil,
				apicapi.ApicSlice{rule_12_0, rule_12_s_0, rule_12_s_1}, name),
			&npTestAugment{
				[]*v1.Endpoints{},
				[]*v1.Service{
					npservice("testns", "service1", "9.0.0.44",
						[]v1.ServicePort{
							servicePort("http", v1.ProtocolTCP, 8080, 80),
							servicePort("https", v1.ProtocolTCP, 8443, 443),
						}),
				},
				[]*discovery.EndpointSlice{
					makeEpSlice("testns", "service1xyz",
						[]discovery.Endpoint{
							{
								Addresses: []string{
									"1.1.1.3",
								},
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "ns1",
									Name:      "pod3",
								},
							},
							{
								Addresses: []string{
									"1.1.1.4",
								},
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "ns1",
									Name:      "pod4",
								},
							},
							{
								Addresses: []string{
									"1.1.1.5",
								},
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "ns2",
									Name:      "pod5",
								},
							},
						}, []discovery.EndpointPort{
							endpointSlicePort(v1.ProtocolTCP, 80, "http"),
							endpointSlicePort(v1.ProtocolTCP, 443, "https"),
						}, "service1"),
				},
			}, "egress-allow-subnet-augment"},

		{netpol("testns", "np1", &metav1.LabelSelector{},
			nil, []v1net.NetworkPolicyEgressRule{
				egressRule(nil, nil),
			}, allPolicyTypes),
			makeNp(nil, apicapi.ApicSlice{rule_13_0}, name),
			&npTestAugment{
				[]*v1.Endpoints{},
				[]*v1.Service{
					npservice("testns", "service1", "9.0.0.42",
						[]v1.ServicePort{
							servicePort("", v1.ProtocolTCP, 8080, 80),
						}),
				},
				[]*discovery.EndpointSlice{
					makeEpSlice("testns", "service1xyz",
						[]discovery.Endpoint{
							{
								Addresses: []string{
									"1.1.1.1",
								},
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "testns",
									Name:      "pod1",
								},
							},
						}, []discovery.EndpointPort{
							endpointSlicePort(v1.ProtocolTCP, 80, ""),
						}, "service1"),
				},
			}, "egress-allow-all-augment"},
	}
	initCont := func() *testAciController {
		cont := testController()
		cont.config.AciPolicyTenant = "test-tenant"
		cont.serviceEndPoints = &serviceEndpointSlice{}
		cont.serviceEndPoints.(*serviceEndpointSlice).cont = &cont.AciController
		cont.config.NodeServiceIpPool = []ipam.IpRange{
			{Start: net.ParseIP("10.1.1.2"), End: net.ParseIP("10.1.1.3")},
		}
		cont.config.PodIpPool = []ipam.IpRange{
			{Start: net.ParseIP("10.1.1.2"), End: net.ParseIP("10.1.255.254")},
		}
		cont.AciController.initIpam()

		cont.fakeNamespaceSource.Add(namespaceLabel("testns",
			map[string]string{"test": "testv"}))
		cont.fakeNamespaceSource.Add(namespaceLabel("ns1",
			map[string]string{"nl": "nv"}))
		cont.fakeNamespaceSource.Add(namespaceLabel("ns2",
			map[string]string{"nl": "nv"}))

		return cont
	}

	{
		cont := testController()
		cont.run()
		static := cont.staticNetPolObjs()
		apicapi.PrepareApicSlice(static, "kube", staticNetPolKey())
		assert.Equal(t, static,
			cont.apicConn.GetDesiredState(staticNetPolKey()), staticNetPolKey())
		cont.stop()
	}

	ips := []string{
		"1.1.1.1", "1.1.1.2", "1.1.1.3", "1.1.1.4", "1.1.1.5", "",
	}
	for ix := range npTests {
		cont := initCont()
		cont.log.Info("Starting podsfirst ", npTests[ix].desc)
		addPods(cont, true, ips, true)
		addServices(cont, npTests[ix].augment)
		cont.run()
		cont.fakeNetworkPolicySource.Add(npTests[ix].netPol)
		checkNp(t, &npTests[ix], "podsfirst", cont)

		cont.log.Info("Starting delete ", npTests[ix].desc)
		cont.fakeNetworkPolicySource.Delete(npTests[ix].netPol)
		checkDelete(t, npTests[0], cont)
		cont.stop()
	}
	for ix := range npTests {
		cont := initCont()
		cont.log.Info("Starting npfirst ", npTests[ix].desc)
		cont.fakeNetworkPolicySource.Add(npTests[ix].netPol)
		cont.run()
		addServices(cont, npTests[ix].augment)
		addPods(cont, false, ips, true)
		addPods(cont, true, ips, true)
		checkNp(t, &npTests[ix], "npfirst", cont)
		cont.stop()
	}
}

func TestNetworkPolicyWithEndPointSliceHppOptimize(t *testing.T) {
	rule_5 := map[string]string{"direction": "egress", "ethertype": "ipv4"}
	rule_6 := map[string]string{"direction": "egress", "ethertype": "ipv4",
		"protocol": "tcp", "fromPort": "80"}
	rule_7 := map[string]string{"direction": "egress", "ethertype": "ipv4",
		"protocol": "tcp", "fromPort": "8080"}
	rule_8 := map[string]string{"direction": "egress", "ethertype": "ipv4",
		"protocol": "tcp", "fromPort": "8443"}

	//egress-allow-http-select-pods
	test15_np := netpol("testns", "np1", &metav1.LabelSelector{},
		nil, []v1net.NetworkPolicyEgressRule{
			egressRule([]v1net.NetworkPolicyPort{port(&tcp, &port80)},
				[]v1net.NetworkPolicyPeer{
					peer(&metav1.LabelSelector{
						MatchLabels: map[string]string{"l1": "v1"},
					}, nil),
				}),
		}, allPolicyTypes)
	hash, _ := util.CreateHashFromNetPol(test15_np)
	test15_np_name := "kube_np_" + hash
	test15_rule := createRule(test15_np_name, false, rule_6, "0_0-ipv4__np1")
	test15_rule.AddChild(apicapi.NewHostprotRemoteIp(test15_rule.GetDn(), "1.1.1.1"))

	//egress-allow-http-augment
	test16_np := netpol("testns", "np1", &metav1.LabelSelector{},
		nil, []v1net.NetworkPolicyEgressRule{
			egressRule([]v1net.NetworkPolicyPort{port(&tcp, &port80)},
				[]v1net.NetworkPolicyPeer{
					peer(&metav1.LabelSelector{
						MatchLabels: map[string]string{"l1": "v1"},
					}, nil),
				}),
		}, allPolicyTypes)
	hash, _ = util.CreateHashFromNetPol(test16_np)
	test16_np_name := "kube_np_" + hash
	test16_rule1 := createRule(test16_np_name, false, rule_6, "0_0-ipv4__np1")
	test16_rule1.AddChild(apicapi.NewHostprotRemoteIp(test16_rule1.GetDn(), "1.1.1.1"))
	test16_rule2 := createRule(test16_np_name, false, rule_7, "service_tcp_8080-ipv4")
	test16_rule2.AddChild(apicapi.NewHostprotRemoteIp(test16_rule2.GetDn(), "9.0.0.42"))

	//egress-allow-http-augment-namedport
	test17_np := netpol("testns", "np1", &metav1.LabelSelector{},
		nil, []v1net.NetworkPolicyEgressRule{
			egressRule([]v1net.NetworkPolicyPort{
				{Protocol: func() *v1.Protocol { a := v1.ProtocolTCP; return &a }(),
					Port: &intstr.IntOrString{Type: intstr.String, StrVal: "serve-80"},
				},
			},
				[]v1net.NetworkPolicyPeer{
					peer(&metav1.LabelSelector{
						MatchLabels: map[string]string{"l1": "v1"},
					}, nil),
				}),
		}, allPolicyTypes)
	hash, _ = util.CreateHashFromNetPol(test17_np)
	test17_np_name := "kube_np_" + hash
	test17_rule1 := createRule(test17_np_name, false, rule_6, "0_0-ipv4__np1")
	test17_rule1.AddChild(apicapi.NewHostprotRemoteIp(test17_rule1.GetDn(), "1.1.1.1"))
	test17_rule2 := createRule(test17_np_name, false, rule_7, "service_tcp_8080-ipv4")
	test17_rule2.AddChild(apicapi.NewHostprotRemoteIp(test17_rule2.GetDn(), "9.0.0.42"))

	//egress-allow-http-all-augment
	test18_np := netpol("testns", "np1", &metav1.LabelSelector{},
		nil, []v1net.NetworkPolicyEgressRule{
			egressRule([]v1net.NetworkPolicyPort{port(&tcp, &port80)},
				nil),
		}, allPolicyTypes)
	hash, _ = util.CreateHashFromNetPol(test18_np)
	test18_np_name := "kube_np_" + hash
	test18_rule1 := createRule(test18_np_name, false, rule_6, "0_0-ipv4__np1")
	test18_rule2 := createRule(test18_np_name, false, rule_7, "service_tcp_8080-ipv4")
	test18_rule2.AddChild(apicapi.NewHostprotRemoteIp(test18_rule2.GetDn(), "9.0.0.42"))

	//egress-allow-subnet-augment
	test19_np := netpol("testns", "np1", &metav1.LabelSelector{},
		nil, []v1net.NetworkPolicyEgressRule{
			egressRule(nil,
				[]v1net.NetworkPolicyPeer{
					peerIpBlock(peer(nil, nil), "1.1.1.0/24", nil),
				}),
		}, allPolicyTypes)
	hash, _ = util.CreateHashFromNetPol(test19_np)
	test19_np_name := "kube_np_" + hash
	test19_rule1 := createRule(test19_np_name, false, rule_5, "0-ipv4__np1")
	test19_rule1.AddChild(apicapi.NewHostprotRemoteIp(test19_rule1.GetDn(), "1.1.1.0/24"))
	test19_rule2 := createRule(test19_np_name, false, rule_7, "service_tcp_8080-ipv4")
	test19_rule2.AddChild(apicapi.NewHostprotRemoteIp(test19_rule2.GetDn(), "9.0.0.44"))
	test19_rule3 := createRule(test19_np_name, false, rule_8, "service_tcp_8443-ipv4")
	test19_rule3.AddChild(apicapi.NewHostprotRemoteIp(test19_rule3.GetDn(), "9.0.0.44"))

	//egress-allow-all-augment
	test20_np := netpol("testns", "np1", &metav1.LabelSelector{},
		nil, []v1net.NetworkPolicyEgressRule{
			egressRule(nil, nil),
		}, allPolicyTypes)
	hash, _ = util.CreateHashFromNetPol(test20_np)
	test20_np_name := "kube_np_" + hash
	test20_rule := createRule(test20_np_name, false, rule_5, "0-ipv4__np1")

	var npTests = []npTest{
		{test15_np,
			makeNp(nil, apicapi.ApicSlice{test15_rule}, test15_np_name),
			nil, "egress-allow-http-select-pods"},
		{test16_np,
			makeNp(nil, apicapi.ApicSlice{test16_rule1, test16_rule2}, test16_np_name),
			&npTestAugment{
				[]*v1.Endpoints{},
				[]*v1.Service{
					npservice("testns", "service1", "9.0.0.42",
						[]v1.ServicePort{
							servicePort("", v1.ProtocolTCP, 8080, 80),
						}),
					npservice("testns", "service2", "9.0.0.99",
						[]v1.ServicePort{
							servicePort("", v1.ProtocolTCP, 8080, 80),
						}), // should not match (no matching IPs)
					npservice("testns", "service3", "9.0.0.98",
						[]v1.ServicePort{
							servicePort("", v1.ProtocolTCP, 8080, 80),
						}), // should not match (incomplete IPs)
				},
				[]*discovery.EndpointSlice{
					makeEpSlice("testns", "service1xyz",
						[]discovery.Endpoint{
							{
								Addresses: []string{
									"1.1.1.1",
								},
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "testns",
									Name:      "pod1",
								},
							},
						}, []discovery.EndpointPort{
							endpointSlicePort(v1.ProtocolTCP, 80, ""),
						}, "service1"),
					makeEpSlice("testns", "service2xyz",
						[]discovery.Endpoint{
							{
								Addresses: []string{
									"2.2.2.2",
								},
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "testns",
									Name:      "pod2",
								},
							},
						}, []discovery.EndpointPort{
							endpointSlicePort(v1.ProtocolTCP, 80, ""),
						}, "service2"),
					makeEpSlice("testns", "service3xyz",
						[]discovery.Endpoint{
							{
								Addresses: []string{
									"1.1.1.1",
								},
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "testns",
									Name:      "pod1",
								},
							},
							{
								Addresses: []string{
									"2.2.2.2",
								},
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "testns",
									Name:      "pod2",
								},
							},
						}, []discovery.EndpointPort{
							endpointSlicePort(v1.ProtocolTCP, 80, ""),
						}, "service3"),
				},
			}, "egress-allow-http-augment"},
		{test17_np,
			makeNp(nil, apicapi.ApicSlice{test17_rule1, test17_rule2}, test17_np_name),
			&npTestAugment{
				[]*v1.Endpoints{},
				[]*v1.Service{
					npservice("testns", "service1", "9.0.0.42",
						[]v1.ServicePort{
							servicePort("", v1.ProtocolTCP, 8080, 80),
						}),
					npservice("testns", "service2", "9.0.0.99",
						[]v1.ServicePort{
							servicePort("", v1.ProtocolTCP, 8080, 80),
						}), // should not match (no matching IPs)
					npservice("testns", "service3", "9.0.0.98",
						[]v1.ServicePort{
							servicePort("", v1.ProtocolTCP, 8080, 80),
						}), // should not match (incomplete IPs)
				},
				[]*discovery.EndpointSlice{
					makeEpSlice("testns", "service1xyz",
						[]discovery.Endpoint{
							{
								Addresses: []string{
									"1.1.1.1",
								},
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "testns",
									Name:      "pod1",
								},
							},
						}, []discovery.EndpointPort{
							endpointSlicePort(v1.ProtocolTCP, 80, ""),
						}, "service1"),
					makeEpSlice("testns", "service2xyz",
						[]discovery.Endpoint{
							{
								Addresses: []string{
									"2.2.2.2",
								},
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "testns",
									Name:      "pod2",
								},
							},
						}, []discovery.EndpointPort{
							endpointSlicePort(v1.ProtocolTCP, 80, ""),
						}, "service2"),
				},
			}, "egress-allow-http-augment-namedport"},
		{test18_np,
			makeNp(nil, apicapi.ApicSlice{test18_rule1, test18_rule2}, test18_np_name),
			&npTestAugment{
				[]*v1.Endpoints{},
				[]*v1.Service{
					npservice("testns", "service1", "9.0.0.42",
						[]v1.ServicePort{
							servicePort("", v1.ProtocolTCP, 8080, 80),
						}),
					npservice("testns", "service2", "9.0.0.99",
						[]v1.ServicePort{
							servicePort("", v1.ProtocolTCP, 8080, 81),
						}), // should not match (no matching IPs)
				},
				[]*discovery.EndpointSlice{
					makeEpSlice("testns", "service1xyz",
						[]discovery.Endpoint{
							{
								Addresses: []string{
									"1.1.1.1",
								},
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "testns",
									Name:      "pod1",
								},
							},
						}, []discovery.EndpointPort{
							endpointSlicePort(v1.ProtocolTCP, 80, ""),
						}, "service1"),
					makeEpSlice("testns", "service2xyz",
						[]discovery.Endpoint{
							{
								Addresses: []string{
									"2.2.2.2",
								},
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "testns",
									Name:      "pod2",
								},
							},
						}, []discovery.EndpointPort{
							endpointSlicePort(v1.ProtocolTCP, 81, ""),
						}, "service2"),
				},
			}, "egress-allow-http-all-augment"},
		{test19_np,
			makeNp(nil,
				apicapi.ApicSlice{test19_rule1, test19_rule2, test19_rule3}, test19_np_name),
			&npTestAugment{
				[]*v1.Endpoints{},
				[]*v1.Service{
					npservice("testns", "service1", "9.0.0.44",
						[]v1.ServicePort{
							servicePort("http", v1.ProtocolTCP, 8080, 80),
							servicePort("https", v1.ProtocolTCP, 8443, 443),
						}),
				},
				[]*discovery.EndpointSlice{
					makeEpSlice("testns", "service1xyz",
						[]discovery.Endpoint{
							{
								Addresses: []string{
									"1.1.1.3",
								},
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "ns1",
									Name:      "pod3",
								},
							},
							{
								Addresses: []string{
									"1.1.1.4",
								},
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "ns1",
									Name:      "pod4",
								},
							},
							{
								Addresses: []string{
									"1.1.1.5",
								},
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "ns2",
									Name:      "pod5",
								},
							},
						}, []discovery.EndpointPort{
							endpointSlicePort(v1.ProtocolTCP, 80, "http"),
							endpointSlicePort(v1.ProtocolTCP, 443, "https"),
						}, "service1"),
				},
			}, "egress-allow-subnet-augment"},

		{test20_np,
			makeNp(nil, apicapi.ApicSlice{test20_rule}, test20_np_name),
			&npTestAugment{
				[]*v1.Endpoints{},
				[]*v1.Service{
					npservice("testns", "service1", "9.0.0.42",
						[]v1.ServicePort{
							servicePort("", v1.ProtocolTCP, 8080, 80),
						}),
				},
				[]*discovery.EndpointSlice{
					makeEpSlice("testns", "service1xyz",
						[]discovery.Endpoint{
							{
								Addresses: []string{
									"1.1.1.1",
								},
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "testns",
									Name:      "pod1",
								},
							},
						}, []discovery.EndpointPort{
							endpointSlicePort(v1.ProtocolTCP, 80, ""),
						}, "service1"),
				},
			}, "egress-allow-all-augment"},
	}
	initCont := func() *testAciController {
		cont := testController()
		cont.config.HppOptimization = true
		cont.config.AciPolicyTenant = "test-tenant"
		cont.serviceEndPoints = &serviceEndpointSlice{}
		cont.serviceEndPoints.(*serviceEndpointSlice).cont = &cont.AciController
		cont.config.NodeServiceIpPool = []ipam.IpRange{
			{Start: net.ParseIP("10.1.1.2"), End: net.ParseIP("10.1.1.3")},
		}
		cont.config.PodIpPool = []ipam.IpRange{
			{Start: net.ParseIP("10.1.1.2"), End: net.ParseIP("10.1.255.254")},
		}
		cont.AciController.initIpam()

		cont.fakeNamespaceSource.Add(namespaceLabel("testns",
			map[string]string{"test": "testv"}))
		cont.fakeNamespaceSource.Add(namespaceLabel("ns1",
			map[string]string{"nl": "nv"}))
		cont.fakeNamespaceSource.Add(namespaceLabel("ns2",
			map[string]string{"nl": "nv"}))

		return cont
	}

	{
		cont := testController()
		cont.run()
		cont.config.HppOptimization = true
		static := cont.staticNetPolObjs()
		apicapi.PrepareApicSlice(static, "kube", staticNetPolKey())
		assert.Equal(t, static,
			cont.apicConn.GetDesiredState(staticNetPolKey()), staticNetPolKey())
		cont.stop()
	}

	ips := []string{
		"1.1.1.1", "1.1.1.2", "1.1.1.3", "1.1.1.4", "1.1.1.5", "",
	}
	for ix := range npTests {
		cont := initCont()
		cont.log.Info("Starting podsfirst ", npTests[ix].desc)
		addPods(cont, true, ips, true)
		addServices(cont, npTests[ix].augment)
		cont.run()
		cont.fakeNetworkPolicySource.Add(npTests[ix].netPol)
		checkNp(t, &npTests[ix], "podsfirst", cont)

		cont.log.Info("Starting delete ", npTests[ix].desc)
		cont.fakeNetworkPolicySource.Delete(npTests[ix].netPol)
		checkDelete(t, npTests[0], cont)
		cont.stop()
	}
	for ix := range npTests {
		cont := initCont()
		cont.log.Info("Starting npfirst ", npTests[ix].desc)
		cont.fakeNetworkPolicySource.Add(npTests[ix].netPol)
		cont.run()
		addServices(cont, npTests[ix].augment)
		addPods(cont, false, ips, true)
		addPods(cont, true, ips, true)
		checkNp(t, &npTests[ix], "npfirst", cont)
		cont.stop()
	}
}

/*
* 1. Create Pods with 2 diffrent containerPorts
* 2.  expose these pods to service1 and 2
*.3. create a wildcard network policy with  nameedport.
* 4. Check matching port is added to the NetworkPolicy
 */
func TestNetworkPolicyEgressNmPort(t *testing.T) {
	name := "kube_np_testns_np1"
	baseDn := makeNp(nil, nil, name).GetDn()
	np1SDnE := fmt.Sprintf("%s/subj-networkpolicy-egress", baseDn)

	rule_1_0 := apicapi.NewHostprotRule(np1SDnE, "0_0-ipv4__np1")
	rule_1_0.SetAttr("direction", "egress")
	rule_1_0.SetAttr("ethertype", "ipv4")
	rule_1_0.SetAttr("protocol", "tcp")
	rule_1_0.SetAttr("fromPort", "80")

	rule_1_s := apicapi.NewHostprotRule(np1SDnE, "service_tcp_8080-ipv4")
	rule_1_s.SetAttr("direction", "egress")
	rule_1_s.SetAttr("ethertype", "ipv4")
	rule_1_s.SetAttr("protocol", "tcp")
	rule_1_s.SetAttr("fromPort", "8080")
	rule_1_s.AddChild(apicapi.NewHostprotRemoteIp(rule_1_s.GetDn(), "9.0.0.42"))
	var npTests = []npTest{
		{netpol("testns", "np1", &metav1.LabelSelector{},
			nil, []v1net.NetworkPolicyEgressRule{
				egressRule([]v1net.NetworkPolicyPort{
					{Protocol: func() *v1.Protocol { a := v1.ProtocolTCP; return &a }(),
						Port: &intstr.IntOrString{Type: intstr.String, StrVal: "serve-80"},
					},
				}, nil),
			}, allPolicyTypes),
			makeNp(nil, apicapi.ApicSlice{rule_1_0, rule_1_s}, name),
			&npTestAugment{
				[]*v1.Endpoints{
					makeEps("testns", "service1",
						[]v1.EndpointAddress{
							{
								IP: "1.1.1.1",
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "testns",
									Name:      "pod1",
								},
							},
						},
						[]v1.EndpointPort{
							endpointPort(v1.ProtocolTCP, 80, ""),
						}),
					makeEps("testns", "service2",
						[]v1.EndpointAddress{
							{
								IP: "2.2.2.2",
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "testns",
									Name:      "pod2",
								},
							},
						},
						[]v1.EndpointPort{
							endpointPort(v1.ProtocolTCP, 81, ""),
						}),
				},
				[]*v1.Service{
					npservice("testns", "service1", "9.0.0.42",
						[]v1.ServicePort{
							servicePort("", v1.ProtocolTCP, 8080, 80),
						}),
					npservice("testns1", "service2", "9.0.0.99",
						[]v1.ServicePort{
							servicePort("", v1.ProtocolTCP, 8081, 81),
						}),
				},
				[]*discovery.EndpointSlice{},
			}, "egress-allow-http-all-augment-namedport-mathing-diffrent-ports"},
	}
	initCont := func() *testAciController {
		cont := testController()
		cont.config.AciPolicyTenant = "test-tenant"
		cont.config.NodeServiceIpPool = []ipam.IpRange{
			{Start: net.ParseIP("10.1.1.2"), End: net.ParseIP("10.1.1.3")},
		}
		cont.config.PodIpPool = []ipam.IpRange{
			{Start: net.ParseIP("10.1.1.2"), End: net.ParseIP("10.1.255.254")},
		}
		cont.AciController.initIpam()

		cont.fakeNamespaceSource.Add(namespaceLabel("testns",
			map[string]string{"test": "testv"}))
		return cont
	}

	{
		cont := testController()
		cont.run()
		static := cont.staticNetPolObjs()
		apicapi.PrepareApicSlice(static, "kube", staticNetPolKey())
		assert.Equal(t, static,
			cont.apicConn.GetDesiredState(staticNetPolKey()), staticNetPolKey())
		cont.stop()
	}

	ports := []v1.ContainerPort{
		{
			Name:          "serve-80",
			ContainerPort: int32(80),
		},
	}

	ports1 := []v1.ContainerPort{
		{
			Name:          "serve-81",
			ContainerPort: int32(81),
		},
	}
	addPod := func(cont *testAciController, namespace string,
		name string, labels map[string]string, ports []v1.ContainerPort) {
		pod := &v1.Pod{
			Spec: v1.PodSpec{
				NodeName: "test-node",
				Containers: []v1.Container{
					{
						Ports: ports,
					},
				},
			},
			ObjectMeta: metav1.ObjectMeta{
				Namespace: namespace,
				Name:      name,
				Labels:    labels,
			},
		}
		cont.fakePodSource.Add(pod)
	}
	for ix := range npTests {
		cont := initCont()
		cont.log.Info("Starting podsfirst ", npTests[ix].desc)
		addPod(cont, "testns", "pod1", map[string]string{"l1": "v1"}, ports)
		addPod(cont, "testns", "pod2", map[string]string{"l1": "v2"}, ports1)
		addServices(cont, npTests[ix].augment)
		cont.run()
		cont.fakeNetworkPolicySource.Add(npTests[ix].netPol)
		checkNp(t, &npTests[ix], "podsfirst", cont)
		cont.log.Info("Starting delete ", npTests[ix].desc)
		cont.fakeNetworkPolicySource.Delete(npTests[ix].netPol)
		checkDelete(t, npTests[0], cont)
		cont.stop()
	}
	for ix := range npTests {
		cont := initCont()
		cont.log.Info("Starting npfirst ", npTests[ix].desc)
		cont.fakeNetworkPolicySource.Add(npTests[ix].netPol)
		cont.run()
		addServices(cont, npTests[ix].augment)
		addPod(cont, "testns", "pod1", map[string]string{"l1": "v1"}, ports)
		addPod(cont, "testns", "pod2", map[string]string{"l1": "v2"}, ports1)
		checkNp(t, &npTests[ix], "npfirst", cont)
		cont.stop()
	}
}

func TestNetworkPolicyEgressNmPortHppOptimize(t *testing.T) {
	rule_1 := map[string]string{"direction": "egress", "ethertype": "ipv4",
		"protocol": "tcp", "fromPort": "80"}
	rule_2 := map[string]string{"direction": "egress", "ethertype": "ipv4",
		"protocol": "tcp", "fromPort": "8080"}

	//egress-allow-http-all-augment-namedport-mathing-diffrent-ports
	test1_np := netpol("testns", "np1", &metav1.LabelSelector{},
		nil, []v1net.NetworkPolicyEgressRule{
			egressRule([]v1net.NetworkPolicyPort{
				{Protocol: func() *v1.Protocol { a := v1.ProtocolTCP; return &a }(),
					Port: &intstr.IntOrString{Type: intstr.String, StrVal: "serve-80"},
				},
			}, nil),
		}, allPolicyTypes)
	hash, _ := util.CreateHashFromNetPol(test1_np)
	test1_np_name := "kube_np_" + hash
	test1_rule1 := createRule(test1_np_name, false, rule_1, "0_0-ipv4__np1")
	test1_rule2 := createRule(test1_np_name, false, rule_2, "service_tcp_8080-ipv4")
	test1_rule2.AddChild(apicapi.NewHostprotRemoteIp(test1_rule2.GetDn(), "9.0.0.42"))

	var npTests = []npTest{
		{test1_np,
			makeNp(nil, apicapi.ApicSlice{test1_rule1, test1_rule2}, test1_np_name),
			&npTestAugment{
				[]*v1.Endpoints{
					makeEps("testns", "service1",
						[]v1.EndpointAddress{
							{
								IP: "1.1.1.1",
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "testns",
									Name:      "pod1",
								},
							},
						},
						[]v1.EndpointPort{
							endpointPort(v1.ProtocolTCP, 80, ""),
						}),
					makeEps("testns", "service2",
						[]v1.EndpointAddress{
							{
								IP: "2.2.2.2",
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "testns",
									Name:      "pod2",
								},
							},
						},
						[]v1.EndpointPort{
							endpointPort(v1.ProtocolTCP, 81, ""),
						}),
				},
				[]*v1.Service{
					npservice("testns", "service1", "9.0.0.42",
						[]v1.ServicePort{
							servicePort("", v1.ProtocolTCP, 8080, 80),
						}),
					npservice("testns1", "service2", "9.0.0.99",
						[]v1.ServicePort{
							servicePort("", v1.ProtocolTCP, 8081, 81),
						}),
				},
				[]*discovery.EndpointSlice{},
			}, "egress-allow-http-all-augment-namedport-mathing-diffrent-ports"},
	}
	initCont := func() *testAciController {
		cont := testController()
		cont.config.HppOptimization = true
		cont.config.AciPolicyTenant = "test-tenant"
		cont.config.NodeServiceIpPool = []ipam.IpRange{
			{Start: net.ParseIP("10.1.1.2"), End: net.ParseIP("10.1.1.3")},
		}
		cont.config.PodIpPool = []ipam.IpRange{
			{Start: net.ParseIP("10.1.1.2"), End: net.ParseIP("10.1.255.254")},
		}
		cont.AciController.initIpam()

		cont.fakeNamespaceSource.Add(namespaceLabel("testns",
			map[string]string{"test": "testv"}))
		return cont
	}

	{
		cont := testController()
		cont.run()
		cont.config.HppOptimization = true
		static := cont.staticNetPolObjs()
		apicapi.PrepareApicSlice(static, "kube", staticNetPolKey())
		assert.Equal(t, static,
			cont.apicConn.GetDesiredState(staticNetPolKey()), staticNetPolKey())
		cont.stop()
	}

	ports := []v1.ContainerPort{
		{
			Name:          "serve-80",
			ContainerPort: int32(80),
		},
	}

	ports1 := []v1.ContainerPort{
		{
			Name:          "serve-81",
			ContainerPort: int32(81),
		},
	}
	addPod := func(cont *testAciController, namespace string,
		name string, labels map[string]string, ports []v1.ContainerPort) {
		pod := &v1.Pod{
			Spec: v1.PodSpec{
				NodeName: "test-node",
				Containers: []v1.Container{
					{
						Ports: ports,
					},
				},
			},
			ObjectMeta: metav1.ObjectMeta{
				Namespace: namespace,
				Name:      name,
				Labels:    labels,
			},
		}
		cont.fakePodSource.Add(pod)
	}
	for ix := range npTests {
		cont := initCont()
		cont.log.Info("Starting podsfirst ", npTests[ix].desc)
		addPod(cont, "testns", "pod1", map[string]string{"l1": "v1"}, ports)
		addPod(cont, "testns", "pod2", map[string]string{"l1": "v2"}, ports1)
		addServices(cont, npTests[ix].augment)
		cont.run()
		cont.fakeNetworkPolicySource.Add(npTests[ix].netPol)
		checkNp(t, &npTests[ix], "podsfirst", cont)
		cont.log.Info("Starting delete ", npTests[ix].desc)
		cont.fakeNetworkPolicySource.Delete(npTests[ix].netPol)
		checkDelete(t, npTests[0], cont)
		cont.stop()
	}
	for ix := range npTests {
		cont := initCont()
		cont.log.Info("Starting npfirst ", npTests[ix].desc)
		cont.fakeNetworkPolicySource.Add(npTests[ix].netPol)
		cont.run()
		addServices(cont, npTests[ix].augment)
		addPod(cont, "testns", "pod1", map[string]string{"l1": "v1"}, ports)
		addPod(cont, "testns", "pod2", map[string]string{"l1": "v2"}, ports1)
		checkNp(t, &npTests[ix], "npfirst", cont)
		cont.stop()
	}
}

func TestCreateStaticNetPolCrs(t *testing.T) {
	initCont := func() *testAciController {
		cont := testController()
		cont.config.AciPolicyTenant = "test-tenant"
		cont.config.NodeServiceIpPool = []ipam.IpRange{
			{Start: net.ParseIP("10.1.1.2"), End: net.ParseIP("10.1.1.3")},
		}
		cont.config.PodIpPool = []ipam.IpRange{
			{Start: net.ParseIP("10.1.1.2"), End: net.ParseIP("10.1.255.254")},
		}
		cont.AciController.initIpam()

		cont.fakeNamespaceSource.Add(namespaceLabel("testns",
			map[string]string{"test": "testv"}))
		return cont
	}

	cont := initCont()
	cont.run()
	defer cont.stop()

	ret := cont.createStaticNetPolCrs()

	assert.True(t, ret)
}

func TestInitStaticNetPolObjs(t *testing.T) {
	initCont := func() *testAciController {
		cont := testController()
		cont.config.EnableHppDirect = true
		cont.config.AciPolicyTenant = "test-tenant"
		cont.config.NodeServiceIpPool = []ipam.IpRange{
			{Start: net.ParseIP("10.1.1.2"), End: net.ParseIP("10.1.1.3")},
		}
		cont.config.PodIpPool = []ipam.IpRange{
			{Start: net.ParseIP("10.1.1.2"), End: net.ParseIP("10.1.255.254")},
		}
		cont.AciController.initIpam()

		cont.fakeNamespaceSource.Add(namespaceLabel("testns",
			map[string]string{"test": "testv"}))
		return cont
	}

	cont := initCont()
	cont.run()
	defer cont.stop()

	cont.initStaticNetPolObjs()

	cont.config.EnableHppDirect = false

	cont.initStaticNetPolObjs()
}

func TestQueueRemoteIpConUpdate(t *testing.T) {
	initCont := func() *testAciController {
		cont := testController()
		cont.config.EnableHppDirect = true
		cont.config.AciPolicyTenant = "test-tenant"
		cont.config.NodeServiceIpPool = []ipam.IpRange{
			{Start: net.ParseIP("10.1.1.2"), End: net.ParseIP("10.1.1.3")},
		}
		cont.config.PodIpPool = []ipam.IpRange{
			{Start: net.ParseIP("10.1.1.2"), End: net.ParseIP("10.1.255.254")},
		}
		cont.AciController.initIpam()

		cont.fakeNamespaceSource.Add(namespaceLabel("testns",
			map[string]string{"test": "testv"}))
		return cont
	}

	cont := initCont()
	cont.run()
	defer cont.stop()

	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "test-namespace",
			Name:      "test-pod",
		},
	}

	pod2 := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "test-namespace2",
			Name:      "test-pod2",
		},
	}

	cont.queueRemoteIpConUpdate(pod, false)
	assert.Equal(t, 1, cont.remIpContQueue.Len())

	cont.queueRemoteIpConUpdate(pod2, true)
	assert.Equal(t, 2, cont.remIpContQueue.Len())
}

func getContWithEnabledLocalHpp() *testAciController {
	cont := testController()
	cont.config.EnableHppDirect = true
	cont.config.AciPolicyTenant = "test-tenant"
	cont.config.NodeServiceIpPool = []ipam.IpRange{
		{Start: net.ParseIP("10.1.1.2"), End: net.ParseIP("10.1.1.3")},
	}
	cont.config.PodIpPool = []ipam.IpRange{
		{Start: net.ParseIP("10.1.1.2"), End: net.ParseIP("10.1.255.254")},
	}
	cont.AciController.initIpam()

	cont.fakeNamespaceSource.Add(namespaceLabel("testns",
		map[string]string{"test": "testv"}))

	cont.env.(*K8sEnvironment).hppClient = fake.NewSimpleClientset()
	return cont
}

func TestGetPeerRemoteSubnets(t *testing.T) {
	cont := getContWithEnabledLocalHpp()
	cont.run()
	defer cont.stop()

	// Define test data
	peers := []v1net.NetworkPolicyPeer{
		{
			PodSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": "web",
				},
			},
		},
	}
	namespace := "default"
	peerPods := []*v1.Pod{
		{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "default",
				Labels: map[string]string{
					"app": "web",
				},
			},
			Status: v1.PodStatus{
				PodIP: "192.168.0.1",
			},
		},
	}
	peerNs := map[string]*v1.Namespace{
		"default": {
			ObjectMeta: metav1.ObjectMeta{
				Name: "default",
			},
		},
	}
	logger := logrus.New().WithField("test", "getPeerRemoteSubnets")

	expectedPeerNsList := []string{"default"}
	expectedSubnetMap := map[string]bool{"192.168.0.1": true}
	expectedRemoteSubnets := []string{"192.168.0.1"}

	remoteSubnets, peerNsList, peerremote, subnetMap, _ := cont.getPeerRemoteSubnets(peers, namespace, peerPods, peerNs, logger)

	assert.Equal(t, expectedRemoteSubnets, remoteSubnets)
	assert.Equal(t, expectedPeerNsList, peerNsList)
	assert.Equal(t, expectedSubnetMap, subnetMap)
	assert.Equal(t, peerPods, peerremote.remotePods)
	assert.Equal(t, peers[0].PodSelector, peerremote.podSelectors[0])
}

func TestBuildLocalNetPolSubjRule(t *testing.T) {
	cont := getContWithEnabledLocalHpp()
	cont.run()
	defer cont.stop()

	testCases := []struct {
		name          string
		subj          *hppv1.HostprotSubj
		ruleName      string
		direction     string
		ethertype     string
		proto         string
		port          string
		remoteNs      []string
		podSelector   *metav1.LabelSelector
		remoteSubnets []string
		expectedRule  hppv1.HostprotRule
	}{
		{
			name:      "Test Case 1",
			subj:      &hppv1.HostprotSubj{},
			ruleName:  "rule1",
			direction: "ingress",
			ethertype: "ipv4",
			proto:     "tcp",
			port:      "80",
			remoteNs:  []string{"namespace1", "namespace2"},
			podSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": "web",
				},
			},
			expectedRule: hppv1.HostprotRule{
				ConnTrack:           "reflexive",
				Direction:           "ingress",
				Ethertype:           "ipv4",
				Protocol:            "tcp",
				ToPort:              "unspecified",
				FromPort:            "80",
				Name:                "rule1",
				RsRemoteIpContainer: []string{"namespace1", "namespace2"},
				HostprotFilterContainer: []hppv1.HostprotFilterContainer{
					{
						HostprotFilter: []hppv1.HostprotFilter{
							{
								Key: "app",
								Values: []string{
									"web",
								},
								Operator: "Equals",
							},
						},
					},
				},
			},
		},
		{
			name:      "Test Case 2",
			subj:      &hppv1.HostprotSubj{},
			ruleName:  "rule1",
			direction: "egress",
			ethertype: "ipv4",
			proto:     "tcp",
			port:      "80",
			remoteNs:  []string{"namespace1", "namespace2"},
			podSelector: &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{
						Key:      "app",
						Operator: metav1.LabelSelectorOpIn,
						Values:   []string{"web"},
					},
				},
			},
			remoteSubnets: []string{"10.0.0.0/24", "192.168.0.0/16"},
			expectedRule: hppv1.HostprotRule{
				ConnTrack: "reflexive",
				Direction: "egress",
				Ethertype: "ipv4",
				Protocol:  "tcp",
				FromPort:  "80",
				ToPort:    "unspecified",
				Name:      "rule1",
				HostprotRemoteIp: []hppv1.HostprotRemoteIp{
					{
						Addr: "10.0.0.0/24",
					},
					{
						Addr: "192.168.0.0/16",
					},
				},
				HostprotServiceRemoteIps: []string{"10.0.0.0/24", "192.168.0.0/16"},
				RsRemoteIpContainer:      []string{"namespace1", "namespace2"},
				HostprotFilterContainer: []hppv1.HostprotFilterContainer{
					{
						HostprotFilter: []hppv1.HostprotFilter{
							{
								Key: "app",
								Values: []string{
									"web",
								},
								Operator: "In",
							},
						},
					},
				},
			},
		},
		{
			name:          "Test Case 3",
			subj:          &hppv1.HostprotSubj{},
			ruleName:      "rule3",
			direction:     "egress",
			ethertype:     "ipv4",
			proto:         "tcp",
			port:          "80",
			remoteNs:      []string{"namespace1"},
			remoteSubnets: []string{},
			expectedRule: hppv1.HostprotRule{
				ConnTrack:           "reflexive",
				Direction:           "egress",
				Ethertype:           "ipv4",
				Protocol:            "tcp",
				FromPort:            "80",
				ToPort:              "unspecified",
				Name:                "rule3",
				RsRemoteIpContainer: []string{"namespace1"},
			},
		},
	}

	for _, tc := range testCases {
		var podSelectors []*metav1.LabelSelector
		if tc.podSelector != nil {
			podSelectors = []*metav1.LabelSelector{tc.podSelector}
		}
		t.Run(tc.name, func(t *testing.T) {
			cont.buildLocalNetPolSubjRule(tc.subj, tc.ruleName, tc.direction, tc.ethertype, tc.proto, tc.port, "", tc.remoteNs, podSelectors, tc.remoteSubnets)
			assert.Equal(t, tc.expectedRule, tc.subj.HostprotRule[0], "Unexpected rule. Expected: %v, Actual: %v", tc.expectedRule, tc.subj.HostprotRule[0])

		})
	}
}

func TestBuildLocalNetPolSubjRules(t *testing.T) {
	cont := getContWithEnabledLocalHpp()
	cont.run()
	defer cont.stop()

	np := &v1net.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-network-policy",
			Namespace: "test-namespace",
		},
		Spec: v1net.NetworkPolicySpec{
			Ingress: []v1net.NetworkPolicyIngressRule{
				{
					From: []v1net.NetworkPolicyPeer{
						{
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"app": "test-app",
								},
							},
						},
					},
					Ports: []v1net.NetworkPolicyPort{
						{
							Port: &intstr.IntOrString{
								Type:   intstr.Int,
								IntVal: 8080,
							},
						},
					},
				},
			},
		},
	}

	subj := &hppv1.HostprotSubj{}

	podSelectors := []*metav1.LabelSelector{
		np.Spec.Ingress[0].From[0].PodSelector,
	}
	cont.buildLocalNetPolSubjRules("test-rule", subj, "ingress", []string{"test-namespace"}, podSelectors, np.Spec.Ingress[0].Ports, nil, "", np, nil)

	assert.Equal(t, 1, len(subj.HostprotRule))
	assert.Equal(t, "test-rule_0-ipv4", subj.HostprotRule[0].Name)
	assert.Equal(t, "ingress", subj.HostprotRule[0].Direction)
	assert.Equal(t, "ipv4", subj.HostprotRule[0].Ethertype)
	assert.Equal(t, "tcp", subj.HostprotRule[0].Protocol)
	assert.Equal(t, "unspecified", subj.HostprotRule[0].ToPort)
	assert.Equal(t, "8080", subj.HostprotRule[0].FromPort)
	assert.Equal(t, []string{"test-namespace"}, subj.HostprotRule[0].RsRemoteIpContainer)

	np = &v1net.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-network-policy",
			Namespace: "test-namespace",
		},
		Spec: v1net.NetworkPolicySpec{
			Ingress: []v1net.NetworkPolicyIngressRule{
				{
					From: []v1net.NetworkPolicyPeer{
						{
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"app": "test-app",
								},
							},
						},
					},
					Ports: []v1net.NetworkPolicyPort{},
				},
			},
		},
	}

	subj = &hppv1.HostprotSubj{}

	podSelectors = []*metav1.LabelSelector{
		np.Spec.Ingress[0].From[0].PodSelector,
	}
	cont.buildLocalNetPolSubjRules("test-rule", subj, "ingress", []string{"test-namespace"}, podSelectors, np.Spec.Ingress[0].Ports, nil, "", np, nil)

	expected := hppv1.HostprotSubj{
		HostprotRule: []hppv1.HostprotRule{
			{
				ConnTrack:           "reflexive",
				Direction:           "ingress",
				Ethertype:           "ipv4",
				Protocol:            "unspecified",
				FromPort:            "unspecified",
				ToPort:              "unspecified",
				Name:                "test-rule-ipv4",
				RsRemoteIpContainer: []string{"test-namespace"},
				HostprotFilterContainer: []hppv1.HostprotFilterContainer{
					{
						HostprotFilter: []hppv1.HostprotFilter{
							{
								Key: "app",
								Values: []string{
									"test-app",
								},
								Operator: "Equals",
							},
						},
					},
				},
			},
		},
	}

	assert.Equal(t, expected, *subj)

	subj = &hppv1.HostprotSubj{}
	cont.buildLocalNetPolSubjRules("test-rule", subj, "ingress", []string{}, podSelectors, np.Spec.Ingress[0].Ports, nil, "", np, nil)

	expectedRule := []hppv1.HostprotRule{
		{
			ConnTrack:           "reflexive",
			Direction:           "ingress",
			Ethertype:           "ipv4",
			Protocol:            "unspecified",
			FromPort:            "unspecified",
			ToPort:              "unspecified",
			Name:                "test-rule-ipv4",
			RsRemoteIpContainer: []string{},
			HostprotFilterContainer: []hppv1.HostprotFilterContainer{
				{
					HostprotFilter: []hppv1.HostprotFilter{
						{
							Key: "app",
							Values: []string{
								"test-app",
							},
							Operator: "Equals",
						},
					},
				},
			},
		},
	}

	assert.Equal(t, expectedRule, subj.HostprotRule)

	np = &v1net.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-network-policy",
			Namespace: "test-namespace",
		},
		Spec: v1net.NetworkPolicySpec{
			Ingress: []v1net.NetworkPolicyIngressRule{
				{
					From: []v1net.NetworkPolicyPeer{
						{
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"app": "test-app",
								},
							},
						},
					},
					Ports: []v1net.NetworkPolicyPort{
						{
							Port: &intstr.IntOrString{
								Type:   intstr.Int,
								IntVal: 8080,
							},
						},
					},
				},
			},
		},
	}

	expectedRule = []hppv1.HostprotRule{
		{
			ConnTrack:           "reflexive",
			Direction:           "ingress",
			Ethertype:           "ipv4",
			Protocol:            "tcp",
			FromPort:            "8080",
			ToPort:              "unspecified",
			Name:                "test-rule_0-ipv4",
			RsRemoteIpContainer: []string{},
			HostprotFilterContainer: []hppv1.HostprotFilterContainer{
				{
					HostprotFilter: []hppv1.HostprotFilter{
						{
							Key: "app",
							Values: []string{
								"test-app",
							},
							Operator: "Equals",
						},
					},
				},
			},
		},
	}

	subj = &hppv1.HostprotSubj{}
	podSelectors = []*metav1.LabelSelector{
		np.Spec.Ingress[0].From[0].PodSelector,
	}
	cont.buildLocalNetPolSubjRules("test-rule", subj, "ingress", []string{}, podSelectors, np.Spec.Ingress[0].Ports, nil, "", np, nil)

	assert.Equal(t, expectedRule, subj.HostprotRule)

}

func TestBuildServiceAugment(t *testing.T) {
	cont := getContWithEnabledLocalHpp()
	cont.run()
	defer cont.stop()

	logger := logrus.New().WithField("test", "getContWithEnabledLocalHpp")

	t.Run("NoPortRemoteSubnets", func(t *testing.T) {
		subj := apicapi.ApicObject{}
		localsubj := &hppv1.HostprotSubj{}
		portRemoteSubs := make(map[string]*portRemoteSubnet)

		cont.buildServiceAugment(subj, localsubj, portRemoteSubs, logger)

		assert.Empty(t, subj)
		assert.Empty(t, localsubj)
	})

	t.Run("WithPortRemoteSubnets", func(t *testing.T) {
		subj := apicapi.ApicObject{}
		localsubj := &hppv1.HostprotSubj{
			HostprotRule: []hppv1.HostprotRule{
				{
					Name: "rule1",
				},
			},
		}
		portRemoteSubs := map[string]*portRemoteSubnet{
			"port1": {
				port: &v1net.NetworkPolicyPort{
					Port: &intstr.IntOrString{
						Type:   intstr.String,
						StrVal: "8080",
					},
				},
				subnetMap: map[string]bool{
					"0.0.0.0/0": true,
				},
				hasNamedTarget: false,
			},
		}

		portkey := portKey(portRemoteSubs["port1"].port)
		cont.targetPortIndex = make(map[string]*portIndexEntry)

		cont.targetPortIndex[portkey] = &portIndexEntry{
			port: targetPort{
				proto: "tcp",
				ports: map[int]bool{8080: true},
			},
		}

		cont.buildServiceAugment(subj, localsubj, portRemoteSubs, logger)

		expected := &hppv1.HostprotSubj{
			HostprotRule: []hppv1.HostprotRule{
				{
					Name: "rule1",
				},
			},
		}

		assert.Empty(t, subj)
		assert.Equal(t, expected, localsubj)
	})
}

func getHppObj() *hppv1.HostprotPol {
	hpp := hppv1.HostprotPol{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-hostprot-pol",
			Namespace: "test-namespace",
		},
		Spec: hppv1.HostprotPolSpec{
			Name: "test-hostprot-pol",
			HostprotSubj: []hppv1.HostprotSubj{
				{
					Name: "test-subject",
				},
			},
		},
	}

	return &hpp
}

func TestCreateHostprotPol(t *testing.T) {
	cont := getContWithEnabledLocalHpp()
	cont.run()
	defer cont.stop()

	hpp := getHppObj()

	ret := cont.createHostprotPol(hpp, "test-namespace")
	assert.True(t, ret)

	cont.env.(*K8sEnvironment).hppClient = nil

	ret = cont.createHostprotPol(hpp, "test-namespace")
	assert.False(t, ret)
}

func TestUpdateHostprotPol(t *testing.T) {
	cont := getContWithEnabledLocalHpp()
	cont.run()
	defer cont.stop()

	hpp := getHppObj()

	ret := cont.createHostprotPol(hpp, "test-namespace")
	assert.True(t, ret)

	ret = cont.updateHostprotPol(hpp, "test-namespace")
	assert.True(t, ret)

	cont.env.(*K8sEnvironment).hppClient = nil

	ret = cont.updateHostprotPol(hpp, "test-namespace")
	assert.False(t, ret)
}

func TestDeleteHostprotPol(t *testing.T) {
	cont := getContWithEnabledLocalHpp()
	cont.run()
	defer cont.stop()

	hpp := getHppObj()

	ret := cont.createHostprotPol(hpp, "test-namespace")
	assert.True(t, ret)

	ret = cont.deleteHostprotPol(hpp.Name, "test-namespace")
	assert.True(t, ret)

	cont.env.(*K8sEnvironment).hppClient = nil

	ret = cont.deleteHostprotPol(hpp.Name, "test-namespace")
	assert.False(t, ret)
}

func TestGetHostprotPol(t *testing.T) {
	cont := getContWithEnabledLocalHpp()
	cont.run()
	defer cont.stop()

	hpp := getHppObj()

	ret := cont.createHostprotPol(hpp, "test-namespace")
	assert.True(t, ret)

	retHpp, err := cont.getHostprotPol(hpp.Name, "test-namespace")
	assert.NoError(t, err)
	assert.Equal(t, *hpp, *retHpp)

	cont.env.(*K8sEnvironment).hppClient = nil

	retHpp, err = cont.getHostprotPol(hpp.Name, "test-namespace")
	assert.Error(t, err)
	assert.Nil(t, retHpp)
}

func getRemoteIPContainer() *hppv1.HostprotRemoteIpContainer {
	remoteIpContainer := &hppv1.HostprotRemoteIpContainer{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-remote-ip-container",
			Namespace: "test-namespace",
		},
		Spec: hppv1.HostprotRemoteIpContainerSpec{
			Name: "test-remote-ip-container",
			HostprotRemoteIp: []hppv1.HostprotRemoteIp{
				{
					Addr: "192.168.52.5",
					HppEpLabel: []hppv1.HppEpLabel{
						{
							Key:   "app",
							Value: "web",
						},
					},
				},
			},
		},
	}

	return remoteIpContainer
}

func TestGetHostprotRemoteIpContainer(t *testing.T) {
	cont := getContWithEnabledLocalHpp()
	cont.run()
	defer cont.stop()

	remoteIpContainer := getRemoteIPContainer()

	ret := cont.createHostprotRemoteIpContainer(remoteIpContainer, "test-namespace")
	assert.True(t, ret)

	retRemoteIpContainer, err := cont.getHostprotRemoteIpContainer(remoteIpContainer.Name, "test-namespace")
	assert.NoError(t, err)
	assert.Equal(t, remoteIpContainer, retRemoteIpContainer)

	cont.env.(*K8sEnvironment).hppClient = nil

	retRemoteIpContainer, err = cont.getHostprotRemoteIpContainer(remoteIpContainer.Name, "test-namespace")
	assert.Error(t, err)
	assert.Nil(t, retRemoteIpContainer)
}

func TestCreateHostprotRemoteIpContainer(t *testing.T) {
	cont := getContWithEnabledLocalHpp()
	cont.run()
	defer cont.stop()

	remoteIpContainer := getRemoteIPContainer()

	ret := cont.createHostprotRemoteIpContainer(remoteIpContainer, "test-namespace")
	assert.True(t, ret)

	cont.env.(*K8sEnvironment).hppClient = nil

	ret = cont.createHostprotRemoteIpContainer(remoteIpContainer, "test-namespace")
	assert.False(t, ret)
}

func TestUpdateHostprotRemoteIpContainer(t *testing.T) {
	cont := getContWithEnabledLocalHpp()
	cont.run()
	defer cont.stop()

	remoteIpContainer := getRemoteIPContainer()

	ret := cont.createHostprotRemoteIpContainer(remoteIpContainer, "test-namespace")
	assert.True(t, ret)

	remoteIpContainer.Spec.HostprotRemoteIp[0].Addr = "192.168.52.7"

	ret = cont.updateHostprotRemoteIpContainer(remoteIpContainer, "test-namespace")
	assert.True(t, ret)

	cont.env.(*K8sEnvironment).hppClient = nil

	ret = cont.updateHostprotRemoteIpContainer(remoteIpContainer, "test-namespace")
	assert.False(t, ret)
}

func TestDeleteHostprotRemoteIpContainer(t *testing.T) {
	cont := getContWithEnabledLocalHpp()
	cont.run()
	defer cont.stop()

	remoteIpContainer := getRemoteIPContainer()

	ret := cont.createHostprotRemoteIpContainer(remoteIpContainer, "test-namespace")
	assert.True(t, ret)

	ret = cont.deleteHostprotRemoteIpContainer(remoteIpContainer.Name, "test-namespace")
	assert.True(t, ret)

	cont.env.(*K8sEnvironment).hppClient = nil

	ret = cont.deleteHostprotRemoteIpContainer(remoteIpContainer.Name, "test-namespace")
	assert.False(t, ret)
}

func TestHandleRemIpContUpdate(t *testing.T) {
	cont := getContWithEnabledLocalHpp()
	cont.run()
	defer cont.stop()

	cont.nsRemoteIpCont["test-namespace"] = remoteIpConts{
		"test-pod": {
			"192.168.10.5": {
				"app": "db",
			},
		},
	}

	requeue := cont.handleRemIpContUpdate("test-namespace")

	assert.False(t, requeue)
}

func TestDeleteHppCr(t *testing.T) {
	cont := getContWithEnabledLocalHpp()
	cont.run()
	defer cont.stop()

	hpp := getHppObj()

	hpp.Name = "kube-np-b3d7dff81d4e6d95f9644c097105bd5a"
	hpp.Spec.NetworkPolicies = []string{"test-hostprot-pol"}

	ret := cont.createHostprotPol(hpp, "test-namespace")
	assert.True(t, ret)
	_, err := cont.getHostprotPol(hpp.Name, "test-namespace")
	assert.NoError(t, err)

	np := &v1net.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kube-np-b3d7dff81d4e6d95f9644c097105bd5a",
			Namespace: "test-namespace",
		},
		Spec: v1net.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": "test-app",
				},
			},
			Ingress: []v1net.NetworkPolicyIngressRule{
				{
					Ports: []v1net.NetworkPolicyPort{
						{
							Port: &intstr.IntOrString{
								Type:   intstr.Int,
								IntVal: 8080,
							},
						},
					},
				},
			},
		},
	}
	ret = cont.deleteHppCr(np)
	assert.False(t, ret)

	os.Setenv("SYSTEM_NAMESPACE", "test-namespace")

	ret = cont.deleteHppCr(np)
	assert.True(t, ret)

	hpp.Spec.NetworkPolicies = []string{}

	ret = cont.updateHostprotPol(hpp, "test-namespace")
	assert.True(t, ret)

	ret = cont.deleteHppCr(np)
	assert.True(t, ret)

	cont.env.(*K8sEnvironment).hppClient = nil

	ret = cont.deleteHppCr(np)
	assert.False(t, ret)
}

func TestUpdateDeleteNodeIpsHostprotRemoteIpContainer(t *testing.T) {
	cont := getContWithEnabledLocalHpp()
	cont.run()
	defer cont.stop()

	nodeIps := map[string]bool{
		"192.168.10.45": true,
	}

	os.Setenv("SYSTEM_NAMESPACE", "kube-system")

	cont.updateNodeIpsHostprotRemoteIpContainer(nodeIps)

	remoteIpContainer, err := cont.getHostprotRemoteIpContainer("nodeips", "kube-system")

	assert.NoError(t, err)
	assert.Equal(t, "nodeips", remoteIpContainer.Name)
	assert.Equal(t, "kube-system", remoteIpContainer.Namespace)
	assert.Equal(t, 1, len(remoteIpContainer.Spec.HostprotRemoteIp))
	assert.Equal(t, "192.168.10.45", remoteIpContainer.Spec.HostprotRemoteIp[0].Addr)

	nodeIps = map[string]bool{
		"192.168.10.45": true,
		"192.168.10.77": true,
	}

	cont.updateNodeIpsHostprotRemoteIpContainer(nodeIps)

	remoteIpContainer, err = cont.getHostprotRemoteIpContainer("nodeips", "kube-system")

	assert.NoError(t, err)
	assert.Equal(t, "192.168.10.45", remoteIpContainer.Spec.HostprotRemoteIp[0].Addr)
	assert.Equal(t, "192.168.10.77", remoteIpContainer.Spec.HostprotRemoteIp[1].Addr)
	assert.Equal(t, 2, len(remoteIpContainer.Spec.HostprotRemoteIp))

	nodeIps = map[string]bool{
		"192.168.10.45": true,
	}

	cont.deleteNodeIpsHostprotRemoteIpContainer(nodeIps)

	remoteIpContainer, err = cont.getHostprotRemoteIpContainer("nodeips", "kube-system")

	assert.NoError(t, err)
	assert.Equal(t, "192.168.10.77", remoteIpContainer.Spec.HostprotRemoteIp[0].Addr)
	assert.Equal(t, 1, len(remoteIpContainer.Spec.HostprotRemoteIp))

	nodeIps = map[string]bool{
		"192.168.10.77": true,
	}

	cont.deleteNodeIpsHostprotRemoteIpContainer(nodeIps)

	_, err = cont.getHostprotRemoteIpContainer("nodeips", "kube-system")

	assert.Error(t, err)
}

func TestUpdateDeleteNodeHostprotRemoteIpContainer(t *testing.T) {
	cont := getContWithEnabledLocalHpp()
	cont.run()
	defer cont.stop()

	nodeIps := map[string]bool{
		"192.168.10.45": true,
	}

	os.Setenv("SYSTEM_NAMESPACE", "kube-system")

	cont.updateNodeHostprotRemoteIpContainer("test-node", nodeIps)

	remoteIpContainer, err := cont.getHostprotRemoteIpContainer("test-node", "kube-system")

	assert.NoError(t, err)
	assert.Equal(t, "test-node", remoteIpContainer.Name)
	assert.Equal(t, "kube-system", remoteIpContainer.Namespace)
	assert.Equal(t, 1, len(remoteIpContainer.Spec.HostprotRemoteIp))
	assert.Equal(t, "192.168.10.45", remoteIpContainer.Spec.HostprotRemoteIp[0].Addr)

	nodeIps = map[string]bool{
		"192.168.10.105": true,
	}

	cont.updateNodeHostprotRemoteIpContainer("test-node", nodeIps)

	remoteIpContainer, err = cont.getHostprotRemoteIpContainer("test-node", "kube-system")

	assert.NoError(t, err)
	assert.Equal(t, "test-node", remoteIpContainer.Name)
	assert.Equal(t, "kube-system", remoteIpContainer.Namespace)
	assert.Equal(t, 1, len(remoteIpContainer.Spec.HostprotRemoteIp))
	assert.Equal(t, "192.168.10.105", remoteIpContainer.Spec.HostprotRemoteIp[0].Addr)

	cont.deleteNodeHostprotRemoteIpContainer("test-node")

	_, err = cont.getHostprotRemoteIpContainer("test-node", "kube-system")

	assert.Error(t, err)
}

func TestCreateNodeHostProtPol(t *testing.T) {
	cont := getContWithEnabledLocalHpp()
	cont.run()
	defer cont.stop()

	os.Setenv("SYSTEM_NAMESPACE", "kube-system")

	name := "ten_test_node"
	hppName := "ten-test-node"
	nodeName := "test-node"
	ns := os.Getenv("SYSTEM_NAMESPACE")

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

	nodeIps := map[string]bool{
		"192.168.10.105": true,
	}

	ret := cont.createHostprotPol(hpp, ns)
	assert.True(t, ret)

	cont.createNodeHostProtPol(name, nodeName, nodeIps)

	remoteIpContainer, err := cont.getHostprotRemoteIpContainer(nodeName, ns)

	assert.NoError(t, err)
	assert.Equal(t, nodeName, remoteIpContainer.Name)
	assert.Equal(t, ns, remoteIpContainer.Namespace)
	assert.Equal(t, 1, len(remoteIpContainer.Spec.HostprotRemoteIp))
	assert.Equal(t, "192.168.10.105", remoteIpContainer.Spec.HostprotRemoteIp[0].Addr)

	remoteIpContainer, err = cont.getHostprotRemoteIpContainer("nodeips", ns)

	assert.NoError(t, err)
	assert.Equal(t, "nodeips", remoteIpContainer.Name)
	assert.Equal(t, ns, remoteIpContainer.Namespace)
	assert.Equal(t, 1, len(remoteIpContainer.Spec.HostprotRemoteIp))
	assert.Equal(t, "192.168.10.105", remoteIpContainer.Spec.HostprotRemoteIp[0].Addr)

	hpp, err = cont.getHostprotPol(hppName, ns)

	assert.NoError(t, err)
	assert.Equal(t, 1, len(hpp.Spec.HostprotSubj))
	assert.Equal(t, 2, len(hpp.Spec.HostprotSubj[0].HostprotRule))

	cont.createNodeHostProtPol(name, nodeName, map[string]bool{})

	_, err = cont.getHostprotRemoteIpContainer(nodeName, ns)

	assert.Error(t, err)

	_, err = cont.getHostprotRemoteIpContainer("nodeips", ns)

	assert.Error(t, err)

	hpp, err = cont.getHostprotPol(hppName, ns)

	assert.NoError(t, err)
	assert.Equal(t, 0, len(hpp.Spec.HostprotSubj))
}

func TestHandleNetPolUpdate(t *testing.T) {
	cont := getContWithEnabledLocalHpp()
	cont.run()
	defer cont.stop()

	os.Setenv("SYSTEM_NAMESPACE", "test-namespace")

	np := &v1net.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-network-policy",
			Namespace: "test-namespace",
		},
		Spec: v1net.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": "test-app",
				},
			},
			Ingress: []v1net.NetworkPolicyIngressRule{
				{
					Ports: []v1net.NetworkPolicyPort{
						{
							Port: &intstr.IntOrString{
								Type:   intstr.Int,
								IntVal: 8080,
							},
						},
					},
				},
			},
			Egress: []v1net.NetworkPolicyEgressRule{
				{
					Ports: []v1net.NetworkPolicyPort{
						{
							Port: &intstr.IntOrString{
								Type:   intstr.Int,
								IntVal: 8080,
							},
						},
					},
				},
			},
		},
	}

	cont.handleNetPolUpdate(np)
	hash, _ := util.CreateHashFromNetPol(np)
	labelKey := cont.aciNameForKey("np", hash)
	hppName := strings.ReplaceAll(labelKey, "_", "-")

	hpp, err := cont.getHostprotPol(hppName, np.Namespace)

	assert.NoError(t, err)
	assert.Equal(t, 2, len(hpp.Spec.HostprotSubj))
	assert.Equal(t, 1, len(hpp.Spec.HostprotSubj[0].HostprotRule))

	npkey, _ := cache.MetaNamespaceKeyFunc(np)
	label_key, ref := cont.removeFromHppCache(np, npkey)

	assert.Equal(t, labelKey, label_key)
	assert.True(t, ref)
}

// TestNetworkPolicyEgressMultipleNamedPortsUniqueRuleNames tests that when a
// network policy has multiple named ports in the same egress rule, each port
// generates unique hostprotRule names (testing the ruleCounter fix).
// This tests the fix for the bug where multiple named ports in the same egress
// rule would generate duplicate rule names when the first named port resolves
// to multiple target ports.
func TestNetworkPolicyEgressMultipleNamedPortsUniqueRuleNames(t *testing.T) {
	// NetworkPolicy with multiple named ports in the same egress rule
	test_np := netpol("testns", "np1", &metav1.LabelSelector{},
		nil, []v1net.NetworkPolicyEgressRule{
			egressRule([]v1net.NetworkPolicyPort{
				{Protocol: func() *v1.Protocol { a := v1.ProtocolTCP; return &a }(),
					Port: &intstr.IntOrString{Type: intstr.String, StrVal: "http"},
				},
				{Protocol: func() *v1.Protocol { a := v1.ProtocolTCP; return &a }(),
					Port: &intstr.IntOrString{Type: intstr.String, StrVal: "https"},
				},
			}, nil),
		}, allPolicyTypes)

	initCont := func() *testAciController {
		cont := testController()
		cont.config.AciPolicyTenant = "test-tenant"
		cont.config.NodeServiceIpPool = []ipam.IpRange{
			{Start: net.ParseIP("10.1.1.2"), End: net.ParseIP("10.1.1.3")},
		}
		cont.config.PodIpPool = []ipam.IpRange{
			{Start: net.ParseIP("10.1.1.2"), End: net.ParseIP("10.1.255.254")},
		}
		cont.AciController.initIpam()
		cont.fakeNamespaceSource.Add(namespaceLabel("testns",
			map[string]string{"test": "testv"}))
		return cont
	}

	// Pod1 with http (80) and https (443) container ports
	ports1 := []v1.ContainerPort{
		{Name: "http", ContainerPort: int32(80)},
		{Name: "https", ContainerPort: int32(443)},
	}

	// Pod2 with http on different port (8080) to trigger multiple port resolution
	ports2 := []v1.ContainerPort{
		{Name: "http", ContainerPort: int32(8080)},
	}

	addPod := func(cont *testAciController, namespace string,
		name string, labels map[string]string, ports []v1.ContainerPort) {
		pod := &v1.Pod{
			Spec: v1.PodSpec{
				NodeName: "test-node",
				Containers: []v1.Container{
					{
						Ports: ports,
					},
				},
			},
			ObjectMeta: metav1.ObjectMeta{
				Namespace: namespace,
				Name:      name,
				Labels:    labels,
			},
		}
		cont.fakePodSource.Add(pod)
	}

	service := npservice("testns", "service1", "9.0.0.42",
		[]v1.ServicePort{
			servicePort("http", v1.ProtocolTCP, 9080, 80),
			servicePort("https", v1.ProtocolTCP, 9443, 443),
		})

	epSlice := makeEpSlice("testns", "service1-slice",
		[]discovery.Endpoint{
			{
				Addresses: []string{"1.1.1.1"},
				TargetRef: &v1.ObjectReference{
					Kind:      "Pod",
					Namespace: "testns",
					Name:      "pod1",
				},
			},
			{
				Addresses: []string{"2.2.2.2"},
				TargetRef: &v1.ObjectReference{
					Kind:      "Pod",
					Namespace: "testns",
					Name:      "pod2",
				},
			},
		},
		[]discovery.EndpointPort{
			endpointSlicePort(v1.ProtocolTCP, 80, "http"),
			endpointSlicePort(v1.ProtocolTCP, 443, "https"),
		},
		"service1")

	cont := initCont()
	// Add two pods: one with http=80, another with http=8080
	// This makes the "http" named port resolve to multiple target ports
	addPod(cont, "testns", "pod1", map[string]string{"l1": "v1"}, ports1)
	addPod(cont, "testns", "pod2", map[string]string{"l1": "v1"}, ports2)
	cont.fakeServiceSource.Add(service)
	cont.fakeEndpointSliceSource.Add(epSlice)
	cont.run()
	cont.fakeNetworkPolicySource.Add(test_np)

	tu.WaitFor(t, "network-policy", 500*time.Millisecond,
		func(last bool) (bool, error) {
			key := cont.aciNameForKey("np", test_np.Namespace+"_"+test_np.Name)
			slice := cont.apicConn.GetDesiredState(key)

			if len(slice) == 0 {
				if last {
					t.Error("No network policy object found")
				}
				return false, nil
			}

			// Get egress rules from the policy
			obj := slice[0]
			hppPol, ok := obj["hostprotPol"]
			if !ok {
				if last {
					t.Error("No hostprotPol found in object")
				}
				return false, nil
			}

			var egressSubj *apicapi.ApicObjectBody
			for _, child := range hppPol.Children {
				if subj, ok := child["hostprotSubj"]; ok {
					if name, ok := subj.Attributes["name"].(string); ok && name == "networkpolicy-egress" {
						egressSubj = subj
						break
					}
				}
			}

			if egressSubj == nil {
				if last {
					t.Error("No egress subject found")
				}
				return false, nil
			}

			// Collect all rule names to check for duplicates
			ruleNames := make(map[string]bool)
			var duplicateFound bool

			for _, rule := range egressSubj.Children {
				if ruleObj, ok := rule["hostprotRule"]; ok {
					if ruleName, ok := ruleObj.Attributes["name"].(string); ok {
						if ruleNames[ruleName] {
							t.Errorf("Duplicate rule name found: %s", ruleName)
							duplicateFound = true
						}
						ruleNames[ruleName] = true
					}
				}
			}

			// We expect at least 5 rules:
			// - 3 for the named port targets (80, 8080, 443)
			// - 2 for service augmentation (9080, 9443)
			if len(ruleNames) < 5 {
				if last {
					t.Errorf("Expected at least 5 unique rules, got %d: %v", len(ruleNames), ruleNames)
				}
				return false, nil
			}

			if duplicateFound {
				return false, fmt.Errorf("duplicate rule names found")
			}

			return true, nil
		})

	cont.log.Info("Starting delete")
	cont.fakeNetworkPolicySource.Delete(test_np)
	checkDelete(t, npTest{netPol: test_np}, cont)
	cont.stop()
}

// TestNamedPortServiceIndexBasic verifies `namedPortServiceIndex` behavior
// for services with named target ports. It validates that:
// 1. Adding a service with named ports populates `namedPortServiceIndex`.
// 2. Deleting the service removes its entries from `namedPortServiceIndex`.
func TestNamedPortServiceIndexBasic(t *testing.T) {
	cont := testController()
	cont.config.AciPolicyTenant = "test-tenant"
	cont.config.NodeServiceIpPool = []ipam.IpRange{
		{Start: net.ParseIP("10.1.1.2"), End: net.ParseIP("10.1.1.3")},
	}
	cont.config.PodIpPool = []ipam.IpRange{
		{Start: net.ParseIP("10.1.1.2"), End: net.ParseIP("10.1.255.254")},
	}
	cont.AciController.initIpam()

	// Create service with named target port
	service := npservice("testns", "web-service", "10.0.0.1",
		[]v1.ServicePort{
			servicePortNamed("http", v1.ProtocolTCP, 80, "http"),
		})
	svcKey := "testns/web-service"

	// Add service
	cont.processServiceTargetPorts(service, svcKey, false)

	// Verify namedPortServiceIndex is populated
	cont.indexMutex.Lock()
	webSvcEntry := cont.namedPortServiceIndex[svcKey]
	assert.NotNil(t, webSvcEntry, "Service should be in namedPortServiceIndex")
	if webSvcEntry != nil {
		httpPort := (*webSvcEntry)["http"]
		assert.NotNil(t, httpPort, "http port should be indexed")
		if httpPort != nil {
			assert.Equal(t, "http", httpPort.targetPortName, "targetPortName should be http")
			assert.NotNil(t, httpPort.resolvedPorts, "resolvedPorts map should exist")
		}
	}
	cont.indexMutex.Unlock()

	// Delete service
	cont.processServiceTargetPorts(service, svcKey, true)

	// Verify namedPortServiceIndex is cleaned up
	cont.indexMutex.Lock()
	_, exists := cont.namedPortServiceIndex[svcKey]
	assert.False(t, exists, "Service should be removed from namedPortServiceIndex")
	cont.indexMutex.Unlock()
}

// TestNamedPortMultipleServicesIndex tests multiple services with same named port
func TestNamedPortMultipleServicesIndex(t *testing.T) {
	cont := testController()
	cont.config.AciPolicyTenant = "test-tenant"
	cont.config.NodeServiceIpPool = []ipam.IpRange{
		{Start: net.ParseIP("10.1.1.2"), End: net.ParseIP("10.1.1.3")},
	}
	cont.config.PodIpPool = []ipam.IpRange{
		{Start: net.ParseIP("10.1.1.2"), End: net.ParseIP("10.1.255.254")},
	}
	cont.AciController.initIpam()

	// Create two services with same named target port
	service1 := npservice("testns", "web-service", "10.0.0.1",
		[]v1.ServicePort{
			servicePortNamed("http", v1.ProtocolTCP, 80, "http"),
		})
	service2 := npservice("testns", "api-service", "10.0.0.2",
		[]v1.ServicePort{
			servicePortNamed("http", v1.ProtocolTCP, 8080, "http"),
		})

	svcKey1 := "testns/web-service"
	svcKey2 := "testns/api-service"

	// Add both services
	cont.processServiceTargetPorts(service1, svcKey1, false)
	cont.processServiceTargetPorts(service2, svcKey2, false)

	// Verify both are in namedPortServiceIndex
	cont.indexMutex.Lock()
	assert.NotNil(t, cont.namedPortServiceIndex[svcKey1], "web-service should be in namedPortServiceIndex")
	assert.NotNil(t, cont.namedPortServiceIndex[svcKey2], "api-service should be in namedPortServiceIndex")
	cont.indexMutex.Unlock()

	// Add endpoint slices to resolve ports
	epSlice1 := makeEpSlice("testns", "web-service-abc",
		[]discovery.Endpoint{
			{
				Addresses: []string{"1.1.1.1"},
				TargetRef: &v1.ObjectReference{Kind: "Pod", Namespace: "testns", Name: "pod1"},
			},
		},
		[]discovery.EndpointPort{endpointSlicePort(v1.ProtocolTCP, 80, "http")},
		"web-service")

	epSlice2 := makeEpSlice("testns", "api-service-abc",
		[]discovery.Endpoint{
			{
				Addresses: []string{"2.2.2.2"},
				TargetRef: &v1.ObjectReference{Kind: "Pod", Namespace: "testns", Name: "pod2"},
			},
		},
		[]discovery.EndpointPort{endpointSlicePort(v1.ProtocolTCP, 8080, "http")},
		"api-service")

	cont.resolveServiceNamedPortFromEpSlice(epSlice1, svcKey1, false)
	cont.resolveServiceNamedPortFromEpSlice(epSlice2, svcKey2, false)

	// Verify resolved ports
	cont.indexMutex.Lock()
	webEntry := cont.namedPortServiceIndex[svcKey1]
	if webEntry != nil && (*webEntry)["http"] != nil {
		assert.True(t, (*webEntry)["http"].resolvedPorts[80], "Port 80 should be resolved for web-service")
	}
	apiEntry := cont.namedPortServiceIndex[svcKey2]
	if apiEntry != nil && (*apiEntry)["http"] != nil {
		assert.True(t, (*apiEntry)["http"].resolvedPorts[8080], "Port 8080 should be resolved for api-service")
	}
	cont.indexMutex.Unlock()

	// Delete one service
	cont.processServiceTargetPorts(service2, svcKey2, true)

	// Verify only deleted service is removed
	cont.indexMutex.Lock()
	_, exists := cont.namedPortServiceIndex[svcKey2]
	assert.False(t, exists, "api-service should be removed")
	assert.NotNil(t, cont.namedPortServiceIndex[svcKey1], "web-service should still exist")
	cont.indexMutex.Unlock()

	// Delete remaining service
	cont.processServiceTargetPorts(service1, svcKey1, true)

	cont.indexMutex.Lock()
	assert.Equal(t, 0, len(cont.namedPortServiceIndex), "namedPortServiceIndex should be empty")
	cont.indexMutex.Unlock()
}

// TestTargetPortIndexServiceReferenceTracking tests that targetPortIndex
// correctly tracks service references
func TestTargetPortIndexServiceReferenceTracking(t *testing.T) {
	cont := testController()
	cont.config.AciPolicyTenant = "test-tenant"
	cont.config.NodeServiceIpPool = []ipam.IpRange{
		{Start: net.ParseIP("10.1.1.2"), End: net.ParseIP("10.1.1.3")},
	}
	cont.config.PodIpPool = []ipam.IpRange{
		{Start: net.ParseIP("10.1.1.2"), End: net.ParseIP("10.1.255.254")},
	}
	cont.AciController.initIpam()

	svcKey1 := "testns/web-service"
	svcKey2 := "testns/api-service"
	portKey := "tcp-name-http"

	// Add services and update targetPortIndex
	service1 := npservice("testns", "web-service", "10.0.0.1",
		[]v1.ServicePort{servicePortNamed("http", v1.ProtocolTCP, 80, "http")})
	service2 := npservice("testns", "api-service", "10.0.0.2",
		[]v1.ServicePort{servicePortNamed("http", v1.ProtocolTCP, 8080, "http")})

	cont.processServiceTargetPorts(service1, svcKey1, false)
	cont.processServiceTargetPorts(service2, svcKey2, false)

	// Manually update targetPortIndex to track service references
	cont.indexMutex.Lock()
	ports := &portIndexEntry{
		port:              targetPort{ports: make(map[int]bool)},
		serviceKeys:       make(map[string]bool),
		networkPolicyKeys: make(map[string]bool),
	}
	ports.port.ports[80] = true
	ports.port.ports[8080] = true
	ports.serviceKeys[svcKey1] = true
	ports.serviceKeys[svcKey2] = true
	cont.targetPortIndex[portKey] = ports
	cont.indexMutex.Unlock()

	// Verify both services are tracked
	cont.indexMutex.Lock()
	entry := cont.targetPortIndex[portKey]
	assert.NotNil(t, entry, "targetPortIndex entry should exist")
	if entry != nil {
		assert.True(t, entry.serviceKeys[svcKey1], "web-service should be tracked")
		assert.True(t, entry.serviceKeys[svcKey2], "api-service should be tracked")
		assert.Equal(t, 2, len(entry.serviceKeys), "Should have 2 service references")
	}
	cont.indexMutex.Unlock()

	// Remove one service reference
	cont.indexMutex.Lock()
	delete(cont.targetPortIndex[portKey].serviceKeys, svcKey2)
	cont.indexMutex.Unlock()

	// Verify reference is removed
	cont.indexMutex.Lock()
	entry = cont.targetPortIndex[portKey]
	if entry != nil {
		assert.False(t, entry.serviceKeys[svcKey2], "api-service should be removed")
		assert.True(t, entry.serviceKeys[svcKey1], "web-service should still be tracked")
		assert.Equal(t, 1, len(entry.serviceKeys), "Should have 1 service reference")
	}
	cont.indexMutex.Unlock()
}

// TestTargetPortIndexCleanupOnLastReference tests that targetPortIndex
// entry is properly cleaned up when all references are removed.
func TestTargetPortIndexCleanupOnLastReference(t *testing.T) {
	cont := testController()
	cont.config.AciPolicyTenant = "test-tenant"
	cont.config.NodeServiceIpPool = []ipam.IpRange{
		{Start: net.ParseIP("10.1.1.2"), End: net.ParseIP("10.1.1.3")},
	}
	cont.config.PodIpPool = []ipam.IpRange{
		{Start: net.ParseIP("10.1.1.2"), End: net.ParseIP("10.1.255.254")},
	}
	cont.AciController.initIpam()

	svcKey := "testns/web-service"
	npKey := "testns/np1"
	portKey := "tcp-name-http"

	// Create targetPortIndex entry with service and netpol references
	cont.indexMutex.Lock()
	ports := &portIndexEntry{
		port:              targetPort{ports: make(map[int]bool)},
		serviceKeys:       make(map[string]bool),
		networkPolicyKeys: make(map[string]bool),
	}
	ports.port.ports[80] = true
	ports.serviceKeys[svcKey] = true
	ports.networkPolicyKeys[npKey] = true
	cont.targetPortIndex[portKey] = ports
	cont.indexMutex.Unlock()

	// Verify entry exists with both references
	cont.indexMutex.Lock()
	entry := cont.targetPortIndex[portKey]
	assert.NotNil(t, entry, "Entry should exist")
	assert.Equal(t, 1, len(entry.serviceKeys), "Should have 1 service reference")
	assert.Equal(t, 1, len(entry.networkPolicyKeys), "Should have 1 netpol reference")
	cont.indexMutex.Unlock()

	// Remove netpol reference
	cont.indexMutex.Lock()
	delete(cont.targetPortIndex[portKey].networkPolicyKeys, npKey)
	cont.indexMutex.Unlock()

	// Verify entry still exists (service reference remains)
	cont.indexMutex.Lock()
	entry = cont.targetPortIndex[portKey]
	assert.NotNil(t, entry, "Entry should still exist")
	assert.Equal(t, 0, len(entry.networkPolicyKeys), "Should have 0 netpol references")
	assert.Equal(t, 1, len(entry.serviceKeys), "Should still have 1 service reference")
	cont.indexMutex.Unlock()

	// Remove service reference
	cont.indexMutex.Lock()
	delete(cont.targetPortIndex[portKey].serviceKeys, svcKey)
	// When all references are gone, entry should be deleted
	if len(cont.targetPortIndex[portKey].serviceKeys) == 0 &&
		len(cont.targetPortIndex[portKey].networkPolicyKeys) == 0 {
		delete(cont.targetPortIndex, portKey)
	}
	cont.indexMutex.Unlock()

	// Verify entry is removed
	cont.indexMutex.Lock()
	_, exists := cont.targetPortIndex[portKey]
	assert.False(t, exists, "Entry should be removed when all references are gone")
	cont.indexMutex.Unlock()
}

// TestNetworkPolicyEgressNamedPortWithPodSelector tests egress with named port
// and a specific pod selector in the To field - should only apply to selected pods.
func TestNetworkPolicyEgressNamedPortWithPodSelector(t *testing.T) {
	// NetworkPolicy with named port "http" and pod selector targeting app=backend
	test_np := netpol("testns", "np1", &metav1.LabelSelector{},
		nil, []v1net.NetworkPolicyEgressRule{
			egressRule([]v1net.NetworkPolicyPort{
				{Protocol: func() *v1.Protocol { a := v1.ProtocolTCP; return &a }(),
					Port: &intstr.IntOrString{Type: intstr.String, StrVal: "http"},
				},
			}, []v1net.NetworkPolicyPeer{
				{
					PodSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"app": "backend"},
					},
				},
			}),
		}, allPolicyTypes)

	name := "kube_np_testns_np1"
	baseDn := makeNp(nil, nil, name).GetDn()
	np1SDnE := fmt.Sprintf("%s/subj-networkpolicy-egress", baseDn)

	// Rule for named port "http" targeting selected pods
	rule_1_0 := apicapi.NewHostprotRule(np1SDnE, "0_0-ipv4__np1")
	rule_1_0.SetAttr("direction", "egress")
	rule_1_0.SetAttr("ethertype", "ipv4")
	rule_1_0.SetAttr("protocol", "tcp")
	rule_1_0.SetAttr("fromPort", "http")
	rule_1_0.AddChild(apicapi.NewHostprotRemoteIp(rule_1_0.GetDn(), "1.1.1.1"))

	// Service augmentation rule - only for services backing selected pods
	rule_1_s := apicapi.NewHostprotRule(np1SDnE, "service_tcp_8080-ipv4")
	rule_1_s.SetAttr("direction", "egress")
	rule_1_s.SetAttr("ethertype", "ipv4")
	rule_1_s.SetAttr("protocol", "tcp")
	rule_1_s.SetAttr("fromPort", "8080")
	rule_1_s.AddChild(apicapi.NewHostprotRemoteIp(rule_1_s.GetDn(), "9.0.0.42"))

	var npTests = []npTest{
		{test_np,
			makeNp(nil, apicapi.ApicSlice{rule_1_0, rule_1_s}, name),
			&npTestAugment{
				[]*v1.Endpoints{},
				[]*v1.Service{
					npservice("testns", "service1", "9.0.0.42",
						[]v1.ServicePort{
							servicePortNamed("http", v1.ProtocolTCP, 8080, "http"),
						}),
				},
				[]*discovery.EndpointSlice{
					makeEpSlice("testns", "service1-abc",
						[]discovery.Endpoint{
							{
								Addresses: []string{"1.1.1.1"},
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "testns",
									Name:      "pod1",
								},
							},
						},
						[]discovery.EndpointPort{
							endpointSlicePort(v1.ProtocolTCP, 80, "http"),
						}, "service1"),
				},
			}, "egress-named-port-with-pod-selector"},
	}

	initCont := func() *testAciController {
		cont := testController()
		cont.config.AciPolicyTenant = "test-tenant"
		cont.config.NodeServiceIpPool = []ipam.IpRange{
			{Start: net.ParseIP("10.1.1.2"), End: net.ParseIP("10.1.1.3")},
		}
		cont.config.PodIpPool = []ipam.IpRange{
			{Start: net.ParseIP("10.1.1.2"), End: net.ParseIP("10.1.255.254")},
		}
		cont.AciController.initIpam()
		cont.serviceEndPoints = &serviceEndpointSlice{}
		cont.serviceEndPoints.(*serviceEndpointSlice).cont = &cont.AciController
		cont.fakeNamespaceSource.Add(namespaceLabel("testns",
			map[string]string{"test": "testv"}))
		return cont
	}

	ports := []v1.ContainerPort{
		{Name: "http", ContainerPort: int32(80)},
	}

	addPod := func(cont *testAciController, namespace string,
		name string, labels map[string]string, ports []v1.ContainerPort) {
		pod := &v1.Pod{
			Spec: v1.PodSpec{
				NodeName: "test-node",
				Containers: []v1.Container{
					{
						Ports: ports,
					},
				},
			},
			ObjectMeta: metav1.ObjectMeta{
				Namespace: namespace,
				Name:      name,
				Labels:    labels,
			},
			Status: v1.PodStatus{
				PodIP: "1.1.1.1",
			},
		}
		cont.fakePodSource.Add(pod)
	}

	for ix := range npTests {
		cont := initCont()
		cont.log.Info("Starting podsfirst ", npTests[ix].desc)
		// Add pod with app=backend label to match the selector
		addPod(cont, "testns", "pod1", map[string]string{"app": "backend"}, ports)
		addServices(cont, npTests[ix].augment)
		cont.run()
		cont.fakeNetworkPolicySource.Add(npTests[ix].netPol)
		checkNp(t, &npTests[ix], "podsfirst", cont)
		cont.log.Info("Starting delete ", npTests[ix].desc)
		cont.fakeNetworkPolicySource.Delete(npTests[ix].netPol)
		checkDelete(t, npTests[0], cont)
		cont.stop()
	}
}

// TestNetworkPolicyNamedPortEndpointSliceLifecycle tests that EndpointSlice changes
// properly trigger network policy updates when services use named target ports.
// This verifies the integration between EndpointSlices, services with named ports,
// and network policies.
// TestNetworkPolicyNamedPortEndpointSliceLifecycle tests that EndpointSlice
// changes correctly update the namedPortServiceIndex's resolvedPorts.
// Uses direct function calls to processServiceTargetPorts and resolveServiceNamedPortFromEpSlice.
func TestNetworkPolicyNamedPortEndpointSliceLifecycle(t *testing.T) {
	cont := testController()
	cont.config.AciPolicyTenant = "test-tenant"
	cont.config.NodeServiceIpPool = []ipam.IpRange{
		{Start: net.ParseIP("10.1.1.2"), End: net.ParseIP("10.1.1.3")},
	}
	cont.config.PodIpPool = []ipam.IpRange{
		{Start: net.ParseIP("10.1.1.2"), End: net.ParseIP("10.1.255.254")},
	}
	cont.AciController.initIpam()

	// Create service with named target port
	service := npservice("testns", "service1", "9.0.0.42",
		[]v1.ServicePort{
			servicePortNamed("http", v1.ProtocolTCP, 8080, "http-port"),
		})
	svcKey := "testns/service1"

	// Step 1: Call processServiceTargetPorts to populate namedPortServiceIndex
	cont.processServiceTargetPorts(service, svcKey, false)

	// Verify namedPortServiceIndex is populated with named port
	cont.indexMutex.Lock()
	svcEntry := cont.namedPortServiceIndex[svcKey]
	assert.NotNil(t, svcEntry, "Service should be in namedPortServiceIndex")
	if svcEntry != nil {
		portEntry := (*svcEntry)["http"]
		assert.NotNil(t, portEntry, "Named port 'http' should be indexed")
		if portEntry != nil {
			assert.Equal(t, "http-port", portEntry.targetPortName, "Target port name should be 'http-port'")
			assert.NotNil(t, portEntry.resolvedPorts, "resolvedPorts should be initialized")
			assert.Equal(t, 0, len(portEntry.resolvedPorts), "resolvedPorts should be empty before EndpointSlice")
		}
	}
	cont.indexMutex.Unlock()

	// Step 2: Add first EndpointSlice and call resolveServiceNamedPortFromEpSlice
	epSlice1 := makeEpSlice("testns", "service1-slice1",
		[]discovery.Endpoint{
			{
				Addresses: []string{"1.1.1.1"},
				TargetRef: &v1.ObjectReference{
					Kind:      "Pod",
					Namespace: "testns",
					Name:      "pod1",
				},
			},
		},
		[]discovery.EndpointPort{
			endpointSlicePort(v1.ProtocolTCP, 80, "http"),
		},
		"service1")
	cont.resolveServiceNamedPortFromEpSlice(epSlice1, svcKey, false)

	// Verify port 80 is now resolved
	cont.indexMutex.Lock()
	svcEntry = cont.namedPortServiceIndex[svcKey]
	assert.NotNil(t, svcEntry, "Service should still be in namedPortServiceIndex")
	if svcEntry != nil {
		portEntry := (*svcEntry)["http"]
		assert.NotNil(t, portEntry, "Named port 'http' should still be indexed")
		if portEntry != nil {
			assert.True(t, portEntry.resolvedPorts[80], "Port 80 should be resolved from EndpointSlice")
		}
	}
	cont.indexMutex.Unlock()

	// Step 3: Add second EndpointSlice with different port
	epSlice2 := makeEpSlice("testns", "service1-slice2",
		[]discovery.Endpoint{
			{
				Addresses: []string{"1.1.1.2"},
				TargetRef: &v1.ObjectReference{
					Kind:      "Pod",
					Namespace: "testns",
					Name:      "pod2",
				},
			},
		},
		[]discovery.EndpointPort{
			endpointSlicePort(v1.ProtocolTCP, 8080, "http"),
		},
		"service1")
	cont.resolveServiceNamedPortFromEpSlice(epSlice2, svcKey, false)

	// Verify both ports are resolved
	cont.indexMutex.Lock()
	svcEntry = cont.namedPortServiceIndex[svcKey]
	if svcEntry != nil {
		portEntry := (*svcEntry)["http"]
		if portEntry != nil {
			assert.True(t, portEntry.resolvedPorts[80], "Port 80 should still be resolved")
			assert.True(t, portEntry.resolvedPorts[8080], "Port 8080 should be resolved from second EndpointSlice")
		}
	}
	cont.indexMutex.Unlock()

	// Step 4: Delete first EndpointSlice (old=true removes ports)
	cont.resolveServiceNamedPortFromEpSlice(epSlice1, svcKey, true)

	// Verify port 80 is removed, 8080 remains
	cont.indexMutex.Lock()
	svcEntry = cont.namedPortServiceIndex[svcKey]
	if svcEntry != nil {
		portEntry := (*svcEntry)["http"]
		if portEntry != nil {
			assert.False(t, portEntry.resolvedPorts[80], "Port 80 should be removed after EndpointSlice deletion")
			assert.True(t, portEntry.resolvedPorts[8080], "Port 8080 should still be resolved")
		}
	}
	cont.indexMutex.Unlock()

	// Step 5: Delete second EndpointSlice
	cont.resolveServiceNamedPortFromEpSlice(epSlice2, svcKey, true)

	// Verify all ports are removed but entry still exists
	cont.indexMutex.Lock()
	svcEntry = cont.namedPortServiceIndex[svcKey]
	assert.NotNil(t, svcEntry, "Service entry should still exist (defined by service spec)")
	if svcEntry != nil {
		portEntry := (*svcEntry)["http"]
		assert.NotNil(t, portEntry, "Port entry should still exist")
		if portEntry != nil {
			assert.Equal(t, 0, len(portEntry.resolvedPorts), "All resolved ports should be removed")
		}
	}
	cont.indexMutex.Unlock()

	// Step 6: Delete service
	cont.processServiceTargetPorts(service, svcKey, true)

	// Verify service entry is removed
	cont.indexMutex.Lock()
	_, exists := cont.namedPortServiceIndex[svcKey]
	assert.False(t, exists, "Service should be removed from namedPortServiceIndex")
	cont.indexMutex.Unlock()
}

// TestNetworkPolicyNamedPortServiceLifecycle tests that service updates
// (add, modify, delete) correctly update the namedPortServiceIndex.
// Uses direct function calls to processServiceTargetPorts.
func TestNetworkPolicyNamedPortServiceLifecycle(t *testing.T) {
	cont := testController()
	cont.config.AciPolicyTenant = "test-tenant"
	cont.config.NodeServiceIpPool = []ipam.IpRange{
		{Start: net.ParseIP("10.1.1.2"), End: net.ParseIP("10.1.1.3")},
	}
	cont.config.PodIpPool = []ipam.IpRange{
		{Start: net.ParseIP("10.1.1.2"), End: net.ParseIP("10.1.255.254")},
	}
	cont.AciController.initIpam()

	svcKey := "testns/service1"

	// Step 1: Add service with named target port
	service := npservice("testns", "service1", "9.0.0.42",
		[]v1.ServicePort{
			servicePortNamed("http", v1.ProtocolTCP, 8080, "http-port"),
		})
	cont.processServiceTargetPorts(service, svcKey, false)

	// Verify namedPortServiceIndex is populated
	cont.indexMutex.Lock()
	namedEntry, exists := cont.namedPortServiceIndex[svcKey]
	assert.True(t, exists, "Service should be in namedPortServiceIndex")
	if exists {
		portEntry, portExists := (*namedEntry)["http"]
		assert.True(t, portExists, "Port 'http' should be in namedPortServiceIndex")
		if portExists {
			assert.Equal(t, "http-port", portEntry.targetPortName, "Target port name should be 'http-port'")
		}
	}
	cont.indexMutex.Unlock()

	// Step 2: Update service to change target port name
	// First remove old entry, then add new one (simulating service update)
	cont.processServiceTargetPorts(service, svcKey, true)
	serviceUpdated := npservice("testns", "service1", "9.0.0.42",
		[]v1.ServicePort{
			servicePortNamed("http", v1.ProtocolTCP, 8080, "new-http-port"),
		})
	cont.processServiceTargetPorts(serviceUpdated, svcKey, false)

	// Verify namedPortServiceIndex is updated
	cont.indexMutex.Lock()
	namedEntryAfter, existsAfter := cont.namedPortServiceIndex[svcKey]
	assert.True(t, existsAfter, "Service should still be in namedPortServiceIndex")
	if existsAfter {
		portEntryAfter, portExistsAfter := (*namedEntryAfter)["http"]
		assert.True(t, portExistsAfter, "Port 'http' should still be in namedPortServiceIndex")
		if portExistsAfter {
			assert.Equal(t, "new-http-port", portEntryAfter.targetPortName, "Target port name should be updated to 'new-http-port'")
		}
	}
	cont.indexMutex.Unlock()

	// Step 3: Add multiple ports to service
	cont.processServiceTargetPorts(serviceUpdated, svcKey, true)
	serviceMultiPort := npservice("testns", "service1", "9.0.0.42",
		[]v1.ServicePort{
			servicePortNamed("http", v1.ProtocolTCP, 8080, "new-http-port"),
			servicePortNamed("https", v1.ProtocolTCP, 8443, "https-port"),
		})
	cont.processServiceTargetPorts(serviceMultiPort, svcKey, false)

	// Verify both ports are indexed
	cont.indexMutex.Lock()
	namedEntryMulti := cont.namedPortServiceIndex[svcKey]
	assert.NotNil(t, namedEntryMulti, "Service should be in namedPortServiceIndex")
	if namedEntryMulti != nil {
		assert.Equal(t, 2, len(*namedEntryMulti), "Should have 2 named ports")
		httpEntry := (*namedEntryMulti)["http"]
		httpsEntry := (*namedEntryMulti)["https"]
		assert.NotNil(t, httpEntry, "http port should exist")
		assert.NotNil(t, httpsEntry, "https port should exist")
		if httpEntry != nil {
			assert.Equal(t, "new-http-port", httpEntry.targetPortName)
		}
		if httpsEntry != nil {
			assert.Equal(t, "https-port", httpsEntry.targetPortName)
		}
	}
	cont.indexMutex.Unlock()

	// Step 4: Delete service
	cont.processServiceTargetPorts(serviceMultiPort, svcKey, true)

	// Verify namedPortServiceIndex entry is removed
	cont.indexMutex.Lock()
	_, existsAfterDelete := cont.namedPortServiceIndex[svcKey]
	assert.False(t, existsAfterDelete, "Service should be removed from namedPortServiceIndex after deletion")
	cont.indexMutex.Unlock()
}

// TestNetworkPolicyNamedPortMultipleEndpoints validates network policy behavior when
// a service references a named port ("http") that resolves to different numeric ports
// across multiple endpoints.
//
// Test Setup:
// - Network policy with egress rule allowing TCP traffic to named port "http"
// - Service "service1" (ClusterIP: 9.0.0.42) with port 9090 targeting named port "http"
// - Two endpoints (pod1: 1.1.1.1, pod2: 1.1.1.2) both exposing "http" on port 80
//
// Expected Behavior:
// Two distinct egress rules should be generated:
// 1. Rule "0_0-ipv4__np1": Allows TCP traffic to named port "http" (cluster-wide resolution)
// 2. Rule "service_tcp_9090-ipv4": Allows TCP traffic to service ClusterIP 9.0.0.42:9090
//
// This validates that:
// - Named ports are resolved across all matching pods in the cluster
// - Service-specific rules are created with the service's ClusterIP and port
// - Multiple endpoints backing a service are handled correctly
func TestNetworkPolicyNamedPortMultipleEndpoints(t *testing.T) {
	test_np := netpol("testns", "np1", &metav1.LabelSelector{},
		nil, []v1net.NetworkPolicyEgressRule{
			egressRule([]v1net.NetworkPolicyPort{
				{Protocol: func() *v1.Protocol { a := v1.ProtocolTCP; return &a }(),
					Port: &intstr.IntOrString{Type: intstr.String, StrVal: "http"},
				},
			}, nil),
		}, allPolicyTypes)

	name := "kube_np_testns_np1"
	baseDn := makeNp(nil, nil, name).GetDn()
	np1SDnE := fmt.Sprintf("%s/subj-networkpolicy-egress", baseDn)

	rule_80 := apicapi.NewHostprotRule(np1SDnE, "0_0-ipv4__np1")
	rule_80.SetAttr("direction", "egress")
	rule_80.SetAttr("ethertype", "ipv4")
	rule_80.SetAttr("protocol", "tcp")
	rule_80.SetAttr("fromPort", "http")

	rule_svc := apicapi.NewHostprotRule(np1SDnE, "service_tcp_9090-ipv4")
	rule_svc.SetAttr("direction", "egress")
	rule_svc.SetAttr("ethertype", "ipv4")
	rule_svc.SetAttr("protocol", "tcp")
	rule_svc.SetAttr("fromPort", "9090")
	rule_svc.AddChild(apicapi.NewHostprotRemoteIp(rule_svc.GetDn(), "9.0.0.42"))

	var npTests = []npTest{
		{test_np,
			makeNp(nil, apicapi.ApicSlice{rule_80, rule_svc}, name),
			&npTestAugment{
				[]*v1.Endpoints{},
				[]*v1.Service{
					npservice("testns", "service1", "9.0.0.42",
						[]v1.ServicePort{
							servicePortNamed("web", v1.ProtocolTCP, 9090, "http"),
						}),
				},
				[]*discovery.EndpointSlice{
					makeEpSlice("testns", "service1-slice1",
						[]discovery.Endpoint{
							{
								Addresses: []string{"1.1.1.1"},
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "testns",
									Name:      "pod1",
								},
							},
							{
								Addresses: []string{"1.1.1.2"},
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "testns",
									Name:      "pod2",
								},
							},
						},
						[]discovery.EndpointPort{
							endpointSlicePort(v1.ProtocolTCP, 80, "http"),
						},
						"service1"),
				},
			}, "egress-named-port-multiple-endpoints"},
	}

	initCont := func() *testAciController {
		cont := testController()
		cont.config.AciPolicyTenant = "test-tenant"
		cont.config.NodeServiceIpPool = []ipam.IpRange{
			{Start: net.ParseIP("10.1.1.2"), End: net.ParseIP("10.1.1.3")},
		}
		cont.config.PodIpPool = []ipam.IpRange{
			{Start: net.ParseIP("10.1.1.2"), End: net.ParseIP("10.1.255.254")},
		}
		cont.AciController.initIpam()

		cont.fakeNamespaceSource.Add(namespaceLabel("testns",
			map[string]string{"test": "testv"}))

		return cont
	}

	ports := []v1.ContainerPort{
		{Name: "http", ContainerPort: int32(80)},
	}

	addPod := func(cont *testAciController, namespace string,
		name string, labels map[string]string, ports []v1.ContainerPort) {
		pod := &v1.Pod{
			Spec: v1.PodSpec{
				NodeName: "test-node",
				Containers: []v1.Container{
					{
						Ports: ports,
					},
				},
			},
			ObjectMeta: metav1.ObjectMeta{
				Namespace: namespace,
				Name:      name,
				Labels:    labels,
			},
		}
		cont.fakePodSource.Add(pod)
	}

	for ix := range npTests {
		cont := initCont()
		addPod(cont, "testns", "pod1", map[string]string{"l1": "v1"}, ports)
		addPod(cont, "testns", "pod2", map[string]string{"l1": "v1"}, ports)
		addServices(cont, npTests[ix].augment)
		cont.run()
		cont.fakeNetworkPolicySource.Add(npTests[ix].netPol)
		checkNp(t, &npTests[ix], "podsfirst", cont)

		cont.fakeNetworkPolicySource.Delete(npTests[ix].netPol)
		checkDelete(t, npTests[0], cont)
		cont.stop()
	}
}

// TestNetworkPolicyEgressEmptyToWithNamedPort tests egress with empty 'to' field
// and named port - should augment all services matching the named port.
func TestNetworkPolicyEgressEmptyToWithNamedPort(t *testing.T) {
	// NetworkPolicy with empty 'to' and named port "http"
	test_np := netpol("testns", "np1", &metav1.LabelSelector{},
		nil, []v1net.NetworkPolicyEgressRule{
			{
				Ports: []v1net.NetworkPolicyPort{
					{Protocol: func() *v1.Protocol { a := v1.ProtocolTCP; return &a }(),
						Port: &intstr.IntOrString{Type: intstr.String, StrVal: "http"},
					},
				},
				// Empty 'To' field - allows all destinations on this port
			},
		}, allPolicyTypes)

	name := "kube_np_testns_np1"
	baseDn := makeNp(nil, nil, name).GetDn()
	np1SDnE := fmt.Sprintf("%s/subj-networkpolicy-egress", baseDn)

	// Rule for named port "http"
	rule_1_0 := apicapi.NewHostprotRule(np1SDnE, "0_0-ipv4__np1")
	rule_1_0.SetAttr("direction", "egress")
	rule_1_0.SetAttr("ethertype", "ipv4")
	rule_1_0.SetAttr("protocol", "tcp")
	rule_1_0.SetAttr("fromPort", "http")

	// Service augmentation rule
	rule_1_s := apicapi.NewHostprotRule(np1SDnE, "service_tcp_8080-ipv4")
	rule_1_s.SetAttr("direction", "egress")
	rule_1_s.SetAttr("ethertype", "ipv4")
	rule_1_s.SetAttr("protocol", "tcp")
	rule_1_s.SetAttr("fromPort", "8080")
	rule_1_s.AddChild(apicapi.NewHostprotRemoteIp(rule_1_s.GetDn(), "9.0.0.42"))

	var npTests = []npTest{
		{test_np,
			makeNp(nil, apicapi.ApicSlice{rule_1_0, rule_1_s}, name),
			&npTestAugment{
				[]*v1.Endpoints{},
				[]*v1.Service{
					npservice("testns", "service1", "9.0.0.42",
						[]v1.ServicePort{
							servicePortNamed("http", v1.ProtocolTCP, 8080, "http"),
						}),
				},
				[]*discovery.EndpointSlice{
					makeEpSlice("testns", "service1-abc",
						[]discovery.Endpoint{
							{
								Addresses: []string{"1.1.1.1"},
								TargetRef: &v1.ObjectReference{
									Kind:      "Pod",
									Namespace: "testns",
									Name:      "pod1",
								},
							},
						},
						[]discovery.EndpointPort{
							endpointSlicePort(v1.ProtocolTCP, 80, "http"),
						}, "service1"),
				},
			}, "egress-empty-to-named-port"},
	}

	initCont := func() *testAciController {
		cont := testController()
		cont.config.AciPolicyTenant = "test-tenant"
		cont.serviceEndPoints = &serviceEndpointSlice{}
		cont.serviceEndPoints.(*serviceEndpointSlice).cont = &cont.AciController
		cont.config.NodeServiceIpPool = []ipam.IpRange{
			{Start: net.ParseIP("10.1.1.2"), End: net.ParseIP("10.1.1.3")},
		}
		cont.config.PodIpPool = []ipam.IpRange{
			{Start: net.ParseIP("10.1.1.2"), End: net.ParseIP("10.1.255.254")},
		}
		cont.AciController.initIpam()
		cont.fakeNamespaceSource.Add(namespaceLabel("testns",
			map[string]string{"test": "testv"}))
		return cont
	}

	ports := []v1.ContainerPort{
		{Name: "http", ContainerPort: int32(80)},
	}

	addPod := func(cont *testAciController, namespace string,
		name string, labels map[string]string, ports []v1.ContainerPort) {
		pod := &v1.Pod{
			Spec: v1.PodSpec{
				NodeName: "test-node",
				Containers: []v1.Container{
					{
						Ports: ports,
					},
				},
			},
			ObjectMeta: metav1.ObjectMeta{
				Namespace: namespace,
				Name:      name,
				Labels:    labels,
			},
		}
		cont.fakePodSource.Add(pod)
	}

	for ix := range npTests {
		cont := initCont()
		cont.log.Info("Starting podsfirst ", npTests[ix].desc)
		addPod(cont, "testns", "pod1", map[string]string{"l1": "v1"}, ports)
		addServices(cont, npTests[ix].augment)
		cont.run()
		cont.fakeNetworkPolicySource.Add(npTests[ix].netPol)
		checkNp(t, &npTests[ix], "podsfirst", cont)
		cont.log.Info("Starting delete ", npTests[ix].desc)
		cont.fakeNetworkPolicySource.Delete(npTests[ix].netPol)
		checkDelete(t, npTests[0], cont)
		cont.stop()
	}
}

// TestNetworkPolicyIngressNamedPort tests ingress with named port.
func TestNetworkPolicyIngressNamedPort(t *testing.T) {
	// NetworkPolicy with ingress named port "http"
	test_np := netpol("testns", "np1", &metav1.LabelSelector{
		MatchLabels: map[string]string{"app": "target"},
	},
		[]v1net.NetworkPolicyIngressRule{
			{
				Ports: []v1net.NetworkPolicyPort{
					{Protocol: func() *v1.Protocol { a := v1.ProtocolTCP; return &a }(),
						Port: &intstr.IntOrString{Type: intstr.String, StrVal: "http"},
					},
				},
				From: []v1net.NetworkPolicyPeer{
					{
						PodSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"app": "client"},
						},
					},
				},
			},
		}, nil, allPolicyTypes)

	name := "kube_np_testns_np1"
	baseDn := makeNp(nil, nil, name).GetDn()
	np1SDnI := fmt.Sprintf("%s/subj-networkpolicy-ingress", baseDn)

	// Rule for named port "http" on ingress - resolves to pod's container port 8080
	rule_1_0 := apicapi.NewHostprotRule(np1SDnI, "0_0-ipv4__np1")
	rule_1_0.SetAttr("direction", "ingress")
	rule_1_0.SetAttr("ethertype", "ipv4")
	rule_1_0.SetAttr("protocol", "tcp")
	rule_1_0.SetAttr("fromPort", "8080")
	rule_1_0.AddChild(apicapi.NewHostprotRemoteIp(rule_1_0.GetDn(), "1.1.1.1"))

	var npTests = []npTest{
		{test_np,
			makeNp(apicapi.ApicSlice{rule_1_0}, nil, name),
			&npTestAugment{
				[]*v1.Endpoints{},
				[]*v1.Service{},
				[]*discovery.EndpointSlice{},
			}, "ingress-named-port"},
	}

	initCont := func() *testAciController {
		cont := testController()
		cont.config.AciPolicyTenant = "test-tenant"
		cont.config.NodeServiceIpPool = []ipam.IpRange{
			{Start: net.ParseIP("10.1.1.2"), End: net.ParseIP("10.1.1.3")},
		}
		cont.config.PodIpPool = []ipam.IpRange{
			{Start: net.ParseIP("10.1.1.2"), End: net.ParseIP("10.1.255.254")},
		}
		cont.AciController.initIpam()
		cont.fakeNamespaceSource.Add(namespaceLabel("testns",
			map[string]string{"test": "testv"}))
		return cont
	}

	targetPorts := []v1.ContainerPort{
		{Name: "http", ContainerPort: int32(8080)},
	}

	addPod := func(cont *testAciController, namespace string,
		name string, labels map[string]string, ports []v1.ContainerPort) {
		pod := &v1.Pod{
			Spec: v1.PodSpec{
				NodeName: "test-node",
				Containers: []v1.Container{
					{
						Ports: ports,
					},
				},
			},
			ObjectMeta: metav1.ObjectMeta{
				Namespace: namespace,
				Name:      name,
				Labels:    labels,
			},
			Status: v1.PodStatus{
				PodIP: "1.1.1.1",
			},
		}
		cont.fakePodSource.Add(pod)
	}

	for ix := range npTests {
		cont := initCont()
		cont.log.Info("Starting podsfirst ", npTests[ix].desc)
		addPod(cont, "testns", "target-pod", map[string]string{"app": "target"}, targetPorts)
		addPod(cont, "testns", "client-pod", map[string]string{"app": "client"}, nil)
		addServices(cont, npTests[ix].augment)
		cont.run()
		cont.fakeNetworkPolicySource.Add(npTests[ix].netPol)
		checkNp(t, &npTests[ix], "podsfirst", cont)
		cont.log.Info("Starting delete ", npTests[ix].desc)
		cont.fakeNetworkPolicySource.Delete(npTests[ix].netPol)
		checkDelete(t, npTests[0], cont)
		cont.stop()
	}
}

// TestNetworkPolicyIngressMultipleNamedPorts tests ingress with multiple named ports.
func TestNetworkPolicyIngressMultipleNamedPorts(t *testing.T) {
	// NetworkPolicy with multiple ingress named ports
	test_np := netpol("testns", "np1", &metav1.LabelSelector{
		MatchLabels: map[string]string{"app": "target"},
	},
		[]v1net.NetworkPolicyIngressRule{
			{
				Ports: []v1net.NetworkPolicyPort{
					{Protocol: func() *v1.Protocol { a := v1.ProtocolTCP; return &a }(),
						Port: &intstr.IntOrString{Type: intstr.String, StrVal: "http"},
					},
					{Protocol: func() *v1.Protocol { a := v1.ProtocolTCP; return &a }(),
						Port: &intstr.IntOrString{Type: intstr.String, StrVal: "admin"},
					},
				},
				From: []v1net.NetworkPolicyPeer{
					{
						PodSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"app": "client"},
						},
					},
				},
			},
		}, nil, allPolicyTypes)

	name := "kube_np_testns_np1"
	baseDn := makeNp(nil, nil, name).GetDn()
	np1SDnI := fmt.Sprintf("%s/subj-networkpolicy-ingress", baseDn)

	// Rules for multiple named ports with unique names - resolve to pod container ports
	rule_1_0 := apicapi.NewHostprotRule(np1SDnI, "0_0-ipv4__np1")
	rule_1_0.SetAttr("direction", "ingress")
	rule_1_0.SetAttr("ethertype", "ipv4")
	rule_1_0.SetAttr("protocol", "tcp")
	rule_1_0.SetAttr("fromPort", "8080")
	rule_1_0.AddChild(apicapi.NewHostprotRemoteIp(rule_1_0.GetDn(), "1.1.1.1"))

	rule_1_1 := apicapi.NewHostprotRule(np1SDnI, "0_1-ipv4__np1")
	rule_1_1.SetAttr("direction", "ingress")
	rule_1_1.SetAttr("ethertype", "ipv4")
	rule_1_1.SetAttr("protocol", "tcp")
	rule_1_1.SetAttr("fromPort", "9000")
	rule_1_1.AddChild(apicapi.NewHostprotRemoteIp(rule_1_1.GetDn(), "1.1.1.1"))

	var npTests = []npTest{
		{test_np,
			makeNp(apicapi.ApicSlice{rule_1_0, rule_1_1}, nil, name),
			&npTestAugment{
				[]*v1.Endpoints{},
				[]*v1.Service{},
				[]*discovery.EndpointSlice{},
			}, "ingress-multiple-named-ports"},
	}

	initCont := func() *testAciController {
		cont := testController()
		cont.config.AciPolicyTenant = "test-tenant"
		cont.config.NodeServiceIpPool = []ipam.IpRange{
			{Start: net.ParseIP("10.1.1.2"), End: net.ParseIP("10.1.1.3")},
		}
		cont.config.PodIpPool = []ipam.IpRange{
			{Start: net.ParseIP("10.1.1.2"), End: net.ParseIP("10.1.255.254")},
		}
		cont.AciController.initIpam()
		cont.fakeNamespaceSource.Add(namespaceLabel("testns",
			map[string]string{"test": "testv"}))
		return cont
	}

	targetPorts := []v1.ContainerPort{
		{Name: "http", ContainerPort: int32(8080)},
		{Name: "admin", ContainerPort: int32(9000)},
	}

	addPod := func(cont *testAciController, namespace string,
		name string, labels map[string]string, ports []v1.ContainerPort) {
		pod := &v1.Pod{
			Spec: v1.PodSpec{
				NodeName: "test-node",
				Containers: []v1.Container{
					{
						Ports: ports,
					},
				},
			},
			ObjectMeta: metav1.ObjectMeta{
				Namespace: namespace,
				Name:      name,
				Labels:    labels,
			},
			Status: v1.PodStatus{
				PodIP: "1.1.1.1",
			},
		}
		cont.fakePodSource.Add(pod)
	}

	for ix := range npTests {
		cont := initCont()
		cont.log.Info("Starting podsfirst ", npTests[ix].desc)
		addPod(cont, "testns", "target-pod", map[string]string{"app": "target"}, targetPorts)
		addPod(cont, "testns", "client-pod", map[string]string{"app": "client"}, nil)
		addServices(cont, npTests[ix].augment)
		cont.run()
		cont.fakeNetworkPolicySource.Add(npTests[ix].netPol)
		checkNp(t, &npTests[ix], "podsfirst", cont)
		cont.log.Info("Starting delete ", npTests[ix].desc)
		cont.fakeNetworkPolicySource.Delete(npTests[ix].netPol)
		checkDelete(t, npTests[0], cont)
		cont.stop()
	}
}

// TestBuildLocalNetPolSubjRulesEgressNamedPort tests that buildLocalNetPolSubjRules
// correctly resolves a named egress port to numeric ports in HppDirect mode.
// The named port "http" is resolved via targetPortIndex to port 80, producing
// a local HostprotRule with fromPort="80".
func TestBuildLocalNetPolSubjRulesEgressNamedPort(t *testing.T) {
	cont := getContWithEnabledLocalHpp()
	cont.run()
	defer cont.stop()

	np := netpol("testns", "np1", &metav1.LabelSelector{},
		nil, []v1net.NetworkPolicyEgressRule{
			egressRule([]v1net.NetworkPolicyPort{
				{Protocol: func() *v1.Protocol { a := v1.ProtocolTCP; return &a }(),
					Port: &intstr.IntOrString{Type: intstr.String, StrVal: "http"},
				},
			}, nil),
		}, allPolicyTypes)

	// Populate targetPortIndex so named port "http" resolves to port 80
	portkey := "tcp-name-http"
	cont.indexMutex.Lock()
	cont.targetPortIndex[portkey] = &portIndexEntry{
		port: targetPort{
			proto: "tcp",
			ports: map[int]bool{80: true},
		},
		serviceKeys:       make(map[string]bool),
		networkPolicyKeys: make(map[string]bool),
	}
	cont.indexMutex.Unlock()

	subj := &hppv1.HostprotSubj{}
	cont.buildLocalNetPolSubjRules("0", subj, "egress",
		nil, nil, np.Spec.Egress[0].Ports, cont.log.WithField("test", "egress-named-port"),
		"testns/np1", np, nil)

	assert.Equal(t, 1, len(subj.HostprotRule), "Should have 1 rule for resolved named port")
	assert.Equal(t, "0_0-ipv4", subj.HostprotRule[0].Name)
	assert.Equal(t, "egress", subj.HostprotRule[0].Direction)
	assert.Equal(t, "ipv4", subj.HostprotRule[0].Ethertype)
	assert.Equal(t, "tcp", subj.HostprotRule[0].Protocol)
	assert.Equal(t, "80", subj.HostprotRule[0].FromPort)
}

// TestBuildLocalNetPolSubjRulesEgressMultipleNamedPorts tests that
// buildLocalNetPolSubjRules produces unique rule names when multiple named ports
// resolve to multiple numeric ports in HppDirect mode. This mirrors the
// TestNetworkPolicyEgressMultipleNamedPortsUniqueRuleNames test for the local path.
func TestBuildLocalNetPolSubjRulesEgressMultipleNamedPorts(t *testing.T) {
	cont := getContWithEnabledLocalHpp()
	cont.run()
	defer cont.stop()

	np := netpol("testns", "np1", &metav1.LabelSelector{},
		nil, []v1net.NetworkPolicyEgressRule{
			egressRule([]v1net.NetworkPolicyPort{
				{Protocol: func() *v1.Protocol { a := v1.ProtocolTCP; return &a }(),
					Port: &intstr.IntOrString{Type: intstr.String, StrVal: "http"},
				},
				{Protocol: func() *v1.Protocol { a := v1.ProtocolTCP; return &a }(),
					Port: &intstr.IntOrString{Type: intstr.String, StrVal: "https"},
				},
			}, nil),
		}, allPolicyTypes)

	// "http" resolves to ports 80 and 8080 (two pods with different container ports)
	cont.indexMutex.Lock()
	cont.targetPortIndex["tcp-name-http"] = &portIndexEntry{
		port: targetPort{
			proto: "tcp",
			ports: map[int]bool{80: true, 8080: true},
		},
		serviceKeys:       make(map[string]bool),
		networkPolicyKeys: make(map[string]bool),
	}
	// "https" resolves to port 443
	cont.targetPortIndex["tcp-name-https"] = &portIndexEntry{
		port: targetPort{
			proto: "tcp",
			ports: map[int]bool{443: true},
		},
		serviceKeys:       make(map[string]bool),
		networkPolicyKeys: make(map[string]bool),
	}
	cont.indexMutex.Unlock()

	subj := &hppv1.HostprotSubj{}
	cont.buildLocalNetPolSubjRules("0", subj, "egress",
		nil, nil, np.Spec.Egress[0].Ports, cont.log.WithField("test", "egress-multi-named"),
		"testns/np1", np, nil)

	// Expect 3 rules: http→80, http→8080, https→443
	assert.Equal(t, 3, len(subj.HostprotRule),
		"Should have 3 rules: http resolves to 80+8080, https to 443")

	// Verify all rule names are unique
	ruleNames := make(map[string]bool)
	for _, rule := range subj.HostprotRule {
		assert.False(t, ruleNames[rule.Name], "Duplicate rule name: %s", rule.Name)
		ruleNames[rule.Name] = true
		assert.Equal(t, "egress", rule.Direction)
		assert.Equal(t, "tcp", rule.Protocol)
	}

	// Verify all expected ports are present
	ports := make(map[string]bool)
	for _, rule := range subj.HostprotRule {
		ports[rule.FromPort] = true
	}
	assert.True(t, ports["80"], "Port 80 should be present")
	assert.True(t, ports["8080"], "Port 8080 should be present")
	assert.True(t, ports["443"], "Port 443 should be present")
}

// TestBuildLocalNetPolSubjRulesIngressNamedPort tests that buildLocalNetPolSubjRules
// correctly resolves a named ingress port via pod selector in HppDirect mode.
// The named port "http" resolves to 8080 from matching pods' container ports.
func TestBuildLocalNetPolSubjRulesIngressNamedPort(t *testing.T) {
	cont := getContWithEnabledLocalHpp()
	cont.run()
	defer cont.stop()

	np := netpol("testns", "np1", &metav1.LabelSelector{
		MatchLabels: map[string]string{"app": "target"},
	},
		[]v1net.NetworkPolicyIngressRule{
			{
				Ports: []v1net.NetworkPolicyPort{
					{Protocol: func() *v1.Protocol { a := v1.ProtocolTCP; return &a }(),
						Port: &intstr.IntOrString{Type: intstr.String, StrVal: "http"},
					},
				},
				From: []v1net.NetworkPolicyPeer{
					{
						PodSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"app": "client"},
						},
					},
				},
			},
		}, nil, allPolicyTypes)

	// Add pod matching the network policy's podSelector
	pod := &v1.Pod{
		Spec: v1.PodSpec{
			NodeName: "test-node",
			Containers: []v1.Container{
				{
					Ports: []v1.ContainerPort{
						{Name: "http", ContainerPort: int32(8080)},
					},
				},
			},
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "testns",
			Name:      "target-pod",
			Labels:    map[string]string{"app": "target"},
		},
	}
	cont.fakePodSource.Add(pod)
	cont.fakeNetworkPolicySource.Add(np)

	// Wait for pod/np to be processed and port cache to be populated
	tu.WaitFor(t, "port-cache", 500*time.Millisecond,
		func(last bool) (bool, error) {
			cont.indexMutex.Lock()
			defer cont.indexMutex.Unlock()
			if len(cont.ctrPortNameCache) == 0 {
				return false, nil
			}
			return true, nil
		})

	npKey := "testns/np1"
	podKeys := cont.netPolPods.GetPodForObj(npKey)
	portMap := cont.getPortNumsFromPortName(podKeys, "http")

	peerSelectors := []*metav1.LabelSelector{
		np.Spec.Ingress[0].From[0].PodSelector,
	}

	subj := &hppv1.HostprotSubj{}
	cont.buildLocalNetPolSubjRules("0", subj, "ingress",
		[]string{"testns"}, peerSelectors, np.Spec.Ingress[0].Ports,
		cont.log.WithField("test", "ingress-named-port"), npKey, np, nil)

	// Named port "http" should resolve to 8080 from pod's container port
	assert.True(t, portMap[8080], "Port 8080 should be in portMap from pod")
	if len(subj.HostprotRule) > 0 {
		assert.Equal(t, "ingress", subj.HostprotRule[0].Direction)
		assert.Equal(t, "tcp", subj.HostprotRule[0].Protocol)
		assert.Equal(t, "8080", subj.HostprotRule[0].FromPort)
	}
}

// TestBuildLocalServiceAugmentNamedPort tests that buildServiceAugment correctly
// produces local HostprotRule entries (not APIC objects) for service augmentation
// with named ports in HppDirect mode.
func TestBuildLocalServiceAugmentNamedPort(t *testing.T) {
	cont := getContWithEnabledLocalHpp()
	cont.run()
	defer cont.stop()

	logger := cont.log.WithField("test", "local-svc-augment-named-port")

	// Set up service in the indexer
	service := npservice("testns", "service1", "9.0.0.42",
		[]v1.ServicePort{
			servicePortNamed("http", v1.ProtocolTCP, 8080, "http"),
		})
	cont.fakeServiceSource.Add(service)

	// Wait for service to be indexed
	tu.WaitFor(t, "service-index", 500*time.Millisecond,
		func(last bool) (bool, error) {
			obj, _, err := cont.serviceIndexer.GetByKey("testns/service1")
			if err != nil || obj == nil {
				return false, nil
			}
			return true, nil
		})

	svcKey := "testns/service1"

	// Populate targetPortIndex with named port entry that references the service
	cont.indexMutex.Lock()
	cont.targetPortIndex["tcp-name-http"] = &portIndexEntry{
		port: targetPort{
			proto: "tcp",
			ports: map[int]bool{80: true},
		},
		serviceKeys:       map[string]bool{svcKey: true},
		networkPolicyKeys: make(map[string]bool),
	}
	// Also add numeric port entry for the resolved port
	cont.targetPortIndex["tcp-num-80"] = &portIndexEntry{
		port: targetPort{
			proto: "tcp",
			ports: map[int]bool{80: true},
		},
		serviceKeys:       map[string]bool{svcKey: true},
		networkPolicyKeys: make(map[string]bool),
	}
	// Set up namedPortServiceIndex
	httpEntry := &namedPortServiceIndexPort{
		targetPortName: "http",
		resolvedPorts:  map[int]bool{80: true},
	}
	svcEntry := &namedPortServiceIndexEntry{"http": httpEntry}
	cont.namedPortServiceIndex[svcKey] = svcEntry
	cont.indexMutex.Unlock()

	// Build service augment with named port
	localsubj := &hppv1.HostprotSubj{}
	portRemoteSubs := map[string]*portRemoteSubnet{
		"tcp-name-http": {
			port: &v1net.NetworkPolicyPort{
				Protocol: func() *v1.Protocol { a := v1.ProtocolTCP; return &a }(),
				Port:     &intstr.IntOrString{Type: intstr.String, StrVal: "http"},
			},
			subnetMap:      map[string]bool{"0.0.0.0/0": true},
			hasNamedTarget: true,
		},
	}

	cont.buildServiceAugment(nil, localsubj, portRemoteSubs, logger)

	// Should produce a local rule for service ClusterIP:port
	assert.GreaterOrEqual(t, len(localsubj.HostprotRule), 1,
		"Should have at least 1 service augment rule")

	// Find the service augment rule
	found := false
	for _, rule := range localsubj.HostprotRule {
		if rule.FromPort == "8080" && rule.Protocol == "tcp" {
			found = true
			assert.Equal(t, "egress", rule.Direction)
			assert.Equal(t, "ipv4", rule.Ethertype)
			// In HppDirect mode, remote IPs go to HostprotServiceRemoteIps
			assert.Contains(t, rule.HostprotServiceRemoteIps, "9.0.0.42",
				"Service ClusterIP should be in remote IPs")
			break
		}
	}
	assert.True(t, found, "Should find service augment rule with port 8080")
}
