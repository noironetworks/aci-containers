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

func servicePort(name string, proto v1.Protocol, port int32, targetPort int) v1.ServicePort {
	return v1.ServicePort{
		Name:       name,
		Protocol:   proto,
		Port:       port,
		TargetPort: intstr.FromInt(targetPort),
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
					nt.netPol.Namespace+"_"+nt.netPol.Name)
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

	rule_0_0 := apicapi.NewHostprotRule(np1SDnI, "0-ipv4")
	rule_0_0.SetAttr("direction", "ingress")
	rule_0_0.SetAttr("ethertype", "ipv4")

	rule_1_0 := apicapi.NewHostprotRule(np1SDnI, "0_0-ipv4")
	rule_1_0.SetAttr("direction", "ingress")
	rule_1_0.SetAttr("ethertype", "ipv4")
	rule_1_0.SetAttr("protocol", "tcp")
	rule_1_0.SetAttr("toPort", "80")

	rule_2_0 := apicapi.NewHostprotRule(np1SDnI, "0_0-ipv4")
	rule_2_0.SetAttr("direction", "ingress")
	rule_2_0.SetAttr("ethertype", "ipv4")
	rule_2_0.SetAttr("protocol", "tcp")
	rule_2_0.SetAttr("toPort", "80")
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

	rule_3_0 := apicapi.NewHostprotRule(np1SDnI, "0_0-ipv4")
	rule_3_0.SetAttr("direction", "ingress")
	rule_3_0.SetAttr("ethertype", "ipv4")
	rule_3_0.SetAttr("protocol", "udp")
	rule_3_0.SetAttr("toPort", "80")

	rule_3_1 := apicapi.NewHostprotRule(np1SDnI, "0_0-ipv4")
	rule_3_1.SetAttr("direction", "ingress")
	rule_3_1.SetAttr("ethertype", "ipv4")
	rule_3_1.SetAttr("protocol", "udp")
	rule_3_1.SetAttr("toPort", "unspecified")

	rule_4_1 := apicapi.NewHostprotRule(np1SDnI, "0_1-ipv4")
	rule_4_1.SetAttr("direction", "ingress")
	rule_4_1.SetAttr("ethertype", "ipv4")
	rule_4_1.SetAttr("protocol", "tcp")
	rule_4_1.SetAttr("toPort", "443")

	rule_5_0 := apicapi.NewHostprotRule(np1SDnI, "0-ipv4")
	rule_5_0.SetAttr("direction", "ingress")
	rule_5_0.SetAttr("ethertype", "ipv4")
	rule_5_0.AddChild(apicapi.NewHostprotRemoteIp(rule_5_0.GetDn(), "1.1.1.1"))
	rule_5_0.AddChild(apicapi.NewHostprotRemoteIp(rule_5_0.GetDn(), "1.1.1.2"))

	rule_6_0 := apicapi.NewHostprotRule(np1SDnI, "0-ipv4")
	rule_6_0.SetAttr("direction", "ingress")
	rule_6_0.SetAttr("ethertype", "ipv4")
	rule_6_0.AddChild(apicapi.NewHostprotRemoteIp(rule_6_0.GetDn(), "1.1.1.3"))
	rule_6_0.AddChild(apicapi.NewHostprotRemoteIp(rule_6_0.GetDn(), "1.1.1.4"))
	rule_6_0.AddChild(apicapi.NewHostprotRemoteIp(rule_6_0.GetDn(), "1.1.1.5"))

	rule_7_0 := apicapi.NewHostprotRule(np1SDnI, "0-ipv4")
	rule_7_0.SetAttr("direction", "ingress")
	rule_7_0.SetAttr("ethertype", "ipv4")
	rule_7_0.AddChild(apicapi.NewHostprotRemoteIp(rule_7_0.GetDn(), "1.1.1.1"))

	rule_8_0 := apicapi.NewHostprotRule(np1SDnI, "0_0-ipv4")
	rule_8_0.SetAttr("direction", "ingress")
	rule_8_0.SetAttr("ethertype", "ipv4")
	rule_8_0.SetAttr("protocol", "tcp")
	rule_8_0.SetAttr("toPort", "80")
	rule_8_0.AddChild(apicapi.NewHostprotRemoteIp(rule_8_0.GetDn(), "1.1.1.1"))
	rule_8_1 := apicapi.NewHostprotRule(np1SDnI, "1_0-ipv4")
	rule_8_1.SetAttr("direction", "ingress")
	rule_8_1.SetAttr("ethertype", "ipv4")
	rule_8_1.SetAttr("protocol", "tcp")
	rule_8_1.SetAttr("toPort", "443")
	rule_8_1.AddChild(apicapi.NewHostprotRemoteIp(rule_8_1.GetDn(), "1.1.1.2"))

	rule_9_0 := apicapi.NewHostprotRule(np1SDnI, "0-ipv4")
	rule_9_0.SetAttr("direction", "ingress")
	rule_9_0.SetAttr("ethertype", "ipv4")
	rule_9_0.AddChild(apicapi.NewHostprotRemoteIp(rule_9_0.GetDn(), "1.1.1.3"))
	rule_9_0.AddChild(apicapi.NewHostprotRemoteIp(rule_9_0.GetDn(), "1.1.1.5"))

	rule_10_0 := apicapi.NewHostprotRule(np1SDnE, "0-ipv4")
	rule_10_0.SetAttr("direction", "egress")
	rule_10_0.SetAttr("ethertype", "ipv4")
	rule_10_0.AddChild(apicapi.NewHostprotRemoteIp(rule_10_0.GetDn(), "1.1.1.3"))
	rule_10_0.AddChild(apicapi.NewHostprotRemoteIp(rule_10_0.GetDn(), "1.1.1.5"))

	rule_11_0 := apicapi.NewHostprotRule(np1SDnE, "0_0-ipv4")
	rule_11_0.SetAttr("direction", "egress")
	rule_11_0.SetAttr("ethertype", "ipv4")
	rule_11_0.SetAttr("protocol", "tcp")
	rule_11_0.SetAttr("toPort", "80")
	rule_11_0.AddChild(apicapi.NewHostprotRemoteIp(rule_11_0.GetDn(), "1.1.1.1"))

	rule_11_s := apicapi.NewHostprotRule(np1SDnE, "service_tcp_8080-ipv4")
	rule_11_s.SetAttr("direction", "egress")
	rule_11_s.SetAttr("ethertype", "ipv4")
	rule_11_s.SetAttr("protocol", "tcp")
	rule_11_s.SetAttr("toPort", "8080")
	rule_11_s.AddChild(apicapi.NewHostprotRemoteIp(rule_11_s.GetDn(), "9.0.0.42"))

	rule_12_0 := apicapi.NewHostprotRule(np1SDnE, "0-ipv4")
	rule_12_0.SetAttr("direction", "egress")
	rule_12_0.SetAttr("ethertype", "ipv4")
	rule_12_0.AddChild(apicapi.NewHostprotRemoteIp(rule_12_0.GetDn(),
		"1.1.1.0/24"))

	rule_12_s_0 := apicapi.NewHostprotRule(np1SDnE, "service_tcp_8080-ipv4")
	rule_12_s_0.SetAttr("direction", "egress")
	rule_12_s_0.SetAttr("ethertype", "ipv4")
	rule_12_s_0.SetAttr("protocol", "tcp")
	rule_12_s_0.SetAttr("toPort", "8080")
	rule_12_s_0.AddChild(apicapi.NewHostprotRemoteIp(rule_12_s_0.GetDn(),
		"9.0.0.44"))

	rule_12_s_1 := apicapi.NewHostprotRule(np1SDnE, "service_tcp_8443-ipv4")
	rule_12_s_1.SetAttr("direction", "egress")
	rule_12_s_1.SetAttr("ethertype", "ipv4")
	rule_12_s_1.SetAttr("protocol", "tcp")
	rule_12_s_1.SetAttr("toPort", "8443")
	rule_12_s_1.AddChild(apicapi.NewHostprotRemoteIp(rule_12_s_1.GetDn(),
		"9.0.0.44"))

	rule_13_0 := apicapi.NewHostprotRule(np1SDnE, "0-ipv4")
	rule_13_0.SetAttr("direction", "egress")
	rule_13_0.SetAttr("ethertype", "ipv4")

	rule_14_0 := apicapi.NewHostprotRule(np1SDnE, "0_0-ipv4")
	rule_14_0.SetAttr("direction", "egress")
	rule_14_0.SetAttr("ethertype", "ipv4")
	rule_14_0.SetAttr("protocol", "tcp")
	rule_14_0.SetAttr("toPort", "80")

	rule_14_s := apicapi.NewHostprotRule(np1SDnE, "service_tcp_8080-ipv4")
	rule_14_s.SetAttr("direction", "egress")
	rule_14_s.SetAttr("ethertype", "ipv4")
	rule_14_s.SetAttr("protocol", "tcp")
	rule_14_s.SetAttr("toPort", "8080")
	rule_14_s.AddChild(apicapi.NewHostprotRemoteIp(rule_14_s.GetDn(), "9.0.0.42"))

	rule_15_0 := apicapi.NewHostprotRule(np1SDnI, "0_0-ipv4")
	rule_15_0.SetAttr("direction", "ingress")
	rule_15_0.SetAttr("ethertype", "ipv4")
	rule_15_0.SetAttr("protocol", "sctp")
	rule_15_0.SetAttr("toPort", "80")
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
		"protocol": "tcp", "toPort": "80"}
	rule_2 := map[string]string{"direction": "ingress", "ethertype": "ipv4",
		"protocol": "udp", "toPort": "80"}
	rule_3 := map[string]string{"direction": "ingress", "ethertype": "ipv4",
		"protocol": "tcp", "toPort": "443"}
	rule_4 := map[string]string{"direction": "ingress", "ethertype": "ipv4",
		"protocol": "sctp", "toPort": "80"}

	rule_5 := map[string]string{"direction": "egress", "ethertype": "ipv4"}
	rule_6 := map[string]string{"direction": "egress", "ethertype": "ipv4",
		"protocol": "tcp", "toPort": "80"}
	rule_7 := map[string]string{"direction": "egress", "ethertype": "ipv4",
		"protocol": "tcp", "toPort": "8080"}
	rule_8 := map[string]string{"direction": "egress", "ethertype": "ipv4",
		"protocol": "tcp", "toPort": "8443"}

	//allow-all
	test0_np := netpol("testns", "np1", &metav1.LabelSelector{},
		[]v1net.NetworkPolicyIngressRule{ingressRule(nil, nil)},
		nil, allPolicyTypes)
	hash, _ := util.CreateHashFromNetPol(test0_np)
	test0_np_name := "kube_np_" + hash
	test0_rule := createRule(test0_np_name, true, rule_0, "0-ipv4")

	//allow-http
	test1_np := netpol("testns", "np1", &metav1.LabelSelector{},
		[]v1net.NetworkPolicyIngressRule{
			ingressRule([]v1net.NetworkPolicyPort{port(&tcp, &port80)},
				nil)}, nil, allPolicyTypes)
	hash, _ = util.CreateHashFromNetPol(test1_np)
	test1_np_name := "kube_np_" + hash
	test1_rule := createRule(test1_np_name, true, rule_1, "0_0-ipv4")

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
	test2_rule := createRule(test2_np_name, true, rule_1, "0_0-ipv4")
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
	test3_rule := createRule(test3_np_name, true, rule_1, "0_0-ipv4")

	//allow-80-udp
	test4_np := netpol("testns", "np1", &metav1.LabelSelector{},
		[]v1net.NetworkPolicyIngressRule{
			ingressRule([]v1net.NetworkPolicyPort{
				port(&udp, &port80)}, nil)}, nil, allPolicyTypes)
	hash, _ = util.CreateHashFromNetPol(test4_np)
	test4_np_name := "kube_np_" + hash
	test4_rule := createRule(test4_np_name, true, rule_2, "0_0-ipv4")

	//allow-80-sctp
	test5_np := netpol("testns", "np1", &metav1.LabelSelector{},
		[]v1net.NetworkPolicyIngressRule{
			ingressRule([]v1net.NetworkPolicyPort{
				port(&sctp, &port80)}, nil)}, nil, allPolicyTypes)
	hash, _ = util.CreateHashFromNetPol(test5_np)
	test5_np_name := "kube_np_" + hash
	test5_rule := createRule(test5_np_name, true, rule_4, "0_0-ipv4")

	//allow-http-https
	test6_np := netpol("testns", "np1", &metav1.LabelSelector{},
		[]v1net.NetworkPolicyIngressRule{
			ingressRule([]v1net.NetworkPolicyPort{
				port(nil, &port80), port(nil, &port443),
			}, nil)}, nil, allPolicyTypes)
	hash, _ = util.CreateHashFromNetPol(test6_np)
	test6_np_name := "kube_np_" + hash
	test6_rule1 := createRule(test6_np_name, true, rule_1, "0_0-ipv4")
	test6_rule2 := createRule(test6_np_name, true, rule_3, "0_1-ipv4")

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
	test7_rule := createRule(test7_np_name, true, rule_0, "0-ipv4")
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
	test9_rule := createRule(test9_np_name, true, rule_0, "0-ipv4")
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
	test10_rule := createRule(test10_np_name, true, rule_0, "0-ipv4")
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
	test11_rule := createRule(test11_np_name, true, rule_0, "0-ipv4")
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
	test12_rule1 := createRule(test12_np_name, true, rule_1, "0_0-ipv4")
	test12_rule1.AddChild(apicapi.NewHostprotRemoteIp(test12_rule1.GetDn(), "1.1.1.1"))
	test12_rule2 := createRule(test12_np_name, true, rule_3, "1_0-ipv4")
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
	test13_rule1 := createRule(test13_np_name, true, rule_1, "0_0-ipv4")
	test13_rule1.AddChild(apicapi.NewHostprotRemoteIp(test13_rule1.GetDn(), "1.1.1.1"))
	test13_rule2 := createRule(test13_np_name, true, rule_3, "1_0-ipv4")
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
	test14_rule := createRule(test14_np_name, false, rule_5, "0-ipv4")
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
	test15_rule := createRule(test15_np_name, false, rule_6, "0_0-ipv4")
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
	test16_rule1 := createRule(test16_np_name, false, rule_6, "0_0-ipv4")
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
	test17_rule1 := createRule(test17_np_name, false, rule_6, "0_0-ipv4")
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
	test18_rule1 := createRule(test18_np_name, false, rule_6, "0_0-ipv4")
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
	test19_rule1 := createRule(test19_np_name, false, rule_5, "0-ipv4")
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
	test20_rule := createRule(test20_np_name, false, rule_5, "0-ipv4")

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

	rule_0_0_v6 := apicapi.NewHostprotRule(npv6SDnI, "0-ipv6")
	rule_0_0_v6.SetAttr("direction", "ingress")
	rule_0_0_v6.SetAttr("ethertype", "ipv6")

	rule_1_0_v6 := apicapi.NewHostprotRule(npv6SDnI, "0_0-ipv6")
	rule_1_0_v6.SetAttr("direction", "ingress")
	rule_1_0_v6.SetAttr("ethertype", "ipv6")
	rule_1_0_v6.SetAttr("protocol", "tcp")
	rule_1_0_v6.SetAttr("toPort", "80")

	rule_2_0_v6 := apicapi.NewHostprotRule(npv6SDnI, "0_0-ipv6")
	rule_2_0_v6.SetAttr("direction", "ingress")
	rule_2_0_v6.SetAttr("ethertype", "ipv6")
	rule_2_0_v6.SetAttr("protocol", "tcp")
	rule_2_0_v6.SetAttr("toPort", "80")
	rule_2_0_v6.AddChild(
		apicapi.NewHostprotRemoteIp(rule_2_0_v6.GetDn(), "2001:db8::/128"))
	rule_2_0_v6.AddChild(
		apicapi.NewHostprotRemoteIp(rule_2_0_v6.GetDn(), "2001:db8::2/127"))
	rule_2_0_v6.AddChild(
		apicapi.NewHostprotRemoteIp(rule_2_0_v6.GetDn(), "2001:db8::4/126"))

	rule_3_0_v6 := apicapi.NewHostprotRule(npv6SDnI, "0_0-ipv6")
	rule_3_0_v6.SetAttr("direction", "ingress")
	rule_3_0_v6.SetAttr("ethertype", "ipv6")
	rule_3_0_v6.SetAttr("protocol", "udp")
	rule_3_0_v6.SetAttr("toPort", "80")

	rule_4_1_v6 := apicapi.NewHostprotRule(npv6SDnI, "0_1-ipv6")
	rule_4_1_v6.SetAttr("direction", "ingress")
	rule_4_1_v6.SetAttr("ethertype", "ipv6")
	rule_4_1_v6.SetAttr("protocol", "tcp")
	rule_4_1_v6.SetAttr("toPort", "443")

	rule_5_0_v6 := apicapi.NewHostprotRule(npv6SDnI, "0-ipv6")
	rule_5_0_v6.SetAttr("direction", "ingress")
	rule_5_0_v6.SetAttr("ethertype", "ipv6")
	rule_5_0_v6.AddChild(apicapi.NewHostprotRemoteIp(rule_5_0_v6.GetDn(), "2001::2"))
	rule_5_0_v6.AddChild(apicapi.NewHostprotRemoteIp(rule_5_0_v6.GetDn(), "2001::3"))

	rule_6_0_v6 := apicapi.NewHostprotRule(npv6SDnI, "0-ipv6")
	rule_6_0_v6.SetAttr("direction", "ingress")
	rule_6_0_v6.SetAttr("ethertype", "ipv6")
	rule_6_0_v6.AddChild(apicapi.NewHostprotRemoteIp(rule_6_0_v6.GetDn(), "2001::4"))
	rule_6_0_v6.AddChild(apicapi.NewHostprotRemoteIp(rule_6_0_v6.GetDn(), "2001::5"))
	rule_6_0_v6.AddChild(apicapi.NewHostprotRemoteIp(rule_6_0_v6.GetDn(), "2001::6"))

	rule_7_0_v6 := apicapi.NewHostprotRule(npv6SDnI, "0-ipv6")
	rule_7_0_v6.SetAttr("direction", "ingress")
	rule_7_0_v6.SetAttr("ethertype", "ipv6")
	rule_7_0_v6.AddChild(apicapi.NewHostprotRemoteIp(rule_7_0_v6.GetDn(), "2001::2"))

	rule_8_0_v6 := apicapi.NewHostprotRule(npv6SDnI, "0_0-ipv6")
	rule_8_0_v6.SetAttr("direction", "ingress")
	rule_8_0_v6.SetAttr("ethertype", "ipv6")
	rule_8_0_v6.SetAttr("protocol", "tcp")
	rule_8_0_v6.SetAttr("toPort", "80")
	rule_8_0_v6.AddChild(apicapi.NewHostprotRemoteIp(rule_8_0_v6.GetDn(), "2001::2"))
	rule_8_1_v6 := apicapi.NewHostprotRule(npv6SDnI, "1_0-ipv6")
	rule_8_1_v6.SetAttr("direction", "ingress")
	rule_8_1_v6.SetAttr("ethertype", "ipv6")
	rule_8_1_v6.SetAttr("protocol", "tcp")
	rule_8_1_v6.SetAttr("toPort", "443")
	rule_8_1_v6.AddChild(apicapi.NewHostprotRemoteIp(rule_8_1_v6.GetDn(), "2001::3"))

	rule_9_0_v6 := apicapi.NewHostprotRule(npv6SDnI, "0-ipv6")
	rule_9_0_v6.SetAttr("direction", "ingress")
	rule_9_0_v6.SetAttr("ethertype", "ipv6")
	rule_9_0_v6.AddChild(apicapi.NewHostprotRemoteIp(rule_9_0_v6.GetDn(), "2001::4"))
	rule_9_0_v6.AddChild(apicapi.NewHostprotRemoteIp(rule_9_0_v6.GetDn(), "2001::6"))

	rule_10_0_v6 := apicapi.NewHostprotRule(npv6SDnE, "0-ipv6")
	rule_10_0_v6.SetAttr("direction", "egress")
	rule_10_0_v6.SetAttr("ethertype", "ipv6")
	rule_10_0_v6.AddChild(apicapi.NewHostprotRemoteIp(rule_10_0_v6.GetDn(), "2001::4"))
	rule_10_0_v6.AddChild(apicapi.NewHostprotRemoteIp(rule_10_0_v6.GetDn(), "2001::6"))

	rule_11_0_v6 := apicapi.NewHostprotRule(npv6SDnE, "0_0-ipv6")
	rule_11_0_v6.SetAttr("direction", "egress")
	rule_11_0_v6.SetAttr("ethertype", "ipv6")
	rule_11_0_v6.SetAttr("protocol", "tcp")
	rule_11_0_v6.SetAttr("toPort", "80")
	rule_11_0_v6.AddChild(apicapi.NewHostprotRemoteIp(rule_11_0_v6.GetDn(), "2001::2"))

	rule_11_s_v6 := apicapi.NewHostprotRule(npv6SDnE, "service_tcp_8080-ipv6")
	rule_11_s_v6.SetAttr("direction", "egress")
	rule_11_s_v6.SetAttr("ethertype", "ipv6")
	rule_11_s_v6.SetAttr("protocol", "tcp")
	rule_11_s_v6.SetAttr("toPort", "8080")
	rule_11_s_v6.AddChild(apicapi.NewHostprotRemoteIp(rule_11_s_v6.GetDn(), "fd00::1234"))

	rule_12_0_v6 := apicapi.NewHostprotRule(npv6SDnE, "0-ipv6")
	rule_12_0_v6.SetAttr("direction", "egress")
	rule_12_0_v6.SetAttr("ethertype", "ipv6")
	rule_12_0_v6.AddChild(apicapi.NewHostprotRemoteIp(rule_12_0_v6.GetDn(),
		"2001::/64"))

	rule_12_s_0_v6 := apicapi.NewHostprotRule(npv6SDnE, "service_tcp_8080-ipv6")
	rule_12_s_0_v6.SetAttr("direction", "egress")
	rule_12_s_0_v6.SetAttr("ethertype", "ipv6")
	rule_12_s_0_v6.SetAttr("protocol", "tcp")
	rule_12_s_0_v6.SetAttr("toPort", "8080")
	rule_12_s_0_v6.AddChild(apicapi.NewHostprotRemoteIp(rule_12_s_0_v6.GetDn(),
		"fd00::1236"))

	rule_12_s_1_v6 := apicapi.NewHostprotRule(npv6SDnE, "service_tcp_8443-ipv6")
	rule_12_s_1_v6.SetAttr("direction", "egress")
	rule_12_s_1_v6.SetAttr("ethertype", "ipv6")
	rule_12_s_1_v6.SetAttr("protocol", "tcp")
	rule_12_s_1_v6.SetAttr("toPort", "8443")
	rule_12_s_1_v6.AddChild(apicapi.NewHostprotRemoteIp(rule_12_s_1_v6.GetDn(),
		"fd00::1236"))

	rule_13_0_v6 := apicapi.NewHostprotRule(npv6SDnE, "0-ipv6")
	rule_13_0_v6.SetAttr("direction", "egress")
	rule_13_0_v6.SetAttr("ethertype", "ipv6")

	rule_14_0_v6 := apicapi.NewHostprotRule(npv6SDnE, "0_0-ipv6")
	rule_14_0_v6.SetAttr("direction", "egress")
	rule_14_0_v6.SetAttr("ethertype", "ipv6")
	rule_14_0_v6.SetAttr("protocol", "tcp")
	rule_14_0_v6.SetAttr("toPort", "80")

	rule_14_s_v6 := apicapi.NewHostprotRule(npv6SDnE, "service_tcp_8080-ipv6")
	rule_14_s_v6.SetAttr("direction", "egress")
	rule_14_s_v6.SetAttr("ethertype", "ipv6")
	rule_14_s_v6.SetAttr("protocol", "tcp")
	rule_14_s_v6.SetAttr("toPort", "8080")
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
		"protocol": "tcp", "toPort": "80"}
	rule_2_v6 := map[string]string{"direction": "ingress", "ethertype": "ipv6",
		"protocol": "udp", "toPort": "80"}
	rule_3_v6 := map[string]string{"direction": "ingress", "ethertype": "ipv6",
		"protocol": "tcp", "toPort": "443"}

	rule_4_v6 := map[string]string{"direction": "egress", "ethertype": "ipv6"}
	rule_5_v6 := map[string]string{"direction": "egress", "ethertype": "ipv6",
		"protocol": "tcp", "toPort": "80"}
	rule_6_v6 := map[string]string{"direction": "egress", "ethertype": "ipv6",
		"protocol": "tcp", "toPort": "8080"}
	rule_7_v6 := map[string]string{"direction": "egress", "ethertype": "ipv6",
		"protocol": "tcp", "toPort": "8443"}

	//v6-np-allow-all
	test0_np_v6 := netpol("testnsv6", "npv6", &metav1.LabelSelector{},
		[]v1net.NetworkPolicyIngressRule{ingressRule(nil, nil)},
		nil, allPolicyTypes)
	hash, _ := util.CreateHashFromNetPol(test0_np_v6)
	test0_np_name_v6 := "kube_np_" + hash
	test0_rule_v6 := createRule(test0_np_name_v6, true, rule_0_v6, "0-ipv6")

	//allow-http
	test1_np_v6 := netpol("testnsv6", "npv6", &metav1.LabelSelector{},
		[]v1net.NetworkPolicyIngressRule{
			ingressRule([]v1net.NetworkPolicyPort{port(&tcp, &port80)},
				nil)}, nil, allPolicyTypes)
	hash, _ = util.CreateHashFromNetPol(test1_np_v6)
	test1_np_name_v6 := "kube_np_" + hash
	test1_rule_v6 := createRule(test1_np_name_v6, true, rule_1_v6, "0_0-ipv6")

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
	test2_rule_v6 := createRule(test2_np_name_v6, true, rule_1_v6, "0_0-ipv6")
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
	test3_rule_v6 := createRule(test3_np_name_v6, true, rule_1_v6, "0_0-ipv6")

	//allow-80-udp
	test4_np_v6 := netpol("testnsv6", "npv6", &metav1.LabelSelector{},
		[]v1net.NetworkPolicyIngressRule{
			ingressRule([]v1net.NetworkPolicyPort{
				port(&udp, &port80)}, nil)}, nil, allPolicyTypes)
	hash, _ = util.CreateHashFromNetPol(test4_np_v6)
	test4_np_name_v6 := "kube_np_" + hash
	test4_rule_v6 := createRule(test4_np_name_v6, true, rule_2_v6, "0_0-ipv6")

	//allow-http-https
	test5_np_v6 := netpol("testnsv6", "npv6", &metav1.LabelSelector{},
		[]v1net.NetworkPolicyIngressRule{
			ingressRule([]v1net.NetworkPolicyPort{
				port(nil, &port80), port(nil, &port443),
			}, nil)}, nil, allPolicyTypes)
	hash, _ = util.CreateHashFromNetPol(test5_np_v6)
	test5_np_name_v6 := "kube_np_" + hash
	test5_rule1_v6 := createRule(test5_np_name_v6, true, rule_1_v6, "0_0-ipv6")
	test5_rule2_v6 := createRule(test5_np_name_v6, true, rule_3_v6, "0_1-ipv6")

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
	test6_rule_v6 := createRule(test6_np_name_v6, true, rule_0_v6, "0-ipv6")
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
	test8_rule_v6 := createRule(test8_np_name_v6, true, rule_0_v6, "0-ipv6")
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
	test9_rule_v6 := createRule(test9_np_name_v6, true, rule_0_v6, "0-ipv6")
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
	test10_rule_v6 := createRule(test10_np_name_v6, true, rule_0_v6, "0-ipv6")
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
	test11_rule1_v6 := createRule(test11_np_name_v6, true, rule_1_v6, "0_0-ipv6")
	test11_rule1_v6.AddChild(apicapi.NewHostprotRemoteIp(test11_rule1_v6.GetDn(), "2001::2"))
	test11_rule2_v6 := createRule(test11_np_name_v6, true, rule_3_v6, "1_0-ipv6")
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
	test12_rule_v6 := createRule(test12_np_name_v6, false, rule_4_v6, "0-ipv6")
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
	test13_rule_v6 := createRule(test13_np_name_v6, false, rule_5_v6, "0_0-ipv6")
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
	test14_rule1_v6 := createRule(test14_np_name_v6, false, rule_5_v6, "0_0-ipv6")
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
	test15_rule1_v6 := createRule(test15_np_name_v6, false, rule_5_v6, "0_0-ipv6")
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
	test16_rule1_v6 := createRule(test16_np_name_v6, false, rule_4_v6, "0-ipv6")
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
	test17_rule_v6 := createRule(test17_np_name_v6, false, rule_4_v6, "0-ipv6")

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

	rule_11_0 := apicapi.NewHostprotRule(np1SDnE, "0_0-ipv4")
	rule_11_0.SetAttr("direction", "egress")
	rule_11_0.SetAttr("ethertype", "ipv4")
	rule_11_0.SetAttr("protocol", "tcp")
	rule_11_0.SetAttr("toPort", "80")
	rule_11_0.AddChild(apicapi.NewHostprotRemoteIp(rule_11_0.GetDn(), "1.1.1.1"))

	rule_11_s := apicapi.NewHostprotRule(np1SDnE, "service_tcp_8080-ipv4")
	rule_11_s.SetAttr("direction", "egress")
	rule_11_s.SetAttr("ethertype", "ipv4")
	rule_11_s.SetAttr("protocol", "tcp")
	rule_11_s.SetAttr("toPort", "8080")
	rule_11_s.AddChild(apicapi.NewHostprotRemoteIp(rule_11_s.GetDn(), "9.0.0.42"))

	rule_12_0 := apicapi.NewHostprotRule(np1SDnE, "0-ipv4")
	rule_12_0.SetAttr("direction", "egress")
	rule_12_0.SetAttr("ethertype", "ipv4")
	rule_12_0.AddChild(apicapi.NewHostprotRemoteIp(rule_12_0.GetDn(),
		"1.1.1.0/24"))

	rule_12_s_0 := apicapi.NewHostprotRule(np1SDnE, "service_tcp_8080-ipv4")
	rule_12_s_0.SetAttr("direction", "egress")
	rule_12_s_0.SetAttr("ethertype", "ipv4")
	rule_12_s_0.SetAttr("protocol", "tcp")
	rule_12_s_0.SetAttr("toPort", "8080")
	rule_12_s_0.AddChild(apicapi.NewHostprotRemoteIp(rule_12_s_0.GetDn(),
		"9.0.0.44"))

	rule_12_s_1 := apicapi.NewHostprotRule(np1SDnE, "service_tcp_8443-ipv4")
	rule_12_s_1.SetAttr("direction", "egress")
	rule_12_s_1.SetAttr("ethertype", "ipv4")
	rule_12_s_1.SetAttr("protocol", "tcp")
	rule_12_s_1.SetAttr("toPort", "8443")
	rule_12_s_1.AddChild(apicapi.NewHostprotRemoteIp(rule_12_s_1.GetDn(),
		"9.0.0.44"))

	rule_13_0 := apicapi.NewHostprotRule(np1SDnE, "0-ipv4")
	rule_13_0.SetAttr("direction", "egress")
	rule_13_0.SetAttr("ethertype", "ipv4")

	rule_14_0 := apicapi.NewHostprotRule(np1SDnE, "0_0-ipv4")
	rule_14_0.SetAttr("direction", "egress")
	rule_14_0.SetAttr("ethertype", "ipv4")
	rule_14_0.SetAttr("protocol", "tcp")
	rule_14_0.SetAttr("toPort", "80")

	rule_14_s := apicapi.NewHostprotRule(np1SDnE, "service_tcp_8080-ipv4")
	rule_14_s.SetAttr("direction", "egress")
	rule_14_s.SetAttr("ethertype", "ipv4")
	rule_14_s.SetAttr("protocol", "tcp")
	rule_14_s.SetAttr("toPort", "8080")
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
		"protocol": "tcp", "toPort": "80"}
	rule_7 := map[string]string{"direction": "egress", "ethertype": "ipv4",
		"protocol": "tcp", "toPort": "8080"}
	rule_8 := map[string]string{"direction": "egress", "ethertype": "ipv4",
		"protocol": "tcp", "toPort": "8443"}

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
	test15_rule := createRule(test15_np_name, false, rule_6, "0_0-ipv4")
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
	test16_rule1 := createRule(test16_np_name, false, rule_6, "0_0-ipv4")
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
	test17_rule1 := createRule(test17_np_name, false, rule_6, "0_0-ipv4")
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
	test18_rule1 := createRule(test18_np_name, false, rule_6, "0_0-ipv4")
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
	test19_rule1 := createRule(test19_np_name, false, rule_5, "0-ipv4")
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
	test20_rule := createRule(test20_np_name, false, rule_5, "0-ipv4")

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

	rule_1_0 := apicapi.NewHostprotRule(np1SDnE, "0_0-ipv4")
	rule_1_0.SetAttr("direction", "egress")
	rule_1_0.SetAttr("ethertype", "ipv4")
	rule_1_0.SetAttr("protocol", "tcp")
	rule_1_0.SetAttr("toPort", "80")

	rule_1_s := apicapi.NewHostprotRule(np1SDnE, "service_tcp_8080-ipv4")
	rule_1_s.SetAttr("direction", "egress")
	rule_1_s.SetAttr("ethertype", "ipv4")
	rule_1_s.SetAttr("protocol", "tcp")
	rule_1_s.SetAttr("toPort", "8080")
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
		"protocol": "tcp", "toPort": "80"}
	rule_2 := map[string]string{"direction": "egress", "ethertype": "ipv4",
		"protocol": "tcp", "toPort": "8080"}

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
	test1_rule1 := createRule(test1_np_name, false, rule_1, "0_0-ipv4")
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
				ToPort:              "80",
				FromPort:            "unspecified",
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
				FromPort:  "unspecified",
				ToPort:    "80",
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
				FromPort:            "unspecified",
				ToPort:              "80",
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
			cont.buildLocalNetPolSubjRule(tc.subj, tc.ruleName, tc.direction, tc.ethertype, tc.proto, tc.port, tc.remoteNs, podSelectors, tc.remoteSubnets)
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
	assert.Equal(t, "8080", subj.HostprotRule[0].ToPort)
	assert.Equal(t, "unspecified", subj.HostprotRule[0].FromPort)
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
			FromPort:            "unspecified",
			ToPort:              "8080",
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
				ports: []int{8080},
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
