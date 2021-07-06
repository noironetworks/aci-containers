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
	"testing"
	"time"

	v1betadnsntp "github.com/noironetworks/aci-containers/pkg/dnsnetworkpolicy/apis/dnsnetpolicy/v1beta"
	v1netpol "github.com/noironetworks/aci-containers/pkg/networkpolicy/apis/netpolicy/v1"
	v1 "k8s.io/api/core/v1"
	v1net "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/noironetworks/aci-containers/pkg/apicapi"
	"github.com/noironetworks/aci-containers/pkg/ipam"
	tu "github.com/noironetworks/aci-containers/pkg/testutil"
	"github.com/noironetworks/aci-containers/pkg/util"
	"github.com/stretchr/testify/assert"
	v1beta1 "k8s.io/api/discovery/v1beta1"
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
func endpointSlicePort(proto v1.Protocol, port int32, name string) v1beta1.EndpointPort {
	return v1beta1.EndpointPort{
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
	endpointslices []*v1beta1.EndpointSlice
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
	pods := []*v1.Pod{}
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
	pods = append(pods, podLabel("ns1", "pod3", map[string]string{"l1": "v1"}))
	pods = append(pods, podLabel("ns1", "pod4", map[string]string{"l1": "v2"}))
	pods = append(pods, podLabel("ns2", "pod5", map[string]string{"l1": "v1"}))
	pods = append(pods, podLabel("ns2", "pod6", map[string]string{"l1": "v2"}))
	/*
		ips := []string{
			"1.1.1.1", "1.1.1.2", "1.1.1.3", "1.1.1.4", "1.1.1.5", "",
		}
	*/
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
func makeEpSlice(namespace string, name string, endpoints []v1beta1.Endpoint,
	ports []v1beta1.EndpointPort, servicename string) *v1beta1.EndpointSlice {
	return &v1beta1.EndpointSlice{
		AddressType: v1beta1.AddressTypeIPv4,
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   namespace,
			Labels:      map[string]string{v1beta1.LabelServiceName: servicename},
			Annotations: map[string]string{},
		},
		Endpoints: endpoints,
		Ports:     ports,
	}
}

func checkNp(t *testing.T, nt *npTest, category string, cont *testAciController) {
	tu.WaitFor(t, category+"/"+nt.desc, 2000*time.Millisecond,
		func(last bool) (bool, error) {
			slice := apicapi.ApicSlice{nt.aciObj}
			key := cont.aciNameForKey("np",
				nt.netPol.Namespace+"_"+nt.netPol.Name)
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
			//nt := npTests[0]
			key := cont.aciNameForKey("np",
				nt.netPol.Namespace+"_"+nt.netPol.Name)
			if !tu.WaitEqual(t, last, 0,
				len(cont.apicConn.GetDesiredState(key)), "delete") {
				return false, nil
			}
			return true, nil
		})
}

func TestNetworkPolicy(t *testing.T) {
	name := "kube_np_testns_np1"
	baseDn := makeNp(nil, nil, name).GetDn()
	np1SDnI := fmt.Sprintf("%s/subj-networkpolicy-ingress", baseDn)
	np1SDnE := fmt.Sprintf("%s/subj-networkpolicy-egress", baseDn)

	rule_0_0 := apicapi.NewHostprotRule(np1SDnI, "0")
	rule_0_0.SetAttr("direction", "ingress")
	rule_0_0.SetAttr("ethertype", "ipv4")

	rule_1_0 := apicapi.NewHostprotRule(np1SDnI, "0_0")
	rule_1_0.SetAttr("direction", "ingress")
	rule_1_0.SetAttr("ethertype", "ipv4")
	rule_1_0.SetAttr("protocol", "tcp")
	rule_1_0.SetAttr("toPort", "80")

	rule_2_0 := apicapi.NewHostprotRule(np1SDnI, "0_0")
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

	rule_3_0 := apicapi.NewHostprotRule(np1SDnI, "0_0")
	rule_3_0.SetAttr("direction", "ingress")
	rule_3_0.SetAttr("ethertype", "ipv4")
	rule_3_0.SetAttr("protocol", "udp")
	rule_3_0.SetAttr("toPort", "80")

	rule_4_1 := apicapi.NewHostprotRule(np1SDnI, "0_1")
	rule_4_1.SetAttr("direction", "ingress")
	rule_4_1.SetAttr("ethertype", "ipv4")
	rule_4_1.SetAttr("protocol", "tcp")
	rule_4_1.SetAttr("toPort", "443")

	rule_5_0 := apicapi.NewHostprotRule(np1SDnI, "0")
	rule_5_0.SetAttr("direction", "ingress")
	rule_5_0.SetAttr("ethertype", "ipv4")
	rule_5_0.AddChild(apicapi.NewHostprotRemoteIp(rule_5_0.GetDn(), "1.1.1.1"))
	rule_5_0.AddChild(apicapi.NewHostprotRemoteIp(rule_5_0.GetDn(), "1.1.1.2"))

	rule_6_0 := apicapi.NewHostprotRule(np1SDnI, "0")
	rule_6_0.SetAttr("direction", "ingress")
	rule_6_0.SetAttr("ethertype", "ipv4")
	rule_6_0.AddChild(apicapi.NewHostprotRemoteIp(rule_6_0.GetDn(), "1.1.1.3"))
	rule_6_0.AddChild(apicapi.NewHostprotRemoteIp(rule_6_0.GetDn(), "1.1.1.4"))
	rule_6_0.AddChild(apicapi.NewHostprotRemoteIp(rule_6_0.GetDn(), "1.1.1.5"))

	rule_7_0 := apicapi.NewHostprotRule(np1SDnI, "0")
	rule_7_0.SetAttr("direction", "ingress")
	rule_7_0.SetAttr("ethertype", "ipv4")
	rule_7_0.AddChild(apicapi.NewHostprotRemoteIp(rule_7_0.GetDn(), "1.1.1.1"))

	rule_8_0 := apicapi.NewHostprotRule(np1SDnI, "0_0")
	rule_8_0.SetAttr("direction", "ingress")
	rule_8_0.SetAttr("ethertype", "ipv4")
	rule_8_0.SetAttr("protocol", "tcp")
	rule_8_0.SetAttr("toPort", "80")
	rule_8_0.AddChild(apicapi.NewHostprotRemoteIp(rule_8_0.GetDn(), "1.1.1.1"))
	rule_8_1 := apicapi.NewHostprotRule(np1SDnI, "1_0")
	rule_8_1.SetAttr("direction", "ingress")
	rule_8_1.SetAttr("ethertype", "ipv4")
	rule_8_1.SetAttr("protocol", "tcp")
	rule_8_1.SetAttr("toPort", "443")
	rule_8_1.AddChild(apicapi.NewHostprotRemoteIp(rule_8_1.GetDn(), "1.1.1.2"))

	rule_9_0 := apicapi.NewHostprotRule(np1SDnI, "0")
	rule_9_0.SetAttr("direction", "ingress")
	rule_9_0.SetAttr("ethertype", "ipv4")
	rule_9_0.AddChild(apicapi.NewHostprotRemoteIp(rule_9_0.GetDn(), "1.1.1.3"))
	rule_9_0.AddChild(apicapi.NewHostprotRemoteIp(rule_9_0.GetDn(), "1.1.1.5"))

	rule_10_0 := apicapi.NewHostprotRule(np1SDnE, "0")
	rule_10_0.SetAttr("direction", "egress")
	rule_10_0.SetAttr("ethertype", "ipv4")
	rule_10_0.AddChild(apicapi.NewHostprotRemoteIp(rule_10_0.GetDn(), "1.1.1.3"))
	rule_10_0.AddChild(apicapi.NewHostprotRemoteIp(rule_10_0.GetDn(), "1.1.1.5"))

	rule_11_0 := apicapi.NewHostprotRule(np1SDnE, "0_0")
	rule_11_0.SetAttr("direction", "egress")
	rule_11_0.SetAttr("ethertype", "ipv4")
	rule_11_0.SetAttr("protocol", "tcp")
	rule_11_0.SetAttr("toPort", "80")
	rule_11_0.AddChild(apicapi.NewHostprotRemoteIp(rule_11_0.GetDn(), "1.1.1.1"))

	rule_11_s := apicapi.NewHostprotRule(np1SDnE, "service_tcp_8080")
	rule_11_s.SetAttr("direction", "egress")
	rule_11_s.SetAttr("ethertype", "ipv4")
	rule_11_s.SetAttr("protocol", "tcp")
	rule_11_s.SetAttr("toPort", "8080")
	rule_11_s.AddChild(apicapi.NewHostprotRemoteIp(rule_11_s.GetDn(), "9.0.0.42"))

	rule_12_0 := apicapi.NewHostprotRule(np1SDnE, "0")
	rule_12_0.SetAttr("direction", "egress")
	rule_12_0.SetAttr("ethertype", "ipv4")
	rule_12_0.AddChild(apicapi.NewHostprotRemoteIp(rule_12_0.GetDn(),
		"1.1.1.0/24"))

	rule_12_s_0 := apicapi.NewHostprotRule(np1SDnE, "service_tcp_8080")
	rule_12_s_0.SetAttr("direction", "egress")
	rule_12_s_0.SetAttr("ethertype", "ipv4")
	rule_12_s_0.SetAttr("protocol", "tcp")
	rule_12_s_0.SetAttr("toPort", "8080")
	rule_12_s_0.AddChild(apicapi.NewHostprotRemoteIp(rule_12_s_0.GetDn(),
		"9.0.0.44"))

	rule_12_s_1 := apicapi.NewHostprotRule(np1SDnE, "service_tcp_8443")
	rule_12_s_1.SetAttr("direction", "egress")
	rule_12_s_1.SetAttr("ethertype", "ipv4")
	rule_12_s_1.SetAttr("protocol", "tcp")
	rule_12_s_1.SetAttr("toPort", "8443")
	rule_12_s_1.AddChild(apicapi.NewHostprotRemoteIp(rule_12_s_1.GetDn(),
		"9.0.0.44"))

	rule_13_0 := apicapi.NewHostprotRule(np1SDnE, "0")
	rule_13_0.SetAttr("direction", "egress")
	rule_13_0.SetAttr("ethertype", "ipv4")

	rule_14_0 := apicapi.NewHostprotRule(np1SDnE, "0_0")
	rule_14_0.SetAttr("direction", "egress")
	rule_14_0.SetAttr("ethertype", "ipv4")
	rule_14_0.SetAttr("protocol", "tcp")
	rule_14_0.SetAttr("toPort", "80")

	rule_14_s := apicapi.NewHostprotRule(np1SDnE, "service_tcp_8080")
	rule_14_s.SetAttr("direction", "egress")
	rule_14_s.SetAttr("ethertype", "ipv4")
	rule_14_s.SetAttr("protocol", "tcp")
	rule_14_s.SetAttr("toPort", "8080")
	rule_14_s.AddChild(apicapi.NewHostprotRemoteIp(rule_14_s.GetDn(), "9.0.0.42"))

	rule_15_0 := apicapi.NewHostprotRule(np1SDnI, "0_0")
	rule_15_0.SetAttr("direction", "ingress")
	rule_15_0.SetAttr("ethertype", "ipv4")
	rule_15_0.SetAttr("protocol", "sctp")
	rule_15_0.SetAttr("toPort", "80")
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
				[]*v1beta1.EndpointSlice{},
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
				[]*v1beta1.EndpointSlice{},
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
				[]*v1beta1.EndpointSlice{},
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
				[]*v1beta1.EndpointSlice{},
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
				[]*v1beta1.EndpointSlice{},
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
	for _, nt := range npTests {
		cont := initCont()
		cont.log.Info("Starting podsfirst ", nt.desc)
		addPods(cont, true, ips, true)
		addServices(cont, nt.augment)
		cont.run()
		cont.fakeNetworkPolicySource.Add(util.GetInternalPolicy(nt.netPol))
		checkNp(t, &nt, "podsfirst", cont)

		cont.log.Info("Starting delete ", nt.desc)
		cont.fakeNetworkPolicySource.Delete(util.GetInternalPolicy(nt.netPol))
		checkDelete(t, npTests[0], cont)
		cont.stop()
	}
	for _, nt := range npTests {
		cont := initCont()
		cont.log.Info("Starting npfirst ", nt.desc)
		cont.fakeNetworkPolicySource.Add(util.GetInternalPolicy(nt.netPol))
		cont.run()
		addServices(cont, nt.augment)
		addPods(cont, false, ips, true)
		addPods(cont, true, ips, true)
		checkNp(t, &nt, "npfirst", cont)
		cont.stop()
	}
}

func TestNetworkPolicyv6(t *testing.T) {
	name := "kube_np_testnsv6_npv6"
	baseDn := makeNp(nil, nil, name).GetDn()

	npv6SDnI := fmt.Sprintf("%s/subj-networkpolicy-ingress", baseDn)
	npv6SDnE := fmt.Sprintf("%s/subj-networkpolicy-egress", baseDn)

	rule_0_0_v6 := apicapi.NewHostprotRule(npv6SDnI, "0")
	rule_0_0_v6.SetAttr("direction", "ingress")
	rule_0_0_v6.SetAttr("ethertype", "ipv6")

	rule_1_0_v6 := apicapi.NewHostprotRule(npv6SDnI, "0_0")
	rule_1_0_v6.SetAttr("direction", "ingress")
	rule_1_0_v6.SetAttr("ethertype", "ipv6")
	rule_1_0_v6.SetAttr("protocol", "tcp")
	rule_1_0_v6.SetAttr("toPort", "80")

	rule_2_0_v6 := apicapi.NewHostprotRule(npv6SDnI, "0_0")
	rule_2_0_v6.SetAttr("direction", "ingress")
	rule_2_0_v6.SetAttr("ethertype", "ipv6")
	rule_2_0_v6.SetAttr("protocol", "tcp")
	rule_2_0_v6.SetAttr("toPort", "80")
	rule_2_0_v6.AddChild(
		apicapi.NewHostprotRemoteIp(rule_2_0_v6.GetDn(), "8.8.8.0/29"))
	rule_2_0_v6.AddChild(
		apicapi.NewHostprotRemoteIp(rule_2_0_v6.GetDn(), "8.8.8.10/31"))
	rule_2_0_v6.AddChild(
		apicapi.NewHostprotRemoteIp(rule_2_0_v6.GetDn(), "8.8.8.12/30"))
	rule_2_0_v6.AddChild(
		apicapi.NewHostprotRemoteIp(rule_2_0_v6.GetDn(), "8.8.8.128/25"))
	rule_2_0_v6.AddChild(
		apicapi.NewHostprotRemoteIp(rule_2_0_v6.GetDn(), "8.8.8.16/28"))
	rule_2_0_v6.AddChild(
		apicapi.NewHostprotRemoteIp(rule_2_0_v6.GetDn(), "8.8.8.32/27"))
	rule_2_0_v6.AddChild(
		apicapi.NewHostprotRemoteIp(rule_2_0_v6.GetDn(), "8.8.8.64/26"))

	rule_3_0_v6 := apicapi.NewHostprotRule(npv6SDnI, "0_0")
	rule_3_0_v6.SetAttr("direction", "ingress")
	rule_3_0_v6.SetAttr("ethertype", "ipv6")
	rule_3_0_v6.SetAttr("protocol", "udp")
	rule_3_0_v6.SetAttr("toPort", "80")

	rule_4_1_v6 := apicapi.NewHostprotRule(npv6SDnI, "0_1")
	rule_4_1_v6.SetAttr("direction", "ingress")
	rule_4_1_v6.SetAttr("ethertype", "ipv6")
	rule_4_1_v6.SetAttr("protocol", "tcp")
	rule_4_1_v6.SetAttr("toPort", "443")

	rule_5_0_v6 := apicapi.NewHostprotRule(npv6SDnI, "0")
	rule_5_0_v6.SetAttr("direction", "ingress")
	rule_5_0_v6.SetAttr("ethertype", "ipv6")
	rule_5_0_v6.AddChild(apicapi.NewHostprotRemoteIp(rule_5_0_v6.GetDn(), "2001::2"))
	rule_5_0_v6.AddChild(apicapi.NewHostprotRemoteIp(rule_5_0_v6.GetDn(), "2001::3"))

	rule_6_0_v6 := apicapi.NewHostprotRule(npv6SDnI, "0")
	rule_6_0_v6.SetAttr("direction", "ingress")
	rule_6_0_v6.SetAttr("ethertype", "ipv6")
	rule_6_0_v6.AddChild(apicapi.NewHostprotRemoteIp(rule_6_0_v6.GetDn(), "2001::4"))
	rule_6_0_v6.AddChild(apicapi.NewHostprotRemoteIp(rule_6_0_v6.GetDn(), "2001::5"))
	rule_6_0_v6.AddChild(apicapi.NewHostprotRemoteIp(rule_6_0_v6.GetDn(), "2001::6"))

	rule_7_0_v6 := apicapi.NewHostprotRule(npv6SDnI, "0")
	rule_7_0_v6.SetAttr("direction", "ingress")
	rule_7_0_v6.SetAttr("ethertype", "ipv6")
	rule_7_0_v6.AddChild(apicapi.NewHostprotRemoteIp(rule_7_0_v6.GetDn(), "2001::2"))

	rule_8_0_v6 := apicapi.NewHostprotRule(npv6SDnI, "0_0")
	rule_8_0_v6.SetAttr("direction", "ingress")
	rule_8_0_v6.SetAttr("ethertype", "ipv6")
	rule_8_0_v6.SetAttr("protocol", "tcp")
	rule_8_0_v6.SetAttr("toPort", "80")
	rule_8_0_v6.AddChild(apicapi.NewHostprotRemoteIp(rule_8_0_v6.GetDn(), "2001::2"))
	rule_8_1_v6 := apicapi.NewHostprotRule(npv6SDnI, "1_0")
	rule_8_1_v6.SetAttr("direction", "ingress")
	rule_8_1_v6.SetAttr("ethertype", "ipv6")
	rule_8_1_v6.SetAttr("protocol", "tcp")
	rule_8_1_v6.SetAttr("toPort", "443")
	rule_8_1_v6.AddChild(apicapi.NewHostprotRemoteIp(rule_8_1_v6.GetDn(), "2001::3"))

	rule_9_0_v6 := apicapi.NewHostprotRule(npv6SDnI, "0")
	rule_9_0_v6.SetAttr("direction", "ingress")
	rule_9_0_v6.SetAttr("ethertype", "ipv6")
	rule_9_0_v6.AddChild(apicapi.NewHostprotRemoteIp(rule_9_0_v6.GetDn(), "2001::4"))
	rule_9_0_v6.AddChild(apicapi.NewHostprotRemoteIp(rule_9_0_v6.GetDn(), "2001::6"))

	rule_10_0_v6 := apicapi.NewHostprotRule(npv6SDnE, "0")
	rule_10_0_v6.SetAttr("direction", "egress")
	rule_10_0_v6.SetAttr("ethertype", "ipv6")
	rule_10_0_v6.AddChild(apicapi.NewHostprotRemoteIp(rule_10_0_v6.GetDn(), "2001::4"))
	rule_10_0_v6.AddChild(apicapi.NewHostprotRemoteIp(rule_10_0_v6.GetDn(), "2001::6"))

	rule_11_0_v6 := apicapi.NewHostprotRule(npv6SDnE, "0_0")
	rule_11_0_v6.SetAttr("direction", "egress")
	rule_11_0_v6.SetAttr("ethertype", "ipv6")
	rule_11_0_v6.SetAttr("protocol", "tcp")
	rule_11_0_v6.SetAttr("toPort", "80")
	rule_11_0_v6.AddChild(apicapi.NewHostprotRemoteIp(rule_11_0_v6.GetDn(), "2001::2"))

	rule_11_s_v6 := apicapi.NewHostprotRule(npv6SDnE, "service_tcp_8080")
	rule_11_s_v6.SetAttr("direction", "egress")
	rule_11_s_v6.SetAttr("ethertype", "ipv6")
	rule_11_s_v6.SetAttr("protocol", "tcp")
	rule_11_s_v6.SetAttr("toPort", "8080")
	rule_11_s_v6.AddChild(apicapi.NewHostprotRemoteIp(rule_11_s_v6.GetDn(), "fd00::1234"))

	rule_12_0_v6 := apicapi.NewHostprotRule(npv6SDnE, "0")
	rule_12_0_v6.SetAttr("direction", "egress")
	rule_12_0_v6.SetAttr("ethertype", "ipv6")
	rule_12_0_v6.AddChild(apicapi.NewHostprotRemoteIp(rule_12_0_v6.GetDn(),
		"2001::/64"))

	rule_12_s_0_v6 := apicapi.NewHostprotRule(npv6SDnE, "service_tcp_8080")
	rule_12_s_0_v6.SetAttr("direction", "egress")
	rule_12_s_0_v6.SetAttr("ethertype", "ipv6")
	rule_12_s_0_v6.SetAttr("protocol", "tcp")
	rule_12_s_0_v6.SetAttr("toPort", "8080")
	rule_12_s_0_v6.AddChild(apicapi.NewHostprotRemoteIp(rule_12_s_0_v6.GetDn(),
		"fd00::1236"))

	rule_12_s_1_v6 := apicapi.NewHostprotRule(npv6SDnE, "service_tcp_8443")
	rule_12_s_1_v6.SetAttr("direction", "egress")
	rule_12_s_1_v6.SetAttr("ethertype", "ipv6")
	rule_12_s_1_v6.SetAttr("protocol", "tcp")
	rule_12_s_1_v6.SetAttr("toPort", "8443")
	rule_12_s_1_v6.AddChild(apicapi.NewHostprotRemoteIp(rule_12_s_1_v6.GetDn(),
		"fd00::1236"))

	rule_13_0_v6 := apicapi.NewHostprotRule(npv6SDnE, "0")
	rule_13_0_v6.SetAttr("direction", "egress")
	rule_13_0_v6.SetAttr("ethertype", "ipv6")

	rule_14_0_v6 := apicapi.NewHostprotRule(npv6SDnE, "0_0")
	rule_14_0_v6.SetAttr("direction", "egress")
	rule_14_0_v6.SetAttr("ethertype", "ipv6")
	rule_14_0_v6.SetAttr("protocol", "tcp")
	rule_14_0_v6.SetAttr("toPort", "80")

	rule_14_s_v6 := apicapi.NewHostprotRule(npv6SDnE, "service_tcp_8080")
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
						peerIpBlock(peer(nil, nil),
							"8.8.8.8/24", []string{"8.8.8.9/31"}),
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
				[]*v1beta1.EndpointSlice{},
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
				[]*v1beta1.EndpointSlice{},
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
				[]*v1beta1.EndpointSlice{},
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
				[]*v1beta1.EndpointSlice{},
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
	for _, nt := range np6Tests {
		cont := initCont()
		cont.log.Info("Starting podsfirst ", nt.desc)
		addPods(cont, true, ips, false)
		addServices(cont, nt.augment)
		cont.run()
		cont.fakeNetworkPolicySource.Add(util.GetInternalPolicy(nt.netPol))
		checkNp(t, &nt, "podsfirst", cont)

		cont.log.Info("Starting delete ", nt.desc)
		cont.fakeNetworkPolicySource.Delete(util.GetInternalPolicy(nt.netPol))
		checkDelete(t, np6Tests[0], cont)
		cont.stop()
	}

	for _, nt := range np6Tests {
		cont := initCont()
		cont.log.Info("Starting npfirst ", nt.desc)
		cont.fakeNetworkPolicySource.Add(util.GetInternalPolicy(nt.netPol))
		cont.run()
		addServices(cont, nt.augment)
		addPods(cont, false, ips, false)
		addPods(cont, true, ips, false)
		checkNp(t, &nt, "npfirst", cont)
		cont.stop()
	}
}

// Test with EndPointslices
func TestNetworkPolicyWithEndPointSlice(t *testing.T) {
	name := "kube_np_testns_np1"
	baseDn := makeNp(nil, nil, name).GetDn()
	np1SDnE := fmt.Sprintf("%s/subj-networkpolicy-egress", baseDn)

	rule_11_0 := apicapi.NewHostprotRule(np1SDnE, "0_0")
	rule_11_0.SetAttr("direction", "egress")
	rule_11_0.SetAttr("ethertype", "ipv4")
	rule_11_0.SetAttr("protocol", "tcp")
	rule_11_0.SetAttr("toPort", "80")
	rule_11_0.AddChild(apicapi.NewHostprotRemoteIp(rule_11_0.GetDn(), "1.1.1.1"))

	rule_11_s := apicapi.NewHostprotRule(np1SDnE, "service_tcp_8080")
	rule_11_s.SetAttr("direction", "egress")
	rule_11_s.SetAttr("ethertype", "ipv4")
	rule_11_s.SetAttr("protocol", "tcp")
	rule_11_s.SetAttr("toPort", "8080")
	rule_11_s.AddChild(apicapi.NewHostprotRemoteIp(rule_11_s.GetDn(), "9.0.0.42"))

	rule_12_0 := apicapi.NewHostprotRule(np1SDnE, "0")
	rule_12_0.SetAttr("direction", "egress")
	rule_12_0.SetAttr("ethertype", "ipv4")
	rule_12_0.AddChild(apicapi.NewHostprotRemoteIp(rule_12_0.GetDn(),
		"1.1.1.0/24"))

	rule_12_s_0 := apicapi.NewHostprotRule(np1SDnE, "service_tcp_8080")
	rule_12_s_0.SetAttr("direction", "egress")
	rule_12_s_0.SetAttr("ethertype", "ipv4")
	rule_12_s_0.SetAttr("protocol", "tcp")
	rule_12_s_0.SetAttr("toPort", "8080")
	rule_12_s_0.AddChild(apicapi.NewHostprotRemoteIp(rule_12_s_0.GetDn(),
		"9.0.0.44"))

	rule_12_s_1 := apicapi.NewHostprotRule(np1SDnE, "service_tcp_8443")
	rule_12_s_1.SetAttr("direction", "egress")
	rule_12_s_1.SetAttr("ethertype", "ipv4")
	rule_12_s_1.SetAttr("protocol", "tcp")
	rule_12_s_1.SetAttr("toPort", "8443")
	rule_12_s_1.AddChild(apicapi.NewHostprotRemoteIp(rule_12_s_1.GetDn(),
		"9.0.0.44"))

	rule_13_0 := apicapi.NewHostprotRule(np1SDnE, "0")
	rule_13_0.SetAttr("direction", "egress")
	rule_13_0.SetAttr("ethertype", "ipv4")

	rule_14_0 := apicapi.NewHostprotRule(np1SDnE, "0_0")
	rule_14_0.SetAttr("direction", "egress")
	rule_14_0.SetAttr("ethertype", "ipv4")
	rule_14_0.SetAttr("protocol", "tcp")
	rule_14_0.SetAttr("toPort", "80")

	rule_14_s := apicapi.NewHostprotRule(np1SDnE, "service_tcp_8080")
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
				[]*v1beta1.EndpointSlice{
					makeEpSlice("testns", "service1xyz",
						[]v1beta1.Endpoint{
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
						}, []v1beta1.EndpointPort{
							endpointSlicePort(v1.ProtocolTCP, 80, ""),
						}, "service1"),
					makeEpSlice("testns", "service2xyz",
						[]v1beta1.Endpoint{
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
						}, []v1beta1.EndpointPort{
							endpointSlicePort(v1.ProtocolTCP, 80, ""),
						}, "service2"),
					makeEpSlice("testns", "service3xyz",
						[]v1beta1.Endpoint{
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
						}, []v1beta1.EndpointPort{
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
				[]*v1beta1.EndpointSlice{
					makeEpSlice("testns", "service1xyz",
						[]v1beta1.Endpoint{
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
						}, []v1beta1.EndpointPort{
							endpointSlicePort(v1.ProtocolTCP, 80, ""),
						}, "service1"),
					makeEpSlice("testns", "service2xyz",
						[]v1beta1.Endpoint{
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
						}, []v1beta1.EndpointPort{
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
				[]*v1beta1.EndpointSlice{
					makeEpSlice("testns", "service1xyz",
						[]v1beta1.Endpoint{
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
						}, []v1beta1.EndpointPort{
							endpointSlicePort(v1.ProtocolTCP, 80, ""),
						}, "service1"),
					makeEpSlice("testns", "service2xyz",
						[]v1beta1.Endpoint{
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
						}, []v1beta1.EndpointPort{
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
				[]*v1beta1.EndpointSlice{
					makeEpSlice("testns", "service1xyz",
						[]v1beta1.Endpoint{
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
						}, []v1beta1.EndpointPort{
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
				[]*v1beta1.EndpointSlice{
					makeEpSlice("testns", "service1xyz",
						[]v1beta1.Endpoint{
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
						}, []v1beta1.EndpointPort{
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
	for _, nt := range npTests {
		cont := initCont()
		cont.log.Info("Starting podsfirst ", nt.desc)
		addPods(cont, true, ips, true)
		addServices(cont, nt.augment)
		cont.run()
		cont.fakeNetworkPolicySource.Add(util.GetInternalPolicy(nt.netPol))
		checkNp(t, &nt, "podsfirst", cont)

		cont.log.Info("Starting delete ", nt.desc)
		cont.fakeNetworkPolicySource.Delete(util.GetInternalPolicy(nt.netPol))
		checkDelete(t, npTests[0], cont)
		cont.stop()
	}
	for _, nt := range npTests {
		cont := initCont()
		cont.log.Info("Starting npfirst ", nt.desc)
		cont.fakeNetworkPolicySource.Add(util.GetInternalPolicy(nt.netPol))
		cont.run()
		addServices(cont, nt.augment)
		addPods(cont, false, ips, true)
		addPods(cont, true, ips, true)
		checkNp(t, &nt, "npfirst", cont)
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

	rule_1_0 := apicapi.NewHostprotRule(np1SDnE, "0_0")
	rule_1_0.SetAttr("direction", "egress")
	rule_1_0.SetAttr("ethertype", "ipv4")
	rule_1_0.SetAttr("protocol", "tcp")
	rule_1_0.SetAttr("toPort", "80")

	rule_1_s := apicapi.NewHostprotRule(np1SDnE, "service_tcp_8080")
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
				[]*v1beta1.EndpointSlice{},
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
	for _, nt := range npTests {
		cont := initCont()
		cont.log.Info("Starting podsfirst ", nt.desc)
		addPod(cont, "testns", "pod1", map[string]string{"l1": "v1"}, ports)
		addPod(cont, "testns", "pod2", map[string]string{"l1": "v2"}, ports1)
		addServices(cont, nt.augment)
		cont.run()
		cont.fakeNetworkPolicySource.Add(util.GetInternalPolicy(nt.netPol))
		checkNp(t, &nt, "podsfirst", cont)
		cont.log.Info("Starting delete ", nt.desc)
		cont.fakeNetworkPolicySource.Delete(util.GetInternalPolicy(nt.netPol))
		checkDelete(t, npTests[0], cont)
		cont.stop()
	}
	for _, nt := range npTests {
		cont := initCont()
		cont.log.Info("Starting npfirst ", nt.desc)
		cont.fakeNetworkPolicySource.Add(util.GetInternalPolicy(nt.netPol))
		cont.run()
		addServices(cont, nt.augment)
		addPod(cont, "testns", "pod1", map[string]string{"l1": "v1"}, ports)
		addPod(cont, "testns", "pod2", map[string]string{"l1": "v2"}, ports1)
		checkNp(t, &nt, "npfirst", cont)
		cont.stop()
	}
}

func TestNetworkPolicyDnsPolicy(t *testing.T) {
	/*
		name := "kube_np_testns_np2"
		baseDn := makeNp(nil, nil, name).GetDn()
		np1SDnE := fmt.Sprintf("%s/subj-networkpolicy-egress", baseDn)

		rule_1_0 := apicapi.NewHostprotRule(np1SDnE, "0_0")
		rule_1_0.SetAttr("direction", "egress")
		rule_1_0.SetAttr("ethertype", "ipv4")
		rule_1_0.SetAttr("protocol", "tcp")
		rule_1_0.SetAttr("toPort", "80")

		rule_1_s := apicapi.NewHostprotRule(np1SDnE, "service_tcp_8080")
		rule_1_s.SetAttr("direction", "egress")
		rule_1_s.SetAttr("ethertype", "ipv4")
		rule_1_s.SetAttr("protocol", "tcp")
		rule_1_s.SetAttr("toPort", "8080")
		rule_1_s.AddChild(apicapi.NewHostprotRemoteIp(rule_1_s.GetDn(), "9.0.0.42"))
	*/
	np := &v1betadnsntp.DnsNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-np",
			Namespace: "tesns",
		},
		Spec: v1betadnsntp.DnsNetworkPolicySpec{
			AppliedTo: v1netpol.AppliedTo{PodSelector: &metav1.LabelSelector{}},
			Egress:    v1betadnsntp.NetworkPolicyEgressRule{ToFqdn: &v1netpol.FQDN{MatchNames: []string{"*.google.com", "*.yahoo.com"}}},
		},
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
	cont := initCont()
	addPod(cont, "testns", "pod1", map[string]string{"l1": "v1"}, nil)
	addPod(cont, "testns", "pod2", map[string]string{"l1": "v2"}, nil)
	cont.run()
	cont.fakeNetworkPolicySource.Add(util.GetInternalPolicy(np))
	time.Sleep(2000 * time.Millisecond)
	//	checkNp(t, &nt, "podsfirst", cont)

	cont.fakeNetworkPolicySource.Delete(util.GetInternalPolicy(np))
	//	checkDelete(t, npTests[0], cont)
	cont.stop()
}
