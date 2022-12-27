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
			hash, _ := util.CreateHashFromNetPol(nt.netPol)
			key := cont.aciNameForKey("np", hash)
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
	test0_rule := createRule(test0_np_name, true, rule_0, "0")

	//allow-http
	test1_np := netpol("testns", "np1", &metav1.LabelSelector{},
		[]v1net.NetworkPolicyIngressRule{
			ingressRule([]v1net.NetworkPolicyPort{port(&tcp, &port80)},
				nil)}, nil, allPolicyTypes)
	hash, _ = util.CreateHashFromNetPol(test1_np)
	test1_np_name := "kube_np_" + hash
	test1_rule := createRule(test1_np_name, true, rule_1, "0_0")

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
	test2_rule := createRule(test2_np_name, true, rule_1, "0_0")
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
	test3_rule := createRule(test3_np_name, true, rule_1, "0_0")

	//allow-80-udp
	test4_np := netpol("testns", "np1", &metav1.LabelSelector{},
		[]v1net.NetworkPolicyIngressRule{
			ingressRule([]v1net.NetworkPolicyPort{
				port(&udp, &port80)}, nil)}, nil, allPolicyTypes)
	hash, _ = util.CreateHashFromNetPol(test4_np)
	test4_np_name := "kube_np_" + hash
	test4_rule := createRule(test4_np_name, true, rule_2, "0_0")

	//allow-80-sctp
	test5_np := netpol("testns", "np1", &metav1.LabelSelector{},
		[]v1net.NetworkPolicyIngressRule{
			ingressRule([]v1net.NetworkPolicyPort{
				port(&sctp, &port80)}, nil)}, nil, allPolicyTypes)
	hash, _ = util.CreateHashFromNetPol(test5_np)
	test5_np_name := "kube_np_" + hash
	test5_rule := createRule(test5_np_name, true, rule_4, "0_0")

	//allow-http-https
	test6_np := netpol("testns", "np1", &metav1.LabelSelector{},
		[]v1net.NetworkPolicyIngressRule{
			ingressRule([]v1net.NetworkPolicyPort{
				port(nil, &port80), port(nil, &port443),
			}, nil)}, nil, allPolicyTypes)
	hash, _ = util.CreateHashFromNetPol(test6_np)
	test6_np_name := "kube_np_" + hash
	test6_rule1 := createRule(test6_np_name, true, rule_1, "0_0")
	test6_rule2 := createRule(test6_np_name, true, rule_3, "0_1")

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
	test7_rule := createRule(test7_np_name, true, rule_0, "0")
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
	test9_rule := createRule(test9_np_name, true, rule_0, "0")
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
	test10_rule := createRule(test10_np_name, true, rule_0, "0")
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
	test11_rule := createRule(test11_np_name, true, rule_0, "0")
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
	test12_rule1 := createRule(test12_np_name, true, rule_1, "0_0")
	test12_rule1.AddChild(apicapi.NewHostprotRemoteIp(test12_rule1.GetDn(), "1.1.1.1"))
	test12_rule2 := createRule(test12_np_name, true, rule_3, "1_0")
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
	test13_rule1 := createRule(test13_np_name, true, rule_1, "0_0")
	test13_rule1.AddChild(apicapi.NewHostprotRemoteIp(test13_rule1.GetDn(), "1.1.1.1"))
	test13_rule2 := createRule(test13_np_name, true, rule_3, "1_0")
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
	test14_rule := createRule(test14_np_name, false, rule_5, "0")
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
	test15_rule := createRule(test15_np_name, false, rule_6, "0_0")
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
	test16_rule1 := createRule(test16_np_name, false, rule_6, "0_0")
	test16_rule1.AddChild(apicapi.NewHostprotRemoteIp(test16_rule1.GetDn(), "1.1.1.1"))
	test16_rule2 := createRule(test16_np_name, false, rule_7, "service_tcp_8080")
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
	test17_rule1 := createRule(test17_np_name, false, rule_6, "0_0")
	test17_rule1.AddChild(apicapi.NewHostprotRemoteIp(test17_rule1.GetDn(), "1.1.1.1"))
	test17_rule2 := createRule(test17_np_name, false, rule_7, "service_tcp_8080")
	test17_rule2.AddChild(apicapi.NewHostprotRemoteIp(test17_rule2.GetDn(), "9.0.0.42"))

	//egress-allow-http-all-augment
	test18_np := netpol("testns", "np1", &metav1.LabelSelector{},
		nil, []v1net.NetworkPolicyEgressRule{
			egressRule([]v1net.NetworkPolicyPort{port(&tcp, &port80)},
				nil),
		}, allPolicyTypes)
	hash, _ = util.CreateHashFromNetPol(test18_np)
	test18_np_name := "kube_np_" + hash
	test18_rule1 := createRule(test18_np_name, false, rule_6, "0_0")
	test18_rule2 := createRule(test18_np_name, false, rule_7, "service_tcp_8080")
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
	test19_rule1 := createRule(test19_np_name, false, rule_5, "0")
	test19_rule1.AddChild(apicapi.NewHostprotRemoteIp(test19_rule1.GetDn(), "1.1.1.0/24"))
	test19_rule2 := createRule(test19_np_name, false, rule_7, "service_tcp_8080")
	test19_rule2.AddChild(apicapi.NewHostprotRemoteIp(test19_rule2.GetDn(), "9.0.0.44"))
	test19_rule3 := createRule(test19_np_name, false, rule_8, "service_tcp_8443")
	test19_rule3.AddChild(apicapi.NewHostprotRemoteIp(test19_rule3.GetDn(), "9.0.0.44"))

	//egress-allow-all-augment
	test20_np := netpol("testns", "np1", &metav1.LabelSelector{},
		nil, []v1net.NetworkPolicyEgressRule{
			egressRule(nil, nil),
		}, allPolicyTypes)
	hash, _ = util.CreateHashFromNetPol(test20_np)
	test20_np_name := "kube_np_" + hash
	test20_rule := createRule(test20_np_name, false, rule_5, "0")

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
				[]*v1beta1.EndpointSlice{},
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
				[]*v1beta1.EndpointSlice{},
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
				[]*v1beta1.EndpointSlice{},
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
				[]*v1beta1.EndpointSlice{},
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
		cont.fakeNetworkPolicySource.Add(nt.netPol)
		checkNp(t, &nt, "podsfirst", cont)

		cont.log.Info("Starting delete ", nt.desc)
		cont.fakeNetworkPolicySource.Delete(nt.netPol)
		checkDelete(t, npTests[0], cont)
		cont.stop()
	}
	for _, nt := range npTests {
		cont := initCont()
		cont.log.Info("Starting npfirst ", nt.desc)
		cont.fakeNetworkPolicySource.Add(nt.netPol)
		cont.run()
		addServices(cont, nt.augment)
		addPods(cont, false, ips, true)
		addPods(cont, true, ips, true)
		checkNp(t, &nt, "npfirst", cont)
		cont.stop()
	}
}

func TestNetworkPolicyv6(t *testing.T) {
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
	test0_rule_v6 := createRule(test0_np_name_v6, true, rule_0_v6, "0")

	//allow-http
	test1_np_v6 := netpol("testnsv6", "npv6", &metav1.LabelSelector{},
		[]v1net.NetworkPolicyIngressRule{
			ingressRule([]v1net.NetworkPolicyPort{port(&tcp, &port80)},
				nil)}, nil, allPolicyTypes)
	hash, _ = util.CreateHashFromNetPol(test1_np_v6)
	test1_np_name_v6 := "kube_np_" + hash
	test1_rule_v6 := createRule(test1_np_name_v6, true, rule_1_v6, "0_0")

	//allow-http-from
	test2_np_v6 := netpol("testnsv6", "npv6", &metav1.LabelSelector{},
		[]v1net.NetworkPolicyIngressRule{
			ingressRule([]v1net.NetworkPolicyPort{port(&tcp, &port80)},
				[]v1net.NetworkPolicyPeer{
					peerIpBlock(peer(nil, nil),
						"8.8.8.8/24", []string{"8.8.8.9/31"}),
				},
			)}, nil, allPolicyTypes)
	hash, _ = util.CreateHashFromNetPol(test2_np_v6)
	test2_np_name_v6 := "kube_np_" + hash
	test2_rule_v6 := createRule(test2_np_name_v6, true, rule_1_v6, "0_0")
	test2_rule_v6.AddChild(
		apicapi.NewHostprotRemoteIp(test2_rule_v6.GetDn(), "8.8.8.0/29"))
	test2_rule_v6.AddChild(
		apicapi.NewHostprotRemoteIp(test2_rule_v6.GetDn(), "8.8.8.10/31"))
	test2_rule_v6.AddChild(
		apicapi.NewHostprotRemoteIp(test2_rule_v6.GetDn(), "8.8.8.12/30"))
	test2_rule_v6.AddChild(
		apicapi.NewHostprotRemoteIp(test2_rule_v6.GetDn(), "8.8.8.128/25"))
	test2_rule_v6.AddChild(
		apicapi.NewHostprotRemoteIp(test2_rule_v6.GetDn(), "8.8.8.16/28"))
	test2_rule_v6.AddChild(
		apicapi.NewHostprotRemoteIp(test2_rule_v6.GetDn(), "8.8.8.32/27"))
	test2_rule_v6.AddChild(
		apicapi.NewHostprotRemoteIp(test2_rule_v6.GetDn(), "8.8.8.64/26"))

	//allow-http-defproto
	test3_np_v6 := netpol("testnsv6", "npv6", &metav1.LabelSelector{},
		[]v1net.NetworkPolicyIngressRule{
			ingressRule([]v1net.NetworkPolicyPort{
				port(nil, &port80)}, nil)}, nil, allPolicyTypes)
	hash, _ = util.CreateHashFromNetPol(test3_np_v6)
	test3_np_name_v6 := "kube_np_" + hash
	test3_rule_v6 := createRule(test3_np_name_v6, true, rule_1_v6, "0_0")

	//allow-80-udp
	test4_np_v6 := netpol("testnsv6", "npv6", &metav1.LabelSelector{},
		[]v1net.NetworkPolicyIngressRule{
			ingressRule([]v1net.NetworkPolicyPort{
				port(&udp, &port80)}, nil)}, nil, allPolicyTypes)
	hash, _ = util.CreateHashFromNetPol(test4_np_v6)
	test4_np_name_v6 := "kube_np_" + hash
	test4_rule_v6 := createRule(test4_np_name_v6, true, rule_2_v6, "0_0")

	//allow-http-https
	test5_np_v6 := netpol("testnsv6", "npv6", &metav1.LabelSelector{},
		[]v1net.NetworkPolicyIngressRule{
			ingressRule([]v1net.NetworkPolicyPort{
				port(nil, &port80), port(nil, &port443),
			}, nil)}, nil, allPolicyTypes)
	hash, _ = util.CreateHashFromNetPol(test5_np_v6)
	test5_np_name_v6 := "kube_np_" + hash
	test5_rule1_v6 := createRule(test5_np_name_v6, true, rule_1_v6, "0_0")
	test5_rule2_v6 := createRule(test5_np_name_v6, true, rule_3_v6, "0_1")

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
	test6_rule_v6 := createRule(test6_np_name_v6, true, rule_0_v6, "0")
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
	test8_rule_v6 := createRule(test8_np_name_v6, true, rule_0_v6, "0")
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
	test9_rule_v6 := createRule(test9_np_name_v6, true, rule_0_v6, "0")
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
	test10_rule_v6 := createRule(test10_np_name_v6, true, rule_0_v6, "0")
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
	test11_rule1_v6 := createRule(test11_np_name_v6, true, rule_1_v6, "0_0")
	test11_rule1_v6.AddChild(apicapi.NewHostprotRemoteIp(test11_rule1_v6.GetDn(), "2001::2"))
	test11_rule2_v6 := createRule(test11_np_name_v6, true, rule_3_v6, "1_0")
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
	test12_rule_v6 := createRule(test12_np_name_v6, false, rule_4_v6, "0")
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
	test13_rule_v6 := createRule(test13_np_name_v6, false, rule_5_v6, "0_0")
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
	test14_rule1_v6 := createRule(test14_np_name_v6, false, rule_5_v6, "0_0")
	test14_rule1_v6.AddChild(apicapi.NewHostprotRemoteIp(test14_rule1_v6.GetDn(), "2001::2"))
	test14_rule2_v6 := createRule(test14_np_name_v6, false, rule_6_v6, "service_tcp_8080")
	test14_rule2_v6.AddChild(apicapi.NewHostprotRemoteIp(test14_rule2_v6.GetDn(), "fd00::1234"))

	//egress-allow-http-all-augment
	test15_np_v6 := netpol("testnsv6", "npv6", &metav1.LabelSelector{},
		nil, []v1net.NetworkPolicyEgressRule{
			egressRule([]v1net.NetworkPolicyPort{port(&tcp, &port80)},
				nil),
		}, allPolicyTypes)
	hash, _ = util.CreateHashFromNetPol(test15_np_v6)
	test15_np_name_v6 := "kube_np_" + hash
	test15_rule1_v6 := createRule(test15_np_name_v6, false, rule_5_v6, "0_0")
	test15_rule2_v6 := createRule(test15_np_name_v6, false, rule_6_v6, "service_tcp_8080")
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
	test16_rule1_v6 := createRule(test16_np_name_v6, false, rule_4_v6, "0")
	test16_rule1_v6.AddChild(apicapi.NewHostprotRemoteIp(test16_rule1_v6.GetDn(), "2001::/64"))
	test16_rule2_v6 := createRule(test16_np_name_v6, false, rule_6_v6, "service_tcp_8080")
	test16_rule2_v6.AddChild(apicapi.NewHostprotRemoteIp(test16_rule2_v6.GetDn(), "fd00::1236"))
	test16_rule3_v6 := createRule(test16_np_name_v6, false, rule_7_v6, "service_tcp_8443")
	test16_rule3_v6.AddChild(apicapi.NewHostprotRemoteIp(test16_rule3_v6.GetDn(), "fd00::1236"))

	//egress-allow-all-augment
	test17_np_v6 := netpol("testnsv6", "npv6", &metav1.LabelSelector{},
		nil, []v1net.NetworkPolicyEgressRule{
			egressRule(nil, nil),
		}, allPolicyTypes)
	hash, _ = util.CreateHashFromNetPol(test17_np_v6)
	test17_np_name_v6 := "kube_np_" + hash
	test17_rule_v6 := createRule(test17_np_name_v6, false, rule_4_v6, "0")

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
				[]*v1beta1.EndpointSlice{},
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
				[]*v1beta1.EndpointSlice{},
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
				[]*v1beta1.EndpointSlice{},
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
		cont.fakeNetworkPolicySource.Add(nt.netPol)
		checkNp(t, &nt, "podsfirst", cont)

		cont.log.Info("Starting delete ", nt.desc)
		cont.fakeNetworkPolicySource.Delete(nt.netPol)
		checkDelete(t, np6Tests[0], cont)
		cont.stop()
	}

	for _, nt := range np6Tests {
		cont := initCont()
		cont.log.Info("Starting npfirst ", nt.desc)
		cont.fakeNetworkPolicySource.Add(nt.netPol)
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
	test15_rule := createRule(test15_np_name, false, rule_6, "0_0")
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
	test16_rule1 := createRule(test16_np_name, false, rule_6, "0_0")
	test16_rule1.AddChild(apicapi.NewHostprotRemoteIp(test16_rule1.GetDn(), "1.1.1.1"))
	test16_rule2 := createRule(test16_np_name, false, rule_7, "service_tcp_8080")
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
	test17_rule1 := createRule(test17_np_name, false, rule_6, "0_0")
	test17_rule1.AddChild(apicapi.NewHostprotRemoteIp(test17_rule1.GetDn(), "1.1.1.1"))
	test17_rule2 := createRule(test17_np_name, false, rule_7, "service_tcp_8080")
	test17_rule2.AddChild(apicapi.NewHostprotRemoteIp(test17_rule2.GetDn(), "9.0.0.42"))

	//egress-allow-http-all-augment
	test18_np := netpol("testns", "np1", &metav1.LabelSelector{},
		nil, []v1net.NetworkPolicyEgressRule{
			egressRule([]v1net.NetworkPolicyPort{port(&tcp, &port80)},
				nil),
		}, allPolicyTypes)
	hash, _ = util.CreateHashFromNetPol(test18_np)
	test18_np_name := "kube_np_" + hash
	test18_rule1 := createRule(test18_np_name, false, rule_6, "0_0")
	test18_rule2 := createRule(test18_np_name, false, rule_7, "service_tcp_8080")
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
	test19_rule1 := createRule(test19_np_name, false, rule_5, "0")
	test19_rule1.AddChild(apicapi.NewHostprotRemoteIp(test19_rule1.GetDn(), "1.1.1.0/24"))
	test19_rule2 := createRule(test19_np_name, false, rule_7, "service_tcp_8080")
	test19_rule2.AddChild(apicapi.NewHostprotRemoteIp(test19_rule2.GetDn(), "9.0.0.44"))
	test19_rule3 := createRule(test19_np_name, false, rule_8, "service_tcp_8443")
	test19_rule3.AddChild(apicapi.NewHostprotRemoteIp(test19_rule3.GetDn(), "9.0.0.44"))

	//egress-allow-all-augment
	test20_np := netpol("testns", "np1", &metav1.LabelSelector{},
		nil, []v1net.NetworkPolicyEgressRule{
			egressRule(nil, nil),
		}, allPolicyTypes)
	hash, _ = util.CreateHashFromNetPol(test20_np)
	test20_np_name := "kube_np_" + hash
	test20_rule := createRule(test20_np_name, false, rule_5, "0")

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
		cont.fakeNetworkPolicySource.Add(nt.netPol)
		checkNp(t, &nt, "podsfirst", cont)

		cont.log.Info("Starting delete ", nt.desc)
		cont.fakeNetworkPolicySource.Delete(nt.netPol)
		checkDelete(t, npTests[0], cont)
		cont.stop()
	}
	for _, nt := range npTests {
		cont := initCont()
		cont.log.Info("Starting npfirst ", nt.desc)
		cont.fakeNetworkPolicySource.Add(nt.netPol)
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
	test1_rule1 := createRule(test1_np_name, false, rule_1, "0_0")
	test1_rule2 := createRule(test1_np_name, false, rule_2, "service_tcp_8080")
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
		cont.fakeNetworkPolicySource.Add(nt.netPol)
		checkNp(t, &nt, "podsfirst", cont)
		cont.log.Info("Starting delete ", nt.desc)
		cont.fakeNetworkPolicySource.Delete(nt.netPol)
		checkDelete(t, npTests[0], cont)
		cont.stop()
	}
	for _, nt := range npTests {
		cont := initCont()
		cont.log.Info("Starting npfirst ", nt.desc)
		cont.fakeNetworkPolicySource.Add(nt.netPol)
		cont.run()
		addServices(cont, nt.augment)
		addPod(cont, "testns", "pod1", map[string]string{"l1": "v1"}, ports)
		addPod(cont, "testns", "pod2", map[string]string{"l1": "v2"}, ports1)
		checkNp(t, &nt, "npfirst", cont)
		cont.stop()
	}
}
