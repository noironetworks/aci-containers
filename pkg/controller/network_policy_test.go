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
	"testing"
	"time"

	v1 "k8s.io/api/core/v1"
	v1net "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/noironetworks/aci-containers/pkg/apicapi"
	tu "github.com/noironetworks/aci-containers/pkg/testutil"
	"github.com/stretchr/testify/assert"
)

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

type npTest struct {
	netPol *v1net.NetworkPolicy
	aciObj apicapi.ApicObject
	desc   string
}

func staticNetPolKey() string {
	return "kube_np_static"
}

func TestNetworkPolicy(t *testing.T) {
	tcp := "TCP"
	udp := "UDP"
	port80 := 80
	port443 := 443

	makeNp := func(ingress apicapi.ApicSlice,
		egress apicapi.ApicSlice) apicapi.ApicObject {
		np1 := apicapi.NewHostprotPol("test-tenant", "kube_np_testns_np1")
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

	baseDn := makeNp(nil, nil).GetDn()
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
	rule_9_0.AddChild(apicapi.NewHostprotRemoteIp(rule_9_0.GetDn(), "1.1.1.1"))
	rule_9_0.AddChild(apicapi.NewHostprotRemoteIp(rule_9_0.GetDn(), "1.1.1.3"))
	rule_9_0.AddChild(apicapi.NewHostprotRemoteIp(rule_9_0.GetDn(), "1.1.1.4"))
	rule_9_0.AddChild(apicapi.NewHostprotRemoteIp(rule_9_0.GetDn(), "1.1.1.5"))

	rule_10_0 := apicapi.NewHostprotRule(np1SDnE, "0")
	rule_10_0.SetAttr("direction", "egress")
	rule_10_0.SetAttr("ethertype", "ipv4")
	rule_10_0.AddChild(apicapi.NewHostprotRemoteIp(rule_10_0.GetDn(), "1.1.1.1"))
	rule_10_0.AddChild(apicapi.NewHostprotRemoteIp(rule_10_0.GetDn(), "1.1.1.3"))
	rule_10_0.AddChild(apicapi.NewHostprotRemoteIp(rule_10_0.GetDn(), "1.1.1.4"))
	rule_10_0.AddChild(apicapi.NewHostprotRemoteIp(rule_10_0.GetDn(), "1.1.1.5"))

	var npTests = []npTest{
		{netpol("testns", "np1", &metav1.LabelSelector{},
			[]v1net.NetworkPolicyIngressRule{ingressRule(nil, nil)},
			nil, allPolicyTypes),
			makeNp(apicapi.ApicSlice{rule_0_0}, nil),
			"allow-all"},
		{netpol("testns", "np1", &metav1.LabelSelector{},
			[]v1net.NetworkPolicyIngressRule{
				ingressRule([]v1net.NetworkPolicyPort{port(&tcp, &port80)},
					nil)}, nil, allPolicyTypes),
			makeNp(apicapi.ApicSlice{rule_1_0}, nil),
			"allow-http"},
		{netpol("testns", "np1", &metav1.LabelSelector{},
			[]v1net.NetworkPolicyIngressRule{
				ingressRule([]v1net.NetworkPolicyPort{port(&tcp, &port80)},
					[]v1net.NetworkPolicyPeer{
						peerIpBlock(peer(nil, nil),
							"8.8.8.8/24", []string{"8.8.8.9/31"}),
					},
				)}, nil, allPolicyTypes),
			makeNp(apicapi.ApicSlice{rule_2_0}, nil),
			"allow-http-from"},
		{netpol("testns", "np1", &metav1.LabelSelector{},
			[]v1net.NetworkPolicyIngressRule{
				ingressRule([]v1net.NetworkPolicyPort{
					port(nil, &port80)}, nil)}, nil, allPolicyTypes),
			makeNp(apicapi.ApicSlice{rule_1_0}, nil),
			"allow-http-defproto"},
		{netpol("testns", "np1", &metav1.LabelSelector{},
			[]v1net.NetworkPolicyIngressRule{
				ingressRule([]v1net.NetworkPolicyPort{
					port(&udp, &port80)}, nil)}, nil, allPolicyTypes),
			makeNp(apicapi.ApicSlice{rule_3_0}, nil),
			"allow-80-udp"},
		{netpol("testns", "np1", &metav1.LabelSelector{},
			[]v1net.NetworkPolicyIngressRule{
				ingressRule([]v1net.NetworkPolicyPort{
					port(nil, &port80), port(nil, &port443),
				}, nil)}, nil, allPolicyTypes),
			makeNp(apicapi.ApicSlice{rule_1_0, rule_4_1}, nil),
			"allow-http-https"},
		{netpol("testns", "np1", &metav1.LabelSelector{},
			[]v1net.NetworkPolicyIngressRule{ingressRule(nil,
				[]v1net.NetworkPolicyPeer{peer(nil,
					&metav1.LabelSelector{
						MatchLabels: map[string]string{"test": "testv"},
					}),
				}),
			}, nil, allPolicyTypes),
			makeNp(apicapi.ApicSlice{rule_5_0}, nil),
			"allow-all-from-ns"},
		{netpol("testns", "np1", &metav1.LabelSelector{},
			[]v1net.NetworkPolicyIngressRule{ingressRule(nil,
				[]v1net.NetworkPolicyPeer{peer(nil,
					&metav1.LabelSelector{
						MatchLabels: map[string]string{"test": "notathing"},
					}),
				}),
			}, nil, allPolicyTypes),
			makeNp(nil, nil),
			"allow-all-from-ns-no-match"},
		{netpol("testns", "np1", &metav1.LabelSelector{},
			[]v1net.NetworkPolicyIngressRule{ingressRule(nil,
				[]v1net.NetworkPolicyPeer{peer(nil,
					&metav1.LabelSelector{
						MatchLabels: map[string]string{"nl": "nv"},
					}),
				}),
			}, nil, allPolicyTypes),
			makeNp(apicapi.ApicSlice{rule_6_0}, nil),
			"allow-all-from-multiple-ns"},
		{netpol("testns", "np1", &metav1.LabelSelector{},
			[]v1net.NetworkPolicyIngressRule{ingressRule(nil,
				[]v1net.NetworkPolicyPeer{
					peer(&metav1.LabelSelector{
						MatchLabels: map[string]string{"l1": "v1"},
					}, nil),
				}),
			}, nil, allPolicyTypes),
			makeNp(apicapi.ApicSlice{rule_7_0}, nil),
			"allow-all-select-pods"},
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
			makeNp(apicapi.ApicSlice{rule_9_0}, nil),
			"allow-all-select-pods-and-ns"},
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
			makeNp(apicapi.ApicSlice{rule_8_0, rule_8_1}, nil),
			"multiple-from"},
		{netpol("testns", "np1", &metav1.LabelSelector{},
			nil, []v1net.NetworkPolicyEgressRule{egressRule(nil,
				[]v1net.NetworkPolicyPeer{
					peer(&metav1.LabelSelector{
						MatchLabels: map[string]string{"l1": "v1"},
					}, &metav1.LabelSelector{
						MatchLabels: map[string]string{"nl": "nv"},
					}),
				}),
			}, allPolicyTypes),
			makeNp(nil, apicapi.ApicSlice{rule_10_0}),
			"allow-all-select-pods-and-ns-egress"},
	}

	initCont := func() *testAciController {
		cont := testController()
		cont.config.AciPolicyTenant = "test-tenant"

		cont.fakeNamespaceSource.Add(namespaceLabel("testns",
			map[string]string{"test": "testv"}))
		cont.fakeNamespaceSource.Add(namespaceLabel("ns1",
			map[string]string{"nl": "nv"}))
		cont.fakeNamespaceSource.Add(namespaceLabel("ns2",
			map[string]string{"nl": "nv"}))
		return cont
	}

	addPods := func(cont *testAciController, incIps bool) {
		pods := []*v1.Pod{
			podLabel("testns", "pod1", map[string]string{"l1": "v1"}),
			podLabel("testns", "pod2", map[string]string{"l1": "v2"}),
			podLabel("ns1", "pod3", map[string]string{"l1": "v1"}),
			podLabel("ns1", "pod4", map[string]string{"l1": "v2"}),
			podLabel("ns2", "pod5", map[string]string{"l1": "v1"}),
			podLabel("ns2", "pod6", map[string]string{"l1": "v2"}),
		}
		ips := []string{
			"1.1.1.1", "1.1.1.2", "1.1.1.3", "1.1.1.4", "1.1.1.5", "",
		}
		if incIps {
			for i := range pods {
				pods[i].Status.PodIP = ips[i]
			}
		}
		for _, pod := range pods {
			cont.fakePodSource.Add(pod)
		}
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

	checkNp := func(nt *npTest, cont *testAciController) {
		tu.WaitFor(t, nt.desc, 500*time.Millisecond,
			func(last bool) (bool, error) {
				cont.indexMutex.Lock()
				defer cont.indexMutex.Unlock()

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
	checkDelete := func(nt *npTest, cont *testAciController) {
		tu.WaitFor(t, "delete", 500*time.Millisecond,
			func(last bool) (bool, error) {
				cont.indexMutex.Lock()
				defer cont.indexMutex.Unlock()

				nt := npTests[0]
				key := cont.aciNameForKey("np",
					nt.netPol.Namespace+"_"+nt.netPol.Name)
				if !tu.WaitEqual(t, last, 0,
					len(cont.apicConn.GetDesiredState(key)), "delete") {
					return false, nil
				}
				return true, nil
			})
	}

	for _, nt := range npTests {
		cont := initCont()
		cont.log.Info("Starting podsfirst ", nt.desc)
		addPods(cont, true)
		cont.run()
		cont.fakeNetworkPolicySource.Add(nt.netPol)
		checkNp(&nt, cont)

		cont.log.Info("Starting delete ", nt.desc)
		cont.fakeNetworkPolicySource.Delete(nt.netPol)
		checkDelete(&nt, cont)
		cont.stop()
	}

	for _, nt := range npTests {
		cont := initCont()
		cont.log.Info("Starting npfirst ", nt.desc)
		cont.fakeNetworkPolicySource.Add(nt.netPol)
		cont.run()
		addPods(cont, false)
		addPods(cont, true)
		checkNp(&nt, cont)
		cont.stop()
	}
}
