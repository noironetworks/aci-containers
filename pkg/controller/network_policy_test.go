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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	v1 "k8s.io/client-go/pkg/api/v1"
	v1beta1 "k8s.io/client-go/pkg/apis/extensions/v1beta1"

	"github.com/noironetworks/aci-containers/pkg/apicapi"
	tu "github.com/noironetworks/aci-containers/pkg/testutil"
	"github.com/stretchr/testify/assert"
)

func port(proto *string, port *int) v1beta1.NetworkPolicyPort {
	var portv intstr.IntOrString
	var protov v1.Protocol
	if port != nil {
		portv = intstr.FromInt(*port)
	}
	if proto != nil {
		protov = v1.Protocol(*proto)
	}
	return v1beta1.NetworkPolicyPort{
		Protocol: &protov,
		Port:     &portv,
	}
}

func peer(podSelector *metav1.LabelSelector,
	nsSelector *metav1.LabelSelector) v1beta1.NetworkPolicyPeer {
	return v1beta1.NetworkPolicyPeer{
		PodSelector:       podSelector,
		NamespaceSelector: nsSelector,
	}
}

func rule(ports []v1beta1.NetworkPolicyPort,
	from []v1beta1.NetworkPolicyPeer) v1beta1.NetworkPolicyIngressRule {
	return v1beta1.NetworkPolicyIngressRule{
		Ports: ports,
		From:  from,
	}
}

func netpol(namespace string, name string, podSelector *metav1.LabelSelector,
	rules []v1beta1.NetworkPolicyIngressRule) *v1beta1.NetworkPolicy {
	return &v1beta1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: v1beta1.NetworkPolicySpec{
			PodSelector: *podSelector,
			Ingress:     rules,
		},
	}
}

type npTest struct {
	netPol *v1beta1.NetworkPolicy
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

	makeNp := func(rules apicapi.ApicSlice) apicapi.ApicObject {
		np1 := apicapi.NewHostprotPol("test-tenant", "kube_np_testns_np1")
		np1Subj := apicapi.NewHostprotSubj(np1.GetDn(), "networkpolicy")
		np1.AddChild(np1Subj)
		for _, r := range rules {
			np1Subj.AddChild(r)
		}
		return np1
	}

	np1SDn := fmt.Sprintf("%s/subj-networkpolicy", makeNp(nil).GetDn())

	rule_0_0 := apicapi.NewHostprotRule(np1SDn, "0")
	rule_0_0.SetAttr("direction", "ingress")
	rule_0_0.SetAttr("ethertype", "ipv4")

	rule_1_0 := apicapi.NewHostprotRule(np1SDn, "0_0")
	rule_1_0.SetAttr("direction", "ingress")
	rule_1_0.SetAttr("ethertype", "ipv4")
	rule_1_0.SetAttr("protocol", "tcp")
	rule_1_0.SetAttr("toPort", "80")

	rule_3_0 := apicapi.NewHostprotRule(np1SDn, "0_0")
	rule_3_0.SetAttr("direction", "ingress")
	rule_3_0.SetAttr("ethertype", "ipv4")
	rule_3_0.SetAttr("protocol", "udp")
	rule_3_0.SetAttr("toPort", "80")

	rule_4_1 := apicapi.NewHostprotRule(np1SDn, "0_1")
	rule_4_1.SetAttr("direction", "ingress")
	rule_4_1.SetAttr("ethertype", "ipv4")
	rule_4_1.SetAttr("protocol", "tcp")
	rule_4_1.SetAttr("toPort", "443")

	rule_5_0 := apicapi.NewHostprotRule(np1SDn, "0")
	rule_5_0.SetAttr("direction", "ingress")
	rule_5_0.SetAttr("ethertype", "ipv4")
	rule_5_0.AddChild(apicapi.NewHostprotRemoteIp(rule_5_0.GetDn(), "1.1.1.1"))
	rule_5_0.AddChild(apicapi.NewHostprotRemoteIp(rule_5_0.GetDn(), "1.1.1.2"))

	rule_6_0 := apicapi.NewHostprotRule(np1SDn, "0")
	rule_6_0.SetAttr("direction", "ingress")
	rule_6_0.SetAttr("ethertype", "ipv4")
	rule_6_0.AddChild(apicapi.NewHostprotRemoteIp(rule_6_0.GetDn(), "1.1.1.3"))
	rule_6_0.AddChild(apicapi.NewHostprotRemoteIp(rule_6_0.GetDn(), "1.1.1.4"))
	rule_6_0.AddChild(apicapi.NewHostprotRemoteIp(rule_6_0.GetDn(), "1.1.1.5"))

	rule_7_0 := apicapi.NewHostprotRule(np1SDn, "0")
	rule_7_0.SetAttr("direction", "ingress")
	rule_7_0.SetAttr("ethertype", "ipv4")
	rule_7_0.AddChild(apicapi.NewHostprotRemoteIp(rule_7_0.GetDn(), "1.1.1.1"))

	rule_8_0 := apicapi.NewHostprotRule(np1SDn, "0_0")
	rule_8_0.SetAttr("direction", "ingress")
	rule_8_0.SetAttr("ethertype", "ipv4")
	rule_8_0.SetAttr("protocol", "tcp")
	rule_8_0.SetAttr("toPort", "80")
	rule_8_0.AddChild(apicapi.NewHostprotRemoteIp(rule_8_0.GetDn(), "1.1.1.1"))
	rule_8_1 := apicapi.NewHostprotRule(np1SDn, "1_0")
	rule_8_1.SetAttr("direction", "ingress")
	rule_8_1.SetAttr("ethertype", "ipv4")
	rule_8_1.SetAttr("protocol", "tcp")
	rule_8_1.SetAttr("toPort", "443")
	rule_8_1.AddChild(apicapi.NewHostprotRemoteIp(rule_8_1.GetDn(), "1.1.1.2"))

	var npTests = []npTest{
		{netpol("testns", "np1", &metav1.LabelSelector{},
			[]v1beta1.NetworkPolicyIngressRule{rule(nil, nil)}),
			makeNp(apicapi.ApicSlice{rule_0_0}),
			"allow-all"},
		{netpol("testns", "np1", &metav1.LabelSelector{},
			[]v1beta1.NetworkPolicyIngressRule{
				rule([]v1beta1.NetworkPolicyPort{port(&tcp, &port80)}, nil)}),
			makeNp(apicapi.ApicSlice{rule_1_0}),
			"allow-http"},
		{netpol("testns", "np1", &metav1.LabelSelector{},
			[]v1beta1.NetworkPolicyIngressRule{
				rule([]v1beta1.NetworkPolicyPort{port(nil, &port80)}, nil)}),
			makeNp(apicapi.ApicSlice{rule_1_0}),
			"allow-http-defproto"},
		{netpol("testns", "np1", &metav1.LabelSelector{},
			[]v1beta1.NetworkPolicyIngressRule{
				rule([]v1beta1.NetworkPolicyPort{port(&udp, &port80)}, nil)}),
			makeNp(apicapi.ApicSlice{rule_3_0}),
			"allow-80-udp"},
		{netpol("testns", "np1", &metav1.LabelSelector{},
			[]v1beta1.NetworkPolicyIngressRule{
				rule([]v1beta1.NetworkPolicyPort{
					port(nil, &port80), port(nil, &port443),
				}, nil)}),
			makeNp(apicapi.ApicSlice{rule_1_0, rule_4_1}),
			"allow-http-https"},
		{netpol("testns", "np1", &metav1.LabelSelector{},
			[]v1beta1.NetworkPolicyIngressRule{rule(nil,
				[]v1beta1.NetworkPolicyPeer{peer(nil,
					&metav1.LabelSelector{
						MatchLabels: map[string]string{"test": "testv"},
					}),
				}),
			}),
			makeNp(apicapi.ApicSlice{rule_5_0}),
			"allow-all-from-ns"},
		{netpol("testns", "np1", &metav1.LabelSelector{},
			[]v1beta1.NetworkPolicyIngressRule{rule(nil,
				[]v1beta1.NetworkPolicyPeer{peer(nil,
					&metav1.LabelSelector{
						MatchLabels: map[string]string{"nl": "nv"},
					}),
				}),
			}),
			makeNp(apicapi.ApicSlice{rule_6_0}),
			"allow-all-from-multiple-ns"},
		{netpol("testns", "np1", &metav1.LabelSelector{},
			[]v1beta1.NetworkPolicyIngressRule{rule(nil,
				[]v1beta1.NetworkPolicyPeer{
					peer(&metav1.LabelSelector{
						MatchLabels: map[string]string{"l1": "v1"},
					}, nil),
				}),
			}),
			makeNp(apicapi.ApicSlice{rule_7_0}),
			"allow-all-select-pods"},
		{netpol("testns", "np1", &metav1.LabelSelector{},
			[]v1beta1.NetworkPolicyIngressRule{
				rule([]v1beta1.NetworkPolicyPort{
					port(nil, &port80),
				}, []v1beta1.NetworkPolicyPeer{
					peer(&metav1.LabelSelector{
						MatchLabels: map[string]string{"l1": "v1"},
					}, nil),
				}),
				rule([]v1beta1.NetworkPolicyPort{
					port(nil, &port443),
				}, []v1beta1.NetworkPolicyPeer{
					peer(&metav1.LabelSelector{
						MatchLabels: map[string]string{"l1": "v2"},
					}, nil),
				}),
			}),
			makeNp(apicapi.ApicSlice{rule_8_0, rule_8_1}),
			"multiple-from"},
	}

	cont := testController()
	cont.config.AciPolicyTenant = "test-tenant"

	cont.fakeNamespaceSource.Add(namespaceLabel("testns",
		map[string]string{"test": "testv"}))
	cont.fakeNamespaceSource.Add(namespaceLabel("ns1",
		map[string]string{"nl": "nv"}))
	cont.fakeNamespaceSource.Add(namespaceLabel("ns2",
		map[string]string{"nl": "nv"}))

	p := podLabel("testns", "pod1", map[string]string{"l1": "v1"})
	p.Status.PodIP = "1.1.1.1"
	cont.fakePodSource.Add(p)
	p = podLabel("testns", "pod2", map[string]string{"l1": "v2"})
	p.Status.PodIP = "1.1.1.2"
	cont.fakePodSource.Add(p)
	p = podLabel("ns1", "pod3", map[string]string{"l1": "v1"})
	p.Status.PodIP = "1.1.1.3"
	cont.fakePodSource.Add(p)
	p = podLabel("ns1", "pod4", map[string]string{"l1": "v2"})
	p.Status.PodIP = "1.1.1.4"
	cont.fakePodSource.Add(p)
	p = podLabel("ns2", "pod5", map[string]string{"l1": "v1"})
	p.Status.PodIP = "1.1.1.5"
	cont.fakePodSource.Add(p)
	p = podLabel("ns2", "pod6", map[string]string{"l1": "v2"})
	cont.fakePodSource.Add(p)
	cont.run()

	static := cont.staticNetPolObjs()
	apicapi.PrepareApicSlice(static, staticNetPolKey())
	assert.Equal(t, static,
		cont.apicConn.GetDesiredState(staticNetPolKey()), staticNetPolKey())

	for _, nt := range npTests {
		cont.log.Info("Starting ", nt.desc)
		cont.fakeNetworkPolicySource.Add(nt.netPol)

		tu.WaitFor(t, nt.desc, 500*time.Millisecond,
			func(last bool) (bool, error) {
				cont.indexMutex.Lock()
				defer cont.indexMutex.Unlock()

				slice := apicapi.ApicSlice{nt.aciObj}
				key := cont.aciNameForKey("np",
					nt.netPol.Namespace+"_"+nt.netPol.Name)
				apicapi.PrepareApicSlice(slice, key)

				if !tu.WaitEqual(t, last, slice,
					cont.apicConn.GetDesiredState(key), nt.desc, key) {
					return false, nil
				}
				return true, nil
			})
	}

	cont.log.Info("Starting delete")
	cont.fakeNetworkPolicySource.Delete(npTests[0].netPol)
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

	cont.stop()
}
