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
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	v1 "k8s.io/client-go/pkg/api/v1"
	v1beta1 "k8s.io/client-go/pkg/apis/extensions/v1beta1"

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
	netPol  *v1beta1.NetworkPolicy
	aciObjs map[aimKey]aciSlice
	desc    string
}

func staticNetPolKey() aimKey {
	return aimKey{"StaticNetworkPolicy", "static"}
}

func TestNetworkPolicy(t *testing.T) {
	tcp := "TCP"
	udp := "UDP"
	port80 := 80
	port443 := 443

	rule_0_0 := NewSecurityGroupRule("test-tenant", "np__testns_np1",
		"NetworkPolicy", "0")
	rule_0_0.Spec.SecurityGroupRule.Direction = "ingress"
	rule_0_0.Spec.SecurityGroupRule.Ethertype = "ipv4"

	rule_1_0 := NewSecurityGroupRule("test-tenant", "np__testns_np1",
		"NetworkPolicy", "0_0")
	rule_1_0.Spec.SecurityGroupRule.Direction = "ingress"
	rule_1_0.Spec.SecurityGroupRule.Ethertype = "ipv4"
	rule_1_0.Spec.SecurityGroupRule.IpProtocol = "tcp"
	rule_1_0.Spec.SecurityGroupRule.ToPort = "80"

	rule_3_0 := NewSecurityGroupRule("test-tenant", "np__testns_np1",
		"NetworkPolicy", "0_0")
	rule_3_0.Spec.SecurityGroupRule.Direction = "ingress"
	rule_3_0.Spec.SecurityGroupRule.Ethertype = "ipv4"
	rule_3_0.Spec.SecurityGroupRule.IpProtocol = "udp"
	rule_3_0.Spec.SecurityGroupRule.ToPort = "80"

	rule_4_1 := NewSecurityGroupRule("test-tenant", "np__testns_np1",
		"NetworkPolicy", "0_1")
	rule_4_1.Spec.SecurityGroupRule.Direction = "ingress"
	rule_4_1.Spec.SecurityGroupRule.Ethertype = "ipv4"
	rule_4_1.Spec.SecurityGroupRule.IpProtocol = "tcp"
	rule_4_1.Spec.SecurityGroupRule.ToPort = "443"

	rule_5_0 := NewSecurityGroupRule("test-tenant", "np__testns_np1",
		"NetworkPolicy", "0")
	rule_5_0.Spec.SecurityGroupRule.Direction = "ingress"
	rule_5_0.Spec.SecurityGroupRule.Ethertype = "ipv4"
	rule_5_0.Spec.SecurityGroupRule.RemoteIps = []string{"1.1.1.1", "1.1.1.2"}

	rule_6_0 := NewSecurityGroupRule("test-tenant", "np__testns_np1",
		"NetworkPolicy", "0")
	rule_6_0.Spec.SecurityGroupRule.Direction = "ingress"
	rule_6_0.Spec.SecurityGroupRule.Ethertype = "ipv4"
	rule_6_0.Spec.SecurityGroupRule.RemoteIps =
		[]string{"1.1.1.3", "1.1.1.4", "1.1.1.5"}

	rule_7_0 := NewSecurityGroupRule("test-tenant", "np__testns_np1",
		"NetworkPolicy", "0")
	rule_7_0.Spec.SecurityGroupRule.Direction = "ingress"
	rule_7_0.Spec.SecurityGroupRule.Ethertype = "ipv4"
	rule_7_0.Spec.SecurityGroupRule.RemoteIps =
		[]string{"1.1.1.1"}

	rule_8_0 := NewSecurityGroupRule("test-tenant", "np__testns_np1",
		"NetworkPolicy", "0_0")
	rule_8_0.Spec.SecurityGroupRule.Direction = "ingress"
	rule_8_0.Spec.SecurityGroupRule.Ethertype = "ipv4"
	rule_8_0.Spec.SecurityGroupRule.IpProtocol = "tcp"
	rule_8_0.Spec.SecurityGroupRule.ToPort = "80"
	rule_8_0.Spec.SecurityGroupRule.RemoteIps =
		[]string{"1.1.1.1"}
	rule_8_1 := NewSecurityGroupRule("test-tenant", "np__testns_np1",
		"NetworkPolicy", "1_0")
	rule_8_1.Spec.SecurityGroupRule.Direction = "ingress"
	rule_8_1.Spec.SecurityGroupRule.Ethertype = "ipv4"
	rule_8_1.Spec.SecurityGroupRule.IpProtocol = "tcp"
	rule_8_1.Spec.SecurityGroupRule.ToPort = "443"
	rule_8_1.Spec.SecurityGroupRule.RemoteIps =
		[]string{"1.1.1.2"}

	baseSlice := func() aciSlice {
		return aciSlice{
			NewSecurityGroup("test-tenant", "np__testns_np1"),
			NewSecurityGroupSubject("test-tenant", "np__testns_np1",
				"NetworkPolicy"),
		}
	}

	var npTests = []npTest{
		{netpol("testns", "np1", &metav1.LabelSelector{},
			[]v1beta1.NetworkPolicyIngressRule{rule(nil, nil)}),
			map[aimKey]aciSlice{
				aimKey{"NetworkPolicy", "np__testns_np1"}: append(baseSlice(),
					rule_0_0),
			}, "allow-all"},
		{netpol("testns", "np1", &metav1.LabelSelector{},
			[]v1beta1.NetworkPolicyIngressRule{
				rule([]v1beta1.NetworkPolicyPort{port(&tcp, &port80)}, nil)}),
			map[aimKey]aciSlice{
				aimKey{"NetworkPolicy", "np__testns_np1"}: append(baseSlice(),
					rule_1_0),
			}, "allow-http"},
		{netpol("testns", "np1", &metav1.LabelSelector{},
			[]v1beta1.NetworkPolicyIngressRule{
				rule([]v1beta1.NetworkPolicyPort{port(nil, &port80)}, nil)}),
			map[aimKey]aciSlice{
				aimKey{"NetworkPolicy", "np__testns_np1"}: append(baseSlice(),
					rule_1_0),
			}, "allow-http-defproto"},
		{netpol("testns", "np1", &metav1.LabelSelector{},
			[]v1beta1.NetworkPolicyIngressRule{
				rule([]v1beta1.NetworkPolicyPort{port(&udp, &port80)}, nil)}),
			map[aimKey]aciSlice{
				aimKey{"NetworkPolicy", "np__testns_np1"}: append(baseSlice(),
					rule_3_0),
			}, "allow-80-udp"},
		{netpol("testns", "np1", &metav1.LabelSelector{},
			[]v1beta1.NetworkPolicyIngressRule{
				rule([]v1beta1.NetworkPolicyPort{
					port(nil, &port80), port(nil, &port443),
				}, nil)}),
			map[aimKey]aciSlice{
				aimKey{"NetworkPolicy", "np__testns_np1"}: append(baseSlice(),
					rule_1_0, rule_4_1),
			}, "allow-http-https"},
		{netpol("testns", "np1", &metav1.LabelSelector{},
			[]v1beta1.NetworkPolicyIngressRule{rule(nil,
				[]v1beta1.NetworkPolicyPeer{peer(nil,
					&metav1.LabelSelector{
						MatchLabels: map[string]string{"test": "testv"},
					}),
				}),
			}),
			map[aimKey]aciSlice{
				aimKey{"NetworkPolicy", "np__testns_np1"}: append(baseSlice(),
					rule_5_0),
			}, "allow-all-from-ns"},
		{netpol("testns", "np1", &metav1.LabelSelector{},
			[]v1beta1.NetworkPolicyIngressRule{rule(nil,
				[]v1beta1.NetworkPolicyPeer{peer(nil,
					&metav1.LabelSelector{
						MatchLabels: map[string]string{"nl": "nv"},
					}),
				}),
			}),
			map[aimKey]aciSlice{
				aimKey{"NetworkPolicy", "np__testns_np1"}: append(baseSlice(),
					rule_6_0),
			}, "allow-all-from-multiple-ns"},
		{netpol("testns", "np1", &metav1.LabelSelector{},
			[]v1beta1.NetworkPolicyIngressRule{rule(nil,
				[]v1beta1.NetworkPolicyPeer{
					peer(&metav1.LabelSelector{
						MatchLabels: map[string]string{"l1": "v1"},
					}, nil),
				}),
			}),
			map[aimKey]aciSlice{
				aimKey{"NetworkPolicy", "np__testns_np1"}: append(baseSlice(),
					rule_7_0),
			}, "allow-all-select-pods"},
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
			map[aimKey]aciSlice{
				aimKey{"NetworkPolicy", "np__testns_np1"}: append(baseSlice(),
					rule_8_0, rule_8_1),
			}, "multiple-from"},
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
	fixAciSlice(static, staticNetPolKey().ktype, staticNetPolKey().key)
	assert.Equal(t, static,
		cont.aimDesiredState[staticNetPolKey()], "np__static")

	for _, nt := range npTests {
		cont.log.Info("Starting ", nt.desc)
		cont.fakeNetworkPolicySource.Add(nt.netPol)

		tu.WaitFor(t, nt.desc, 500*time.Millisecond,
			func(last bool) (bool, error) {
				cont.indexMutex.Lock()
				defer cont.indexMutex.Unlock()

				for key, slice := range nt.aciObjs {
					fixAciSlice(slice, "NetworkPolicy",
						cont.aciNameForKey("np",
							nt.netPol.Namespace+"_"+nt.netPol.Name))
					if !tu.WaitEqual(t, last, slice,
						cont.aimDesiredState[key], nt.desc, key) {
						return false, nil
					}
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

			for key, _ := range npTests[0].aciObjs {
				if !tu.WaitEqual(t, last, 0,
					len(cont.aimDesiredState[key]), "delete") {
					return false, nil
				}
			}
			return true, nil
		})

	cont.stop()
}
