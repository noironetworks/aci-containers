// Copyright 2026 Cisco Systems, Inc.
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

package util

import (
	"reflect"
	"testing"

	v1 "k8s.io/api/core/v1"
	v1net "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func netPolWithIngressPeers(peers []v1net.NetworkPolicyPeer) *v1net.NetworkPolicy {
	return &v1net.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "policy",
			Namespace: "default",
		},
		Spec: v1net.NetworkPolicySpec{
			Ingress: []v1net.NetworkPolicyIngressRule{{From: peers}},
		},
	}
}

func TestCreateHashFromNetPolIgnoresPeerOrder(t *testing.T) {
	podPeer := v1net.NetworkPolicyPeer{
		PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
	}
	namespacePeer := v1net.NetworkPolicyPeer{
		NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"environment": "prod"}},
	}

	firstHash, err := CreateCanonicalHashFromNetPol(netPolWithIngressPeers([]v1net.NetworkPolicyPeer{podPeer, namespacePeer}))
	if err != nil {
		t.Fatalf("hash first policy: %v", err)
	}
	secondHash, err := CreateCanonicalHashFromNetPol(netPolWithIngressPeers([]v1net.NetworkPolicyPeer{namespacePeer, podPeer}))
	if err != nil {
		t.Fatalf("hash second policy: %v", err)
	}
	if firstHash != secondHash {
		t.Errorf("hash differs with peer order: %q != %q", firstHash, secondHash)
	}
}

func TestCreateHashFromNetPolCanonicalizesSelectorValuesWithoutMutation(t *testing.T) {
	selector := &metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{
			{Key: "role", Operator: metav1.LabelSelectorOpIn, Values: []string{"web", "api"}},
			{Key: "tier", Operator: metav1.LabelSelectorOpIn, Values: []string{"frontend", "backend"}},
		},
	}
	original := selector.DeepCopy()

	firstHash, err := CreateCanonicalHashFromNetPol(netPolWithIngressPeers([]v1net.NetworkPolicyPeer{{PodSelector: selector}}))
	if err != nil {
		t.Fatalf("hash first policy: %v", err)
	}
	if !reflect.DeepEqual(selector, original) {
		t.Errorf("CreateHashFromNetPol mutated selector: got %#v, want %#v", selector, original)
	}

	reorderedSelector := &metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{
			{Key: "tier", Operator: metav1.LabelSelectorOpIn, Values: []string{"backend", "frontend"}},
			{Key: "role", Operator: metav1.LabelSelectorOpIn, Values: []string{"api", "web"}},
		},
	}
	secondHash, err := CreateCanonicalHashFromNetPol(netPolWithIngressPeers([]v1net.NetworkPolicyPeer{{PodSelector: reorderedSelector}}))
	if err != nil {
		t.Fatalf("hash second policy: %v", err)
	}
	if firstHash != secondHash {
		t.Errorf("hash differs with selector expression/value order: %q != %q", firstHash, secondHash)
	}
}

func TestCreateHashFromNetPolDistinguishesMatchLabelBoundaries(t *testing.T) {
	firstHash, err := CreateCanonicalHashFromNetPol(netPolWithIngressPeers([]v1net.NetworkPolicyPeer{{
		PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"a_b": "c"}},
	}}))
	if err != nil {
		t.Fatalf("hash first policy: %v", err)
	}
	secondHash, err := CreateCanonicalHashFromNetPol(netPolWithIngressPeers([]v1net.NetworkPolicyPeer{{
		PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"a": "b_c"}},
	}}))
	if err != nil {
		t.Fatalf("hash second policy: %v", err)
	}
	if firstHash == secondHash {
		t.Errorf("hash is identical for distinct match labels: %q", firstHash)
	}
}

func TestCreateHashFromNetPolCanonicalizesSameKeyRequirements(t *testing.T) {
	firstSelector := &metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{
			{Key: "role", Operator: metav1.LabelSelectorOpNotIn, Values: []string{"batch", "cron"}},
			{Key: "role", Operator: metav1.LabelSelectorOpIn, Values: []string{"web", "api"}},
		},
	}
	secondSelector := &metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{
			{Key: "role", Operator: metav1.LabelSelectorOpIn, Values: []string{"api", "web"}},
			{Key: "role", Operator: metav1.LabelSelectorOpNotIn, Values: []string{"cron", "batch"}},
		},
	}

	firstHash, err := CreateCanonicalHashFromNetPol(netPolWithIngressPeers([]v1net.NetworkPolicyPeer{{PodSelector: firstSelector}}))
	if err != nil {
		t.Fatalf("hash first policy: %v", err)
	}
	secondHash, err := CreateCanonicalHashFromNetPol(netPolWithIngressPeers([]v1net.NetworkPolicyPeer{{PodSelector: secondSelector}}))
	if err != nil {
		t.Fatalf("hash second policy: %v", err)
	}
	if firstHash != secondHash {
		t.Errorf("hash differs with same-key requirements reordered: %q != %q", firstHash, secondHash)
	}
}

func TestCreateHashFromNetPolPeersDistinguishesPeerBoundaries(t *testing.T) {
	podSelector := &metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}}
	namespaceSelector := &metav1.LabelSelector{MatchLabels: map[string]string{"team": "payments"}}

	separatePeersHash := CreateHashFromNetPolPeers([]v1net.NetworkPolicyPeer{
		{PodSelector: podSelector},
		{NamespaceSelector: namespaceSelector},
	}, "default")

	combinedPeerHash := CreateHashFromNetPolPeers([]v1net.NetworkPolicyPeer{{
		PodSelector:       podSelector,
		NamespaceSelector: namespaceSelector,
	}}, "default")

	if separatePeersHash == combinedPeerHash {
		t.Errorf("hash is identical for distinct peer groupings: %q", separatePeersHash)
	}
}

func TestCanonicalHashIgnoresIPBlockOrder(t *testing.T) {
	proto := v1.ProtocolTCP
	np1 := &v1net.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "policy", Namespace: "default"},
		Spec: v1net.NetworkPolicySpec{
			Egress: []v1net.NetworkPolicyEgressRule{{
				To: []v1net.NetworkPolicyPeer{
					{IPBlock: &v1net.IPBlock{CIDR: "10.0.0.0/8", Except: []string{"10.1.0.0/16", "10.2.0.0/16"}}},
					{IPBlock: &v1net.IPBlock{CIDR: "192.168.0.0/16"}},
				},
				Ports: []v1net.NetworkPolicyPort{{Protocol: &proto}},
			}},
		},
	}
	np2 := &v1net.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "policy", Namespace: "default"},
		Spec: v1net.NetworkPolicySpec{
			Egress: []v1net.NetworkPolicyEgressRule{{
				To: []v1net.NetworkPolicyPeer{
					{IPBlock: &v1net.IPBlock{CIDR: "192.168.0.0/16"}},
					{IPBlock: &v1net.IPBlock{CIDR: "10.0.0.0/8", Except: []string{"10.2.0.0/16", "10.1.0.0/16"}}},
				},
				Ports: []v1net.NetworkPolicyPort{{Protocol: &proto}},
			}},
		},
	}
	h1, err := CreateCanonicalHashFromNetPol(np1)
	if err != nil {
		t.Fatalf("hash np1: %v", err)
	}
	h2, err := CreateCanonicalHashFromNetPol(np2)
	if err != nil {
		t.Fatalf("hash np2: %v", err)
	}
	if h1 != h2 {
		t.Errorf("hash differs with IPBlock/Except reordered: %q != %q", h1, h2)
	}
}

func TestCanonicalHashIgnoresPortOrder(t *testing.T) {
	tcp := v1.ProtocolTCP
	udp := v1.ProtocolUDP
	np1 := &v1net.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "policy", Namespace: "default"},
		Spec: v1net.NetworkPolicySpec{
			Ingress: []v1net.NetworkPolicyIngressRule{{
				Ports: []v1net.NetworkPolicyPort{{Protocol: &tcp}, {Protocol: &udp}},
			}},
		},
	}
	np2 := &v1net.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "policy", Namespace: "default"},
		Spec: v1net.NetworkPolicySpec{
			Ingress: []v1net.NetworkPolicyIngressRule{{
				Ports: []v1net.NetworkPolicyPort{{Protocol: &udp}, {Protocol: &tcp}},
			}},
		},
	}
	h1, err := CreateCanonicalHashFromNetPol(np1)
	if err != nil {
		t.Fatalf("hash np1: %v", err)
	}
	h2, err := CreateCanonicalHashFromNetPol(np2)
	if err != nil {
		t.Fatalf("hash np2: %v", err)
	}
	if h1 != h2 {
		t.Errorf("hash differs with port order: %q != %q", h1, h2)
	}
}

func int32Ptr(v int32) *int32 { return &v }

// npWithRules builds a policy with the given ingress/egress rules and policyTypes.
func npWithRules(ingress []v1net.NetworkPolicyIngressRule, egress []v1net.NetworkPolicyEgressRule, pt []v1net.PolicyType) *v1net.NetworkPolicy {
	return &v1net.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "policy", Namespace: "default"},
		Spec: v1net.NetworkPolicySpec{
			Ingress:     ingress,
			Egress:      egress,
			PolicyTypes: pt,
		},
	}
}

// Class 2: an ingress rule and an egress rule with identical peer/port text and
// identical policyTypes must not collapse onto one HPP.
func TestCanonicalHashDistinguishesDirection(t *testing.T) {
	tcp := v1.ProtocolTCP
	port := intstr.FromInt(32501)
	rulePorts := []v1net.NetworkPolicyPort{{Protocol: &tcp, Port: &port}}
	both := []v1net.PolicyType{v1net.PolicyTypeIngress, v1net.PolicyTypeEgress}

	ingressOnly := npWithRules(
		[]v1net.NetworkPolicyIngressRule{{Ports: rulePorts}}, nil, both)
	egressOnly := npWithRules(
		nil, []v1net.NetworkPolicyEgressRule{{Ports: rulePorts}}, both)

	h1, err := CreateCanonicalHashFromNetPol(ingressOnly)
	if err != nil {
		t.Fatalf("hash ingress: %v", err)
	}
	h2, err := CreateCanonicalHashFromNetPol(egressOnly)
	if err != nil {
		t.Fatalf("hash egress: %v", err)
	}
	if h1 == h2 {
		t.Errorf("ingress-only and egress-only policies collapsed to one hash: %q", h1)
	}
}

// Class 3: different endPort values (and absent endPort) must differ.
func TestCanonicalHashDistinguishesEndPort(t *testing.T) {
	tcp := v1.ProtocolTCP
	port := intstr.FromInt(32400)
	mk := func(end *int32) *v1net.NetworkPolicy {
		return npWithRules([]v1net.NetworkPolicyIngressRule{{
			Ports: []v1net.NetworkPolicyPort{{Protocol: &tcp, Port: &port, EndPort: end}},
		}}, nil, nil)
	}
	h401, err := CreateCanonicalHashFromNetPol(mk(int32Ptr(32401)))
	if err != nil {
		t.Fatalf("hash 401: %v", err)
	}
	h402, err := CreateCanonicalHashFromNetPol(mk(int32Ptr(32402)))
	if err != nil {
		t.Fatalf("hash 402: %v", err)
	}
	hNone, err := CreateCanonicalHashFromNetPol(mk(nil))
	if err != nil {
		t.Fatalf("hash none: %v", err)
	}
	if h401 == h402 {
		t.Errorf("32400-32401 and 32400-32402 collapsed: %q", h401)
	}
	if h401 == hNone || h402 == hNone {
		t.Errorf("ranged and unranged ports collapsed: %q / %q / %q", h401, h402, hNone)
	}
}

// Selector nil vs empty {}: an absent podSelector must differ from a present
// empty selector (which matches all pods).
func TestCanonicalHashDistinguishesNilVsEmptySelector(t *testing.T) {
	nilSel := CreateHashFromNetPolPeers([]v1net.NetworkPolicyPeer{
		{NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"team": "x"}}},
	}, "default")
	emptyPodSel := CreateHashFromNetPolPeers([]v1net.NetworkPolicyPeer{{
		PodSelector:       &metav1.LabelSelector{},
		NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"team": "x"}},
	}}, "default")
	if nilSel == emptyPodSel {
		t.Errorf("nil podSelector and empty podSelector collapsed: %q", nilSel)
	}
}

// Empty-peer handling (retained original behavior): a fully empty peer is
// dropped so [{}] equals an empty peer list, but an all-pods peer
// [{podSelector:{}}] stays distinct.
func TestCanonicalHashEmptyPeerHandling(t *testing.T) {
	none := CreateHashFromNetPolPeers(nil, "default")
	emptyPeer := CreateHashFromNetPolPeers([]v1net.NetworkPolicyPeer{{}}, "default")
	allPods := CreateHashFromNetPolPeers([]v1net.NetworkPolicyPeer{
		{PodSelector: &metav1.LabelSelector{}},
	}, "default")
	if none != emptyPeer {
		t.Errorf("fully-empty peer not dropped: %q != %q", none, emptyPeer)
	}
	if none == allPods {
		t.Errorf("all-pods peer collapsed with allow-all: %q", none)
	}
}

func TestCreateHashFromNetPolPeersDistinguishesNamedPortScope(t *testing.T) {
	peers := []v1net.NetworkPolicyPeer{
		{PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}}},
	}
	http := CreateHashFromNetPolPeersWithNamedPort(
		peers, "default", "tcp", "http", "8080")
	metrics := CreateHashFromNetPolPeersWithNamedPort(
		peers, "default", "tcp", "metrics", "8080")
	if http == metrics {
		t.Errorf("different named ports at the same number collapsed: %q", http)
	}

	unscoped := CreateHashFromNetPolPeers(peers, "default")
	if http == unscoped {
		t.Errorf("named-port-scoped and unscoped RICs collapsed: %q", http)
	}

	udpHTTP := CreateHashFromNetPolPeersWithNamedPort(
		peers, "default", "udp", "http", "8080")
	if http == udpHTTP {
		t.Errorf("different named-port protocols collapsed: %q", http)
	}

	http9090 := CreateHashFromNetPolPeersWithNamedPort(
		peers, "default", "tcp", "http", "9090")
	if http == http9090 {
		t.Errorf("different named-port numbers collapsed: %q", http)
	}

	httpAgain := CreateHashFromNetPolPeersWithNamedPort(
		peers, "default", "tcp", "http", "8080")
	if http != httpAgain {
		t.Errorf("identical named-port scopes produced different hashes: %q != %q",
			http, httpAgain)
	}
}
