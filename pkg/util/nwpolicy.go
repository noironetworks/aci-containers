// Copyright 2018 Cisco Systems, Inc.
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

package util

import (
	"fmt"
	"sort"
	"strings"

	v1net "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

func GetNetPolPolicyTypes(indexer cache.Indexer, key string) []v1net.PolicyType {
	npobj, exists, err := indexer.GetByKey(key)
	if !exists || err != nil {
		return nil
	}
	np := npobj.(*v1net.NetworkPolicy)
	if len(np.Spec.PolicyTypes) > 0 {
		return np.Spec.PolicyTypes
	}
	if len(np.Spec.Egress) > 0 {
		return []v1net.PolicyType{
			v1net.PolicyTypeIngress,
			v1net.PolicyTypeEgress,
		}
	} else {
		return []v1net.PolicyType{v1net.PolicyTypeIngress}
	}
}

func CreateHashFromNetPol(np *v1net.NetworkPolicy) (string, error) {
	_, err := cache.MetaNamespaceKeyFunc(np)
	if err != nil {
		return "", err
	}

	var in, e, pt string
	if np.Spec.Ingress != nil && len(np.Spec.Ingress) > 0 {
		in = ingressStrSorted(np)
	}
	if np.Spec.Egress != nil && len(np.Spec.Egress) > 0 {
		e = egressStrSorted(np)
	}
	key := in + e
	if np.Spec.PolicyTypes != nil && len(np.Spec.PolicyTypes) > 0 {
		for _, policyType := range sortPolicyTypes(np.Spec.PolicyTypes) {
			pt += policyType
		}
	}

	key += pt

	return Hash(key), nil
}

func peersToStr(peers []v1net.NetworkPolicyPeer) string {
	pStr := "["
	for _, p := range peers {
		if p.IPBlock != nil {
			pStr += p.IPBlock.CIDR
			if len(p.IPBlock.Except) != 0 {
				pStr += "[except"
				for _, e := range p.IPBlock.Except {
					pStr += fmt.Sprintf("-%s", e)
				}
				pStr += "]"
			}
			pStr += "+"
		}
	}

	pStr = strings.TrimSuffix(pStr, "+")
	pStr += "]"
	return pStr
}

func portsToStr(ports []v1net.NetworkPolicyPort) string {
	pStr := "["

	for _, p := range ports {
		if p.Protocol != nil {
			pStr += string(*p.Protocol)
		}
		if p.Port != nil {
			pStr += ":" + p.Port.String()
		}
		pStr += "+"
	}

	pStr = strings.TrimSuffix(pStr, "+")
	pStr += "]"
	return pStr
}

func egressStrSorted(np *v1net.NetworkPolicy) string {
	var rules []string
	for _, rule := range np.Spec.Egress {
		eStr := ""
		eStr += selectorsToStr(rule.To, np.Namespace)
		eStr += peersToStr(rule.To)
		eStr += portsToStr(rule.Ports)
		rules = append(rules, eStr)
	}
	sort.Slice(rules, func(i, j int) bool {
		return rules[i] < rules[j]
	})
	eStr := ""
	for _, rule := range rules {
		eStr += rule
		eStr += "+"
	}
	eStr = strings.TrimSuffix(eStr, "+")
	return eStr
}

func ingressStrSorted(np *v1net.NetworkPolicy) string {
	var rules []string
	for _, rule := range np.Spec.Ingress {
		iStr := ""
		iStr += selectorsToStr(rule.From, np.Namespace)
		iStr += peersToStr(rule.From)
		iStr += portsToStr(rule.Ports)
		rules = append(rules, iStr)
	}
	sort.Slice(rules, func(i, j int) bool {
		return rules[i] < rules[j]
	})
	iStr := ""
	for _, rule := range rules {
		iStr += rule
		iStr += "+"
	}
	iStr = strings.TrimSuffix(iStr, "+")
	return iStr
}

func sortPolicyTypes(pType []v1net.PolicyType) []string {
	var strPolicyTypes []string
	for _, pt := range pType {
		strPolicyTypes = append(strPolicyTypes, string(pt))
	}
	sort.Slice(strPolicyTypes, func(i, j int) bool {
		return strPolicyTypes[i] < strPolicyTypes[j]
	})
	return strPolicyTypes
}

func selectorsToStr(peers []v1net.NetworkPolicyPeer, ns string) string {
	var str string
	for _, p := range peers {
		podSel := labelSelectorToStr(p.PodSelector)
		str += podSel
		nsSel := labelSelectorToStr(p.NamespaceSelector)
		if podSel != "" && nsSel == "" {
			str += ns
		} else {
			str += nsSel
		}
	}
	return str
}

func labelSelectorToStr(labelsel *metav1.LabelSelector) string {
	var str string
	if labelsel != nil {
		str = "["
		matchLKeys := make([]string, 0, len(labelsel.MatchLabels))
		for k := range labelsel.MatchLabels {
			matchLKeys = append(matchLKeys, k)
		}
		sort.Strings(matchLKeys)
		for _, key := range matchLKeys {
			keyval := key + "_" + labelsel.MatchLabels[key]
			str += keyval
		}
		sort.Slice(labelsel.MatchExpressions, func(i, j int) bool {
			return labelsel.MatchExpressions[i].Key < labelsel.MatchExpressions[j].Key
		})
		for _, expressions := range labelsel.MatchExpressions {
			str += expressions.Key
			str += string(expressions.Operator)
			for _, values := range expressions.Values {
				str += values
			}
		}
		str += "]"
	}
	return str
}

// --- Canonical variants (HPP-direct mode only) ---
//
// These are added alongside the originals so that existing HPP-optimisation
// deployments are not affected. Used only in HPP-direct mode; the originals
// can be removed once HPP-direct is the only supported mode.

func CreateCanonicalHashFromNetPol(np *v1net.NetworkPolicy) (string, error) {
	_, err := cache.MetaNamespaceKeyFunc(np)
	if err != nil {
		return "", err
	}

	var in, e, pt string
	if np.Spec.Ingress != nil && len(np.Spec.Ingress) > 0 {
		in = canonicalIngressStrSorted(np)
	}
	if np.Spec.Egress != nil && len(np.Spec.Egress) > 0 {
		e = canonicalEgressStrSorted(np)
	}
	key := in + e
	if np.Spec.PolicyTypes != nil && len(np.Spec.PolicyTypes) > 0 {
		for _, policyType := range sortPolicyTypes(np.Spec.PolicyTypes) {
			pt += policyType
		}
	}

	key += pt

	return Hash(key), nil
}

func CreateHashFromNetPolPeers(peers []v1net.NetworkPolicyPeer, namespace string, suffix string) string {
	return Hash(canonicalSelectorsToStr(peers, namespace) + canonicalPeersToStr(peers) + suffix)
}

func canonicalPeersToStr(peers []v1net.NetworkPolicyPeer) string {
	var blocks []string
	for _, p := range peers {
		if p.IPBlock != nil {
			b := p.IPBlock.CIDR
			if len(p.IPBlock.Except) != 0 {
				excepts := make([]string, len(p.IPBlock.Except))
				copy(excepts, p.IPBlock.Except)
				sort.Strings(excepts)
				b += "[except"
				for _, e := range excepts {
					b += fmt.Sprintf("-%s", e)
				}
				b += "]"
			}
			blocks = append(blocks, b)
		}
	}
	sort.Strings(blocks)
	return "[" + strings.Join(blocks, "+") + "]"
}

func canonicalPortsToStr(ports []v1net.NetworkPolicyPort) string {
	var portStrs []string
	for _, p := range ports {
		s := ""
		if p.Protocol != nil {
			s += string(*p.Protocol)
		}
		if p.Port != nil {
			s += ":" + p.Port.String()
		}
		portStrs = append(portStrs, s)
	}
	sort.Strings(portStrs)
	return "[" + strings.Join(portStrs, "+") + "]"
}

func canonicalEgressStrSorted(np *v1net.NetworkPolicy) string {
	var rules []string
	for _, rule := range np.Spec.Egress {
		eStr := ""
		eStr += canonicalSelectorsToStr(rule.To, np.Namespace)
		eStr += canonicalPeersToStr(rule.To)
		eStr += canonicalPortsToStr(rule.Ports)
		rules = append(rules, eStr)
	}
	sort.Slice(rules, func(i, j int) bool {
		return rules[i] < rules[j]
	})
	eStr := ""
	for _, rule := range rules {
		eStr += rule
		eStr += "+"
	}
	eStr = strings.TrimSuffix(eStr, "+")
	return eStr
}

func canonicalIngressStrSorted(np *v1net.NetworkPolicy) string {
	var rules []string
	for _, rule := range np.Spec.Ingress {
		iStr := ""
		iStr += canonicalSelectorsToStr(rule.From, np.Namespace)
		iStr += canonicalPeersToStr(rule.From)
		iStr += canonicalPortsToStr(rule.Ports)
		rules = append(rules, iStr)
	}
	sort.Slice(rules, func(i, j int) bool {
		return rules[i] < rules[j]
	})
	iStr := ""
	for _, rule := range rules {
		iStr += rule
		iStr += "+"
	}
	iStr = strings.TrimSuffix(iStr, "+")
	return iStr
}

func canonicalSelectorsToStr(peers []v1net.NetworkPolicyPeer, ns string) string {
	selectors := make([]string, 0, len(peers))
	for _, p := range peers {
		podSel := canonicalLabelSelectorToStr(p.PodSelector)
		nsSel := canonicalLabelSelectorToStr(p.NamespaceSelector)
		if podSel != "" && nsSel == "" {
			selectors = append(selectors, podSel+ns)
		} else if podSel != "" || nsSel != "" {
			selectors = append(selectors, podSel+nsSel)
		}
	}
	sort.Strings(selectors)
	var str string
	for _, s := range selectors {
		str += s
	}
	return str
}

func canonicalLabelSelectorToStr(labelsel *metav1.LabelSelector) string {
	var str string
	if labelsel != nil {
		str = "["
		matchLKeys := make([]string, 0, len(labelsel.MatchLabels))
		for k := range labelsel.MatchLabels {
			matchLKeys = append(matchLKeys, k)
		}
		sort.Strings(matchLKeys)
		for _, key := range matchLKeys {
			str += key + "=" + labelsel.MatchLabels[key]
		}
		exprs := make([]metav1.LabelSelectorRequirement, len(labelsel.MatchExpressions))
		copy(exprs, labelsel.MatchExpressions)
		for i := range exprs {
			vals := make([]string, len(exprs[i].Values))
			copy(vals, exprs[i].Values)
			sort.Strings(vals)
			exprs[i].Values = vals
		}
		sort.Slice(exprs, func(i, j int) bool {
			return lessLabelSelectorRequirement(exprs[i], exprs[j])
		})
		for _, expressions := range exprs {
			str += expressions.Key
			str += string(expressions.Operator)
			for _, values := range expressions.Values {
				str += values
			}
		}
		str += "]"
	}
	return str
}

func lessLabelSelectorRequirement(a, b metav1.LabelSelectorRequirement) bool {
	if a.Key != b.Key {
		return a.Key < b.Key
	}
	if a.Operator != b.Operator {
		return a.Operator < b.Operator
	}
	for i := 0; i < len(a.Values) && i < len(b.Values); i++ {
		if a.Values[i] != b.Values[i] {
			return a.Values[i] < b.Values[i]
		}
	}
	return len(a.Values) < len(b.Values)
}
