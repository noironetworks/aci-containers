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
	if np.Spec.PolicyTypes != nil && len(np.Spec.PolicyTypes) > 0 {
		for _, policyType := range sortPolicyTypes(np.Spec.PolicyTypes) {
			pt += policyType
		}
	}

	key := in + e

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
	eStr := ""
	for _, rule := range np.Spec.Egress {
		eStr += selectorsToStr(rule.To, np.Namespace)
		eStr += peersToStr(rule.To)
		eStr += portsToStr(rule.Ports)
		eStr += "+"
	}
	eStr = strings.TrimSuffix(eStr, "+")
	return eStr
}

func ingressStrSorted(np *v1net.NetworkPolicy) string {
	iStr := ""
	for _, rule := range np.Spec.Ingress {
		iStr += selectorsToStr(rule.From, np.Namespace)
		iStr += peersToStr(rule.From)
		iStr += portsToStr(rule.Ports)
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
		for key, val := range labelsel.MatchLabels {
			keyval := key + "_" + val
			str += keyval
		}
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
