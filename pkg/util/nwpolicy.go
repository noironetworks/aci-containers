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
	"context"
	v1betadnsnetpol "github.com/noironetworks/aci-containers/pkg/dnsnetworkpolicy/apis/dnsnetpolicy/v1beta"
	v1netpol "github.com/noironetworks/aci-containers/pkg/networkpolicy/apis/netpolicy/v1"
	v1netpolclset "github.com/noironetworks/aci-containers/pkg/networkpolicy/clientset/versioned"
	v1net "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

func GetNetPolPolicyTypes(indexer cache.Indexer, key string) []v1net.PolicyType {
	npobj, exists, err := indexer.GetByKey(key)
	if !exists || err != nil {
		return nil
	}
	np := npobj.(*v1netpol.NetworkPolicy)
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

// CreateNodeInfoCR Creates a NodeInfo CR
func CreateNetPol(c *v1netpolclset.Clientset, netpol *v1netpol.NetworkPolicy) error {
	_, err := c.AciV1().NetworkPolicies(netpol.ObjectMeta.Namespace).Create(context.TODO(), netpol, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	return nil
}

func UpdateNetPol(c *v1netpolclset.Clientset, netpol *v1netpol.NetworkPolicy) error {
	_, err := c.AciV1().NetworkPolicies(netpol.ObjectMeta.Namespace).Update(context.TODO(), netpol, metav1.UpdateOptions{})
	if err != nil {
		return err
	}
	return nil
}

func DeleteNetPol(c *v1netpolclset.Clientset, name string, namespace string) error {
	err := c.AciV1().NetworkPolicies(namespace).Delete(context.TODO(), name, metav1.DeleteOptions{})
	if err != nil {
		return err
	}
	return nil
}

func GetNetPol(c *v1netpolclset.Clientset, ns string, name string) error {
	_, err := c.AciV1().NetworkPolicies(ns).Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	return nil
}

func GetInternalPolicy(obj interface{}) *v1netpol.NetworkPolicy {
	var intrNP *v1netpol.NetworkPolicy
	switch obj.(type) {
	case *v1net.NetworkPolicy:
		np := obj.(*v1net.NetworkPolicy)
		var ingress []v1netpol.NetworkPolicyIngressRule
		for _, v := range np.Spec.Ingress {
			var ports []v1netpol.NetworkPolicyPort
			for _, port := range v.Ports {
				ports = append(ports, v1netpol.NetworkPolicyPort{Protocol: port.Protocol, Port: port.Port})
			}
			var peers []v1netpol.NetworkPolicyPeer
			for _, peer := range v.From {
				peers = append(peers, v1netpol.NetworkPolicyPeer{IPBlock: peer.IPBlock,
					PodSelector: peer.PodSelector, NamespaceSelector: peer.NamespaceSelector})
			}
			ingress = append(ingress, v1netpol.NetworkPolicyIngressRule{
				Ports: ports,
				From:  peers})
		}
		var egress []v1netpol.NetworkPolicyEgressRule
		for _, v := range np.Spec.Egress {
			var ports []v1netpol.NetworkPolicyPort
			for _, port := range v.Ports {
				ports = append(ports, v1netpol.NetworkPolicyPort{Protocol: port.Protocol, Port: port.Port})
			}
			var peers []v1netpol.NetworkPolicyPeer
			for _, peer := range v.To {
				peers = append(peers, v1netpol.NetworkPolicyPeer{IPBlock: peer.IPBlock, PodSelector: peer.PodSelector,
					NamespaceSelector: peer.NamespaceSelector})
			}
			egress = append(egress, v1netpol.NetworkPolicyEgressRule{
				Ports: ports,
				To:    peers,
			})
		}
		intrNP = &v1netpol.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      np.ObjectMeta.Name,
				Namespace: np.ObjectMeta.Namespace,
			},
			Spec: v1netpol.NetworkPolicySpec{
				Type:        v1netpol.K8sNetworkPolicy,
				PolicyTypes: np.Spec.PolicyTypes,
				AppliedTo:   v1netpol.AppliedTo{PodSelector: &np.Spec.PodSelector},
				Ingress:     ingress,
				Egress:      egress,
			},
		}
	case *v1betadnsnetpol.DnsNetworkPolicy:
		np := obj.(*v1betadnsnetpol.DnsNetworkPolicy)
		var egress []v1netpol.NetworkPolicyEgressRule
		egress = append(egress, v1netpol.NetworkPolicyEgressRule{
			ToFqdn: np.Spec.Egress.ToFqdn,
		})
		intrNP = &v1netpol.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      np.ObjectMeta.Name,
				Namespace: np.ObjectMeta.Namespace,
			},
			Spec: v1netpol.NetworkPolicySpec{
				Type:      v1netpol.DnsAwareNetworkPolicy,
				AppliedTo: np.Spec.AppliedTo,
				Egress:    egress,
			},
		}

	}
	return intrNP
}
