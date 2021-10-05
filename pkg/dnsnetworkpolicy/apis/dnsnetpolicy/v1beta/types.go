package v1beta

import (
	v1netpol "github.com/noironetworks/aci-containers/pkg/networkpolicy/apis/netpolicy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +genclient:noStatus
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// dns network Policy
type DnsNetworkPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// Specification of the desired behavior of NetworkPolicy.
	Spec DnsNetworkPolicySpec `json:"spec"`
}

// dns NetworkPolicySpec defines the desired state for NetworkPolicy.
type DnsNetworkPolicySpec struct {
	// Select workloads on which the rules will be applied to. Cannot be set in
	// +optional
	AppliedTo v1netpol.AppliedTo `json:"appliedTo,omitempty"`

	// Set of egress rules evaluated based on the order in which they are set.
	// +optional
	Egress NetworkPolicyEgressRule `json:"egress"`
}

type NetworkPolicyEgressRule struct {
	ToFqdn *v1netpol.FQDN `json:"toFqdn" protobuf:"bytes,1,name=matchname"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// DnsNetworkPolicyList is list of Dns network policies
type DnsNetworkPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []DnsNetworkPolicy `json:"items"`
}
