package v1

import (
	v1 "k8s.io/api/core/v1"
	v1net "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

type NetworkPolicyType string

const (
	K8sNetworkPolicy      NetworkPolicyType = "K8sNetworkPolicy"
	ClusterNetworkPolicy  NetworkPolicyType = "ClusterNetworkPolicy"
	DnsAwareNetworkPolicy NetworkPolicyType = "DnsAwareNetworkPolicy"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// network Policy
type NetworkPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// Specification of the desired behavior of NetworkPolicy.
	Spec NetworkPolicySpec `json:"spec"`
}

// NetworkPolicySpec defines the desired state for NetworkPolicy.
type NetworkPolicySpec struct {
	// type of the policy.
	Type NetworkPolicyType `json:"type"`
	// Priority specfies the order of the NetworkPolicy relative to other
	// NetworkPolicies.
	// +optional
	Priority *int `json:"priority"`
	// Select workloads on which the rules will be applied to. Cannot be set in
	// +optional
	AppliedTo AppliedTo `json:"appliedTo,omitempty"`
	// Set of ingress rules evaluated based on the order in which they are set.
	// +optional
	Ingress []NetworkPolicyIngressRule `json:"ingress"`
	// Set of egress rules evaluated based on the order in which they are set.
	// +optional
	Egress []NetworkPolicyEgressRule `json:"egress"`
	// +optional
	PolicyTypes []v1net.PolicyType `json:"policyTypes,omitempty" protobuf:"bytes,4,rep,name=policyTypes,casttype=PolicyType"`
}

type AppliedTo struct {
	// allow ingress from the same namespace
	// +optional
	PodSelector *metav1.LabelSelector `json:"podSelector"`
	// +optional
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector"`
}

type NetworkPolicyIngressRule struct {
	// Action specifies the action to be applied on the rule.
	// +optional
	Action *RuleAction `json:"action"`
	// Set of port and protocol allowed/denied by the rule. If this field is unset
	// or empty, this rule matches all ports.
	// +optional
	Ports []NetworkPolicyPort `json:"ports,omitempty"`
	// Rule is matched if traffic originates from workloads selected by
	// this field. If this field is empty, this rule matches all sources.
	// +optional
	From []NetworkPolicyPeer `json:"from"`
	// EnableLogging is used to indicate if agent should generate logs
	// when rules are matched. Should be default to false.
	// +optional
	EnableLogging bool `json:"enableLogging"`
}

type NetworkPolicyEgressRule struct {
	// Action specifies the action to be applied on the rule.
	// +optional
	Action *RuleAction `json:"action"`
	// Set of port and protocol allowed/denied by the rule. If this field is unset
	// or empty, this rule matches all ports.
	// +optional
	Ports []NetworkPolicyPort `json:"ports,omitempty"`
	// Rule is matched if traffic is intended for workloads selected by
	// this field. If this field is empty or missing, this rule matches all
	// destinations.
	// +optional
	To []NetworkPolicyPeer `json:"to"`

	// EnableLogging is used to indicate if agent should generate logs
	// default to false.
	// +optinal
	EnableLogging bool `json:"enableLogging"`
	// +optinal
	ToFqdn *FQDN `json:"toFqDn" protobuf:"bytes,1,name=matchname"`
}

type FQDN struct {
	MatchNames []string `json:"matchNames" protobuf:"bytes,1,name=matchname"`
}

type NetworkPolicyPeer struct {
	// IPBlock describes the IPAddresses/IPBlocks that is matched in to/from.
	// IPBlock cannot be set as part of the AppliedTo field.
	// Cannot be set with any other selector.
	// +optional
	IPBlock *v1net.IPBlock `json:"ipBlock,omitempty"`
	// Select Pods from NetworkPolicy's Namespace as workloads in
	// AppliedTo/To/From fields. If set with NamespaceSelector, Pods are
	// matched from Namespaces matched by the NamespaceSelector.
	// Cannot be set with any other selector except NamespaceSelector.
	// +optional
	PodSelector *metav1.LabelSelector `json:"podSelector,omitempty"`
	// Select all Pods from Namespaces matched by this selector, as
	// workloads in To/From fields. If set with PodSelector,
	// Pods are matched from Namespaces matched by the NamespaceSelector.
	// Cannot be set with any other selector except PodSelector or
	// ExternalEntitySelector.
	// +optional
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector,omitempty"`
}

type IPBlock struct {
	// CIDR is a string representing the IP Block
	CIDR string `json:"cidr"`
	// Except is a slice of CIDRs that should not be included within an IP Block
	// Valid examples are "192.168.1.1/24" or "2001:db9::/64"
	// Except values will be rejected if they are outside the CIDR range
	// +optional
	Except []string `json:"except,omitempty" protobuf:"bytes,2,rep,name=except"`
}

// NetworkPolicyPort describes the port and protocol to match in a rule.
type NetworkPolicyPort struct {
	// The protocol (TCP, UDP, or SCTP) which traffic must match.
	// If not specified, this field defaults to TCP.
	// +optional
	Protocol *v1.Protocol `json:"protocol,omitempty"`
	// The port on the given protocol. This can be either a numerical
	// or named port on a Pod. If this field is not provided, this
	// matches all port names and numbers.
	// +optional
	Port *intstr.IntOrString `json:"port,omitempty"`
	// EndPort defines the end of the port range, being the end included within the range.
	// It can only be specified when a numerical `port` is specified.
	// +optional
	EndPort *int32 `json:"endPort,omitempty"`
}

// RuleAction describes the action to be applied on traffic matching a rule.
type RuleAction string

const (
	// matching traffic must be allowed.
	RuleActionAllow RuleAction = "Allow"
	// matching traffic must be dropped.
	RuleActionDrop RuleAction = "Drop"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type NetworkPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []NetworkPolicy `json:"items"`
}
