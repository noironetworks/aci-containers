package v1alpha

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type PolicyState string

const (
	Ready  PolicyState = "Ready"
	Failed PolicyState = "Failed"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// NetflowPolicySpec defines the desired state of NetflowPolicy
type NetflowPolicySpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "operator-sdk generate k8s" to regenerate code after modifying this file
	// Add custom validation using kubebuilder tags: https://book.kubebuilder.io/beyond_basics/generating_crd.html

	FlowSamplingPolicy NetflowType `json:"flowSamplingPolicy,omitempty"`
}

// NetflowType contains all the attrbutes of Netflow Policy.
type NetflowType struct {
	// Remote node destination IP address.
	DstAddr string `json:"destIp"`
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=65535
	// +kubebuilder:default:=2055
	DstPort int `json:"destPort"`
	// +kubebuilder:validation:Enum=netflow,ipfix
	// +optional
	// +kubebuilder:default:=netflow
	FlowType string `json:"flowType,omitempty"`
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=3600
	// Specifies the timeout for an active flow.
	// +optional
	// +kubebuilder:default:=60
	ActiveFlowTimeOut int `json:"activeFlowTimeOut,omitempty"`
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=600
	// Specifies the timeout for an idle flow.
	// +optional
	// +kubebuilder:default:=15
	IdleFlowTimeOut int `json:"idleFlowTimeOut,omitempty"`
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=1000
	// +optional
	// +kubebuilder:default:=0
	SamplingRate int `json:"samplingRate,omitempty"`
}

// NetflowPolicyStatus defines the observed state of NetflowPolicy
type NetflowPolicyStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "operator-sdk generate k8s" to regenerate code after modifying this file7
	// Add custom validation using kubebuilder tags: https://book.kubebuilder.io/beyond_basics/generating_crd.html
	State PolicyState `json:"state"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// NetflowPolicy is the Schema for the netflowpolicies API
type NetflowPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   NetflowPolicySpec   `json:"spec,omitempty"`
	Status NetflowPolicyStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// NetflowPolicyList contains a list of NetflowPolicy
type NetflowPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NetflowPolicy `json:"items"`
}
