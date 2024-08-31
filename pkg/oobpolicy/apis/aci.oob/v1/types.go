package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +kubebuilder:validation:Enum=Immediate;OnDemand
type VmmEpgDeploymentImmediacyType string

const (
	VmmEpgDeploymentImmediacyTypeImmediate VmmEpgDeploymentImmediacyType = "Immediate"
	VmmEpgDeploymentImmediacyTypeOnDemand  VmmEpgDeploymentImmediacyType = "OnDemand"
)

type OutOfBandPolicySpec struct {
	TunnelEpAdvertisementInterval uint64                        `json:"TunnelEpAdvertisementInterval,omitempty"`
	VmmEpgDeploymentImmediacy     VmmEpgDeploymentImmediacyType `json:"VmmEpgDeploymentImmediacy,omitempty"`
}

// +genclient
// +genclient:noStatus
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:scope=Cluster
// OutOfBandPolicy is the Schema for the outofbandpolicies API
type OutOfBandPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec OutOfBandPolicySpec `json:"spec,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// OutOfBandPolicyList contains a list of OutOfBandPolicy
type OutOfBandPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OutOfBandPolicy `json:"items"`
}
