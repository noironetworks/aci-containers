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

type ProactiveConfSpec struct {
	TunnelEpAdvertisementInterval uint64                        `json:"TunnelEpAdvertisementInterval,omitempty"`
	VmmEpgDeploymentImmediacy     VmmEpgDeploymentImmediacyType `json:"VmmEpgDeploymentImmediacy,omitempty"`
}

// +genclient
// +genclient:noStatus
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:scope=Cluster
// ProactiveConf is the Schema for the proactiveconfs API
type ProactiveConf struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec ProactiveConfSpec `json:"spec,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// ProactiveConfList contains a list of ProactiveConf
type ProactiveConfList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ProactiveConf `json:"items"`
}
