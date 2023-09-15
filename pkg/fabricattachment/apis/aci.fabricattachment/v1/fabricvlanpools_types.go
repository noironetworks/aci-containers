package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type FabricVlanPoolState string

const (
	FabricVlanPoolValid   FabricVlanPoolState = "valid"
	FabricVlanPoolInvalid FabricVlanPoolState = "invalid"
)

// FabricVlanPoolStatus defines the observed state of FabricVlanPool
type FabricVlanPoolStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "operator-sdk generate k8s" to regenerate code after modifying this file7
	// Add custom validation using kubebuilder tags: https://book.kubebuilder.io/beyond_basics/generating_crd.html
	State FabricVlanPoolState `json:"state,omitempty"`
	Error string              `json:"error,omitempty"`
}

// FabricVlanPoolSpec defines the list of vlans in the fabric vlan pool
type FabricVlanPoolSpec struct {
	Vlans []string `json:"vlans,omitempty"`
}

// +genclient
// +kubebuilder:subresource:status
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// FabricVlanPool is the Schema for the fabricattachments vlanpool API
type FabricVlanPool struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   FabricVlanPoolSpec   `json:"spec,omitempty"`
	Status FabricVlanPoolStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// FabricVlanPoolList contains a list of FabricVlanPool
type FabricVlanPoolList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []FabricVlanPool `json:"items"`
}
