package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type VlanSpec struct {
	Label string `json:"label,omitempty"`
	Vlans string `json:"vlans"`
}

type NadVlanMapSpec struct {
	// NAD namespace/name to vlan list mapping
	NadVlanMapping map[string][]VlanSpec `json:"nadVlanMapping"`
}

type NadVlanMapState string

const (
	NadVlanMapValid   = "valid"
	NadVlanMapInvalid = "error"
)

type NadVlanMapStatus struct {
	Status NadVlanMapState `json:"status,omitempty"`
}

// +genclient
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:subresource:status
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// NadVlanMap is the Schema for FabricAttachments NAD name to vlan mapping API
type NadVlanMap struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              NadVlanMapSpec   `json:"spec"`
	Status            NadVlanMapStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// NadVlanMapList contains a list of NadVlanMap
type NadVlanMapList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NadVlanMap `json:"items"`
}
