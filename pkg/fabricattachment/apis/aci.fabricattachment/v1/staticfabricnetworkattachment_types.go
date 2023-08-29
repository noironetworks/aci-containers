package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// StaticFabricNetworkAttachmentStatus defines the observed state of StaticFabricNetworkAttachment
type StaticFabricNetworkAttachmentStatus struct {
	State string `json:"state,omitempty"`
}

type NADVlanRef struct {
	NadVlanLabel string   `json:"nadVlanLabel"`
	Aeps         []string `json:"aeps"`
}

type VlanRef struct {
	Vlans string   `json:"vlans"`
	Aeps  []string `json:"aeps"`
}

type StaticFabricNetworkAttachmentSpec struct {
	// Refer to vlan/s directly
	VlanRefs []VlanRef `json:"vlans,omitempty"`
	// Refer to a NADVlanLabel defined in NadVlanMap CR
	NADVlanRefs []NADVlanRef `json:"nadVlanRefs,omitempty"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:subresource:status
// StaticFabricAttachment allows attaching aeps to NAD based and regular vlans created by aci controller
type StaticFabricNetworkAttachment struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   StaticFabricNetworkAttachmentSpec   `json:"spec,omitempty"`
	Status StaticFabricNetworkAttachmentStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// StaticFabricNetworkAttachmentList contains a list of StaticFabricNetworkAttachment
type StaticFabricNetworkAttachmentList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []StaticFabricNetworkAttachment `json:"items"`
}
