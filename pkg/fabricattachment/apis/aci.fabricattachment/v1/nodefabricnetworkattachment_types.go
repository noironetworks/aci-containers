package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.
type FabricAttachmentState string

const (
	Created    FabricAttachmentState = "Created"
	Incomplete FabricAttachmentState = "Incomplete"
)

type ObjRef struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

type PodAttachment struct {
	LocalIface string `json:"localIface,omitempty"`
	PodRef     ObjRef `json:"podRef,omitempty"`
}

type AciNodeLinkAdjacency struct {
	FabricLink []string        `json:"fabricLink,omitempty"`
	Pods       []PodAttachment `json:"pods,omitempty"`
}

// NodeFabricAttachmentSpec defines the desired state of network attachment to the fabric
type NodeFabricNetworkAttachmentSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "operator-sdk generate k8s" to regenerate code after modifying this file
	// Add custom validation using kubebuilder tags: https://book.kubebuilder.io/beyond_basics/generating_crd.html
	// NetworkRef is the ns/net-att-def name, used as part of the epg ns-<NetworkName>
	NetworkRef ObjRef `json:"networkRef"`
	EncapVlan  string `json:"encapVlan,omitempty"`
	NodeName   string `json:"nodeName,omitempty"`
	// Map of iface to fabricLink
	AciTopology map[string]AciNodeLinkAdjacency `json:"aciTopology,omitempty"`
}

// NodeFabricAttachmentStatus defines the observed state of FabricAttachment
type NodeFabricNetworkAttachmentStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "operator-sdk generate k8s" to regenerate code after modifying this file7
	// Add custom validation using kubebuilder tags: https://book.kubebuilder.io/beyond_basics/generating_crd.html
	State FabricAttachmentState `json:"state,omitmepty"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:shortName=nfna
// NodeFabricAttachment is the Schema for the FabricAttachments API
type NodeFabricNetworkAttachment struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   NodeFabricNetworkAttachmentSpec   `json:"spec,omitempty"`
	Status NodeFabricNetworkAttachmentStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// NodeFabricAttachmentList contains a list of FabricAttachment
type NodeFabricNetworkAttachmentList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NodeFabricNetworkAttachment `json:"items"`
}
