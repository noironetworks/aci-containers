package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type FabricL3Peers struct {
	Encap         int   `json:"encap"`
	FabricPodId   int   `json:"podId"`
	FabricNodeIds []int `json:"fabricNodeIds"`
}

type NodeFabricL3Peer struct {
	NodeName      string          `json:"nodeName"`
	FabricL3Peers []FabricL3Peers `json:"fabricL3Peers,omitempty"`
}

type NetworkFabricL3PeeringInfo struct {
	Encap       int               `json:"encap"`
	ASN         int               `json:"asn"`
	Secret      ObjRef            `json:"secret,omitempty"`
	FabricNodes []FabricL3OutNode `json:"fabricNodes,omitempty"`
}

type NADFabricL3Peer struct {
	NAD   ObjRef             `json:"nad"`
	Nodes []NodeFabricL3Peer `json:"nodes,omitempty"`
}

type NodeFabricNetworkL3PeerStatus struct {
	NADRefs     []NADFabricL3Peer            `json:"nadRefs"`
	PeeringInfo []NetworkFabricL3PeeringInfo `json:"peeringInfo"`
}

// +genclient
// +genclient:nonNamespaced
// +genclient:noStatus
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:scope=Cluster
// NodeFabricNetworkL3Peers displays the status of L3 peers on svis created by aci controller
type NodeFabricNetworkL3Peer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Status            NodeFabricNetworkL3PeerStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// NodeFabricNetworkL3PeerList contains a list of NetworkFabricL3Configuration
type NodeFabricNetworkL3PeerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NodeFabricNetworkL3Peer `json:"items"`
}
