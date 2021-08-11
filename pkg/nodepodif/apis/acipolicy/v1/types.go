package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +genclient:noStatus
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type NodePodIF struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec NodePodIFSpec `json:"spec"`
}

// NodePodIFSpec is the desired state of NodePodIF
type NodePodIFSpec struct {
	PodIFs []PodIF `json:"podifs"`
}

type PodIF struct {
	PodNS       string `json:"podns,omitempty"`
	PodName     string `json:"podname,omitempty"`
	ContainerID string `json:"containerID,omitempty"`
	MacAddr     string `json:"macaddr,omitempty"`
	IPAddr      string `json:"ipaddr,omitempty"`
	EPG         string `json:"epg,omitempty"`
	VTEP        string `json:"vtep,omitempty"`
	IFName      string `json:"ifname,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// NodePodIFList is a list of NodePodIF
type NodePodIFList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []NodePodIF `json:"items"`
}
