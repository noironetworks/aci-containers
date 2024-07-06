package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Following restrictions apply for container contracts
// - Bidirectional only
// - Whitelist model (i.e. implicit allow for a rule)
// -  tcp, udp, icmp

type IntRange struct {
	Start int `json:"start,omitempty"`
	End   int `json:"end,omitempty"`
}

// WLRules are implicit allow
type WLRule struct {
	Protocol string   `json:"protocol,omitempty"`
	Ports    IntRange `json:"ports,omitempty"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// PodIF describes a pod network interface
type PodIF struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Status PodIFStatus `json:"status"`
}

// PodIFStatus is the status of a PodIF
type PodIFStatus struct {
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

// PodIFList is a list of pod interfaces
type PodIFList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []PodIF `json:"items"`
}
