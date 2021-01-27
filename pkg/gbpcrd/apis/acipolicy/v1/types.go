package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +genclient:noStatus
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Contract describe a policy between two endpoint groups
type Contract struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec ContractSpec `json:"spec"`
}

// ContractSpec is the spec for a Contract resource
type ContractSpec struct {
	Name      string   `json:"name,omitempty"`
	AllowList []WLRule `json:"allow-list,omitempty"`
}

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

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ContractList is a list of Contract resources
type ContractList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []Contract `json:"items"`
}

// +genclient
// +genclient:noStatus
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Epg describes a group of network endpoints
type Epg struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec EpgSpec `json:"spec"`
}

// EpgSpec is the spec for an epg
type EpgSpec struct {
	Name          string   `json:"name,omitempty"`
	ConsContracts []string `json:"consumed-contracts,omitempty"`
	ProvContracts []string `json:"provided-contracts,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// EpgList is a list of Epg resources
type EpgList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []Epg `json:"items"`
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
        AccessIfaceMac string `json:"accessifacemac,omitempty"`
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

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// GBPSState describes the internal state of the GBP server
type GBPSState struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Status            GBPSStatus `json:"status"`
}

// GBPSSpec is the spec for a gbpserver
type GBPSSpec struct {
	ApiPort      string `json:"api-port,omitempty"`
	InsecurePort string `json:"insecure-port,omitempty"`
	ApicURL      string `json:"apic-url,omitempty"`
	AwsRegion    string `json:"aws-region,omitempty"`
}

// GBPSStatus is the operational state for a gbpserver
type GBPSStatus struct {
	ClassIDs  map[string]uint  `json:"class-ids,omitempty"`
	TunnelIDs map[string]int64 `json:"tunnel-ids,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// GBPSStateList is a list of gbpserverstate objects
type GBPSStateList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []GBPSState `json:"items"`
}
