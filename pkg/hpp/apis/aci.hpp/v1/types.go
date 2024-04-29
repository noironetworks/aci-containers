package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

type HostprotPolSpec struct {
	Name            string         `json:"name,omitempty"`
	HostprotSubj    []HostprotSubj `json:"hostprotSubj,omitempty"`
	NetworkPolicies []string       `json:"networkPolicies,omitempty"`
}

type HostprotSubj struct {
	Name         string         `json:"name,omitempty"`
	HostprotRule []HostprotRule `json:"hostprotRule,omitempty"`
}

type HostprotRule struct {
	Name                     string                  `json:"name,omitempty"`
	Direction                string                  `json:"direction,omitempty"`
	Ethertype                string                  `json:"ethertype,omitempty"`
	ConnTrack                string                  `json:"connTrack,omitempty"`
	Protocol                 string                  `json:"protocol,omitempty"`
	ToPort                   string                  `json:"toPort,omitempty"`
	FromPort                 string                  `json:"fromPort,omitempty"`
	RsRemoteIpContainer      []string                `json:"rsRemoteIpContainer,omitempty"`
	HostprotFilterContainer  HostprotFilterContainer `json:"hostprotFilterContainer,omitempty"`
	HostprotServiceRemoteIps []string                `json:"hostprotServiceRemoteIps,omitempty"`
}

type HostprotFilterContainer struct {
	HostprotFilter []HostprotFilter `json:"hostprotFilter,omitempty"`
}

type HostprotFilter struct {
	Key      string   `json:"key,omitempty"`
	Operator string   `json:"operator,omitempty"`
	Values   []string `json:"values,omitempty"`
}

// +genclient
// +genclient:noStatus
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type HostprotPol struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec HostprotPolSpec `json:"spec,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// HostprotPolList contains a list of HostprotPol
type HostprotPolList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []HostprotPol `json:"items"`
}

type HppEpLabel struct {
	Key   string `json:"key,omitempty"`
	Value string `json:"value,omitempty"`
}

type HostprotRemoteIp struct {
	Addr       string       `json:"addr,omitempty"`
	HppEpLabel []HppEpLabel `json:"hppEpLabel,omitempty"`
}

type HostprotRemoteIpContainerSpec struct {
	Name             string             `json:"name,omitempty"`
	HostprotRemoteIp []HostprotRemoteIp `json:"hostprotRemoteIp,omitempty"`
}

// +genclient
// +genclient:noStatus
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type HostprotRemoteIpContainer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec HostprotRemoteIpContainerSpec `json:"spec,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// HostprotRemoteIpContainerList contains a list of HostprotRemoteIpContainer
type HostprotRemoteIpContainerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []HostprotRemoteIpContainer `json:"items"`
}
