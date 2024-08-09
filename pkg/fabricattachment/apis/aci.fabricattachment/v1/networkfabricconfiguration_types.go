package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +kubebuilder:validation:Enum=LLDP;AEP;""
type StaticPathMgmtType string

const (
	StaticPathMgmtTypeAll  StaticPathMgmtType = ""
	StaticPathMgmtTypeLLDP StaticPathMgmtType = "LLDP"
	StaticPathMgmtTypeAEP  StaticPathMgmtType = "AEP"
)

// NetworkFabricConfigurationStatus defines the observed state of NetworkFabricConfiguration
type NetworkFabricConfigurationStatus struct {
	State string `json:"state,omitempty"`
}

type NADVlanRef struct {
	NadVlanLabel string   `json:"nadVlanLabel"`
	Aeps         []string `json:"aeps"`
}

type VRF struct {
	Name         string `json:"name,omitempty"`
	CommonTenant bool   `json:"common-tenant,omitempty"`
}

type BridgeDomain struct {
	Name         string   `json:"name,omitempty"`
	CommonTenant bool     `json:"common-tenant,omitempty"`
	Subnets      []string `json:"subnets,omitempty"`
	Vrf          VRF      `json:"vrf,omitempty"`
}

type Contracts struct {
	Consumer []string `json:"consumer,omitempty"`
	Provider []string `json:"provider,omitempty"`
}

type Epg struct {
	ApplicationProfile string             `json:"applicationProfile,omitempty"`
	Name               string             `json:"name,omitempty"`
	Tenant             string             `json:"tenant,omitempty"`
	Contracts          Contracts          `json:"contracts,omitempty"`
	BD                 BridgeDomain       `json:"bd,omitempty"`
	DiscoveryType      StaticPathMgmtType `json:"discoveryType,omitempty"`
}

type VlanRef struct {
	Vlans string   `json:"vlans"`
	Aeps  []string `json:"aeps,omitempty"`
	Epg   Epg      `json:"epg,omitempty"`
}

type NetworkFabricConfigurationSpec struct {
	// Refer to vlan/s directly
	VlanRefs []VlanRef `json:"vlans,omitempty"`
	// Refer to a NADVlanLabel defined in NadVlanMap CR
	NADVlanRefs []NADVlanRef `json:"nadVlanRefs,omitempty"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:subresource:status
// +kubebuilder:validation:XValidation:rule="self.metadata.name == 'networkfabricconfiguration'",message="Only one instance with name networkfabricconfiguration allowed"
// NetworkFabricConfiguration allows additional configuration on NAD based and regular vlans created by aci controller
type NetworkFabricConfiguration struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   NetworkFabricConfigurationSpec   `json:"spec,omitempty"`
	Status NetworkFabricConfigurationStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// NetworkFabricConfigurationList contains a list of NetworkFabricConfiguration
type NetworkFabricConfigurationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NetworkFabricConfiguration `json:"items"`
}
