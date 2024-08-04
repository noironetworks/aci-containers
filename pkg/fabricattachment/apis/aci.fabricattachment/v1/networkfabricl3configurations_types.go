package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type FabricSviType string

const (
	FloatingSviType     FabricSviType = "floating_svi"
	ConventionalSviType FabricSviType = "svi"
)

type FabricPodRef struct {
	PodId int `json:"podId"`
}

type FabricNodeRef struct {
	FabricPodRef `json:",inline,omitempty"`
	NodeId       int `json:"nodeId"`
}

type BGPPeerPrefixPolicy struct {
	Name        string `json:"name"`
	MaxPrefixes int    `json:"maxPrefixes"`
	Action      string `json:"action,omitempty"`
}

type BGPPeerPolicy struct {
	Enabled        bool   `json:"enabled,omitempty"`
	Prefix         string `json:"prefix,omitempty"`
	Ctrl           string `json:"ctrl,omitempty"`
	PeerASN        int    `json:"peerASN"`
	PeerCtl        string `json:"peerCtl,omitempty"`
	LocalASN       int    `json:"localASN,omitempty"`
	LocalASNConfig string `json:"localASNConfig,omitempty"`
	// Refers to a k8s secret which has the BGP password in data field
	Secret       ObjRef `json:"secret,omitempty"`
	PrefixPolicy string `json:"prefixPolicy,omitempty"`
}

type FabricL3OutNextHop struct {
	Addr       string `json:"addr"`
	Preference int    `json:"preference,omitempty"`
}

type FabricL3OutStaticRoute struct {
	Prefix   string               `json:"prefix"`
	NextHops []FabricL3OutNextHop `json:"nextHops"`
	Ctrl     string               `json:"ctrl,omitempty"`
}

type FabricL3OutRtrNode struct {
	NodeRef      FabricNodeRef            `json:"nodeRef"`
	RtrId        string                   `json:"rtrId,omitempty"`
	StaticRoutes []FabricL3OutStaticRoute `json:"staticRoutes,omitempty"`
}

type FabricL3OutNode struct {
	NodeRef            FabricNodeRef `json:"nodeRef"`
	PrimaryAddress     string        `json:"primaryAddress"`
	SecondaryAddresses []string      `json:"secondaryAddresses,omitempty"`
}

type FabricL3Subnet struct {
	ConnectedSubnet  string `json:"connectedSubnet"`
	FloatingAddress  string `json:"floatingAddress,omitempty"`
	SecondaryAddress string `json:"secondaryAddress,omitempty"`
}

type PrimaryNetwork struct {
	L3OutName           string `json:"l3OutName"`
	L3OutOnCommonTenant bool   `json:"l3OutOnCommonTenant,omitempty"`
	UseExistingL3Out    bool   `json:"useExistingL3Out,omitempty"`
	// +kubebuilder:validation:Minimum=2
	MaxNodes int `json:"maxNodes,omitempty"`
	Encap    int `json:"encap"`
	// +kubebuilder:validation:Enum=floating_svi;svi
	// +kubebuilder:default=floating_svi
	SviType               FabricSviType `json:"sviType,omitempty"`
	RequirePodToProvision bool          `json:"requirePodToProvision,omitempty"`
	PrimarySubnet         string        `json:"primarySubnet"`
	BGPPeerPolicy         BGPPeerPolicy `json:"bgpPeerPolicy,omitempty"`
}

type FabricL3Network struct {
	PrimaryNetwork `json:",inline"`
	Subnets        []FabricL3Subnet `json:"subnets,omitempty"`
}

type ConnectedL3Network struct {
	FabricL3Network `json:",inline"`
	Nodes           []FabricL3OutNode `json:"nodes,omitempty"`
}

type ConnectedL3NetworkStatus struct {
	ConnectedL3Network `json:",inline"`
	Status             string `json:"status,omitempty"`
}

type FabricTenantConfiguration struct {
	CommonTenant          bool                  `json:"commonTenant,omitempty"`
	L3OutInstances        []FabricL3Out         `json:"l3OutInstances,omitempty"`
	BGPPeerPrefixPolicies []BGPPeerPrefixPolicy `json:"bgpInstances,omitempty"`
}

type FabricL3OutStatus struct {
	FabricL3Out `json:",inline"`
	Status      string `json:"status,omitempty"`
}

type BGPPeerPrefixPolicyStatus struct {
	BGPPeerPrefixPolicy `json:",inline"`
	Status              string `json:"status,omitempty"`
}

type FabricTenantConfigurationStatus struct {
	CommonTenant          bool                        `json:"commonTenant,omitempty"`
	L3OutInstances        []FabricL3OutStatus         `json:"l3OutInstances,omitempty"`
	BGPPeerPrefixPolicies []BGPPeerPrefixPolicyStatus `json:"bgpInstances,omitempty"`
	Status                string                      `json:"status,omitempty"`
}

type FabricVrfConfiguration struct {
	Vrf                       VRF                         `json:"vrf"`
	DirectlyConnectedNetworks []ConnectedL3Network        `json:"directlyConnectedNetworks,omitempty"`
	Tenants                   []FabricTenantConfiguration `json:"tenants,omitempty"`
}

type FabricVrfConfigurationStatus struct {
	Vrf                       VRF                               `json:"vrf"`
	DirectlyConnectedNetworks []ConnectedL3NetworkStatus        `json:"directlyConnectedNetworks,omitempty"`
	Tenants                   []FabricTenantConfigurationStatus `json:"tenants,omitempty"`
	Status                    string                            `json:"status,omitempty"`
}

type PolicyPrefix struct {
	Subnet    string `json:"subnet"`
	Scope     string `json:"scope,omitempty"`
	Aggregate string `json:"aggregate,omitempty"`
}

type PolicyPrefixGroup struct {
	Name           string         `json:"name"`
	PolicyPrefixes []PolicyPrefix `json:"policyPrefixes"`
	Contracts      Contracts      `json:"contracts,omitempty"`
}

type FabricL3Out struct {
	Name         string               `json:"name"`
	RtCtrl       string               `json:"rtCtrl,omitempty"`
	PodRef       FabricPodRef         `json:"podRef"`
	RtrNodes     []FabricL3OutRtrNode `json:"rtrNodes,omitempty"`
	ExternalEpgs []PolicyPrefixGroup  `json:"externalEpgs,omitempty"`
}

type NetworkFabricL3ConfigSpec struct {
	Vrfs []FabricVrfConfiguration `json:"vrfs,omitempty"`
}

type NetworkFabricL3ConfigStatus struct {
	Vrfs []FabricVrfConfigurationStatus `json:"vrfs,omitempty"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:subresource:status
// NetworkFabricL3Configuration allows additional configuration on NAD based and regular vlans created by aci controller
type NetworkFabricL3Configuration struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   NetworkFabricL3ConfigSpec   `json:"spec,omitempty"`
	Status NetworkFabricL3ConfigStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// NetworkFabricL3ConfigurationList contains a list of NetworkFabricL3Configuration
type NetworkFabricL3ConfigurationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NetworkFabricL3Configuration `json:"items"`
}
