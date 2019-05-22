package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type SnatGlobalInfoSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "operator-sdk generate k8s" to regenerate code after modifying this file
	// Add custom validation using kubebuilder tags: https://book.kubebuilder.io/beyond_basics/generating_crd.html
	// +kubebuilder:validation:Enum=selector, node
	SnatType    string                  `json:"snatType"`
	GlobalInfos map[string][]GlobalInfo `json:"globalInfos"`
}

// SnatGlobalInfoStatus defines the observed state of SnatGlobalInfo
// +k8s:openapi-gen=true
type SnatGlobalInfoStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "operator-sdk generate k8s" to regenerate code after modifying this file
	// Add custom validation using kubebuilder tags: https://book.kubebuilder.io/beyond_basics/generating_crd.html
}

// SnatGlobalInfo is the Schema for the snatglobalinfos API
// +genclient
// +genclient:noStatus
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type SnatGlobalInfo struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SnatGlobalInfoSpec   `json:"spec,omitempty"`
	Status SnatGlobalInfoStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// SnatGlobalInfoList contains a list of SnatGlobalInfo
type SnatGlobalInfoList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SnatGlobalInfo `json:"items"`
}

type GlobalInfo struct {
	MacAddress string      `json:"macAddress"`
	PortRanges []PortRange `json:"portRanges"`
	SnatIp     string      `json:"snatIp"`
	SnatIpUid  string      `json:"snatIpUid"`
	// +kubebuilder:validation:Enum=tcp,udp,icmp
	Protocols []string `json:"protocols"`
}

// +k8s:openapi-gen=true
type PortRange struct {
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Start int `json:"start,omitempty"`
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	End int `json:"end,omitempty"`
}
