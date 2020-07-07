package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SnatLocalInfoSpec defines the desired state of SnatLocalInfo
type SnatLocalInfoSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "operator-sdk generate k8s" to regenerate code after modifying this file
	// Add custom validation using kubebuilder tags: https://book.kubebuilder.io/beyond_basics/generating_crd.html
	LocalInfos []LocalInfo `json:"localInfos"`
}

// +genclient
// +genclient:noStatus
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type SnatLocalInfo struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec SnatLocalInfoSpec `json:"spec,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// snatLocalinfon list
type SnatLocalInfoList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SnatLocalInfo `json:"items"`
}

type SnatPolicy struct {
	Name   string   `json:"name"`
	SnatIp string   `json:"snatIp"`
	DestIp []string `json:"destIp"`
}

type LocalInfo struct {
	PodName      string       `json:"podName"`
	PodNamespace string       `json:"podNamespace"`
	PodUid       string       `json:"podUid"`
	SnatPolicies []SnatPolicy `json:"snatPolicies"`
}
