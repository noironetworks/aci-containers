package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type PolicyState string

const (
	Ready            PolicyState = "Ready"
	Failed           PolicyState = "Failed"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// QosPolicySpec defines the desired state of QosPolicy
type QosPolicySpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "operator-sdk generate k8s" to regenerate code after modifying this file
	// Add custom validation using kubebuilder tags: https://book.kubebuilder.io/beyond_basics/generating_crd.html
	Selector  PodSelector `json:"selector,omitempty"`
	Ingress   PolicingType `json:"ingress,omitempty"`
	Egress    PolicingType `json:"egress,omitempty"`
}

//PolicingType
type PolicingType struct {
	PolicingRate int      `json:"policing_rate"`
	PolicingBurst int     `json:"policing_burst"`
}
// QosPolicyStatus defines the observed state of QosPolicy
type QosPolicyStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "operator-sdk generate k8s" to regenerate code after modifying this file7
	// Add custom validation using kubebuilder tags: https://book.kubebuilder.io/beyond_basics/generating_crd.html
	State PolicyState `json:"state"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Policy is the Schema for the qospolicies API
type QosPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   QosPolicySpec   `json:"spec,omitempty"`
	Status QosPolicyStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// QosPolicyList contains a list of QosPolicy
type QosPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []QosPolicy `json:"items"`
}

type PodSelector struct {
	Labels    map[string]string `json:"labels,omitempty"`
	Namespace string            `json:"namespace,omitempty"`
}
