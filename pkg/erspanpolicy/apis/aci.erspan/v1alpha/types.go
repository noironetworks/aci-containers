package v1alpha

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

//PolicyState defines the current state of ErspanPolicy
type PolicyState string

const (
	// Ready and Failed are PolicyState constants
	Ready  PolicyState = "Ready"
	Failed PolicyState = "Failed"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// ErspanPolicySpec defines the desired state of ErspanPolicy
type ErspanPolicySpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "operator-sdk generate k8s" to regenerate code after modifying this file
	// Add custom validation using kubebuilder tags: https://book.kubebuilder.io/beyond_basics/generating_crd.html
	Selector PodSelector      `json:"selector,omitempty"`
	Source   ErspanSourceType `json:"source,omitempty"`
	Dest     ErspanDestType   `json:"destination,omitempty"`
}

//ErspanSourceType contains all the attrbutes of erspan source.
type ErspanSourceType struct {
	// +kubebuilder:validation:Enum=start,stop
	// Administrative state.
	// +optional
	AdminState string `json:"adminState,omitempty"`
	// +kubebuilder:validation:Enum=in,out,both
	// The direction of the packets to monitor.
	// +optional
	Direction string `json:"direction,omitempty"`
}

///ErspanDestType contains all the attrbutes of erspan destination.
type ErspanDestType struct {
	// The destination IP of the ERSPAN packet.
	DestIP string `json:"destIP"`
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=1023
	// The unique flow ID of the ERSPAN packet.
	// +optional
	FlowID int `json:"flowID,omitempty"`
}

// ErspanPolicyStatus defines the observed state of ErspanPolicy
type ErspanPolicyStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "operator-sdk generate k8s" to regenerate code after modifying this file7
	// Add custom validation using kubebuilder tags: https://book.kubebuilder.io/beyond_basics/generating_crd.html
	State PolicyState `json:"state"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ErspanPolicy is the Schema for the erspanpolicies API
type ErspanPolicy struct {
	metav1.TypeMeta `json:",inline"`
	// Standard object's metadata.
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Specification of the desired behavior of the ERSPAN Object.
	Spec ErspanPolicySpec `json:"spec,omitempty"`
	// Most recently observed status of the ERSPAN Object.
	// This data may not be up to date.
	// Populated by the system. Read-only.
	Status ErspanPolicyStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ErspanPolicyList contains a list of ErspanPolicy
type ErspanPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ErspanPolicy `json:"items"`
}

//PodSelector contains namespace and map of lables.
type PodSelector struct {
	Labels    map[string]string `json:"labels,omitempty"`
	Namespace string            `json:"namespace,omitempty"`
}
