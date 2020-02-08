package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)


// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AciIstioOperator is a specification for a AciIstioOperator resource
type AciIstioOperator struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AciIstioOperatorSpec   `json:"spec,omitempty"`
	Status AciIstioOperatorStatus `json:"status,omitempty"`
}

// AciIstioOperatorSpec defines the desired state of AciIstioOperator
type AciIstioOperatorSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "operator-sdk generate k8s" to regenerate code after modifying this file
	// Add custom validation using kubebuilder tags: https://book.kubebuilder.io/beyond_basics/generating_crd.html
	Config     string        `json:"config"`
	Profile    string        `json:"profile"`
}

// AciIstioOperatorStatus defines the observed state of AciIstioOperator
type AciIstioOperatorStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "operator-sdk generate k8s" to regenerate code after modifying this file
	// Add custom validation using kubebuilder tags: https://book.kubebuilder.io/beyond_basics/generating_crd.html
	Status    bool       `json:"Successful or Not"`
}


// +k8s:depcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AciIstioOperator list
type AciIstioOperatorList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AciIstioOperator `json:"items"`
}
