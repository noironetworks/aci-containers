package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)


// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AciContainersOperator is a specification for a AciContainersOperator resource
type AciContainersOperator struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AciContainersOperatorSpec   `json:"spec,omitempty"`
	Status AciContainersOperatorStatus `json:"status,omitempty"`
}

// AciContainersOperatorSpec defines the desired state of AciContainersOperator
type AciContainersOperatorSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "acioperator-sdk generate k8s" to regenerate code after modifying this file
	// Add custom validation using kubebuilder tags: https://book.kubebuilder.io/beyond_basics/generating_crd.html
	Flavor     string        `json:"flavor"`
	Config     string        `json:"config"`
}

// AciContainersOperatorStatus defines the observed state of AciContainersOperator
type AciContainersOperatorStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "acioperator-sdk generate k8s" to regenerate code after modifying this file
	// Add custom validation using kubebuilder tags: https://book.kubebuilder.io/beyond_basics/generating_crd.html
	Status    bool       `json:"Successful or Not"`
}


// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AciContainersOperator list
type AciContainersOperatorList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AciContainersOperator `json:"items"`
}
