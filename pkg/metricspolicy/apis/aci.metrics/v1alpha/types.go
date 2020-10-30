package v1alpha

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// PolicyState represents the status of MetricsPolicy
type PolicyState string

const (
	// Ready represents successful application of CRD
	Ready PolicyState = "Ready"
	// Failed represents unsuccessful application of CRD
	Failed PolicyState = "Failed"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// MetricsPolicySpec defines the desired state of MetricsPolicy
type MetricsPolicySpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "operator-sdk generate k8s" to regenerate code after modifying this file
	// Add custom validation using kubebuilder tags: https://book.kubebuilder.io/beyond_basics/generating_crd.html

	MetricsPolicy MetricsType `json:"metricsPolicy,omitempty"`
}

// MetricsType represents the contents of MetricsPolicySpec
type MetricsType struct {
	PromServerAddr  string   `json:"promServerIp"`
	KafkaBrokerAddr []string `json:"kafkaBrokerIp"`
	// +kubebuilder:validation:Minimum=5
	// +kubebuilder:validation:Maximum=3600
	ScrapeInterval int `json:"scrapeInterval"`
}

// MetricsPolicyStatus defines the observed state of MetricsPolicy
type MetricsPolicyStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "operator-sdk generate k8s" to regenerate code after modifying this file7
	// Add custom validation using kubebuilder tags: https://book.kubebuilder.io/beyond_basics/generating_crd.html
	State PolicyState `json:"state"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// MetricsPolicy is the Schema for the metricspolicies API
type MetricsPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   MetricsPolicySpec   `json:"spec,omitempty"`
	Status MetricsPolicyStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// MetricsPolicyList contains a list of MetricsPolicy
type MetricsPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []MetricsPolicy `json:"items"`
}
