// Important: Run "droplog-sdk generate k8s" to regenerate code after modifying this file
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.
// Add custom validation using kubebuilder tags: https://book.kubebuilder.io/beyond_basics/generating_crd.html

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// EnableDropLog is a specification for a EnableDropLog resource
type EnableDropLog struct {
	metav1.TypeMeta `json:",inline"`
	// Standard object's metadata.
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// Specification of the desired behavior of the EnableDropLog Object.
	Spec EnableDropLogSpec `json:"spec,omitempty"`
	// Most recently observed status of the EnableDropLog Object.
	// This data may not be up to date.
	// Populated by the system. Read-only.
	Status EnableDropLogStatus `json:"status,omitempty"`
}

// EnableDropLogSpec defines the desired state of DropLog
type EnableDropLogSpec struct {
	// Disables the default droplog enabled by acc-provision. Defaults to false.
	// +kubebuilder:default:=false
	// +kubebuilder:validation:Optional
	DisableDroplog bool `json:"disableDefaultDropLog,omitempty"`
	// Drop logging is enabled on nodes selected based on labels
	// +kubebuilder:validation:Optional
	NodeSelector NodeSelector `json:"nodeSelector,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// EnableDropLogList contains a list of EnableDropLog
type EnableDropLogList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []EnableDropLog `json:"items"`
}

// EnableDropLogStatus defines the observed state of EnableDropLog
type EnableDropLogStatus struct {
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// PruneDropLog is a specification for a PruneDropLog resource
type PruneDropLog struct {
	metav1.TypeMeta `json:",inline"`
	// Standard object's metadata.
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// Specification of the desired behavior of the PruneDropLog Object.
	Spec PruneDropLogSpec `json:"spec,omitempty"`
	// Most recently observed status of the PruneDropLog Object.
	// This data may not be up to date.
	// Populated by the system. Read-only.
	Status PruneDropLogStatus `json:"status,omitempty"`
}

// PruneDropLogSpec defines the desired state of PruneDropLog
type PruneDropLogSpec struct {
	// Drop logging filters are applied to nodes selected based on labels
	// +kubebuilder:validation:Optional
	NodeSelector NodeSelector `json:"nodeSelector,omitempty"`
	// Drop logging filters specification
	// +kubebuilder:validation:Optional
	DropLogFilters DropLogFilters `json:"dropLogPruning,omitempty"`
}

type DropLogFilters struct {
	// +kubebuilder:validation:Optional
	SrcIP string `json:"srcIP,omitempty"`
	// +kubebuilder:validation:Optional
	DstIP string `json:"destIP,omitempty"`
	// +kubebuilder:validation:Optional
	SrcMac string `json:"srcMAC,omitempty"`
	// +kubebuilder:validation:Optional
	DstMac string `json:"destMAC,omitempty"`
	// +kubebuilder:validation:Optional
	SrcPort int16 `json:"srcPort,omitempty"`
	// +kubebuilder:validation:Optional
	DstPort int16 `json:"destPort,omitempty"`
	// Inner IP proto
	// +kubebuilder:validation:Optional
	IpProto int8 `json:"ipProto,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// PruneDropLogList contains a list of PruneDropLog
type PruneDropLogList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []PruneDropLog `json:"items"`
}

// PruneDropLogStatus defines the observed state of PruneDropLog
type PruneDropLogStatus struct {
}

//NodeSelector contains a map of lables.
type NodeSelector struct {
	Labels map[string]string `json:"labels,omitempty"`
}
