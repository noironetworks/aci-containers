// +k8s:deepcopy-gen=package
// +groupName=aci.attachmentmonitor

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type AaepMonitorSpec struct {
	Aaeps []string `json:"aaeps"`
}

type AaepMonitorStatus struct {
	Status string `json:"status,omitempty"`
}

// +genclient
// +genclient:nonNamespaced
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=aaepmonitor
// +kubebuilder:printcolumn:name="Status",type="string",JSONPath=".status.status"
// +kubebuilder:validation:XValidation:rule="self.metadata.name == 'aaepmonitor'",message="Only one instance allowed with name aaepmonitor"
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// AaepMonitor is the Schema for AttachmentMonitors to monitor AAEP and EPG resources
type AaepMonitor struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AaepMonitorSpec   `json:"spec,omitempty"`
	Status AaepMonitorStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// AaepMonitorList contains a list of AaepMonitor
type AaepMonitorList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AaepMonitor `json:"items"`
}
