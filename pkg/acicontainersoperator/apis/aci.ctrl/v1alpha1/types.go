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
	Flavor            string `json:"flavor"`
	Config            string `json:"config"`
	AccProvisionInput AccProvisionSpec `json:"acc_provision_input"`
}

type AccProvisionSpec struct {
	DeploymentOperator bool `json:"deployment_operator"`
	AciConfig          AciConfigSpec `json:"aci_config"`
	NetConfig          NetConfigSpec `json:"net_config"`
	Registry           RegistrySpec `json:"registry"`
	Logging            LoggingSpec `json:"logging"`
	IstioConfig        IstioConfigSpec `json:"istio_config"`
	DropLogConfig      DropLogConfigSpec `json:"drop_log_config"`
	Multus             MultusSpec `json:"multus"`
	KubeConfig         KubeConfigSpec `json:"kube_config"`
}

type AciConfigSpec struct {
	ClusterTenant string `json:"cluster_tenant"`
	SyncLogin     SyncLoginSpec `json:"sync_login"`
	ClientSSL     bool `json:"client_ssl"`
}

type SyncLoginSpec struct {
	CertFile string `json:"certfile"`
	KeyFile  string `json:"keyfile"`
}

type NetConfigSpec struct {
	InterfaceMTU       int `json:"interface_mtu,omitempty"`
	SvcMonitorInterval int `json:"service_monitor_interval,omitempty"`
	PBRTrackingNonSNAT bool `json:"pbr_tracking_non_snat"`
}

type RegistrySpec struct {
	ImagePrefix                    string `json:"image_prefix"`
	ImagePullSecret                string `json:"image_pull_secret"`
        AccProvisionOperatorVersion    string `json:"acc_provision_operator_version"`
	AciContainersControllerVersion string `json:"aci_containers_controller_version"`
	AciContainersHostVersion       string `json:"aci_containers_host_version"`
	CNIDeployVersion               string `json:"cnideploy_version"`
	OpflexAgentVersion             string `json:"opflex_agent_version"`
	OpenVSwitchVersion             string `json:"openvswitch_version"`
	GBPVersion                     string `json:"gbp_version"`
}

type LoggingSpec struct {
	ControllerLogLevel  string `json:"controller_log_level"`
	HostagentLogLevel   string `json:"hostagent_log_level"`
	OpflexagentLogLevel string `json:"opflexagent_log_level"`
}

type IstioConfigSpec struct {
	InstallIstio   bool `json:"install_istio"`
	InstallProfile string `json:"install_profile"`
}

type MultusSpec struct {
	Disable bool `json:"disable"`
}

type DropLogConfigSpec struct {
	Enable bool `json:"enable"`
}

type KubeConfigSpec struct {
	OVSMemoryLimit                         string `json:"ovs_memory_limit"`
	UseExternalServiceIpAllocator          bool `json:"use_external_service_ip_allocator"`
	UsePrivilegedContainers                bool `json:"use_privileged_containers"`
	UseOpenshiftSecurityContextConstraints bool `json:"use_openshift_security_context_constraints"`
	AllowKubeAPIDefaultEPG                 bool `json:"allow_kube_api_default_epg"`
	ImagePullPolicy                        string `json:"image_pull_policy"`
	RebootOpflexWithOvs                    string `json:"reboot_opflex_with_ovs"`
}

// AciContainersOperatorStatus defines the observed state of AciContainersOperator
type AciContainersOperatorStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "acioperator-sdk generate k8s" to regenerate code after modifying this file
	// Add custom validation using kubebuilder tags: https://book.kubebuilder.io/beyond_basics/generating_crd.html
	Status bool `json:"Successful"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AciContainersOperator list
type AciContainersOperatorList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AciContainersOperator `json:"items"`
}
