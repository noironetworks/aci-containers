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
	AciConfig          AciConfigSpec `json:"aci_config,omitempty"`
	NetConfig          NetConfigSpec `json:"net_config,omitempty"`
	Registry           RegistrySpec `json:"registry,omitempty"`
	Logging            LoggingSpec `json:"logging,omitempty"`
	IstioConfig        IstioConfigSpec `json:"istio_config,omitempty"`
	DropLogConfig      DropLogConfigSpec `json:"drop_log_config,omitempty"`
	Multus             MultusSpec `json:"multus,omitempty"`
	KubeConfig         KubeConfigSpec `json:"kube_config,omitempty"`
}

type AciConfigSpec struct {
	ClusterTenant string `json:"cluster_tenant,omitempty"`
	SyncLogin     SyncLoginSpec `json:"sync_login,omitempty"`
	ClientSSL     bool `json:"client_ssl,omitempty"`
}

type SyncLoginSpec struct {
	CertFile string `json:"certfile,omitempty"`
	KeyFile  string `json:"keyfile,omitempty"`
}

type NetConfigSpec struct {
	InterfaceMTU       int `json:"interface_mtu,omitempty"`
	SvcMonitorInterval int `json:"service_monitor_interval,omitempty"`
	PBRTrackingNonSNAT bool `json:"pbr_tracking_non_snat,omitempty"`
}

type RegistrySpec struct {
	ImagePrefix                    string `json:"image_prefix,omitempty"`
	ImagePullSecret                string `json:"image_pull_secret,omitempty"`
        AccProvisionOperatorVersion    string `json:"acc_provision_operator_version,omitempty"`
	AciContainersControllerVersion string `json:"aci_containers_controller_version,omitempty"`
	AciContainersHostVersion       string `json:"aci_containers_host_version,omitempty"`
	CNIDeployVersion               string `json:"cnideploy_version,omitempty"`
	OpflexAgentVersion             string `json:"opflex_agent_version,omitempty"`
	OpenVSwitchVersion             string `json:"openvswitch_version,omitempty"`
	GBPVersion                     string `json:"gbp_version,omitempty"`
}

type LoggingSpec struct {
	ControllerLogLevel  string `json:"controller_log_level,omitempty"`
	HostagentLogLevel   string `json:"hostagent_log_level,omitempty"`
	OpflexagentLogLevel string `json:"opflexagent_log_level,omitempty"`
}

type IstioConfigSpec struct {
	InstallIstio   bool `json:"install_istio,omitempty"`
	InstallProfile string `json:"install_profile,omitempty"`
}

type MultusSpec struct {
	Disable bool `json:"disable,omitempty"`
}

type DropLogConfigSpec struct {
	Enable bool `json:"enable,omitempty"`
}

type KubeConfigSpec struct {
	OVSMemoryLimit                         string `json:"ovs_memory_limit,omitempty"`
	UseExternalServiceIpAllocator          bool `json:"use_external_service_ip_allocator,omitempty"`
	UsePrivilegedContainers                bool `json:"use_privileged_containers,omitempty"`
	UseOpenshiftSecurityContextConstraints bool `json:"use_openshift_security_context_constraints,omitempty"`
	AllowKubeAPIDefaultEPG                 bool `json:"allow_kube_api_default_epg,omitempty"`
	ImagePullPolicy                        string `json:"image_pull_policy,omitempty"`
	RebootOpflexWithOvs                    string `json:"reboot_opflex_with_ovs,omitempty"`
}

// AciContainersOperatorStatus defines the observed state of AciContainersOperator
type AciContainersOperatorStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "acioperator-sdk generate k8s" to regenerate code after modifying this file
	// Add custom validation using kubebuilder tags: https://book.kubebuilder.io/beyond_basics/generating_crd.html
	Status bool `json:"Successful"`
        Custom string `json:"Custom"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AciContainersOperator list
type AciContainersOperatorList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AciContainersOperator `json:"items"`
}
