// Copyright 2017 Cisco Systems, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package hostagent

import (
	"flag"
	"net"
	"os"

	cnitypes "github.com/containernetworking/cni/pkg/types"

	"github.com/noironetworks/aci-containers/pkg/metadata"
)

type route struct {
	Dst cnitypes.IPNet `json:"dst"`
	GW  net.IP         `json:"gw,omitempty"`
}

type cniNetConfig struct {
	Subnet  cnitypes.IPNet `json:"subnet,omitempty"`
	Gateway net.IP         `json:"gateway,omitempty"`
	Routes  []route        `json:"routes,omitempty"`
}

type OpflexServerConfig struct {
	GRPCAddress string `json:"grpc-address,omitempty"`
	DebugLevel  string `json:"level,omitempty"`
}

type GroupDefaults struct {
	// Default endpoint group annotation value
	DefaultEg metadata.OpflexGroup `json:"default-endpoint-group,omitempty"`

	// Default security group annotation value
	DefaultSg []metadata.OpflexGroup `json:"default-security-group,omitempty"`

	// Default qospolicy group annotation value
	DefaultQp metadata.OpflexGroup `json:"default-qospolicy-group,omitempty"`

	// Override default endpoint group assignments for a namespace
	// map ns name -> group
	NamespaceDefaultEg map[string]metadata.OpflexGroup `json:"namespace-default-endpoint-group,omitempty"`

	// Override default security group assignments for namespaces
	// map ns name -> slice of groups
	NamespaceDefaultSg map[string][]metadata.OpflexGroup `json:"namespace-default-security-group,omitempty"`

	// Override default qospolicy group assignments for a namespace
	// map ns name -> group
	NamespaceDefaultQp map[string]metadata.OpflexGroup `json:"namespace-default-qospolicy-group,omitempty"`
}

type HostAgentNodeConfig struct {
	// Uplink interface for this host
	UplinkIface string `json:"uplink-iface,omitempty"`

	// Subinterface of uplink interface on AciInfraVlan
	VxlanIface string `json:"vxlan-iface,omitempty"`

	// Anycast IP used for unicast VXLAN packets
	VxlanAnycastIp string `json:"vxlan-anycast-ip,omitempty"`

	// Anycast IP used for OpFlex communication
	OpflexPeerIp string `json:"opflex-peer-ip,omitempty"`

	// Uplink Mac adress
	UplinkMacAdress string `json:"uplink mac_adress,omitempty"`

	// Registry Server URL -- for updating remote EP information
	RegistryURL string `json:"registry-url,omitempty"`
}

// Configuration for the host agent
type HostAgentConfig struct {
	HostAgentNodeConfig
	GroupDefaults

	// Run as child mode for executing network namespace commands in a
	// separate process.
	ChildMode bool `json:"child-mode,omitempty"`

	// Log level
	LogLevel string `json:"log-level,omitempty"`

	// Absolute path to a kubeconfig file
	KubeConfig string `json:"kubeconfig,omitempty"`

	// Name of Kubernetes node on which this agent is running
	NodeName string `json:"node-name,omitempty"`

	// TCP port to run status server on (or 0 to disable)
	StatusPort int `json:"status-port,omitempty"`

	// TCP port for opflex server to connect
	GRPCPort int `json:"grpc-port,omitempty"`

	// Directory containing OpFlex CNI metadata
	CniMetadataDir string `json:"cni-metadata-dir,omitempty"`

	// Name of the CNI network
	CniNetwork string `json:"cni-network,omitempty"`

	// Directory for writing CNI network metadata
	CniNetworksDir string `json:"cni-networks-dir,omitempty"`

	// Directory for writing Opflex configuration
	OpFlexConfigPath string `json:"opflex-config-path,omitempty"`

	// Directory for writing OpFlex endpoint metadata
	OpFlexEndpointDir string `json:"opflex-endpoint-dir,omitempty"`

	// Directory for writing OpFlex service metadata
	OpFlexServiceDir string `json:"opflex-service-dir,omitempty"`

	// Directory for writing OpFlex snat metadata
	OpFlexSnatDir string `json:"opflex-snat-dir,omitempty"`

	// Directory for writing OpFlex fault metadata
	OpFlexFaultDir string `json:"opflex-fault-dir,omitempty"`

	// OpFlex agent's flow-ID cache directory
	OpFlexFlowIdCacheDir string `json:"opflex-flowid-cache-dir,omitempty"`

	// Multicast groups file used by OpFlex agent
	OpFlexMcastFile string `json:"opflex-mcast-file,omitempty"`

	// File for writing Opflex server configuration
	OpFlexServerConfigFile string `json:"opflex-server-config-file,omitempty"`

	// Location of the packet event notification socket which listens to opflex-agent packet events
	PacketEventNotificationSock string `json:"packet-event-notification-socket,omitempty"`

	// Directory for drop log config
	OpFlexDropLogConfigDir string `json:"opflex-drop-log-config-dir,omitempty"`

	// RemoteIp for opflex drop logger
	OpFlexDropLogRemoteIp string `json:"opflex-drop-log-remote-ip,omitempty"`

	// Location of the OVS DB socket
	OvsDbSock string `json:"ovs-db-sock,omitempty"`

	// Location of the endpoint RPC socket used for communicating with
	// the CNI plugin
	EpRpcSock string `json:"ep-rpc-sock,omitempty"`

	// Permissions to set for endpoint RPC socket file. Octal string.
	EpRpcSockPerms string `json:"ep-rpc-sock-perms,omitempty"`

	// AciPrefix is used for generating aci names
	AciPrefix string `json:"aci-prefix,omitempty"`

	// Vlan used for ACI infrastructure traffic
	AciInfraVlan uint `json:"aci-infra-vlan,omitempty"`

	// VLAN for service traffic
	ServiceVlan uint `json:"service-vlan,omitempty"`

	// Type of encapsulation to use for uplink; either vlan or vxlan
	EncapType string `json:"encap-type,omitempty"`

	// Name of the OVS integration bridge
	IntBridgeName string `json:"int-bridge-name,omitempty"`

	// Name of the OVS access bridge
	AccessBridgeName string `json:"access-bridge-name,omitempty"`

	// Interface MTU to use when configuring container interfaces
	InterfaceMtu int `json:"interface-mtu,omitempty"`

	// Interface MTU headroom for VXLAN
	InterfaceMtuHeadroom int `json:"interface-mtu-headroom,omitempty"`

	// Configuration for CNI networks
	NetConfig []cniNetConfig `json:"cni-netconfig,omitempty"`

	// The type of the ACI VMM domain: either "Kubernetes"
	// or "OpenShift"
	AciVmmDomainType string `json:"aci-vmm-type,omitempty"`

	// The name of the ACI VMM domain
	AciVmmDomain string `json:"aci-vmm-domain,omitempty"`

	// The name of the ACI VMM domain controller instance
	AciVmmController string `json:"aci-vmm-controller,omitempty"`

	// ACI VRF for this kubernetes instance
	AciVrf string `json:"aci-vrf,omitempty"`

	// ACI Tenant containing the ACI VRF for this kubernetes instance
	AciVrfTenant string `json:"aci-vrf-tenant,omitempty"`

	// EP Registry specifies where to send ep updates
	EPRegistry string `json:"ep-registry,omitempty"`

	// EnableNodePodIF enabled
	EnableNodePodIF bool `json:"enable-nodepodif,omitempty"`

	// OpflexMode selects overlay vs physical fabric. Default is physical
	OpflexMode string `json:"opflex-mode,omitempty"`

	//ZoneId for Snat flows
	Zone uint `json:"zone,omitempty"`

	//Namespace for SNAT CRDs
	AciSnatNamespace string `json:"aci-snat-namespace,omitempty"`

	//DropLogging enabled
	EnableDropLogging bool `json:"enable-drop-log,omitempty"`

	// DropLog Interface connecting to access bridge
	DropLogAccessInterface string `json:"drop-log-access-iface,omitempty"`

	// DropLog Interface connecting to integration bridge
	DropLogIntInterface string `json:"drop-log-int-iface,omitempty"`

	// Droplogs older than the expiry-time will be discarded if not published
	DropLogExpiryTime uint `json:"drop-log-expiry,omitempty"`

	// More than one droplog within the repeat interval for the same event is suppressed
	DropLogRepeatIntervalTime uint `json:"drop-log-repeat-intvl,omitempty"`

	//default is false
	HppOptimization bool `json:"hpp-optimization,omitempty"`

	// If true, enable opflex agent reconnect after vm migration
	// Default is false
	EnableOpflexAgentReconnect bool `json:"enable-opflex-agent-reconnect,omitempty"`

	// Default is false
	AciMultipod bool `json:"aci-multipod,omitempty"`

	// Max number of time dhcp renew will be executed after multi pod vm migration
	DhcpRenewMaxRetryCount int `json:"dhcp-renew-max-retry-count,omitempty"`

	// Delay between dhcp release and renew in seconds
	DhcpDelay int `json:"dhcp-delay,omitempty"`

	// enable EndpointSlice
	EnabledEndpointSlice bool `json:"enable_endpointslice,omitempty"`
	// Cluster Flavour
	Flavor string `json:"flavor,omitempty"`
	// Installer lb Ip provisioned for Openshift on Esx
	InstallerProvlbIp string `json:"installer-provisioned-lb-ip,omitempty"`

	// Sriov and Ovs Hardward Offload enabled
	OvsHardwareOffload bool `json:"enable-ovs-hw-offload,omitempty"`

	// DpuOvsDBSocket when OpflexMode is dpu selects ovsdb sock on dpu
	DpuOvsDBSocket string `json:"dpu-ovsdb-socket,omitempty"`

	// chained mode enabled
	ChainedMode bool `json:"chained-mode,omitempty"`

	// enable chained operation on primary cni chain
	EnableChainedPrimary bool `json:"enable-chained-primary,omitempty"`

	// enable chained operation on secondary cni chain
	EnableChainedSecondary bool `json:"enable-chained-secondary,omitempty"`

	// Primary cni path
	PrimaryCniPath string `json:"primary-cni-path,omitempty"`

	//In chained mode, global l2 port policy has been configured, so enable shared vlan pool
	AciUseGlobalScopeVlan bool `json:"aci-use-global-scope-vlan,omitempty"`

	// Metrics
	EnableMetrics bool `json:"enable-metrics,omitempty"`
	MetricsPort   int  `json:"metrics-port,omitempty"`

	// Disable hpp rendering if set to true
	DisableHppRendering bool `json:"disable-hpp-rendering,omitempty"`

	// Enable/disable making node unschedulable when it's not ready
	TaintNotReadyNode bool `json:"taint-not-ready-node,omitempty"`
}

func (config *HostAgentConfig) InitFlags() {
	flag.BoolVar(&config.ChildMode, "child-mode", false, "Child Mode")

	flag.StringVar(&config.LogLevel, "log-level", "info", "Log level")

	flag.StringVar(&config.KubeConfig, "kube-config", "", "Absolute path to a kubeconfig file")
	flag.StringVar(&config.NodeName, "node-name", "", "Name of Kubernetes node on which this agent is running")

	flag.IntVar(&config.StatusPort, "status-port", 8090, "TCP port to run status server on (or 0 to disable)")
	flag.IntVar(&config.GRPCPort, "grpc-port", 19999, "TCP port for opflex server to connect")

	flag.StringVar(&config.CniMetadataDir, "cni-metadata-dir", "/usr/local/var/lib/aci-containers/", "Directory for writing OpFlex endpoint metadata")

	veth_mode := os.Getenv("GENERIC_VETH_MODE")

	// Check if the environment variable is set
	if veth_mode != "True" {
		flag.StringVar(&config.CniNetwork, "cni-network", "k8s-pod-network", "Name of the CNI network")
	} else {
		flag.StringVar(&config.CniNetwork, "cni-network", "generic-veth", "Name of the CNI network")
	}

	flag.StringVar(&config.OpFlexConfigPath, "opflex-config-path", "/usr/local/etc/opflex-agent-ovs/base-conf.d", "Directory for writing Opflex configuration")
	flag.StringVar(&config.OpFlexEndpointDir, "opflex-endpoint-dir", "/usr/local/var/lib/opflex-agent-ovs/endpoints/", "Directory for writing OpFlex endpoint metadata")
	flag.StringVar(&config.OpFlexServiceDir, "opflex-service-dir", "/usr/local/var/lib/opflex-agent-ovs/services/", "Directory for writing OpFlex anycast service metadata")
	flag.StringVar(&config.OpFlexSnatDir, "opflex-snat-dir", "/usr/local/var/lib/opflex-agent-ovs/snats/", "Directory for writing OpFlex snat metadata")
	flag.StringVar(&config.OpFlexFaultDir, "opflex-fault-dir", "/usr/local/var/lib/opflex-agent-ovs/faults/", "Directory for writing OpFlex fault metadata")
	flag.StringVar(&config.OpFlexFlowIdCacheDir, "opflex-flowid-cache-dir",
		"/usr/local/var/lib/opflex-agent-ovs/ids/",
		"OpFlex agent's flow-ID cache directory")
	flag.StringVar(&config.OpFlexMcastFile, "opflex-mcast-file",
		"/usr/local/var/lib/opflex-agent-ovs/mcast/opflex-groups.json",
		"Multicast groups file used by OpFlex agent")

	flag.StringVar(&config.OpFlexServerConfigFile, "opflex-server-config-file",
		"/usr/local/var/lib/opflex-server/config.json",
		"Config file for opflex server")
	flag.StringVar(&config.PacketEventNotificationSock, "packet-event-notification-socket", "/usr/local/var/run/aci-containers-packet-event-notification.sock", "Location of the packet event notification socket")
	flag.StringVar(&config.OpFlexDropLogConfigDir, "opflex-drop-log-config-dir", "/usr/local/var/lib/opflex-agent-ovs/droplog", "Directory for writing OpFlex drop logging configuration")
	flag.StringVar(&config.OpFlexDropLogRemoteIp, "opflex-drop-log-remote-ip", "192.168.1.2", "Remote IPv4 address for encapsulated dropped packets")
	flag.StringVar(&config.OvsDbSock, "ovs-db-sock", "/usr/local/var/run/openvswitch/db.sock", "Location of the OVS DB socket")
	flag.StringVar(&config.EpRpcSock, "ep-rpc-sock", "/usr/local/var/run/aci-containers-ep-rpc.sock", "Location of the endpoint RPC socket used for communicating with the CNI plugin")
	flag.StringVar(&config.EpRpcSockPerms, "ep-rpc-sock-perms", "", "Permissions to set for endpoint RPC socket file. Octal string")

	flag.StringVar(&config.IntBridgeName, "int-bridge-name", "br-int", "Name of the OVS integration bridge")
	flag.StringVar(&config.AccessBridgeName, "access-bridge-name", "br-access", "Name of the OVS access bridge")

	flag.IntVar(&config.InterfaceMtu, "interface-mtu", 0, "Interface MTU to use when configuring container interfaces")
	flag.IntVar(&config.InterfaceMtuHeadroom, "interface-mtu-headroom", 100, "Interface MTU headroom for VXLAN")

	flag.UintVar(&config.ServiceVlan, "service-vlan", 4003, "VLAN for service traffic")

	flag.StringVar(&config.UplinkIface, "uplink-iface", "eth1", "Uplink interface for this host")
	flag.UintVar(&config.AciInfraVlan, "aci-infra-vlan", 4093, "Vlan used for ACI infrastructure traffic")
	flag.StringVar(&config.EncapType, "encap-type", "vxlan", "Type of encapsulation to use for uplink; either vlan or vxlan")
	flag.StringVar(&config.VxlanIface, "vxlan-iface", "eth1.4093", "Subinterface of uplink interface on AciInfraVlan")
	flag.StringVar(&config.VxlanAnycastIp, "vxlan-anycast-ip", "10.0.0.32", "Anycast IP used for unicast VXLAN packets")
	flag.StringVar(&config.OpflexPeerIp, "opflex-peer-ip", "10.0.0.30", "Anycast IP used for OpFlex communication")

	flag.StringVar(&config.AciVmmDomainType, "aci-vmm-type", "Kubernetes", "ACI VMM domain type")
	flag.StringVar(&config.AciVmmDomain, "aci-vmm-domain", "kubernetes", "ACI VMM domain")
	flag.StringVar(&config.AciVmmController, "aci-vmm-controller", "kubernetes", "ACI VMM domain controller")

	flag.StringVar(&config.AciVrf, "aci-vrf", "kubernetes-vrf", "ACI VRF for this kubernetes instance")
	flag.StringVar(&config.AciVrfTenant, "aci-vrf-tenant", "common", "ACI Tenant containing the ACI VRF for this kubernetes instance")
	flag.UintVar(&config.Zone, "zone", 8191, "Zone Id for snat flows")
	flag.StringVar(&config.AciSnatNamespace, "aci-snat-namespace", "aci-containers-system", "Namespace for SNAT CRDs")
	flag.BoolVar(&config.EnableDropLogging, "enable-drop-log", false, "Allow dropped packets to be logged")
	flag.StringVar(&config.DropLogAccessInterface, "drop-log-access-iface", "gen2", "Interface in Access bridge to send dropped packets")
	flag.StringVar(&config.DropLogIntInterface, "drop-log-int-iface", "gen1", "Interface in Integration bridge to send dropped packets")
	flag.UintVar(&config.DropLogExpiryTime, "drop-log-expiry", 10, "Expiry time for droplogs in the pipeline in minutes")
	flag.UintVar(&config.DropLogRepeatIntervalTime, "drop-log-repeat-intvl", 2, "Deduplication interval for droplogs of the same event in minutes")
	flag.IntVar(&config.DhcpDelay, "dhcp-delay", 5, "Delay between dhcp release and dhcp renew in seconds")
	flag.IntVar(&config.DhcpRenewMaxRetryCount, "dhcp-renew-max-retry-count", 5, "max number of times dhcp renew should be executed before giving up")
	flag.StringVar(&config.Flavor, "flavor", "", "Cluster flavor where it is running on")
	flag.StringVar(&config.InstallerProvlbIp, "installer-provisioned-lb-ip", "", "Installer lb ip provisioned for OpenShift on ESX")
	flag.BoolVar(&config.EnableNodePodIF, "enable-nodepodif", false, "Enable NodePodIF")
	flag.StringVar(&config.EPRegistry, "ep-registry", "", "Enable PodIF")
	flag.BoolVar(&config.OvsHardwareOffload, "enable-ovs-hw-offload", false, "SRIOV config and ovs hardware offload feature")
	flag.StringVar(&config.DpuOvsDBSocket, "dpu-ovsdb-socket", "tcp:192.168.200.2:6640", "TCP socket on DPU to connect to")
	flag.BoolVar(&config.ChainedMode, "chained_mode", false, "Chained Mode")
	flag.StringVar(&config.CniNetworksDir, "cni-networks-dir", "/usr/local/var/lib/netop-cni/networks", "Cni Networks Directory")
	flag.BoolVar(&config.EnableMetrics, "enable-metrics", false, "Enable metrics")
	flag.IntVar(&config.MetricsPort, "metrics-port", 8190, "Port to expose metrics on")
}
