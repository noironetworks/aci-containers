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

type GroupDefaults struct {
	// Default endpoint group annotation value
	DefaultEg metadata.OpflexGroup `json:"default-endpoint-group,omitempty"`

	// Default security group annotation value
	DefaultSg []metadata.OpflexGroup `json:"default-security-group,omitempty"`

	// Override default endpoint group assignments for a namespace
	// map ns name -> group
	NamespaceDefaultEg map[string]metadata.OpflexGroup `json:"namespace-default-endpoint-group,omitempty"`

	// Override default security group assignments for namespaces
	// map ns name -> slice of groups
	NamespaceDefaultSg map[string][]metadata.OpflexGroup `json:"namespace-default-security-group,omitempty"`
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

	// Absolute path to CloudFoundry-specific config file
	CfConfig string `json:"cfconfig,omitempty"`

	// Name of Kubernetes node on which this agent is running
	NodeName string `json:"node-name,omitempty"`

	// TCP port to run status server on (or 0 to disable)
	StatusPort int `json:"status-port,omitempty"`

	// Directory containing OpFlex CNI metadata
	CniMetadataDir string `json:"cni-metadata-dir,omitempty"`

	// Name of the CNI network
	CniNetwork string `json:"cni-network,omitempty"`

	// Directory for writing Opflex configuration
	OpFlexConfigPath string `json:"opflex-config-path,omitempty"`

	// Directory for writing OpFlex endpoint metadata
	OpFlexEndpointDir string `json:"opflex-endpoint-dir,omitempty"`

	// Directory for writing OpFlex service metadata
	OpFlexServiceDir string `json:"opflex-service-dir,omitempty"`

	// Directory for writing OpFlex snat metadata
	OpFlexSnatDir string `json:"opflex-snat-dir,omitempty"`

	// OpFlex agent's flow-ID cache directory
	OpFlexFlowIdCacheDir string `json:"opflex-flowid-cache-dir,omitempty"`

	// Multicast groups file used by OpFlex agent
	OpFlexMcastFile string `json:"opflex-mcast-file,omitempty"`

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

	// Configuration for CNI networks
	NetConfig []cniNetConfig `json:"cni-netconfig,omitempty"`

	// The type of the ACI VMM domain: either "Kubernetes",
	// "OpenShift" or "CloudFoundry"
	AciVmmDomainType string `json:"aci-vmm-type,omitempty"`

	// The name of the ACI VMM domain
	AciVmmDomain string `json:"aci-vmm-domain,omitempty"`

	// The name of the ACI VMM domain controller instance
	AciVmmController string `json:"aci-vmm-controller,omitempty"`

	// ACI VRF for this kubernetes instance
	AciVrf string `json:"aci-vrf,omitempty"`

	// ACI Tenant containing the ACI VRF for this kubernetes instance
	AciVrfTenant string `json:"aci-vrf-tenant,omitempty"`

	//ZoneId for Snat flows
	Zone uint `json:"zone,omitempty"`

	//Namespace for SNAT CRDs
	AciSnatNamespace string `json:"aci-snat-namespace,omitempty"`
}

func (config *HostAgentConfig) InitFlags() {
	flag.BoolVar(&config.ChildMode, "child-mode", false, "Child Mode")

	flag.StringVar(&config.LogLevel, "log-level", "info", "Log level")

	flag.StringVar(&config.KubeConfig, "kubeconfig", "", "Absolute path to a kubeconfig file")
	flag.StringVar(&config.NodeName, "node-name", "", "Name of Kubernetes node on which this agent is running")

	flag.StringVar(&config.CfConfig, "cfconfig", "", "Absolute path to CloudFoundry-specific config file")

	flag.IntVar(&config.StatusPort, "status-port", 8090, "TCP port to run status server on (or 0 to disable)")

	flag.StringVar(&config.CniMetadataDir, "cni-metadata-dir", "/usr/local/var/lib/aci-containers/", "Directory for writing OpFlex endpoint metadata")
	flag.StringVar(&config.CniNetwork, "cni-network", "k8s-pod-network", "Name of the CNI network")

	flag.StringVar(&config.OpFlexConfigPath, "opflex-config-path", "/usr/local/etc/opflex-agent-ovs/base-conf.d", "Directory for writing Opflex configuration")
	flag.StringVar(&config.OpFlexEndpointDir, "opflex-endpoint-dir", "/usr/local/var/lib/opflex-agent-ovs/endpoints/", "Directory for writing OpFlex endpoint metadata")
	flag.StringVar(&config.OpFlexServiceDir, "opflex-service-dir", "/usr/local/var/lib/opflex-agent-ovs/services/", "Directory for writing OpFlex anycast service metadata")
	flag.StringVar(&config.OpFlexSnatDir, "opflex-snat-dir", "/usr/local/var/lib/opflex-agent-ovs/snats/", "Directory for writing OpFlex snat metadata")
	flag.StringVar(&config.OpFlexFlowIdCacheDir, "opflex-flowid-cache-dir",
		"/usr/local/var/lib/opflex-agent-ovs/ids/",
		"OpFlex agent's flow-ID cache directory")
	flag.StringVar(&config.OpFlexMcastFile, "opflex-mcast-file",
		"/usr/local/var/lib/opflex-agent-ovs/mcast/opflex-groups.json",
		"Multicast groups file used by OpFlex agent")

	flag.StringVar(&config.OvsDbSock, "ovs-db-sock", "/usr/local/var/run/openvswitch/db.sock", "Location of the OVS DB socket")
	flag.StringVar(&config.EpRpcSock, "ep-rpc-sock", "/usr/local/var/run/aci-containers-ep-rpc.sock", "Location of the endpoint RPC socket used for communicating with the CNI plugin")
	flag.StringVar(&config.EpRpcSockPerms, "ep-rpc-sock-perms", "", "Permissions to set for endpoint RPC socket file. Octal string")

	flag.StringVar(&config.IntBridgeName, "int-bridge-name", "br-int", "Name of the OVS integration bridge")
	flag.StringVar(&config.AccessBridgeName, "access-bridge-name", "br-access", "Name of the OVS access bridge")

	flag.IntVar(&config.InterfaceMtu, "interface-mtu", 1500, "Interface MTU to use when configuring container interfaces")

	flag.UintVar(&config.ServiceVlan, "service-vlan", 4003, "VLAN for service traffic")

	flag.StringVar(&config.UplinkIface, "uplink-iface", "eth1", "Uplink interface for this host")
	flag.UintVar(&config.AciInfraVlan, "aci-infra-vlan", 4093, "Vlan used for ACI infrastructure traffic")
	flag.StringVar(&config.EncapType, "encap-type", "vxlan", "Type of encapsulation to use for uplink; either vlan or vxlan")
	flag.StringVar(&config.VxlanIface, "vxlan-iface", "eth1.4093", "Subinterface of uplink interface on AciInfraVlan")
	flag.StringVar(&config.VxlanAnycastIp, "vxlan-anycast-ip", "10.0.0.32", "Anycast IP used for unicast VXLAN packets")
	flag.StringVar(&config.OpflexPeerIp, "opflex-peer-ip", "10.0.0.30", "Anycast IP used for OpFlex communication")

	flag.StringVar(&config.AciVmmDomainType, "aci-vmm-domain-type", "Kubernetes", "ACI VMM domain type")
	flag.StringVar(&config.AciVmmDomain, "aci-vmm-domain", "kubernetes", "ACI VMM domain")
	flag.StringVar(&config.AciVmmController, "aci-vmm-controller", "kubernetes", "ACI VMM domain controller")

	flag.StringVar(&config.AciVrf, "aci-vrf", "kubernetes-vrf", "ACI VRF for this kubernetes instance")
	flag.StringVar(&config.AciVrfTenant, "aci-vrf-tenant", "common", "ACI Tenant containing the ACI VRF for this kubernetes instance")
	flag.UintVar(&config.Zone, "zone", 8191, "Zone Id for snat flows")
	flag.StringVar(&config.AciSnatNamespace, "aci-snat-namespace", "aci-containers-system", "Namespace for SNAT CRDs")
}
