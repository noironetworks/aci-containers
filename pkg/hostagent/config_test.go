// Copyright 2019 Cisco Systems, Inc.
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
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func TestInitFlags(t *testing.T) {
	expConfig := &HostAgentConfig{
		HostAgentNodeConfig: HostAgentNodeConfig{
			UplinkIface:    "eth1",
			VxlanIface:     "eth1.4093",
			VxlanAnycastIp: "10.0.0.32",
			OpflexPeerIp:   "10.0.0.30",
		},
		ChildMode:                   false,
		LogLevel:                    "info",
		KubeConfig:                  "",
		NodeName:                    "",
		StatusPort:                  8090,
		GRPCPort:                    19999,
		CniMetadataDir:              "/usr/local/var/lib/aci-containers/",
		OpFlexConfigPath:            "/usr/local/etc/opflex-agent-ovs/base-conf.d",
		OpFlexEndpointDir:           "/usr/local/var/lib/opflex-agent-ovs/endpoints/",
		OpFlexServiceDir:            "/usr/local/var/lib/opflex-agent-ovs/services/",
		OpFlexSnatDir:               "/usr/local/var/lib/opflex-agent-ovs/snats/",
		OpFlexFaultDir:              "/usr/local/var/lib/opflex-agent-ovs/faults/",
		OpFlexFlowIdCacheDir:        "/usr/local/var/lib/opflex-agent-ovs/ids/",
		OpFlexMcastFile:             "/usr/local/var/lib/opflex-agent-ovs/mcast/opflex-groups.json",
		OpFlexServerConfigFile:      "/usr/local/var/lib/opflex-server/config.json",
		PacketEventNotificationSock: "/usr/local/var/run/aci-containers-packet-event-notification.sock",
		OpFlexDropLogConfigDir:      "/usr/local/var/lib/opflex-agent-ovs/droplog",
		OpFlexDropLogRemoteIp:       "192.168.1.2",
		OvsDbSock:                   "/usr/local/var/run/openvswitch/db.sock",
		EpRpcSock:                   "/usr/local/var/run/aci-containers-ep-rpc.sock",
		EpRpcSockPerms:              "",
		IntBridgeName:               "br-int",
		AccessBridgeName:            "br-access",
		InterfaceMtu:                0,
		InterfaceMtuHeadroom:        100,
		ServiceVlan:                 4003,
		AciInfraVlan:                4093,
		EncapType:                   "vxlan",
		AciVmmDomainType:            "Kubernetes",
		AciVmmDomain:                "kubernetes",
		AciVmmController:            "kubernetes",
		AciVrf:                      "kubernetes-vrf",
		AciVrfTenant:                "common",
		Zone:                        8191,
		AciSnatNamespace:            "aci-containers-system",
		EnableDropLogging:           false,
		DropLogAccessInterface:      "gen2",
		DropLogIntInterface:         "gen1",
		DropLogExpiryTime:           10,
		DropLogRepeatIntervalTime:   2,
		DhcpDelay:                   5,
		DhcpRenewMaxRetryCount:      5,
		Flavor:                      "",
		InstallerProvlbIp:           "",
		EnableNodePodIF:             false,
		EPRegistry:                  "",
		OvsHardwareOffload:          false,
		DpuOvsDBSocket:              "tcp:192.168.200.2:6640",
		ChainedMode:                 false,
		CniNetworksDir:              "/usr/local/var/lib/netop-cni/networks",
		EnableMetrics:               false,
		MetricsPort:                 8190,
	}

	veth_mode := os.Getenv("GENERIC_VETH_MODE")
	// Check if the environment variable is set
	if veth_mode != "True" {
		expConfig.CniNetwork = "k8s-pod-network"
	} else {
		expConfig.CniNetwork = "generic-veth"
	}

	config := &HostAgentConfig{}
	config.InitFlags()
	assert.Equal(t, expConfig, config)
}
