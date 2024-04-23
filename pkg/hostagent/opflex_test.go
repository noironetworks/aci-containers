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
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vishvananda/netlink"
)

func doTestOpflex(t *testing.T, agent *testHostAgent) {
	tempdir, err := os.MkdirTemp("", "hostagent_test_")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tempdir)

	agent.config.OpFlexConfigPath = tempdir

	err = agent.writeOpflexConfig()
	assert.Nil(t, err, "config")
	_, err = os.Stat(filepath.Join(tempdir, "01-base.conf"))
	assert.Nil(t, err, "base")
	_, err = os.Stat(filepath.Join(tempdir, "10-renderer.conf"))
	assert.Nil(t, err, "renderer")
}

func TestOpflexConfigVxlan(t *testing.T) {
	agent := testAgent()
	agent.config = &HostAgentConfig{
		HostAgentNodeConfig: HostAgentNodeConfig{
			VxlanIface:  "eth1.4093",
			UplinkIface: "eth1",
		},
		EncapType:    "vxlan",
		AciInfraVlan: 4093,
		NodeName:     "node1",
	}
	doTestOpflex(t, agent)
}

func TestOpflexConfigVlan(t *testing.T) {
	agent := testAgent()
	agent.config = &HostAgentConfig{
		HostAgentNodeConfig: HostAgentNodeConfig{
			VxlanIface:  "eth1.4093",
			UplinkIface: "eth1",
		},
		EncapType:    "vlan",
		AciInfraVlan: 4093,
		NodeName:     "node1",
	}
	doTestOpflex(t, agent)
}

func TestDiscoverUpdateOverlayConfig(t *testing.T) {
	tempdir, err := os.MkdirTemp("", "hostagent_test_")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tempdir)

	agent := testAgent()
	agent.config.OpflexMode = "overlay"
	config := agent.discoverHostConfig()
	assert.NotNil(t, config, "Host config is nil")
	agent.config.HostAgentNodeConfig.VxlanIface = "eth1.4093"
	agent.config.HostAgentNodeConfig.UplinkIface = "eth1"
	agent.config.EncapType = "vlan"
	agent.config.AciInfraVlan = 4093
	agent.config.NodeName = "node1"
	err = agent.writeOpflexConfig()
	if err != nil {
		panic(err)
	}
	agent.config.InterfaceMtu = 1600
	agent.config.OpFlexConfigPath = tempdir + "/opflex.conf"
	agent.updateOpflexConfig()
}

func TestDiscoverDpuConfig(t *testing.T) {
	tempdir, err := os.MkdirTemp("", "hostagent_test_")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tempdir)

	agent := testAgent()
	agent.config.OpflexMode = "dpu"
	agent.config.OpFlexConfigPath = tempdir + "/opflex.conf"
	config := agent.discoverHostConfig()
	assert.NotNil(t, config, "Host config is nil")
	agent.config.InterfaceMtu = 9000
	agent.updateOpflexConfig()
}

func TestDiscoverHostConfigInvalidVlan(t *testing.T) {
	agent := testAgent()
	// assumes there won't be an interface with vlan 0
	agent.config.AciInfraVlan = 0
	config := agent.discoverHostConfig()
	assert.Nil(t, config, "Host config is not nil")
}

func TestDiscoverHostConfigMTUMismtach(t *testing.T) {
	tempdir, err := os.MkdirTemp("", "faultdir_test_")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tempdir)
	agent := testAgent()
	//assigning user defined MTU to be greater than the uplink MTU
	agent.config.OpFlexFaultDir = tempdir
	agent.config.InterfaceMtu = 2000
	config := agent.discoverHostConfig()
	assert.Nil(t, config, "Host config is not nil")
}

func TestOpFlexFaultDirRemoveAll(t *testing.T) {
	tempdir, err := os.MkdirTemp("", "faultdir_test_")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tempdir)
	agent := testAgent()
	agent.config.OpFlexFaultDir = tempdir
	agent.removeAllFiles(tempdir)
}

func TestDiscoverHostIPNotSetForLink(t *testing.T) {
	tempdir, err := os.MkdirTemp("", "faultdir_test_")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tempdir)
	agent := testAgent()
	agent.config.OpFlexFaultDir = tempdir
	agent.config.InterfaceMtu = 200
	config := agent.discoverHostConfig()
	assert.Nil(t, config, "Host config is not nil")
}

func TestCheckIpsInSubnet(t *testing.T) {
	agent := testAgent()

	assert.False(t, agent.isIpSameSubnet("eth0", "1.1.1.0/24"))

	subnet := "192.168.1.0/24"
	addrs := []netlink.Addr{
		{
			IPNet: &net.IPNet{
				IP:   net.IPv4(192, 168, 2, 1),
				Mask: net.IPv4Mask(255, 255, 255, 0),
			},
		},
		{
			IPNet: &net.IPNet{
				IP:   net.IPv4(192, 168, 1, 1),
				Mask: net.IPv4Mask(255, 255, 255, 0),
			},
		},
	}

	// Call the function under test
	result := agent.checkIfAnyIpsInSubnet(subnet, addrs)
	assert.True(t, result, "Expected IP to be in the same subnet")

	addrs = []netlink.Addr{
		{
			IPNet: &net.IPNet{
				IP:   net.IPv4(192, 168, 2, 1),
				Mask: net.IPv4Mask(255, 255, 255, 0),
			},
		},
	}

	result = agent.checkIfAnyIpsInSubnet(subnet, addrs)
	assert.False(t, result, "Expected IP to be in a different subnet")

	subnet = "2001:aa::/64"
	addrs = []netlink.Addr{
		{
			IPNet: &net.IPNet{
				IP:   net.ParseIP("2001:aa:11::1"),
				Mask: net.CIDRMask(64, 128),
			},
		},
		{
			IPNet: &net.IPNet{
				IP:   net.ParseIP("2001:aa::1"),
				Mask: net.CIDRMask(64, 128),
			},
		},
	}

	result = agent.checkIfAnyIpsInSubnet(subnet, addrs)
	assert.True(t, result, "Expected IP to be in the same subnet")

	addrs = []netlink.Addr{
		{
			IPNet: &net.IPNet{
				IP:   net.ParseIP("2001:aa:11::1"),
				Mask: net.CIDRMask(64, 128),
			},
		},
	}

	result = agent.checkIfAnyIpsInSubnet(subnet, addrs)
	assert.False(t, result, "Expected IP to be in a different subnet")
}

func TestDoDhcpRenew(t *testing.T) {
	agent := testAgent()
	agent.aciPodAnnotation = "aci-containers.cisco.com/pod"
	agent.doDhcpRenew("10.1.1.0/24")
}
