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

// IP address management for host agent

package hostagent

import (
	"net"
	"reflect"
	"testing"

	cnitypes "github.com/containernetworking/cni/pkg/types"
	"github.com/noironetworks/aci-containers/pkg/ipam"
	"github.com/noironetworks/aci-containers/pkg/metadata"
	"github.com/sirupsen/logrus"
)

func TestDeallocateIpsLocked(t *testing.T) {
	agent := testAgent()
	agent.run()
	defer agent.stop()

	agent.usedIPs = make(map[string]string)
	agent.usedIPs["192.168.0.1"] = "test"
	agent.usedIPs["2001:db8::1"] = "test"

	iface := &metadata.ContainerIfaceMd{
		IPs: []metadata.ContainerIfaceIP{
			{Address: net.IPNet{IP: net.ParseIP("192.168.0.1")}},
			{Address: net.IPNet{IP: net.ParseIP("2001:db8::1")}},
		},
	}

	agent.deallocateIpsLocked(iface)

	for _, ip := range iface.IPs {
		if _, ok := agent.usedIPs[ip.Address.IP.String()]; ok {
			t.Errorf("IP %v was not deallocated", ip.Address.IP)
		}
	}

	if len(agent.usedIPs) != 0 {
		t.Errorf("usedIPs map is not empty")
	}
}
func TestConvertRoutes(t *testing.T) {
	routes := []route{
		{
			Dst: cnitypes.IPNet{
				IP:   net.ParseIP("192.168.0.0"),
				Mask: net.CIDRMask(24, 32),
			},
			GW: net.ParseIP("192.168.0.1"),
		},
		{
			Dst: cnitypes.IPNet{
				IP:   net.ParseIP("10.0.0.0"),
				Mask: net.CIDRMask(16, 32),
			},
			GW: net.ParseIP("10.0.0.1"),
		},
	}

	expected := []*cnitypes.Route{
		{
			Dst: net.IPNet{
				IP:   net.ParseIP("192.168.0.0"),
				Mask: net.CIDRMask(24, 32),
			},
			GW: net.ParseIP("192.168.0.1"),
		},
		{
			Dst: net.IPNet{
				IP:   net.ParseIP("10.0.0.0"),
				Mask: net.CIDRMask(16, 32),
			},
			GW: net.ParseIP("10.0.0.1"),
		},
	}

	cniroutes := convertRoutes(routes)

	if len(cniroutes) != len(expected) {
		t.Errorf("Expected %d routes, but got %d", len(expected), len(cniroutes))
	}

	for i, route := range cniroutes {
		if !reflect.DeepEqual(route, expected[i]) {
			t.Errorf("Expected route %v, but got %v", expected[i], route)
		}
	}
}
func TestRebuildIpam(t *testing.T) {
	agent := &HostAgent{}
	log := logrus.New()
	agent.log = log
	agent.usedIPs = map[string]string{
		"192.168.0.1": "test",
		"50":          "test",
		"2001:db8::1": "test",
	}

	agent.podIps = ipam.NewIpCache()
	agent.podIps.DeallocateIp(net.ParseIP("192.168.0.2"))
	agent.podIps.DeallocateIp(net.ParseIP("2001:db8::2"))

	agent.rebuildIpam()

	if len(agent.usedIPs) == 0 {
		t.Errorf("usedIPs map is empty")
	}

	expectedV4 := []ipam.IpRange{
		{Start: net.ParseIP("192.168.0.2"), End: net.ParseIP("192.168.0.2")},
	}
	expectedV6 := []ipam.IpRange{
		{Start: net.ParseIP("2001:db8::2"), End: net.ParseIP("2001:db8::2")},
	}

	if !reflect.DeepEqual(agent.podIps.CombineV4(), expectedV4) {
		t.Errorf("Expected V4 ranges %v, but got %v", expectedV4, agent.podIps.CombineV4())
	}

	if !reflect.DeepEqual(agent.podIps.CombineV6(), expectedV6) {
		t.Errorf("Expected V6 ranges %v, but got %v", expectedV6, agent.podIps.CombineV6())
	}

	agent.podIps.DeallocateIp(net.ParseIP("192.168.0.1"))
	agent.podIps.DeallocateIp(net.ParseIP("2001:db8::1"))

	agent.usedIPs["192.168.0.2"] = "test1"
	agent.usedIPs["2001:db8::2"] = "test1"

	agent.rebuildIpam()

	if len(agent.podIps.CombineV4()) != 0 || len(agent.podIps.CombineV6()) != 0 {
		t.Errorf("podIps map is not empty")
	}
}
