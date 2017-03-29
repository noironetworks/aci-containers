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

package controller

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/client-go/pkg/api/v1"

	"github.com/noironetworks/aci-containers/pkg/ipam"
	"github.com/noironetworks/aci-containers/pkg/metadata"
	tu "github.com/noironetworks/aci-containers/pkg/testutil"
)

func waitForSStatus(t *testing.T, cont *testAciController,
	ips []string, desc string) {

	tu.WaitFor(t, desc, 500*time.Millisecond,
		func(last bool) (bool, error) {
			if !tu.WaitCondition(t, last, func() bool {
				return len(cont.serviceUpdates) >= 1
			}, desc, "update") {
				return false, nil
			}
			ingress :=
				cont.serviceUpdates[len(cont.serviceUpdates)-1].
					Status.LoadBalancer.Ingress
			expected := make(map[string]bool)
			for _, i := range ips {
				expected[i] = true
			}
			seen := make(map[string]bool)
			for _, i := range ingress {
				seen[i.IP] = true
			}
			return tu.WaitEqual(t, last, expected, seen, "lb ingress ips"), nil
		})
}

func hasIpCond(pool *ipam.IpAlloc, ipStr string) func() bool {
	return func() bool {
		ip := net.ParseIP(ipStr)
		r := pool.RemoveIp(ip)
		if r {
			pool.AddIp(ip)
		}
		return r
	}
}
func notHasIpCond(pool *ipam.IpAlloc, ipStr string) func() bool {
	return func() bool {
		return !hasIpCond(pool, ipStr)()
	}
}

func TestServiceIp(t *testing.T) {
	cont := testController()
	cont.config.ServiceIpPool = []ipam.IpRange{
		ipam.IpRange{Start: net.ParseIP("10.4.1.1"), End: net.ParseIP("10.4.1.255")},
	}
	cont.config.StaticServiceIpPool = []ipam.IpRange{
		ipam.IpRange{Start: net.ParseIP("10.4.2.1"), End: net.ParseIP("10.4.2.255")},
	}
	cont.AciController.initIpam()
	cont.run()

	{
		cont.serviceUpdates = nil
		cont.fakeServiceSource.Add(service("testns", "service1", ""))
		waitForSStatus(t, cont, []string{"10.4.1.1"}, "pool")
	}
	{
		cont.serviceUpdates = nil
		cont.fakeServiceSource.Add(service("testns", "service2", "10.4.2.1"))
		waitForSStatus(t, cont, []string{"10.4.2.1"}, "static")
	}
	{
		cont.serviceUpdates = nil
		cont.fakeServiceSource.Add(service("testns", "service3", "10.4.3.1"))
		waitForSStatus(t, cont, []string{"10.4.1.2"}, "static invalid")
	}
	{
		cont.serviceUpdates = nil
		cont.fakeServiceSource.Add(service("testns", "service1", "10.4.2.2"))
		waitForSStatus(t, cont, []string{"10.4.2.2"}, "add request")
	}
	{
		cont.serviceUpdates = nil
		cont.fakeServiceSource.Add(service("testns", "service4", ""))
		waitForSStatus(t, cont, []string{"10.4.1.1"}, "pool return")
	}
	{
		cont.serviceUpdates = nil
		s := service("testns", "service5", "")
		s.Status.LoadBalancer.Ingress =
			[]v1.LoadBalancerIngress{v1.LoadBalancerIngress{IP: "10.4.1.32"}}
		cont.handleServiceUpdate(s)
		assert.Nil(t, cont.serviceUpdates, "existing")
		assert.Condition(t, notHasIpCond(cont.serviceIps.V4, "10.4.1.32"),
			"existing pool check")
	}
	{
		cont.serviceUpdates = nil
		s := service("testns", "service6", "10.4.2.3")
		s.Status.LoadBalancer.Ingress =
			[]v1.LoadBalancerIngress{v1.LoadBalancerIngress{IP: "10.4.2.3"}}
		cont.handleServiceUpdate(s)
		assert.Nil(t, cont.serviceUpdates, "static existing")
	}
	{
		cont.serviceUpdates = nil
		cont.serviceDeleted(service("testns", "service1", "10.4.2.2"))
		assert.Condition(t, hasIpCond(cont.staticServiceIps.V4, "10.4.2.2"),
			"delete static return")
	}
	{
		cont.serviceUpdates = nil
		cont.serviceDeleted(service("testns", "service5", ""))
		assert.Condition(t, hasIpCond(cont.serviceIps.V4, "10.4.1.32"),
			"delete pool return")
	}

	cont.stop()
}

func TestServiceGraph(t *testing.T) {
	sgCont := func() *testAciController {
		cont := testController()
		cont.config.NodeServiceIpPool = []ipam.IpRange{
			ipam.IpRange{Start: net.ParseIP("10.6.1.1"), End: net.ParseIP("10.6.1.2")},
		}
		cont.config.ServiceIpPool = []ipam.IpRange{
			ipam.IpRange{Start: net.ParseIP("10.4.1.1"), End: net.ParseIP("10.4.1.255")},
		}
		cont.config.StaticServiceIpPool = []ipam.IpRange{
			ipam.IpRange{Start: net.ParseIP("10.4.2.1"), End: net.ParseIP("10.4.2.255")},
		}
		cont.AciController.initIpam()
		cont.config.AciServicePhysDom = "service-physdom"
		cont.config.AciServiceEncap = "vlan-4001"
		cont.config.AciPolicyTenant = "test"
		cont.config.AciL3OutTenant = "common"
		cont.config.AciL3Out = "l3out"
		cont.config.AciExtNetworks = []string{"ext1"}
		cont.config.NodeServiceSubnets = []string{"10.6.0.1/16"}
		return cont
	}

	name := "service__testns_service1"
	twoNodeCluster := NewDeviceCluster("common", name)
	twoNodeCluster.Spec.DeviceCluster.Managed = false
	twoNodeCluster.Spec.DeviceCluster.PhysicalDomainName = "service-physdom"
	twoNodeCluster.Spec.DeviceCluster.Encap = "vlan-4001"
	twoNodeCluster.Spec.DeviceCluster.Devices = []Devices{
		Devices{
			Name: "node1",
			// XXX TODO: device path for node
		},
		Devices{
			Name: "node2",
			// XXX TODO: device path for node
		},
	}

	graph := NewServiceGraph("common", name)
	graph.Spec.ServiceGraph.LinearChainNodes = []LinearChainNodes{
		LinearChainNodes{
			DeviceClusterTenantName: "common",
			DeviceClusterName:       name,
			Name:                    "LoadBalancer",
		},
	}

	twoNodeRedirect :=
		NewServiceRedirectPolicy("common", name)
	twoNodeRedirect.Spec.ServiceRedirectPolicy.Destinations = []Destinations{
		Destinations{
			Ip:  "10.6.1.1",
			Mac: "8a:35:a1:a6:e4:60",
		},
		Destinations{
			Ip:  "10.6.1.2",
			Mac: "a2:7e:45:57:a0:d4",
		},
	}

	extNet := NewExternalNetwork("common", "l3out", name)
	extNet.Spec.ExternalNetwork.ProvidedContractNames =
		[]string{name}
	extNetSub := NewExternalSubnet("common", "l3out", name, "10.4.2.2/32")
	contract := NewContract("common", name)
	contractSubj := NewContractSubject("common", name, "LoadBalancedService")
	f_in := NewFilter("common", name+"_in")
	f_out := NewFilter("common", name+"_out")
	contractSubj.Spec.ContractSubject.ServiceGraphName = name
	contractSubj.Spec.ContractSubject.InFilters = []string{name + "_in"}
	contractSubj.Spec.ContractSubject.OutFilters = []string{name + "_out"}
	fe_tcp_80_in := NewFilterEntry("common", name+"_in", "0")
	fe_tcp_80_in.Spec.FilterEntry.EtherType = "ip"
	fe_tcp_80_in.Spec.FilterEntry.IpProtocol = "tcp"
	fe_tcp_80_in.Spec.FilterEntry.DestFromPort = "80"
	fe_udp_53_in := NewFilterEntry("common", name+"_in", "1")
	fe_udp_53_in.Spec.FilterEntry.EtherType = "ip"
	fe_udp_53_in.Spec.FilterEntry.IpProtocol = "udp"
	fe_udp_53_in.Spec.FilterEntry.DestFromPort = "53"
	fe_tcp_80_out := NewFilterEntry("common", name+"_out", "0")
	fe_tcp_80_out.Spec.FilterEntry.EtherType = "ip"
	fe_tcp_80_out.Spec.FilterEntry.IpProtocol = "tcp"
	fe_tcp_80_out.Spec.FilterEntry.SourceFromPort = "80"
	fe_udp_53_out := NewFilterEntry("common", name+"_out", "1")
	fe_udp_53_out.Spec.FilterEntry.EtherType = "ip"
	fe_udp_53_out.Spec.FilterEntry.IpProtocol = "udp"
	fe_udp_53_out.Spec.FilterEntry.SourceFromPort = "53"

	s1Dcc := NewDeviceClusterContext("common",
		name, name, "LoadBalancer")
	s1Dcc.Spec.DeviceClusterContext.BridgeDomainTenantName =
		"common"
	s1Dcc.Spec.DeviceClusterContext.BridgeDomainName =
		"kubernetes-service-bd"
	s1Dcc.Spec.DeviceClusterContext.DeviceClusterTenantName =
		"common"
	s1Dcc.Spec.DeviceClusterContext.DeviceClusterName = name
	s1Dcc.Spec.DeviceClusterContext.ServiceRedirectPolicyTenantName =
		"common"
	s1Dcc.Spec.DeviceClusterContext.ServiceRedirectPolicyName = name

	s1key := aimKey{"Service", name}
	s2key := aimKey{"Service", "service__testns_service2"}

	endpoints1 := endpoints("testns", "service1", []string{"node1", "node2"})
	service1 := service("testns", "service1", "10.4.2.2")
	service1.Spec.Ports = []v1.ServicePort{
		v1.ServicePort{
			Name:     "tcp_80",
			Protocol: "TCP",
			Port:     80,
		},
		v1.ServicePort{
			Name:     "udp_53",
			Protocol: "UDP",
			Port:     53,
		},
	}
	service2 := service("testns", "service2", "")
	service2.Spec.Type = ""

	node1 := node("node1")
	node1.ObjectMeta.Annotations[metadata.ServiceEpAnnotation] =
		"{\"mac\":\"8a:35:a1:a6:e4:60\",\"ipv4\":\"10.6.1.1\"}"
	node2 := node("node2")
	node2.ObjectMeta.Annotations[metadata.ServiceEpAnnotation] =
		"{\"mac\":\"a2:7e:45:57:a0:d4\",\"ipv4\":\"10.6.1.2\"}"

	sgWait := func(t *testing.T, desc string, cont *testAciController,
		expected map[aimKey]aciSlice) {

		tu.WaitFor(t, desc, 500*time.Millisecond,
			func(last bool) (bool, error) {
				cont.indexMutex.Lock()
				defer cont.indexMutex.Unlock()

				for key, slice := range expected {
					fixAciSlice(slice,
						"Service", name)
					if !tu.WaitEqual(t, last, slice,
						cont.aimDesiredState[key], desc, key) {
						if last && len(slice) == len(cont.aimDesiredState[key]) {
							for i := range slice {
								assert.Equal(t, slice[i], cont.aimDesiredState[key][i])
							}
						}
						return false, nil
					}
				}
				return true, nil
			})
	}

	mWait := func(t *testing.T, desc string, cont *testAciController,
		expected []string) {

		tu.WaitFor(t, desc, 500*time.Millisecond,
			func(last bool) (bool, error) {
				if !tu.WaitEqual(t, last, 1, len(cont.aimUpdates)) {
					return false, nil
				}
				for _, a := range cont.aimUpdates {
					return tu.WaitEqual(t, last, expected,
						a.Spec.ExternalNetwork.ConsumedContractNames,
						desc), nil
				}
				return false, nil
			})
	}

	expected := map[aimKey]aciSlice{
		s1key: aciSlice{twoNodeCluster, graph, twoNodeRedirect,
			extNet, extNetSub, contract, contractSubj, f_in, f_out,
			fe_tcp_80_in, fe_tcp_80_out, fe_udp_53_in, fe_udp_53_out,
			s1Dcc},
	}

	cont := sgCont()
	cont.fakeNodeSource.Add(node1)
	cont.fakeNodeSource.Add(node2)
	cont.fakeServiceSource.Add(service2)
	cont.run()

	sgWait(t, "non-lb", cont, map[aimKey]aciSlice{s2key: nil})

	cont.serviceUpdates = nil
	cont.fakeEndpointsSource.Add(endpoints1)
	cont.fakeServiceSource.Add(service1)

	sgWait(t, "create", cont, expected)

	cont.fakeEndpointsSource.Delete(endpoints1)
	sgWait(t, "delete eps", cont, map[aimKey]aciSlice{s1key: nil})

	cont.fakeEndpointsSource.Add(endpoints1)
	sgWait(t, "add eps", cont, expected)

	monitored := NewExternalNetwork("common", "l3out", "ext1")
	monitored.Spec.ExternalNetwork.Monitored = true

	cont.fakeAimSource.Add(monitored)
	mWait(t, "add extnet", cont, []string{name})
	cont.aimUpdates = nil

	cont.fakeServiceSource.Delete(service1)
	sgWait(t, "delete service", cont, map[aimKey]aciSlice{s1key: nil})
	mWait(t, "delete service monitored extnet", cont, nil)
	cont.aimUpdates = nil

	cont.fakeServiceSource.Add(service1)
	sgWait(t, "add service", cont, expected)
	mWait(t, "add service monitored extnet", cont, []string{name})
	cont.aimUpdates = nil

	cont.fakeNodeSource.Delete(node1)
	cont.fakeNodeSource.Delete(node2)
	sgWait(t, "delete node", cont, map[aimKey]aciSlice{s1key: nil})

	cont.fakeNodeSource.Add(node1)
	cont.fakeNodeSource.Add(node2)
	sgWait(t, "add node", cont, expected)

	service1.Spec.Type = ""
	cont.fakeServiceSource.Add(service1)
	sgWait(t, "convert to non-lb", cont, map[aimKey]aciSlice{s1key: nil})

	cont.stop()

}

func staticServiceKey() aimKey {
	return aimKey{"StaticService", "static"}
}
