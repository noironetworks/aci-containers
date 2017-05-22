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
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/client-go/pkg/api/v1"

	"github.com/noironetworks/aci-containers/pkg/apicapi"
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

type seMap map[string]*metadata.ServiceEndpoint

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
		cont.config.AciVrfTenant = "common"
		cont.config.AciL3Out = "l3out"
		cont.config.AciExtNetworks = []string{"ext1"}
		cont.config.NodeServiceSubnets = []string{"10.6.0.1/16"}
		cont.config.AciVmmDomain = "kube-domain"
		cont.config.AciVmmController = "kube-controller"

		return cont
	}

	graphName := "kube_service_global"
	cluster := func(nmap map[string]string) apicapi.ApicObject {
		var nodes []string
		for node, _ := range nmap {
			nodes = append(nodes, node)
		}
		sort.Strings(nodes)
		dc, _ := apicDeviceCluster(graphName, "common", "service-physdom",
			"vlan-4001", nodes, nmap)
		return dc
	}
	twoNodeCluster := cluster(map[string]string{
		"node1": "topology/pod-1/paths-301/pathep-[eth1/33]",
		"node2": "topology/pod-1/paths-301/pathep-[eth1/34]",
	})
	oneNodeCluster := cluster(map[string]string{
		"node1": "topology/pod-1/paths-301/pathep-[eth1/100]",
	})

	graph := apicServiceGraph(graphName, "common", twoNodeCluster.GetDn())

	name := "kube_service_testns_service1"
	nameS2 := "kube_service_testns_service2"
	redirect := func(nmap seMap) apicapi.ApicObject {
		var nodes []string
		for node, _ := range nmap {
			nodes = append(nodes, node)
		}
		sort.Strings(nodes)
		dc, _ := apicRedirectPol(name, "common", nodes, nmap)
		return dc
	}
	twoNodeRedirect := redirect(seMap{
		"node1": &metadata.ServiceEndpoint{
			Mac:  "8a:35:a1:a6:e4:60",
			Ipv4: net.ParseIP("10.6.1.1"),
		},
		"node2": &metadata.ServiceEndpoint{
			Mac:  "a2:7e:45:57:a0:d4",
			Ipv4: net.ParseIP("10.6.1.2"),
		},
	})
	oneNodeRedirect := redirect(seMap{
		"node1": &metadata.ServiceEndpoint{
			Mac:  "8a:35:a1:a6:e4:60",
			Ipv4: net.ParseIP("10.6.1.1"),
		},
	})

	extNet := apicExtNet(name, "common", "l3out", []string{"10.4.2.2"})
	contract := apicContract(name, "common", graphName)
	rsCons := apicExtNetCons(name, "common", "l3out", "ext1")

	filter := apicapi.NewVzFilter("common", name)
	filterDn := filter.GetDn()
	{
		fe := apicapi.NewVzEntry(filterDn, "0")
		fe.SetAttr("etherT", "ip")
		fe.SetAttr("prot", "tcp")
		fe.SetAttr("dFromPort", "80")
		fe.SetAttr("dToPort", "80")
		filter.AddChild(fe)
	}
	{
		fe := apicapi.NewVzEntry(filterDn, "1")
		fe.SetAttr("etherT", "ip")
		fe.SetAttr("prot", "udp")
		fe.SetAttr("dFromPort", "53")
		fe.SetAttr("dToPort", "53")
		filter.AddChild(fe)
	}

	s1Dcc := apicDevCtx(name, "common", graphName,
		"kube_bd_kubernetes-service", oneNodeRedirect.GetDn())

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

	opflexDevice1 := apicapi.EmptyApicObject("opflexODev", "dev1")
	opflexDevice1.SetAttr("hostName", "node1")
	opflexDevice1.SetAttr("fabricPathDn",
		"topology/pod-1/paths-301/pathep-[eth1/33]")

	opflexDevice2 := apicapi.EmptyApicObject("opflexODev", "dev2")
	opflexDevice2.SetAttr("hostName", "node2")
	opflexDevice2.SetAttr("fabricPathDn",
		"topology/pod-1/paths-301/pathep-[eth1/34]")

	opflexDevice3 := apicapi.EmptyApicObject("opflexODev", "dev1")
	opflexDevice3.SetAttr("hostName", "node3")
	opflexDevice3.SetAttr("fabricPathDn",
		"topology/pod-1/paths-301/pathep-[eth1/50]")

	opflexDevice4 := apicapi.EmptyApicObject("opflexODev", "dev2")
	opflexDevice4.SetAttr("hostName", "node4")
	opflexDevice4.SetAttr("fabricPathDn",
		"topology/pod-1/paths-301/pathep-[eth1/51]")

	opflexDevice1_alt := apicapi.EmptyApicObject("opflexODev", "dev1")
	opflexDevice1_alt.SetAttr("hostName", "node1")
	opflexDevice1_alt.SetAttr("fabricPathDn",
		"topology/pod-1/paths-301/pathep-[eth1/100]")

	//
	//opflexDevice0 := NewOpflexDevice("pod1", "node-301", "br", "dev1")
	//opflexDevice0.Spec.OpflexDevice.HostName = "node1"
	//opflexDevice0.Spec.OpflexDevice.DomainName = "not-kube-domain"
	//opflexDevice0.Spec.OpflexDevice.ControllerName = "kube-controller"
	//opflexDevice0.Spec.OpflexDevice.FabricPathDn =
	//	"topology/pod-1/paths-301/pathep-[eth1/42]"
	//
	//opflexDevice1 := NewOpflexDevice("pod1", "node-301", "br", "dev1")
	//opflexDevice1.Spec.OpflexDevice.HostName = "node1"
	//opflexDevice1.Spec.OpflexDevice.DomainName = "kube-domain"
	//opflexDevice1.Spec.OpflexDevice.ControllerName = "kube-controller"
	//opflexDevice1.Spec.OpflexDevice.FabricPathDn =
	//	"topology/pod-1/paths-301/pathep-[eth1/33]"
	//
	//opflexDevice2 := NewOpflexDevice("pod1", "node-301", "br", "dev2")
	//opflexDevice2.Spec.OpflexDevice.HostName = "node2"
	//opflexDevice2.Spec.OpflexDevice.DomainName = "kube-domain"
	//opflexDevice2.Spec.OpflexDevice.ControllerName = "kube-controller"
	//opflexDevice2.Spec.OpflexDevice.FabricPathDn =
	//	"topology/pod-1/paths-301/pathep-[eth1/34]"
	//
	//opflexDevice3 := NewOpflexDevice("pod1", "node-301", "br", "dev1")
	//opflexDevice3.Spec.OpflexDevice.HostName = "node3"
	//opflexDevice3.Spec.OpflexDevice.DomainName = "kube-domain"
	//opflexDevice3.Spec.OpflexDevice.ControllerName = "kube-controller"
	//opflexDevice3.Spec.OpflexDevice.FabricPathDn =
	//	"topology/pod-1/paths-301/pathep-[eth1/50]"
	//
	//opflexDevice4 := NewOpflexDevice("pod1", "node-301", "br", "dev2")
	//opflexDevice4.Spec.OpflexDevice.HostName = "node4"
	//opflexDevice4.Spec.OpflexDevice.DomainName = "kube-domain"
	//opflexDevice4.Spec.OpflexDevice.ControllerName = "kube-controller"
	//opflexDevice4.Spec.OpflexDevice.FabricPathDn =
	//	"topology/pod-1/paths-301/pathep-[eth1/51]"
	//
	//opflexDevice1_alt := NewOpflexDevice("pod1", "node-301", "br", "dev1")
	//opflexDevice1_alt.Spec.OpflexDevice.HostName = "node1"
	//opflexDevice1_alt.Spec.OpflexDevice.DomainName = "kube-domain"
	//opflexDevice1_alt.Spec.OpflexDevice.ControllerName = "kube-controller"
	//opflexDevice1_alt.Spec.OpflexDevice.FabricPathDn =
	//	"topology/pod-1/paths-301/pathep-[eth1/100]"
	//
	sgWait := func(t *testing.T, desc string, cont *testAciController,
		expected map[string]apicapi.ApicSlice) {

		tu.WaitFor(t, desc, 500*time.Millisecond,
			func(last bool) (bool, error) {
				cont.indexMutex.Lock()
				defer cont.indexMutex.Unlock()

				for key, slice := range expected {
					ds := cont.apicConn.GetDesiredState(key)
					if !tu.WaitEqual(t, last, slice, ds, desc, key) {
						for i := range slice {
							if last &&
								assert.Equal(t, len(slice[i]), len(ds[i])) {
								assert.Equal(t, slice[i], ds[i])
							} else {
								return false, nil
							}
						}
					}
				}
				return true, nil
			})
		cont.log.Info("Finished waiting for ", desc)
	}
	//
	//mWait := func(t *testing.T, desc string, cont *testAciController,
	//	expected []string) {
	//
	//	tu.WaitFor(t, desc, 500*time.Millisecond,
	//		func(last bool) (bool, error) {
	//			if !tu.WaitEqual(t, last, 1, len(cont.aimUpdates)) {
	//				return false, nil
	//			}
	//			for _, a := range cont.aimUpdates {
	//				return tu.WaitEqual(t, last, expected,
	//					a.Spec.ExternalNetwork.ConsumedContractNames,
	//					desc), nil
	//			}
	//			return false, nil
	//		})
	//}
	//
	expected := map[string]apicapi.ApicSlice{
		graphName: apicapi.PrepareApicSlice(apicapi.ApicSlice{twoNodeCluster,
			graph}, graphName),
		name: apicapi.PrepareApicSlice(apicapi.ApicSlice{twoNodeRedirect,
			extNet, contract, rsCons, filter, s1Dcc}, name),
		nameS2: nil,
	}

	expectedOneNode := map[string]apicapi.ApicSlice{
		graphName: apicapi.PrepareApicSlice(apicapi.ApicSlice{oneNodeCluster,
			graph},
			graphName),
		name: apicapi.PrepareApicSlice(apicapi.ApicSlice{oneNodeRedirect,
			extNet, contract, rsCons, filter, s1Dcc}, name),
		nameS2: nil,
	}

	expectedNoService := map[string]apicapi.ApicSlice{
		graphName: apicapi.PrepareApicSlice(apicapi.ApicSlice{twoNodeCluster,
			graph},
			graphName),
		name:   nil,
		nameS2: nil,
	}

	//
	//expectedOneNode := map[aimKey]aciSlice{
	//	graphkey: fixAciSlice(aciSlice{oneNodeCluster, graph},
	//		"DeviceCluster", "static"),
	//	s1key: fixAciSlice(aciSlice{oneNodeRedirect,
	//		extNet, extNetSub, contract, contractSubj, f_in,
	//		fe_tcp_80_in, fe_udp_53_in, s1Dcc},
	//		"Service", name),
	//}
	//expectedNoService := map[aimKey]aciSlice{
	//	graphkey: fixAciSlice(aciSlice{twoNodeCluster, graph},
	//		"DeviceCluster", "static"),
	//	s1key: nil,
	//	s2key: nil,
	//}
	//
	cont := sgCont()
	cont.fakeNodeSource.Add(node1)
	cont.fakeNodeSource.Add(node2)
	cont.fakeServiceSource.Add(service2)
	cont.run()
	cont.opflexDeviceChanged(opflexDevice1)
	cont.opflexDeviceChanged(opflexDevice2)

	sgWait(t, "non-lb", cont, expectedNoService)

	cont.serviceUpdates = nil
	cont.fakeEndpointsSource.Add(endpoints1)
	cont.fakeServiceSource.Add(service1)

	sgWait(t, "create", cont, expected)

	cont.opflexDeviceDeleted(opflexDevice1.GetDn())
	cont.opflexDeviceDeleted(opflexDevice2.GetDn())
	sgWait(t, "delete device", cont,
		map[string]apicapi.ApicSlice{name: nil})

	cont.opflexDeviceChanged(opflexDevice1)
	cont.opflexDeviceChanged(opflexDevice2)
	sgWait(t, "add device", cont, expected)

	cont.opflexDeviceChanged(opflexDevice1_alt)
	cont.opflexDeviceDeleted(opflexDevice2.GetDn())
	sgWait(t, "update device", cont, expectedOneNode)

	cont.opflexDeviceChanged(opflexDevice3)
	cont.opflexDeviceChanged(opflexDevice4)
	sgWait(t, "move device", cont,
		map[string]apicapi.ApicSlice{name: nil})

	cont.opflexDeviceChanged(opflexDevice1)
	cont.opflexDeviceChanged(opflexDevice2)
	sgWait(t, "restore device", cont, expected)

	cont.fakeEndpointsSource.Delete(endpoints1)
	sgWait(t, "delete eps", cont,
		map[string]apicapi.ApicSlice{name: nil})

	cont.fakeEndpointsSource.Add(endpoints1)
	sgWait(t, "add eps", cont, expected)

	cont.fakeNodeSource.Delete(node1)
	cont.fakeNodeSource.Delete(node2)
	sgWait(t, "delete node", cont, map[string]apicapi.ApicSlice{name: nil})

	cont.fakeNodeSource.Add(node1)
	cont.fakeNodeSource.Add(node2)
	sgWait(t, "add node", cont, expected)

	service1.Spec.Type = ""
	cont.fakeServiceSource.Add(service1)
	sgWait(t, "convert to non-lb", cont,
		map[string]apicapi.ApicSlice{name: nil})

	cont.stop()

}
