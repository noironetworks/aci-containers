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
	"fmt"
	"github.com/noironetworks/aci-containers/pkg/apicapi"
	"github.com/noironetworks/aci-containers/pkg/ipam"
	"github.com/noironetworks/aci-containers/pkg/metadata"
	tu "github.com/noironetworks/aci-containers/pkg/testutil"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	"net"
	"sort"
	"testing"
	"time"
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

func TestServiceIpV6(t *testing.T) {
	cont := testController()
	cont.config.ServiceIpPool = []ipam.IpRange{
		{Start: net.ParseIP("2001::1"), End: net.ParseIP("2001::64")},
	}
	cont.config.StaticServiceIpPool = []ipam.IpRange{
		{Start: net.ParseIP("2002::1"), End: net.ParseIP("2002::64")},
	}
	cont.AciController.initIpam()
	cont.run()

	{
		cont.serviceUpdates = nil
		cont.fakeServiceSource.Add(service("testv6", "service1", ""))
		waitForSStatus(t, cont, []string{"2001::1"}, "testv6")
	}
	{
		cont.serviceUpdates = nil
		cont.fakeServiceSource.Add(service("testns", "service2", "2002::1"))
		waitForSStatus(t, cont, []string{"2002::1"}, "static")
	}
	{
		cont.serviceUpdates = nil
		cont.fakeServiceSource.Add(service("testns", "service4", ""))
		waitForSStatus(t, cont, []string{"2001::2"}, "next ip from pool")
	}
	{
		cont.serviceUpdates = nil
		s := service("testns", "service5", "")
		s.Status.LoadBalancer.Ingress =
			[]v1.LoadBalancerIngress{{IP: "2001::32"}}
		cont.handleServiceUpdate(s)
		assert.Nil(t, cont.serviceUpdates, "existing")
		assert.False(t, ipam.HasIp(cont.serviceIps.GetV6IpCache()[0], net.ParseIP("2001::32")),
			"existing pool check")
	}
	{
		cont.serviceUpdates = nil
		s := service("testns", "service6", "2002::3")
		s.Status.LoadBalancer.Ingress =
			[]v1.LoadBalancerIngress{{IP: "2002::3"}}
		cont.handleServiceUpdate(s)
		assert.Nil(t, cont.serviceUpdates, "static existing")
	}
	{
		cont.serviceUpdates = nil
		cont.serviceDeleted(service("testns", "service2", "2002::1"))
		assert.True(t, ipam.HasIp(cont.staticServiceIps.V6, net.ParseIP("2002::1")),
			"delete static return")
	}
	{
		cont.serviceUpdates = nil
		cont.serviceDeleted(service("testns", "service5", ""))
		assert.True(t, ipam.HasIp(cont.serviceIps.GetV6IpCache()[1], net.ParseIP("2001::32")),
			"delete pool return")
	}

	cont.stop()
}

func TestServiceIp(t *testing.T) {
	cont := testController()
	cont.config.ServiceIpPool = []ipam.IpRange{
		{Start: net.ParseIP("10.4.1.1"), End: net.ParseIP("10.4.1.255")},
	}
	cont.config.StaticServiceIpPool = []ipam.IpRange{
		{Start: net.ParseIP("10.4.2.1"), End: net.ParseIP("10.4.2.255")},
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
		waitForSStatus(t, cont, []string{"10.4.1.3"}, "next ip from pool")
	}
	{
		cont.serviceUpdates = nil
		s := service("testns", "service5", "")
		s.Status.LoadBalancer.Ingress =
			[]v1.LoadBalancerIngress{{IP: "10.4.1.32"}}
		cont.handleServiceUpdate(s)
		assert.Nil(t, cont.serviceUpdates, "existing")
		assert.False(t, ipam.HasIp(cont.serviceIps.GetV4IpCache()[0], net.ParseIP("10.4.1.32")),
			"existing pool check")
	}
	{
		cont.serviceUpdates = nil
		s := service("testns", "service6", "10.4.2.3")
		s.Status.LoadBalancer.Ingress =
			[]v1.LoadBalancerIngress{{IP: "10.4.2.3"}}
		cont.handleServiceUpdate(s)
		assert.Nil(t, cont.serviceUpdates, "static existing")
	}
	{
		cont.serviceUpdates = nil
		cont.serviceDeleted(service("testns", "service1", "10.4.2.2"))
		assert.True(t, ipam.HasIp(cont.staticServiceIps.V4, net.ParseIP("10.4.2.2")),
			"delete static return")
	}
	{
		cont.serviceUpdates = nil
		cont.serviceDeleted(service("testns", "service5", ""))
		assert.True(t, ipam.HasIp(cont.serviceIps.GetV4IpCache()[1], net.ParseIP("10.4.1.32")),
			"delete pool return")
	}

	cont.stop()
}

type seMap map[string]*metadata.ServiceEndpoint

func sgCont() *testAciController {
	cont := testController()
	cont.config.NodeServiceIpPool = []ipam.IpRange{
		{Start: net.ParseIP("10.6.1.1"), End: net.ParseIP("10.6.1.2")},
	}
	cont.config.ServiceIpPool = []ipam.IpRange{
		{Start: net.ParseIP("10.4.1.1"), End: net.ParseIP("10.4.1.255")},
	}
	cont.config.StaticServiceIpPool = []ipam.IpRange{
		{Start: net.ParseIP("10.4.2.1"), End: net.ParseIP("10.4.2.255")},
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
	cont.config.AciServiceMonitorInterval = 10
	return cont
}

func sgWait(t *testing.T, desc string, cont *testAciController, expected map[string]apicapi.ApicSlice) {
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

func TestServiceAnnotation(t *testing.T) {
	name := "kube_svc_testns_service1"
	nameS2 := "kube_svc_testns_service2"
	graphName := "kube_svc_global"
	cluster := func(nmap map[string]string) apicapi.ApicObject {
		var nodes []string
		for node := range nmap {
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
	graph := apicServiceGraph(graphName, "common", twoNodeCluster.GetDn())

	redirect := func(nmap seMap) apicapi.ApicObject {
		var nodes []string
		for node := range nmap {
			nodes = append(nodes, node)
		}
		sort.Strings(nodes)
		monPolDn := fmt.Sprintf("uni/tn-%s/ipslaMonitoringPol-%s",
			"common", "kube_monPol_kubernetes-service")
		dc, _ := apicRedirectPol(name, "common", nodes,
			nmap, monPolDn, false)
		return dc
	}
	twoNodeRedirect := redirect(seMap{
		"node1": &metadata.ServiceEndpoint{
			HealthGroupDn: "uni/tn-common/svcCont/redirectHealthGroup-kube_svc_node1",
			Mac:           "8a:35:a1:a6:e4:60",
			Ipv4:          net.ParseIP("10.6.1.1"),
		},
		"node2": &metadata.ServiceEndpoint{
			HealthGroupDn: "uni/tn-common/svcCont/redirectHealthGroup-kube_svc_node2",
			Mac:           "a2:7e:45:57:a0:d4",
			Ipv4:          net.ParseIP("10.6.1.2"),
		},
	})
	oneNodeRedirect := redirect(seMap{
		"node1": &metadata.ServiceEndpoint{
			Mac:  "8a:35:a1:a6:e4:60",
			Ipv4: net.ParseIP("10.6.1.1"),
		},
	})
	extNet := apicExtNet(name, "common", "l3out", []string{"10.4.2.2"}, true, false)
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
	endpoints1 := endpoints("testns", "service1",
		[]string{"node1", "node2"}, nil, nil)
	service1 := service("testns", "service1", "10.4.2.2")
	service1.Spec.Ports = []v1.ServicePort{
		{
			Name:     "tcp_80",
			Protocol: "TCP",
			Port:     80,
		},
		{
			Name:     "udp_53",
			Protocol: "UDP",
			Port:     53,
		},
	}

	service1.Spec.Type = v1.ServiceTypeLoadBalancer
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
	opflexDevice1.SetAttr("devType", "k8s")
	opflexDevice1.SetAttr("domName", "kube")
	opflexDevice1.SetAttr("ctrlrName", "kube")

	opflexDevice2 := apicapi.EmptyApicObject("opflexODev", "dev2")
	opflexDevice2.SetAttr("hostName", "node2")
	opflexDevice2.SetAttr("fabricPathDn",
		"topology/pod-1/paths-301/pathep-[eth1/34]")
	opflexDevice2.SetAttr("devType", "k8s")
	opflexDevice2.SetAttr("domName", "kube")
	opflexDevice2.SetAttr("ctrlrName", "kube")

	cont := sgCont()
	cont.config.AciVmmDomain = "kube"
	cont.config.AciVmmController = "kube"
	cont.fakeNodeSource.Add(node1)
	cont.fakeNodeSource.Add(node2)
	cont.fakeServiceSource.Add(service2)
	cont.run()
	cont.opflexDeviceChanged(opflexDevice1)
	cont.opflexDeviceChanged(opflexDevice2)
	cont.fakeEndpointsSource.Add(endpoints1)

	//Function to check if an object is present in the apic connection at a specific key
	sgPresentObject := func(t *testing.T, desc string, cont *testAciController,
		key string, expected string, present bool) {

		tu.WaitFor(t, desc, 500*time.Millisecond,
			func(last bool) (bool, error) {
				cont.indexMutex.Lock()
				defer cont.indexMutex.Unlock()
				var ok bool
				ds := cont.apicConn.GetDesiredState(key)
				for _, v := range ds {
					if _, ok = v[expected]; ok {
						break
					}
				}
				if ok == present {
					return true, nil
				}
				return false, nil
			})
		cont.log.Info("Finished waiting for ", desc)

	}

	service1.ObjectMeta.Annotations[metadata.ServiceContractScopeAnnotation] = "tenn"
	time.Sleep(2 * time.Second)
	cont.fakeServiceSource.Add(service1)
	sgPresentObject(t, "object absent check", cont, name, "vzBrCP", false)

	service1.ObjectMeta.Annotations[metadata.ServiceContractScopeAnnotation] = "global"
	time.Sleep(2 * time.Second)
	cont.fakeServiceSource.Modify(service1)
	contract := apicContract(name, "common", graphName, "global")
	expected := map[string]apicapi.ApicSlice{
		graphName: apicapi.PrepareApicSlice(apicapi.ApicSlice{twoNodeCluster,
			graph}, "kube", graphName),
		name: apicapi.PrepareApicSlice(apicapi.ApicSlice{twoNodeRedirect, extNet, contract, rsCons, filter, s1Dcc},
			"kube", name),
		nameS2: nil,
	}
	sgPresentObject(t, "object present check", cont, name, "vzBrCP", true)
	sgWait(t, "valid scope check", cont, expected)
	cont.stop()
}

func TestServiceGraph(t *testing.T) {

	graphName := "kube_svc_global"
	cluster := func(nmap map[string]string) apicapi.ApicObject {
		var nodes []string
		for node := range nmap {
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

	name := "kube_svc_testns_service1"
	conScope := "context"
	nameS2 := "kube_svc_testns_service2"
	redirect := func(nmap seMap) apicapi.ApicObject {
		var nodes []string
		for node := range nmap {
			nodes = append(nodes, node)
		}
		sort.Strings(nodes)
		monPolDn := fmt.Sprintf("uni/tn-%s/ipslaMonitoringPol-%s",
			"common", "kube_monPol_kubernetes-service")
		dc, _ := apicRedirectPol(name, "common", nodes,
			nmap, monPolDn, false)
		return dc
	}
	twoNodeRedirect := redirect(seMap{
		"node1": &metadata.ServiceEndpoint{
			HealthGroupDn: "uni/tn-common/svcCont/redirectHealthGroup-kube_svc_node1",
			Mac:           "8a:35:a1:a6:e4:60",
			Ipv4:          net.ParseIP("10.6.1.1"),
		},
		"node2": &metadata.ServiceEndpoint{
			HealthGroupDn: "uni/tn-common/svcCont/redirectHealthGroup-kube_svc_node2",
			Mac:           "a2:7e:45:57:a0:d4",
			Ipv4:          net.ParseIP("10.6.1.2"),
		},
	})
	oneNodeRedirect := redirect(seMap{
		"node1": &metadata.ServiceEndpoint{
			HealthGroupDn: "uni/tn-common/svcCont/redirectHealthGroup-kube_svc_node1",
			Mac:           "8a:35:a1:a6:e4:60",
			Ipv4:          net.ParseIP("10.6.1.1"),
		},
	})

	extNet := apicExtNet(name, "common", "l3out", []string{"10.4.2.2"}, false, false)
	contract := apicContract(name, "common", graphName, conScope)
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

	endpoints1 := endpoints("testns", "service1",
		[]string{"node1", "node2"}, nil, nil)
	service1 := service("testns", "service1", "10.4.2.2")
	service1.Spec.Ports = []v1.ServicePort{
		{
			Name:     "tcp_80",
			Protocol: "TCP",
			Port:     80,
		},
		{
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
	opflexDevice1.SetAttr("devType", "k8s")
	opflexDevice1.SetAttr("domName", "kube")
	opflexDevice1.SetAttr("ctrlrName", "kube")

	opflexDevice2 := apicapi.EmptyApicObject("opflexODev", "dev2")
	opflexDevice2.SetAttr("hostName", "node2")
	opflexDevice2.SetAttr("fabricPathDn",
		"topology/pod-1/paths-301/pathep-[eth1/34]")
	opflexDevice2.SetAttr("devType", "k8s")
	opflexDevice2.SetAttr("domName", "kube")
	opflexDevice2.SetAttr("ctrlrName", "kube")

	opflexDevice3 := apicapi.EmptyApicObject("opflexODev", "dev1")
	opflexDevice3.SetAttr("hostName", "node3")
	opflexDevice3.SetAttr("fabricPathDn",
		"topology/pod-1/paths-301/pathep-[eth1/50]")
	opflexDevice3.SetAttr("devType", "k8s")
	opflexDevice3.SetAttr("domName", "kube")
	opflexDevice3.SetAttr("ctrlrName", "kube")

	opflexDevice4 := apicapi.EmptyApicObject("opflexODev", "dev2")
	opflexDevice4.SetAttr("hostName", "node4")
	opflexDevice4.SetAttr("fabricPathDn",
		"topology/pod-1/paths-301/pathep-[eth1/51]")
	opflexDevice4.SetAttr("devType", "k8s")
	opflexDevice4.SetAttr("domName", "kube")
	opflexDevice4.SetAttr("ctrlrName", "kube")

	opflexDevice1_alt := apicapi.EmptyApicObject("opflexODev", "dev1")
	opflexDevice1_alt.SetAttr("hostName", "node1")
	opflexDevice1_alt.SetAttr("fabricPathDn",
		"topology/pod-1/paths-301/pathep-[eth1/100]")
	opflexDevice1_alt.SetAttr("devType", "k8s")
	opflexDevice1_alt.SetAttr("domName", "kube")
	opflexDevice1_alt.SetAttr("ctrlrName", "kube")

	expected := map[string]apicapi.ApicSlice{
		graphName: apicapi.PrepareApicSlice(apicapi.ApicSlice{twoNodeCluster,
			graph}, "kube", graphName),
		name: apicapi.PrepareApicSlice(apicapi.ApicSlice{
			twoNodeRedirect, extNet, contract, rsCons, filter, s1Dcc},
			"kube", name),
		nameS2: nil,
	}

	expectedOneNode := map[string]apicapi.ApicSlice{
		graphName: apicapi.PrepareApicSlice(apicapi.ApicSlice{oneNodeCluster,
			graph}, "kube", graphName),
		name: apicapi.PrepareApicSlice(apicapi.ApicSlice{
			oneNodeRedirect, extNet, contract, rsCons, filter, s1Dcc},
			"kube", name),
		nameS2: nil,
	}

	expectedNoService := map[string]apicapi.ApicSlice{
		graphName: apicapi.PrepareApicSlice(apicapi.ApicSlice{twoNodeCluster,
			graph}, "kube", graphName),
		name:   nil,
		nameS2: nil,
	}

	cont := sgCont()
	cont.config.AciVmmDomain = "kube"
	cont.config.AciVmmController = "kube"
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
	//reset the node annotations with diffrent values before adding the node
	node1.ObjectMeta.Annotations[metadata.ServiceEpAnnotation] =
		"{\"mac\":\"8a:35:a1:a6:e4:60\",\"ipv4\":\"10.6.1.5\"}"
	node2.ObjectMeta.Annotations[metadata.ServiceEpAnnotation] =
		"{\"mac\":\"a2:7e:45:57:a0:d4\",\"ipv4\":\"10.6.1.6\"}"

	cont.fakeNodeSource.Add(node1)
	cont.fakeNodeSource.Add(node2)
	sgWait(t, "add node", cont, expected)

	service1.Spec.Type = ""
	cont.fakeServiceSource.Add(service1)
	sgWait(t, "convert to non-lb", cont,
		map[string]apicapi.ApicSlice{name: nil})

	cont.stop()

}

func TestEndpointsIpIndex(t *testing.T) {
	eps1 := endpoints("ns1", "name1", nil, []string{"1.1.1.1", "1.1.1.2"}, nil)

	cont := testController()
	cont.fakeEndpointsSource.Add(eps1)
	cont.run()

	tu.WaitForComp(t, "add", 500*time.Millisecond,
		func() bool {
			c1, _ := cont.endpointsIpIndex.Contains(net.ParseIP("1.1.1.1"))
			c2, _ := cont.endpointsIpIndex.Contains(net.ParseIP("1.1.1.2"))
			return (c1 && c2)
		})

	eps1 = endpoints("ns1", "name1", nil, []string{"1.1.1.1"}, nil)
	cont.log.Info("updating")
	cont.fakeEndpointsSource.Add(eps1)

	tu.WaitForComp(t, "update", 500*time.Millisecond,
		func() bool {
			c1, _ := cont.endpointsIpIndex.Contains(net.ParseIP("1.1.1.1"))
			c2, _ := cont.endpointsIpIndex.Contains(net.ParseIP("1.1.1.2"))
			return (c1 && !c2)
		})

	cont.log.Info("adding new")
	eps2 := endpoints("ns1", "name2", nil, []string{"1.1.1.1", "1.1.1.3"}, nil)
	cont.fakeEndpointsSource.Add(eps2)

	tu.WaitForComp(t, "new", 500*time.Millisecond,
		func() bool {
			c1, _ := cont.endpointsIpIndex.Contains(net.ParseIP("1.1.1.3"))
			return c1
		})

	cont.log.Info("ipv6")
	eps3 := endpoints("ns1", "name2", nil, []string{"2001::1"}, nil)
	cont.fakeEndpointsSource.Add(eps3)

	tu.WaitForComp(t, "ipv6", 500*time.Millisecond,
		func() bool {
			c1, _ := cont.endpointsIpIndex.Contains(net.ParseIP("2001::1"))
			return c1
		})

	cont.log.Info("deleting")
	cont.fakeEndpointsSource.Delete(eps1)
	cont.fakeEndpointsSource.Delete(eps2)

	tu.WaitForComp(t, "delete", 500*time.Millisecond,
		func() bool {
			c1, _ := cont.endpointsIpIndex.Contains(net.ParseIP("1.1.1.1"))
			c2, _ := cont.endpointsIpIndex.Contains(net.ParseIP("1.1.1.2"))
			c3, _ := cont.endpointsIpIndex.Contains(net.ParseIP("1.1.1.3"))
			return (!c1 && !c2 && !c3)
		})

}
