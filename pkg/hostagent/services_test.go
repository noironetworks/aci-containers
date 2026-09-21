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
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apitypes "k8s.io/apimachinery/pkg/types"

	"github.com/noironetworks/aci-containers/pkg/metadata"
	tu "github.com/noironetworks/aci-containers/pkg/testutil"
)

func service(uuid string, namespace string, name string,
	clusterIp string, externalIp string, ports []int32) *v1.Service {
	var timeout int32 = 10000
	s := &v1.Service{
		Spec: v1.ServiceSpec{
			ClusterIP:             clusterIp,
			SessionAffinity:       "ClientIP",
			SessionAffinityConfig: &v1.SessionAffinityConfig{ClientIP: &v1.ClientIPConfig{TimeoutSeconds: &timeout}},
		},
		ObjectMeta: metav1.ObjectMeta{
			UID:         apitypes.UID(uuid),
			Namespace:   namespace,
			Name:        name,
			Annotations: map[string]string{},
			Labels:      map[string]string{},
		},
	}

	if externalIp != "" {
		s.Status = v1.ServiceStatus{
			LoadBalancer: v1.LoadBalancerStatus{
				Ingress: []v1.LoadBalancerIngress{
					{
						IP: externalIp,
					},
				},
			},
		}
		s.Spec.Type = v1.ServiceTypeLoadBalancer
	}

	for _, port := range ports {
		s.Spec.Ports = append(s.Spec.Ports,
			v1.ServicePort{
				Protocol: "TCP",
				Port:     port,
			})
	}

	return s
}

func endpointslice(namespace string, name string,
	nextHopIps []string, ports []int32, nodename string) *discovery.EndpointSlice {
	e := &discovery.EndpointSlice{
		Endpoints: []discovery.Endpoint{},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name + "ext",
			Labels:    map[string]string{discovery.LabelServiceName: name},
		},
		Ports: []discovery.EndpointPort{},
	}

	for i, ip := range nextHopIps {
		var endpoint discovery.Endpoint
		var condition = true
		endpoint.Addresses = append(endpoint.Addresses, ip)
		endpoint.Conditions.Ready = &condition
		e.Endpoints = append(e.Endpoints, endpoint)
		e.Endpoints[i].NodeName = &nodename
	}

	for _, port := range ports {
		e.Ports =
			append(e.Ports, discovery.EndpointPort{
				Port:     func() *int32 { a := port; return &a }(),
				Protocol: func() *v1.Protocol { a := v1.ProtocolTCP; return &a }(),
			})
	}
	return e
}

type serviceTest struct {
	uuid       string
	namespace  string
	name       string
	clusterIp  string
	clusterIPs []string
	externalIp string
	ports      []int32
	nextHopIps []string
	nodename   string
}

var serviceTests = []serviceTest{
	{
		"e93abb02-3ffd-41e8-8f3e-7d65b7f970c0",
		"testns",
		"service1",
		"100.1.1.1",
		[]string{},
		"200.1.1.1",
		[]int32{80},
		[]string{"10.1.1.1", "10.2.2.2"},
		"test-node",
	},
	{
		"683c333d-a594-4f00-baa6-0d578a13d83f",
		"testns",
		"service2",
		"100.1.1.2",
		[]string{},
		"",
		[]int32{42},
		[]string{"10.5.1.1", "10.6.2.2"},
		"test-node",
	},
	{
		"683c333d-a594-4f00-baa6-0d578a13d123",
		"testns",
		"service3",
		"2001:1db8:42::8664",
		[]string{},
		"",
		[]int32{42},
		[]string{"2001:db8:42::47"},
		"test-node",
	},
	{
		"683c333d-a594-4f00-baa6-0d578a13d222",
		"testns",
		"service4",
		"2001:1db8:42::8664",
		[]string{"2001:1db8:42::8664", "10.6.50.131"},
		"",
		[]int32{42},
		[]string{"2001:db8:42::47", "10.1.1.1"},
		"test-node",
	},
}

func (agent *testHostAgent) checkAs(t *testing.T, st *serviceTest,
	as *opflexService, desc string) {
	assert.Equal(t, agent.config.AciVrfTenant, as.DomainPolicySpace,
		desc, st.name, "policy-space")
	assert.Equal(t, agent.config.AciVrf, as.DomainName,
		desc, st.name, "domain")
	assert.Equal(t, "loadbalancer", as.ServiceMode,
		desc, st.name, "domain")
	if assert.Equal(t, 1, len(as.ServiceMappings), desc, "service-mappings") {
		sm := &as.ServiceMappings[0]
		assert.Equal(t, st.nextHopIps, sm.NextHopIps, desc, "next-hop")
		assert.Equal(t, st.ports[0], int32(sm.NextHopPort), desc, "next-hop-port")
		assert.Equal(t, st.ports[0], int32(sm.ServicePort), desc, "service-port")
		assert.Equal(t, int32(10000),
			sm.SessionAffinity.ClientIP.TimeoutSeconds, desc, "sessionAffinity")
	}
}

func (agent *testHostAgent) doTestService(t *testing.T, tempdir string,
	st *serviceTest, desc string) {
	var raw []byte

	as := &opflexService{}
	asexternal := &opflexService{}

	tu.WaitFor(t, st.name, 1000*time.Millisecond,
		func(last bool) (bool, error) {
			var err error
			{
				asfile := filepath.Join(tempdir, st.uuid+".service")
				raw, err = os.ReadFile(asfile)
				if !tu.WaitNil(t, last, err, desc, st.name, "read service") {
					return false, nil
				}
				err = json.Unmarshal(raw, as)
				if !tu.WaitNil(t, last, err, desc, st.name, "unmarshal service") {
					return false, nil
				}
			}

			if st.externalIp != "" {
				asfile := filepath.Join(tempdir, st.uuid+"-external.service")
				raw, err = os.ReadFile(asfile)
				if !tu.WaitNil(t, last, err, desc, st.name, "read service") {
					return false, nil
				}
				err = json.Unmarshal(raw, asexternal)
				if !tu.WaitNil(t, last, err, desc, st.name, "unmarshal service") {
					return false, nil
				}
			}

			return true, nil
		})

	assert.Equal(t, st.uuid, as.Uuid, desc, st.name, "uuid")
	agent.checkAs(t, st, as, desc)

	if st.externalIp != "" {
		assert.Equal(t, st.uuid+"-external", asexternal.Uuid,
			desc, st.name, "uuid-external")
		agent.checkAs(t, st, asexternal, desc)

		assert.Equal(t, agent.config.UplinkMacAdress, asexternal.ServiceMac,
			desc, st.name, "service-mac")
		assert.Equal(t, "10.6.0.1", asexternal.InterfaceIp,
			desc, st.name, "service-ip")
	}
}

func TestServiceSync(t *testing.T) {
	tempdir, err := os.MkdirTemp("", "hostagent_test_")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tempdir)

	agent := testAgent()
	agent.config.NodeName = "test-node"
	agent.config.OpFlexEndpointDir = tempdir
	agent.config.OpFlexServiceDir = tempdir
	agent.config.OpFlexSnatDir = tempdir
	agent.config.OpFlexNetPolDir = tempdir
	agent.config.UplinkIface = "eth42"
	agent.config.UplinkMacAdress = "76:47:db:97:ba:4c"
	agent.config.ServiceVlan = 4003
	agent.config.AciVrf = "kubernetes-vrf"
	agent.config.AciVrfTenant = "common"

	node := &v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-node",
			Annotations: map[string]string{
				metadata.ServiceEpAnnotation: "{\"mac\": \"76:47:db:97:ba:4c\", \"ipv4\": \"10.6.0.1\"}",
			},
		},
	}
	agent.fakeNodeSource.Add(node)

	agent.run()

	for i, st := range serviceTests {
		if i%2 == 0 {
			os.WriteFile(filepath.Join(tempdir, st.uuid+".service"),
				[]byte("random gibberish"), 0644)
			os.WriteFile(filepath.Join(tempdir, st.uuid+"-external.service"),
				[]byte("random gibberish"), 0644)
		}
		service := service(st.uuid, st.namespace, st.name,
			st.clusterIp, st.externalIp, st.ports)
		epSlice := endpointslice(st.namespace, st.name, st.nextHopIps, st.ports, "test-node")
		agent.fakeServiceSource.Add(service)
		agent.fakeEndpointSliceSource.Add(epSlice)
		agent.doTestService(t, tempdir, &serviceTests[i], "create")
	}

	for _, st := range serviceTests {
		service := service(st.uuid, st.namespace, st.name,
			st.clusterIp, st.externalIp, st.ports)
		agent.fakeServiceSource.Delete(service)

		tu.WaitFor(t, st.name, 1000*time.Millisecond,
			func(last bool) (bool, error) {
				r := true
				{
					asfile := filepath.Join(tempdir, st.uuid+".service")
					_, err := os.ReadFile(asfile)
					if !tu.WaitNotNil(t, last, err, "read service") {
						r = false
					}
				}

				{
					asfile := filepath.Join(tempdir, st.uuid+"-external.service")
					_, err := os.ReadFile(asfile)
					if !tu.WaitNotNil(t, last, err, "read external service") {
						r = false
					}
				}

				return r, nil
			})
	}

	agent.stop()
}

// Test Service with endpointslice
func TestServiceSyncWithEps(t *testing.T) {
	tempdir, err := os.MkdirTemp("", "hostagent_test_")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tempdir)

	agent := testAgent()
	agent.config.NodeName = "test-node"
	agent.config.OpFlexEndpointDir = tempdir
	agent.config.OpFlexServiceDir = tempdir
	agent.config.OpFlexSnatDir = tempdir
	agent.config.UplinkIface = "eth42"
	agent.config.UplinkMacAdress = "76:47:db:97:ba:4c"
	agent.config.ServiceVlan = 4003
	agent.config.AciVrf = "kubernetes-vrf"
	agent.config.AciVrfTenant = "common"
	agent.serviceEndPoints = &serviceEndpointSlice{}
	agent.serviceEndPoints.(*serviceEndpointSlice).agent = agent.HostAgent

	node := &v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-node",
			Annotations: map[string]string{
				metadata.ServiceEpAnnotation: "{\"mac\": \"76:47:db:97:ba:4c\", \"ipv4\": \"10.6.0.1\"}",
			},
		},
	}
	agent.fakeNodeSource.Add(node)

	agent.run()
	for i, st := range serviceTests {
		if i%2 == 0 {
			os.WriteFile(filepath.Join(tempdir, st.uuid+".service"),
				[]byte("random gibberish"), 0644)
			os.WriteFile(filepath.Join(tempdir, st.uuid+"-external.service"),
				[]byte("random gibberish"), 0644)
		}
		service := service(st.uuid, st.namespace, st.name,
			st.clusterIp, st.externalIp, st.ports)
		endpoints := endpointslice(st.namespace, st.name, st.nextHopIps, st.ports, "test-node")
		agent.fakeServiceSource.Add(service)
		agent.fakeEndpointSliceSource.Add(endpoints)
		agent.doTestService(t, tempdir, &serviceTests[i], "create")
	}

	for _, st := range serviceTests {
		service := service(st.uuid, st.namespace, st.name,
			st.clusterIp, st.externalIp, st.ports)
		agent.fakeServiceSource.Delete(service)

		tu.WaitFor(t, st.name, 1000*time.Millisecond,
			func(last bool) (bool, error) {
				r := true
				{
					asfile := filepath.Join(tempdir, st.uuid+".service")
					_, err := os.ReadFile(asfile)
					if !tu.WaitNotNil(t, last, err, "read service") {
						r = false
					}
				}

				{
					asfile := filepath.Join(tempdir, st.uuid+"-external.service")
					_, err := os.ReadFile(asfile)
					if !tu.WaitNotNil(t, last, err, "read external service") {
						r = false
					}
				}

				return r, nil
			})
	}

	agent.stop()
}

// TopoKeys testing.
func TestServiceWithTopoKeys(t *testing.T) {
	tempdir, err := os.MkdirTemp("", "hostagent_test_")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tempdir)

	agent := testAgent()
	agent.config.NodeName = "test-node"
	agent.config.OpFlexEndpointDir = tempdir
	agent.config.OpFlexServiceDir = tempdir
	agent.config.OpFlexSnatDir = tempdir
	agent.config.UplinkIface = "eth42"
	agent.config.UplinkMacAdress = "76:47:db:97:ba:4c"
	agent.config.ServiceVlan = 4003
	agent.config.AciVrf = "kubernetes-vrf"
	agent.config.AciVrfTenant = "common"
	agent.serviceEndPoints = &serviceEndpointSlice{}
	agent.serviceEndPoints.(*serviceEndpointSlice).agent = agent.HostAgent

	node := &v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-node",
			Annotations: map[string]string{
				metadata.ServiceEpAnnotation: "{\"mac\": \"76:47:db:97:ba:4c\", \"ipv4\": \"10.6.0.1\"}",
			},
			Labels: map[string]string{
				v1.LabelHostname:       "test-node",
				v1.LabelTopologyZone:   "fabric1-pod-1",
				v1.LabelTopologyRegion: "fabric1",
			},
		},
	}
	agent.fakeNodeSource.Add(node)

	agent.run()
	for i, st := range serviceTests {
		if i%2 == 0 {
			os.WriteFile(filepath.Join(tempdir, st.uuid+".service"),
				[]byte("random gibberish"), 0644)
			os.WriteFile(filepath.Join(tempdir, st.uuid+"-external.service"),
				[]byte("random gibberish"), 0644)
		}
		service := service(st.uuid, st.namespace, st.name,
			st.clusterIp, st.externalIp, st.ports)
		service.ObjectMeta.Annotations[v1.AnnotationTopologyMode] = "Auto"
		endpoints := endpointslice(st.namespace, st.name, st.nextHopIps, st.ports, agent.config.NodeName)
		for i := range endpoints.Endpoints {
			hintForZone := discovery.ForZone{Name: "fabric1-pod-1"}
			hints := discovery.EndpointHints{ForZones: []discovery.ForZone{hintForZone}}
			endpoints.Endpoints[i].Hints = &hints
		}
		agent.fakeServiceSource.Add(service)
		agent.fakeEndpointSliceSource.Add(endpoints)
		agent.doTestService(t, tempdir, &serviceTests[i], "create")
	}

	for _, st := range serviceTests {
		service := service(st.uuid, st.namespace, st.name,
			st.clusterIp, st.externalIp, st.ports)
		agent.fakeServiceSource.Delete(service)

		tu.WaitFor(t, st.name, 700*time.Millisecond,
			func(last bool) (bool, error) {
				r := true
				{
					asfile := filepath.Join(tempdir, st.uuid+".service")
					_, err := os.ReadFile(asfile)
					if !tu.WaitNotNil(t, last, err, "read service") {
						r = false
					}
				}

				{
					asfile := filepath.Join(tempdir, st.uuid+"-external.service")
					_, err := os.ReadFile(asfile)
					if !tu.WaitNotNil(t, last, err, "read external service") {
						r = false
					}
				}

				return r, nil
			})
	}

	agent.stop()
}

// 1. Create Pod with 10.1.1.1
// 2. Create Endpoint with 10.1.1.1
// 3. Create Service with clusterIp 100.1.1.1
// 4. Check ServiceIp's updated properly for the Pod created
// 5. Delete the Service Make sure that cleanup happend
func TestServiceEptoSerMap(t *testing.T) {
	tempdir, err := os.MkdirTemp("", "hostagent_test_")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tempdir)

	agent := testAgent()
	agent.config.NodeName = "test-node"
	agent.config.OpFlexEndpointDir = tempdir
	agent.config.OpFlexServiceDir = tempdir
	agent.config.OpFlexSnatDir = tempdir
	agent.config.UplinkIface = "eth42"
	agent.config.UplinkMacAdress = "76:47:db:97:ba:4c"
	agent.config.ServiceVlan = 4003
	agent.config.AciVrf = "kubernetes-vrf"
	agent.config.AciVrfTenant = "common"

	node := &v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-node",
			Annotations: map[string]string{
				metadata.ServiceEpAnnotation: "{\"mac\": \"76:47:db:97:ba:4c\", \"ipv4\": \"10.6.0.1\"}",
			},
		},
	}
	agent.fakeNodeSource.Add(node)
	agent.run()
	pod := mkPod("poduid", "testns", "pod1", "", "", map[string]string{"app": "tier"})
	cnimd := cnimd("testns", "pod1", "10.1.1.1", "cont1", "veth1")
	cnimd.Ifaces[0].Mac = "00:0c:29:92:fe:d0"
	agent.epMetadata["testns"+"/"+"pod1"] =
		map[string]*metadata.ContainerMetadata{
			cnimd.Id.ContId: cnimd,
		}
	pod.Status.PodIP = "10.1.1.1"
	agent.fakePodSource.Add(pod)
	time.Sleep(10 * time.Millisecond)
	st := serviceTests[0]
	service := service(st.uuid, st.namespace, st.name,
		st.clusterIp, st.externalIp, st.ports)
	service.Spec.Selector = map[string]string{"app": "tier"}
	epSlice := endpointslice(st.namespace, st.name, st.nextHopIps, st.ports, "test-node")
	agent.fakeServiceSource.Add(service)
	agent.fakeEndpointSliceSource.Add(epSlice)
	time.Sleep(10 * time.Millisecond)
	clusterIp := agent.getServiceIPs("poduid")
	assert.Equal(t, clusterIp, []string{"100.1.1.1"}, "Updated", "ClusterIp")
	agent.fakeServiceSource.Delete(service)
	time.Sleep(10 * time.Millisecond)
	clusterIp = agent.getServiceIPs("poduid")
	var empty []string
	assert.Equal(t, clusterIp, empty, "deleted", "ClusterIp")
	agent.stop()
}

// 1. Create Pod with 2001:db8:42::47
// 2. Create Endpoint with 2001:db8:42::47
// 3. Create Service with clusterIp 2001:1db8:42::8664
// 4. Check ServiceIp's updated properly for the Pod created
// 5. Delete the Service Make sure that cleanup happend
func TestSingleStackIPv6ServiceEptoSerMap(t *testing.T) {
	tempdir, err := os.MkdirTemp("", "hostagent_test_")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tempdir)

	agent := testAgent()
	agent.config.NodeName = "test-node"
	agent.config.OpFlexEndpointDir = tempdir
	agent.config.OpFlexServiceDir = tempdir
	agent.config.OpFlexSnatDir = tempdir
	agent.config.UplinkIface = "eth42"
	agent.config.UplinkMacAdress = "76:47:db:97:ba:4c"
	agent.config.ServiceVlan = 4003
	agent.config.AciVrf = "kubernetes-vrf"
	agent.config.AciVrfTenant = "common"

	node := &v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-node",
			Annotations: map[string]string{
				metadata.ServiceEpAnnotation: "{\"mac\": \"76:47:db:97:ba:4c\", \"ipv4\": \"10.6.0.1\", \"ipv6\": \"2001:2db8:42::0001\"}",
			},
		},
	}
	agent.fakeNodeSource.Add(node)
	agent.run()
	pod := mkPod("poduid", "testns", "pod1", "", "", map[string]string{"app": "tier"})
	cnimd := cnimd("testns", "pod1", "2001:db8:42::47", "cont1", "veth1")
	cnimd.Ifaces[0].Mac = "00:0c:29:92:fe:d0"
	agent.epMetadata["testns"+"/"+"pod1"] =
		map[string]*metadata.ContainerMetadata{
			cnimd.Id.ContId: cnimd,
		}
	pod.Status.PodIP = "2001:db8:42::47"
	agent.fakePodSource.Add(pod)
	time.Sleep(10 * time.Millisecond)
	st := serviceTests[2]
	service := service(st.uuid, st.namespace, st.name,
		st.clusterIp, st.externalIp, st.ports)
	service.Spec.Selector = map[string]string{"app": "tier"}
	epSlice := endpointslice(st.namespace, st.name, st.nextHopIps, st.ports, "test-node")
	agent.fakeServiceSource.Add(service)
	agent.fakeEndpointSliceSource.Add(epSlice)
	time.Sleep(10 * time.Millisecond)
	clusterIp := agent.getServiceIPs("poduid")
	assert.Equal(t, clusterIp, []string{"2001:1db8:42::8664"}, "Updated", "ClusterIp")
	agent.fakeServiceSource.Delete(service)
	time.Sleep(10 * time.Millisecond)
	clusterIp = agent.getServiceIPs("poduid")
	var empty []string
	assert.Equal(t, clusterIp, empty, "deleted", "ClusterIp")
	agent.stop()
}

// 1. Create Pod with 10.1.1.1, 2001:db8:42::47
// 2. Create Endpoint with 10.1.1.1, 2001:db8:42::47
// 3. Create Service with clusterIp 10.6.50.131, 2001:1db8:42::8664
// 4. Check ServiceIp's updated properly for the Pod created
// 5. Delete the Service Make sure that cleanup happend
func TestDualStackServiceEptoSerMap(t *testing.T) {
	tempdir, err := os.MkdirTemp("", "hostagent_test_")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tempdir)

	agent := testAgent()
	agent.config.NodeName = "test-node"
	agent.config.OpFlexEndpointDir = tempdir
	agent.config.OpFlexServiceDir = tempdir
	agent.config.OpFlexSnatDir = tempdir
	agent.config.UplinkIface = "eth42"
	agent.config.UplinkMacAdress = "76:47:db:97:ba:4c"
	agent.config.ServiceVlan = 4003
	agent.config.AciVrf = "kubernetes-vrf"
	agent.config.AciVrfTenant = "common"

	node := &v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-node",
			Annotations: map[string]string{
				metadata.ServiceEpAnnotation: "{\"mac\": \"76:47:db:97:ba:4c\", \"ipv4\": \"10.6.0.1\", \"ipv6\": \"2001:2db8:42::0001\"}",
			},
		},
	}
	agent.fakeNodeSource.Add(node)
	agent.run()
	pod := mkPod("poduid", "testns", "pod1", "", "", map[string]string{"app": "tier"})
	cnimd := cnimd("testns", "pod1", "2001:db8:42::47", "cont1", "veth1")
	cnimd.Ifaces[0].Mac = "00:0c:29:92:fe:d0"
	agent.epMetadata["testns"+"/"+"pod1"] =
		map[string]*metadata.ContainerMetadata{
			cnimd.Id.ContId: cnimd,
		}
	pod.Status.PodIP = "2001:db8:42::47"
	podIPv4 := v1.PodIP{IP: "10.1.1.1"}
	podIPv6 := v1.PodIP{IP: "2001:db8:42::47"}
	pod.Status.PodIPs = []v1.PodIP{podIPv6, podIPv4}
	agent.fakePodSource.Add(pod)
	time.Sleep(10 * time.Millisecond)
	st := serviceTests[3]
	service := service(st.uuid, st.namespace, st.name,
		st.clusterIp, st.externalIp, st.ports)
	service.Spec.Selector = map[string]string{"app": "tier"}
	epSlice := endpointslice(st.namespace, st.name, st.nextHopIps, st.ports, "test-node")
	agent.fakeServiceSource.Add(service)
	agent.fakeEndpointSliceSource.Add(epSlice)
	time.Sleep(10 * time.Millisecond)
	clusterIp := agent.getServiceIPs("poduid")
	assert.Equal(t, clusterIp, []string{"2001:1db8:42::8664"}, "Updated", "ClusterIp")
	agent.fakeServiceSource.Delete(service)
	time.Sleep(10 * time.Millisecond)
	clusterIp = agent.getServiceIPs("poduid")
	var empty []string
	assert.Equal(t, clusterIp, empty, "deleted", "ClusterIp")
	agent.stop()
}

// endpointsliceWithRawPorts is a variant of endpointslice() that lets the
// caller supply the raw discovery.EndpointPort slice. Needed for the
// nil-port regression test where at least one port has a nil Port pointer,
// which cannot be expressed through the []int32 signature of endpointslice().
func endpointsliceWithRawPorts(namespace, name string, nextHopIps []string,
	ports []discovery.EndpointPort, nodename string) *discovery.EndpointSlice {
	e := endpointslice(namespace, name, nextHopIps, nil, nodename)
	e.Ports = ports
	return e
}

// TestServiceEndpointSliceNilPort is a regression test for the nil
// EndpointSlice port crash in the host agent.
//
// discovery/v1 permits EndpointPort.Port to be nil. Before the fix, the host
// agent unconditionally dereferenced *p.Port in
// serviceEndpointSlice.SetOpflexService, causing every host agent watching
// the slice to panic. This test drives the reconciler with three scenarios:
//
//  1. Nil-only port  – slice's sole port has Port == nil. The reconciler
//     must not panic and must not write a .service file (no valid mapping
//     can be produced, so hasValidMapping stays false).
//  2. Correction     – the same slice is updated to carry a numeric port.
//     A normal .service file must appear with the correct next-hop-port
//     and backend IPs.
//  3. Mixed ports    – a separate service's slice carries both a nil-port
//     entry and a valid entry. Exactly one mapping must be produced, using
//     the valid port; the nil entry must be silently skipped.
func TestServiceEndpointSliceNilPort(t *testing.T) {
	tempdir, err := os.MkdirTemp("", "hostagent_test_")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tempdir)

	agent := testAgent()
	agent.config.NodeName = "test-node"
	agent.config.OpFlexEndpointDir = tempdir
	agent.config.OpFlexServiceDir = tempdir
	agent.config.OpFlexSnatDir = tempdir
	agent.config.UplinkIface = "eth42"
	agent.config.UplinkMacAdress = "76:47:db:97:ba:4c"
	agent.config.ServiceVlan = 4003
	agent.config.AciVrf = "kubernetes-vrf"
	agent.config.AciVrfTenant = "common"
	agent.serviceEndPoints = &serviceEndpointSlice{}
	agent.serviceEndPoints.(*serviceEndpointSlice).agent = agent.HostAgent

	node := &v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-node",
			Annotations: map[string]string{
				metadata.ServiceEpAnnotation: "{\"mac\": \"76:47:db:97:ba:4c\", \"ipv4\": \"10.6.0.1\"}",
			},
		},
	}
	agent.fakeNodeSource.Add(node)
	agent.run()
	defer agent.stop()

	tcpProto := func() *v1.Protocol { p := v1.ProtocolTCP; return &p }
	int32Ptr := func(v int32) *int32 { return &v }

	// ---- Scenario 1: nil-only port ----
	// Use serviceTests[1] (no external IP) so we only have to reason about
	// the base .service file.
	st := serviceTests[1]
	svc := service(st.uuid, st.namespace, st.name,
		st.clusterIp, st.externalIp, st.ports)

	nilOnlyPorts := []discovery.EndpointPort{
		{
			// Port intentionally nil.
			Protocol: tcpProto(),
		},
	}
	slice := endpointsliceWithRawPorts(st.namespace, st.name, st.nextHopIps,
		nilOnlyPorts, "test-node")

	agent.fakeServiceSource.Add(svc)
	agent.fakeEndpointSliceSource.Add(slice)

	asfile := filepath.Join(tempdir, st.uuid+".service")
	extfile := filepath.Join(tempdir, st.uuid+"-external.service")

	// Give the informer + reconciler a chance to process the event, then
	// confirm no .service file was ever written for the nil-only slice.
	// If the old bug were present, the test process would panic before
	// reaching this point.
	time.Sleep(200 * time.Millisecond)
	if _, statErr := os.Stat(asfile); statErr == nil {
		raw, _ := os.ReadFile(asfile)
		t.Fatalf("nil-only port slice must not produce a .service file; got %s", string(raw))
	}
	if _, statErr := os.Stat(extfile); statErr == nil {
		t.Fatalf("nil-only port slice must not produce an -external.service file")
	}

	// ---- Scenario 2: correction path ----
	// Same slice, now with a real port. A normal mapping must appear.
	correctedPorts := []discovery.EndpointPort{
		{
			Port:     int32Ptr(st.ports[0]),
			Protocol: tcpProto(),
		},
	}
	corrected := endpointsliceWithRawPorts(st.namespace, st.name, st.nextHopIps,
		correctedPorts, "test-node")
	// Preserve the slice's identity so the fake source treats this as an
	// Update rather than an Add.
	corrected.ObjectMeta = slice.ObjectMeta
	agent.fakeEndpointSliceSource.Modify(corrected)

	agent.doTestService(t, tempdir, &serviceTests[1], "corrected-from-nil-port")

	// ---- Scenario 3: mixed nil + valid port on a fresh service ----
	stMixed := serviceTest{
		uuid:       "9c7c9c00-0000-0000-0000-000000000001",
		namespace:  "testns",
		name:       "service-mixed",
		clusterIp:  "100.1.1.99",
		clusterIPs: []string{},
		externalIp: "",
		ports:      []int32{8080},
		nextHopIps: []string{"10.7.1.1"},
		nodename:   "test-node",
	}
	svcMixed := service(stMixed.uuid, stMixed.namespace, stMixed.name,
		stMixed.clusterIp, stMixed.externalIp, stMixed.ports)
	mixedPorts := []discovery.EndpointPort{
		{
			// Nil port; must be skipped.
			Protocol: tcpProto(),
		},
		{
			// Valid port; must be the single mapping produced.
			Port:     int32Ptr(stMixed.ports[0]),
			Protocol: tcpProto(),
		},
	}
	mixedSlice := endpointsliceWithRawPorts(stMixed.namespace, stMixed.name,
		stMixed.nextHopIps, mixedPorts, "test-node")

	agent.fakeServiceSource.Add(svcMixed)
	agent.fakeEndpointSliceSource.Add(mixedSlice)

	agent.doTestService(t, tempdir, &stMixed, "mixed-nil-and-valid-port")

	// Extra invariant across every file written by this test: no mapping may
	// ever carry next-hop-port = 0, which is what the buggy code would have
	// produced by dereferencing a nil *int32.
	files, ferr := os.ReadDir(tempdir)
	if ferr != nil {
		t.Fatalf("readdir tempdir: %v", ferr)
	}
	for _, f := range files {
		if !strings.HasSuffix(f.Name(), ".service") {
			continue
		}
		raw, rerr := os.ReadFile(filepath.Join(tempdir, f.Name()))
		if rerr != nil {
			t.Fatalf("read %s: %v", f.Name(), rerr)
		}
		var written opflexService
		if jerr := json.Unmarshal(raw, &written); jerr != nil {
			t.Fatalf("unmarshal %s: %v", f.Name(), jerr)
		}
		for i, sm := range written.ServiceMappings {
			if sm.NextHopPort == 0 {
				t.Errorf("%s mapping[%d] has next-hop-port=0 (nil-port regression)",
					f.Name(), i)
			}
		}
	}
}

// TestEndpointReadyHelper covers the endpointReady() helper directly so the
// nil-safe semantics are locked down at the unit level.
func TestEndpointReadyHelper(t *testing.T) {
	trueVal := true
	falseVal := false

	cases := []struct {
		name string
		ep   discovery.Endpoint
		want bool
	}{
		{
			name: "nil Ready is ready (discovery/v1 default)",
			ep:   discovery.Endpoint{},
			want: true,
		},
		{
			name: "explicit true is ready",
			ep:   discovery.Endpoint{Conditions: discovery.EndpointConditions{Ready: &trueVal}},
			want: true,
		},
		{
			name: "explicit false is not ready",
			ep:   discovery.Endpoint{Conditions: discovery.EndpointConditions{Ready: &falseVal}},
			want: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, endpointReady(c.ep))
		})
	}
}

// endpointsliceWithRawEndpoints is a variant of endpointslice() that lets the
// caller supply the raw discovery.Endpoint slice. Needed for the nil-Ready
// regression test where at least one endpoint has Conditions.Ready == nil,
// which cannot be expressed through the []string signature of endpointslice().
func endpointsliceWithRawEndpoints(namespace, name string,
	endpoints []discovery.Endpoint, ports []int32) *discovery.EndpointSlice {
	e := endpointslice(namespace, name, nil, ports, "test-node")
	e.Endpoints = endpoints
	return e
}

// TestServiceEndpointSliceNilReady is a regression test for the nil
// EndpointSlice Ready-condition crash in the host agent.
//
// discovery/v1 defines Endpoint.Conditions.Ready as *bool with the semantic
// that nil means "unspecified — must be treated as ready". Before the fix,
// serviceEndpointSlice.SetOpflexService dereferenced *e.Conditions.Ready
// unconditionally in both the topology-aware-hints branch and the normal
// branch, so any valid selectorless slice omitting conditions.ready crashed
// every host agent watching it.
//
// This test drives the reconciler with two shapes on both code branches:
//
//  1. Normal branch, mixed nil / explicit-true / explicit-false endpoints:
//     the .service file must contain both ready IPs (nil-Ready one and
//     explicit-true one) and must NOT contain the explicit-false IP.
//  2. Topology-aware-hints branch with a nil-Ready endpoint that has a
//     matching zone hint: the .service file must contain that endpoint's
//     IP; the reconciler must not panic.
func TestServiceEndpointSliceNilReady(t *testing.T) {
	tempdir, err := os.MkdirTemp("", "hostagent_test_")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tempdir)

	agent := testAgent()
	agent.config.NodeName = "test-node"
	agent.config.OpFlexEndpointDir = tempdir
	agent.config.OpFlexServiceDir = tempdir
	agent.config.OpFlexSnatDir = tempdir
	agent.config.UplinkIface = "eth42"
	agent.config.UplinkMacAdress = "76:47:db:97:ba:4c"
	agent.config.ServiceVlan = 4003
	agent.config.AciVrf = "kubernetes-vrf"
	agent.config.AciVrfTenant = "common"
	agent.serviceEndPoints = &serviceEndpointSlice{}
	agent.serviceEndPoints.(*serviceEndpointSlice).agent = agent.HostAgent

	node := &v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-node",
			Annotations: map[string]string{
				metadata.ServiceEpAnnotation: "{\"mac\": \"76:47:db:97:ba:4c\", \"ipv4\": \"10.6.0.1\"}",
			},
			Labels: map[string]string{
				v1.LabelHostname:       "test-node",
				v1.LabelTopologyZone:   "fabric1-pod-1",
				v1.LabelTopologyRegion: "fabric1",
			},
		},
	}
	agent.fakeNodeSource.Add(node)
	agent.run()
	defer agent.stop()

	nodeName := "test-node"
	trueVal := true
	falseVal := false

	// ---- Scenario 1: normal branch (no topology hints) ----
	st := serviceTests[1]
	svc := service(st.uuid, st.namespace, st.name,
		st.clusterIp, st.externalIp, st.ports)

	// Three endpoints: nil Ready (implicit true), explicit true, explicit
	// false. The .service file must include the first two and exclude the
	// third.
	mixedEndpoints := []discovery.Endpoint{
		{
			Addresses:  []string{"10.5.1.1"},
			NodeName:   &nodeName,
			Conditions: discovery.EndpointConditions{}, // Ready == nil
		},
		{
			Addresses:  []string{"10.5.1.2"},
			NodeName:   &nodeName,
			Conditions: discovery.EndpointConditions{Ready: &trueVal},
		},
		{
			Addresses:  []string{"10.5.1.3"},
			NodeName:   &nodeName,
			Conditions: discovery.EndpointConditions{Ready: &falseVal},
		},
	}
	slice := endpointsliceWithRawEndpoints(st.namespace, st.name,
		mixedEndpoints, st.ports)

	agent.fakeServiceSource.Add(svc)
	agent.fakeEndpointSliceSource.Add(slice)

	// Wait for the .service file to be rendered and read it back.
	asfile := filepath.Join(tempdir, st.uuid+".service")
	var as opflexService
	tu.WaitFor(t, "nil-ready-normal", 1000*time.Millisecond,
		func(last bool) (bool, error) {
			raw, rerr := os.ReadFile(asfile)
			if !tu.WaitNil(t, last, rerr, "read service") {
				return false, nil
			}
			as = opflexService{}
			jerr := json.Unmarshal(raw, &as)
			if !tu.WaitNil(t, last, jerr, "unmarshal service") {
				return false, nil
			}
			if len(as.ServiceMappings) == 0 {
				return false, nil
			}
			return true, nil
		})

	if assert.Equal(t, 1, len(as.ServiceMappings), "one mapping expected") {
		got := as.ServiceMappings[0].NextHopIps
		assert.ElementsMatch(t, []string{"10.5.1.1", "10.5.1.2"}, got,
			"nil-Ready and explicit-true endpoints must be included; explicit-false must be excluded")
	}

	// ---- Scenario 2: topology-aware-hints branch, nil Ready ----
	stHints := serviceTest{
		uuid:       "8b6d5a00-0000-0000-0000-000000000002",
		namespace:  "testns",
		name:       "service-hints",
		clusterIp:  "100.1.1.77",
		clusterIPs: []string{},
		externalIp: "",
		ports:      []int32{7070},
		nextHopIps: []string{"10.9.1.1"},
		nodename:   "test-node",
	}
	svcHints := service(stHints.uuid, stHints.namespace, stHints.name,
		stHints.clusterIp, stHints.externalIp, stHints.ports)
	// Enable topology-aware routing so the reconciler enters the hinted
	// branch (the pre-fix dereference site).
	svcHints.ObjectMeta.Annotations[v1.AnnotationTopologyMode] = "Auto"

	hintZone := discovery.EndpointHints{
		ForZones: []discovery.ForZone{{Name: "fabric1-pod-1"}},
	}
	hintEndpoints := []discovery.Endpoint{
		{
			Addresses:  []string{"10.9.1.1"},
			NodeName:   &nodeName,
			Conditions: discovery.EndpointConditions{}, // Ready == nil
			Hints:      &hintZone,
		},
	}
	hintSlice := endpointsliceWithRawEndpoints(stHints.namespace, stHints.name,
		hintEndpoints, stHints.ports)

	agent.fakeServiceSource.Add(svcHints)
	agent.fakeEndpointSliceSource.Add(hintSlice)

	// doTestService validates uuid, service-port, next-hop-port, and that
	// the mapping contains exactly stHints.nextHopIps. That's precisely the
	// nil-Ready-in-hinted-branch case.
	agent.doTestService(t, tempdir, &stHints, "nil-ready-topology-hints")
}
