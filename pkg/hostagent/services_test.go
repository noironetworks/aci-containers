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
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apitypes "k8s.io/apimachinery/pkg/types"

	"github.com/noironetworks/aci-containers/pkg/metadata"
	tu "github.com/noironetworks/aci-containers/pkg/testutil"
)

func service(uuid string, namespace string, name string,
	clusterIp string, externalIp string, ports []int32) *v1.Service {
	s := &v1.Service{
		Spec: v1.ServiceSpec{
			ClusterIP: clusterIp,
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

func endpoints(namespace string, name string,
	nextHopIps []string, ports []int32) *v1.Endpoints {
	e := &v1.Endpoints{
		Subsets: []v1.EndpointSubset{{}},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
		},
	}

	nn := "test-node"
	for _, ip := range nextHopIps {
		e.Subsets[0].Addresses =
			append(e.Subsets[0].Addresses, v1.EndpointAddress{
				IP:       ip,
				NodeName: &nn,
			})
	}

	for _, port := range ports {
		e.Subsets[0].Ports =
			append(e.Subsets[0].Ports, v1.EndpointPort{
				Port:     port,
				Protocol: "TCP",
			})
	}

	return e
}

type serviceTest struct {
	uuid       string
	namespace  string
	name       string
	clusterIp  string
	externalIp string
	ports      []int32
	nextHopIps []string
}

var serviceTests = []serviceTest{
	{
		"e93abb02-3ffd-41e8-8f3e-7d65b7f970c0",
		"testns",
		"service1",
		"100.1.1.1",
		"200.1.1.1",
		[]int32{80},
		[]string{"10.1.1.1", "10.2.2.2"},
	},
	{
		"683c333d-a594-4f00-baa6-0d578a13d83f",
		"testns",
		"service2",
		"100.1.1.2",
		"",
		[]int32{42},
		[]string{"10.5.1.1", "10.6.2.2"},
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
	}
}

func (agent *testHostAgent) doTestService(t *testing.T, tempdir string,
	st *serviceTest, desc string) {
	var raw []byte

	as := &opflexService{}
	asexternal := &opflexService{}

	tu.WaitFor(t, st.name, 100*time.Millisecond,
		func(last bool) (bool, error) {
			var err error
			{
				asfile := filepath.Join(tempdir, st.uuid+".service")
				raw, err = ioutil.ReadFile(asfile)
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
				raw, err = ioutil.ReadFile(asfile)
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
	tempdir, err := ioutil.TempDir("", "hostagent_test_")
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

	for i, st := range serviceTests {
		if i%2 == 0 {
			ioutil.WriteFile(filepath.Join(tempdir, st.uuid+".service"),
				[]byte("random gibberish"), 0644)
			ioutil.WriteFile(filepath.Join(tempdir, st.uuid+"-external.service"),
				[]byte("random gibberish"), 0644)
		}

		service := service(st.uuid, st.namespace, st.name,
			st.clusterIp, st.externalIp, st.ports)
		endpoints := endpoints(st.namespace, st.name, st.nextHopIps, st.ports)
		agent.fakeServiceSource.Add(service)
		agent.fakeEndpointsSource.Add(endpoints)
		agent.doTestService(t, tempdir, &st, "create")
	}

	for _, st := range serviceTests {
		service := service(st.uuid, st.namespace, st.name,
			st.clusterIp, st.externalIp, st.ports)
		agent.fakeServiceSource.Delete(service)

		tu.WaitFor(t, st.name, 100*time.Millisecond,
			func(last bool) (bool, error) {
				r := true
				{
					asfile := filepath.Join(tempdir, st.uuid+".service")
					_, err := ioutil.ReadFile(asfile)
					if !tu.WaitNotNil(t, last, err, "read service") {
						r = false
					}
				}

				{
					asfile := filepath.Join(tempdir, st.uuid+"-external.service")
					_, err := ioutil.ReadFile(asfile)
					if !tu.WaitNotNil(t, last, err, "read external service") {
						r = false
					}
				}

				return r, nil
			})
	}

	agent.stop()
}
