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

package controller

import (
	"testing"
	"time"

	"github.com/noironetworks/aci-containers/pkg/apicapi"
	nodeinfo "github.com/noironetworks/aci-containers/pkg/nodeinfo/apis/aci.snat/v1"
	snatglobalinfo "github.com/noironetworks/aci-containers/pkg/snatglobalinfo/apis/aci.snat/v1"
	snatpolicy "github.com/noironetworks/aci-containers/pkg/snatpolicy/apis/aci.snat/v1"
	tu "github.com/noironetworks/aci-containers/pkg/testutil"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

const globalInfoSyncWaitTime = 5 // seconds

func snatpolicydata(name string, namespace string,
	snatIp []string, labels map[string]string) *snatpolicy.SnatPolicy {
	policy := &snatpolicy.SnatPolicy{
		Spec: snatpolicy.SnatPolicySpec{
			SnatIp: snatIp,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Status: snatpolicy.SnatPolicyStatus{
			State: snatpolicy.Ready,
		},
	}
	var podSelector snatpolicy.PodSelector
	podSelector.Namespace = namespace
	podSelector.Labels = labels
	policy.Spec.Selector = podSelector
	return policy
}

func Nodeinfodata(name, namespace, macaddr string, snatplcy map[string]bool) *nodeinfo.NodeInfo {
	info := &nodeinfo.NodeInfo{
		Spec: nodeinfo.NodeInfoSpec{
			SnatPolicyNames: snatplcy,
			Macaddress:      macaddr,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
	}
	return info
}

type policy struct {
	namespace string
	name      string
	snatip    []string
	labels    map[string]string
}

type nodedata struct {
	namespace       string
	name            string
	snatpolicynames map[string]bool
	macaddr         string
}

var snatTests = []policy{
	{
		"testns",
		"policy1",
		[]string{"10.1.1.8"},
		map[string]string{"key": "value"},
	},
	{
		"testns",
		"policy2",
		[]string{"10.1.1.9"},
		map[string]string{"key": "value"},
	},
	{
		"testns",
		"policy3",
		[]string{},
		map[string]string{},
	},
}
var snatTestsupdated = []policy{
	{
		"testns",
		"policy1",
		[]string{"10.1.1.20"},
		map[string]string{"key": "value"},
	},
	{
		"testns",
		"policy2",
		[]string{"10.1.1.30"},
		map[string]string{"key": "value"},
	},
}

var nodeTests = []nodedata{
	{
		"testns",
		"node-1",
		map[string]bool{"policy1": true},
		"01:02:03:04",
	},
	{
		"testns",
		"node-2",
		map[string]bool{"policy1": true},
		"01:02:03:05",
	},
	{
		"testns",
		"node-1",
		map[string]bool{"policy2": true, "policy1": true},
		"01:02:03:04",
	},
}

func snatWait(t *testing.T, desc string, expected map[string]snatglobalinfo.GlobalInfo,
	actual map[string]*snatglobalinfo.GlobalInfo, portRangeSet bool) {
	tu.WaitFor(t, desc, 100*time.Millisecond, func(last bool) (bool, error) {
		for key, v := range expected {
			val, ok := actual[key]
			if ok {
				if portRangeSet {
					result := tu.WaitEqual(t, last, v.SnatIp, val.SnatIp, "snatIp does not match") &&
						tu.WaitEqual(t, last,
							v.PortRanges[0], val.PortRanges[0], "Portrange does not match") &&
						tu.WaitEqual(t, last, v.SnatPolicyName, val.SnatPolicyName, "snatPolicyName does not match")
					if !result {
						return false, nil
					}
				} else {
					result := tu.WaitEqual(t, last, v.SnatIp, val.SnatIp, "snatIp does not match") &&
						tu.WaitEqual(t, last, v.SnatPolicyName, val.SnatPolicyName, "snatPolicyName does not match")
					if !result {
						return false, nil
					}
				}
			} else {
				return false, nil
			}
		}
		return true, nil
	})
}

func snatdeleted(t *testing.T, desc string, actual map[string]map[string]*snatglobalinfo.GlobalInfo) {
	tu.WaitFor(t, desc, 100*time.Millisecond, func(last bool) (bool, error) {
		if len(actual) > 0 {
			return false, nil
		}
		return true, nil
	})
}
func snatWaitForIpUpdated(t *testing.T, desc, snatIp string, actual map[string]map[string]*snatglobalinfo.GlobalInfo) {
	tu.WaitFor(t, desc, 100*time.Millisecond, func(last bool) (bool, error) {
		_, ok := actual[snatIp]
		if !ok {
			return false, nil
		}
		return true, nil
	})
}

func TestServiceBackedSnatLifecycle(t *testing.T) {
	for _, servicesFirst := range []bool{false, true} {
		name := "policy-before-services"
		if servicesFirst {
			name = "services-before-policy"
		}
		t.Run(name, func(t *testing.T) {
			cont := testController()
			var err error
			cont.apicConn, err = apicapi.New(cont.log, nil, "", "", nil, nil,
				cont.config.AciPrefix, 1800, 210, 60, 5, "common", nil, false)
			if err != nil {
				t.Fatal(err)
			}
			*cont.config.AllocateServiceIps = false
			policyObj := snatpolicydata("service-policy", "testns", nil, nil)
			nodes := []*nodeinfo.NodeInfo{
				Nodeinfodata("node-1", "aci-containers-system", "00:11:22:33:44:01", map[string]bool{policyObj.Name: true}),
				Nodeinfodata("node-2", "aci-containers-system", "00:11:22:33:44:02", map[string]bool{policyObj.Name: true}),
			}
			for _, info := range nodes {
				assert.NoError(t, cont.nodeIndexer.Add(node(info.Name)))
				cont.snatNodeInfoCache[info.Name] = info
			}
			drainNodes := func(expected int) {
				t.Helper()
				assert.Equal(t, expected, cont.snatNodeInfoQueue.Len())
				for cont.snatNodeInfoQueue.Len() > 0 {
					key, shutdown := cont.snatNodeInfoQueue.Get()
					assert.False(t, shutdown)
					_, nodeName, err := cache.SplitMetaNamespaceKey(key.(string))
					assert.NoError(t, err)
					assert.False(t, cont.handleSnatNodeInfo(cont.snatNodeInfoCache[nodeName]))
					cont.snatNodeInfoQueue.Done(key)
				}
			}
			setService := func(svc *v1.Service) {
				t.Helper()
				assert.NoError(t, cont.serviceIndexer.Update(svc))
				assert.False(t, cont.handleServiceUpdate(svc))
			}
			assertAllocations := func(expected map[string]string) {
				t.Helper()
				assert.Len(t, cont.snatGlobalInfoCache, len(expected))
				for ip, serviceName := range expected {
					entries := cont.snatGlobalInfoCache[ip]
					assert.Len(t, entries, len(nodes))
					for _, info := range nodes {
						entry := entries[info.Name]
						assert.NotNil(t, entry)
						assert.Equal(t, policyObj.Name, entry.SnatPolicyName)
						assert.Equal(t, "testns/"+serviceName, entry.ServiceKey)
						assert.Equal(t, ip, entry.SnatIp)
						assert.Equal(t, info.Spec.Macaddress, entry.MacAddress)
					}
					assert.NotEqual(t, entries["node-1"].PortRanges, entries["node-2"].PortRanges)
				}
			}
			first := service("testns", "lb1", "")
			first.Status.LoadBalancer.Ingress = []v1.LoadBalancerIngress{{IP: "10.3.0.9"}}
			second := service("testns", "lb2", "")
			second.Status.LoadBalancer.Ingress = []v1.LoadBalancerIngress{{IP: "10.3.0.10"}}
			if servicesFirst {
				setService(first)
				setService(second)
				drainNodes(0)
			}
			cont.updateSnatPolicyCache(policyObj.Name, policyObj)
			for _, info := range nodes {
				cont.snatNodeInfoAdded(info)
			}
			drainNodes(2)
			if !servicesFirst {
				setService(first)
				drainNodes(2)
				assertAllocations(map[string]string{"10.3.0.9": "lb1"})
				original := *cont.snatGlobalInfoCache["10.3.0.9"]["node-1"]
				setService(second)
				drainNodes(2)
				assert.Equal(t, original, *cont.snatGlobalInfoCache["10.3.0.9"]["node-1"])
			}
			assertAllocations(map[string]string{"10.3.0.9": "lb1", "10.3.0.10": "lb2"})
			setService(second.DeepCopy())
			drainNodes(2)
			assertAllocations(map[string]string{"10.3.0.9": "lb1", "10.3.0.10": "lb2"})

			second = second.DeepCopy()
			second.Status.LoadBalancer.Ingress = []v1.LoadBalancerIngress{{IP: "10.3.0.11"}}
			setService(second)
			drainNodes(2)
			assertAllocations(map[string]string{"10.3.0.9": "lb1", "10.3.0.11": "lb2"})

			assert.NoError(t, cont.serviceIndexer.Delete(first))
			assert.False(t, cont.handleServiceDelete("testns/lb1"))
			drainNodes(2)
			assert.NotContains(t, cont.snatServices, "testns/lb1")
			assertAllocations(map[string]string{"10.3.0.11": "lb2"})

			assert.NoError(t, cont.serviceIndexer.Delete(second))
			assert.False(t, cont.handleServiceDelete("testns/lb2"))
			second = second.DeepCopy()
			second.Status.LoadBalancer.Ingress = []v1.LoadBalancerIngress{{IP: "10.3.0.12"}}
			setService(second)
			drainNodes(2)
			assertAllocations(map[string]string{"10.3.0.12": "lb2"})

			replacement := second.DeepCopy()
			replacement.Name = "replacement"
			assert.NoError(t, cont.serviceIndexer.Delete(second))
			assert.False(t, cont.handleServiceDelete("testns/lb2"))
			setService(replacement)
			drainNodes(2)
			assertAllocations(map[string]string{"10.3.0.12": "replacement"})

			cont.snatPolicyCache[policyObj.Name].Selector.Labels = map[string]string{"selected": "true"}
			setService(replacement)
			drainNodes(2)
			assert.NotContains(t, cont.snatServices, "testns/replacement")
			assertAllocations(nil)
			replacement = replacement.DeepCopy()
			replacement.Labels = map[string]string{"selected": "true"}
			setService(replacement)
			drainNodes(2)
			assertAllocations(map[string]string{"10.3.0.12": "replacement"})

			replacement = replacement.DeepCopy()
			replacement.Spec.Type = v1.ServiceTypeClusterIP
			setService(replacement)
			drainNodes(2)
			assertAllocations(nil)
			replacement = replacement.DeepCopy()
			replacement.Spec.Type = v1.ServiceTypeLoadBalancer
			setService(replacement)
			drainNodes(2)
			assertAllocations(map[string]string{"10.3.0.12": "replacement"})

			replacement = replacement.DeepCopy()
			replacement.Status.LoadBalancer.Ingress = append(replacement.Status.LoadBalancer.Ingress,
				v1.LoadBalancerIngress{IP: "10.3.0.13"},
				v1.LoadBalancerIngress{Hostname: "loadbalancer.example.com"},
				v1.LoadBalancerIngress{IP: "invalid"})
			setService(replacement)
			drainNodes(2)
			assertAllocations(map[string]string{"10.3.0.12": "replacement", "10.3.0.13": "replacement"})
			replacement = replacement.DeepCopy()
			replacement.DeletionTimestamp = &metav1.Time{Time: time.Now()}
			setService(replacement)
			drainNodes(2)
			assertAllocations(nil)
			replacement = replacement.DeepCopy()
			replacement.DeletionTimestamp = nil
			setService(replacement)
			drainNodes(2)
			assertAllocations(map[string]string{"10.3.0.12": "replacement", "10.3.0.13": "replacement"})

			assert.NoError(t, cont.serviceIndexer.Delete(replacement))
			cont.clearSnatGlobalCache(policyObj.Name, "node-1")
			assert.NotContains(t, cont.snatGlobalInfoCache["10.3.0.12"], "node-1")
			assert.Contains(t, cont.snatGlobalInfoCache["10.3.0.12"], "node-2")
			cont.clearSnatGlobalCache(policyObj.Name, "")
			assertAllocations(nil)
		})
	}
}

func TestSnatnodeInfo(t *testing.T) {
	cont := testController()

	cont.fakeNodeSource.Add(node("node-1"))
	cont.fakeNodeSource.Add(node("node-2"))

	for _, pt := range snatTests {
		snatObj := snatpolicydata(pt.name, pt.namespace, pt.snatip, pt.labels)
		cont.fakeSnatPolicySource.Add(snatObj)
	}
	cont.run()
	nodinfo := make(map[string]bool)
	for _, pt := range nodeTests {
		nodeobj := Nodeinfodata(pt.name, pt.namespace, pt.macaddr, pt.snatpolicynames)
		if _, ok := nodinfo[pt.name]; !ok {
			cont.fakeNodeInfoSource.Add(nodeobj)
			cont.log.Debug("NodeInfo Added: ", nodeobj)
			nodinfo[pt.name] = true
		} else {
			cont.log.Debug("NodeInfo Modified: ", nodeobj)
			cont.fakeNodeInfoSource.Modify(nodeobj)
		}
	}
	time.Sleep(time.Millisecond * 100)
	cont.log.Debug("snatGlobalInfoCache: ", cont.AciController.snatGlobalInfoCache)
	expected := map[string]snatglobalinfo.GlobalInfo{
		"node-1": {SnatIp: "10.1.1.8", SnatPolicyName: "policy1", PortRanges: []snatglobalinfo.PortRange{{Start: 5000, End: 7999}}},
		"node-2": {SnatIp: "10.1.1.8", SnatPolicyName: "policy1", PortRanges: []snatglobalinfo.PortRange{{Start: 8000, End: 10999}}},
	}
	expected1 := map[string]snatglobalinfo.GlobalInfo{
		"node-1": {SnatIp: "10.1.1.9", SnatPolicyName: "policy2", PortRanges: []snatglobalinfo.PortRange{{Start: 5000, End: 7999}}},
	}
	snatWait(t, "snat test", expected, cont.AciController.snatGlobalInfoCache["10.1.1.8"], true)
	snatWait(t, "snat test", expected1, cont.AciController.snatGlobalInfoCache["10.1.1.9"], true)

	type test struct {
		metav1.ObjectMeta
	}

	nodeInfo := &test{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "test-namespace",
			Name:      "test-nodeinfo",
		},
	}
	cont.snatNodeInfoDeleted(nodeInfo)
	time.Sleep(time.Millisecond * 100)

	snatWait(t, "snat test", expected, cont.AciController.snatGlobalInfoCache["10.1.1.8"], true)
	snatWait(t, "snat test", expected1, cont.AciController.snatGlobalInfoCache["10.1.1.9"], true)

	nodeInfo1 := cache.DeletedFinalStateUnknown{}

	cont.snatNodeInfoDeleted(nodeInfo1)
	time.Sleep(time.Millisecond * 100)

	snatWait(t, "snat test", expected, cont.AciController.snatGlobalInfoCache["10.1.1.8"], true)
	snatWait(t, "snat test", expected1, cont.AciController.snatGlobalInfoCache["10.1.1.9"], true)

	for _, pt := range snatTestsupdated {
		snatObj := snatpolicydata(pt.name, pt.namespace, pt.snatip, pt.labels)
		cont.fakeSnatPolicySource.Modify(snatObj)
	}
	time.Sleep(time.Millisecond * 100)
	snatWaitForIpUpdated(t, "snat test", "10.1.1.20", cont.AciController.snatGlobalInfoCache)

	for _, pt := range nodeTests {
		nodeobj := Nodeinfodata(pt.name, pt.namespace, pt.macaddr, pt.snatpolicynames)
		cont.fakeNodeInfoSource.Delete(nodeobj)
	}
	time.Sleep(time.Millisecond * 100)
	expected = map[string]snatglobalinfo.GlobalInfo{}
	snatWait(t, "snat test", expected, cont.AciController.snatGlobalInfoCache["10.1.1.20"], true)

	for _, pt := range snatTests {
		snatObj := snatpolicydata(pt.name, pt.namespace, pt.snatip, pt.labels)
		cont.fakeSnatPolicySource.Delete(snatObj)
	}
	snatdeleted(t, "snat test", cont.AciController.snatGlobalInfoCache)
	time.Sleep(time.Millisecond * 200)
	for _, pt := range snatTests {
		snatObj := snatpolicydata(pt.name, pt.namespace, pt.snatip, pt.labels)
		cont.fakeSnatPolicySource.Add(snatObj)
	}
	// Add service
	cont.fakeServiceSource.Add(service("testns", "service1", "10.4.2.1"))
	time.Sleep(time.Millisecond * 100)
	for _, pt := range nodeTests {
		nodeobj := Nodeinfodata(pt.name, pt.namespace, pt.macaddr, pt.snatpolicynames)
		if _, ok := nodinfo[pt.name]; !ok {
			cont.fakeNodeInfoSource.Add(nodeobj)
			cont.log.Debug("NodeInfo Added: ", nodeobj)
			nodinfo[pt.name] = true
		} else {
			cont.log.Debug("NodeInfo Modified: ", nodeobj)
			cont.fakeNodeInfoSource.Modify(nodeobj)
		}
	}
	time.Sleep(time.Millisecond * 100)
	cont.log.Debug("snatGlobalInfoCache: ", cont.AciController.snatGlobalInfoCache)
	expected = map[string]snatglobalinfo.GlobalInfo{
		"node-1": {SnatIp: "10.1.1.8", SnatPolicyName: "policy1", PortRanges: []snatglobalinfo.PortRange{{Start: 5000, End: 7999}}},
		"node-2": {SnatIp: "10.1.1.8", SnatPolicyName: "policy1", PortRanges: []snatglobalinfo.PortRange{{Start: 8000, End: 10999}}},
	}
	expected1 = map[string]snatglobalinfo.GlobalInfo{
		"node-1": {SnatIp: "10.1.1.9", SnatPolicyName: "policy2", PortRanges: []snatglobalinfo.PortRange{{Start: 5000, End: 7999}}},
	}
	snatWait(t, "snat test", expected, cont.AciController.snatGlobalInfoCache["10.1.1.8"], true)
	snatWait(t, "snat test", expected1, cont.AciController.snatGlobalInfoCache["10.1.1.9"], true)
	cont.stop()
}

func TestPeriodicSnatGlobalCacheCachesync(t *testing.T) {
	cont := testController()

	cont.fakeNodeSource.Add(node("node-1"))
	cont.fakeNodeSource.Add(node("node-2"))

	for _, pt := range snatTests {
		snatObj := snatpolicydata(pt.name, pt.namespace, pt.snatip, pt.labels)
		cont.fakeSnatPolicySource.Add(snatObj)
	}
	cont.run()
	nodinfo := make(map[string]bool)
	for _, pt := range nodeTests {
		nodeobj := Nodeinfodata(pt.name, pt.namespace, pt.macaddr, pt.snatpolicynames)
		if _, ok := nodinfo[pt.name]; !ok {
			cont.fakeNodeInfoSource.Add(nodeobj)
			cont.log.Debug("NodeInfo Added: ", nodeobj)
			nodinfo[pt.name] = true
		} else {
			cont.log.Debug("NodeInfo Modified: ", nodeobj)
			cont.fakeNodeInfoSource.Modify(nodeobj)
		}
	}
	time.Sleep(time.Millisecond * 100)
	cont.log.Debug("snatGlobalInfoCache: ", cont.AciController.snatGlobalInfoCache)
	expected := map[string]snatglobalinfo.GlobalInfo{
		"node-1": {SnatIp: "10.1.1.8", SnatPolicyName: "policy1", PortRanges: []snatglobalinfo.PortRange{{Start: 5000, End: 7999}}},
		"node-2": {SnatIp: "10.1.1.8", SnatPolicyName: "policy1", PortRanges: []snatglobalinfo.PortRange{{Start: 8000, End: 10999}}},
	}

	expected1 := map[string]snatglobalinfo.GlobalInfo{
		"node-1": {SnatIp: "10.1.1.9", SnatPolicyName: "policy2", PortRanges: []snatglobalinfo.PortRange{{Start: 5000, End: 7999}}},
	}
	snatWait(t, "snat test", expected,
		cont.AciController.snatGlobalInfoCache["10.1.1.8"], true)

	snatWait(t, "snat test", expected1,
		cont.AciController.snatGlobalInfoCache["10.1.1.9"], true)

	// Remove a node entry from snatglobalcache
	delete(cont.AciController.snatGlobalInfoCache["10.1.1.8"], "node-2")

	go cont.snatGlobalInfoSync(cont.stopCh, 1)
	time.Sleep(time.Second * globalInfoSyncWaitTime)

	snatWait(t, "snat test", expected,
		cont.AciController.snatGlobalInfoCache["10.1.1.8"], true)

	// Edit an associated policyname with node
	node1item := cont.AciController.snatGlobalInfoCache["10.1.1.8"]["node-1"]
	node1item.SnatPolicyName = "wrongpolicyname"
	cont.AciController.snatGlobalInfoCache["10.1.1.8"]["node-1"] = node1item
	time.Sleep(time.Second * globalInfoSyncWaitTime)

	snatWait(t, "snat test", expected,
		cont.AciController.snatGlobalInfoCache["10.1.1.8"], true)

	// Remove a policy entry from snatglobalcache
	delete(cont.AciController.snatGlobalInfoCache, "10.1.1.8")
	time.Sleep(time.Second * globalInfoSyncWaitTime)

	snatWait(t, "snat test", expected,
		cont.AciController.snatGlobalInfoCache["10.1.1.8"], false)

	cont.stop()
}

func TestSnatCfgChangeTest(t *testing.T) {
	cont := testController()

	cont.fakeNodeSource.Add(node("node-1"))

	for _, pt := range snatTests {
		snatObj := snatpolicydata(pt.name, pt.namespace, pt.snatip, pt.labels)
		cont.fakeSnatPolicySource.Add(snatObj)
	}
	cont.run()
	nodinfo := make(map[string]bool)
	configmap := &v1.ConfigMap{
		Data: map[string]string{"start": "5000", "end": "65000", "ports-per-node": "3000"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "snat-operator-config",
			Namespace: "aci-containers-system",
		},
	}
	cont.fakeSnatCfgSource.Add(configmap)
	for _, pt := range nodeTests {
		nodeobj := Nodeinfodata(pt.name, pt.namespace, pt.macaddr, pt.snatpolicynames)
		if _, ok := nodinfo[pt.name]; !ok {
			cont.fakeNodeInfoSource.Add(nodeobj)
			cont.log.Debug("NodeInfo Added: ", nodeobj)
			nodinfo[pt.name] = true
		} else {
			cont.log.Debug("NodeInfo Modified: ", nodeobj)
			cont.fakeNodeInfoSource.Modify(nodeobj)
		}
	}
	time.Sleep(time.Millisecond * 700)
	// When the config map values are not modified, it should log and return
	modconfigmap := &v1.ConfigMap{
		Data: map[string]string{"start": "5000", "end": "65000", "ports-per-node": "3000"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "snat-operator-config",
			Namespace: "aci-containers-system",
		},
	}
	cont.fakeSnatCfgSource.Modify(modconfigmap)
	time.Sleep(time.Millisecond * 700)
	expected := map[string]snatglobalinfo.GlobalInfo{
		"node-1": {SnatIp: "10.1.1.9", SnatPolicyName: "policy2", PortRanges: []snatglobalinfo.PortRange{{Start: 5000, End: 7999}}},
	}
	snatWait(t, "snat test", expected,
		cont.AciController.snatGlobalInfoCache["10.1.1.9"], true)
	modconfigmap = &v1.ConfigMap{
		Data: map[string]string{"start": "10000", "end": "65000", "ports-per-node": "5000"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "snat-operator-config",
			Namespace: "aci-containers-system",
		},
	}
	cont.fakeSnatCfgSource.Modify(modconfigmap)
	time.Sleep(time.Millisecond * 700)
	cont.log.Debug("snatGlobalInfoCache: ", cont.AciController.snatGlobalInfoCache)
	expected = map[string]snatglobalinfo.GlobalInfo{
		"node-1": {SnatIp: "10.1.1.9", SnatPolicyName: "policy2", PortRanges: []snatglobalinfo.PortRange{{Start: 10000, End: 14999}}},
	}
	snatWait(t, "snat test", expected,
		cont.AciController.snatGlobalInfoCache["10.1.1.9"], true)
	modconfigmap = &v1.ConfigMap{
		Data: map[string]string{"start": "5000", "end": "65000", "ports-per-node": "60000"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "snat-operator-config",
			Namespace: "aci-containers-system",
		},
	}
	cont.fakeSnatCfgSource.Modify(modconfigmap)
	expected = map[string]snatglobalinfo.GlobalInfo{
		"node-1": {SnatIp: "10.1.1.9", SnatPolicyName: "policy2", PortRanges: []snatglobalinfo.PortRange{{Start: 10000, End: 14999}}},
	}
	snatWait(t, "snat test", expected,
		cont.AciController.snatGlobalInfoCache["10.1.1.9"], true)
	cont.stop()
}
