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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apitypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"

	"github.com/noironetworks/aci-containers/pkg/metadata"
	nodeinfo "github.com/noironetworks/aci-containers/pkg/nodeinfo/apis/aci.snat/v1"
	nodeinfoclient "github.com/noironetworks/aci-containers/pkg/nodeinfo/clientset/versioned"
	snatglobal "github.com/noironetworks/aci-containers/pkg/snatglobalinfo/apis/aci.snat/v1"
	snatpolicy "github.com/noironetworks/aci-containers/pkg/snatpolicy/apis/aci.snat/v1"
	tu "github.com/noironetworks/aci-containers/pkg/testutil"
)

type portRange struct {
	start int
	end   int
}

func snatglobaldata(uuid, name, nodename, namespace string, globalinfo snatglobal.GlobalInfoList) *snatglobal.SnatGlobalInfo {
	GlobalInfos := make(map[string]snatglobal.GlobalInfoList, 10)
	GlobalInfos[nodename] = globalinfo
	return &snatglobal.SnatGlobalInfo{
		Spec: snatglobal.SnatGlobalInfoSpec{
			GlobalInfos: GlobalInfos,
		},
		ObjectMeta: metav1.ObjectMeta{
			UID:       apitypes.UID(uuid),
			Namespace: namespace,
			Name:      name,
			Labels:    map[string]string{},
		},
	}
}

func snatpolicydata(name, namespace string,
	snatIp, destIp []string, labels map[string]string) *snatpolicy.SnatPolicy {
	policy := &snatpolicy.SnatPolicy{
		Spec: snatpolicy.SnatPolicySpec{
			SnatIp: snatIp,
			DestIp: destIp,
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

type snatGlobal struct {
	name       string
	ip         string
	mac        string
	port_range portRange
	nodename   string
	policyname string
	uuid       string
	namespace  string
}
type policy struct {
	namespace string
	name      string
	snatip    []string
	destip    []string
	labels    map[string]string
}

var snatGlobals = []snatGlobal{
	{
		"snatglobalinfo",
		"10.1.1.8",
		"00:0c:29:92:fe:d0",
		portRange{4000, 5000},
		"test-node",
		"policy1",
		"uid-policy1",
		"test",
	},

	{
		"snatglobalinfo",
		"10.1.1.9",
		"00:0c:29:92:fe:d1",
		portRange{7000, 8000},
		"test-node",
		"policy2",
		"uid-policy2",
		"test",
	},
}

var snatpolices = []policy{
	{
		"testns",
		"policy1",
		[]string{"10.1.1.8"},
		[]string{"10.10.10.0/24"},
		map[string]string{ /*"key": "value"*/ },
	},

	{
		"testns",
		"policy2",
		[]string{"10.1.1.9"},
		[]string{"10.10.0.0/16"},
		map[string]string{ /*"key": "value"*/ },
	},
	{
		"testns",
		"policy1",
		[]string{"10.1.1.8"},
		[]string{"10.10.10.0/26", "10.10.10.0/31", "10.10.10.0/24"},
		map[string]string{ /*"key": "value"*/ },
	},
}

func (agent *testHostAgent) doTestSnat(t *testing.T, tempdir string,
	pt *snatGlobal, desc string) {
	var raw []byte
	snat := &OpflexSnatIp{}

	tu.WaitFor(t, pt.name, 2000*time.Millisecond,
		func(last bool) (bool, error) {
			var err error
			snatfile := filepath.Join(tempdir,
				pt.uuid+".snat")
			raw, err = os.ReadFile(snatfile)
			if !tu.WaitNil(t, last, err, desc, pt.name, "read snat") {
				return false, nil
			}
			err = json.Unmarshal(raw, snat)
			agent.log.Info("Snat file added ", snatfile)
			return tu.WaitNil(t, last, err, desc, pt.name, "unmarshal snat"), nil
		})
	agent.log.Info("Snat Object added ", snat)
	snatdstr := pt.uuid
	assert.Equal(t, snatdstr, snat.Uuid, desc, pt.name, "uuid")
	assert.Equal(t, pt.ip, snat.SnatIp, desc, pt.name, "ip")
	switch {
	case pt.policyname == "policy1":
		assert.Equal(t, []string{"10.10.10.0/31", "10.10.10.0/26", "10.10.10.0/24"}, snat.DestIpAddress, desc, pt.name, "destip")
	case pt.policyname == "policy2":
		assert.Equal(t, []string{"10.10.0.0/16"}, snat.DestIpAddress, desc, pt.name, "destip")
	}
}

func TestSnatServiceDeletionPreservesRemainingMembership(t *testing.T) {
	for _, test := range []struct {
		name             string
		policyLabels     map[string]string
		survivorLabels   map[string]string
		survivorSelector map[string]string
		survivorType     v1.ServiceType
		survivorNS       string
		keepDeleted      bool
		retainPolicy     bool
		fallbackPolicy   bool
	}{
		{name: "namespace-only", survivorNS: "testns", survivorSelector: map[string]string{"role": "shared"}, retainPolicy: true},
		{name: "deleted-service-still-cached", survivorNS: "testns", survivorSelector: map[string]string{"role": "shared"}, keepDeleted: true, retainPolicy: true},
		{name: "label-selected", policyLabels: map[string]string{"snat": "yes"}, survivorLabels: map[string]string{"snat": "yes"}, survivorNS: "testns", survivorSelector: map[string]string{"role": "shared"}, retainPolicy: true},
		{name: "nonmatching-policy-labels", policyLabels: map[string]string{"snat": "yes"}, survivorNS: "testns", survivorSelector: map[string]string{"role": "shared"}},
		{name: "nonmatching-pod-selector", survivorNS: "testns", survivorSelector: map[string]string{"role": "unrelated"}},
		{name: "different-namespace", survivorNS: "otherns", survivorSelector: map[string]string{"role": "shared"}},
		{name: "clusterip-does-not-retain-service-backed-policy", survivorNS: "testns", survivorSelector: map[string]string{"role": "shared"}, survivorType: v1.ServiceTypeClusterIP, fallbackPolicy: true},
		{name: "last-service"},
		{name: "last-service-still-cached", keepDeleted: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			agent := testAgent()
			agent.config.AciSnatNamespace = "aci-containers-system"
			agent.config.UplinkMacAdress = "00:50:56:97:2d:0e"
			agent.config.OpFlexEndpointDir = t.TempDir()
			agent.syncEnabled.Store(true)
			assert.NoError(t, agent.nodeInformer.GetStore().Add(&v1.Node{
				ObjectMeta: metav1.ObjectMeta{Name: agent.config.NodeName},
			}))
			policy := snatpolicydata("service-policy", "testns", nil, nil, test.policyLabels)
			agent.snatPolicyCache[policy.Name] = policy
			fallbackPolicyName := "lower-priority-policy"
			if test.fallbackPolicy {
				agent.snatPolicyCache[fallbackPolicyName] = snatpolicydata(fallbackPolicyName,
					"testns", []string{"10.3.0.20"}, []string{"192.0.2.0/24"}, nil)
			}
			shared := &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "shared", Namespace: "testns", UID: "shared-pod", Labels: map[string]string{"app": "backend", "role": "shared"}},
				Spec:       v1.PodSpec{NodeName: agent.config.NodeName},
			}
			onlyDeleted := shared.DeepCopy()
			onlyDeleted.Name = "only-lb2"
			onlyDeleted.UID = "only-lb2-pod"
			onlyDeleted.Labels = map[string]string{"app": "backend", "role": "only-lb2"}
			assert.NoError(t, agent.podInformer.GetStore().Add(shared))
			assert.NoError(t, agent.podInformer.GetStore().Add(onlyDeleted))
			deleted := &v1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: "lb2", Namespace: "testns", UID: "lb2-uid", Labels: map[string]string{"snat": "yes"}},
				Spec:       v1.ServiceSpec{Type: v1.ServiceTypeLoadBalancer, Selector: map[string]string{"app": "backend"}},
			}
			assert.NoError(t, agent.serviceInformer.GetStore().Add(deleted))
			agent.handleObjectUpdateForSnat(deleted)
			var survivor *v1.Service
			if test.survivorNS != "" {
				survivorType := test.survivorType
				if survivorType == "" {
					survivorType = v1.ServiceTypeLoadBalancer
				}
				survivor = &v1.Service{
					ObjectMeta: metav1.ObjectMeta{Name: "lb1", Namespace: test.survivorNS, UID: "lb1-uid", Labels: test.survivorLabels},
					Spec:       v1.ServiceSpec{Type: survivorType, Selector: test.survivorSelector},
				}
				assert.NoError(t, agent.serviceInformer.GetStore().Add(survivor))
				agent.handleObjectUpdateForSnat(survivor)
			}
			var reportMutex sync.Mutex
			reported := nodeinfo.NodeInfo{
				TypeMeta:   metav1.TypeMeta{APIVersion: "aci.snat/v1", Kind: "NodeInfo"},
				ObjectMeta: metav1.ObjectMeta{Name: agent.config.NodeName, Namespace: agent.config.AciSnatNamespace},
			}
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				reportMutex.Lock()
				defer reportMutex.Unlock()
				writer.Header().Set("Content-Type", "application/json")
				if request.Method == http.MethodPut {
					var updated nodeinfo.NodeInfo
					assert.NoError(t, json.NewDecoder(request.Body).Decode(&updated))
					reported = updated
				}
				assert.NoError(t, json.NewEncoder(writer).Encode(&reported))
			}))
			defer server.Close()
			client, err := nodeinfoclient.NewForConfig(&rest.Config{Host: server.URL})
			if !assert.NoError(t, err) {
				return
			}
			agent.env.(*K8sEnvironment).nodeInfo = client
			assertReport := func(required bool) {
				t.Helper()
				assert.False(t, agent.syncSnatNodeInfo())
				reportMutex.Lock()
				defer reportMutex.Unlock()
				assert.Equal(t, required, reported.Spec.SnatPolicyNames[policy.Name])
				assert.Equal(t, agent.config.UplinkMacAdress, reported.Spec.Macaddress)
			}
			assertReport(true)
			if !test.keepDeleted {
				assert.NoError(t, agent.serviceInformer.GetStore().Delete(deleted))
			}
			agent.serviceDeleted(deleted)
			assert.NotContains(t, agent.snatPods[policy.Name], string(onlyDeleted.UID))
			if test.fallbackPolicy {
				assert.Contains(t, agent.snatPods[fallbackPolicyName], string(shared.UID))
				agent.opflexSnatGlobalInfos[agent.config.NodeName] = []*opflexSnatGlobalInfo{{
					SnatIp:         "10.3.0.20",
					SnatIpUid:      "lower-priority-uuid",
					SnatPolicyName: fallbackPolicyName,
				}}
				agent.updateEpFiles([]string{string(shared.UID)})
				assert.Equal(t, []string{"lower-priority-uuid"},
					agent.opflexSnatLocalInfos[string(shared.UID)].PlcyUuids)
			}
			if test.retainPolicy {
				assert.Equal(t, SERVICE, agent.snatPods[policy.Name][string(shared.UID)]&SERVICE)
				assert.Contains(t, agent.opflexSnatLocalInfos[string(shared.UID)].Snatpolicies[SERVICE], policy.Name)
			} else {
				assert.Empty(t, agent.snatPods[policy.Name])
			}
			assertReport(test.retainPolicy)
			if test.retainPolicy {
				if test.keepDeleted {
					assert.NoError(t, agent.serviceInformer.GetStore().Delete(deleted))
				}
				assert.NoError(t, agent.serviceInformer.GetStore().Delete(survivor))
				agent.serviceDeleted(survivor)
				assert.Empty(t, agent.snatPods[policy.Name])
				assertReport(false)
			}
		})
	}
}

func TestSnatGlobalInfoRemovalClearsEndpointUUID(t *testing.T) {
	agent := testAgent()
	agent.config.OpFlexServiceDir = t.TempDir()
	policyName := "service-policy"
	podUID := "backend-pod"
	agent.snatPolicyCache[policyName] = snatpolicydata(policyName, "testns", nil,
		[]string{"192.0.2.0/24"}, nil)
	agent.snatPods[policyName] = map[string]ResourceType{podUID: POD}
	agent.opflexSnatLocalInfos[podUID] = &opflexSnatLocalInfo{
		Existing: true,
		Snatpolicies: map[ResourceType][]string{
			POD: {policyName},
		},
		PlcyUuids: []string{"removed-snat-uuid"},
	}
	agent.opflexSnatGlobalInfos[agent.config.NodeName] = []*opflexSnatGlobalInfo{{
		SnatIp:         "10.3.0.3",
		SnatIpUid:      "removed-snat-uuid",
		SnatPolicyName: policyName,
	}}

	remoteInfo := snatglobal.GlobalInfo{
		MacAddress:     "00:11:22:33:44:55",
		PortRanges:     []snatglobal.PortRange{{Start: 5000, End: 7999}},
		SnatIp:         "10.3.0.4",
		SnatIpUid:      "remote-snat-uuid",
		SnatPolicyName: policyName,
	}
	globalInfo := snatglobaldata("global-uid", "snatglobalinfo", "remote-node",
		"aci-containers-system", snatglobal.GlobalInfoList{remoteInfo})
	agent.snaGlobalInfoChanged(globalInfo, nil)

	assert.Empty(t, agent.opflexSnatGlobalInfos[agent.config.NodeName])
	assert.Empty(t, agent.opflexSnatLocalInfos[podUID].PlcyUuids)
	assert.False(t, agent.opflexSnatLocalInfos[podUID].Existing)
}

func TestSnatSync(t *testing.T) {
	tempdir, err := os.MkdirTemp("", "hostagent_test_")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tempdir)
	agent := testAgent()
	agent.config.OpFlexSnatDir = tempdir
	agent.config.OpFlexEndpointDir = tempdir
	agent.config.OpFlexServiceDir = tempdir
	agent.config.UplinkIface = "eth10"
	agent.config.NodeName = "test-node"
	agent.config.ServiceVlan = 4003
	agent.config.UplinkMacAdress = "5a:fd:16:e5:e7:c0"
	agent.run()
	for i, pt := range podTests {
		if i%2 == 0 {
			os.WriteFile(filepath.Join(tempdir,
				pt.uuid+"_"+pt.cont+"_"+pt.veth+".ep"),
				[]byte("random gibberish"), 0644)
		}

		pod := pod(pt.uuid, pt.namespace, pt.name, pt.eg, pt.sg, pt.qp)
		cnimd := cnimd(pt.namespace, pt.name, pt.ip, pt.cont, pt.veth)
		agent.epMetadata[pt.namespace+"/"+pt.name] =
			map[string]*metadata.ContainerMetadata{
				cnimd.Id.ContId: cnimd,
			}
		agent.fakePodSource.Add(pod)
	}
	time.Sleep(1000 * time.Millisecond)
	for _, pt := range snatpolices {
		snatObj := snatpolicydata(pt.name, pt.namespace, pt.snatip, pt.destip, pt.labels)
		agent.fakeSnatPolicySource.Add(snatObj)
		agent.log.Info("Snat Obj Created #### ", snatObj)
	}
	time.Sleep(1000 * time.Millisecond)
	var newglobal snatglobal.GlobalInfoList
	var snatglobalinfo *snatglobal.SnatGlobalInfo
	for i, pt := range snatGlobals {
		if i%2 == 0 {
			os.WriteFile(filepath.Join(tempdir,
				pt.uuid+".snat"),
				[]byte("random gibberish"), 0644)
		}
		var globalinfo snatglobal.GlobalInfo
		portrange := make([]snatglobal.PortRange, 1)
		portrange[0].Start = pt.port_range.start
		portrange[0].End = pt.port_range.end
		globalinfo.MacAddress = pt.mac
		globalinfo.SnatIp = pt.ip
		globalinfo.SnatIpUid = pt.uuid
		globalinfo.PortRanges = portrange
		globalinfo.SnatPolicyName = pt.policyname
		if i == 0 {
			newglobal = append(newglobal, globalinfo)
		}
		for _, v := range newglobal {
			if v.MacAddress != pt.mac {
				newglobal = append(newglobal, globalinfo)
				agent.log.Info("Global added##### ", newglobal)
			}
		}
		snatglobalinfo = snatglobaldata(pt.uuid, pt.name, pt.nodename, pt.namespace, newglobal)
		agent.fakeSnatGlobalSource.Add(snatglobalinfo)
		agent.log.Info("Complete Globale Info #### ", snatglobalinfo)
		agent.doTestSnat(t, tempdir, &snatGlobals[i], "create")
	}
	agent.stop()
}

func TestSnatPortExhausted(t *testing.T) {
	tempdir, err := os.MkdirTemp("", "hostagent_test_")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tempdir)
	agent := testAgent()
	agent.config.OpFlexSnatDir = tempdir
	agent.config.OpFlexEndpointDir = tempdir
	agent.config.OpFlexServiceDir = tempdir
	agent.config.UplinkIface = "eth10"
	agent.config.NodeName = "test-node"
	agent.config.ServiceVlan = 4003
	agent.config.UplinkMacAdress = "5a:fd:16:e5:e7:c0"
	agent.run()
	for _, pt := range podTests {
		pod := pod(pt.uuid, pt.namespace, pt.name, pt.eg, pt.sg, pt.qp)
		cnimd := cnimd(pt.namespace, pt.name, pt.ip, pt.cont, pt.veth)
		agent.epMetadata[pt.namespace+"/"+pt.name] =
			map[string]*metadata.ContainerMetadata{
				cnimd.Id.ContId: cnimd,
			}
		agent.fakePodSource.Add(pod)
	}
	time.Sleep(1000 * time.Millisecond)
	for _, pt := range snatpolices {
		snatObj := snatpolicydata(pt.name, pt.namespace, pt.snatip, pt.destip, pt.labels)
		agent.fakeSnatPolicySource.Add(snatObj)
		agent.log.Info("Snat Obj Created #### ", snatObj)
	}
	time.Sleep(1000 * time.Millisecond)

	policy := &snatpolicy.SnatPolicy{
		Spec: snatpolicy.SnatPolicySpec{
			SnatIp: []string{"172.12.12.11/24"},
			DestIp: []string{"100.100.100.100/24"},
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "policy1",
		},
		Status: snatpolicy.SnatPolicyStatus{
			State: snatpolicy.IpPortsExhausted,
		},
	}
	// set the globalinfo for other node, and port exhausted for policy1
	var newglobal []snatglobal.GlobalInfo
	var snatglobalinfo *snatglobal.SnatGlobalInfo
	var globalinfo snatglobal.GlobalInfo
	portrange := make([]snatglobal.PortRange, 1)
	portrange[0].Start = 5000
	portrange[0].End = 8000
	globalinfo.MacAddress = "01:02:03:04"
	globalinfo.SnatIp = "192.128.1.1"
	globalinfo.SnatIpUid = "policy1-uid"
	globalinfo.PortRanges = portrange
	globalinfo.SnatPolicyName = "policy1"
	newglobal = append(newglobal, globalinfo)
	snatglobalinfo = snatglobaldata("policy1-uid", "snatglobalinfo", "test-node-1", "testns", newglobal)
	agent.fakeSnatGlobalSource.Add(snatglobalinfo)
	time.Sleep(1000 * time.Millisecond)
	// modify the policy with port exhaused
	agent.fakeSnatPolicySource.Modify(policy)
	time.Sleep(1000 * time.Millisecond)
	agent.log.Info("SnatLocal Info #### ", agent.snatPods)
	// check the policy is deleted from local information as ip/port is not allocated
	_, ok := agent.snatPods["policy1"]
	assert.Equal(t, true, ok, "create", "Epfile", "uids")
	agent.stop()
}
