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
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/noironetworks/aci-containers/pkg/metadata"
	snatglobal "github.com/noironetworks/aci-containers/pkg/snatglobalinfo/apis/aci.snat/v1"
	snatpolicy "github.com/noironetworks/aci-containers/pkg/snatpolicy/apis/aci.snat/v1"
	tu "github.com/noironetworks/aci-containers/pkg/testutil"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apitypes "k8s.io/apimachinery/pkg/types"
)

type portRange struct {
	start int
	end   int
}

func snatglobaldata(uuid string, name string, nodename string, namespace string, globalinfo []snatglobal.GlobalInfo) *snatglobal.SnatGlobalInfo {
	GlobalInfos := make(map[string][]snatglobal.GlobalInfo, 10)
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

func snatpolicydata(name string, namespace string,
	snatIp []string, destIp []string, labels map[string]string) *snatpolicy.SnatPolicy {
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
			raw, err = ioutil.ReadFile(snatfile)
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
	//assert.Equal(t, pt.port_range.start, snat.PortRange[0].Start, desc, pt.name, "port start")
	//assert.Equal(t, pt.port_range.end, snat.PortRange[0].End, desc, pt.name, "port end")
}

func TestSnatSync(t *testing.T) {
	tempdir, err := ioutil.TempDir("", "hostagent_test_")
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
			ioutil.WriteFile(filepath.Join(tempdir,
				pt.uuid+"_"+pt.cont+"_"+pt.veth+".ep"),
				[]byte("random gibberish"), 0644)
		}

		pod := pod(pt.uuid, pt.namespace, pt.name, pt.eg, pt.sg)
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
	var newglobal []snatglobal.GlobalInfo
	var snatglobalinfo *snatglobal.SnatGlobalInfo
	for i, pt := range snatGlobals {
		if i%2 == 0 {
			ioutil.WriteFile(filepath.Join(tempdir,
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
		agent.doTestSnat(t, tempdir, &pt, "create")
	}
	agent.stop()
}

func TestSnatPortExhausted(t *testing.T) {
	tempdir, err := ioutil.TempDir("", "hostagent_test_")
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
		pod := pod(pt.uuid, pt.namespace, pt.name, pt.eg, pt.sg)
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
	assert.Equal(t, false, ok, "create", "Epfile", "uids")
	agent.stop()
}
