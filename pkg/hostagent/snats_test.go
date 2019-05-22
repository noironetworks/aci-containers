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
	//v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apitypes "k8s.io/apimachinery/pkg/types"

	"github.com/noironetworks/aci-containers/pkg/metadata"
	//md "github.com/noironetworks/aci-containers/pkg/metadata"
	snatglobal "github.com/noironetworks/aci-containers/pkg/snatglobalinfo/apis/aci.snat/v1"
	snatlocal "github.com/noironetworks/aci-containers/pkg/snatlocalinfo/apis/aci.snat/v1"
	tu "github.com/noironetworks/aci-containers/pkg/testutil"
)

type portRange struct {
	start int
	end   int
}

var LocalInfos map[string]snatlocal.LocalInfo

func snatlocaldata(uuid string, poduuid string, namespace string, name string,
	ip string) *snatlocal.SnatLocalInfo {
	var localinfo snatlocal.LocalInfo
	localinfo.SnatIp = ip
	LocalInfos[poduuid] = localinfo
	return &snatlocal.SnatLocalInfo{
		Spec: snatlocal.SnatLocalInfoSpec{
			Nodename:   "test-node",
			LocalInfos: LocalInfos,
		},
		ObjectMeta: metav1.ObjectMeta{
			UID:       apitypes.UID(uuid),
			Namespace: namespace,
			Name:      name,
			Labels:    map[string]string{},
		},
	}
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

type snatTest struct {
	uuid       string
	poduuid    string
	namespace  string
	name       string
	ip         string
	mac        string
	port_range portRange
	nodename   string
}

var snatTests = []snatTest{
	{
		"730a8e7a-8455-4d46-8e6e-n4fdf0e3a688",
		"730a8e7a-8455-4d46-8e6e-f4fdf0e3a667",
		"testns",
		"pod1",
		"10.1.1.8",
		"00:0c:29:92:fe:d0",
		portRange{4000, 5000},
		"test-node",
	},
	{
		"730a8e7a-8455-4d46-8e6e-n4fdf0e3a655",
		"6a281ef1-0fcb-4140-a38c-62977ef25d72",
		"testns",
		"pod2",
		"10.1.1.8",
		"00:0c:29:92:fe:d0",
		portRange{4000, 5000},
		"test-node",
	},
	{
		"730a8e7a-8455-4d46-8e6e-n4fdf0e3a655",
		"6a281ef1-0fcb-4140-a38c-62977ef25d71",
		"testns",
		"pod3",
		"10.1.1.8",
		"00:0c:29:92:fe:d0",
		portRange{4000, 5000},
		"test-node",
	},
	{
		"730a8e7a-8455-4d46-8e6e-n4fdf0e3a655",
		"6a281ef1-0fcb-4140-a38c-62977ef25d73",
		"testns",
		"pod3",
		"10.1.1.8",
		"00:0c:29:92:fe:d1",
		portRange{9000, 10000},
		"test-node1",
	},
	{
		"730a8e7a-8455-4d46-8e6e-n4fdf0e3a665",
		"6a281ef1-0fcb-4140-a38c-62977ef25d74",
		"testns",
		"pod4",
		"10.1.1.8",
		"00:0c:29:92:fe:d3",
		portRange{11000, 120000},
		"test-node3",
	},
	/*
		{
			"",
			"683c333d-a594-4f00-baa6-0d578a13d83a",
			"testns",
			"pod3",
			"10.1.1.10",
			"52:54:00:e5:26:57",
			portRange {5000, 6000},
			egAnnot,
			sgAnnot,
		},
	*/
}

func (agent *testHostAgent) doTestSnat(t *testing.T, tempdir string,
	pt *snatTest, desc string) {
	var raw []byte
	snat := &OpflexSnatIp{}

	tu.WaitFor(t, pt.name, 100*time.Millisecond,
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
}

func TestSnatSync(t *testing.T) {
	tempdir, err := ioutil.TempDir("", "hostagent_test_")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tempdir)
	LocalInfos = make(map[string]snatlocal.LocalInfo, 10)
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
		time.Sleep(1000 * time.Millisecond)
		//agent.doTestPod(t, tempdir, &pt, "create")
	}
	var newglobal []snatglobal.GlobalInfo
	var snatglobalinfo *snatglobal.SnatGlobalInfo
	for i, pt := range snatTests {
		if i%2 == 0 {
			ioutil.WriteFile(filepath.Join(tempdir,
				pt.uuid+".snat"),
				[]byte("random gibberish"), 0644)
		}

		snatlocalinfo := snatlocaldata(pt.uuid, pt.poduuid, pt.namespace, pt.name, pt.ip)
		portrange := make([]snatglobal.PortRange, 1)
		portrange[0].Start = pt.port_range.start
		var globalinfo snatglobal.GlobalInfo
		portrange[0].End = pt.port_range.end
		globalinfo.MacAddress = pt.mac
		globalinfo.SnatIp = pt.ip
		globalinfo.SnatIpUid = pt.uuid
		globalinfo.PortRanges = portrange
		if i == 0 {
			newglobal = append(newglobal, globalinfo)
		}
		for _, v := range newglobal {
			if v.SnatIp != pt.ip {
				newglobal = append(newglobal, globalinfo)
			}
		}
		snatglobalinfo = snatglobaldata(pt.uuid, pt.name, pt.nodename, pt.namespace, newglobal)
		if i < 3 {
			agent.fakeSnatLocalSource.Add(snatlocalinfo)
		}
		time.Sleep(3000 * time.Millisecond)
		agent.fakeSnatGlobalSource.Add(snatglobalinfo)
		agent.doTestSnat(t, tempdir, &pt, "create")
	}
	var newglobal1 []snatglobal.GlobalInfo
	for i, pt := range snatTests {
		snatlocalinfo := snatlocaldata(pt.uuid, pt.poduuid, pt.namespace, pt.name, pt.ip)
		portrange := make([]snatglobal.PortRange, 1)
		portrange[0].Start = pt.port_range.start
		var globalinfo snatglobal.GlobalInfo
		portrange[0].End = pt.port_range.end
		globalinfo.MacAddress = pt.mac
		globalinfo.SnatIp = pt.ip
		globalinfo.SnatIpUid = pt.uuid
		globalinfo.PortRanges = portrange
		if i == 0 {
			newglobal1 = append(newglobal1, globalinfo)
		}
		for _, v := range newglobal {
			if v.SnatIp != pt.ip {
				newglobal1 = append(newglobal1, globalinfo)
			}
		}
		snatglobalinfo = snatglobaldata(pt.uuid, pt.name, pt.nodename, pt.namespace, newglobal)
		if i < 3 {
			agent.fakeSnatLocalSource.Add(snatlocalinfo)
		}
		time.Sleep(3000 * time.Millisecond)
		agent.fakeSnatGlobalSource.Add(snatglobalinfo)
		agent.doTestSnat(t, tempdir, &pt, "update")
	}
	/*
		time.Sleep(3000 * time.Millisecond)
		var newglobal1 []snatglobal.GlobalInfo
		for _, pt := range snatTests {
			snatlocalinfo := snatlocaldata(pt.uuid, pt.poduuid, pt.namespace, pt.name, pt.ip)
			portrange := make([]snatglobal.PortRange, 1)
			portrange[0].Start = pt.port_range.start
			portrange[0].End = pt.port_range.end
			var globalinfo snatglobal.GlobalInfo
			globalinfo.MacAddress = pt.mac
			globalinfo.NodeName = "test-node"
			globalinfo.SnatIpUid = pt.uuid
			globalinfo.PortRanges = portrange
			newglobal1 = append(newglobal1, globalinfo)
			snatglobalinfo = snatglobaldata(pt.uuid, pt.name, pt.ip, pt.namespace, newglobal1)
			agent.fakeSnatSource.Add(snatlocalinfo)
			time.Sleep(3000 * time.Millisecond)
			agent.fakeSnatSource.Add(snatglobalinfo)
			agent.doTestSnat(t, tempdir, &pt, "update")
		}
	*/
	time.Sleep(3000 * time.Millisecond)
	for _, pt := range podTests {
		pod := pod(pt.uuid, pt.namespace, pt.name, pt.eg, pt.sg)
		cnimd := cnimd(pt.namespace, pt.name, pt.ip, pt.cont, pt.veth)
		agent.epMetadata[pt.namespace+"/"+pt.name] =
			map[string]*metadata.ContainerMetadata{
				cnimd.Id.ContId: cnimd,
			}
		agent.fakePodSource.Delete(pod)
		time.Sleep(1000 * time.Millisecond)
	}
	/*
		for _, pt := range snatTests {
			agent.fakeSnatSource.Delete(snat)

			tu.WaitFor(t, pt.name, 100*time.Millisecond,
				func(last bool) (bool, error) {
					snatfile := filepath.Join(tempdir,
						pt.uuid+".snat")
					_, err := ioutil.ReadFile(snatfile)
					return tu.WaitNotNil(t, last, err, "snat deleted"), nil
				})
		}
	*/
	agent.stop()
}
