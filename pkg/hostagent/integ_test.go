// Copyright 2018 Cisco Systems, Inc.
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
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cnitypes "github.com/containernetworking/cni/pkg/types"
	"github.com/noironetworks/aci-containers/pkg/eprpcclient"
	"github.com/noironetworks/aci-containers/pkg/ipam"
	"github.com/noironetworks/aci-containers/pkg/metadata"
	snatglobal "github.com/noironetworks/aci-containers/pkg/snatglobalinfo/apis/aci.snat/v1"
	tu "github.com/noironetworks/aci-containers/pkg/testutil"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	apitypes "k8s.io/apimachinery/pkg/types"
)

const (
	testPodNS    = "itPodNS"
	testNetNS    = "/var/run/netns/integns"
	rpcSock      = "/tmp/aci-containers-ep-rpc.sock"
	testPodID    = "8ec72deca647bfa60a4b815aa735c87de859b47e87"
	testIfName   = "testeth1"
	testEgAnnot1 = "{\"tenant\": \"testps\", " +
		"\"app-profile\": \"test-prof\", \"name\": \"test-eg\"}"
	testEgAnnot2 = "{\"tenant\": \"testps\", " +
		"\"name\": \"foo|bar\"}"
	testEgAnnot3 = "{\"tenant\": \"testps\", " +
		"\"app-profile\": \"test-prof\", \"name\": \"ann-ns-eg\"}"
	testEgAnnot4 = "{\"tenant\": \"testps\", " +
		"\"app-profile\": \"test-prof\", \"name\": \"ann-depl-eg\"}"
	testEgAnnot5 = "{\"tenant\": \"testps\", " +
		"\"app-profile\": \"test-prof\", \"name\": \"ann-rc-eg\"}"
	emptyJSON = "null"

	sgAnnot1 = "[{\"policy-space\":\"testps\",\"name\":\"test-sg1\"}]"

	sgAnnot2 = "[{\"policy-space\":\"testps\",\"name\":\"test-sg1\"}, {\"policy-space\":\"testps\",\"name\":\"test-sg2\"}]"
	sgAnnot3 = "[{\"policy-space\":\"testps\",\"name\":\"test-sg1\"}, {\"policy-space\":\"testps\",\"name\":\"test-sg3\"}]"

	sgAnnotNP1 = "[{\"policy-space\":\"tenantA\",\"name\":\"it_np_annNS_np1\"}," +
		"{\"policy-space\":\"tenantA\",\"name\":\"it_node_test-node\"}," +
		"{\"policy-space\":\"tenantA\",\"name\":\"it_np_static-discovery\"}," +
		"{\"policy-space\":\"tenantA\",\"name\":\"it_np_static-egress\"}]"
	sgAnnotNP2 = "[{\"policy-space\":\"tenantA\",\"name\":\"it_np_annNS_np1\"}," +
		"{\"policy-space\":\"tenantA\",\"name\":\"it_np_annNS_np2\"}," +
		"{\"policy-space\":\"tenantA\",\"name\":\"it_node_test-node\"}," +
		"{\"policy-space\":\"tenantA\",\"name\":\"it_np_static-discovery\"}," +
		"{\"policy-space\":\"tenantA\",\"name\":\"it_np_static-egress\"}]"
)

type buildIpam struct {
	annotation string
	freeListV4 []ipam.IpRange
	freeListV6 []ipam.IpRange
	desc       string
}

var itIpam = buildIpam{
	"{\"V4\":[{\"start\":\"10.128.2.130\",\"end\":\"10.128.3.1\"},{\"start\":\"10.128.3.2\",\"end\":\"10.128.3.129\"},{\"start\":\"10.128.3.130\",\"end\":\"10.128.4.1\"},{\"start\":\"10.128.4.2\",\"end\":\"10.128.4.129\"},{\"start\":\"10.128.4.130\",\"end\":\"10.128.5.1\"},{\"start\":\"10.128.6.130\",\"end\":\"10.128.7.1\"},{\"start\":\"10.128.5.2\",\"end\":\"10.128.5.129\"},{\"start\":\"10.128.2.2\",\"end\":\"10.128.2.129\"},{\"start\":\"10.128.5.130\",\"end\":\"10.128.6.129\"},{\"start\":\"10.128.5.130\",\"end\":\"10.128.6.129\"},{\"start\":\"10.128.7.2\",\"end\":\"10.128.9.1\"},{\"start\":\"10.128.7.2\",\"end\":\"10.128.8.129\"} ],\"V6\":null}",
	[]ipam.IpRange{
		{Start: net.ParseIP("10.128.2.2"), End: net.ParseIP("10.128.9.1")},
	},
	[]ipam.IpRange{},
	"v4 with duplicates",
}

var updIpams = []buildIpam{
	{
		"{\"V4\":[{\"start\":\"10.128.2.130\",\"end\":\"10.128.3.1\"},{\"start\":\"10.128.3.2\",\"end\":\"10.128.3.129\"},{\"start\":\"10.128.3.130\",\"end\":\"10.128.4.1\"},{\"start\":\"10.128.4.2\",\"end\":\"10.128.4.129\"},{\"start\":\"10.128.4.130\",\"end\":\"10.128.5.1\"},{\"start\":\"10.128.6.130\",\"end\":\"10.128.7.1\"},{\"start\":\"10.128.5.2\",\"end\":\"10.128.5.129\"},{\"start\":\"10.128.2.2\",\"end\":\"10.128.2.129\"},{\"start\":\"10.128.5.130\",\"end\":\"10.128.6.129\"},{\"start\":\"10.128.5.130\",\"end\":\"10.128.6.129\"},{\"start\":\"10.128.7.2\",\"end\":\"10.128.9.1\"},{\"start\":\"10.128.7.2\",\"end\":\"10.128.8.129\"} ],\"V6\":null}",
		[]ipam.IpRange{
			{Start: net.ParseIP("10.128.2.2"), End: net.ParseIP("10.128.9.1")},
		},
		[]ipam.IpRange{},
		"v4 with duplicates",
	},
	{
		"{\"V4\":[{\"start\":\"10.128.2.130\",\"end\":\"10.128.3.1\"},{\"start\":\"10.128.3.2\",\"end\":\"10.128.3.129\"},{\"start\":\"10.128.3.130\",\"end\":\"10.128.4.1\"},{\"start\":\"10.128.4.2\",\"end\":\"10.128.4.129\"},{\"start\":\"10.128.4.130\",\"end\":\"10.128.5.1\"},{\"start\":\"10.128.6.130\",\"end\":\"10.128.7.1\"},{\"start\":\"10.128.5.2\",\"end\":\"10.128.5.129\"},{\"start\":\"10.128.2.2\",\"end\":\"10.128.2.129\"},{\"start\":\"10.128.5.130\",\"end\":\"10.128.6.129\"} ],\"V6\":null}",
		[]ipam.IpRange{
			{Start: net.ParseIP("10.128.2.2"), End: net.ParseIP("10.128.7.1")},
		},
		[]ipam.IpRange{},
		"v4 with duplicates",
	},
}

// hostagent integration set up
type integ struct {
	t      *testing.T
	ta     *testHostAgent
	hcf    *HostAgentConfig
	testNS string
}

func SetupInteg(t *testing.T, c *HostAgentConfig) *integ {
	cnidir, err := ioutil.TempDir("", "it_cni_")
	if err != nil {
		panic(err)
	}

	epdir, err := ioutil.TempDir("", "it_ep_")
	if err != nil {
		panic(err)
	}

	svcdir, err := ioutil.TempDir("", "it_svc_")
	if err != nil {
		panic(err)
	}
	snatdir, err := ioutil.TempDir("", "it_snat_")
	if err != nil {
		panic(err)
	}

	it := &integ{t: t, testNS: testPodNS, hcf: c}
	it.hcf.CniMetadataDir = cnidir
	it.hcf.OpFlexEndpointDir = epdir
	it.hcf.OpFlexServiceDir = svcdir
	it.hcf.OpFlexSnatDir = snatdir
	PluginCloner.Stub = true
	it.ta = testAgentWithConf(c)
	it.ta.run()

	return it
}

func (it *integ) tearDown() {
	it.ta.stop()
	os.RemoveAll(it.hcf.CniMetadataDir)
	os.RemoveAll(it.hcf.OpFlexEndpointDir)
	os.RemoveAll(it.hcf.OpFlexServiceDir)
	os.RemoveAll(it.hcf.OpFlexSnatDir)
}

func (it *integ) setupNode(ipam buildIpam, wait bool) {
	it.ta.indexMutex.Lock()

	if it.ta.epMetadata == nil {
		it.ta.epMetadata =
			make(map[string]map[string]*metadata.ContainerMetadata)
	}
	node := &v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: it.hcf.NodeName,
			Annotations: map[string]string{
				metadata.PodNetworkRangeAnnotation: ipam.annotation,
			},
		},
	}
	it.ta.indexMutex.Unlock()
	it.ta.fakeNodeSource.Add(node)
	if !wait {
		return
	}

	tu.WaitFor(it.t, ipam.desc, 100*time.Millisecond,
		func(last bool) (bool, error) {
			it.ta.indexMutex.Lock()
			defer it.ta.indexMutex.Unlock()
			return tu.WaitEqual(it.t, last, ipam.freeListV4,
				it.ta.podIps.CombineV4(), ipam.desc) &&
				tu.WaitEqual(it.t, last, ipam.freeListV4,
					it.ta.podIps.CombineV4(), ipam.desc), nil
		})
}

func (it *integ) cniAddParallel(start, end int) {
	if start >= end {
		return
	}
	var wg sync.WaitGroup
	wg.Add(end - start)
	for ix := start; ix < end; ix++ {
		go func(id int) {
			defer wg.Done()
			name := fmt.Sprintf("pod%d", id)
			cid := fmt.Sprintf("%d%s", id, testPodID)
			err := it.cniAdd(name, cid, testIfName)
			if err != nil {
				it.t.Error(err)
			}
		}(ix)
	}

	log.Infof("Waiting for %d Adds to finish", end-start)
	wg.Wait()
}

func (it *integ) cniDelParallel(start, end int) {
	if start >= end {
		return
	}
	var wg sync.WaitGroup
	wg.Add(end - start)
	for ix := start; ix < end; ix++ {
		go func(id int) {
			defer wg.Done()
			name := fmt.Sprintf("pod%d", id)
			cid := fmt.Sprintf("%d%s", id, testPodID)
			err := it.cniDel(name, cid)
			if err != nil {
				it.t.Error(err)
			}
		}(ix)
	}

	log.Infof("Waiting for %d Deletes to finish", end-start)
	wg.Wait()
}

func (it *integ) checkEpGroups(id int, epg, sg string) {
	epid := fmt.Sprintf("%d%s_%d%s_", id, testPodID, id, testPodID)
	epfile := it.ta.FormEPFilePath(epid)
	var secGroups []metadata.OpflexGroup
	err := json.Unmarshal([]byte(sg), &secGroups)
	assert.Equal(it.t, nil, err)

	tu.WaitFor(it.t, "checking epg in epfile", 100*time.Millisecond,
		func(last bool) (bool, error) {
			var ep opflexEndpoint
			epRaw, err := getEp(epfile)
			if err == nil {
				err = json.Unmarshal([]byte(epRaw), &ep)
			}
			log.Infof("EP Raw Data %v", epRaw)
			log.Infof("EP Raw Data %v", err)

			epgRes := tu.WaitEqual(it.t, last, epg, ep.EndpointGroup, "epg does not match") && tu.WaitEqual(it.t, last, err, nil, "epg file read error")
			if epgRes {
				// sec group is an unordered list
				return assert.ElementsMatch(it.t, secGroups, ep.SecurityGroup, "sec group does not match"), nil
			}

			return false, nil
		})
}

func (it *integ) addPodObj(id int, ns, eg, sg string, labels map[string]string) {
	name := fmt.Sprintf("pod%d", id)
	cid := fmt.Sprintf("%d%s", id, testPodID)

	p := mkPod(cid, ns, name, eg, sg, labels)
	it.ta.fakePodSource.Add(p)
}

func (it *integ) cniAdd(podName, cid, ifname string) error {

	md := metadata.ContainerMetadata{
		Id: metadata.ContainerId{
			ContId:    cid,
			Namespace: it.testNS,
			Pod:       podName,
		},
		Ifaces: []*metadata.ContainerIfaceMd{
			{
				HostVethName: "eth0",
				Name:         ifname,
				Sandbox:      testNetNS,
			},
		},
	}

	eprpc, err := eprpcclient.NewClient(rpcSock, time.Millisecond*500)
	if err != nil {
		return err
	}
	defer eprpc.Close()

	_, err = eprpc.Register(&md)
	return err
}

func (it *integ) cniDel(podName, cid string) error {
	eprpc, err := eprpcclient.NewClient(rpcSock, time.Millisecond*500)
	if err != nil {
		return err
	}

	defer eprpc.Close()
	md := metadata.ContainerId{
		ContId:    cid,
		Namespace: it.testNS,
		Pod:       podName,
	}

	_, err = eprpc.Unregister(&md)
	return err
}

func mkPod(uuid string, namespace string, name string,
	egAnnot string, sgAnnot string, labels map[string]string) *v1.Pod {
	return &v1.Pod{
		Spec: v1.PodSpec{
			NodeName: "test-node",
		},
		ObjectMeta: metav1.ObjectMeta{
			UID:       apitypes.UID(uuid),
			Namespace: namespace,
			Name:      name,
			Annotations: map[string]string{
				metadata.EgAnnotation: egAnnot,
				metadata.SgAnnotation: sgAnnot,
			},
			Labels: labels,
		},
	}
}

func TestIPAM(t *testing.T) {
	poolSizes := make([]int64, len(updIpams))
	ncf := cniNetConfig{Subnet: cnitypes.IPNet{IP: net.ParseIP("10.128.2.0"), Mask: net.CIDRMask(24, 32)}}
	hcf := &HostAgentConfig{
		NodeName:  "node1",
		EpRpcSock: "/tmp/aci-containers-ep-rpc.sock",
		NetConfig: []cniNetConfig{ncf},
	}

	it := SetupInteg(t, hcf)
	defer it.tearDown()

	ipCounter := func() int64 {
		var total int64
		it.ta.ipamMutex.Lock()
		defer it.ta.ipamMutex.Unlock()

		ipaList := it.ta.podIps.GetV4IpCache()
		for _, ipa := range ipaList {
			total += ipa.GetSize()
		}

		return total
	}

	for ix, am := range updIpams {
		it.setupNode(am, true)
		poolSizes[ix] = ipCounter()
		log.Infof("IP pool size is %v", poolSizes[ix])
	}

	// schedule annotation update in the background
	stopCh := make(chan bool)
	go func() {
		var ix int
		for {
			select {
			case <-stopCh:
				return
			case <-time.After(2 * time.Millisecond):
				it.setupNode(updIpams[ix], false)
			}

			ix++
			if ix > 1 {
				ix = 0
			}
		}
	}()

	for jx := 0; jx < 2000; jx++ {
		count := 16
		it.cniAddParallel(0, count)

		used, err := metadata.CheckMetadata(it.hcf.CniMetadataDir, "")
		if err != nil {
			t.Fatal(err)
		}

		// check for leaks
		avail := ipCounter()
		ipCount := used + avail
		if ipCount != poolSizes[0] && ipCount != poolSizes[1] {
			t.Fatalf("ADD Iter: %d IP addr leak -- total: %v used: %v avail: %v", jx, poolSizes, used, avail)
		}

		it.cniDelParallel(0, count)
		// check for leaks
		used, err = metadata.CheckMetadata(it.hcf.CniMetadataDir, "")
		if err != nil {
			t.Fatal(err)
		}
		avail = ipCounter()
		ipCount = used + avail
		if ipCount != poolSizes[0] && ipCount != poolSizes[1] {
			t.Fatalf("DEL Iter: %d IP addr leak -- total: %v used: %v avail: %v", jx, poolSizes, used, avail)
		}

	}

	close(stopCh)
	time.Sleep(200 * time.Millisecond)
}

func TestEPDelete(t *testing.T) {
	ncf := cniNetConfig{Subnet: cnitypes.IPNet{IP: net.ParseIP("10.128.2.0"), Mask: net.CIDRMask(24, 32)}}
	hcf := &HostAgentConfig{
		NodeName:  "node1",
		EpRpcSock: "/tmp/aci-containers-ep-rpc.sock",
		NetConfig: []cniNetConfig{ncf},
		AciPrefix: "it",
		GroupDefaults: GroupDefaults{
			DefaultEg: metadata.OpflexGroup{
				PolicySpace: "tenantA",
				Name:        "defaultEPG",
			},

			NamespaceDefaultEg: map[string]metadata.OpflexGroup{
				"ns1": {
					PolicySpace: "tenantA",
					Name:        "ns1EPG",
				},
				"ns2": {
					PolicySpace: "tenantA",
					Name:        "ns2EPG",
				},
			},
		},
	}

	it := SetupInteg(t, hcf)
	it.setupNode(itIpam, true)
	defer it.tearDown()

	// Add pods intf via cni
	it.cniAddParallel(0, 2)

	time.Sleep(10 * time.Millisecond)
	it.addPodObj(0, testPodNS, "", "", nil)
	it.addPodObj(1, testPodNS, testEgAnnot1, "", nil)
	time.Sleep(1000 * time.Millisecond)

	// verify ep file
	it.checkEpGroups(0, "defaultEPG", emptyJSON)
	it.checkEpGroups(1, "test-prof|test-eg", emptyJSON)
	it.cniDelParallel(0, 2)

	// verify ep files are deleted
	delVerify := func(id int) {
		epid := fmt.Sprintf("%d%s_%d%s_", id, testPodID, id, testPodID)
		epfile := it.ta.FormEPFilePath(epid)
		tu.WaitFor(it.t, "checking in epfile delete", 100*time.Millisecond,
			func(last bool) (bool, error) {
				_, err := getEp(epfile)
				return tu.WaitNotEqual(it.t, last, err, nil, "epfile not removed"), nil
			})
	}

	for id := 0; id < 2; id++ {
		delVerify(id)
	}
}

func TestGroupAssign(t *testing.T) {
	ncf := cniNetConfig{Subnet: cnitypes.IPNet{IP: net.ParseIP("10.128.2.0"), Mask: net.CIDRMask(24, 32)}}
	hcf := &HostAgentConfig{
		NodeName:  "node1",
		EpRpcSock: "/tmp/aci-containers-ep-rpc.sock",
		NetConfig: []cniNetConfig{ncf},
		AciPrefix: "it",
		GroupDefaults: GroupDefaults{
			DefaultEg: metadata.OpflexGroup{
				PolicySpace: "tenantA",
				Name:        "defaultEPG",
			},

			NamespaceDefaultEg: map[string]metadata.OpflexGroup{
				"ns1": {
					PolicySpace: "tenantA",
					Name:        "ns1EPG",
				},
				"ns2": {
					PolicySpace: "tenantA",
					Name:        "ns2EPG",
				},
			},
		},
	}

	it := SetupInteg(t, hcf)
	it.setupNode(itIpam, true)
	defer it.tearDown()

	// add an annotated namespace
	it.ta.fakeNamespaceSource.Add(mkNamespace("annNS", testEgAnnot3, sgAnnot1))

	// add an annotated deployment
	it.ta.fakeDeploymentSource.Add(mkDeployment("annNS", "testDeployment", testEgAnnot4, sgAnnot2))

	// add an RC without annotation
	rc1 := mkRC("annNS", "rcNoAnn", "", "")
	rc1.Spec.Selector = map[string]string{"app": "rc-app"}
	it.ta.fakeRCSource.Add(rc1)

	// add an annotated rc
	rc2 := mkRC("annNS", "rcWithAnn", testEgAnnot5, sgAnnot2)
	rc2.Spec.Selector = map[string]string{"app": "rc-ann-app"}
	it.ta.fakeRCSource.Add(rc2)

	// add an annotated rc, no selector, set labels in template
	templRC := mkRC("annNS", "noSelRC", testEgAnnot5, sgAnnot2)
	templRC.Spec.Template.Labels = map[string]string{"app": "nosel-app"}
	it.ta.fakeRCSource.Add(templRC)

	// Add pods intf via cni
	it.cniAddParallel(0, 2)
	it.testNS = "ns1"
	it.cniAddParallel(2, 3)
	it.testNS = "ns2"
	it.cniAddParallel(3, 5)
	it.testNS = "annNS"
	it.cniAddParallel(5, 10)

	time.Sleep(10 * time.Millisecond)
	it.addPodObj(0, testPodNS, "", "", nil)
	it.addPodObj(1, testPodNS, testEgAnnot1, "", nil)
	it.addPodObj(2, "ns1", "", "", nil)
	it.addPodObj(3, "ns2", "", "", nil)
	it.addPodObj(4, "ns2", testEgAnnot2, sgAnnot3, nil)
	it.addPodObj(5, "annNS", "", "", nil)
	depLabels := map[string]string{
		"app":  "sample-app",
		"tier": "sample-tier",
		"deer": "dear",
	}

	it.addPodObj(6, "annNS", "", "", depLabels)

	rcLabels1 := map[string]string{
		"app":  "rc-app",
		"tier": "sample-tier",
		"deer": "dear",
	}

	rcLabels2 := map[string]string{
		"app":  "rc-ann-app",
		"tier": "sample-tier",
		"deer": "dear",
	}

	rcLabels3 := map[string]string{
		"app":  "nosel-app",
		"tier": "sample-tier",
		"deer": "dear",
	}

	it.addPodObj(7, "annNS", "", "", rcLabels1)
	it.addPodObj(8, "annNS", "", "", rcLabels2)
	it.addPodObj(9, "annNS", "", "", rcLabels3)

	// verify ep file
	it.checkEpGroups(0, "defaultEPG", emptyJSON)
	it.checkEpGroups(1, "test-prof|test-eg", emptyJSON)
	it.checkEpGroups(2, "ns1EPG", emptyJSON)
	it.checkEpGroups(3, "ns2EPG", emptyJSON)
	it.checkEpGroups(4, "foo|bar", sgAnnot3)
	it.checkEpGroups(5, "test-prof|ann-ns-eg", sgAnnot1)
	it.checkEpGroups(6, "test-prof|ann-depl-eg", sgAnnot2)
	it.checkEpGroups(7, "test-prof|ann-ns-eg", sgAnnot1)
	it.checkEpGroups(8, "test-prof|ann-rc-eg", sgAnnot2)
	it.checkEpGroups(9, "test-prof|ann-rc-eg", sgAnnot2)

	it.cniDelParallel(5, 10)
	it.testNS = "ns2"
	it.cniDelParallel(3, 5)
	it.testNS = "ns1"
	it.cniDelParallel(2, 3)
	it.testNS = testPodNS
	it.cniDelParallel(0, 2)
}

func TestNPGroupAssign(t *testing.T) {
	ncf := cniNetConfig{Subnet: cnitypes.IPNet{IP: net.ParseIP("10.128.2.0"), Mask: net.CIDRMask(24, 32)}}
	hcf := &HostAgentConfig{
		NodeName:  "node1",
		EpRpcSock: "/tmp/aci-containers-ep-rpc.sock",
		NetConfig: []cniNetConfig{ncf},
		AciPrefix: "it",
		GroupDefaults: GroupDefaults{
			DefaultEg: metadata.OpflexGroup{
				PolicySpace: "tenantA",
				Name:        "defaultEPG",
			},
		},
	}

	it := SetupInteg(t, hcf)
	it.setupNode(itIpam, true)
	defer it.tearDown()

	// add an annotated namespace
	it.ta.fakeNamespaceSource.Add(mkNamespace("annNS", testEgAnnot3, ""))

	// add a default network policy
	it.ta.fakeNetworkPolicySource.Add(mkNetPol("annNS", "np1",
		&metav1.LabelSelector{}, nil, nil, nil))

	// add a selector based network policy
	it.ta.fakeNetworkPolicySource.Add(mkNetPol("annNS", "np2",
		&metav1.LabelSelector{
			MatchLabels: map[string]string{"foo": "bar"},
		}, nil, nil, nil))

	// Add pods intf via cni
	it.cniAddParallel(0, 1)
	it.testNS = "annNS"
	it.cniAddParallel(1, 3)

	time.Sleep(10 * time.Millisecond)
	it.addPodObj(0, testPodNS, "", "", nil)
	p1Labels := map[string]string{
		"foo":  "rod",
		"tier": "sample-tier",
	}
	it.addPodObj(1, "annNS", "", "", p1Labels)

	p2Labels := map[string]string{
		"foo":  "bar",
		"tier": "sample-tier",
	}
	it.addPodObj(2, "annNS", "", "", p2Labels)

	// verify ep file
	it.checkEpGroups(0, "defaultEPG", emptyJSON)
	it.checkEpGroups(1, "test-prof|ann-ns-eg", sgAnnotNP1)
	it.checkEpGroups(2, "test-prof|ann-ns-eg", sgAnnotNP2)

	it.cniDelParallel(1, 3)
	it.testNS = testPodNS
	it.cniDelParallel(0, 1)
}

func mkSnatGlobalObj() *snatglobal.SnatGlobalInfo {
	var newglobal []snatglobal.GlobalInfo
	for i, pt := range snatGlobals {
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
			}
		}
	}
	return snatglobaldata("123456", "snatglobalinfo", "test-node", "aci", newglobal)
}
func (it *integ) checkEpSnatUids(id int, uids []string, sg string) {
	epid := fmt.Sprintf("%d%s_%d%s_", id, testPodID, id, testPodID)
	epfile := it.ta.FormEPFilePath(epid)
	var ep opflexEndpoint
	tu.WaitFor(it.t, "checking epg in epfile", 2000*time.Millisecond,
		func(last bool) (bool, error) {
			epRaw, err := getEp(epfile)
			if !tu.WaitNil(it.t, last, err, "create", "Epfile", "read pod") {
				return false, nil
			}
			log.Infof("EP Raw Data %v", epRaw)
			log.Infof("EP Raw Data %v", err)
			err = json.Unmarshal([]byte(epRaw), &ep)
			if !reflect.DeepEqual(uids, ep.SnatUuid) {
				return false, nil
			}
			return tu.WaitNil(it.t, last, err, "create", "Epfile", "unmarshal snat"), nil
		})
	assert.Equal(it.t, uids, ep.SnatUuid, "create", "Epfile", "uids")
}

func TestSnatPolicy(t *testing.T) {
	ncf := cniNetConfig{Subnet: cnitypes.IPNet{IP: net.ParseIP("10.128.2.0"), Mask: net.CIDRMask(24, 32)}}
	hcf := &HostAgentConfig{
		NodeName:  "test-node",
		EpRpcSock: "/tmp/aci-containers-ep-rpc.sock",
		NetConfig: []cniNetConfig{ncf},
		AciPrefix: "it",
		GroupDefaults: GroupDefaults{
			DefaultEg: metadata.OpflexGroup{
				PolicySpace: "tenantA",
				Name:        "defaultEPG",
			},
		},
	}
	it := SetupInteg(t, hcf)
	it.ta.config.NodeName = "test-node"
	it.setupNode(itIpam, true)
	defer it.tearDown()

	// add an annotated namespace
	it.ta.fakeNamespaceSource.Add(mkNamespace("annNS", testEgAnnot3, ""))

	// Add pods intf via cni
	it.cniAddParallel(0, 1)
	it.testNS = "annNS"
	it.cniAddParallel(1, 3)

	time.Sleep(10 * time.Millisecond)
	it.addPodObj(0, testPodNS, "", "", nil)
	p1Labels := map[string]string{
		"foo":  "rod",
		"tier": "sample-tier",
	}
	it.addPodObj(1, "annNS", "", "", p1Labels)

	p2Labels := map[string]string{
		"foo":  "bar",
		"tier": "sample-tier",
	}
	it.addPodObj(2, "annNS", "", "", p2Labels)

	snatobj1 := snatpolicydata("policy1", "annNS", []string{"10.1.1.8"}, []string{"10.10.10.0/24"}, map[string]string{"foo": "rod"})
	snatobj2 := snatpolicydata("policy2", "annNS", []string{"10.1.1.9"}, []string{"10.10.0.0/16"}, map[string]string{"tier": "sample-tier"})
	it.ta.fakeSnatPolicySource.Add(snatobj1)
	it.ta.fakeSnatPolicySource.Add(snatobj2)
	time.Sleep(100 * time.Millisecond)
	it.ta.fakeSnatGlobalSource.Add(mkSnatGlobalObj())
	var uids []string
	uids = append(uids, "uid-policy1")
	uids = append(uids, "uid-policy2")
	it.checkEpSnatUids(1, uids, emptyJSON)
	uids = []string{}
	uids = append(uids, "uid-policy2")
	it.checkEpSnatUids(2, uids, emptyJSON)
	it.cniDelParallel(1, 3)
	it.testNS = testPodNS
	it.cniDelParallel(0, 1)
}

func TestSnatPolicyDep(t *testing.T) {
	ncf := cniNetConfig{Subnet: cnitypes.IPNet{IP: net.ParseIP("10.128.2.0"), Mask: net.CIDRMask(24, 32)}}
	hcf := &HostAgentConfig{
		NodeName:  "test-node",
		EpRpcSock: "/tmp/aci-containers-ep-rpc.sock",
		NetConfig: []cniNetConfig{ncf},
		AciPrefix: "it",
		GroupDefaults: GroupDefaults{
			DefaultEg: metadata.OpflexGroup{
				PolicySpace: "tenantA",
				Name:        "defaultEPG",
			},
		},
	}

	it := SetupInteg(t, hcf)
	it.setupNode(itIpam, true)
	defer it.tearDown()

	// add an annotated namespace
	it.ta.fakeNamespaceSource.Add(mkNamespace("annNS", testEgAnnot3, sgAnnot1))

	// add an annotated deployment
	it.ta.fakeDeploymentSource.Add(mkDeployment("annNS", "testDeployment", testEgAnnot4, sgAnnot2))

	it.testNS = "annNS"
	it.cniAddParallel(5, 10)

	time.Sleep(10 * time.Millisecond)
	it.addPodObj(5, "annNS", "", "", nil)
	depLabels := map[string]string{
		"app":  "sample-app",
		"tier": "sample-tier",
		"deer": "dear",
	}
	it.addPodObj(6, "annNS", "", "", depLabels)
	snatobj1 := snatpolicydata("policy1", "annNS", []string{"10.1.1.8"}, []string{"10.10.0.0/16", "172.192.153.0/26"}, map[string]string{"app": "sample-app"})
	snatobj2 := snatpolicydata("policy2", "annNS", []string{"10.1.1.9"}, []string{"10.10.10.10/31", "10.10.0.0/24"}, map[string]string{"deer": "dear"})
	it.ta.fakeSnatPolicySource.Add(snatobj1)
	time.Sleep(100 * time.Millisecond)
	it.ta.fakeSnatPolicySource.Add(snatobj2)
	time.Sleep(100 * time.Millisecond)
	it.ta.fakeSnatGlobalSource.Add(mkSnatGlobalObj())
	var uids []string
	uids = append(uids, "uid-policy2")
	uids = append(uids, "uid-policy1")
	it.checkEpSnatUids(6, uids, emptyJSON)
	it.ta.fakeSnatPolicySource.Delete(snatobj1)
	it.ta.fakeSnatPolicySource.Delete(snatobj2)
	time.Sleep(100 * time.Millisecond)
	it.ta.fakeSnatGlobalSource.Delete(mkSnatGlobalObj())
	var uids1 []string
	it.checkEpSnatUids(6, uids1, emptyJSON)
	it.cniDelParallel(5, 10)
	it.cniDelParallel(6, 10)
}
