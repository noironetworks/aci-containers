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

package controller

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"

	"github.com/noironetworks/aci-containers/pkg/ipam"
	"github.com/noironetworks/aci-containers/pkg/metadata"
)

type ipRangeSorter struct {
	IPRanges []ipam.IpRange
}

func (irs *ipRangeSorter) Len() int {
	return len(irs.IPRanges)
}

func (irs *ipRangeSorter) Swap(i, j int) {
	irs.IPRanges[i], irs.IPRanges[j] = irs.IPRanges[j], irs.IPRanges[i]
}

// is i less than j?
func (irs *ipRangeSorter) Less(i, j int) bool {
	return bytes.Compare(irs.IPRanges[i].Start, irs.IPRanges[j].Start) < 0
}

func (irs *ipRangeSorter) Print() {
	raw, err := json.Marshal(irs.IPRanges)
	if err != nil {
		logrus.Errorf("Error marshaling: %v", err)
		return
	}
	logrus.Info(string(raw))
}

type nodeRec struct {
	sync.Mutex
	updates int
	nodes   map[string]*v1.Node
}

func (nr *nodeRec) Update(n *v1.Node) {
	nr.Lock()
	nr.updates++
	nr.nodes[n.ObjectMeta.Name] = n
	nr.Unlock()
}

func (nr *nodeRec) ValidatePodNets(verbose bool) error {
	// extract podnets from each node
	var podIpr ipRangeSorter
	nr.Lock()
	for name, n := range nr.nodes {
		if verbose {
			logrus.Infof("Node: %s podNets: %s", name, n.ObjectMeta.Annotations[metadata.PodNetworkRangeAnnotation])
		}
		pnet := metadata.NetIps{}
		err := json.Unmarshal([]byte(n.ObjectMeta.Annotations[metadata.PodNetworkRangeAnnotation]), &pnet)
		if err != nil {
			return err
		}

		podIpr.IPRanges = append(podIpr.IPRanges, pnet.V4...)
	}
	nr.Unlock()

	if verbose {
		podIpr.Print()
	}
	// validate the extracted pod IP range from all nodes.
	sort.Sort(&podIpr)
	if verbose {
		logrus.Infof("sorted podIpr: ")
		podIpr.Print()
	}

	// look for overlaps, duplicates
	var prev ipam.IpRange

	for _, ipr := range podIpr.IPRanges {
		if bytes.Compare(ipr.Start, ipr.End) > 0 {
			return fmt.Errorf("Bad range %+v", ipr)
		}

		err := checkOverlap(&prev, &ipr, verbose)
		if err != nil {
			return err
		}

		prev = ipr
	}

	logrus.Infof("Validated %d net ranges", len(podIpr.IPRanges))
	return nil
}

func checkOverlap(first, second *ipam.IpRange, verbose bool) error {
	if verbose {
		raw1, err := json.Marshal(first)
		if err != nil {
			return err
		}
		raw2, err := json.Marshal(second)
		if err != nil {
			return err
		}

		logrus.Infof("checkOverlap: %s vs %s", string(raw1), string(raw2))
	}

	if bytes.Compare(first.Start, second.Start) == 0 {
		return fmt.Errorf("Duplicate found %+v, %+v", first, second)
	}

	if bytes.Compare(first.End, second.Start) >= 0 {
		return fmt.Errorf("Overlap found %+v, %+v", first, second)
	}

	return nil
}

func TestPodNetAnnotStress(t *testing.T) {
	testNodeRec := &nodeRec{
		nodes: make(map[string]*v1.Node),
	}
	cont := testController()
	cont.config.PodIpPoolChunkSize = 128
	cont.config.PodIpPool = []ipam.IpRange{
		{Start: net.ParseIP("10.128.2.2"), End: net.ParseIP("10.128.16.1")},
	}
	cont.updateNode = func(node *v1.Node) (*v1.Node, error) {
		testNodeRec.Update(node)
		return node, nil
	}

	cont.AciController.initIpam()
	cont.run()
	setupODev(cont, "node2", true)

	nodeAdder := func(start, end int) {
		for ix := start; ix < end; ix++ {
			nodeName := fmt.Sprintf("node%d", ix)
			n := node(nodeName)
			cont.fakeNodeSource.Add(n)
		}
	}
	// add 8 nodes
	nodeAdder(1, 8)

	podAdder := func(n, start, end int) {
		nodeName := fmt.Sprintf("node%d", n)
		for ix := start; ix < end; ix++ {
			podName := fmt.Sprintf("testPod%d", ix)
			cont.fakeNodeSource.Add(node(nodeName))
			cont.fakePodSource.Add(podOnNode("testns", podName, nodeName))
		}
	}

	time.Sleep(time.Second)
	err := testNodeRec.ValidatePodNets(false)
	if err != nil {
		testNodeRec.ValidatePodNets(true)
		t.Fatalf("Initial alloc failed - %v", err)
	}

	podId := 1
	for total := 0; total < 3000; {
		count := int(time.Now().UnixNano() % 61)
		podAdder(1, podId, podId+count)
		total += count
		time.Sleep(200 * time.Millisecond)
		err = testNodeRec.ValidatePodNets(false)
		if err != nil {
			t.Errorf("Validation failed - %v", err)
			testNodeRec.ValidatePodNets(true)
			t.Errorf("Total: %v, count: %v", total, count)
			break
		}

		count = int(time.Now().UnixNano() % 17)
		podAdder(6, podId, podId+count)
		total += count
		time.Sleep(200 * time.Millisecond)
		err = testNodeRec.ValidatePodNets(false)
		if err != nil {
			t.Errorf("Validation failed - %v", err)
			testNodeRec.ValidatePodNets(true)
			t.Errorf("Total: %v, count: %v", total, count)
			break
		}

		podId += 90
	}

	cont.stop()
}
