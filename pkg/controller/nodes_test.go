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
	"encoding/json"
	"fmt"
	"net"
	"testing"
	"time"

	v1 "k8s.io/api/core/v1"

	"github.com/noironetworks/aci-containers/pkg/ipam"
	"github.com/noironetworks/aci-containers/pkg/metadata"

	"github.com/noironetworks/aci-containers/pkg/apicapi"
	tu "github.com/noironetworks/aci-containers/pkg/testutil"
	//"github.com/stretchr/testify/assert"
)

func waitForSEpAnnot(t *testing.T, cont *testAciController,
	ipv4 net.IP, ipv6 net.IP, mac *string, desc string) {

	tu.WaitFor(t, desc, 500*time.Millisecond,
		func(last bool) (bool, error) {
			if !tu.WaitCondition(t, last, func() bool {
				return len(cont.nodeUpdates) >= 1
			}, desc, "update") {
				return false, nil
			}

			annot := cont.nodeUpdates[len(cont.nodeUpdates)-1].
				ObjectMeta.Annotations[metadata.ServiceEpAnnotation]

			ep := &metadata.ServiceEndpoint{}
			err := json.Unmarshal([]byte(annot), ep)
			if !tu.WaitNil(t, last, err, desc, "unmarshal", err) {
				return false, nil
			}
			_, err = net.ParseMAC(ep.Mac)
			return tu.WaitNil(t, last, err, desc, "hardware addr parse", err) &&
				(mac == nil ||
					tu.WaitEqual(t, last, *mac, ep.Mac, desc, "mac")) &&
				tu.WaitEqual(t, last, ipv4, ep.Ipv4, desc, "ipv4") &&
				tu.WaitEqual(t, last, ipv6, ep.Ipv6, desc, "ipv6"), nil
		})
}

var odevMac = "aa:bb:cc:dd:ee:ff"

func setupODev(cont *testAciController, nodeName string, hasMac bool) {
	oDev := apicapi.EmptyApicObject("opflexODev", nodeName)
	oDev.SetAttr("hostName", nodeName)
	if hasMac {
		oDev.SetAttr("mac", odevMac)
	}
	oDev.SetAttr("fabricPathDn",
		"topology/pod-1/paths-301/pathep-[eth1/33]")
	cont.opflexDeviceChanged(oDev)
}

func TestServiceEpAnnotationV4(t *testing.T) {
	cont := testController()
	cont.config.NodeServiceIpPool = []ipam.IpRange{
		{Start: net.ParseIP("10.1.1.2"), End: net.ParseIP("10.1.1.3")},
	}
	cont.AciController.initIpam()
	cont.run()

	setupODev(cont, "node1", true)
	setupODev(cont, "node2", true)
	setupODev(cont, "node3", false)

	cont.fakeNodeSource.Add(node("node1"))
	waitForSEpAnnot(t, cont, net.ParseIP("10.1.1.2"), nil, &odevMac, "simple")

	cont.nodeUpdates = nil
	cont.fakeNodeSource.Add(node("node2"))
	waitForSEpAnnot(t, cont, net.ParseIP("10.1.1.3"), nil, &odevMac, "second")

	cont.nodeUpdates = nil
	cont.fakeNodeSource.Add(node("node3"))
	waitForSEpAnnot(t, cont, nil, nil, nil, "noneleft")

	cont.nodeUpdates = nil
	setupODev(cont, "node3", true)
	waitForSEpAnnot(t, cont, nil, nil, &odevMac, "odev update add mac")

	cont.stop()
}

func TestServiceEpAnnotationV6(t *testing.T) {
	cont := testController()
	cont.config.NodeServiceIpPool = []ipam.IpRange{
		{Start: net.ParseIP("fd43:85d7:bcf2:9ad2::2"), End: net.ParseIP("fd43:85d7:bcf2:9ad2::3")},
	}
	cont.AciController.initIpam()
	cont.run()

	setupODev(cont, "node1", false)
	setupODev(cont, "node2", true)
	setupODev(cont, "node3", true)

	cont.fakeNodeSource.Add(node("node1"))
	waitForSEpAnnot(t, cont, nil, net.ParseIP("fd43:85d7:bcf2:9ad2::2"),
		nil, "simple")

	cont.nodeUpdates = nil
	cont.fakeNodeSource.Add(node("node2"))
	waitForSEpAnnot(t, cont, nil, net.ParseIP("fd43:85d7:bcf2:9ad2::3"),
		&odevMac, "second")

	cont.nodeUpdates = nil
	cont.fakeNodeSource.Add(node("node3"))
	waitForSEpAnnot(t, cont, nil, nil, &odevMac, "noneleft")

	cont.stop()
}

func TestServiceEpAnnotationExisting(t *testing.T) {
	cont := testController()
	cont.config.NodeServiceIpPool = []ipam.IpRange{
		{Start: net.ParseIP("10.1.1.2"), End: net.ParseIP("10.1.1.4")},
		{Start: net.ParseIP("fd43:85d7:bcf2:9ad2::2"), End: net.ParseIP("fd43:85d7:bcf2:9ad2::4")},
	}
	cont.AciController.initIpam()
	cont.run()

	setupODev(cont, "node1", false)
	setupODev(cont, "node2", true)
	setupODev(cont, "node3", false)

	ep := &metadata.ServiceEndpoint{
		Ipv4: net.ParseIP("10.1.1.1"),
		Ipv6: net.ParseIP("fd43:85d7:bcf2:9ad2::1"),
	}
	n := node("node1")
	raw, _ := json.Marshal(ep)
	n.ObjectMeta.Annotations[metadata.ServiceEpAnnotation] = string(raw)
	cont.fakeNodeSource.Add(n)
	waitForSEpAnnot(t, cont, net.ParseIP("10.1.1.2"),
		net.ParseIP("fd43:85d7:bcf2:9ad2::2"), nil, "out of range")

	cont.nodeUpdates = nil
	n = node("node2")
	ep.Mac = "00:0c:29:92:fe:d0"
	ep.Ipv4 = net.ParseIP("10.1.1.4")
	raw, _ = json.Marshal(ep)
	n.ObjectMeta.Annotations[metadata.ServiceEpAnnotation] = string(raw)
	cont.fakeNodeSource.Add(n)
	waitForSEpAnnot(t, cont, net.ParseIP("10.1.1.4"),
		net.ParseIP("fd43:85d7:bcf2:9ad2::3"), &odevMac, "in range")

	cont.nodeUpdates = nil
	n = node("node3")
	ep.Mac = "00:0c:29:92:fe:d0"
	ep.Ipv4 = net.ParseIP("10.1.1.5")
	raw, _ = json.Marshal(ep)
	n.ObjectMeta.Annotations[metadata.ServiceEpAnnotation] = string(raw)
	cont.fakeNodeSource.Add(n)
	waitForSEpAnnot(t, cont, net.ParseIP("10.1.1.3"),
		net.ParseIP("fd43:85d7:bcf2:9ad2::4"), &ep.Mac, "out of range no odev")

	cont.stop()
}

func waitForPodNetAnnot(t *testing.T, cont *testAciController,
	expIps *metadata.NetIps, desc string) {
	tu.WaitFor(t, desc, 500*time.Millisecond,
		func(last bool) (bool, error) {
			if !tu.WaitCondition(t, last, func() bool {
				return len(cont.nodeUpdates) >= 1
			}, desc, "update") {
				return false, nil
			}

			annot := cont.nodeUpdates[len(cont.nodeUpdates)-1].
				ObjectMeta.Annotations[metadata.PodNetworkRangeAnnotation]
			ips := &metadata.NetIps{}
			err := json.Unmarshal([]byte(annot), ips)
			if !tu.WaitNil(t, last, err, desc, "unmarshal", err) {
				return false, nil
			}
			return tu.WaitEqual(t, last, expIps, ips, desc), nil
		})
}

func TestPodNetV6Annotation(t *testing.T) {
	cont := testController()
	cont.config.PodIpPoolChunkSize = 2
	cont.config.PodIpPool = []ipam.IpRange{
		{Start: net.ParseIP("1:1:1:1::2"), End: net.ParseIP("1:1:1:1::12")},
	}
	cont.AciController.initIpam()
	cont.run()

	{
		cont.nodeUpdates = nil
		cont.fakeNodeSource.Add(node("node1"))
		waitForPodNetAnnot(t, cont, &metadata.NetIps{
			V6: []ipam.IpRange{
				{Start: net.ParseIP("1:1:1:1::2"), End: net.ParseIP("1:1:1:1::3")},
			},
		}, "simple")
	}

	cont.stop()
}

func TestPodNetAnnotation(t *testing.T) {
	cont := testController()
	cont.config.PodIpPoolChunkSize = 2
	cont.config.PodIpPool = []ipam.IpRange{
		{Start: net.ParseIP("10.1.1.2"), End: net.ParseIP("10.1.1.13")},
	}
	cont.AciController.initIpam()
	cont.run()
	setupODev(cont, "node2", true)

	{
		cont.nodeUpdates = nil
		cont.fakeNodeSource.Add(node("node1"))
		waitForPodNetAnnot(t, cont, &metadata.NetIps{
			V4: []ipam.IpRange{
				{Start: net.ParseIP("10.1.1.2"), End: net.ParseIP("10.1.1.3")},
			},
		}, "simple")
	}

	{
		cont.nodeUpdates = nil
		cont.fakePodSource.Add(podOnNode("testns", "testpod", "node1"))
		cont.fakePodSource.Add(podOnNode("testns", "testpod2", "node1"))

		waitForPodNetAnnot(t, cont, &metadata.NetIps{
			V4: []ipam.IpRange{
				{Start: net.ParseIP("10.1.1.2"), End: net.ParseIP("10.1.1.5")},
			},
		}, "newchunk")
	}

	{
		cont.nodeUpdates = nil
		node2 := node("node2")
		ips := &metadata.NetIps{
			V4: []ipam.IpRange{
				{Start: net.ParseIP("10.1.1.7"), End: net.ParseIP("10.1.1.9")},
			},
		}
		raw, _ := json.Marshal(ips)
		node2.ObjectMeta.Annotations[metadata.PodNetworkRangeAnnotation] = string(raw)
		cont.fakeNodeSource.Add(node2)
		waitForPodNetAnnot(t, cont, ips, "existing")
	}

	{
		cont.nodeUpdates = nil
		node3 := node("node3")
		ips := &metadata.NetIps{
			V4: []ipam.IpRange{
				{Start: net.ParseIP("10.1.1.10"), End: net.ParseIP("10.1.1.15")},
			},
		}
		raw, _ := json.Marshal(ips)
		node3.ObjectMeta.Annotations[metadata.PodNetworkRangeAnnotation] = string(raw)
		cont.fakeNodeSource.Add(node3)
		waitForPodNetAnnot(t, cont, &metadata.NetIps{
			V4: []ipam.IpRange{
				{Start: net.ParseIP("10.1.1.10"), End: net.ParseIP("10.1.1.13")},
			},
		}, "out of range intersection")
	}

	cont.stop()
}

func TestNodeNetPol(t *testing.T) {
	cont := testController()
	cont.config.AciPolicyTenant = "test-tenant"
	node := node("node1")
	node.Status.Addresses = []v1.NodeAddress{
		{Type: "Hostname", Address: "test-node"},
		{Type: "InternalIP", Address: "1.1.1.1"},
	}
	cont.fakeNodeSource.Add(node)
	cont.run()

	key := cont.aciNameForKey("node", "node1")
	sg := apicNodeNetPol(key, "test-tenant", map[string]bool{"1.1.1.1": true})

	tu.WaitFor(t, "node-net-pol", 500*time.Millisecond,
		func(last bool) (bool, error) {
			cont.indexMutex.Lock()
			defer cont.indexMutex.Unlock()

			slice := apicapi.ApicSlice{sg}
			apicapi.PrepareApicSlice(slice, "kube", key)

			if !tu.WaitEqual(t, last, slice,
				cont.apicConn.GetDesiredState(key), "node-net-pol", key) {
				return false, nil
			}
			return true, nil
		})
	cont.stop()
}

func TestPodNetAnnotUpgrade(t *testing.T) {
	cont := testController()
	cont.config.PodIpPool = []ipam.IpRange{
		{Start: net.ParseIP("10.128.2.2"), End: net.ParseIP("10.128.16.1")},
	}

	cont.AciController.initIpam()
	cont.run()
	setupODev(cont, "node2", true)

	nodeAdder := func(id int, ips *metadata.NetIps) {
		nodeName := fmt.Sprintf("node%d", id)
		n := node(nodeName)
		raw, _ := json.Marshal(ips)
		n.ObjectMeta.Annotations[metadata.PodNetworkRangeAnnotation] = string(raw)
		cont.fakeNodeSource.Add(n)
	}
	// add 3 nodes
	ips1 := &metadata.NetIps{
		V4: []ipam.IpRange{
			{Start: net.ParseIP("10.128.2.2"), End: net.ParseIP("10.128.2.129")},
		},
	}
	ips2 := &metadata.NetIps{
		V4: []ipam.IpRange{
			{Start: net.ParseIP("10.128.3.2"), End: net.ParseIP("10.128.3.129")},
		},
	}
	ips3 := &metadata.NetIps{
		V4: []ipam.IpRange{
			{Start: net.ParseIP("10.128.2.130"), End: net.ParseIP("10.128.2.162")},
		},
	}

	nodeAdder(1, ips1)
	nodeAdder(2, ips2)
	nodeAdder(3, ips3)

	podAdder := func(n, start, end int) {
		nodeName := fmt.Sprintf("node%d", n)
		for ix := start; ix < end; ix++ {
			podName := fmt.Sprintf("testPod%d", ix)
			cont.fakeNodeSource.Add(node(nodeName))
			cont.fakePodSource.Add(podOnNode("testns", podName, nodeName))
		}
	}

	time.Sleep(time.Second)

	cont.nodeUpdates = nil
	podId := 1
	for total := 0; total < 120; total++ {
		podAdder(1, podId, podId+total)
		time.Sleep(2 * time.Millisecond)
	}
	ips4 := &metadata.NetIps{
		V4: []ipam.IpRange{
			{Start: net.ParseIP("10.128.2.2"), End: net.ParseIP("10.128.2.129")},
			{Start: net.ParseIP("10.128.2.163"), End: net.ParseIP("10.128.2.194")},
		},
	}
	waitForPodNetAnnot(t, cont, ips4, "node1 add")
	cont.stop()
}
