// Copyright 2020 Cisco Systems, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package hostagent

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/noironetworks/aci-containers/pkg/metadata"
)

// Check if ignoring PacketEvent based on time of reporting works
func TestShouldIgnoreDelayed(t *testing.T) {
	var packetEvent PacketEvent = PacketEvent{
		TimeStamp:       "Sun Mar 08 20:02:59 EDT 2020",
		DropReason:      "PolicyDrop-br-int/POL_TABLE",
		SourceMac:       "16:39:19:fa:f8:40",
		DestinationMac:  "62:58:da:98:01:97",
		EtherType:       "IPv4",
		SourceIP:        "10.1.1.1",
		DestinationIP:   "10.1.1.2",
		IPProto:         "UDP",
		SourcePort:      "10023",
		DestinationPort: "53",
	}
	agent := testAgent()
	agent.config.DropLogExpiryTime = 10
	agent.config.DropLogRepeatIntervalTime = 2
	currTime, _ := time.Parse(time.UnixDate, "Sun Mar 08 20:13:59 EDT 2020")
	assert.Equal(t, true, agent.shouldIgnore(packetEvent, currTime), "late event prune test failed")
}

// Check if ignoring PacketEvent based on frequency works
func TestShouldIgnoreRepeated(t *testing.T) {
	var packetEvent PacketEvent = PacketEvent{
		TimeStamp:       "Sun Mar 08 20:02:59 EDT 2020",
		DropReason:      "PolicyDrop-br-int/POL_TABLE",
		SourceMac:       "16:39:19:fa:f8:40",
		DestinationMac:  "62:58:da:98:01:97",
		EtherType:       "IPv4",
		SourceIP:        "10.1.1.1",
		DestinationIP:   "10.1.1.2",
		IPProto:         "UDP",
		SourcePort:      "10023",
		DestinationPort: "53",
	}
	tempdir, err := os.MkdirTemp("", "hostagent_test_")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tempdir)
	agent := testAgent()
	agent.config.OpFlexEndpointDir = tempdir
	agent.config.OpFlexServiceDir = tempdir
	agent.config.OpFlexSnatDir = tempdir
	agent.config.UplinkIface = "eth10"
	agent.config.NodeName = "test-node"
	agent.config.ServiceVlan = 4003
	agent.config.UplinkMacAdress = "5a:fd:16:e5:e7:c0"
	agent.config.DropLogExpiryTime = 10
	agent.config.DropLogRepeatIntervalTime = 2
	agent.run()
	for i, pt := range podTests {
		if i%2 == 0 {
			os.WriteFile(filepath.Join(tempdir,
				pt.uuid+"_"+pt.cont+"_"+pt.veth+".ep"),
				[]byte("random gibberish"), 0644)
		}

		pod := pod(pt.uuid, pt.namespace, pt.name, pt.eg, pt.sg, pt.qp)
		pod.Status.PodIP = pt.ip
		pod.Status.Phase = "Running"
		cnimd := cnimd(pt.namespace, pt.name, pt.ip, pt.cont, pt.veth)
		agent.epMetadata[pt.namespace+"/"+pt.name] =
			map[string]*metadata.ContainerMetadata{
				cnimd.Id.ContId: cnimd,
			}
		agent.fakePodSource.Add(pod)
	}
	time.Sleep(3000 * time.Millisecond)
	currTime, _ := time.Parse(time.UnixDate, "Sun Mar 08 20:03:59 EDT 2020")
	err = agent.processPacketEvent(packetEvent, currTime)
	assert.Nil(t, err, "Failed to process event")
	packetEvent.TimeStamp = "Sun Mar 08 20:04:59 EDT 2020"
	currTime = currTime.Add(time.Minute * 1)
	assert.Equal(t, true, agent.shouldIgnore(packetEvent, currTime), "repeated event prune test failed")
	packetEvent.TimeStamp = "Sun Mar 08 20:06:59 EDT 2020"
	currTime = currTime.Add(time.Minute * 5)
	assert.Equal(t, false, agent.shouldIgnore(packetEvent, currTime), "post event test failed")
	for _, pt := range podTests {
		pod := pod(pt.uuid, pt.namespace, pt.name, pt.eg, pt.sg, pt.qp)
		agent.fakePodSource.Delete(pod)
	}
	agent.stop()
}
