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
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	log "github.com/Sirupsen/logrus"
	"github.com/noironetworks/aci-containers/pkg/eprpcclient"
	"github.com/noironetworks/aci-containers/pkg/ipam"
	"github.com/noironetworks/aci-containers/pkg/metadata"
	tu "github.com/noironetworks/aci-containers/pkg/testutil"
)

const (
	testPodNS = "itPodNS"
	testNetNS = "/var/run/netns/integns"
	rpcSock   = "/tmp/aci-containers-ep-rpc.sock"
)

type buildIpam struct {
	annotation  string
	existingEps []metadata.ContainerMetadata
	freeListV4  []ipam.IpRange
	freeListV6  []ipam.IpRange
	desc        string
}

var buildIpams = []buildIpam{
	{
		"{\"V4\":[{\"start\":\"10.128.2.130\",\"end\":\"10.128.3.1\"},{\"start\":\"10.128.3.2\",\"end\":\"10.128.3.129\"},{\"start\":\"10.128.3.130\",\"end\":\"10.128.4.1\"},{\"start\":\"10.128.4.2\",\"end\":\"10.128.4.129\"},{\"start\":\"10.128.4.130\",\"end\":\"10.128.5.1\"},{\"start\":\"10.128.6.130\",\"end\":\"10.128.7.1\"},{\"start\":\"10.128.5.2\",\"end\":\"10.128.5.129\"},{\"start\":\"10.128.2.2\",\"end\":\"10.128.2.129\"},{\"start\":\"10.128.5.130\",\"end\":\"10.128.6.129\"},{\"start\":\"10.128.5.130\",\"end\":\"10.128.6.129\"},{\"start\":\"10.128.7.2\",\"end\":\"10.128.9.1\"},{\"start\":\"10.128.7.2\",\"end\":\"10.128.8.129\"} ],\"V6\":null}",
		[]metadata.ContainerMetadata{},
		[]ipam.IpRange{
			{Start: net.ParseIP("10.128.2.2"), End: net.ParseIP("10.128.9.1")},
		},
		[]ipam.IpRange{},
		"v4 with duplicates",
	},
	{
		"{\"V4\":[{\"start\":\"10.128.2.130\",\"end\":\"10.128.3.1\"},{\"start\":\"10.128.3.2\",\"end\":\"10.128.3.129\"},{\"start\":\"10.128.3.130\",\"end\":\"10.128.4.1\"},{\"start\":\"10.128.4.2\",\"end\":\"10.128.4.129\"},{\"start\":\"10.128.4.130\",\"end\":\"10.128.5.1\"},{\"start\":\"10.128.6.130\",\"end\":\"10.128.7.1\"},{\"start\":\"10.128.5.2\",\"end\":\"10.128.5.129\"},{\"start\":\"10.128.2.2\",\"end\":\"10.128.2.129\"},{\"start\":\"10.128.5.130\",\"end\":\"10.128.6.129\"},{\"start\":\"10.128.5.130\",\"end\":\"10.128.6.129\"}],\"V6\":null}",
		[]metadata.ContainerMetadata{},
		[]ipam.IpRange{
			{Start: net.ParseIP("10.128.2.2"), End: net.ParseIP("10.128.7.1")},
		},
		[]ipam.IpRange{},
		"v4 with duplicates",
	},
}

func TestInteg(t *testing.T) {
	PluginCloner.Stub = true
	agent := testAgent()

	poolSizes := make([]int64, len(buildIpams))
	node := func(podNetAnnotation string) *v1.Node {
		return &v1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name: nodename,
				Annotations: map[string]string{
					metadata.PodNetworkRangeAnnotation: podNetAnnotation,
				},
			},
		}
	}

	ipCounter := func() int64 {
		var total int64
		agent.ipamMutex.Lock()
		defer agent.ipamMutex.Unlock()

		ipaList := agent.podIps.GetV4IpCache()
		for _, ipa := range ipaList {
			total += ipa.GetSize()
		}

		return total
	}

	agent.run()

	for ix,  test := range buildIpams {
		agent.indexMutex.Lock()
		agent.epMetadata =
			make(map[string]map[string]*metadata.ContainerMetadata)
		agent.podNetAnnotation = ""
		for _, ep := range test.existingEps {
			podid := "ns/pod" + ep.Id.ContId
			if _, ok := agent.epMetadata[podid]; !ok {
				agent.epMetadata[podid] =
					make(map[string]*metadata.ContainerMetadata)
			}
			agent.epMetadata[podid][ep.Id.ContId] = &ep
		}
		agent.indexMutex.Unlock()
		agent.fakeNodeSource.Add(node(test.annotation))

		tu.WaitFor(t, test.desc, 100*time.Millisecond,
			func(last bool) (bool, error) {
				agent.indexMutex.Lock()
				defer agent.indexMutex.Unlock()
				return tu.WaitEqual(t, last, test.freeListV4,
					agent.podIps.CombineV4(), test.desc) &&
					tu.WaitEqual(t, last, test.freeListV4,
						agent.podIps.CombineV4(), test.desc), nil
			})

		poolSizes[ix] = ipCounter()

	}

	// schedule annotation update in the background
	stopCh := make(chan bool)
	go func() {
		var ix int
		for {
			select {
			case <-stopCh:
				return
			case <-time.After(2*time.Millisecond):
				agent.fakeNodeSource.Add(node(buildIpams[ix].annotation))
			}

			ix++
			if ix > 1 {
				ix = 0
			}
		}
	} ()

	log.Infof("IP pool size is %v", poolSizes)
	for jx := 0; jx < 2000; jx++ {
		log.Infof("=>Iteration %d<=", jx)
		var wg sync.WaitGroup
		count := 16

		wg.Add(count)
		for ix := 0; ix < count; ix++ {
			go func(id int) {
				defer wg.Done()
				name := fmt.Sprintf("pod%d", id)
				cid := fmt.Sprintf("%d8ec72deca647bfa60a4b815aa735c87de859b47e87", id)
				err := cniAdd(name, cid, "testeth1")
				if err != nil {
					t.Error(err)
				}
			}(ix)
		}

		log.Infof("Waiting for Adds to finish")
		wg.Wait()
		log.Infof("Adds finished")

		used, err := metadata.CheckMetadata("/tmp/cnimeta", "")
		if err != nil {
			t.Fatal(err)
		}

		// check for leaks
		ipCount := used+ipCounter()
		if ipCount != poolSizes[0] && ipCount != poolSizes[1] {
			t.Fatalf("IP addr leak -- total: %v used: %v avail: %v", poolSizes, used, ipCounter())
		}

		log.Infof("Starting deletes")
		var wgdel sync.WaitGroup
		wgdel.Add(count)
		for ix := 0; ix < count; ix++ {
			go func(id int) {
				defer wgdel.Done()
				name := fmt.Sprintf("pod%d", id)
				cid := fmt.Sprintf("%d8ec72deca647bfa60a4b815aa735c87de859b47e87", id)
				err := cniDel(name, cid)
				if err != nil {
					t.Error(err)
				}
			}(ix)
		}

		log.Infof("Waiting for deletes")
		wgdel.Wait()
		log.Infof("Deletes done")

	}

	close(stopCh)
	agent.stop()
}

func cniAdd(podName, cid, ifname string) error {

	md := metadata.ContainerMetadata{
		Id: metadata.ContainerId{
			ContId:    cid,
			Namespace: testPodNS,
			Pod:       podName,
		},
		Ifaces: []*metadata.ContainerIfaceMd{
			{
				Name:    ifname,
				Sandbox: testNetNS,
			},
		},
	}

	eprpc, err := eprpcclient.NewClient(rpcSock, time.Millisecond*500)
	if err != nil {
		return err
	}
	defer eprpc.Close()

	result, err := eprpc.Register(&md)
	log.Infof("Result: %+v", result)
	return err
}

func cniDel(podName, cid string) error {
	eprpc, err := eprpcclient.NewClient(rpcSock, time.Millisecond*500)
	if err != nil {
		return err
	}

	defer eprpc.Close()
	md := metadata.ContainerId{
		ContId:    cid,
		Namespace: testPodNS,
		Pod:       podName,
	}

	_, err = eprpc.Unregister(&md)
	return err
}
