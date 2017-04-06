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
	"net"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "k8s.io/client-go/pkg/api/v1"

	cnitypes "github.com/containernetworking/cni/pkg/types/current"
	"github.com/noironetworks/aci-containers/pkg/ipam"
	"github.com/noironetworks/aci-containers/pkg/metadata"
	tu "github.com/noironetworks/aci-containers/pkg/testutil"
)

type buildIpamTest struct {
	annotation  string
	existingEps []metadata.ContainerMetadata
	freeListV4  []ipam.IpRange
	freeListV6  []ipam.IpRange
	desc        string
}

func mditem(ip string) metadata.ContainerMetadata {
	i := net.ParseIP(ip)

	ipconfig := &cnitypes.IPConfig{
		Address: net.IPNet{
			IP: i,
		},
	}

	if i.To4() != nil {
		ipconfig.Version = "4"
	} else {
		ipconfig.Version = "6"
	}

	return metadata.ContainerMetadata{
		Id: ip,
		NetConf: cnitypes.Result{
			IPs: []*cnitypes.IPConfig{ipconfig},
		},
	}

}

var buildIpamTests = []buildIpamTest{
	{
		"{\"V4\":[{\"start\":\"10.1.0.2\",\"end\":\"10.1.1.1\"}],\"V6\":null}",
		[]metadata.ContainerMetadata{},
		[]ipam.IpRange{
			{Start: net.ParseIP("10.1.0.2"), End: net.ParseIP("10.1.1.1")},
		},
		[]ipam.IpRange{},
		"simple v4",
	},
	{
		"{\"V4\":[{\"start\":\"10.1.0.2\",\"end\":\"10.1.1.1\"}],\"V6\":null}",
		[]metadata.ContainerMetadata{mditem("10.1.0.126")},
		[]ipam.IpRange{
			{Start: net.ParseIP("10.1.0.2"), End: net.ParseIP("10.1.0.125")},
			{Start: net.ParseIP("10.1.0.127"), End: net.ParseIP("10.1.1.1")},
		},
		[]ipam.IpRange{},
		"v4 with existing",
	},
	{
		"{\"V6\":[{\"start\":\"fd43:85d7:bcf2:9ad2::\",\"end\":\"fd43:85d7:bcf2:9ad2::ffff:ffff\"}]}",
		[]metadata.ContainerMetadata{},
		[]ipam.IpRange{},
		[]ipam.IpRange{
			{Start: net.ParseIP("fd43:85d7:bcf2:9ad2::"), End: net.ParseIP("fd43:85d7:bcf2:9ad2::ffff:ffff")},
		},
		"simple v6",
	},
	{
		"{\"V6\":[{\"start\":\"fd43:85d7:bcf2:9ad2::\",\"end\":\"fd43:85d7:bcf2:9ad2::ffff:ffff\"}]}",
		[]metadata.ContainerMetadata{mditem("fd43:85d7:bcf2:9ad2::126")},
		[]ipam.IpRange{},
		[]ipam.IpRange{
			{Start: net.ParseIP("fd43:85d7:bcf2:9ad2::"), End: net.ParseIP("fd43:85d7:bcf2:9ad2::125")},
			{Start: net.ParseIP("fd43:85d7:bcf2:9ad2::127"), End: net.ParseIP("fd43:85d7:bcf2:9ad2::ffff:ffff")},
		},
		"v6 with existing",
	},
	{
		"{}",
		[]metadata.ContainerMetadata{},
		[]ipam.IpRange{},
		[]ipam.IpRange{},
		"empty",
	},
}

func TestBuildIpam(t *testing.T) {
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

	agent := testAgent()
	agent.run()

	for _, test := range buildIpamTests {
		agent.indexMutex.Lock()
		agent.epMetadata = make(map[string]*metadata.ContainerMetadata)
		agent.podNetAnnotation = ""
		for _, ep := range test.existingEps {
			agent.epMetadata[ep.Id] = &ep
		}
		agent.indexMutex.Unlock()
		agent.fakeNodeSource.Add(node(test.annotation))

		tu.WaitFor(t, test.desc, 100*time.Millisecond,
			func(last bool) (bool, error) {
				agent.indexMutex.Lock()
				defer agent.indexMutex.Unlock()
				return tu.WaitEqual(t, last, test.freeListV4,
					combine(agent.podIpsV4).FreeList, test.desc) &&
					tu.WaitEqual(t, last, test.freeListV4,
						combine(agent.podIpsV4).FreeList, test.desc), nil
			})

	}

	agent.stop()
}
