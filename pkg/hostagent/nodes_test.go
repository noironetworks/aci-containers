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

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

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

	return metadata.ContainerMetadata{
		Id: metadata.ContainerId{
			ContId:    ip,
			Pod:       "pod" + ip,
			Namespace: "ns",
		},
		Ifaces: []*metadata.ContainerIfaceMd{
			{
				IPs: []metadata.ContainerIfaceIP{
					{
						Address: net.IPNet{
							IP: i,
						},
					},
				},
			},
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
		"{\"V4\":[{\"start\":\"10.128.2.130\",\"end\":\"10.128.3.1\"},{\"start\":\"10.128.3.2\",\"end\":\"10.128.3.129\"},{\"start\":\"10.128.3.130\",\"end\":\"10.128.4.1\"},{\"start\":\"10.128.4.2\",\"end\":\"10.128.4.129\"},{\"start\":\"10.128.4.130\",\"end\":\"10.128.5.1\"},{\"start\":\"10.128.6.130\",\"end\":\"10.128.7.1\"},{\"start\":\"10.128.5.2\",\"end\":\"10.128.5.129\"},{\"start\":\"10.128.2.2\",\"end\":\"10.128.2.129\"},{\"start\":\"10.128.5.130\",\"end\":\"10.128.6.129\"},{\"start\":\"10.128.5.130\",\"end\":\"10.128.6.129\"},{\"start\":\"10.128.7.2\",\"end\":\"10.128.9.1\"},{\"start\":\"10.128.7.2\",\"end\":\"10.128.8.129\"} ],\"V6\":null}",
		[]metadata.ContainerMetadata{},
		[]ipam.IpRange{
			{Start: net.ParseIP("10.128.2.2"), End: net.ParseIP("10.128.9.1")},
		},
		[]ipam.IpRange{},
		"v4 with duplicates",
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
		agent.epMetadata =
			make(map[string]map[string]*metadata.ContainerMetadata)
		agent.podNetAnnotation = ""
		for ix := range test.existingEps {
			podid := "ns/pod" + test.existingEps[ix].Id.ContId
			if _, ok := agent.epMetadata[podid]; !ok {
				agent.epMetadata[podid] =
					make(map[string]*metadata.ContainerMetadata)
			}
			agent.epMetadata[podid][test.existingEps[ix].Id.ContId] = &test.existingEps[ix]
		}
		agent.buildUsedIPs()
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
	}

	agent.stop()
}
