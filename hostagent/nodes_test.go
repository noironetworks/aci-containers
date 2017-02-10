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

package main

import (
	"net"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "k8s.io/client-go/pkg/api/v1"

	"github.com/noironetworks/aci-containers/ipam"
	"github.com/noironetworks/aci-containers/metadata"
	tu "github.com/noironetworks/aci-containers/testutil"
)

type buildIpamTest struct {
	annotation  string
	existingEps []opflexEndpoint
	freeListV4  []ipam.IpRange
	freeListV6  []ipam.IpRange
	desc        string
}

var buildIpamTests = []buildIpamTest{
	{
		"{\"V4\":[{\"start\":\"10.1.0.2\",\"end\":\"10.1.1.1\"}],\"V6\":null}",
		[]opflexEndpoint{},
		[]ipam.IpRange{
			{Start: net.ParseIP("10.1.0.2"), End: net.ParseIP("10.1.1.1")},
		},
		[]ipam.IpRange{},
		"simple v4",
	},
	{
		"{\"V4\":[{\"start\":\"10.1.0.2\",\"end\":\"10.1.1.1\"}],\"V6\":null}",
		[]opflexEndpoint{
			opflexEndpoint{
				Uuid:      "1",
				IpAddress: []string{"10.1.0.126"},
			},
		},
		[]ipam.IpRange{
			{Start: net.ParseIP("10.1.0.2"), End: net.ParseIP("10.1.0.125")},
			{Start: net.ParseIP("10.1.0.127"), End: net.ParseIP("10.1.1.1")},
		},
		[]ipam.IpRange{},
		"v4 with existing",
	},
	{
		"{\"V6\":[{\"start\":\"fd43:85d7:bcf2:9ad2::\",\"end\":\"fd43:85d7:bcf2:9ad2::ffff:ffff\"}]}",
		[]opflexEndpoint{},
		[]ipam.IpRange{},
		[]ipam.IpRange{
			{Start: net.ParseIP("fd43:85d7:bcf2:9ad2::"), End: net.ParseIP("fd43:85d7:bcf2:9ad2::ffff:ffff")},
		},
		"simple v6",
	},
	{
		"{\"V6\":[{\"start\":\"fd43:85d7:bcf2:9ad2::\",\"end\":\"fd43:85d7:bcf2:9ad2::ffff:ffff\"}]}",
		[]opflexEndpoint{
			opflexEndpoint{
				Uuid:      "1",
				IpAddress: []string{"fd43:85d7:bcf2:9ad2::126"},
			},
		},
		[]ipam.IpRange{},
		[]ipam.IpRange{
			{Start: net.ParseIP("fd43:85d7:bcf2:9ad2::"), End: net.ParseIP("fd43:85d7:bcf2:9ad2::125")},
			{Start: net.ParseIP("fd43:85d7:bcf2:9ad2::127"), End: net.ParseIP("fd43:85d7:bcf2:9ad2::ffff:ffff")},
		},
		"v6 with existing",
	},
	{
		"{}",
		[]opflexEndpoint{},
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
		agent.opflexEps = make(map[string]*opflexEndpoint)
		agent.podNetAnnotation = ""
		for _, ep := range test.existingEps {
			agent.opflexEps[ep.Uuid] = &ep
		}
		agent.indexMutex.Unlock()
		agent.fakeNodeSource.Add(node(test.annotation))

		tu.WaitFor(t, test.desc, 100*time.Millisecond,
			func(last bool) (bool, error) {
				agent.indexMutex.Lock()
				defer agent.indexMutex.Unlock()
				return tu.WaitEqual(t, last, test.freeListV4,
					agent.podIpsV4.FreeList, test.desc) &&
					tu.WaitEqual(t, last, test.freeListV4,
						agent.podIpsV4.FreeList, test.desc), nil
			})

	}

	agent.stop()
}
