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
	"encoding/json"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	cnitypes "github.com/containernetworking/cni/pkg/types"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apitypes "k8s.io/apimachinery/pkg/types"
	v1 "k8s.io/client-go/pkg/api/v1"

	"github.com/noironetworks/aci-containers/metadata"
	md "github.com/noironetworks/aci-containers/metadata"
	tu "github.com/noironetworks/aci-containers/testutil"
)

func pod(uuid string, namespace string, name string,
	egAnnot string, sgAnnot string) *v1.Pod {
	return &v1.Pod{
		Spec: v1.PodSpec{
			NodeName: "test-node",
		},
		ObjectMeta: metav1.ObjectMeta{
			UID:       apitypes.UID(uuid),
			Namespace: namespace,
			Name:      name,
			Annotations: map[string]string{
				metadata.CompEgAnnotation: egAnnot,
				metadata.CompSgAnnotation: sgAnnot,
			},
			Labels: map[string]string{},
		},
	}
}

func cnimd(namespace string, name string, ip string) *md.ContainerMetadata {
	return &md.ContainerMetadata{
		Namespace: namespace,
		Pod:       name,
		Id:        namespace + "_" + name,
		NetConf: cnitypes.Result{
			IP4: &cnitypes.IPConfig{
				IP: net.IPNet{
					IP:   net.ParseIP(ip),
					Mask: net.CIDRMask(24, 32),
				},
			},
		},
	}
}

const egAnnot = "{\"policy-space\": \"testps\", \"name\": \"test|test-eg\"}"
const sgAnnot = "[{\"policy-space\": \"testps\", \"name\": \"test-sg\"}]"

type podTest struct {
	uuid      string
	namespace string
	name      string
	ip        string
	mac       string
	eg        string
	sg        string
}

var podTests = []podTest{
	podTest{
		"730a8e7a-8455-4d46-8e6e-f4fdf0e3a667",
		"testns",
		"pod1",
		"10.1.1.1",
		"00:0c:29:92:fe:d0",
		egAnnot,
		sgAnnot,
	},
	podTest{
		"6a281ef1-0fcb-4140-a38c-62977ef25d72",
		"testns",
		"pod2",
		"10.1.1.2",
		"52:54:00:e5:26:57",
		egAnnot,
		sgAnnot,
	},
}

func (agent *testHostAgent) doTestPod(t *testing.T, tempdir string,
	pt *podTest, desc string) {
	var raw []byte
	ep := &opflexEndpoint{}

	tu.WaitFor(t, pt.name, 100*time.Millisecond,
		func(last bool) (bool, error) {
			var err error
			epfile := filepath.Join(tempdir, pt.uuid+".ep")
			raw, err = ioutil.ReadFile(epfile)
			if !tu.WaitNil(t, last, err, desc, pt.name, "read pod") {
				return false, nil
			}
			err = json.Unmarshal(raw, ep)
			return tu.WaitNil(t, last, err, desc, pt.name, "unmarshal pod"), nil
		})

	eg := &opflexGroup{}
	sg := make([]opflexGroup, 0)
	json.Unmarshal([]byte(pt.eg), eg)
	json.Unmarshal([]byte(pt.sg), &sg)

	assert.Equal(t, pt.uuid, ep.Uuid, desc, pt.name, "uuid")
	assert.Equal(t, []string{pt.ip}, ep.IpAddress, desc, pt.name, "ip")
	assert.Equal(t, eg.PolicySpace, ep.EgPolicySpace, desc, pt.name, "eg pspace")
	assert.Equal(t, eg.Name, ep.EndpointGroup, desc, pt.name, "eg")
	assert.Equal(t, sg, ep.SecurityGroup, desc, pt.name, "secgroup")
}

func TestPodSync(t *testing.T) {
	tempdir, err := ioutil.TempDir("", "hostagent_test_")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tempdir)

	agent := testAgent()
	agent.config.OpFlexEndpointDir = tempdir
	agent.config.OpFlexServiceDir = tempdir
	agent.run()

	for i, pt := range podTests {
		pod := pod(pt.uuid, pt.namespace, pt.name, pt.eg, pt.sg)
		cnimd := cnimd(pt.namespace, pt.name, pt.ip)
		agent.epMetadata[cnimd.Id] = cnimd
		agent.fakePodSource.Add(pod)

		if i%2 == 0 {
			ioutil.WriteFile(filepath.Join(tempdir, pt.uuid+".ep"),
				[]byte("random gibberish"), 0644)
		}
		agent.doTestPod(t, tempdir, &pt, "create")
	}

	for _, pt := range podTests {
		pod := pod(pt.uuid, pt.namespace, pt.name, pt.eg, pt.sg)
		cnimd := cnimd(pt.namespace, pt.name, pt.ip)
		cnimd.MAC = pt.mac
		agent.epMetadata[cnimd.Id] = cnimd
		agent.fakePodSource.Add(pod)

		agent.doTestPod(t, tempdir, &pt, "update")
	}

	for _, pt := range podTests {
		pod := pod(pt.uuid, pt.namespace, pt.name, pt.eg, pt.sg)
		agent.fakePodSource.Delete(pod)

		tu.WaitFor(t, pt.name, 100*time.Millisecond,
			func(last bool) (bool, error) {
				epfile := filepath.Join(tempdir, pt.uuid+".ep")
				_, err := ioutil.ReadFile(epfile)
				return tu.WaitNotNil(t, last, err, "pod deleted"), nil
			})
	}

	agent.stop()
}
