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
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apitypes "k8s.io/apimachinery/pkg/types"

	"github.com/noironetworks/aci-containers/pkg/metadata"
	md "github.com/noironetworks/aci-containers/pkg/metadata"
	tu "github.com/noironetworks/aci-containers/pkg/testutil"
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
				metadata.EgAnnotation: egAnnot,
				metadata.SgAnnotation: sgAnnot,
			},
			Labels: map[string]string{},
		},
	}
}

func cnimd(namespace string, name string,
	ip string, cont string, veth string) *md.ContainerMetadata {

	return &md.ContainerMetadata{
		Id: md.ContainerId{
			Namespace: namespace,
			Pod:       name,
			ContId:    cont,
		},
		Ifaces: []*md.ContainerIfaceMd{
			{
				HostVethName: veth,
				Name:         "eth0",
				IPs: []md.ContainerIfaceIP{
					{
						Address: net.IPNet{
							IP:   net.ParseIP(ip),
							Mask: net.CIDRMask(24, 32),
						},
					},
				},
			},
		},
	}
}

const egAnnot = "{\"tenant\": \"testps\", " +
	"\"app-profile\": \"test\", \"name\": \"test-eg\"}"
const sgAnnot = "[{\"tenant\": \"testps\", \"name\": \"test-sg\"}]"

type podTest struct {
	uuid      string
	cont      string
	veth      string
	namespace string
	name      string
	ip        string
	mac       string
	eg        string
	sg        string
}

var podTests = []podTest{
	{
		"730a8e7a-8455-4d46-8e6e-f4fdf0e3a667",
		"cont1",
		"veth1",
		"testns",
		"pod1",
		"10.1.1.1",
		"00:0c:29:92:fe:d0",
		egAnnot,
		sgAnnot,
	},
	{
		"730a8e7a-8455-4d46-8e6e-f4fdf0e3a667",
		"cont2",
		"veth2",
		"testns",
		"pod1",
		"10.1.1.3",
		"00:0c:29:92:fe:d1",
		egAnnot,
		sgAnnot,
	},
	{
		"6a281ef1-0fcb-4140-a38c-62977ef25d72",
		"cont2",
		"veth2",
		"testns",
		"pod2",
		"10.1.1.2",
		"52:54:00:e5:26:57",
		egAnnot,
		sgAnnot,
	},
	{
		"6a281ef1-0fcb-4140-a38c-62977ef25d71",
		"cont2",
		"veth2",
		"testns",
		"pod3",
		"10.1.1.5",
		"52:54:00:e5:26:59",
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
			epfile := filepath.Join(tempdir,
				pt.uuid+"_"+pt.cont+"_"+pt.veth+".ep")
			raw, err = ioutil.ReadFile(epfile)
			if !tu.WaitNil(t, last, err, desc, pt.name, "read pod") {
				return false, nil
			}
			err = json.Unmarshal(raw, ep)
			return tu.WaitNil(t, last, err, desc, pt.name, "unmarshal pod"), nil
		})

	eg := &metadata.OpflexGroup{}
	sg := make([]metadata.OpflexGroup, 0)
	json.Unmarshal([]byte(pt.eg), eg)
	json.Unmarshal([]byte(pt.sg), &sg)

	epidstr := pt.uuid + "_" + pt.cont + "_" + pt.veth
	assert.Equal(t, epidstr, ep.Uuid, desc, pt.name, "uuid")
	assert.Equal(t, []string{pt.ip}, ep.IpAddress, desc, pt.name, "ip")
	assert.Equal(t, eg.Tenant, ep.EgPolicySpace, desc, pt.name, "eg pspace")
	assert.Equal(t, eg.AppProfile+"|"+eg.Name, ep.EndpointGroup,
		desc, pt.name, "eg")
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
		agent.doTestPod(t, tempdir, &pt, "create")
	}

	for _, pt := range podTests {
		pod := pod(pt.uuid, pt.namespace, pt.name, pt.eg, pt.sg)
		cnimd := cnimd(pt.namespace, pt.name, pt.ip, pt.cont, pt.veth)
		cnimd.Ifaces[0].Mac = pt.mac
		agent.epMetadata[pt.namespace+"/"+pt.name] =
			map[string]*metadata.ContainerMetadata{
				cnimd.Id.ContId: cnimd,
			}
		agent.fakePodSource.Add(pod)

		agent.doTestPod(t, tempdir, &pt, "update")
	}

	for _, pt := range podTests {
		pod := pod(pt.uuid, pt.namespace, pt.name, pt.eg, pt.sg)
		agent.fakePodSource.Delete(pod)

		tu.WaitFor(t, pt.name, 100*time.Millisecond,
			func(last bool) (bool, error) {
				epfile := filepath.Join(tempdir,
					pt.uuid+"_"+pt.cont+"_"+pt.veth+".ep")
				_, err := ioutil.ReadFile(epfile)
				return tu.WaitNotNil(t, last, err, "pod deleted"), nil
			})
	}

	agent.stop()
}
