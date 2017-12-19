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
	"testing"
	"time"

	v1net "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/noironetworks/aci-containers/pkg/metadata"
	tu "github.com/noironetworks/aci-containers/pkg/testutil"
)

type annotTest struct {
	ns      string
	egannot string
	sgannot string
	desc    string
}

const egAnnot = "{\"policy-space\":\"testps\",\"name\":\"test|test-eg\"}"
const sgAnnot = "[{\"policy-space\":\"testps\",\"name\":\"test-sg\"}]"

var egAnnotVal = OpflexGroup{
	PolicySpace: "testps",
	Name:        "test|test-eg",
}
var sgAnnotVal = []OpflexGroup{
	{
		PolicySpace: "testps",
		Name:        "test-sg",
	},
}

var annotTests = []annotTest{
	{"testns", egAnnot, "", "egonly"},
	{"testns", "", sgAnnot, "sgonly"},
	{"testns", "", "", "neither"},
	{"testns", egAnnot, sgAnnot, "both"},
}

func waitForGroupAnnot(t *testing.T, cont *testAciController,
	egAnnot string, sgAnnot string, desc string) {
	tu.WaitFor(t, desc, 500*time.Millisecond,
		func(last bool) (bool, error) {
			if !tu.WaitCondition(t, last, func() bool {
				return len(cont.podUpdates) >= 1
			}, desc) {
				return false, nil
			}
			annot :=
				cont.podUpdates[len(cont.podUpdates)-1].ObjectMeta.Annotations
			return tu.WaitEqual(t, last, egAnnot,
				annot[metadata.CompEgAnnotation], desc) &&
				tu.WaitEqual(t, last, sgAnnot,
					annot[metadata.CompSgAnnotation], desc), nil
		})
}

func TestPodDefault(t *testing.T) {
	for _, test := range annotTests {
		cont := testController()
		cont.defaultEg = test.egannot
		cont.defaultSg = test.sgannot
		cont.run()

		cont.podUpdates = nil
		cont.fakePodSource.Add(pod(test.ns, "testpod", "", ""))
		waitForGroupAnnot(t, cont, test.egannot, test.sgannot, test.desc)

		cont.stop()
	}
}

func TestPodNamespaceDefault(t *testing.T) {
	for _, test := range annotTests {
		cont := testController()
		if test.egannot != "" {
			var eg OpflexGroup
			err := json.Unmarshal([]byte(test.egannot), &eg)
			if err != nil {
				cont.log.Error(err)
			}
			cont.config.NamespaceDefaultEg[test.ns] = eg
		}
		if test.sgannot != "" {
			groups := make([]OpflexGroup, 0)
			err := json.Unmarshal([]byte(test.sgannot), &groups)
			if err != nil {
				cont.log.Error(err)
			}

			cont.config.NamespaceDefaultSg[test.ns] = groups
		}
		cont.run()

		cont.podUpdates = nil
		cont.fakePodSource.Add(pod(test.ns, "testpod", "", ""))
		waitForGroupAnnot(t, cont, test.egannot, test.sgannot, test.desc)

		cont.stop()
	}
}

func TestPodAnnotation(t *testing.T) {
	cont := testController()
	cont.run()

	for _, test := range annotTests {
		cont.podUpdates = nil
		cont.fakePodSource.Add(pod(test.ns, "testpod",
			test.egannot, test.sgannot))
		waitForGroupAnnot(t, cont, test.egannot, test.sgannot, test.desc)
	}

	cont.stop()
}

func TestPodNamespaceAnnotation(t *testing.T) {
	cont := testController()
	cont.run()

	cont.fakePodSource.Add(pod("testns", "testpod", "", ""))
	waitForGroupAnnot(t, cont, "", "", "none")

	for _, test := range annotTests {
		cont.podUpdates = nil
		cont.fakeNamespaceSource.Add(namespace(test.ns, test.egannot,
			test.sgannot))
		waitForGroupAnnot(t, cont, test.egannot, test.sgannot, test.desc)
	}

	cont.fakeNamespaceSource.Delete(namespace("testns", "", ""))
	waitForGroupAnnot(t, cont, "", "", "none")

	cont.stop()
}

func TestPodDeploymentAnnotation(t *testing.T) {
	cont := testController()
	cont.run()

	cont.fakePodSource.Add(pod("testns", "testpod", "", ""))
	waitForGroupAnnot(t, cont, "", "", "none")

	for _, test := range annotTests {
		cont.podUpdates = nil
		cont.fakeDeploymentSource.Add(deployment(test.ns, "testdep",
			test.egannot, test.sgannot))
		waitForGroupAnnot(t, cont, test.egannot, test.sgannot, test.desc)
	}

	cont.fakeDeploymentSource.Delete(deployment("testns", "testdep", "", ""))
	waitForGroupAnnot(t, cont, "", "", "none")

	cont.stop()
}

func TestPodDeploymentAnnotationPre(t *testing.T) {
	cont := testController()
	cont.run()

	cont.fakePodSource.Add(pod("testns", "testpod", "", ""))
	waitForGroupAnnot(t, cont, "", "", "pod1")

	cont.podUpdates = nil
	cont.fakeDeploymentSource.Add(deployment("testns", "testdep",
		egAnnot, sgAnnot))
	waitForGroupAnnot(t, cont, egAnnot, sgAnnot, "pod1update")

	cont.podUpdates = nil
	cont.fakePodSource.Add(pod("testns", "testpod2", "", ""))
	waitForGroupAnnot(t, cont, egAnnot, sgAnnot, "pod2")

	cont.stop()
}

func TestPodNetworkPolicy(t *testing.T) {
	cont := testController()
	cont.fakePodSource.Add(pod("testns", "testpod", "", ""))
	cont.fakeNetworkPolicySource.Add(netpol("testns", "np1",
		&metav1.LabelSelector{}, nil, nil, nil))
	cont.run()

	ns := namespace("testns", "", "")
	cont.fakeNamespaceSource.Add(ns)
	waitForGroupAnnot(t, cont, "",
		"[{\"policy-space\":\"kubernetes\",\"name\":\"kube_np_testns_np1\"},"+
			"{\"policy-space\":\"kubernetes\",\"name\":\"kube_node_test-node\"},"+
			"{\"policy-space\":\"kubernetes\",\"name\":\"kube_np_static-discovery\"},"+
			"{\"policy-space\":\"kubernetes\",\"name\":\"kube_np_static-egress\"}]",
		"added")

	cont.fakePodSource.Add(pod("testns", "testpod", "",
		"[{\"policy-space\":\"test\",\"name\":\"mysg\"}]"))
	waitForGroupAnnot(t, cont, "",
		"[{\"policy-space\":\"kubernetes\",\"name\":\"kube_np_testns_np1\"},"+
			"{\"policy-space\":\"test\",\"name\":\"mysg\"},"+
			"{\"policy-space\":\"kubernetes\",\"name\":\"kube_node_test-node\"},"+
			"{\"policy-space\":\"kubernetes\",\"name\":\"kube_np_static-discovery\"},"+
			"{\"policy-space\":\"kubernetes\",\"name\":\"kube_np_static-egress\"}]",
		"combine")

	cont.fakeNetworkPolicySource.Add(netpol("testns", "np1",
		&metav1.LabelSelector{}, nil, nil, allPolicyTypes))
	waitForGroupAnnot(t, cont, "",
		"[{\"policy-space\":\"kubernetes\",\"name\":\"kube_np_testns_np1\"},"+
			"{\"policy-space\":\"test\",\"name\":\"mysg\"},"+
			"{\"policy-space\":\"kubernetes\",\"name\":\"kube_node_test-node\"},"+
			"{\"policy-space\":\"kubernetes\",\"name\":\"kube_np_static-discovery\"}]",
		"all-policy-types")

	cont.fakeNetworkPolicySource.Add(netpol("testns", "np1",
		&metav1.LabelSelector{}, nil, nil,
		[]v1net.PolicyType{v1net.PolicyTypeEgress}))
	waitForGroupAnnot(t, cont, "",
		"[{\"policy-space\":\"kubernetes\",\"name\":\"kube_np_testns_np1\"},"+
			"{\"policy-space\":\"test\",\"name\":\"mysg\"},"+
			"{\"policy-space\":\"kubernetes\",\"name\":\"kube_node_test-node\"},"+
			"{\"policy-space\":\"kubernetes\",\"name\":\"kube_np_static-discovery\"},"+
			"{\"policy-space\":\"kubernetes\",\"name\":\"kube_np_static-ingress\"}]",
		"egress-only")

	pod := pod("testns", "testpod", "", "")
	pod.Spec.NodeName = ""
	cont.fakePodSource.Add(pod)
	waitForGroupAnnot(t, cont, "",
		"[{\"policy-space\":\"kubernetes\",\"name\":\"kube_np_testns_np1\"},"+
			"{\"policy-space\":\"kubernetes\",\"name\":\"kube_np_static-discovery\"},"+
			"{\"policy-space\":\"kubernetes\",\"name\":\"kube_np_static-ingress\"}]",
		"no-node")

	cont.stop()
}
