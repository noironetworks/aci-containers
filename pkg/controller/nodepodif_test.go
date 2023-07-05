// Copyright 2021 Cisco Systems, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package controller

import (
	"testing"
	"time"

	nodePodIf "github.com/noironetworks/aci-containers/pkg/nodepodif/apis/acipolicy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type nodepodif struct {
	name   string
	podifs []nodePodIf.PodIF
}

func nodepodifdata(name string, podifs []nodePodIf.PodIF) *nodePodIf.NodePodIF {
	nodepodifinfo := &nodePodIf.NodePodIF{
		Spec: nodePodIf.NodePodIFSpec{
			PodIFs: podifs,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "kube-system",
		},
	}
	return nodepodifinfo
}

var nodePodIFTests = []nodepodif{
	{
		"nodepodif1",
		[]nodePodIf.PodIF{
			{
				MacAddr: "C2-85-53-A1-85-61",
				EPG:     "test-epg1",
				PodNS:   "testns",
				PodName: "pod-1",
			},
		},
	},
	{
		"nodepodif2",
		[]nodePodIf.PodIF{
			{
				MacAddr: "C2-85-53-A1-85-62",
				EPG:     "test-epg2",
				PodNS:   "testns",
				PodName: "pod-2",
			},
		},
	},
}

var nodePodIFTestsUpdated = []nodepodif{
	{
		"nodepodif1",
		[]nodePodIf.PodIF{
			{
				MacAddr: "C2-85-53-A1-85-61",
				EPG:     "test-epg1",
				PodNS:   "testns",
				PodName: "pod-1",
			},
			{
				MacAddr: "C2-85-53-A1-85-62",
				EPG:     "test-epg1",
				PodNS:   "testns",
				PodName: "pod-3",
			},
			{
				MacAddr: "C2-85-53-A1-85-63",
				EPG:     "test-epg1",
				PodNS:   "testns",
				PodName: "pod-4",
			},
		},
	},
	{
		"nodepodif2",
		[]nodePodIf.PodIF{
			{
				MacAddr: "C2-85-53-A1-85-63",
				EPG:     "test-epg3",
				PodNS:   "testns",
				PodName: "pod-2",
			},
		},
	},
}

func TestNodePodIF(t *testing.T) {
	cont := testController()
	cont.run()
	go cont.nodePodIfInformer.Run(cont.stopCh)

	npinfo := make(map[string]bool)
	for _, pt := range nodePodIFTests {
		nodepodifObj := nodepodifdata(pt.name, pt.podifs)
		if _, ok := npinfo[pt.name]; !ok {
			cont.fakeNodePodIFSource.Add(nodepodifObj)
			cont.log.Debug("nodepodif Added###: ", nodepodifObj)
			npinfo[pt.name] = true
		} else {
			cont.log.Debug("nodepodif updated###: ", nodepodifObj)
			cont.fakeNodePodIFSource.Modify(nodepodifObj)
		}
	}
	time.Sleep(time.Millisecond * 100)
	cont.log.Debug("podIftoEp after add: ", cont.AciController.podIftoEp)

	for _, pt := range nodePodIFTestsUpdated {
		nodepodifObj := nodepodifdata(pt.name, pt.podifs)
		cont.fakeNodePodIFSource.Modify(nodepodifObj)
		cont.log.Debug("nodepodif Updated###: ", nodepodifObj)
	}
	time.Sleep(time.Millisecond * 100)
	cont.log.Debug("podIftoEp after update: ", cont.AciController.podIftoEp)

	for _, pt := range nodePodIFTests {
		nodepodifObj := nodepodifdata(pt.name, pt.podifs)
		cont.fakeNodePodIFSource.Delete(nodepodifObj)
		cont.log.Debug("nodepodif Deleted###: ", nodepodifObj)
	}
	time.Sleep(time.Millisecond * 100)
	cont.log.Debug("podIftoEp after delete: ", cont.AciController.podIftoEp)
	cont.stop()
}
