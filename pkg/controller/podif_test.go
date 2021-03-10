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
	podIfpolicy "github.com/noironetworks/aci-containers/pkg/gbpcrd/apis/acipolicy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"testing"
)

type podifdata struct {
	name      string
	macAddr   string
	epg       string
	namespace string
}

func podifinfodata(name string, namespace string, macaddr string,
	epg string) *podIfpolicy.PodIF {
	podifinfo := &podIfpolicy.PodIF{
		Status: podIfpolicy.PodIFStatus{
			MacAddr: macaddr,
			EPG:     epg,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
	}
	return podifinfo
}

var podifTests = []podifdata{
	{
		"test1",
		"C2-85-53-A1-85-61",
		"test-epg1",
		"testns",
	},
	{
		"test2",
		"C2-85-53-A1-85-62",
		"test-epg2",
		"testns",
	},
	{
		"test3",
		"C2-85-53-A1-85-63",
		"test-epg3",
		"testns",
	},
}

func TestPodIF(t *testing.T) {
	cont := testController()

	ips := []string{
		"1.1.1.1", "1.1.1.2", "1.1.1.3", "1.1.1.4", "1.1.1.5", "",
	}

	cont.run()
	pinfo := make(map[string]bool)
	for _, pt := range podifTests {
		cont.log.Info("Testing podif data")
		addPods(cont, true, ips, true)
		podifObj := podifinfodata(pt.name, pt.macAddr, pt.epg, pt.namespace)
		if _, ok := pinfo[pt.name]; !ok {
			cont.fakePodIFSource.Add(podifObj)
			cont.log.Infof("podif Added: %s", pt.name)
			pinfo[pt.name] = true
		} else {
			cont.log.Infof("podif updated: %s", pt.name)
		}
		cont.fakePodIFSource.Delete(podifObj)
		cont.log.Infof("podif Deleted: %s", pt.name)

	}
	cont.stop()
}
