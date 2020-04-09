// Copyright 2019 Cisco Systems, Inc.
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
	"fmt"
	"github.com/noironetworks/aci-containers/pkg/apicapi"
	"github.com/noironetworks/aci-containers/pkg/metadata"
	snatpolicy "github.com/noironetworks/aci-containers/pkg/snatpolicy/apis/aci.snat/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"net"
	"sort"
	"testing"
	"time"
)

func testsnatpolicy(name string, namespace string, deploy string,
	snatIp []string, labels map[string]string) *snatpolicy.SnatPolicy {
	policy := &snatpolicy.SnatPolicy{
		Spec: snatpolicy.SnatPolicySpec{
			SnatIp: snatIp,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Status: snatpolicy.SnatPolicyStatus{
			State: snatpolicy.Ready,
		},
	}
	var podSelector snatpolicy.PodSelector
	podSelector.Namespace = namespace
	podSelector.Labels = labels
	policy.Spec.Selector = podSelector

	return policy
}

func TestSnatGraph(t *testing.T) {
	name := "kube_snat_" + snatGraphName
	graphName := "kube_svc_global"
	cluster := func(nmap map[string]string) apicapi.ApicObject {
		var nodes []string
		for node := range nmap {
			nodes = append(nodes, node)
		}
		sort.Strings(nodes)
		dc, _ := apicDeviceCluster(graphName, "common", "service-physdom",
			"vlan-4001", nodes, nmap)
		return dc
	}
	twoNodeCluster := cluster(map[string]string{
		"node1": "topology/pod-1/paths-301/pathep-[eth1/33]",
		"node2": "topology/pod-1/paths-301/pathep-[eth1/34]",
	})

	graph := apicServiceGraph(graphName, "common", twoNodeCluster.GetDn())

	redirect := func(nmap seMap) apicapi.ApicObject {
		var nodes []string
		for node := range nmap {
			nodes = append(nodes, node)
		}
		sort.Strings(nodes)
		monPolDn := fmt.Sprintf("uni/tn-%s/ipslaMonitoringPol-%s",
			"common", "kube_monPol_kubernetes-service")
		dc, _ := apicRedirectPol(name, "common", nodes,
			nmap, monPolDn, true)
		return dc
	}
	twoNodeRedirect := redirect(seMap{
		"node1": &metadata.ServiceEndpoint{
			HealthGroupDn: "uni/tn-common/svcCont/redirectHealthGroup-kube_svc_node1",
			Mac:           "8a:35:a1:a6:e4:60",
			Ipv4:          net.ParseIP("10.6.1.1"),
		},
		"node2": &metadata.ServiceEndpoint{
			HealthGroupDn: "uni/tn-common/svcCont/redirectHealthGroup-kube_svc_node2",
			Mac:           "a2:7e:45:57:a0:d4",
			Ipv4:          net.ParseIP("10.6.1.2"),
		},
	})
	extNet := apicExtNet(name, "common", "l3out", []string{"10.4.2.2", "10.20.30.40/20"}, true, true)
	rsProv := apicExtNetProv(name, "common", "l3out", "ext1")

	portRanges := []portRangeSnat{
		portRangeSnat{
			start: 5000,
			end:   65000,
		},
	}
	contract := apicContract(name, "common", graphName, "global")
	filter := apicFilterSnat(name, "common", portRanges)
	cc := apicDevCtx(name, "common", graphName,
		"kube_bd_kubernetes-service", twoNodeRedirect.GetDn())

	snatIp := []string{"10.4.2.2", "10.20.30.40/20"}
	labels := map[string]string{
		"lab_key": "lab_value"}
	policy := testsnatpolicy("testpolicy", "common", "deployment",
		snatIp, labels)

	snatIp2 := []string{"172.2.2.1/32"}
	labels2 := map[string]string{
		"lab_key2": "lab_value2"}
	policy2 := testsnatpolicy("testpolicy2", "common", "deployment2",
		snatIp2, labels2)

	node1 := node("node1")
	node1.ObjectMeta.Annotations[metadata.ServiceEpAnnotation] =
		"{\"health-group-dn\":\"uni/tn-common/svcCont/redirectHealthGroup-kube_svc_node1\",\"mac\":\"8a:35:a1:a6:e4:60\",\"ipv4\":\"10.6.1.1\"}"
	node2 := node("node2")
	node2.ObjectMeta.Annotations[metadata.ServiceEpAnnotation] =
		"{\"health-group-dn\":\"uni/tn-common/svcCont/redirectHealthGroup-kube_svc_node2\",\"mac\":\"a2:7e:45:57:a0:d4\",\"ipv4\":\"10.6.1.2\"}"
	node3 := node("node3")
	node3.ObjectMeta.Annotations[metadata.ServiceEpAnnotation] =
		"{\"health-group-dn\":\"uni/tn-common/svcCont/redirectHealthGroup-kube_svc_node3\",\"mac\":\"3e:13:a1:a1:34:60\",\"ipv4\":\"10.6.1.3\"}"

	opflexDevice1 := apicapi.EmptyApicObject("opflexODev", "dev1")
	opflexDevice1.SetAttr("hostName", "node1")
	opflexDevice1.SetAttr("fabricPathDn",
		"topology/pod-1/paths-301/pathep-[eth1/33]")
	opflexDevice1.SetAttr("devType", "k8s")
	opflexDevice1.SetAttr("domName", "kube")
	opflexDevice1.SetAttr("ctrlrName", "kube")

	opflexDevice2 := apicapi.EmptyApicObject("opflexODev", "dev2")
	opflexDevice2.SetAttr("hostName", "node2")
	opflexDevice2.SetAttr("fabricPathDn",
		"topology/pod-1/paths-301/pathep-[eth1/34]")
	opflexDevice2.SetAttr("devType", "k8s")
	opflexDevice2.SetAttr("domName", "kube")
	opflexDevice2.SetAttr("ctrlrName", "kube")

	cont := sgCont()
	cont.config.AciVmmDomain = "kube"
	cont.config.AciVmmController = "kube"
	cont.config.MaxSvcGraphNodes = 2
	cont.fakeNodeSource.Add(node1)
	cont.fakeNodeSource.Add(node2)
	//cont.fakeNodeSource.Add(node3)

	cont.run()
	cont.fakeSnatPolicySource.Add(policy)

	cont.opflexDeviceChanged(opflexDevice1)
	cont.opflexDeviceChanged(opflexDevice2)

	expected := map[string]apicapi.ApicSlice{
		graphName: apicapi.PrepareApicSlice(apicapi.ApicSlice{twoNodeCluster,
			graph}, "kube", graphName),
		name: apicapi.PrepareApicSlice(apicapi.ApicSlice{twoNodeRedirect, extNet, contract, rsProv, filter, cc},
			"kube", name),
	}
	sgWait(t, "snat graph creation", cont, expected)

	cont.fakeSnatPolicySource.Add(policy2)
	time.Sleep(2 * time.Second)
	extNet2 := apicExtNet(name, "common", "l3out", []string{"10.4.2.2", "10.20.30.40/20", "172.2.2.1/32"}, true, true)
	expected2 := map[string]apicapi.ApicSlice{
		graphName: apicapi.PrepareApicSlice(apicapi.ApicSlice{twoNodeCluster,
			graph}, "kube", graphName),
		name: apicapi.PrepareApicSlice(apicapi.ApicSlice{twoNodeRedirect, extNet2, contract, rsProv, filter, cc},
			"kube", name),
	}
	sgWait(t, "snat graph addition", cont, expected2)

	cont.fakeSnatPolicySource.Delete(policy2)
	time.Sleep(2 * time.Second)
	expectedDeleteSnatPolicy := map[string]apicapi.ApicSlice{
		graphName: apicapi.PrepareApicSlice(apicapi.ApicSlice{twoNodeCluster,
			graph}, "kube", graphName),
		name: apicapi.PrepareApicSlice(apicapi.ApicSlice{twoNodeRedirect, extNet, contract, rsProv, filter, cc},
			"kube", name),
	}
	sgWait(t, "snat policy deleted", cont, expectedDeleteSnatPolicy)

	cont.fakeSnatPolicySource.Delete(policy)
	time.Sleep(2 * time.Second)
	expectedNoSnat := map[string]apicapi.ApicSlice{
		graphName: apicapi.PrepareApicSlice(apicapi.ApicSlice{twoNodeCluster,
			graph}, "kube", graphName),
		name: nil,
	}
	sgWait(t, "snat graph deleted", cont, expectedNoSnat)
	cont.stop()

}
