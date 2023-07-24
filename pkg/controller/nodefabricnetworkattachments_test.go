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

// Test for node fabric network attachments updates.
package controller

import (
	"fmt"
	"github.com/noironetworks/aci-containers/pkg/apicapi"
	fabattv1 "github.com/noironetworks/aci-containers/pkg/fabricattachment/apis/aci.fabricattachment/v1"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"testing"
)

type nfnaVlanTest struct {
	EncapString   string
	ExpectedVlans []int
	ExpectError   bool
}

func TestNFNAVlanParse(t *testing.T) {
	vlanTests := []nfnaVlanTest{
		{"", []int{}, true},
		{"[1,5-10,15]", []int{1, 5, 6, 7, 8, 9, 10, 15}, false},
		{"1,5-8,10", []int{1, 5, 6, 7, 8, 10}, false},
		{"[5-6]", []int{5, 6}, false},
		{"[100, 102, 103, 104]", []int{100, 102, 103, 104}, false},
	}
	cont := testController()
	for _, tc := range vlanTests {
		vlanList, _, err := cont.parseNodeFabNetAttVlanList(tc.EncapString)
		if err != nil {
			if tc.ExpectError {
				assert.True(t, true, "")
				continue
			}
			errorMsg := fmt.Sprintf("%v", err)
			assert.True(t, false, errorMsg)
		}
		for idx := range tc.ExpectedVlans {
			assert.Equal(t, tc.ExpectedVlans[idx], vlanList[idx])
		}
	}
}

func CreateNFNADom(nfna *fabattv1.NodeFabricNetworkAttachment, cont *testAciController) apicapi.ApicSlice {
	var apicSlice apicapi.ApicSlice
	networkName := nfna.Spec.NetworkRef.Namespace + "-" + nfna.Spec.NetworkRef.Name
	if cont.config.AciUseGlobalScopeVlan {
		networkName = "secondary"
	}
	fvnsVlanInstP := apicapi.NewFvnsVlanInstP("kubernetes", networkName)
	fvnsEncapBlk := apicapi.NewFvnsEncapBlk(fvnsVlanInstP.GetDn(), "5", "6")
	fvnsVlanInstP.AddChild(fvnsEncapBlk)
	apicSlice = append(apicSlice, fvnsVlanInstP)
	physDom := apicapi.NewPhysDomP("kubernetes-" + networkName)
	infraRsVlanNs := apicapi.NewInfraRsVlanNs(physDom.GetDn(), fvnsVlanInstP.GetDn())
	physDom.AddChild(infraRsVlanNs)
	apicSlice = append(apicSlice, physDom)
	// associate aep with physdom
	secondaryAepDn := "uni/infra/attentp-" + "second-aep"
	infraRsDomP := apicapi.NewInfraRsDomP(secondaryAepDn, physDom.GetDn())
	apicSlice = append(apicSlice, infraRsDomP)
	return apicSlice
}

func CreateNFNAObjs(nfna *fabattv1.NodeFabricNetworkAttachment, cont *testAciController) apicapi.ApicSlice {
	var apicSlice apicapi.ApicSlice
	networkName := nfna.Spec.NetworkRef.Namespace + "-" + nfna.Spec.NetworkRef.Name
	bd := apicapi.NewFvBD("kubernetes", networkName)
	bd.SetAttr("arpFlood", "yes")
	bd.SetAttr("ipLearning", "no")
	bd.SetAttr("unkMacUcastAct", "flood")
	fvRsCtx := apicapi.NewFvRsCtx(bd.GetDn(), "kube-vrf")
	bd.AddChild(fvRsCtx)
	apicSlice = append(apicSlice, bd)
	if !cont.config.AciUseGlobalScopeVlan {
		apicSlice = append(apicSlice, CreateNFNADom(nfna, cont)...)
	}
	return apicSlice
}

func PopulateFabricPaths(nfna *fabattv1.NodeFabricNetworkAttachment, fabricLinks []string, cont *testAciController, apicSlice apicapi.ApicSlice) apicapi.ApicSlice {
	for _, encap := range []int{5, 6} {
		encapVlan := fmt.Sprintf("%d", encap)
		epg := CreateNFNAEPG(nfna, encap, cont)
		for _, fabricLink := range fabricLinks {
			fvRsPathAtt := apicapi.NewFvRsPathAtt(epg.GetDn(), fabricLink, encapVlan)
			epg.AddChild(fvRsPathAtt)
		}
		apicSlice = append(apicSlice, epg)
	}
	return apicSlice
}

func CreateNFNAEPG(nfna *fabattv1.NodeFabricNetworkAttachment, vlan int, cont *testAciController) apicapi.ApicObject {
	var fvRsDomAtt apicapi.ApicObject
	apName := "netop-" + "kubernetes"
	encap := fmt.Sprintf("%d", vlan)
	networkName := nfna.Spec.NetworkRef.Namespace + "-" + nfna.Spec.NetworkRef.Name
	epg := apicapi.NewFvAEPg("kubernetes", apName, networkName+"-vlan-"+encap)
	fvRsBd := apicapi.NewFvRsBD(epg.GetDn(), networkName)
	epg.AddChild(fvRsBd)
	if !cont.config.AciUseGlobalScopeVlan {
		fvRsDomAtt = apicapi.NewFvRsDomAttPhysDom(epg.GetDn(), "kubernetes-"+networkName)
	} else {
		fvRsDomAtt = apicapi.NewFvRsDomAttPhysDom(epg.GetDn(), "kubernetes-secondary")
	}
	epg.AddChild(fvRsDomAtt)
	return epg
}

func CreateNFNA(nadName, nodeName, uplink, podName string, fabricLinks []string) *fabattv1.NodeFabricNetworkAttachment {
	return &fabattv1.NodeFabricNetworkAttachment{
		ObjectMeta: metav1.ObjectMeta{},
		Spec: fabattv1.NodeFabricNetworkAttachmentSpec{
			NetworkRef: fabattv1.ObjRef{
				Name:      nadName,
				Namespace: "default",
			},
			EncapVlan: "[5-6]",
			NodeName:  nodeName,
			AciTopology: map[string]fabattv1.AciNodeLinkAdjacency{
				uplink: {
					FabricLink: fabricLinks,
					Pods: []fabattv1.PodAttachment{
						{
							LocalIface: "net1",
							PodRef: fabattv1.ObjRef{
								Name:      podName,
								Namespace: "default",
							},
						},
					},
				},
			},
			PrimaryCNI: "macvlan",
		},
	}
}

func NFNACRUDCase(t *testing.T, globalScopeVlan bool) {
	cont := testChainedController(globalScopeVlan)
	nfna1 := CreateNFNA("macvlan-net1", "master1.cluster.local", "bond1", "pod1-macvlan-net1",
		[]string{"/topology/pod-1/node-101/pathep-[eth1/34]", "/topology/pod-1/node-102/pathep-[eth1/34]"})
	nfna2 := CreateNFNA("macvlan-net1", "master2.cluster.local", "bond1", "pod2-macvlan-net1",
		[]string{"/topology/pod-1/node-101/pathep-[eth1/31]", "/topology/pod-1/node-102/pathep-[eth1/31]"})
	if globalScopeVlan {
		apicSliceStatic, err := cont.setGlobalScopeVlanConfig("[5-6]")
		expectedApicSlice := CreateNFNADom(nfna1, cont)
		assert.Nil(t, err, "nfna global dom create")
		assert.Equal(t, expectedApicSlice, apicSliceStatic, "nfna global dom create")
	}
	apicSlice := cont.updateNodeFabNetAttObj(nfna1)
	var expectedApicSlice1 apicapi.ApicSlice
	expectedApicSlice1 = CreateNFNAObjs(nfna1, cont)
	expectedApicSlice1 = PopulateFabricPaths(nfna1,
		[]string{"/topology/pod-1/protpaths-101-102/pathep-[test-bond1]"},
		cont,
		expectedApicSlice1)
	assert.Equal(t, expectedApicSlice1, apicSlice, "nfna create")

	apicSlice = cont.updateNodeFabNetAttObj(nfna2)
	var expectedApicSlice2 apicapi.ApicSlice
	expectedApicSlice2 = CreateNFNAObjs(nfna2, cont)
	expectedApicSlice2 = PopulateFabricPaths(nfna2,
		[]string{"/topology/pod-1/protpaths-101-102/pathep-[test-bond1]",
			"/topology/pod-1/protpaths-101-102/pathep-[test-bond2]",
		},
		cont,
		expectedApicSlice2)
	// Objects can get reordered. TODO: Hash can be used to compare 2 slices
	assert.Equal(t, len(expectedApicSlice2), len(apicSlice), "nfna update")

	apicSlice, networkName, deleted := cont.deleteNodeFabNetAttObj("master1.cluster.local_" + nfna1.Spec.NetworkRef.Namespace + "/" + nfna1.Spec.NetworkRef.Name)
	var expectedApicSlice3 apicapi.ApicSlice
	expectedApicSlice3 = CreateNFNAObjs(nfna2, cont)
	expectedApicSlice3 = PopulateFabricPaths(nfna2,
		[]string{"/topology/pod-1/protpaths-101-102/pathep-[test-bond2]"},
		cont,
		expectedApicSlice3)
	assert.Equal(t, expectedApicSlice3, apicSlice, "nfna delete part1")
	assert.Equal(t, false, deleted, "nfna delete part1 return")
	assert.Equal(t, nfna1.Spec.NetworkRef.Namespace+"-"+nfna1.Spec.NetworkRef.Name, networkName, "nfna delete part1 name")

	_, _, deleted = cont.deleteNodeFabNetAttObj("master2.cluster.local_" + nfna2.Spec.NetworkRef.Namespace + "/" + nfna2.Spec.NetworkRef.Name)
	assert.Equal(t, true, deleted, "nfna delete part2 return")
}

func TestPerPortVlanNFNACRUD(t *testing.T) {
	NFNACRUDCase(t, false)
}

func TestGlobalVlanNFNACRUD(t *testing.T) {
	NFNACRUDCase(t, true)

}
