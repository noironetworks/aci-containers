// Copyright 2024 Cisco Systems, Inc.
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

// Test for neodefabricl3peers.
package controller

import (
	"fmt"
	"sort"
	"testing"

	fabattv1 "github.com/noironetworks/aci-containers/pkg/fabricattachment/apis/aci.fabricattachment/v1"

	"github.com/noironetworks/aci-containers/pkg/apicapi"
	"github.com/stretchr/testify/assert"
)

func GetNodeFabricNetworkL3PeerStatus(vlan int) *fabattv1.NodeFabricNetworkL3PeerStatus {
	nodeFabricL3PeerStatus := &fabattv1.NodeFabricNetworkL3PeerStatus{
		NADRefs: []fabattv1.NADFabricL3Peer{
			{
				NAD: fabattv1.ObjRef{
					Name:      "macvlan-net1",
					Namespace: "default",
				},
				Nodes: []fabattv1.NodeFabricL3Peer{
					{
						NodeName: "master1.cluster.local",
						FabricL3Peers: []fabattv1.FabricL3Peers{
							{
								Encap:         vlan,
								FabricPodId:   1,
								FabricNodeIds: []int{101, 102},
							},
						},
					},
				},
			},
		},
		PeeringInfo: []fabattv1.NetworkFabricL3PeeringInfo{
			{
				Encap: vlan,
				ASN:   64514,
				Secret: fabattv1.ObjRef{
					Name:      "",
					Namespace: "",
				},
				FabricNodes: []fabattv1.FabricL3OutNode{
					{
						NodeRef: fabattv1.FabricNodeRef{
							FabricPodRef: fabattv1.FabricPodRef{
								PodId: 1,
							},
							NodeId: 101,
						},
						PrimaryAddress: "192.168.100.247/24",
					},
					{
						NodeRef: fabattv1.FabricNodeRef{
							FabricPodRef: fabattv1.FabricPodRef{
								PodId: 1,
							},
							NodeId: 102,
						},
						PrimaryAddress: "192.168.100.248/24",
					},
				},
			},
		},
	}
	return nodeFabricL3PeerStatus
}

type TestFabL3OutNodes []fabattv1.FabricL3OutNode

func (a TestFabL3OutNodes) Len() int           { return len(a) }
func (a TestFabL3OutNodes) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a TestFabL3OutNodes) Less(i, j int) bool { return a[i].NodeRef.NodeId < a[j].NodeRef.NodeId }

func NodeFabricNetworkL3PeerCRUDCase(t *testing.T, additionalVlans string, aciPrefix string, preexisting_l3out, use_regular_svi bool) {
	cont := testChainedController(aciPrefix, true, additionalVlans)

	nfna1 := CreateNFNA("macvlan-net1", "master1.cluster.local", "bond1", "pod1-macvlan-net1", "101",
		[]string{"topology/pod-1/node-101/pathep-[eth1/34]", "topology/pod-1/node-102/pathep-[eth1/34]"})
	fvp := CreateFabricVlanPool("aci-containers-system", "default", additionalVlans)
	progMapPool := cont.updateFabricVlanPool(fvp)
	var nfcL3Obj *fabattv1.NetworkFabricL3Configuration
	sviType := fabattv1.FloatingSviType
	if use_regular_svi {
		sviType = fabattv1.ConventionalSviType
	}
	nfcL3Obj = CreateNFCL3(101, sviType, true)
	progMapNFC := cont.updateNetworkFabricL3ConfigObj(nfcL3Obj)
	progMap := cont.updateNodeFabNetAttObj(nfna1)
	var expectedApicSlice1 apicapi.ApicSlice
	//expectedApicSlice1 = CreateNFNAObjs(nfna1, additionalVlans, cont)
	var labelKey string
	nfcObjCount := 1
	assert.Equal(t, nfcObjCount, len(progMapNFC), "nfc obj count")
	assert.Equal(t, 1, len(progMapPool), "dom count")
	assert.Equal(t, 2, len(progMap), "nfna svi count")
	expectedApicSlice1 = CreateNFNADom(nfna1, additionalVlans, cont)
	labelKey = cont.aciNameForKey("nfna", "secondary")
	assert.Equal(t, expectedApicSlice1, progMapPool[labelKey], "nfna create global dom")
	epgName := fmt.Sprintf("%s-%d", globalScopeVlanEpgPrefix, 101)
	labelKey = cont.aciNameForKey("nfna", epgName)
	expectedApicSlice1 = CreateNFNASVIObjs(cont, 101, preexisting_l3out, use_regular_svi)
	assert.Equal(t, expectedApicSlice1, progMap[labelKey], "nfna create floating svi")
	expectedL3Peers := GetNodeFabricNetworkL3PeerStatus(101)
	l3peers := cont.computeNodeFabricNetworkL3PeerStatus(false)
	for _, peerInfo := range l3peers.PeeringInfo {
		sort.Sort(TestFabL3OutNodes(peerInfo.FabricNodes))
	}
	for _, NADRefs := range l3peers.NADRefs {
		for _, nodes := range NADRefs.Nodes {
			sort.Ints(nodes.FabricL3Peers[0].FabricNodeIds)
		}
	}
	assert.Equal(t, expectedL3Peers, l3peers, "nfna nodefabricl3peers status")
	delProgMap := cont.deleteNetworkFabricL3ConfigObj()
	nfcObjCount = 1
	assert.Equal(t, nfcObjCount, len(delProgMap), "nfna update epg count")
	expectedL3Peers = &fabattv1.NodeFabricNetworkL3PeerStatus{}
	l3peers = cont.computeNodeFabricNetworkL3PeerStatus(false)
	assert.Equal(t, expectedL3Peers, l3peers, "nfna nodefabricl3peers status ond delete")
	delProgMap = cont.deleteNodeFabNetAttObj("master1.cluster.local_" + nfna1.Spec.NetworkRef.Namespace + "/" + nfna1.Spec.NetworkRef.Name)
	assert.Equal(t, 1, len(delProgMap), "nfna delete epg count")
}

func TestNodeFabricL3PeersCRUD(t *testing.T) {
	NodeFabricNetworkL3PeerCRUDCase(t, "[100-101]", "suite1", true, false)
}
