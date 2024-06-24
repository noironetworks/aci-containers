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

// Handlers for network fabric l3 configuration updates.

package controller

import (
	"fmt"
	"net"
	"testing"

	fabattv1 "github.com/noironetworks/aci-containers/pkg/fabricattachment/apis/aci.fabricattachment/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/noironetworks/aci-containers/pkg/apicapi"
	"github.com/stretchr/testify/assert"
)

func CreateNFCL3(vlan int, sviType fabattv1.FabricSviType) *fabattv1.NetworkFabricL3Configuration {
	nfc := &fabattv1.NetworkFabricL3Configuration{
		ObjectMeta: metav1.ObjectMeta{
			Name: "networkfabricl3configuration",
		},
		Spec: fabattv1.NetworkFabricL3ConfigSpec{
			Vrfs: []fabattv1.FabricVrfConfiguration{
				{
					Vrf: fabattv1.VRF{
						Name:         "vrf1",
						CommonTenant: false,
					},
					DirectlyConnectedNetworks: []fabattv1.ConnectedL3Network{
						{
							FabricL3Network: fabattv1.FabricL3Network{
								PrimaryNetwork: fabattv1.PrimaryNetwork{
									L3OutName:           "l3out1",
									L3OutOnCommonTenant: true,
									UseExistingL3Out:    true,
									Encap:               vlan,
									SviType:             sviType,
									PrimarySubnet:       "192.168.100.0/24",
									BGPPeerPolicy: fabattv1.BGPPeerPolicy{
										Enabled:      true,
										PeerASN:      64514,
										PrefixPolicy: "default",
									},
								},
							},
						},
					},
				},
			},
		},
	}
	return nfc
}

func GetNFCL3Status(vlan int, sviType fabattv1.FabricSviType) *fabattv1.NetworkFabricL3ConfigStatus {
	nfcL3Status := &fabattv1.NetworkFabricL3ConfigStatus{
		Vrfs: []fabattv1.FabricVrfConfigurationStatus{
			{
				Vrf: fabattv1.VRF{
					Name:         "vrf1",
					CommonTenant: false,
				},
				DirectlyConnectedNetworks: []fabattv1.ConnectedL3NetworkStatus{
					{ConnectedL3Network: fabattv1.ConnectedL3Network{
						FabricL3Network: fabattv1.FabricL3Network{
							PrimaryNetwork: fabattv1.PrimaryNetwork{
								L3OutName:           "l3out1",
								L3OutOnCommonTenant: true,
								UseExistingL3Out:    true,
								Encap:               vlan,
								SviType:             sviType,
								PrimarySubnet:       "192.168.100.0/24",
								BGPPeerPolicy: fabattv1.BGPPeerPolicy{
									Enabled:      true,
									PeerASN:      64514,
									PrefixPolicy: "default",
								},
							},
							Subnets: []fabattv1.FabricL3Subnet{},
						},
						Nodes: []fabattv1.FabricL3OutNode{
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
				},
				Tenants: []fabattv1.FabricTenantConfigurationStatus{
					{
						CommonTenant: true,
						L3OutInstances: []fabattv1.FabricL3OutStatus{
							{
								FabricL3Out: fabattv1.FabricL3Out{
									Name: "l3out1",
									RtrNodes: []fabattv1.FabricL3OutRtrNode{
										{
											NodeRef: fabattv1.FabricNodeRef{
												FabricPodRef: fabattv1.FabricPodRef{
													PodId: 1,
												},
												NodeId: 101,
											},
											RtrId: "101.101.0.101",
										},
										{
											NodeRef: fabattv1.FabricNodeRef{
												FabricPodRef: fabattv1.FabricPodRef{
													PodId: 1,
												},
												NodeId: 102,
											},
											RtrId: "102.102.0.102",
										},
									},
									PodRef: fabattv1.FabricPodRef{
										PodId: 1,
									},
								},
							},
						},
					},
				},
			},
		},
	}
	return nfcL3Status
}

func CreateNFNASVIObjs(cont *testAciController, vlan int, use_preexisting_l3out, is_regular_svi bool) apicapi.ApicSlice {
	nodeProfileName := fmt.Sprintf("%s-vlan-%d", "l3out1"+"_"+globalScopeVlanLNodePPrefix, vlan)
	intfProfileName := fmt.Sprintf("%s-vlan-%d", "l3out1"+"_"+globalScopeVlanExtLifPPrefix, vlan)
	l3outNodeP := apicapi.NewL3ExtLNodeP("common", "l3out1", nodeProfileName)
	l3outLifP := apicapi.NewL3ExtLifP("common", "l3out1", nodeProfileName, intfProfileName)
	_, nw, _ := net.ParseCIDR("192.168.100.0/24")
	mskLen, _ := nw.Mask.Size()
	nw.IP[3] = 247
	primaryAddr := make(net.IP, 4)
	floatingAddr := make(net.IP, 4)
	secondaryAddr := make(net.IP, 4)
	copy(primaryAddr, nw.IP)
	nw.IP[3] = 254
	copy(floatingAddr, nw.IP)
	nw.IP[3] = 253
	copy(secondaryAddr, nw.IP)
	primaryAddrStr := fmt.Sprintf("%s/%d", primaryAddr.String(), mskLen)
	floatingAddrStr := fmt.Sprintf("%s/%d", floatingAddr.String(), mskLen)
	secondaryAddrStr := fmt.Sprintf("%s/%d", secondaryAddr.String(), mskLen)
	nw.IP[3] = 253
	copy(secondaryAddr, nw.IP)
	encapVlan := fmt.Sprintf("vlan-%d", vlan)
	fabricLink := "topology/pod-1/protpaths-101-102/pathep-[test-bond1]"
	l3extRsPath := apicapi.NewL3ExtRsPathL3OutAtt(l3outLifP.GetDn(), fabricLink, "ext-svi", encapVlan)
	side := []string{"A", "B"}
	peerASN := "64514"
	for idx, nodeId := range []int{101, 102} {
		rtrId := fmt.Sprintf("%d.%d.0.%d", nodeId, nodeId, nodeId)
		nodeDn := fmt.Sprintf("topology/pod-1/node-%d", nodeId)
		if !is_regular_svi {
			l3extVirtualLifP := apicapi.NewL3ExtVirtualLifP(l3outLifP.GetDn(), "ext-svi", nodeDn, encapVlan, primaryAddrStr)
			l3extRsDynPathAtt := apicapi.NewL3ExtRsDynPathAtt(l3extVirtualLifP.GetDn(), cont.globalVlanConfig.SharedPhysDom.GetDn(), floatingAddrStr, encapVlan)
			l3extIp := apicapi.NewL3ExtIp(l3extVirtualLifP.GetDn(), secondaryAddrStr)
			l3extVirtualLifP.AddChild(l3extRsDynPathAtt)
			l3extVirtualLifP.AddChild(l3extIp)
			bgpPeerP := apicapi.NewBGPPeerP(l3extVirtualLifP.GetDn(), "192.168.100.0/24", "", "")
			bgpAsP := apicapi.NewBGPAsP(bgpPeerP.GetDn(), peerASN)
			bgpPeerP.AddChild(bgpAsP)
			bgpRsPPfxPol := apicapi.NewBGPRsPeerPfxPol(bgpPeerP.GetDn(), "common", "default")
			bgpPeerP.AddChild(bgpRsPPfxPol)
			l3extVirtualLifP.AddChild(bgpPeerP)
			l3outLifP.AddChild(l3extVirtualLifP)
		} else {
			l3extMember := apicapi.NewL3ExtMember(l3extRsPath.GetDn(), side[idx], primaryAddrStr)
			l3extIp := apicapi.NewL3ExtIp(l3extMember.GetDn(), secondaryAddrStr)
			l3extMember.AddChild(l3extIp)
			l3extRsPath.AddChild(l3extMember)
		}
		l3extRsNodeL3OutAtt := apicapi.NewL3ExtRsNodeL3OutAtt(l3outNodeP.GetDn(), nodeDn, rtrId)
		l3outNodeP.AddChild(l3extRsNodeL3OutAtt)
		primaryAddr[3] += byte(1)
		primaryAddrStr = fmt.Sprintf("%s/%d", primaryAddr.String(), mskLen)
	}
	if is_regular_svi {
		bgpPeerP := apicapi.NewBGPPeerP(l3extRsPath.GetDn(), "192.168.100.0/24", "", "")
		bgpAsP := apicapi.NewBGPAsP(bgpPeerP.GetDn(), peerASN)
		bgpPeerP.AddChild(bgpAsP)
		bgpRsPPfxPol := apicapi.NewBGPRsPeerPfxPol(bgpPeerP.GetDn(), "common", "default")
		bgpPeerP.AddChild(bgpRsPPfxPol)
		l3extRsPath.AddChild(bgpPeerP)
		l3outLifP.AddChild(l3extRsPath)
	}
	l3outNodeP.AddChild(l3outLifP)
	var apicSlice apicapi.ApicSlice
	if use_preexisting_l3out {
		apicSlice = append(apicSlice, l3outNodeP)
	}
	return apicSlice
}

func NFCL3CRUDCase(t *testing.T, additionalVlans string, aciPrefix string, preexisting_l3out, use_regular_svi bool) {
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
	nfcL3Obj = CreateNFCL3(101, sviType)
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
	status := cont.computeNetworkFabricL3ConfigurationStatus()
	expectedStatus := GetNFCL3Status(101, sviType)
	assert.Equal(t, expectedStatus.Vrfs[0].DirectlyConnectedNetworks[0].FabricL3Network, status.Vrfs[0].DirectlyConnectedNetworks[0].FabricL3Network, "nfcl3status svi")
	if expectedStatus.Vrfs[0].DirectlyConnectedNetworks[0].Nodes[0].NodeRef != status.Vrfs[0].DirectlyConnectedNetworks[0].Nodes[0].NodeRef {
		assert.Equal(t, expectedStatus.Vrfs[0].DirectlyConnectedNetworks[0].Nodes[0], status.Vrfs[0].DirectlyConnectedNetworks[0].Nodes[1], "nfcl3status svi ipam")
		assert.Equal(t, expectedStatus.Vrfs[0].DirectlyConnectedNetworks[0].Nodes[1], status.Vrfs[0].DirectlyConnectedNetworks[0].Nodes[0], "nfcl3status svi ipam")
	} else {
		assert.Equal(t, expectedStatus.Vrfs[0].DirectlyConnectedNetworks[0].Nodes, status.Vrfs[0].DirectlyConnectedNetworks[0].Nodes, "nfcl3status svi ipam")
	}
	if expectedStatus.Vrfs[0].Tenants[0].L3OutInstances[0].RtrNodes[0].RtrId != status.Vrfs[0].Tenants[0].L3OutInstances[0].RtrNodes[0].RtrId {
		assert.Equal(t, expectedStatus.Vrfs[0].Tenants[0].L3OutInstances[0].RtrNodes[0], status.Vrfs[0].Tenants[0].L3OutInstances[0].RtrNodes[1], "nfcl3status rtrNode0")
		assert.Equal(t, expectedStatus.Vrfs[0].Tenants[0].L3OutInstances[0].RtrNodes[1], status.Vrfs[0].Tenants[0].L3OutInstances[0].RtrNodes[0], "nfcl3status rtrNode1")
	} else {
		assert.Equal(t, expectedStatus.Vrfs[0].Tenants[0].L3OutInstances[0].RtrNodes, status.Vrfs[0].Tenants[0].L3OutInstances[0].RtrNodes, "nfcl3status rtrNodes")
	}
	delProgMap := cont.deleteNetworkFabricL3ConfigObj()
	nfcObjCount = 1
	assert.Equal(t, nfcObjCount, len(delProgMap), "nfna update epg count")
	delProgMap = cont.deleteNodeFabNetAttObj("master1.cluster.local_" + nfna1.Spec.NetworkRef.Namespace + "/" + nfna1.Spec.NetworkRef.Name)
	assert.Equal(t, 2, len(delProgMap), "nfna delete epg count")
}

func TestNFCL3CRUD(t *testing.T) {
	NFCL3CRUDCase(t, "[100-101]", "suite1", true, false)
	NFCL3CRUDCase(t, "[100-101]", "suite1", true, true)
	// TODO: CreateL3out, Subnets,contracts, extepg
}
