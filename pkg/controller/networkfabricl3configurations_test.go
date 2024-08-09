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

func CreateNFCL3(vlan int, sviType fabattv1.FabricSviType, useExistingL3Out bool) *fabattv1.NetworkFabricL3Configuration {
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
									UseExistingL3Out:    useExistingL3Out,
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
	if !useExistingL3Out {
		nfc.Spec.Vrfs[0].Tenants = []fabattv1.FabricTenantConfiguration{
			{
				CommonTenant: true,
				L3OutInstances: []fabattv1.FabricL3Out{
					{
						Name: "l3out1",
						ExternalEpgs: []fabattv1.PolicyPrefixGroup{
							{
								Name: "default",
								PolicyPrefixes: []fabattv1.PolicyPrefix{
									{
										Subnet: "0.0.0.0/0",
									},
								},
								Contracts: fabattv1.Contracts{
									Consumer: []string{"internal_bd_allow_all"},
									Provider: []string{"l3out1_allow_all"},
								},
							},
						},
					},
				},
			},
		}
	}
	return nfc
}

func GetNFCL3Status(vlan int, sviType fabattv1.FabricSviType, useExistingL3Out bool) *fabattv1.NetworkFabricL3ConfigStatus {
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
								UseExistingL3Out:    useExistingL3Out,
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
	subnet := fabattv1.FabricL3Subnet{
		ConnectedSubnet:  "192.168.100.0/24",
		SecondaryAddress: "192.168.100.253/24",
	}
	if sviType == fabattv1.FloatingSviType {
		subnet.FloatingAddress = "192.168.100.254/24"
	} else {
		nfcL3Status.Vrfs[0].DirectlyConnectedNetworks[0].Nodes[0].PrimaryAddress = "192.168.100.243/24"
		nfcL3Status.Vrfs[0].DirectlyConnectedNetworks[0].Nodes[1].PrimaryAddress = "192.168.100.244/24"
	}
	nfcL3Status.Vrfs[0].DirectlyConnectedNetworks[0].Subnets = append(nfcL3Status.Vrfs[0].DirectlyConnectedNetworks[0].Subnets, subnet)
	if !useExistingL3Out {
		nfcL3Status.Vrfs[0].Tenants[0].L3OutInstances[0].ExternalEpgs = []fabattv1.PolicyPrefixGroup{
			{
				Name: "default",
				PolicyPrefixes: []fabattv1.PolicyPrefix{
					{
						Subnet: "0.0.0.0/0",
					},
				},
				Contracts: fabattv1.Contracts{
					Consumer: []string{"internal_bd_allow_all"},
					Provider: []string{"l3out1_allow_all"},
				},
			},
		}
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
	if is_regular_svi {
		nw.IP[3] = 243
	}
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
			l3extVirtualLifP.AddChild(l3extIp)
			l3extVirtualLifP.AddChild(l3extRsDynPathAtt)
			bgpPeerP := apicapi.NewBGPPeerP(l3extVirtualLifP.GetDn(), "192.168.100.0/24", "", "", "", "", "", 3, 1, 0)
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
		bgpPeerP := apicapi.NewBGPPeerP(l3extRsPath.GetDn(), "192.168.100.0/24", "", "", "", "", "", 3, 1, 0)
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
	} else {
		l3out := apicapi.NewL3ExtOut("common", "l3out1", "")
		rsEctx := apicapi.NewL3ExtRsEctx("common", "l3out1", "vrf1")
		l3out.AddChild(rsEctx)
		bgpExtP := apicapi.NewBGPExtP(l3out.GetDn())
		l3out.AddChild(bgpExtP)
		l3Dom := cont.config.AciPolicyTenant + "-" + globalScopeVlanDomPrefix
		rsl3DomAtt := apicapi.NewL3ExtRsL3DomAtt("common", "l3out1", l3Dom)
		l3out.AddChild(rsl3DomAtt)
		l3ExtInstP := apicapi.NewL3extInstP("common", "l3out1", "default")
		l3ExtSubnet := apicapi.NewL3extSubnet(l3ExtInstP.GetDn(), "0.0.0.0/0", "", "")
		l3ExtInstP.AddChild(l3ExtSubnet)
		fvRsCons := apicapi.NewFvRsCons(l3ExtInstP.GetDn(), "internal_bd_allow_all")
		l3ExtInstP.AddChild(fvRsCons)
		fvRsProv := apicapi.NewFvRsProv(l3ExtInstP.GetDn(), "l3out1_allow_all")
		l3ExtInstP.AddChild(fvRsProv)
		l3out.AddChild(l3ExtInstP)
		l3out.AddChild(l3outNodeP)
		apicSlice = append(apicSlice, l3out)
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
	nfcL3Obj = CreateNFCL3(101, sviType, preexisting_l3out)
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
	//cont.log.Info("Expected", expectedApicSlice1, "\nActual: ", progMap[labelKey])
	assert.Equal(t, expectedApicSlice1, progMap[labelKey], "nfna create floating svi")
	status := cont.computeNetworkFabricL3ConfigurationStatus(false)
	expectedStatus := GetNFCL3Status(101, sviType, preexisting_l3out)
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
	if !preexisting_l3out {
		assert.Equal(t, expectedStatus.Vrfs[0].Tenants[0].L3OutInstances[0].ExternalEpgs, status.Vrfs[0].Tenants[0].L3OutInstances[0].ExternalEpgs, "nfcl3status external epgs")
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
	NFCL3CRUDCase(t, "[100-101]", "suite1", false, true)
	NFCL3CRUDCase(t, "[100-101]", "suite1", false, false)
}

func NFCL3RestoreCase(t *testing.T, additionalVlans string, aciPrefix string, preexisting_l3out, use_regular_svi bool) {
	cont := testChainedController(aciPrefix, true, additionalVlans)
	nfna1 := CreateNFNA("macvlan-net1", "master1.cluster.local", "bond1", "pod1-macvlan-net1", "101",
		[]string{"topology/pod-1/node-101/pathep-[eth1/34]", "topology/pod-1/node-102/pathep-[eth1/34]"})
	fvp := CreateFabricVlanPool("aci-containers-system", "default", additionalVlans)
	cont.updateFabricVlanPool(fvp)
	sviType := fabattv1.FloatingSviType
	if use_regular_svi {
		sviType = fabattv1.ConventionalSviType
	}
	expectedStatus := GetNFCL3Status(101, sviType, preexisting_l3out)
	nfcL3Obj := &fabattv1.NetworkFabricL3Configuration{
		Status: *expectedStatus,
	}
	cont.restoreNetworkFabricL3ConfigurationStatus(nfcL3Obj)
	cont.updateNodeFabNetAttObj(nfna1)
	nfcL3Obj = CreateNFCL3(101, sviType, preexisting_l3out)
	cont.updateNetworkFabricL3ConfigObj(nfcL3Obj)
	status := cont.computeNetworkFabricL3ConfigurationStatus(false)
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
	if !preexisting_l3out {
		assert.Equal(t, expectedStatus.Vrfs[0].Tenants[0].L3OutInstances[0].ExternalEpgs, status.Vrfs[0].Tenants[0].L3OutInstances[0].ExternalEpgs, "nfcl3status external epgs")
	}
}

func TestNFCRestore(t *testing.T) {
	NFCL3RestoreCase(t, "[100-101]", "suite1", true, false)
	NFCL3RestoreCase(t, "[100-101]", "suite1", true, true)
	NFCL3RestoreCase(t, "[100-101]", "suite1", false, true)
	NFCL3RestoreCase(t, "[100-101]", "suite1", false, false)
}
