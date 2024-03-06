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

// Test for network fabric configuration.
package controller

import (
	fabattv1 "github.com/noironetworks/aci-containers/pkg/fabricattachment/apis/aci.fabricattachment/v1"

	"fmt"
	"github.com/noironetworks/aci-containers/pkg/apicapi"
	"github.com/stretchr/testify/assert"
	"testing"
)

func CreateNFNAExplicitBD(tenant, vrf, bdName string, subnets []string) apicapi.ApicObject {
	bd := apicapi.NewFvBD(tenant, bdName)
	bd.SetAttr("arpFlood", "yes")
	bd.SetAttr("ipLearning", "no")
	bd.SetAttr("unicastRoute", "no")
	if len(subnets) != 0 {
		bd.SetAttr("unicastRoute", "yes")
	}
	bd.SetAttr("unkMacUcastAct", "flood")
	fvRsCtx := apicapi.NewFvRsCtx(bd.GetDn(), vrf)
	bd.AddChild(fvRsCtx)
	for _, subnet := range subnets {
		fvSubnet := apicapi.NewFvSubnet(bd.GetDn(), subnet)
		bd.AddChild(fvSubnet)
	}
	return bd
}

func CreateNFNAExplicitEPG(systemid, tenant, bdName, epgName string, consumers, providers []string) apicapi.ApicObject {
	var fvRsDomAtt apicapi.ApicObject
	var epg apicapi.ApicObject
	apName := "netop-" + systemid
	epg = apicapi.NewFvAEPg(tenant, apName, epgName)
	fvRsBd := apicapi.NewFvRsBD(epg.GetDn(), bdName)
	epg.AddChild(fvRsBd)
	fvRsDomAtt = apicapi.NewFvRsDomAttPhysDom(epg.GetDn(), "kubernetes-secondary")
	epg.AddChild(fvRsDomAtt)
	for _, consumer := range consumers {
		fvRsCons := apicapi.NewFvRsCons(epg.GetDn(), consumer)
		epg.AddChild(fvRsCons)
	}
	for _, provider := range providers {
		fvRsProv := apicapi.NewFvRsProv(epg.GetDn(), provider)
		epg.AddChild(fvRsProv)
	}
	return epg
}

func CreateAepEpgAttachment(vlan int, aep string, epg apicapi.ApicObject) (apicSlice apicapi.ApicSlice) {
	aepDn := "uni/infra/attentp-" + aep
	var physDom string
	physDom = "kubernetes" + "-" + globalScopeVlanDomPrefix
	secondaryPhysDomDn := "uni/phys-" + physDom
	infraRsDomP := apicapi.NewInfraRsDomP(aepDn, secondaryPhysDomDn)
	apicSlice = append(apicSlice, infraRsDomP)
	// Workaround alert: Due to the fact that infraGeneric cannot take
	// any other name than default, we have to follow this hack of not adding
	// infraRsFuncToEpg as a child and making infraGeneric not deletable.
	infraGeneric := apicapi.NewInfraGeneric(aep)
	encap := fmt.Sprintf("%d", vlan)
	infraRsFuncToEpg := apicapi.NewInfraRsFuncToEpg(infraGeneric.GetDn(), epg.GetDn(), encap, "regular")
	apicSlice = append(apicSlice, infraGeneric)
	apicSlice = append(apicSlice, infraRsFuncToEpg)
	return apicSlice

}

func CreateNFCVlanRef(vlans string) *fabattv1.NetworkFabricConfiguration {
	return &fabattv1.NetworkFabricConfiguration{
		Spec: fabattv1.NetworkFabricConfigurationSpec{
			VlanRefs: []fabattv1.VlanRef{
				{
					Vlans: vlans,
					Aeps:  []string{"testAep"},
					Epg: fabattv1.Epg{
						Name:   "testEpg",
						Tenant: "testTenant",
						Contracts: fabattv1.Contracts{
							Consumer: []string{"ctrct1"},
							Provider: []string{"ctrct2"}},
						BD: fabattv1.BridgeDomain{
							Name:         "testBd",
							CommonTenant: true,
							Subnets:      []string{"10.30.40.1/24"},
							Vrf: fabattv1.VRF{
								Name:         "testVrf",
								CommonTenant: true},
						},
					},
				},
			},
		},
	}
}

func NFCCRUDCase(t *testing.T, additionalVlans string, aciPrefix string) {
	cont := testChainedController(aciPrefix, true, additionalVlans)

	nfna1 := CreateNFNA("macvlan-net1", "master1.cluster.local", "bond1", "pod1-macvlan-net1", "101",
		[]string{"/topology/pod-1/node-101/pathep-[eth1/34]", "/topology/pod-1/node-102/pathep-[eth1/34]"})
	fvp := CreateFabricVlanPool("aci-containers-system", "default", additionalVlans)
	progMapPool := cont.updateFabricVlanPool(fvp)
	progMapNFC := cont.updateNetworkFabricConfigurationObj(CreateNFCVlanRef("101"))
	progMap := cont.updateNodeFabNetAttObj(nfna1)
	var expectedApicSlice1 apicapi.ApicSlice
	expectedApicSlice1 = CreateNFNAObjs(nfna1, additionalVlans, cont)
	var labelKey string
	assert.Equal(t, 1, len(progMapNFC), "nfc obj count")
	assert.Equal(t, 1, len(progMapPool), "dom count")
	assert.Equal(t, 1, len(progMap), "nfna epg count")
	expectedApicSlice1 = CreateNFNADom(nfna1, additionalVlans, cont)
	labelKey = cont.aciNameForKey("nfna", "secondary")
	assert.Equal(t, expectedApicSlice1, progMapPool[labelKey], "nfna create global dom")
	var expectedApicSlice2 apicapi.ApicSlice
	bd := CreateNFNAExplicitBD("common", "testVrf", "testBd", []string{"10.30.40.1/24"})
	expectedApicSlice2 = append(expectedApicSlice2, bd)
	epg := CreateNFNAExplicitEPG(aciPrefix, "testTenant", "testBd", "testEpg", []string{"ctrct1"}, []string{"ctrct2"})
	expectedApicSlice2 = PopulateFabricPaths(epg, 101, nfna1,
		[]string{"/topology/pod-1/protpaths-101-102/pathep-[test-bond1]"},
		cont, expectedApicSlice2)
	expectedApicSlice2 = append(expectedApicSlice2, CreateAepEpgAttachment(101, "testAep", epg)...)
	labelKey = cont.aciNameForKey("nfna", "secondary-vlan-101")
	assert.Equal(t, expectedApicSlice2, progMap[labelKey], "nfna create global epg vlan 101")

	var expectedApicSlice3 apicapi.ApicSlice
	bd = CreateNFNABD(nfna1, 101, aciPrefix, cont)
	expectedApicSlice3 = append(expectedApicSlice3, bd)
	epg = CreateNFNAEPG(nfna1, 101, aciPrefix, cont)
	expectedApicSlice3 = PopulateFabricPaths(epg, 101, nfna1,
		[]string{"/topology/pod-1/protpaths-101-102/pathep-[test-bond1]"},
		cont, expectedApicSlice3)
	delProgMap := cont.deleteNetworkFabricConfigurationObj("NetworkFabricConfiguration")
	assert.Equal(t, 1, len(delProgMap), "nfna update epg count")
	assert.Equal(t, expectedApicSlice3, delProgMap[labelKey], "nfna update global epg vlan 101")
	delProgMap = cont.deleteNodeFabNetAttObj("master1.cluster.local_" + nfna1.Spec.NetworkRef.Namespace + "/" + nfna1.Spec.NetworkRef.Name)
	assert.Equal(t, 2, len(delProgMap), "nfna delete epg count")
}

func TestNFCCRUD(t *testing.T) {
	NFCCRUDCase(t, "[100-101]", "suite1")
}
