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
	"testing"

	"github.com/noironetworks/aci-containers/pkg/apicapi"
	"github.com/stretchr/testify/assert"
)

func CreateNFNAExplicitBD(tenant, vrf, bdName string, subnets []fabattv1.Subnets) apicapi.ApicObject {
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
		fvSubnet := apicapi.NewFvSubnet(bd.GetDn(), subnet.Subnet)
		scope := getSubnetScope(subnet.ScopeOptions)
		fvSubnet.SetAttr("scope", scope)
		ctrl := getSubnetCtrl(subnet.ControlOptions)
		fvSubnet.SetAttr("ctrl", ctrl)
		bd.AddChild(fvSubnet)
	}
	return bd
}

func CreateNFNAExplicitEPG(systemid, tenant, apName, bdName, epgName string, consumers, providers []string) apicapi.ApicObject {
	var fvRsDomAtt apicapi.ApicObject
	var epg apicapi.ApicObject
	if apName == "" {
		apName = "netop-" + systemid
	}
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

func CreateAepEpgAttachment(vlan int, aep string, discoveryType fabattv1.StaticPathMgmtType, epg apicapi.ApicObject, labelKey string, progMap map[string]apicapi.ApicSlice) (apicSlice apicapi.ApicSlice) {
	aepDn := "uni/infra/attentp-" + aep
	var physDom string
	var apicSlice2 apicapi.ApicSlice
	physDom = "kubernetes" + "-" + globalScopeVlanDomPrefix
	secondaryPhysDomDn := "uni/phys-" + physDom
	infraRsDomP := apicapi.NewInfraRsDomP(aepDn, secondaryPhysDomDn)
	apicSlice2 = append(apicSlice2, infraRsDomP)
	progMap[labelKey] = apicSlice2
	// Workaround alert: Due to the fact that infraGeneric cannot take
	// any other name than default, we have to follow this hack of not adding
	// infraRsFuncToEpg as a child and making infraGeneric not deletable.
	if discoveryType != fabattv1.StaticPathMgmtTypeLLDP {
		infraGeneric := apicapi.NewInfraGeneric(aep)
		encap := fmt.Sprintf("%d", vlan)
		infraRsFuncToEpg := apicapi.NewInfraRsFuncToEpg(infraGeneric.GetDn(), epg.GetDn(), encap, "regular")
		apicSlice = append(apicSlice, infraGeneric)
		apicSlice = append(apicSlice, infraRsFuncToEpg)
	}
	return apicSlice

}

func CreateNFCVlanRef(vlans string, explicitAp bool, discoveryType fabattv1.StaticPathMgmtType) *fabattv1.NetworkFabricConfiguration {

	nfc := &fabattv1.NetworkFabricConfiguration{
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
							Subnets: []fabattv1.Subnets{
								{
									Subnet: "10.30.40.1/24",
								},
							},
							Vrf: fabattv1.VRF{
								Name:         "testVrf",
								CommonTenant: true},
						},
						DiscoveryType: discoveryType,
					},
				},
			},
		},
	}
	if explicitAp {
		nfc.Spec.VlanRefs[0].Epg.ApplicationProfile = "testAp"
	}
	return nfc
}

func NFCCRUDCase(t *testing.T, additionalVlans string, explicitAp bool, discoveryType fabattv1.StaticPathMgmtType, aciPrefix string) {
	cont := testChainedController(aciPrefix, true, additionalVlans)

	nfna1 := CreateNFNA("macvlan-net1", "master1.cluster.local", "bond1", "pod1-macvlan-net1", "101",
		[]string{"topology/pod-1/node-101/pathep-[eth1/34]", "topology/pod-1/node-102/pathep-[eth1/34]"})
	fvp := CreateFabricVlanPool("aci-containers-system", "default", additionalVlans)
	progMapPool := cont.updateFabricVlanPool(fvp)
	progMapNFC := cont.updateNetworkFabricConfigurationObj(CreateNFCVlanRef("101", explicitAp, discoveryType))
	progMap := cont.updateNodeFabNetAttObj(nfna1)
	var expectedApicSlice1 apicapi.ApicSlice
	expectedApicSlice1 = CreateNFNAObjs(nfna1, additionalVlans, cont)
	var labelKey string
	nfcObjCount := 1
	if explicitAp {
		nfcObjCount = 2
	}
	assert.Equal(t, nfcObjCount, len(progMapNFC), "nfc obj count")
	assert.Equal(t, 1, len(progMapPool), "dom count")
	lenEpgObjs := 1
	if discoveryType == fabattv1.StaticPathMgmtTypeAEP {
		lenEpgObjs = 2
	}
	assert.Equal(t, lenEpgObjs, len(progMap), "nfna epg count")
	expectedApicSlice1 = CreateNFNADom(nfna1, additionalVlans, cont)
	labelKey = cont.aciNameForKey("nfna", "secondary")
	assert.Equal(t, expectedApicSlice1, progMapPool[labelKey], "nfna create global dom")
	var expectedApicSlice2 apicapi.ApicSlice
	bd := CreateNFNAExplicitBD("common", "testVrf", "testBd", []fabattv1.Subnets{{"10.30.40.1/24", nil, nil}})
	expectedApicSlice2 = append(expectedApicSlice2, bd)
	apName := ""
	if explicitAp {
		apName = "testAp"
	}
	epg := CreateNFNAExplicitEPG(aciPrefix, "testTenant", apName, "testBd", "testEpg", []string{"ctrct1"}, []string{"ctrct2"})
	if discoveryType != fabattv1.StaticPathMgmtTypeAEP {
		expectedApicSlice2 = PopulateFabricPaths(epg, 101, nfna1,
			[]string{"topology/pod-1/protpaths-101-102/pathep-[test-bond1]"},
			cont, expectedApicSlice2)
	} else {
		expectedApicSlice2 = append(expectedApicSlice2, epg)
	}
	progMap2 := make(map[string]apicapi.ApicSlice)
	infraRsDomPKey := cont.aciNameForKey("aepPhysDom", "testAep")

	expectedApicSlice2 = append(expectedApicSlice2, CreateAepEpgAttachment(101, "testAep", discoveryType, epg, infraRsDomPKey, progMap2)...)
	labelKey = cont.aciNameForKey("nfna", "secondary-vlan-101")
	assert.Equal(t, expectedApicSlice2, progMap[labelKey], "nfna create global epg vlan 101")
	if explicitAp {
		var expectedApicSlice apicapi.ApicSlice
		ap := apicapi.NewFvAP("testTenant", "testAp")
		expectedApicSlice = append(expectedApicSlice, ap)
		apKey := cont.aciNameForKey("ap", "tenant_testTenant_testAp")
		assert.Equal(t, expectedApicSlice, progMapNFC[apKey], "nfna create ap")
	}
	var expectedApicSlice3 apicapi.ApicSlice
	bd = CreateNFNABD(nfna1, 101, aciPrefix, cont)
	expectedApicSlice3 = append(expectedApicSlice3, bd)
	epg = CreateNFNAEPG(nfna1, 101, aciPrefix, cont)
	expectedApicSlice3 = PopulateFabricPaths(epg, 101, nfna1,
		[]string{"topology/pod-1/protpaths-101-102/pathep-[test-bond1]"},
		cont, expectedApicSlice3)
	delProgMap := cont.deleteNetworkFabricConfigurationObj("NetworkFabricConfiguration")
	nfcObjCount = 1
	if explicitAp {
		nfcObjCount = 2
	}
	assert.Equal(t, nfcObjCount, len(delProgMap), "nfna update epg count")
	assert.Equal(t, expectedApicSlice3, delProgMap[labelKey], "nfna update global epg vlan 101")
	delProgMap = cont.deleteNodeFabNetAttObj("master1.cluster.local_" + nfna1.Spec.NetworkRef.Namespace + "/" + nfna1.Spec.NetworkRef.Name)

	lenEpgObjs = 1
	if discoveryType == fabattv1.StaticPathMgmtTypeAEP {
		lenEpgObjs = 2
	}
	assert.Equal(t, lenEpgObjs, len(delProgMap), "nfna delete epg count")
}

func TestNFCCRUD(t *testing.T) {
	NFCCRUDCase(t, "[100-101]", false, fabattv1.StaticPathMgmtTypeLLDP, "suite1")
	NFCCRUDCase(t, "[100-101]", true, fabattv1.StaticPathMgmtTypeLLDP, "suite1")
	NFCCRUDCase(t, "[100-101]", false, fabattv1.StaticPathMgmtTypeAEP, "suite1")
}
