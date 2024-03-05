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

package apicapi

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestApicObject(t *testing.T) {
	bd := EmptyApicObject("notAValidObject", "/fake/dn")
	bd.SetAttr("test1", "value1")
	assert.Equal(t, "value1", bd.GetAttr("test1"))
}

func TestNormalizerHostprotRule(t *testing.T) {
	rule := NewHostprotRule("fake/dn", "ruleName")
	rule.SetAttr("fromPort", "80")
	rule.SetAttr("toPort", "443")
	rule.SetAttr("proto", "6")
	PrepareApicSlice(ApicSlice{rule}, "kube", "tag")
	assert.Equal(t, "http", rule.GetAttr("fromPort"))
	assert.Equal(t, "https", rule.GetAttr("toPort"))
	assert.Equal(t, "tcp", rule.GetAttr("proto"))
}

func TestNormalizerFilterEntry(t *testing.T) {
	entry := NewVzEntry("fake/dn", "entryName")
	entry.SetAttr("sFromPort", "80")
	entry.SetAttr("sToPort", "443")
	entry.SetAttr("dFromPort", "80")
	entry.SetAttr("dToPort", "443")
	entry.SetAttr("prot", "6")
	PrepareApicSlice(ApicSlice{entry}, "kube", "tag")
	assert.Equal(t, "http", entry.GetAttr("sFromPort"))
	assert.Equal(t, "https", entry.GetAttr("sToPort"))
	assert.Equal(t, "http", entry.GetAttr("dFromPort"))
	assert.Equal(t, "https", entry.GetAttr("dToPort"))
	assert.Equal(t, "tcp", entry.GetAttr("prot"))
}

func TestNormalizerRedirectDest(t *testing.T) {
	d := NewVnsRedirectDest("fake/dn", "1.1.1.1", "0a:0b:0c:0d:0e:0f")
	PrepareApicSlice(ApicSlice{d}, "kube", "tag")
	assert.Equal(t, "0A:0B:0C:0D:0E:0F", d.GetAttr("mac"))
}

func TestTypes(t *testing.T) {
	assert.Equal(t, "uni/tn-common/BD-test",
		NewFvBD("common", "test").GetDn())
	assert.Equal(t, "fake/dn/subnet-[1.1.3.4/24]",
		NewFvSubnet("fake/dn", "1.1.3.4/24").GetDn())
	assert.Equal(t, "fake/dn/rsctx",
		NewRsCtx("fake/dn", "rd").GetDn())
	assert.Equal(t, "fake/dn/rsBDToOut-l3out",
		NewRsBdToOut("fake/dn", "l3out").GetDn())
	assert.Equal(t, "fake/dn/tag-tag",
		NewTagInst("fake/dn", "tag").GetDn())
	assert.Equal(t, "uni/tn-common/pol-polName",
		NewHostprotPol("common", "polName").GetDn())
	assert.Equal(t, "fake/dn/subj-subjName",
		NewHostprotSubj("fake/dn", "subjName").GetDn())
	assert.Equal(t, "fake/dn/rule-ruleName",
		NewHostprotRule("fake/dn", "ruleName").GetDn())
	assert.Equal(t, "fake/dn/ip-[1.1.1.1]",
		NewHostprotRemoteIp("fake/dn", "1.1.1.1").GetDn())
	assert.Equal(t, "uni/tn-common/lDevVip-vipName",
		NewVnsLDevVip("common", "vipName").GetDn())
	assert.Equal(t, "fake/dn/rsALDevToPhysDomP",
		NewVnsRsALDevToPhysDomP("fake/dn", "/fake/dn2").GetDn())
	assert.Equal(t, "fake/dn/lIf-interface",
		NewVnsLIf("fake/dn", "interface").GetDn())
	assert.Equal(t, "fake/dn/rscIfAttN-[att1]",
		NewVnsRsCIfAttN("fake/dn", "att1").GetDn())
	assert.Equal(t, "fake/dn/cDev-cdevName",
		NewVnsCDev("fake/dn", "cdevName").GetDn())
	assert.Equal(t, "fake/dn/cIf-[interface]",
		NewVnsCif("fake/dn", "interface").GetDn())
	assert.Equal(t, "fake/dn/rsCIfPathAtt",
		NewVnsRsCIfPathAtt("fake/dn", "/fake/dn2").GetDn())
	assert.Equal(t, "uni/tn-common/AbsGraph-graphName",
		NewVnsAbsGraph("common", "graphName").GetDn())
	assert.Equal(t, "fake/dn/AbsTermNodeCon-termConName",
		NewVnsAbsTermNodeCon("fake/dn", "termConName").GetDn())
	assert.Equal(t, "fake/dn/AbsTermNodeProv-termProvName",
		NewVnsAbsTermNodeProv("fake/dn", "termProvName").GetDn())
	assert.Equal(t, "fake/dn/AbsTConn",
		NewVnsAbsTermConn("fake/dn").GetDn())
	assert.Equal(t, "fake/dn/intmnl",
		NewVnsInTerm("fake/dn").GetDn())
	assert.Equal(t, "fake/dn/outtmnl",
		NewVnsOutTerm("fake/dn").GetDn())
	assert.Equal(t, "fake/dn/AbsConnection-connName",
		NewVnsAbsConnection("fake/dn", "connName").GetDn())
	assert.Equal(t, "fake/dn/rsabsConnectionConns-[/fake/dn2]",
		NewVnsRsAbsConnectionConns("fake/dn", "/fake/dn2").GetDn())
	assert.Equal(t, "fake/dn/AbsNode-nodeName",
		NewVnsAbsNode("fake/dn", "nodeName").GetDn())
	assert.Equal(t, "fake/dn/AbsFConn-funcconn",
		NewVnsAbsFuncConn("fake/dn", "funcconn").GetDn())
	assert.Equal(t, "fake/dn/rsNodeToLDev",
		NewVnsRsNodeToLDev("fake/dn", "/fake/dn2").GetDn())
	assert.Equal(t, "uni/tn-common/svcCont/svcRedirectPol-redir",
		NewVnsSvcRedirectPol("common", "redir").GetDn())
	assert.Equal(t, "fake/dn/RedirectDest_ip-[1.1.1.1]",
		NewVnsRedirectDest("fake/dn", "1.1.1.1", "1:2:3:4:5:6").GetDn())
	assert.Equal(t, "uni/tn-common/ipslaMonitoringPol-polName",
		NewFvIPSLAMonitoringPol("common", "polName").GetDn())
	assert.Equal(t, "fake/dn/rsIPSLAMonitoringPol",
		NewVnsRsIPSLAMonitoringPol("fake/dn", "/fake/dn2").GetDn())
	assert.Equal(t, "uni/tn-common/svcCont/redirectHealthGroup-groupName",
		NewVnsRedirectHealthGroup("common", "groupName").GetDn())
	assert.Equal(t, "fake/dn/rsRedirectHealthGroup",
		NewVnsRsRedirectHealthGroup("fake/dn", "/fake/dn2").GetDn())
	assert.Equal(t, "uni/tn-common/ldevCtx-c-contract-g-graph-n-node",
		NewVnsLDevCtx("common", "contract", "graph", "node").GetDn())
	assert.Equal(t, "fake/dn/rsLDevCtxToLDev",
		NewVnsRsLDevCtxToLDev("fake/dn", "/fake/dn2").GetDn())
	assert.Equal(t, "fake/dn/lIfCtx-c-conn",
		NewVnsLIfCtx("fake/dn", "conn").GetDn())
	assert.Equal(t, "fake/dn/rsLIfCtxToSvcRedirectPol",
		NewVnsRsLIfCtxToSvcRedirectPol("fake/dn", "/fake/dn2").GetDn())
	assert.Equal(t, "fake/dn/rsLIfCtxToBD",
		NewVnsRsLIfCtxToBD("fake/dn", "/fake/dn2").GetDn())
	assert.Equal(t, "fake/dn/rsLIfCtxToLIf",
		NewVnsRsLIfCtxToLIf("fake/dn", "/fake/dn2").GetDn())
	assert.Equal(t, "uni/tn-common/brc-conName",
		NewVzBrCP("common", "conName").GetDn())
	assert.Equal(t, "fake/dn/subj-subjName",
		NewVzSubj("fake/dn", "subjName").GetDn())
	assert.Equal(t, "fake/dn/rssubjFiltAtt-flt1",
		NewVzRsSubjFiltAtt("fake/dn", "flt1").GetDn())
	assert.Equal(t, "fake/dn/rsSubjGraphAtt",
		NewVzRsSubjGraphAtt("fake/dn", "dummy", false).GetDn())
	assert.Equal(t, "uni/tn-common/flt-f1",
		NewVzFilter("common", "f1").GetDn())
	assert.Equal(t, "fake/dn/e-e1",
		NewVzEntry("fake/dn", "e1").GetDn())
	assert.Equal(t, "uni/tn-common/out-out1/instP-name1",
		NewL3extInstP("common", "out1", "name1").GetDn())
	assert.Equal(t, "fake/dn/extsubnet-[1.1.1.1/10]",
		NewL3extSubnet("fake/dn", "1.1.1.1/10").GetDn())
	assert.Equal(t, "fake/dn/rsprov-prov",
		NewFvRsProv("fake/dn", "prov").GetDn())
	assert.Equal(t, "fake/dn/rscons-con",
		NewFvRsCons("fake/dn", "con").GetDn())
	assert.Equal(t, "comp/prov-kube/ctrlr-[domain]-cont/injcont/ns-[ns]/grp-[name]",
		NewVmmInjectedContGrp("kube", "domain", "cont", "ns", "name").GetDn())
	assert.Equal(t, "comp/prov-kube/ctrlr-[domain]-cont/injcont/ns-[ns]/depl-[name]",
		NewVmmInjectedDepl("kube", "domain", "cont", "ns", "name").GetDn())
	assert.Equal(t, "comp/prov-kube/ctrlr-[domain]-cont/injcont/ns-[ns]/rs-[name]",
		NewVmmInjectedReplSet("kube", "domain", "cont", "ns", "name").GetDn())
	assert.Equal(t, "comp/prov-kube/ctrlr-[domain]-cont/injcont/ns-[ns]/svc-[name]",
		NewVmmInjectedSvc("kube", "domain", "cont", "ns", "name").GetDn())
	assert.Equal(t, "fake/dn/ep-podName",
		NewVmmInjectedSvcEp("fake/dn", "podName").GetDn())
	assert.Equal(t, "fake/dn/p-http-prot-tcp-t-https",
		NewVmmInjectedSvcPort("fake/dn", "80", "6", "443").GetDn())
	assert.Equal(t, "comp/prov-kube/ctrlr-[domain]-cont/injcont/host-[name]",
		NewVmmInjectedHost("kube", "domain", "cont", "name").GetDn())
	assert.Equal(t, "comp/prov-kube/ctrlr-[domain]-cont/injcont/ns-[name]",
		NewVmmInjectedNs("kube", "domain", "cont", "name").GetDn())
	assert.Equal(t, "comp/prov-kube/ctrlr-[domain]-cont/injcont/org-[name]",
		NewVmmInjectedOrg("kube", "domain", "cont", "name").GetDn())
	assert.Equal(t, "comp/prov-kube/ctrlr-[domain]-cont/injcont/"+
		"org-[org]/unit-[name]",
		NewVmmInjectedOrgUnit("kube", "domain", "cont", "org", "name").GetDn())
	assert.Equal(t, "comp/prov-kube/ctrlr-[domain]-cont/injcont/"+
		"org-[org]/unit-[unit]/depl-[name]",
		NewVmmInjectedOrgUnitDepl("kube", "domain", "cont",
			"org", "unit", "name").GetDn())
	assert.Equal(t, "comp/prov-kube/ctrlr-[domain]-cont/injcont/"+
		"org-[org]/unit-[unit]/grp-[name]",
		NewVmmInjectedOrgUnitContGrp("kube", "domain", "cont",
			"org", "unit", "name").GetDn())
	assert.Equal(t, "fake/dn/infra",
		NewInfra("fake/dn").GetDn())
	assert.Equal(t, "uni/infra/vmmexporterpol-testTan",
		NewNetflowVmmExporterPol("testTan").GetDn())
	assert.Equal(t, "uni/vmmp-Kubernetes/dom-k8s/vswitchpolcont",
		NewVmmVSwitchPolicyCont("Kubernetes", "k8s").GetDn())
	assert.Equal(t, "fake/dn/rsvswitchExporterPol-[uni/infra/vmmexporterpol-testTan]",
		NewVmmRsVswitchExporterPol("fake/dn", "uni/infra/vmmexporterpol-testTan").GetDn())
	assert.Equal(t, "uni/infra/vsrcgrp-testSrcGrp",
		NewSpanVSrcGrp("testSrcGrp").GetDn())
	assert.Equal(t, "fake/dn/vsrc-testSrc",
		NewSpanVSrc("fake/dn", "testSrc").GetDn())
	assert.Equal(t, "fake/dn/rssrcToVPort-"+
		"[uni/tn-infra/ap-access/epg-default/cep-58:F3:9C:24:5B:F0]",
		NewSpanRsSrcToVPort("fake/dn", "uni/tn-infra/ap-access/epg-default/cep-58:F3:9C:24:5B:F0").GetDn())
	assert.Equal(t, "uni/infra/vdestgrp-testDestGrp",
		NewSpanVDestGrp("testDestGrp").GetDn())
	assert.Equal(t, "fake/dn/vdest-testDest",
		NewSpanVDest("fake/dn", "testDest").GetDn())
	assert.Equal(t, "fake/dn/vepgsummary",
		NewSpanVEpgSummary("fake/dn").GetDn())
	assert.Equal(t, "fake/dn/spanlbl-testDestGrp",
		NewSpanSpanLbl("fake/dn", "testDestGrp").GetDn())
	assert.Equal(t, "uni/infra/funcprof/accbundle-vpc-101-1-20-102-1-20",
		NewInfraAccBndlGrp("vpc-101-1-20-102-1-20").GetDn())
	assert.Equal(t, "uni/infra/funcprof/accportgrp-sauto_l3out_port_grp",
		NewInfraAccPortGrp("sauto_l3out_port_grp").GetDn())
	assert.Equal(t, "uni/infra/funcprof/accbundle-fake/rsspanVSrcGrp-testSrcGrp",
		NewInfraRsSpanVSrcGrp("fake", "testSrcGrp").GetDn())
	assert.Equal(t, "uni/infra/funcprof/accbundle-fake/rsspanVDestGrp-testDestGrp",
		NewInfraRsSpanVDestGrp("fake", "testDestGrp").GetDn())
	assert.Equal(t, "uni/infra/funcprof/accportgrp-fake/rsspanVSrcGrp-testSrcGrp",
		NewInfraRsSpanVSrcGrpAP("fake", "testSrcGrp").GetDn())
	assert.Equal(t, "uni/infra/funcprof/accportgrp-fake/rsspanVDestGrp-testDestGrp",
		NewInfraRsSpanVDestGrpAP("fake", "testDestGrp").GetDn())
	assert.Equal(t, "comp/prov-kube/ctrlr-[domain]-cont/injcont/info",
		NewVmmInjectedClusterInfo("kube", "domain", "cont").GetDn())
	assert.Equal(t, "comp/prov-kube/ctrlr-[domain]-cont/injcont/info/clusterfaultinfo-10",
		NewVmmClusterFaultInfo("comp/prov-kube/ctrlr-[domain]-cont/injcont/info", "10").GetDn())
}
func TestApicConnection_GetDesiredState(t *testing.T) {
	conn := &ApicConnection{
		desiredState: map[string]ApicSlice{
			"key1": {
				ApicObject{
					"vzRsSubjGraphAtt": &ApicObjectBody{
						Attributes: map[string]interface{}{
							"tnVnsAbsGraphName": "graph1",
						},
					},
				},
				ApicObject{
					"vzRsSubjGraphAtt": &ApicObjectBody{
						Attributes: map[string]interface{}{
							"tnVnsAbsGraphName": "graph2",
						},
					},
				},
			},
		},
	}

	key1 := "key1"
	expected1 := conn.desiredState[key1]
	actual1 := conn.GetDesiredState(key1)
	assert.Equal(t, expected1, actual1)

	invalidKey := "invalidKey"
	expected2 := ApicSlice(nil)
	actual2 := conn.GetDesiredState(invalidKey)
	assert.Equal(t, expected2, actual2)
}
func TestApicObject_GetRn(t *testing.T) {
	obj := ApicObject{
		"key1": {
			Attributes: map[string]interface{}{
				"rn": "rn1",
			},
		}}

	expected := "rn1"
	actual := obj.GetRn()
	assert.Equal(t, expected, actual)
}
func TestApicObject_BuildDn(t *testing.T) {
	parentDn := "parent/dn"

	t.Run("WithDn", func(t *testing.T) {
		obj := ApicObject{
			"key1": {
				Attributes: map[string]interface{}{
					"dn": "fake/dn",
				},
			},
		}
		expected := "fake/dn"
		actual := obj.BuildDn(parentDn)
		assert.Equal(t, expected, actual)
	})

	t.Run("WithRn", func(t *testing.T) {
		obj := ApicObject{
			"key1": {
				Attributes: map[string]interface{}{
					"rn": "fakeRn",
				},
			},
		}
		expected := "parent/dn/fakeRn"
		actual := obj.BuildDn(parentDn)
		assert.Equal(t, expected, actual)
	})

	t.Run("Empty", func(t *testing.T) {
		obj := ApicObject{}
		expected := ""
		actual := obj.BuildDn(parentDn)
		assert.Equal(t, expected, actual)
	})
}
func TestApicObject_GetHintDn(t *testing.T) {
	o := ApicObject{
		"key1": {
			HintDn: "hint/dn",
			Attributes: map[string]interface{}{
				"dn": "fake/dn",
			},
		},
	}

	expected := "hint/dn"
	result := o.GetHintDn()
	if result != expected {
		t.Errorf("Expected %s, but got %s", expected, result)
	}
}

func TestApicObject_GetHintDn_Empty(t *testing.T) {
	o := ApicObject{}

	expected := ""
	result := o.GetHintDn()
	if result != expected {
		t.Errorf("Expected %s, but got %s", expected, result)
	}
}

func TestApicSlice_Copy(t *testing.T) {
	slice := ApicSlice{
		ApicObject{
			"vzRsSubjGraphAtt": &ApicObjectBody{
				Attributes: map[string]interface{}{
					"tnVnsAbsGraphName": "graph1",
				},
			},
		},
		ApicObject{
			"vzRsSubjGraphAtt": &ApicObjectBody{
				Attributes: map[string]interface{}{
					"tnVnsAbsGraphName": "graph2",
				},
			},
		},
	}

	copy := slice.Copy()

	assert.Equal(t, len(slice), len(copy))

	for i := range slice {
		assert.Equal(t, slice[i], copy[i])
	}
}
func TestApicObject_Copy(t *testing.T) {
	obj := ApicObject{
		"class1": &ApicObjectBody{
			Attributes: map[string]interface{}{
				"attr1": "value1",
			},
		},
		"class2": &ApicObjectBody{
			Attributes: map[string]interface{}{
				"attr2": "value2",
			},
		},
	}
	copyObj := obj.Copy()

	if &copyObj == &obj {
		t.Errorf("Copy method did not create a new object")
	}

	for class, body := range obj {
		copyBody, ok := copyObj[class]
		if !ok {
			t.Errorf("Copy method did not copy object body for class: %s", class)
		}

		for k, v := range body.Attributes {
			copyV, ok := copyBody.Attributes[k]
			if !ok {
				t.Errorf("Copy method did not copy attribute: %s", k)
			}
			if v != copyV {
				t.Errorf("Copy method did not copy attribute value correctly")
			}
		}

		assert.Equal(t, body.Children, copyBody.Children)
	}
}
func TestNewFvTenant(t *testing.T) {
	name := "testTenant"
	obj := NewFvTenant(name)
	assert.Equal(t, name, obj.GetAttr("name"))
}
func TestNewCloudAwsProvider(t *testing.T) {
	tenant := "testTenant"
	region := "us-west-2"
	providerID := "aws-1234567890"

	obj := NewCloudAwsProvider(tenant, region, providerID)

	assert.Equal(t, region, obj.GetAttr("region"))
	assert.Equal(t, providerID, obj.GetAttr("providerId"))
	assert.Equal(t, fmt.Sprintf("uni/tn-%s/awsprovider", tenant), obj.GetDn())
}

func TestNewCloudCtxProfile(t *testing.T) {
	tenant := "testTenant"
	name := "testProfile"
	expectedDn := fmt.Sprintf("uni/tn-%s/ctxprofile-%s", tenant, name)

	obj := NewCloudCtxProfile(tenant, name)

	expected := ApicObject{
		"cloudCtxProfile": &ApicObjectBody{
			Attributes: map[string]interface{}{
				"dn":   expectedDn,
				"name": name,
			},
		},
	}

	assert.Equal(t, expected, obj)
}

func TestNewCloudRsToCtx(t *testing.T) {
	cCtxDn := "fake/dn"
	ctxName := "testCtx"

	obj := NewCloudRsToCtx(cCtxDn, ctxName)

	expected := ApicObject{
		"cloudRsToCtx": {
			Attributes: map[string]interface{}{
				"tnFvCtxName": ctxName,
				"dn":          fmt.Sprintf("%s/rstoCtx", cCtxDn),
			},
		},
	}

	assert.Equal(t, expected, obj)
}

func TestNewCloudRsCtxProfileToRegion(t *testing.T) {
	cCtxDn := "fake/dn"
	tDn := "/fake/dn2"

	obj := NewCloudRsCtxProfileToRegion(cCtxDn, tDn)

	expected := ApicObject{
		"cloudRsCtxProfileToRegion": {
			Attributes: map[string]interface{}{
				"tDn": tDn,
				"dn":  fmt.Sprintf("%s/rsctxProfileToRegion", cCtxDn),
			},
		},
	}

	assert.Equal(t, expected, obj)
}

func TestNewCloudCidr(t *testing.T) {
	cCtxDn := "fake/dn"
	addr := "10.0.0.0/24"

	obj := NewCloudCidr(cCtxDn, addr)

	expectedDn := fmt.Sprintf("%s/cidr-[%s]", cCtxDn, addr)
	assert.Equal(t, addr, obj.GetAttr("addr"))
	assert.Equal(t, expectedDn, obj.GetDn())
}

func TestNewCloudSubnet(t *testing.T) {
	cidrDn := "fake/dn"
	ip := "1.1.1.1/24"

	subnet := NewCloudSubnet(cidrDn, ip)

	expectedDn := fmt.Sprintf("%s/subnet-[%s]", cidrDn, ip)
	assert.Equal(t, ip, subnet.GetAttr("ip"))
	assert.Equal(t, expectedDn, subnet.GetDn())
}

func TestNewFvCtx(t *testing.T) {
	tenantName := "testTenant"
	name := "testCtx"
	expectedDn := fmt.Sprintf("uni/tn-%s/ctx-%s", tenantName, name)

	ctx := NewFvCtx(tenantName, name)

	assert.Equal(t, name, ctx.GetAttr("name"))
	assert.Equal(t, expectedDn, ctx.GetDn())
}

func TestNewFvnsEncapBlk(t *testing.T) {
	parentDn := "/fake/parent"
	from := "100"
	to := "200"

	obj := NewFvnsEncapBlk(parentDn, from, to)

	expected := ApicObject{
		"fvnsEncapBlk": {
			Attributes: map[string]interface{}{
				"from":      "vlan-100",
				"to":        "vlan-200",
				"allocMode": "static",
			},
			HintDn: "/fake/parent/from-[vlan-100]-to-[vlan-200]",
		},
	}

	assert.Equal(t, expected, obj)
}

func TestNewFvnsVlanInstP(t *testing.T) {
	tenant := "testTenant"
	name := "testName"
	expectedName := tenant + "-" + name
	expectedAllocMode := "static"
	expectedHintDn := "uni/infra/vlanns-[" + expectedName + "]-static"

	obj := NewFvnsVlanInstP(tenant, name)

	assert.Equal(t, expectedName, obj.GetAttr("name"))
	assert.Equal(t, expectedAllocMode, obj.GetAttr("allocMode"))
	assert.Equal(t, expectedHintDn, obj.GetHintDn())
}

func TestNewPhysDomP(t *testing.T) {
	physDom := "testPhysDom"
	expectedDn := "uni/phys-" + physDom

	obj := NewPhysDomP(physDom)

	assert.Equal(t, physDom, obj.GetAttr("name"))
	assert.Equal(t, expectedDn, obj.GetDn())
}

func TestNewInfraRsDomP(t *testing.T) {
	parentDn := "fake/parent/dn"
	tDn := "/fake/tDn"
	expected := ApicObject{
		"infraRsDomP": {
			Attributes: map[string]interface{}{
				"tDn": tDn,
			},
			HintDn: parentDn + "/rsdomP-[" + tDn + "]",
		},
	}

	result := NewInfraRsDomP(parentDn, tDn)

	assert.Equal(t, expected, result)
}
func TestNewInfraRsVlanNs(t *testing.T) {
	parentDn := "fake/dn"
	tDn := "/fake/dn2"
	obj := NewInfraRsVlanNs(parentDn, tDn)

	expected := ApicObject{
		"infraRsVlanNs": {
			Attributes: map[string]interface{}{
				"tDn": tDn,
			},
			HintDn: parentDn + "/rsvlanNs",
		},
	}

	assert.Equal(t, expected, obj)
}

func TestNewFvRsDomAttPhysDom(t *testing.T) {
	parentDn := "fake/parent/dn"
	physDom := "fakePhysDom"

	expectedDn := "fake/parent/dn/rsdomAtt-[uni/phys-fakePhysDom]"
	expectedTdn := "uni/phys-fakePhysDom"

	obj := NewFvRsDomAttPhysDom(parentDn, physDom)

	assert.Equal(t, expectedDn, obj.GetDn())
	assert.Equal(t, expectedDn, obj.GetHintDn())
	assert.Equal(t, expectedTdn, obj["fvRsDomAtt"].Attributes["tDn"])
}

func TestNewFvAP(t *testing.T) {
	ap := "testAp"
	obj := NewFvAP(ap)
	assert.NotNil(t, obj)

	assert.Equal(t, ap, obj.GetAttr("name"))
}

func TestNewFvAEPg(t *testing.T) {
	tenant := "testTenant"
	ap := "testAp"
	name := "testEpg"

	epg := NewFvAEPg(tenant, ap, name)

	expectedDn := fmt.Sprintf("uni/tn-%s/ap-%s/epg-%s", tenant, ap, name)
	expectedName := name

	assert.Equal(t, expectedDn, epg.GetDn())
	assert.Equal(t, expectedName, epg.GetAttr("name"))
}

func TestNewInfraGeneric(t *testing.T) {
	aep := "testAEP"
	expectedDn := "uni/infra/attentp-testAEP/gen-default"

	obj := NewInfraGeneric(aep)

	assert.Equal(t, "default", obj.GetAttr("name"))
	assert.Equal(t, expectedDn, obj.GetDn())
}

func TestNewInfraRsFuncToEpg(t *testing.T) {
	parentDn := "fake/parent/dn"
	epgDn := "fake/epg/dn"
	vlan := "100"
	mode := "regular"

	obj := NewInfraRsFuncToEpg(parentDn, epgDn, vlan, mode)

	expected := ApicObject{
		"infraRsFuncToEpg": {
			Attributes: map[string]interface{}{
				"tDn":   epgDn,
				"encap": "vlan-" + vlan,
				"mode":  mode,
			},
			HintDn: parentDn + "/rsfuncToEpg-[" + epgDn + "]",
		},
	}

	assert.Equal(t, expected, obj)
}

func TestNewFvRsBD(t *testing.T) {
	parentDn := "fake/dn"
	bdName := "testBD"
	obj := NewFvRsBD(parentDn, bdName)

	assert.Equal(t, bdName, obj.GetAttr("tnFvBDName"))
	assert.Equal(t, parentDn+"/rsbd", obj.GetHintDn())
}
func TestNewFvRsPathAtt(t *testing.T) {
	parentDn := "fake/dn"
	path := "/fake/path"
	encap := "100"
	mode := "regular"

	obj := NewFvRsPathAtt(parentDn, path, encap, mode)

	assert.Equal(t, path, obj.GetAttr("tDn"))
	assert.Equal(t, "vlan-"+encap, obj.GetAttr("encap"))
	assert.Equal(t, parentDn+"/rspathAtt-["+path+"]", obj.GetHintDn())
	assert.Equal(t, mode, obj.GetAttr("mode"))
}
func TestNewFvBD(t *testing.T) {
	tenantName := "testTenant"
	name := "testBD"
	expectedDn := "uni/tn-testTenant/BD-testBD"

	bd := NewFvBD(tenantName, name)

	assert.Equal(t, name, bd.GetAttr("name"))
	assert.Equal(t, expectedDn, bd.GetDn())
}
func TestNewFvRsCtx(t *testing.T) {
	parentDn := "fake/dn"
	vrfName := "testVRF"

	obj := NewFvRsCtx(parentDn, vrfName)

	assert.Equal(t, vrfName, obj.GetAttr("tnFvCtxName"))
	assert.Equal(t, parentDn+"/rsctx", obj.GetHintDn())
}
func TestNewCloudApp(t *testing.T) {
	tenantName := "testTenant"
	name := "testApp"

	obj := NewCloudApp(tenantName, name)

	expectedName := "testApp"
	actualName := obj["cloudApp"].Attributes["name"]
	if actualName != expectedName {
		t.Errorf("Expected name to be %s, but got %s", expectedName, actualName)
	}

	expectedDn := "uni/tn-testTenant/cloudapp-testApp"
	actualDn := obj["cloudApp"].Attributes["dn"]
	if actualDn != expectedDn {
		t.Errorf("Expected dn to be %s, but got %s", expectedDn, actualDn)
	}
}

func TestNewCloudEpg(t *testing.T) {
	tenantName := "testTenant"
	appName := "testApp"
	name := "testEpg"

	epg := NewCloudEpg(tenantName, appName, name)

	expectedName := "testEpg"
	expectedDn := fmt.Sprintf("uni/tn-%s/cloudapp-%s/cloudepg-%s", tenantName, appName, name)

	assert.Equal(t, expectedName, epg.GetAttr("name"))
	assert.Equal(t, expectedDn, epg.GetDn())
}
func TestNewDeleteHostprotRemoteIp(t *testing.T) {
	addr := "1.1.1.1"
	obj := NewDeleteHostprotRemoteIp(addr)

	assert.Equal(t, addr, obj.GetAttr("addr"))
	assert.Equal(t, "deleted", obj.GetAttr("status"))
}
func TestNewQosDppPol(t *testing.T) {
	tenantName := "testTenant"
	name := "testPol"
	expectedDn := "uni/tn-testTenant/qosdpppol-testPol"

	obj := NewQosDppPol(tenantName, name)

	assert.Equal(t, name, obj["qosDppPol"].Attributes["name"])
	assert.Equal(t, expectedDn, obj["qosDppPol"].Attributes["dn"])
}
func TestNewQosRequirement(t *testing.T) {
	tenantName := "testTenant"
	name := "testQosReq"
	expectedDn := fmt.Sprintf("uni/tn-%s/qosreq-%s", tenantName, name)

	qosReq := NewQosRequirement(tenantName, name)

	assert.Equal(t, name, qosReq.GetAttr("name"))
	assert.Equal(t, expectedDn, qosReq.GetDn())
}
func TestNewRsEgressDppPol(t *testing.T) {
	parentDn := "fake/parent/dn"
	dppPolName := "testDppPol"

	obj := NewRsEgressDppPol(parentDn, dppPolName)

	expected := ApicObject{
		"qosRsEgressDppPol": {
			Attributes: map[string]interface{}{
				"tnQosDppPolName": dppPolName,
				"dn":              fmt.Sprintf("%s/rsegressDppPol", parentDn),
			},
		},
	}

	assert.Equal(t, expected, obj)
}

func TestNewRsIngressDppPol(t *testing.T) {
	parentDn := "fake/dn"
	dppPolName := "testPol"

	obj := NewRsIngressDppPol(parentDn, dppPolName)

	expected := ApicObject{
		"qosRsIngressDppPol": {
			Attributes: map[string]interface{}{
				"tnQosDppPolName": dppPolName,
				"dn":              fmt.Sprintf("%s/rsingressDppPol", parentDn),
			},
		},
	}

	assert.Equal(t, expected, obj)
}
func TestNewQosEpDscpMarking(t *testing.T) {
	qosreqDn := "/fake/dn"
	name := "testDscpMarking"
	obj := NewQosEpDscpMarking(qosreqDn, name)

	expectedDn := fmt.Sprintf("%s/dscp_marking", qosreqDn)
	assert.Equal(t, expectedDn, obj.GetDn())
	assert.Equal(t, name, obj.GetAttr("name"))
}
func TestNewVzInTerm(t *testing.T) {
	parentDn := "fake/dn"
	expectedDn := "fake/dn/intmnl"

	obj := NewVzInTerm(parentDn)

	assert.Equal(t, expectedDn, obj.GetDn())
}
func TestNewVzOutTerm(t *testing.T) {
	parentDn := "fake/parent/dn"
	expectedDn := "fake/parent/dn/outtmnl"

	obj := NewVzOutTerm(parentDn)

	assert.Equal(t, expectedDn, obj.GetDn())
}
func TestNewVzRsFiltAtt(t *testing.T) {
	parentDn := "fake/dn"
	tnVzFilterName := "filterName"

	obj := NewVzRsFiltAtt(parentDn, tnVzFilterName)

	expected := ApicObject{
		"vzRsFiltAtt": {
			Attributes: map[string]interface{}{
				"tnVzFilterName": tnVzFilterName,
				"dn":             fmt.Sprintf("%s/rsfiltAtt-%s", parentDn, tnVzFilterName),
			},
		},
	}

	assert.Equal(t, expected, obj)
}
func TestNewVzRsInTermGraphAtt(t *testing.T) {
	parentDn := "fake/dn"
	tnVnsAbsGraphName := "testGraph"

	obj := NewVzRsInTermGraphAtt(parentDn, tnVnsAbsGraphName)

	expected := ApicObject{
		"vzRsInTermGraphAtt": {
			Attributes: map[string]interface{}{
				"tnVnsAbsGraphName": tnVnsAbsGraphName,
				"dn":                fmt.Sprintf("%s/rsInTermGraphAtt", parentDn),
			},
		},
	}

	assert.Equal(t, expected, obj)
}

func TestNewVzRsOutTermGraphAtt(t *testing.T) {
	parentDn := "fake/dn"
	tnVnsAbsGraphName := "testGraph"

	obj := NewVzRsOutTermGraphAtt(parentDn, tnVnsAbsGraphName)

	expected := ApicObject{
		"vzRsOutTermGraphAtt": {
			Attributes: map[string]interface{}{
				"tnVnsAbsGraphName": tnVnsAbsGraphName,
				"dn":                fmt.Sprintf("%s/rsOutTermGraphAtt", parentDn),
			},
		},
	}

	assert.Equal(t, expected, obj)
}
func TestNewVmmInjectedNwPol(t *testing.T) {
	vendor := "testVendor"
	domain := "testDomain"
	controller := "testController"
	ns := "testNamespace"
	name := "testName"

	obj := NewVmmInjectedNwPol(vendor, domain, controller, ns, name)

	expectedName := "testName"
	if obj["vmmInjectedNwPol"].Attributes["name"] != expectedName {
		t.Errorf("Expected name to be %s, but got %s", expectedName, obj["vmmInjectedNwPol"].Attributes["name"])
	}

	expectedNameAlias := truncatedName(name)
	if obj["vmmInjectedNwPol"].Attributes["nameAlias"] != expectedNameAlias {
		t.Errorf("Expected nameAlias to be %s, but got %s", expectedNameAlias, obj["vmmInjectedNwPol"].Attributes["nameAlias"])
	}

	expectedDN := fmt.Sprintf("comp/prov-%s/ctrlr-[%s]-%s/injcont/ns-[%s]/nwpol-[%s]", vendor, domain, controller, ns, name)
	if obj["vmmInjectedNwPol"].Attributes["dn"] != expectedDN {
		t.Errorf("Expected dn to be %s, but got %s", expectedDN, obj["vmmInjectedNwPol"].Attributes["dn"])
	}
}
func TestNewVmmInjectedLabel(t *testing.T) {
	parentDn := "fake/dn"
	name := "labelName"
	value := "labelValue"

	obj := NewVmmInjectedLabel(parentDn, name, value)

	expectedDn := fmt.Sprintf("%s/key-[%s]-val-%s", parentDn, name, value)
	assert.Equal(t, expectedDn, obj.GetDn())
	assert.Equal(t, name, obj.GetAttr("name"))
	assert.Equal(t, value, obj.GetAttr("value"))
}
