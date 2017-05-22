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
	PrepareApicSlice(ApicSlice{rule}, "tag")
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
	PrepareApicSlice(ApicSlice{entry}, "tag")
	assert.Equal(t, "http", entry.GetAttr("sFromPort"))
	assert.Equal(t, "https", entry.GetAttr("sToPort"))
	assert.Equal(t, "http", entry.GetAttr("dFromPort"))
	assert.Equal(t, "https", entry.GetAttr("dToPort"))
	assert.Equal(t, "tcp", entry.GetAttr("prot"))
}

func TestNormalizerRedirectDest(t *testing.T) {
	d := NewVnsRedirectDest("fake/dn", "1.1.1.1", "0a:0b:0c:0d:0e:0f")
	PrepareApicSlice(ApicSlice{d}, "tag")
	assert.Equal(t, "0A:0B:0C:0D:0E:0F", d.GetAttr("mac"))
}

func TestTypes(t *testing.T) {
	assert.Equal(t, "uni/tn-common/BD-test",
		NewBridgeDomain("common", "test").GetDn())
	assert.Equal(t, "fake/dn/subnet-[1.1.3.4/24]",
		NewSubnet("fake/dn", "1.1.3.4/24").GetDn())
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
		NewVzRsSubjGraphAtt("fake/dn", "dummy").GetDn())
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
}
