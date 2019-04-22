/***
Copyright 2019 Cisco Systems Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package watchers

import (
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"github.com/noironetworks/aci-containers/pkg/apicapi"
	"github.com/noironetworks/aci-containers/pkg/gbpcrd/apis/aci.aw/v1"
	"github.com/noironetworks/aci-containers/pkg/gbpserver"
	"reflect"
	"testing"
	"time"
)

type suite struct {
	s  *gbpserver.Server
	aw *ApicWatcher
}

func (s *suite) setup() {
	s.s = gbpserver.NewServer()
	s.aw = NewApicWatcher(s.s)
}

func (s *suite) expectMsg(op int, msg interface{}) error {
	gotOp, gotMsg, err := s.s.UTReadMsg(200 * time.Millisecond)
	if err != nil {
		return err
	}

	if gotOp != op {
		return fmt.Errorf("Exp op: %d, got: %d", op, gotOp)
	}

	if !reflect.DeepEqual(msg, gotMsg) {
		spew.Dump(msg)
		spew.Dump(gotMsg)
		return fmt.Errorf("msgs don't match")
	}

	return nil
}

func (s *suite) expectOp(op int) error {
	gotOp, _, err := s.s.UTReadMsg(200 * time.Millisecond)
	if err != nil {
		return err
	}

	if gotOp != op {
		return fmt.Errorf("Exp op: %d, got: %d", op, gotOp)
	}

	return nil
}

var apic_epgA_obj = apicapi.ApicObject{
	"cloudEPg": &apicapi.ApicObjectBody{
		Attributes: map[string]interface{}{
			"isSharedSrvMsiteEPg": "no",
			"lcOwn":               "local",
			"modTs":               "2019-04-05T18:45:36.886+00:00",
			"pcTag":               "32772",
			"uid":                 "15374",
			"childAction":         "",
			"extMngdBy":           "",
			"floodOnEncap":        "disabled",
			"monPolDn":            "",
			"name":                "epg-a",
			"status":              "",
			"triggerSt":           "triggerable",
			"annotation":          "",
			"exceptionTag":        "",
			"nameAlias":           "",
			"prefGrMemb":          "exclude",
			"prio":                "unspecified",
			"txId":                "6341068275337766678",
			"configIssues":        "",
			"descr":               "",
			"dn":                  "uni/tn-test-kube/cloudapp-test-kubeApp1/cloudepg-epg-a",
			"matchT":              "AtleastOne",
			"scope":               "2097152",
			"configSt":            "applied",
		},
		Children: apicapi.ApicSlice{
			{"fvRsProv": &apicapi.ApicObjectBody{Attributes: map[string]interface{}{"annotation": "", "childAction": "", "ctrctUpd": "ctrct", "extMngdBy": "", "forceResolve": "yes", "lcOwn": "local", "matchT": "AtleastOne", "modTs": "2019-04-05T18:45:36.886+00:00", "monPolDn": "", "prio": "unspecified", "rType": "mo", "rn": "rsprov-tcp-6020", "state": "formed", "stateQual": "none", "status": "", "tCl": "vzBrCP", "tContextDn": "", "tDn": "uni/tn-test-kube/brc-tcp-6020", "tRn": "brc-tcp-6020", "tType": "name", "tnVzBrCPName": "tcp-6020", "triggerSt": "triggerable", "uid": "15374", "updateCollection": "no"}, Children: []apicapi.ApicObject{{"fvCollectionCont": &apicapi.ApicObjectBody{Attributes: map[string]interface{}{"childAction": "", "collectionDn": "uni/tn-test-kube/brc-tcp-6020", "lcOwn": "local", "modTs": "2019-04-05T18:45:36.822+00:00", "monPolDn": "", "name": "", "nameAlias": "", "rn": "collectionDn-[uni/tn-test-kube/brc-tcp-6020]", "status": ""}}}}}},
			{"fvRsCons": &apicapi.ApicObjectBody{Attributes: map[string]interface{}{"annotation": "", "childAction": "", "ctrctUpd": "ctrct", "deplInfo": "", "extMngdBy": "", "forceResolve": "yes", "lcOwn": "local", "modTs": "2019-04-05T18:45:36.886+00:00", "monPolDn": "", "prio": "unspecified", "rType": "mo", "rn": "rscons-tcp-6020", "state": "formed", "stateQual": "none", "status": "", "tCl": "vzBrCP", "tContextDn": "", "tDn": "uni/tn-test-kube/brc-tcp-6020", "tRn": "brc-tcp-6020", "tType": "name", "tnVzBrCPName": "tcp-6020", "triggerSt": "triggerable", "uid": "15374", "updateCollection": "no"}, Children: []apicapi.ApicObject{{"fvCollectionCont": {Attributes: map[string]interface{}{"childAction": "", "collectionDn": "uni/tn-test-kube/brc-tcp-6020", "lcOwn": "local", "modTs": "2019-04-05T18:45:36.822+00:00", "monPolDn": "", "name": "", "nameAlias": "", "rn": "collectionDn-[uni/tn-test-kube/brc-tcp-6020]", "status": ""}}}}}},
		},
	},
}

var apic_contract_obj = apicapi.ApicObject{
	"vzBrCP": &apicapi.ApicObjectBody{
		Attributes: map[string]interface{}{
			"descr":         "",
			"extMngdBy":     "",
			"nameAlias":     "",
			"status":        "",
			"uid":           "15374",
			"modTs":         "2019-04-05T18:40:39.422+00:00",
			"ownerKey":      "",
			"ownerTag":      "",
			"prio":          "unspecified",
			"reevaluateAll": "no",
			"childAction":   "",
			"name":          "tcp-6020",
			"scope":         "context",
			"annotation":    "",
			"configIssues":  "",
			"dn":            "uni/tn-test-kube/brc-tcp-6020",
			"lcOwn":         "local",
			"monPolDn":      "uni/tn-common/monepg-default",
			"targetDscp":    "unspecified",
		},
		Children: apicapi.ApicSlice{
			{"vzSubj": &apicapi.ApicObjectBody{Attributes: map[string]interface{}{"annotation": "", "childAction": "", "configIssues": "", "consMatchT": "AtleastOne", "descr": "", "extMngdBy": "", "lcOwn": "local", "modTs": "2019-04-05T18:45:34.119+00:00", "monPolDn": "uni/tn-common/monepg-default", "name": "subj-tcp-6020", "nameAlias": "", "prio": "unspecified", "provMatchT": "AtleastOne", "revFltPorts": "yes", "rn": "subj-subj-tcp-6020", "status": "", "targetDscp": "unspecified", "uid": "15374"}, Children: []apicapi.ApicObject{{"vzRsSubjFiltAtt": &apicapi.ApicObjectBody{Attributes: map[string]interface{}{"action": "permit", "annotation": "", "childAction": "", "directives": "", "extMngdBy": "", "forceResolve": "yes", "lcOwn": "local", "modTs": "2019-04-05T18:45:34.119+00:00", "monPolDn": "uni/tn-common/monepg-default", "priorityOverride": "default", "rType": "mo", "rn": "rssubjFiltAtt-tcp-6020", "state": "formed", "stateQual": "none", "status": "", "tCl": "vzFilter", "tContextDn": "", "tDn": "uni/tn-test-kube/flt-tcp-6020", "tRn": "flt-tcp-6020", "tType": "name", "tnVzFilterName": "tcp-6020", "uid": "15374"}}}}}},
		},
	},
}

var apic_filter_obj = apicapi.ApicObject{
	"vzFilter": &apicapi.ApicObjectBody{
		Attributes: map[string]interface{}{
			"ownerTag":               "",
			"txId":                   "6341068275337766672",
			"usesIds":                "yes",
			"lcOwn":                  "local",
			"nameAlias":              "",
			"ownerKey":               "",
			"name":                   "tcp-6020",
			"status":                 "",
			"dn":                     "uni/tn-test-kube/flt-tcp-6020",
			"fwdId":                  "27",
			"monPolDn":               "uni/tn-common/monepg-default",
			"id":                     "implicit",
			"revId":                  "27",
			"uid":                    "15374",
			"unsupportedEntries":     "no",
			"unsupportedMgmtEntries": "no",
			"annotation":             "",
			"childAction":            "",
			"descr":                  "",
			"extMngdBy":              "",
			"modTs":                  "2019-04-05T18:45:34.048+00:00",
		},
		Children: apicapi.ApicSlice{
			{"vzEntry": &apicapi.ApicObjectBody{Attributes: map[string]interface{}{"annotation": "", "applyToFrag": "no", "arpOpc": "unspecified", "childAction": "", "dFromPort": "unspecified", "dToPort": "unspecified", "descr": "", "etherT": "ip", "extMngdBy": "", "icmpv4T": "unspecified", "icmpv6T": "unspecified", "lcOwn": "local", "matchDscp": "unspecified", "modTs": "2019-04-05T18:45:34.006+00:00", "monPolDn": "uni/tn-common/monepg-default", "name": "0", "nameAlias": "", "prot": "tcp", "rn": "e-0", "sFromPort": "unspecified", "sToPort": "unspecified", "stateful": "no", "status": "", "tcpRules": "", "uid": "15374"}}},
		},
	},
}
var gbp_epgA_obj = &gbpserver.EPG{
	Tenant:        "test-kube",
	Name:          "epg-a",
	ConsContracts: []string{"test-kube/tcp-6020"},
	ProvContracts: []string{"test-kube/tcp-6020"},
}

var gbp_epgA_obj_trim = &gbpserver.EPG{
	Tenant:        "test-kube",
	Name:          "epg-a",
	ProvContracts: []string{"test-kube/tcp-6020"},
}

var gbp_contract = &gbpserver.Contract{
	Tenant: "test-kube",
	Name:   "tcp-6020",
	AllowList: []v1.WLRule{
		{
			Protocol: "tcp",
		},
	},
}

func TestApicEPG(t *testing.T) {
	ts := &suite{}
	ts.setup()
	ts.aw.EpgChanged(apic_epgA_obj)
	err := ts.expectMsg(gbpserver.OpaddEPG, gbp_epgA_obj)
	if err != nil {
		t.Error(err)
	}

	// verify redundant updates are ignored
	apic_epgA_obj.SetAttr("modTs", "2020-05-05T18:45:36.886+00:00")
	ts.aw.EpgChanged(apic_epgA_obj)
	err = ts.expectMsg(gbpserver.OpaddEPG, gbp_epgA_obj)
	if err == nil {
		t.Errorf("Expected timeout")
	}

	// make a genuine update and verify
	for _, body := range apic_epgA_obj {
		body.Children = body.Children[0:1]
	}

	ts.aw.EpgChanged(apic_epgA_obj)
	err = ts.expectMsg(gbpserver.OpaddEPG, gbp_epgA_obj_trim)
	if err != nil {
		t.Error(err)
	}

	// inject a contract
	ts.aw.ContractChanged(apic_contract_obj)
	err = ts.expectOp(gbpserver.OpdelContract)
	if err != nil {
		t.Error(err)
	}

	err = ts.expectMsg(gbpserver.OpaddEPG, gbp_epgA_obj_trim)
	if err != nil {
		t.Error(err)
	}

	ts.aw.FilterChanged(apic_filter_obj)
	err = ts.expectMsg(gbpserver.OpaddContract, gbp_contract)
	if err != nil {
		t.Error(err)
	}
	err = ts.expectMsg(gbpserver.OpaddEPG, gbp_epgA_obj_trim)
	if err != nil {
		t.Error(err)
	}
	err = ts.expectMsg(gbpserver.OpaddEPG, gbp_epgA_obj_trim)
	if err == nil {
		t.Errorf("Expected timeout")
	}

	//spew.Dump(ts.aw.idb)

	// deleting the filter should result in removal of the contract
	ts.aw.FilterDeleted("uni/tn-test-kube/flt-tcp-6020")
	err = ts.expectOp(gbpserver.OpdelContract)
	if err != nil {
		t.Error(err)
	}
}
