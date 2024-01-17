// Copyright 2021 Cisco Systems, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package controller

import (
	"encoding/json"
	"sort"
	"testing"

	apicapi "github.com/noironetworks/aci-containers/pkg/apicapi"
	"github.com/noironetworks/aci-containers/pkg/metadata"
)

func TestGetEpgFromEppd(t *testing.T) {
	cont := testController()
	cont.run()
	defer cont.stop()
	cont.config.AciVmmDomain = "k8s16_test"
	vmmEppdDn := "uni/vmmp-Kubernetes/dom-k8s16_test/eppd-[uni/tn-k8s16_test/ap-aci-containers-k8s16_test/epg-ns1]"
	epgDn := cont.getEpgFromEppd(vmmEppdDn)
	if epgDn != "uni/tn-k8s16_test/ap-aci-containers-k8s16_test/epg-ns1" {
		t.Errorf("EpgDn not returned")
	}
}

func TestVmmEpPDChanged(t *testing.T) {
	cont := testController()
	cont.run()
	defer cont.stop()
	cont.config.AciVmmDomain = "k8s16_test"
	vmmEppdDn := "uni/vmmp-Kubernetes/dom-k8s16_test/eppd-[uni/tn-k8s16_test/ap-aci-containers-k8s16_test/epg-ns1]"
	attr := map[string]interface{}{
		"dn": vmmEppdDn,
	}
	obj := apicapi.ApicObject{
		"vmmEpPD": {
			Attributes: attr,
		},
	}
	cont.vmmEpPDChanged(obj)
	expectedCachedEpgDnsString := "uni/tn-k8s16_test/ap-aci-containers-k8s16_test/epg-ns1"
	if cont.cachedEpgDns[0] != expectedCachedEpgDnsString {
		t.Errorf("EpgCache not updated")
	}
}

func TestVmmEpPDChangedAlreadyCached(t *testing.T) {
	cont := testController()
	cont.run()
	defer cont.stop()
	cont.config.AciVmmDomain = "k8s16_test"
	vmmEppdDn := "uni/vmmp-Kubernetes/dom-k8s16_test/eppd-[uni/tn-k8s16_test/ap-aci-containers-k8s16_test/epg-ns1]"
	attr := map[string]interface{}{
		"dn": vmmEppdDn,
	}
	obj := apicapi.ApicObject{
		"vmmEpPD": {
			Attributes: attr,
		},
	}
	expectedCachedEpgDnsString := "uni/tn-k8s16_test/ap-aci-containers-k8s16_test/epg-ns1"
	cont.cachedEpgDns = append(cont.cachedEpgDns, expectedCachedEpgDnsString)
	cont.vmmEpPDChanged(obj)
	if len(cont.cachedEpgDns) != 1 {
		t.Errorf("EpgCache updated with duplicate value")
	}
}

func TestVmmEpPDDeleted(t *testing.T) {
	cont := testController()
	cont.run()
	defer cont.stop()
	cont.config.AciVmmDomain = "k8s16_test"
	vmmEppdDn := "uni/vmmp-Kubernetes/dom-k8s16_test/eppd-[uni/tn-k8s16_test/ap-aci-containers-k8s16_test/epg-ns1]"
	testCachedEpgDnsString := "uni/tn-k8s16_test/ap-aci-containers-k8s16_test/epg-ns1"
	cont.cachedEpgDns = append(cont.cachedEpgDns, testCachedEpgDnsString)
	cont.vmmEpPDDeleted(vmmEppdDn)
	if len(cont.cachedEpgDns) != 0 {
		t.Errorf("EpgCache not deleted")
	}
}

func TestRemoveSlice(t *testing.T) {
	cont := testController()
	testString1 := "some random string"
	testString2 := "another random string"
	var testSlice []string
	testSlice = append(testSlice, testString1)
	testSlice = append(testSlice, testString2)
	sort.Strings(testSlice)
	cont.removeSlice(&testSlice, testString1)
	if len(testSlice) != 1 {
		t.Errorf("String not removed from slice")
	}
	if testSlice[0] != testString2 {
		t.Errorf("Wrong string removed from slice")
	}
}

func TestCheckEpgCache(t *testing.T) {
	cont := testController()
	cont.run()
	defer cont.stop()
	cont.config.AciVmmDomain = "k8s16_test"
	testEgval := metadata.OpflexGroup{
		Tenant:     "k8s16_test",
		AppProfile: "aci-containers-k8s16_test",
		Name:       "ns1",
	}
	testEgvalString, _ := json.Marshal(testEgval)
	testComment := "testComment"
	testEpgDn := "uni/tn-k8s16_test/ap-aci-containers-k8s16_test/epg-ns1"
	cont.cachedEpgDns = append(cont.cachedEpgDns, testEpgDn)

	expectedEgval := metadata.OpflexGroup{
		Tenant:     "k8s16_test",
		AppProfile: "aci-containers-k8s16_test",
		Name:       "ns1",
	}

	present, egval, fault := cont.checkEpgCache(string(testEgvalString), testComment)

	if !present {
		t.Errorf("Epg not present in cache")
	}
	if egval != expectedEgval {
		t.Errorf("Epg not returned from cache")
	}
	if fault {
		t.Errorf("Fault returned from cache")
	}
}

func TestCheckEpgCacheInvalidFormat(t *testing.T) {
	cont := testController()
	cont.run()
	defer cont.stop()
	cont.config.AciVmmDomain = "k8s16_test"
	testComment := "testComment"
	testEpgDn := "uni/tn-k8s16_test/ap-aci-containers-k8s16_test/epg-ns1"
	cont.cachedEpgDns = append(cont.cachedEpgDns, testEpgDn)

	expectedEgval := metadata.OpflexGroup{
		Tenant:     "",
		AppProfile: "",
		Name:       "",
	}

	present, egval, fault := cont.checkEpgCache("test", testComment)

	if present {
		t.Errorf("Epg should not be present in cache")
	}
	if egval != expectedEgval {
		t.Errorf("Invalid egval returned")
	}
	if fault {
		t.Errorf("Fault returned from cache")
	}
}

func TestCheckEpgCacheInvalidFormat2(t *testing.T) {
	cont := testController()
	cont.run()
	defer cont.stop()
	cont.config.AciVmmDomain = "k8s16_test"
	type test struct {
		Ten        string
		AppProfile string
		Name       string
	}
	testEgval := test{
		Ten:        "k8s16_test",
		AppProfile: "aci-containers-k8s16_test",
		Name:       "ns1",
	}
	testEgvalString, _ := json.Marshal(testEgval)
	testComment := "testComment"
	testEpgDn := "uni/tn-k8s16_test/ap-aci-containers-k8s16_test/epg-ns1"
	cont.cachedEpgDns = append(cont.cachedEpgDns, testEpgDn)

	expectedEgval := metadata.OpflexGroup{
		Name: "ns1",
	}

	present, egval, fault := cont.checkEpgCache(string(testEgvalString), testComment)

	if present {
		t.Errorf("Epg should not be present in cache")
	}
	if egval != expectedEgval {
		t.Errorf("Invalid egval returned")
	}
	if fault {
		t.Errorf("Fault returned from cache")
	}
}

func TestCheckEpgCacheNotExist(t *testing.T) {
	cont := testController()
	cont.run()
	defer cont.stop()
	cont.config.AciVmmDomain = "k8s16_test"
	testEgval := metadata.OpflexGroup{
		Tenant:     "k8s16_test",
		AppProfile: "aci-containers-k8s16_test",
		Name:       "ns1",
	}
	testEgvalString, _ := json.Marshal(testEgval)
	testComment := "testComment"
	testEpgDn := "uni/tn-k8s16_test/ap-aci-containers-k8s16_test/epg-ns2"
	cont.cachedEpgDns = append(cont.cachedEpgDns, testEpgDn)

	expectedEgval := metadata.OpflexGroup{
		Tenant:     "k8s16_test",
		AppProfile: "aci-containers-k8s16_test",
		Name:       "ns1",
	}

	present, egval, fault := cont.checkEpgCache(string(testEgvalString), testComment)

	if present {
		t.Errorf("Epg should not be present in cache")
	}
	if egval != expectedEgval {
		t.Errorf("Epg not returned from cache")
	}
	if !fault {
		t.Errorf("Fault should be returned from cache")
	}
}

func TestClearFaultInstances(t *testing.T) {
	cont := testController()
	cont.run()
	defer cont.stop()
	cont.config.AciVmmDomain = "k8s16_test"
	cont.apicConn.ApicIndex = 0
	cont.apicConn.Apic = append(cont.apicConn.Apic, "testhost:80")
	cont.clearFaultInstances()
}
