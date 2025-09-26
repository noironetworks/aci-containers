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

// Unit tests for AAEP monitor utility functions - targeting 0% coverage functions

package controller

import (
	"testing"

	nadapi "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Test utility functions that don't require complex setup
func TestMatchesAEPFilter(t *testing.T) {
	cont := testController()

	// Initialize shared AAEP monitor map
	cont.sharedAaepMonitor = make(map[string][]*AaepMonitoringData)
	cont.sharedAaepMonitor["test-aaep"] = []*AaepMonitoringData{}
	cont.sharedAaepMonitor["prod-aaep"] = []*AaepMonitoringData{}

	tests := []struct {
		name           string
		infraRsObjDn   string
		expectedResult string
	}{
		{
			name:           "Matches test-aaep",
			infraRsObjDn:   "uni/infra/attentp-test-aaep/rsPathToIf-[uni/tn-test/ap-test/epg-web]",
			expectedResult: "test-aaep",
		},
		{
			name:           "Matches prod-aaep",
			infraRsObjDn:   "uni/infra/attentp-prod-aaep/rsPathToIf-[uni/tn-prod/ap-prod/epg-db]",
			expectedResult: "prod-aaep",
		},
		{
			name:           "No match",
			infraRsObjDn:   "uni/infra/attentp-unknown-aaep/rsPathToIf-[uni/tn-test/ap-test/epg-web]",
			expectedResult: "",
		},
		{
			name:           "Empty DN",
			infraRsObjDn:   "",
			expectedResult: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cont.matchesAEPFilter(tt.infraRsObjDn)
			assert.Equal(t, tt.expectedResult, result)
		})
	}
}

func TestGetEpgDnFromInfraRsDn(t *testing.T) {
	cont := testController()

	tests := []struct {
		name           string
		infraRsObjDn   string
		expectedResult string
	}{
		{
			name:           "Valid EPG DN extraction",
			infraRsObjDn:   "uni/infra/attentp-test-aaep/rsPathToIf-[uni/tn-test/ap-test/epg-web]",
			expectedResult: "uni/tn-test/ap-test/epg-web",
		},
		{
			name:           "Complex EPG DN",
			infraRsObjDn:   "uni/infra/attentp-prod-aaep/rsPathToIf-[uni/tn-production/ap-myapp/epg-database-tier]",
			expectedResult: "uni/tn-production/ap-myapp/epg-database-tier",
		},
		{
			name:           "No brackets",
			infraRsObjDn:   "uni/infra/attentp-test-aaep/rsPathToIf-uni/tn-test/ap-test/epg-web",
			expectedResult: "",
		},
		{
			name:           "Empty brackets",
			infraRsObjDn:   "uni/infra/attentp-test-aaep/rsPathToIf-[]",
			expectedResult: "",
		},
		{
			name:           "Empty input",
			infraRsObjDn:   "",
			expectedResult: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cont.getEpgDnFromInfraRsDn(tt.infraRsObjDn)
			assert.Equal(t, tt.expectedResult, result)
		})
	}
}

func TestGenerateDefaultNadName(t *testing.T) {
	cont := testController()

	tests := []struct {
		name           string
		epgDn          string
		expectedResult string
	}{
		{
			name:           "Standard EPG DN",
			epgDn:          "uni/tn-test/ap-web/epg-frontend",
			expectedResult: "test-web-frontend",
		},
		{
			name:           "Production EPG DN",
			epgDn:          "uni/tn-production/ap-database/epg-mysql-cluster",
			expectedResult: "production-database-mysql-cluster",
		},
		{
			name:           "Simple names",
			epgDn:          "uni/tn-t/ap-a/epg-e",
			expectedResult: "t-a-e",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cont.generateDefaultNadName(tt.epgDn)
			assert.Equal(t, tt.expectedResult, result)
		})
	}
}

func TestGetVlanId(t *testing.T) {
	cont := testController()

	tests := []struct {
		name           string
		encap          string
		expectedResult int
	}{
		{
			name:           "Valid VLAN",
			encap:          "vlan-100",
			expectedResult: 100,
		},
		{
			name:           "High VLAN ID",
			encap:          "vlan-4094",
			expectedResult: 4094,
		},
		{
			name:           "VLAN ID 1",
			encap:          "vlan-1",
			expectedResult: 1,
		},
		{
			name:           "Invalid format",
			encap:          "invalid-100",
			expectedResult: 0,
		},
		{
			name:           "Non-numeric VLAN",
			encap:          "vlan-abc",
			expectedResult: 0,
		},
		{
			name:           "Empty encap",
			encap:          "",
			expectedResult: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cont.getVlanId(tt.encap)
			assert.Equal(t, tt.expectedResult, result)
		})
	}
}

func TestGetAaepDiff(t *testing.T) {
	cont := testController()

	// Initialize shared AAEP monitor map
	cont.sharedAaepMonitor = make(map[string][]*AaepMonitoringData)
	cont.sharedAaepMonitor["existing-aaep-1"] = []*AaepMonitoringData{}
	cont.sharedAaepMonitor["existing-aaep-2"] = []*AaepMonitoringData{}

	tests := []struct {
		name            string
		crAaeps         []string
		expectedAdded   []string
		expectedRemoved []string
	}{
		{
			name:            "Add new AaEPs",
			crAaeps:         []string{"existing-aaep-1", "existing-aaep-2", "new-aaep-1", "new-aaep-2"},
			expectedAdded:   []string{"new-aaep-1", "new-aaep-2"},
			expectedRemoved: []string{},
		},
		{
			name:            "Remove existing AaEPs",
			crAaeps:         []string{"existing-aaep-1"},
			expectedAdded:   []string{},
			expectedRemoved: []string{"existing-aaep-2"},
		},
		{
			name:            "Mixed add and remove",
			crAaeps:         []string{"existing-aaep-1", "new-aaep-1"},
			expectedAdded:   []string{"new-aaep-1"},
			expectedRemoved: []string{"existing-aaep-2"},
		},
		{
			name:            "No changes",
			crAaeps:         []string{"existing-aaep-1", "existing-aaep-2"},
			expectedAdded:   []string{},
			expectedRemoved: []string{},
		},
		{
			name:            "Empty CR list",
			crAaeps:         []string{},
			expectedAdded:   []string{},
			expectedRemoved: []string{"existing-aaep-1", "existing-aaep-2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			added, removed := cont.getAaepDiff(tt.crAaeps)

			// Sort slices for consistent comparison
			assert.ElementsMatch(t, tt.expectedAdded, added)
			assert.ElementsMatch(t, tt.expectedRemoved, removed)
		})
	}
}

func TestIsVmmLiteNAD(t *testing.T) {
	cont := testController()

	tests := []struct {
		name           string
		nadDetails     *nadapi.NetworkAttachmentDefinition
		expectedResult bool
	}{
		{
			name: "VMM Lite NAD",
			nadDetails: &nadapi.NetworkAttachmentDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"managed-by": "cisco-network-operator",
					},
				},
			},
			expectedResult: true,
		},
		{
			name: "Non-VMM Lite NAD",
			nadDetails: &nadapi.NetworkAttachmentDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"managed-by": "other-operator",
					},
				},
			},
			expectedResult: false,
		},
		{
			name: "No annotations",
			nadDetails: &nadapi.NetworkAttachmentDefinition{
				ObjectMeta: metav1.ObjectMeta{},
			},
			expectedResult: false,
		},
		{
			name: "Nil annotations",
			nadDetails: &nadapi.NetworkAttachmentDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: nil,
				},
			},
			expectedResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cont.isVmmLiteNAD(tt.nadDetails)
			assert.Equal(t, tt.expectedResult, result)
		})
	}
}

func TestGetNADDeleteMessage(t *testing.T) {
	cont := testController()

	tests := []struct {
		name           string
		deleteReason   string
		expectedResult string
	}{
		{
			name:           "Namespace annotation removed",
			deleteReason:   "NamespaceAnnotationRemoved",
			expectedResult: "NAD is in use by pods: Namespace name EPG annotaion removed",
		},
		{
			name:           "AAEP EPG detached",
			deleteReason:   "AaepEpgDetached",
			expectedResult: "NAD is in use by pods: EPG detached from AAEP",
		},
		{
			name:           "CR deleted",
			deleteReason:   "CRDeleted",
			expectedResult: "NAD is in use by pods: aaepmonitor CR deleted",
		},
		{
			name:           "AAEP removed from CR",
			deleteReason:   "AaepRemovedFromCR",
			expectedResult: "NAD is in use by pods: AAEP removed from aaepmonitor CR",
		},
		{
			name:           "Unknown reason",
			deleteReason:   "UnknownReason",
			expectedResult: "NAD is in use by pods: One or many pods are using NAD",
		},
		{
			name:           "Empty reason",
			deleteReason:   "",
			expectedResult: "NAD is in use by pods: One or many pods are using NAD",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cont.getNADDeleteMessage(tt.deleteReason)
			assert.Equal(t, tt.expectedResult, result)
		})
	}
}

func TestGetNADRevampMessage(t *testing.T) {
	cont := testController()

	tests := []struct {
		name           string
		createReason   string
		expectedResult string
	}{
		{
			name:           "Namespace annotation added",
			createReason:   "NamespaceAnnotationAdded",
			expectedResult: "NAD is in sync: Namespace name EPG annotaion added",
		},
		{
			name:           "AAEP EPG attached",
			createReason:   "AaepEpgAttached",
			expectedResult: "NAD is in sync: EPG attached with AAEP",
		},
		{
			name:           "AAEP added in CR",
			createReason:   "AaepAddedInCR",
			expectedResult: "NAD is in sync: AAEP added back in aaepmonitor CR",
		},
		{
			name:           "Namespace created",
			createReason:   "NamespaceCreated",
			expectedResult: "NAD is in sync: Namespace created back",
		},
		{
			name:           "Unknown reason",
			createReason:   "UnknownReason",
			expectedResult: "NAD is in sync: NAD synced with ACI",
		},
		{
			name:           "Empty reason",
			createReason:   "",
			expectedResult: "NAD is in sync: NAD synced with ACI",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cont.getNADRevampMessage(tt.createReason)
			assert.Equal(t, tt.expectedResult, result)
		})
	}
}

// Test isNADUpdateRequired function with various scenarios
func TestIsNADUpdateRequired(t *testing.T) {
	cont := testController()

	tests := []struct {
		name           string
		nadData        *AaepMonitoringData
		existingNAD    *nadapi.NetworkAttachmentDefinition
		expectedResult bool
	}{
		{
			name: "Out of sync annotation",
			nadData: &AaepMonitoringData{
				aaepEpgData: AaepEpgAttachData{
					epgDn:     "uni/tn-test/ap-web/epg-frontend",
					encapVlan: 100,
				},
				namespaceName: "test-ns",
				nadName:       "test-nad",
			},
			existingNAD: &nadapi.NetworkAttachmentDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"aci-sync-status": "out-of-sync",
						"cno-name":        "test-nad",
					},
				},
			},
			expectedResult: true,
		},
		{
			name: "Different cno-name",
			nadData: &AaepMonitoringData{
				aaepEpgData: AaepEpgAttachData{
					epgDn:     "uni/tn-test/ap-web/epg-frontend",
					encapVlan: 100,
				},
				namespaceName: "test-ns",
				nadName:       "new-nad-name",
			},
			existingNAD: &nadapi.NetworkAttachmentDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"aci-sync-status": "in-sync",
						"cno-name":        "old-nad-name",
					},
				},
			},
			expectedResult: true,
		},
		{
			name: "No annotations on existing NAD",
			nadData: &AaepMonitoringData{
				aaepEpgData: AaepEpgAttachData{
					epgDn:     "uni/tn-test/ap-web/epg-frontend",
					encapVlan: 100,
				},
				namespaceName: "test-ns",
				nadName:       "test-nad",
			},
			existingNAD: &nadapi.NetworkAttachmentDefinition{
				ObjectMeta: metav1.ObjectMeta{},
			},
			expectedResult: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cont.isNADUpdateRequired(tt.nadData, tt.existingNAD)
			assert.Equal(t, tt.expectedResult, result)
		})
	}
}

// Test generateDefaultNadName with additional cases
func TestGenerateDefaultNadNameAdditional(t *testing.T) {
	cont := testController()

	tests := []struct {
		name           string
		epgDn          string
		expectedResult string
	}{
		{
			name:           "Complex tenant names with hyphens",
			epgDn:          "uni/tn-multi-tenant-prod/ap-web-tier/epg-frontend-nginx",
			expectedResult: "multi-tenant-prod-web-tier-frontend-nginx",
		},
		{
			name:           "Single character components",
			epgDn:          "uni/tn-x/ap-y/epg-z",
			expectedResult: "x-y-z",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cont.generateDefaultNadName(tt.epgDn)
			assert.Equal(t, tt.expectedResult, result)
		})
	}
}
