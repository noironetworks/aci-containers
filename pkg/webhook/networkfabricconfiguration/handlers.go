// Copyright 2024 Cisco Systems, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package networkfabricconfiguration

import (
	"context"
	"fmt"

	"encoding/json"
	"net"
	"net/http"

	fabattv1 "github.com/noironetworks/aci-containers/pkg/fabricattachment/apis/aci.fabricattachment/v1"
	"github.com/noironetworks/aci-containers/pkg/util"
	aciwebhooktypes "github.com/noironetworks/aci-containers/pkg/webhook/types"
	admv1 "k8s.io/api/admission/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	. "sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

var (
	// Build webhooks used for the various server
	// configuration options
	//
	// These handlers could be also be implementations
	// of the AdmissionHandler interface for more complex
	// implementations.
	ResourceName = "networkfabricconfiguration"
	MutatingHook = &Admission{
		Handler: admission.HandlerFunc(func(ctx context.Context, req AdmissionRequest) AdmissionResponse {
			return Allowed("No mutation needed")
		}),
	}

	ValidatingHook = &Admission{
		Handler: admission.HandlerFunc(validateNFC),
	}
)

func RegisterHandlers(config *aciwebhooktypes.Config, registry map[string]*Admission) {
	mutatePath := fmt.Sprintf("/mutate-%s", ResourceName)
	registry[mutatePath] = MutatingHook
	validatePath := fmt.Sprintf("/validate-%s", ResourceName)
	registry[validatePath] = ValidatingHook
}

func validateNFC(ctx context.Context, req AdmissionRequest) AdmissionResponse {
	if (req.Operation != admv1.Create) && (req.Operation != admv1.Update) {
		return Allowed("no op")
	}
	webhookHdlrLog := ctrl.Log.WithName("NetworkFabricConfigurationHandler: ")
	raw := req.Object.Raw
	nfc := &fabattv1.NetworkFabricConfiguration{}
	err := json.Unmarshal(raw, nfc)
	if err != nil {
		return Errored(http.StatusBadRequest, err)
	}
	nadVlanMap := make(map[string]bool)
	vlanMap := make(map[int]bool)
	epgMap := make(map[string]string)
	bdMap := make(map[string]string)
	// Disallow repeated keys
	for _, nadVlanRef := range nfc.Spec.NADVlanRefs {
		if _, ok := nadVlanMap[nadVlanRef.NadVlanLabel]; !ok {
			nadVlanMap[nadVlanRef.NadVlanLabel] = true
		} else {
			return Denied(fmt.Sprintf("nadVlanLabel %s is repeated", nadVlanRef.NadVlanLabel))
		}
	}
	subnetMap := make(map[string]map[string]bool)
	for _, vlanRef := range nfc.Spec.VlanRefs {
		vlans, _, _, err := util.ParseVlanList([]string{vlanRef.Vlans})
		if err != nil {
			return Denied(fmt.Sprintf("vlan %s is unparseable: %v", vlanRef.Vlans, err))
		}
		if len(vlans) > 0 {
			if ((vlanRef.Epg.ApplicationProfile != "") || (vlanRef.Epg.Name != "") || len(vlanRef.Epg.Contracts.Consumer) > 0 ||
				len(vlanRef.Epg.Contracts.Provider) > 0) || (vlanRef.Epg.BD.Name != "") || (vlanRef.Epg.DiscoveryType != "") {
				return Denied(fmt.Sprintf("vlan list %s cannot be mapped to a single EPG/BD vlan list can only be used to associate an AEP list",
					vlanRef.Vlans))
			}
		}
		if vlanRef.Epg.Name != "" {
			if _, ok := epgMap[vlanRef.Epg.Name]; ok {
				return Denied(fmt.Sprintf("EPG %s cannot be mapped to more than one vlan %s and %s",
					vlanRef.Epg.Name, epgMap[vlanRef.Epg.Name], vlanRef.Vlans))
			}
			epgMap[vlanRef.Epg.Name] = vlanRef.Vlans
			consMap := make(map[string]bool)
			for _, cons := range vlanRef.Epg.Contracts.Consumer {
				if _, ok := consMap[cons]; ok {
					return Denied(fmt.Sprintf("contract %s is repeated under epg %s consumers", cons, vlanRef.Epg.Name))
				}
				consMap[cons] = true
			}
			provMap := make(map[string]bool)
			for _, prov := range vlanRef.Epg.Contracts.Provider {
				if _, ok := provMap[prov]; ok {
					return Denied(fmt.Sprintf("contract %s is repeated under epg %s providers", prov, vlanRef.Epg.Name))
				}
				provMap[prov] = true
			}
		}
		if vlanRef.Epg.BD.Name != "" {
			if _, ok := bdMap[vlanRef.Epg.BD.Name]; ok {
				return Denied(fmt.Sprintf("BD %s cannot be associated with more than one vlan %s and %s",
					vlanRef.Epg.BD.Name, bdMap[vlanRef.Epg.BD.Name], vlanRef.Vlans))
			}
			bdMap[vlanRef.Epg.BD.Name] = vlanRef.Vlans
			vrfName := "policyTenant/"
			if vlanRef.Epg.BD.CommonTenant {
				vrfName = "common/"
			}
			vrfName += vlanRef.Epg.BD.Vrf.Name
			for _, subnet := range vlanRef.Epg.BD.Subnets {
				if _, ok := subnetMap[vrfName]; !ok {
					subnetMap[vrfName] = make(map[string]bool)
				}
				if _, ok := subnetMap[vrfName][subnet]; ok {
					return Denied(fmt.Sprintf("subnet %s is repeated under vrf %s", subnet, vrfName))
				}
				bdAddress, nw, err := net.ParseCIDR(subnet)
				if err != nil {
					return Denied(fmt.Sprintf("subnet %s under BD %s is invalid", subnet, vlanRef.Epg.BD.Name))
				}
				if bdAddress.Equal(nw.IP) {
					return Denied(fmt.Sprintf("subnet %s under BD %s should have BD host address besides subnet and mask",
						subnet, vlanRef.Epg.BD.Name))
				}
				subnetMap[vrfName][subnet] = true
				// TODO: Check for overlapping subnets
			}
		}
		for _, vlan := range vlans {
			if _, ok := vlanMap[vlan]; ok {
				return Denied(fmt.Sprintf("vlan %d is repeated under vlanRefs", vlan))
			}
			vlanMap[vlan] = true
		}
	}
	webhookHdlrLog.Info("Validated")
	return Allowed("validated")
}
