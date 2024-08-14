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
package networkfabricl3configuration

import (
	"context"
	"fmt"
	"net"

	"encoding/json"
	"net/http"

	fabattv1 "github.com/noironetworks/aci-containers/pkg/fabricattachment/apis/aci.fabricattachment/v1"
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
	ResourceName = "networkfabricl3configuration"
	MutatingHook = &Admission{
		Handler: admission.HandlerFunc(func(ctx context.Context, req AdmissionRequest) AdmissionResponse {
			return Allowed("No mutation needed")
		}),
	}

	ValidatingHook = &Admission{
		Handler: admission.HandlerFunc(validateNFL3Config),
	}
)

func RegisterHandlers(config *aciwebhooktypes.Config, registry map[string]*Admission) {
	mutatePath := fmt.Sprintf("/mutate-%s", ResourceName)
	registry[mutatePath] = MutatingHook
	validatePath := fmt.Sprintf("/validate-%s", ResourceName)
	registry[validatePath] = ValidatingHook
}

func validateNFL3Config(ctx context.Context, req AdmissionRequest) AdmissionResponse {
	if (req.Operation != admv1.Create) && (req.Operation != admv1.Update) {
		return Allowed("no op")
	}
	raw := req.Object.Raw
	nfl3Cfg := &fabattv1.NetworkFabricL3Configuration{}
	err := json.Unmarshal(raw, nfl3Cfg)
	if err != nil {
		return Errored(http.StatusBadRequest, err)
	}
	webhookHdlrLog := ctrl.Log.WithName("NetworkFabricL3ConfigurationHandler: ")
	vrfMap := make(map[string]map[string]bool)
	encapMap := make(map[int]bool)
	l3OutMap := make(map[string]string)
	// Disallow repeated keys
	for _, vrfCfg := range nfl3Cfg.Spec.Vrfs {
		vrfName := "policyTenant/"
		if vrfCfg.Vrf.CommonTenant {
			vrfName = "common/"
		}
		vrfName += vrfCfg.Vrf.Name
		if _, ok := vrfMap[vrfName]; ok {
			return Denied(fmt.Sprintf("vrf %s is repeated", vrfCfg.Vrf.Name))
		}
		vrfMap[vrfName] = make(map[string]bool)
		for _, svi := range vrfCfg.DirectlyConnectedNetworks {
			if _, ok := encapMap[svi.Encap]; ok {
				return Denied(fmt.Sprintf("encap %d is repeated", svi.Encap))
			}
			encapMap[svi.Encap] = true
			if (svi.MaxNodes != 0) && (svi.MaxNodes < 2) {
				return Denied(fmt.Sprintf("Please allow atleast 2 fabric node addresses for svi vlan %d", svi.Encap))
			}
			_, nw, err := net.ParseCIDR(svi.PrimarySubnet)
			if err != nil {
				return Denied(fmt.Sprintf("vrf %s,subnet %s is not valid:%v", vrfName, svi.PrimarySubnet, err))
			}
			if _, ok := vrfMap[vrfName][nw.String()]; ok {
				return Denied(fmt.Sprintf("vrf %s,subnet %s is repeated", vrfName, nw.String()))
			}
			vrfMap[vrfName][nw.String()] = true
			for _, secNw := range svi.Subnets {
				_, nw2, err2 := net.ParseCIDR(secNw.ConnectedSubnet)
				if err2 != nil {
					return Denied(fmt.Sprintf("vrf %s,subnet %s is not valid:%v", vrfName, secNw.ConnectedSubnet, err2))
				}
				if _, ok := vrfMap[vrfName][nw2.String()]; ok {
					return Denied(fmt.Sprintf("vrf %s,subnet %s is repeated", vrfName, nw2.String()))
				}
				vrfMap[vrfName][nw2.String()] = true
				secIP := net.ParseIP(secNw.SecondaryAddress)
				if secIP == nil {
					return Denied(fmt.Sprintf("vrf %s,subnet %s, secondary address %s is not valid",
						vrfName, secNw.ConnectedSubnet, secNw.SecondaryAddress))
				} else {
					if !nw2.Contains(secIP) {
						return Denied(fmt.Sprintf("vrf %s,subnet %s, secondary address %s is not in the subnet",
							vrfName, secNw.ConnectedSubnet, secNw.SecondaryAddress))
					}
				}
				floatIP := net.ParseIP(secNw.FloatingAddress)
				if floatIP == nil {
					return Denied(fmt.Sprintf("vrf %s,subnet %s, floating address %s is not valid",
						vrfName, secNw.ConnectedSubnet, secNw.FloatingAddress))
				} else {
					if !nw2.Contains(floatIP) {
						return Denied(fmt.Sprintf("vrf %s,subnet %s, floating address %s is not in the subnet",
							vrfName, secNw.ConnectedSubnet, secNw.FloatingAddress))
					}
				}
				if secNw.SecondaryAddress == secNw.FloatingAddress {
					return Denied(fmt.Sprintf("vrf %s,floating address %s should not be the same as secondary address %s",
						vrfName, secNw.FloatingAddress, secNw.SecondaryAddress))
				}
				// TODO: Check for overlapping subnets
			}
			bgpCtrlMap := make(map[string]bool)
			for _, ctrl := range svi.BGPPeerPolicy.Ctrl {
				if _, ok := bgpCtrlMap[string(ctrl)]; ok {
					return Denied(fmt.Sprintf("bgp ctrl flag %s is repeated in svi encap %d", ctrl, svi.Encap))
				}
				bgpCtrlMap[string(ctrl)] = true
			}
		}
		for _, tenantCfg := range vrfCfg.Tenants {
			if !vrfCfg.Vrf.CommonTenant && tenantCfg.CommonTenant {
				return Denied(fmt.Sprintf("vrf %s, cannot be chosen by an l3out in policyTenant", vrfName))
			}
			l3outTenant := "policyTenant/"
			if tenantCfg.CommonTenant {
				l3outTenant = "common/"
			}
			rtrNodeMap := make(map[int]string)
			for _, l3out := range tenantCfg.L3OutInstances {
				l3OutKey := l3outTenant + l3out.Name
				if l3OutVrf, ok := l3OutMap[l3OutKey]; ok {
					return Denied(fmt.Sprintf("l3out %s is repeated across vrf %s and %s", l3OutKey, l3OutVrf, vrfName))
				}
				l3OutMap[l3OutKey] = vrfName
				l3outPod := 0
				for _, rtrNode := range l3out.RtrNodes {
					if l3outPod == 0 {
						l3outPod = rtrNode.NodeRef.PodId
					} else if rtrNode.NodeRef.PodId != l3outPod {
						return Denied(fmt.Sprintf("multiple podIds used %d, %d in l3out %s", rtrNode.NodeRef.PodId, l3outPod, l3OutKey))
					}
					if _, ok := rtrNodeMap[rtrNode.NodeRef.NodeId]; ok {
						return Denied(fmt.Sprintf("node %d is repeated in l3out %s and l3out %s",
							rtrNode.NodeRef.NodeId, l3OutKey, rtrNodeMap[rtrNode.NodeRef.NodeId]))
					}
					rtrNodeMap[rtrNode.NodeRef.NodeId] = l3OutKey
				}
				extEpgMap := make(map[string]map[string]bool)
				for _, extEpg := range l3out.ExternalEpgs {
					if _, ok := extEpgMap[extEpg.Name]; ok {
						return Denied(fmt.Sprintf("extEpg %s is repeated in l3out %s", extEpg.Name, l3OutKey))
					}
					extEpgMap[extEpg.Name] = make(map[string]bool)
					ppMap := make(map[string]bool)
					for _, ppfx := range extEpg.PolicyPrefixes {
						if _, ok := ppMap[ppfx.Subnet]; ok {
							return Denied(fmt.Sprintf("subnet %s is repeated in extEpg %s", ppfx.Subnet, l3OutKey+"/"+extEpg.Name))
						}
						scopeMap := make(map[string]bool)
						for _, scope := range ppfx.Scope {
							if _, ok := scopeMap[string(scope)]; ok {
								return Denied(fmt.Sprintf("scope %s is repeated in subnet %s ppfx %s", string(scope), ppfx.Subnet, l3OutKey+"/"+extEpg.Name))
							}
							scopeMap[string(scope)] = true
						}
						aggMap := make(map[string]bool)
						for _, agg := range ppfx.Aggregate {
							if _, ok := aggMap[string(agg)]; ok {
								return Denied(fmt.Sprintf("aggregate %s is repeated in subnet %s ppfx %s", string(agg), ppfx.Subnet, l3OutKey+"/"+extEpg.Name))
							}
							scopeMap[string(agg)] = true
						}
						// TODO: Check for overlapping subnets
						ppMap[ppfx.Subnet] = true
					}
					consMap := make(map[string]bool)
					for _, cons := range extEpg.Contracts.Consumer {
						if _, ok := consMap[cons]; ok {
							return Denied(fmt.Sprintf("consumer %s is repeated in extEpg %s", cons, l3OutKey+"/"+extEpg.Name))
						}
						consMap[cons] = true
					}
					provMap := make(map[string]bool)
					for _, prov := range extEpg.Contracts.Provider {
						if _, ok := provMap[prov]; ok {
							return Denied(fmt.Sprintf("provider %s is repeated in extEpg %s", prov, l3OutKey+"/"+extEpg.Name))
						}
						provMap[prov] = true
					}
				}
			}
		}
	}
	// Disallow change of routerId once assigned.
	if req.Operation == admv1.Update {
		rtrNodeMap := make(map[string]map[int]string)
		podMap := make(map[string]int)
		for _, vrfCfg := range nfl3Cfg.Spec.Vrfs {
			vrfName := "policyTenant/"
			if vrfCfg.Vrf.CommonTenant {
				vrfName = "common/"
			}
			vrfName += vrfCfg.Vrf.Name
			rtrNodeMap[vrfName] = make(map[int]string)
			podMap[vrfName] = 0
			for _, tenantCfg := range vrfCfg.Tenants {
				for _, l3out := range tenantCfg.L3OutInstances {
					for _, rtrNode := range l3out.RtrNodes {
						podMap[vrfName] = rtrNode.NodeRef.PodId
						rtrNodeMap[vrfName][rtrNode.NodeRef.NodeId] = rtrNode.RtrId
					}
				}
			}
		}
		for _, vrfCfg := range nfl3Cfg.Status.Vrfs {
			vrfName := "policyTenant/"
			if vrfCfg.Vrf.CommonTenant {
				vrfName = "common/"
			}
			vrfName += vrfCfg.Vrf.Name
			if _, ok := rtrNodeMap[vrfName]; !ok {
				continue
			}
			for _, tenantCfg := range vrfCfg.Tenants {
				for _, l3out := range tenantCfg.L3OutInstances {
					for _, rtrNode := range l3out.RtrNodes {
						if _, ok := rtrNodeMap[vrfName][rtrNode.NodeRef.NodeId]; ok {
							if podMap[vrfName] != rtrNode.NodeRef.PodId {
								return Denied(fmt.Sprintf("PodId of node pod-%d/node-%d vrf %s, can't be updated(try delete followed by add) once assigned",
									rtrNode.NodeRef.PodId, rtrNode.NodeRef.NodeId, vrfName))
							}
							if rtrNode.RtrId != rtrNodeMap[vrfName][rtrNode.NodeRef.NodeId] {
								return Denied(fmt.Sprintf("RouterId of node pod-%d/node-%d vrf %s, can't be updated(try delete followed by add) once assigned",
									rtrNode.NodeRef.PodId, rtrNode.NodeRef.NodeId, vrfName))
							}
						}
					}
				}
			}
		}
	}
	webhookHdlrLog.Info("Validated")
	return Allowed("validated")
}
