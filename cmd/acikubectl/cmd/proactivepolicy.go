// Copyright  2024 Cisco Systems, Inc.
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

package cmd

import (
	"bytes"
	appContext "context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/noironetworks/aci-containers/pkg/apicapi"
	aciCtrlr "github.com/noironetworks/aci-containers/pkg/controller"
	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type AciConfigSpec struct {
	SystemId  string   `json:"system_id,omitempty"`
	Aep       string   `json:"aep,omitempty"`
	ApicHosts []string `json:"apic_hosts,omitempty"`
}

type AciNetConfigSpec struct {
	NodeSubnet       []string `json:"node_subnet,omitempty"`
	PodSubnet        []string `json:"pod_subnet,omitempty"`
	ExternDynamic    []string `json:"extern_dynamic,omitempty"`
	ExternStatic     []string `json:"extern_static,omitempty"`
	KubeApiVlan      int      `json:"kubeapi_vlan,omitempty"`
	ClusterSvcSubnet string   `json:"cluster_svc_subnet,omitempty"`
	InterfaceMTU     int      `json:"interface_mtu,omitempty"`
	ServiceVlan      int      `json:"service_vlan,omitempty"`
	NodeSvcSubnet    string   `json:"node_svc_subnet,omitempty"`
}

type AccProvisionConfig struct {
	AciConfig AciConfigSpec    `json:"aci_config,omitempty"`
	NetConfig AciNetConfigSpec `json:"net_config,omitempty"`
	Flavor    string           `json:"flavor,omitempty"`
}

type AccProvisionInput struct {
	ProvisionConfig AccProvisionConfig `json:"acc_provision_input,omitempty"`
}

func proactivePolicy(args []string, apicUser, apicPassword, vmmEpgAttachment string) {
	var ctrlrConfig aciCtrlr.ControllerConfig
	var useCert bool
	var user string
	var provConfig AccProvisionInput

	kubeClient := initClientPrintError()
	if kubeClient == nil {
		return
	}

	cfgMap, err := kubeClient.CoreV1().ConfigMaps("aci-containers-system").Get(appContext.TODO(), "aci-containers-config", metav1.GetOptions{})
	if err != nil {
		fmt.Printf("\nFailed to read configmap aci-containers-system/aci-containers-config:%v", err)
		return
	}
	buffer := bytes.NewBufferString(cfgMap.Data["controller-config"])
	err = json.Unmarshal(buffer.Bytes(), &ctrlrConfig)
	if err != nil {
		fmt.Printf("\nFailed to read aci-containers-controller-config:%v", err)
		return
	}

	cfgMap2, err := kubeClient.CoreV1().ConfigMaps("aci-containers-system").Get(appContext.TODO(), "acc-provision-config", metav1.GetOptions{})
	if err != nil {
		fmt.Printf("\nFailed to read configmap aci-containers-system/acc-provision-config:%v", err)
		return
	}
	buffer = bytes.NewBufferString(cfgMap2.Data["spec"])
	err = json.Unmarshal(buffer.Bytes(), &provConfig)
	if err != nil {
		fmt.Printf("\nFailed to read acc_provision_input:%v", err)
		return
	}

	user = provConfig.ProvisionConfig.AciConfig.SystemId

	if apicHosts == nil || len(*apicHosts) == 0 {
		apicHosts = &ctrlrConfig.ApicHosts
	}
	if apicPassword == "" {
		apicPassword = os.Getenv("APIC_PASSWORD")
	}

	certFile, keyFile, file_err := findCertAndKeyFiles(user)

	if file_err != nil && (apicUser == "" && apicPassword == "") {
		fmt.Printf("\nFailed to find file: %v\n", file_err)
	}

	if file_err == nil {
		fmt.Printf("\nFound Cert:%s and Key:%s\n", certFile, keyFile)
		useCert = true
	} else if apicUser == "" || apicPassword == "" {
		fmt.Printf("\nMissing arguments: apicUser: %s, apicPassword: %s\n", apicUser, apicPassword)
		return
	}

	if len(*apicHosts) == 0 {
		fmt.Printf("\nMissing argument: apicHosts:%v\n", *apicHosts)
		return
	}
	immediacy := ""
	switch vmmEpgAttachment {
	case "immediate":
		immediacy = "immediate"
	case "on-demand":
		immediacy = "lazy"
	}
	client, err := apicClient()
	if err != nil {
		fmt.Printf("\nFailed to create apicclient:%v", err)
		return
	}
	_, apicIdx, err := apicLogin(client, *apicHosts, apicUser, apicPassword, certFile, keyFile, user)
	if err != nil || apicIdx == -1 {
		fmt.Printf("\nFailed to login to APIC/s:%v", err)
		return
	}
	uri := fmt.Sprintf("/api/node/class/fvRsDomAtt.json?query-target-filter=and(wcard(fvRsDomAtt.dn,\"%s\"))", ctrlrConfig.AciPolicyTenant)
	resp, err := apicGetResponse(client, (*apicHosts)[apicIdx], uri, useCert, user)
	if err != nil {
		fmt.Printf("\nFailed to get APIC response:%v", err)
		return
	}
	effectiveDns := apicFilterfvRsDomAtt(resp.Imdata, &ctrlrConfig)

	applyPreProvision := func(effectiveDns apicapi.ApicSlice) bool {
		applyErrors := false
		for _, fvRsDomAtt := range effectiveDns {
			apicSlice := apicapi.ApicSlice{}
			fvRsDomAttDn := fvRsDomAtt.GetAttrDn()
			rsdomAttIndex := strings.LastIndex(fvRsDomAttDn, "/rsdomAtt-")
			if rsdomAttIndex == -1 {
				fmt.Printf("Skipping invalid vmm epg attachment for %s:%v", fvRsDomAttDn, err)
				applyErrors = true
				continue
			}
			epgDn := fvRsDomAttDn[:rsdomAttIndex]
			uri = fmt.Sprintf("/api/node/mo/%s.json", epgDn)
			epgObj := apicapi.EmptyApicObject("fvAEPg", epgDn)
			epgObj.SetAttr("status", "created,modified")
			epgObj.AddChild(fvRsDomAtt)
			apicSlice = append(apicSlice, epgObj)
			err = apicPostApicObjects(client, (*apicHosts)[apicIdx], uri, apicSlice, useCert, user)
			if err != nil {
				fmt.Printf("Failed to apply vmm epg attachment for %s:%v", epgDn, err)
				applyErrors = true
				continue
			}
		}
		return applyErrors
	}

	switch args[0] {
	case "create":
		{
			updatedDns := apicUpdateFvRsDomAttInstrImedcy(effectiveDns, immediacy)
			fmt.Println(updatedDns)
			if applyStaticPaths {
				provisionedAep := provConfig.ProvisionConfig.AciConfig.Aep
				uri = fmt.Sprintf("/api/node/class/infraRsAttEntP.json?query-target-filter=and(eq(infraRsAttEntP.tDn,\"uni/infra/attentp-%s\"))", provisionedAep)
				resp, err := apicGetResponse(client, (*apicHosts)[apicIdx], uri, useCert, user)
				if err != nil {
					fmt.Printf("Failed to get aep attachments:%v", err)
					return
				}
				staticPathsToAdd := map[string][]string{}
				epgEncap := map[string]string{}
				fabricNodeMap := apicGetNodesFromInterfacePolicyProfiles(client, (*apicHosts)[apicIdx], resp.Imdata, useCert, user)
				for _, fvRsDomAtt := range effectiveDns {
					fvRsDomAttDn := fvRsDomAtt.GetAttrDn()
					rsdomAttIndex := strings.LastIndex(fvRsDomAttDn, "/rsdomAtt-")
					if rsdomAttIndex == -1 {
						continue
					}
					epgDn := fvRsDomAttDn[:rsdomAttIndex]
					uri = fmt.Sprintf("/api/node/class/vmmEpPD.json?query-target-filter=and(eq(vmmEpPD.epgPKey,\"%s\"))", epgDn)
					resp, err := apicGetResponse(client, (*apicHosts)[apicIdx], uri, useCert, user)
					if err != nil {
						fmt.Printf("\nFailed to get encap for epg %s:%v", epgDn, err)
						continue
					}
					for _, vmmEpPD := range resp.Imdata {
						encap := vmmEpPD.GetAttr("encap").(string)
						epgEncap[epgDn] = encap
						break
					}
					for pathDn, nodeList := range fabricNodeMap {
						for _, nodeId := range nodeList {
							uri = fmt.Sprintf("/api/node/mo/uni/epp/fv-[%s]/node-%d/dyatt-[%s].json?query-target=self", epgDn, nodeId, pathDn)
							resp, err := apicGetResponse(client, (*apicHosts)[apicIdx], uri, useCert, user)
							if err != nil {
								fmt.Printf("\nMissing pv attachment(%s,node-%d,%s)", pathDn, nodeId, epgDn)
								staticPathsToAdd[epgDn] = append(staticPathsToAdd[epgDn], pathDn)
								continue
							}
							if len(resp.Imdata) == 0 {
								fmt.Printf("\nMissing pv attachment(%s,node-%d,%s)", pathDn, nodeId, epgDn)
								staticPathsToAdd[epgDn] = append(staticPathsToAdd[epgDn], pathDn)
								continue
							}
							for _, fvDyPathAtt := range resp.Imdata {
								tDn := fvDyPathAtt.GetAttr("targetDn").(string)
								if tDn == pathDn {
									fmt.Printf("\nFound pv attachment(%s,node-%d,%s)", pathDn, nodeId, epgDn)
									break
								}
							}
						}
					}
				}
				if len(staticPathsToAdd) == 0 {
					fmt.Printf("\nNo missing paths, so no paths added")
					return
				}
				_, err = os.Stat("proactive_policy.json")
				if err == nil {
					fmt.Println("\nFound existing policy file. Please remove proactive_policy.json or rename!")
					return
				}
				policyFile, err := os.Create("proactive_policy.json")
				if err != nil {
					fmt.Printf("\nFailed to create file:%v", err)
					return
				}
				uri = fmt.Sprintf("/api/node/mo/uni/tn-%s.json", ctrlrConfig.AciPolicyTenant)
				progMap := map[string]apicapi.ApicSlice{}
				for epgDn, paths := range staticPathsToAdd {
					apicSlice := apicapi.ApicSlice{}
					uri = fmt.Sprintf("/api/node/mo/%s.json", epgDn)
					epgObj := apicapi.EmptyApicObject("fvAEPg", epgDn)
					epgObj.SetAttr("status", "created,modified")
					pathMap := map[string]bool{}
					for _, pathDn := range paths {
						if _, ok := pathMap[pathDn]; ok {
							continue
						}
						pathMap[pathDn] = true
						fvRsPathAttDn := fmt.Sprintf("%s/rspathAtt-[%s]", epgDn, pathDn)
						fvRsPathAtt := apicapi.EmptyApicObject("fvRsPathAtt", fvRsPathAttDn)
						fvRsPathAtt.SetAttr("encap", epgEncap[epgDn])
						fvRsPathAtt.SetAttr("tDn", pathDn)
						fvRsPathAtt.SetAttr("instrImedcy", "immediate")
						fvRsPathAtt.SetAttr("status", "created")
						progMap[epgDn] = append(progMap[epgDn], fvRsPathAtt)
						epgObj.AddChild(fvRsPathAtt)
					}
					apicSlice = append(apicSlice, epgObj)
					err = apicPostApicObjects(client, (*apicHosts)[apicIdx], uri, apicSlice, useCert, user)
					if err != nil {
						fmt.Printf("\nFailed to post static path/s for epg %s: %v", epgDn, err)
						return
					}
				}
				enc := json.NewEncoder(policyFile)
				err = enc.Encode(progMap)
				if err != nil {
					fmt.Printf("\nFailed to encode static path/s: %v", err)
					return
				}
				policyFile.Close()
				fmt.Println("\nStatic paths applied!")
				return
			}
			if !applyPreProvision(updatedDns) {
				fmt.Println("applied!")
			}
		}
	case "delete":
		{
			if immediacy != "immediate" {
				fmt.Println("vmmEpgAttachment/-e argument has no effect in delete command.")
			}
			updatedDns := apicUpdateFvRsDomAttInstrImedcy(effectiveDns, "lazy")
			fmt.Println(updatedDns)
			if applyStaticPaths {
				policyFile, err := os.Open("proactive_policy.json")
				if err != nil {
					fmt.Printf("\nproactive_policy.json file not found:%v", err)
					return
				}
				dec := json.NewDecoder(policyFile)
				progMap := map[string]apicapi.ApicSlice{}
				err = dec.Decode(&progMap)
				if err != nil {
					fmt.Printf("\nproactive_policy.json file not readable:%v", err)
					return
				}
				uri = fmt.Sprintf("/api/node/mo/uni/tn-%s.json", ctrlrConfig.AciPolicyTenant)
				for epgDn, fvRsPathAttList := range progMap {
					apicSlice := apicapi.ApicSlice{}
					epgObj := apicapi.EmptyApicObject("fvAEPg", epgDn)
					epgObj.SetAttr("status", "created,modified")
					for _, fvRsPathAtt := range fvRsPathAttList {
						fvRsPathAtt.SetAttr("status", "deleted")
						epgObj.AddChild(fvRsPathAtt)
					}
					apicSlice = append(apicSlice, epgObj)
					err = apicPostApicObjects(client, (*apicHosts)[apicIdx], uri, apicSlice, useCert, user)
					if err != nil {
						fmt.Printf("\nFailed to revert static path/s for epg %s: %v", epgDn, err)
					}
				}
				policyFile.Close()
				os.Remove("proactive_policy.json")
				fmt.Println("\nStatic paths reverted!")
				return
			}
			if !applyPreProvision(updatedDns) {
				fmt.Println("applied!")
			}
		}
	case "verify":
		{
			provisionedAep := provConfig.ProvisionConfig.AciConfig.Aep
			uri = fmt.Sprintf("/api/node/class/infraRsAttEntP.json?query-target-filter=and(eq(infraRsAttEntP.tDn,\"uni/infra/attentp-%s\"))", provisionedAep)
			resp, err := apicGetResponse(client, (*apicHosts)[apicIdx], uri, useCert, user)
			if err != nil {
				fmt.Printf("\nFailed to get aep attachments:%v", err)
				return
			}

			verifyFailures := false

			fabricNodeMap := apicGetNodesFromInterfacePolicyProfiles(client, (*apicHosts)[apicIdx], resp.Imdata, useCert, user)
			for _, fvRsDomAtt := range effectiveDns {
				eppMissingCnt := 0
				fvRsDomAttDn := fvRsDomAtt.GetAttrDn()
				rsdomAttIndex := strings.LastIndex(fvRsDomAttDn, "/rsdomAtt-")
				if rsdomAttIndex == -1 {
					continue
				}
				epgDn := fvRsDomAttDn[:rsdomAttIndex]
				fmt.Printf("\nChecking epg profile(fvEpP) for %s...", epgDn)
				fvEppMap := make(map[int]bool)
				missingNodeMap := make(map[int]bool)
				// Check fabric node
				uri = fmt.Sprintf("/api/node/mo/uni/epp/fv-[%s].json?query-target=children&target-subtree-class=fvLocale", epgDn)
				resp, err = apicGetResponse(client, (*apicHosts)[apicIdx], uri, useCert, user)
				if err != nil {
					fmt.Printf("\nFailed to get epg profile(fvEpP):%v", err)
					return
				}
				for _, fvLocale := range resp.Imdata {
					nodeIdStr := fvLocale.GetAttr("id").(string)
					nodeId, _ := strconv.Atoi(nodeIdStr)
					fvEppMap[nodeId] = true
					fmt.Printf("\nFound fvEpP on node-%d", nodeId)
				}
				for _, nodeList := range fabricNodeMap {
					for _, nodeId := range nodeList {
						if _, ok := fvEppMap[nodeId]; !ok {
							if _, ok2 := missingNodeMap[nodeId]; !ok2 {
								missingNodeMap[nodeId] = true
								fmt.Printf("\nMissing fvEpP on node-%d", nodeId)
								eppMissingCnt++
							}
						}
					}
				}
				if eppMissingCnt > 0 {
					verifyFailures = true
				}
			}
			if verifyFailures {
				fmt.Printf("\nVERIFY FAILURE: some nodes are missing epg deployments!")
			} else {
				fmt.Printf("\nVERIFY SUCCESS!")
			}
		}
	default:
		{
			fmt.Printf("Invalid option %s", args[0])
		}
	}
	fmt.Println("")
}

var apicUser, apicPassword, vmmEpgAttachment string
var apicHosts *[]string
var applyStaticPaths bool
var ProactivePolicyCmd = &cobra.Command{
	Use:     "proactive_policy create/delete/verify",
	Short:   "Do override configuration like changing vmm epg attachment mode",
	Example: `proactive_policy create/delete/verify`,
	Args:    cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		proactivePolicy(args, apicUser, apicPassword, vmmEpgAttachment)
	},
}

func init() {
	apicHosts = ProactivePolicyCmd.Flags().StringSliceP("apic-hosts", "a", []string{}, "APIC Hosts")
	ProactivePolicyCmd.Flags().StringVarP(&apicUser, "apic-user", "u", "", "APIC username")
	ProactivePolicyCmd.Flags().StringVarP(&apicPassword, "apic-passwd", "p", "", "APIC password")
	ProactivePolicyCmd.Flags().StringVarP(&vmmEpgAttachment, "vmm-epg-attachment", "e", "immediate", "Enable immediate/on-demand deployment and resolution immediacy on vmm-epg-attachment")
	ProactivePolicyCmd.Flags().BoolVarP(&applyStaticPaths, "apply-revert-static-paths", "t", false, "Apply static paths on create, so all pv combinations are deployed and revert during delete")
	RootCmd.AddCommand(ProactivePolicyCmd)
}
