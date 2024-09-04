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
	"strings"

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

	kubeClient := initClientPrintError()
	if kubeClient == nil {
		return
	}
	cfgMap, err := kubeClient.CoreV1().ConfigMaps("aci-containers-system").Get(appContext.TODO(), "aci-containers-config", metav1.GetOptions{})
	if err != nil {
		fmt.Printf("Failed to read configmap aci-containers-system/aci-containers-config:%v", err)
		return
	}
	buffer := bytes.NewBufferString(cfgMap.Data["controller-config"])
	err = json.Unmarshal(buffer.Bytes(), &ctrlrConfig)
	if err != nil {
		fmt.Printf("Failed to read aci-containers-controller-config:%v", err)
		return
	}
	if apicHosts == nil || len(*apicHosts) == 0 {
		apicHosts = &ctrlrConfig.ApicHosts
	}
	if apicPassword == "" {
		apicPassword = os.Getenv("APIC_PASSWORD")
	}
	if apicUser == "" || apicPassword == "" || len(*apicHosts) == 0 {
		fmt.Printf("Some missing arguments: apicUser: %s, apicPassword: %s, apicHosts:%v", apicUser, apicPassword, *apicHosts)
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
		fmt.Printf("Failed to create apicclient:%v", err)
		return
	}
	_, apicIdx, err := apicLogin(client, *apicHosts, apicUser, apicPassword, &ctrlrConfig)
	if err != nil || apicIdx == -1 {
		fmt.Printf("Failed to login to APIC/s:%v", err)
		return
	}
	uri := fmt.Sprintf("/api/node/class/fvRsDomAtt.json?query-target-filter=and(wcard(fvRsDomAtt.dn,\"%s\"))", ctrlrConfig.AciPolicyTenant)
	resp, err := apicGetResponse(client, (*apicHosts)[apicIdx], uri)
	if err != nil {
		fmt.Printf("Failed to get APIC response:%v", err)
		return
	}
	effectiveDns := apicFilterfvRsDomAtt(resp.Imdata, &ctrlrConfig)
	switch args[0] {
	case "create":
		{
			updatedDns := apicUpdateFvRsDomAttInstrImedcy(effectiveDns, immediacy)
			fmt.Println(updatedDns)
			uri = fmt.Sprintf("/api/node/mo/uni/tn-%s.json", ctrlrConfig.AciPolicyTenant)
			err = apicPostApicObjects(client, (*apicHosts)[apicIdx], uri, updatedDns)
			if err != nil {
				fmt.Printf("%v", err)
				return
			}
			fmt.Println("applied!")
		}
	case "delete":
		{
			if immediacy != "lazy" {
				fmt.Println("vmmEpgAttachment/-e argument has no effect in delete command.")
			}
			updatedDns := apicUpdateFvRsDomAttInstrImedcy(effectiveDns, "lazy")
			fmt.Println(updatedDns)
			uri = fmt.Sprintf("/api/node/mo/uni/tn-%s.json", ctrlrConfig.AciPolicyTenant)
			err = apicPostApicObjects(client, (*apicHosts)[apicIdx], uri, updatedDns)
			if err != nil {
				fmt.Printf("%v", err)
				return
			}
			fmt.Println("applied!")
		}
	case "verify":
		{
			var provConfig AccProvisionInput
			cfgMap2, err := kubeClient.CoreV1().ConfigMaps("aci-containers-system").Get(appContext.TODO(), "acc-provision-config", metav1.GetOptions{})
			if err != nil {
				fmt.Printf("Failed to read configmap aci-containers-system/acc-provision-config:%v", err)
				return
			}
			buffer := bytes.NewBufferString(cfgMap2.Data["spec"])
			err = json.Unmarshal(buffer.Bytes(), &provConfig)
			if err != nil {
				fmt.Printf("Failed to read acc_provision_input:%v", err)
				return
			}
			provisionedAep := provConfig.ProvisionConfig.AciConfig.Aep
			uri = fmt.Sprintf("/api/node/class/infraRsAttEntP.json?query-target-filter=and(eq(infraRsAttEntP.tDn,\"uni/infra/attentp-%s\"))", provisionedAep)
			resp, err := apicGetResponse(client, (*apicHosts)[apicIdx], uri)
			if err != nil {
				fmt.Printf("Failed to get aep attachments:%v", err)
				return
			}
			fabricNodeMap := apicGetNodesFromInterfacePolicyProfiles(client, (*apicHosts)[apicIdx], resp.Imdata)
			for _, fvRsDomAtt := range effectiveDns {
				fvRsDomAttDn := fvRsDomAtt.GetAttrDn()
				rsdomAttIndex := strings.LastIndex(fvRsDomAttDn, "/rsdomAtt-")
				if rsdomAttIndex == -1 {
					continue
				}
				epgDn := fvRsDomAttDn[:rsdomAttIndex]
				for pathDn, nodeList := range fabricNodeMap {
					for _, nodeId := range nodeList {
						uri = fmt.Sprintf("/api/node/mo/uni/epp/fv-[%s]/node-%d/dyatt-[%s].json?query-target=self", epgDn, nodeId, pathDn)
						resp, err := apicGetResponse(client, (*apicHosts)[apicIdx], uri)
						if err != nil {
							fmt.Printf("\nMissing pv attachment(%s,node-%d,%s):%v", pathDn, nodeId, epgDn)
							continue
						}
						if len(resp.Imdata) == 0 {
							fmt.Printf("\nMissing pv attachment(%s,node-%d,%s)", pathDn, nodeId, epgDn)
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
var ProactivePolicyCmd = &cobra.Command{
	Use:     "proactive_policy create/delete/verify",
	Short:   "Do override configuration like changing vmm epg attachment mode",
	Example: `proactive_policy create/delete`,
	Args:    cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		proactivePolicy(args, apicUser, apicPassword, vmmEpgAttachment)
	},
}

func init() {
	apicHosts = ProactivePolicyCmd.Flags().StringSliceP("apic-hosts", "a", []string{}, "APIC Hosts")
	ProactivePolicyCmd.Flags().StringVarP(&apicUser, "apic-user", "u", "", "APIC username")
	ProactivePolicyCmd.Flags().StringVarP(&apicPassword, "apic-passwd", "p", "", "APIC password")
	ProactivePolicyCmd.Flags().StringVarP(&vmmEpgAttachment, "vmm-epg-attachment", "e", "on-demand", "Enable immediate/on-demand deployment and resolution immediacy on vmm-epg-attachment")
	RootCmd.AddCommand(ProactivePolicyCmd)
}
