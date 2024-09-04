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

	aciCtrlr "github.com/noironetworks/aci-containers/pkg/controller"
	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

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
			fmt.Println("Verify not implemented yet")
		}
	default:
		{
			fmt.Printf("Invalid option %s", args[0])
		}
	}

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
