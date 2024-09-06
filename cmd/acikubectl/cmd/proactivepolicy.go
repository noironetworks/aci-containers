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
	"github.com/noironetworks/aci-containers/pkg/apicapi"
	aciCtrlr "github.com/noironetworks/aci-containers/pkg/controller"
	pconfv1 "github.com/noironetworks/aci-containers/pkg/proactiveconf/apis/aci.pc/v1"
	pconfclientset "github.com/noironetworks/aci-containers/pkg/proactiveconf/clientset/versioned"
	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"net/http"
	"os"
	"strings"
)

func proactivePolicy(args []string, apicUser, apicPassword, vmmEpgAttachment string, useCr bool) {
	var ctrlrConfig aciCtrlr.ControllerConfig
	var useCert bool
	var user string
	var apicIdx int
	var client *http.Client
	var err error
	var pconfClient pconfclientset.Interface

	immediacy := ""
	effectiveDns := []apicapi.ApicObject{}

	if !useCr {
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

		certFile, keyFile, file_err := findCertAndKeyFiles()

		if file_err == nil {
			fmt.Printf("Found Cert:%s and Key:%s\n", certFile, keyFile)
			useCert = true
			user = strings.Split(strings.Split(certFile, "-")[1], ".")[0]
		} else if apicUser == "" || apicPassword == "" {
			fmt.Printf("Missing arguments: apicUser: %s, apicPassword: %s\n", apicUser, apicPassword)
			return
		}

		if len(*apicHosts) == 0 {
			fmt.Printf("Missing argument: apicHosts:%v\n", *apicHosts)
			return
		}

		switch vmmEpgAttachment {
		case "immediate":
			immediacy = "immediate"
		case "on-demand":
			immediacy = "lazy"
		}
		
		client, err = apicClient()
		if err != nil {
			fmt.Printf("Failed to create apicclient:%v", err)
			return
		}
		_, apicIdx, err = apicLogin(client, *apicHosts, apicUser, apicPassword, certFile, keyFile, &ctrlrConfig)
		if err != nil || apicIdx == -1 {
			fmt.Printf("Failed to login to APIC/s:%v\n", err)
			return
		}
		uri := fmt.Sprintf("/api/node/class/fvRsDomAtt.json?query-target-filter=and(wcard(fvRsDomAtt.dn,\"%s\"))", ctrlrConfig.AciPolicyTenant)
		resp, err := apicGetResponse(client, (*apicHosts)[apicIdx], uri, useCert, user)
		if err != nil {
			fmt.Printf("Failed to get APIC response:%v", err)
			return
		}
		effectiveDns = apicFilterfvRsDomAtt(resp.Imdata, &ctrlrConfig)
	} else {
		pconfClient, err = initProactiveClient()
		if err != nil {
			fmt.Printf("Failed to init proactive client:%v", err)
			return
		}
	}

	switch args[0] {
	case "create":
		{
			if useCr {
				err = CreateOrUpdateProactiveConf(pconfClient, vmmEpgAttachment)
				if err != nil {
					fmt.Printf("%v", err)
					return
				}
				fmt.Println("applied!")
			} else {
				updatedDns := apicUpdateFvRsDomAttInstrImedcy(effectiveDns, immediacy)
				fmt.Println(updatedDns)
				uri := fmt.Sprintf("/api/node/mo/uni/tn-%s.json", ctrlrConfig.AciPolicyTenant)
				err = apicPostApicObjects(client, (*apicHosts)[apicIdx], uri, updatedDns, useCert, user)
				if err != nil {
					fmt.Printf("%v", err)
					return
				}
				fmt.Println("applied!")
			}
		}
	case "delete":
		{
			if useCr {
				err = deleteProactiveConfFromList(pconfClient)
				if err != nil {
					fmt.Printf("%v", err)
					return
				}
				fmt.Println("applied!")
			} else {
				if immediacy != "lazy" {
					fmt.Println("vmmEpgAttachment/-e argument has no effect in delete command.")
				}
				updatedDns := apicUpdateFvRsDomAttInstrImedcy(effectiveDns, "lazy")
				fmt.Println(updatedDns)
				uri := fmt.Sprintf("/api/node/mo/uni/tn-%s.json", ctrlrConfig.AciPolicyTenant)
				err = apicPostApicObjects(client, (*apicHosts)[apicIdx], uri, updatedDns, useCert, user)
				if err != nil {
					fmt.Printf("%v", err)
					return
				}
				fmt.Println("applied!")
			}

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

func CreateOrUpdateProactiveConf(pconfClient pconfclientset.Interface, vmmEpgAttachment string) error {
	var immediacy pconfv1.VmmEpgDeploymentImmediacyType
	var namespace = "aci-containers-system"
	switch vmmEpgAttachment {
	case "immediate":
		immediacy = "Immediate"
	case "on-demand":
		immediacy = "OnDemand"
	}
	//AciV1().ProactiveConfs(metav1.NamespaceAll).List(context.TODO(), metav1.ListOptions{})
	pconfList, err := pconfClient.AciV1().ProactiveConfs(namespace).List(appContext.TODO(), metav1.ListOptions{})
	if err != nil && len(pconfList.Items) > 0 {
		return fmt.Errorf("failed to list ProactiveConfs: %v", err)
	}

	if len(pconfList.Items) > 0 {
		pconf := &pconfList.Items[0]
		pconf.Spec.TunnelEpAdvertisementInterval = 5
		pconf.Spec.VmmEpgDeploymentImmediacy = immediacy

		_, err := pconfClient.AciV1().ProactiveConfs(namespace).Update(appContext.TODO(), pconf, metav1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("failed to update ProactiveConf: %v", err)
		}
		fmt.Println("ProactiveConf updated successfully.")
		return nil
	}

	newPconf := &pconfv1.ProactiveConf{
		ObjectMeta: metav1.ObjectMeta{
			Name: "proactiveconf",
		},
		Spec: pconfv1.ProactiveConfSpec{
			TunnelEpAdvertisementInterval: 5,
			VmmEpgDeploymentImmediacy:     immediacy,
		},
	}
	_, err = pconfClient.AciV1().ProactiveConfs(namespace).Create(appContext.TODO(), newPconf, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create ProactiveConf: %v", err)
	}
	fmt.Println("ProactiveConf created successfully.")
	return nil

}

func deleteProactiveConfFromList(pconfClient pconfclientset.Interface) error {
	var namespace = "aci-containers-system"
	pconfList, err := pconfClient.AciV1().ProactiveConfs(namespace).List(appContext.TODO(), metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list ProactiveConfs: %v", err)
	}

	if len(pconfList.Items) == 0 {
		return fmt.Errorf("no ProactiveConf resources found to delete")
	}

	pconfToDelete := &pconfList.Items[0]

	err = pconfClient.AciV1().ProactiveConfs(namespace).Delete(appContext.TODO(), pconfToDelete.Name, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("failed to delete ProactiveConf: %v", err)
	}
	fmt.Println("ProactiveConf deleted successfully.")
	return nil
}

var apicUser, apicPassword, vmmEpgAttachment string
var useCr bool
var apicHosts *[]string

var ProactivePolicyCmd = &cobra.Command{
	Use:     "proactive_policy create/delete/verify",
	Short:   "Do override configuration like changing vmm epg attachment mode",
	Example: `proactive_policy create/delete`,
	Args:    cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		proactivePolicy(args, apicUser, apicPassword, vmmEpgAttachment, useCr)
	},
}

func init() {
	apicHosts = ProactivePolicyCmd.Flags().StringSliceP("apic-hosts", "a", []string{}, "APIC Hosts")
	ProactivePolicyCmd.Flags().StringVarP(&apicUser, "apic-user", "u", "", "APIC username")
	ProactivePolicyCmd.Flags().StringVarP(&apicPassword, "apic-passwd", "p", "", "APIC password")
	ProactivePolicyCmd.Flags().StringVarP(&vmmEpgAttachment, "vmm-epg-attachment", "e", "on-demand", "Enable immediate/on-demand deployment and resolution immediacy on vmm-epg-attachment")
	ProactivePolicyCmd.Flags().BoolVarP(&useCr, "use-cr", "c", false, "Use proactiveconfs CR for resolution_immediacy")
	RootCmd.AddCommand(ProactivePolicyCmd)
}
