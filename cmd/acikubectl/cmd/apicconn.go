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
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/noironetworks/aci-containers/pkg/apicapi"
	acictrlr "github.com/noironetworks/aci-containers/pkg/controller"
)

func apicClient() (*http.Client, error) {
	tls := &tls.Config{InsecureSkipVerify: true}
	tr := &http.Transport{
		Proxy:           http.ProxyFromEnvironment,
		TLSClientConfig: tls,
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{
		Transport: tr,
		Jar:       jar,
		Timeout:   5 * time.Minute,
	}
	return client, nil
}

func apicLogin(apicClient *http.Client, apicHosts []string, apicUser, apicPassword string, aciConfig *acictrlr.ControllerConfig) (string, int, error) {
	for apicIndex, apicHost := range apicHosts {
		url := fmt.Sprintf("https://%s/api/aaaLogin.json", apicHost)

		login := &apicapi.ApicObject{
			"aaaUser": &apicapi.ApicObjectBody{
				Attributes: map[string]interface{}{
					"name": apicUser,
					"pwd":  apicPassword,
				},
			},
		}
		raw, err := json.Marshal(login)
		if err != nil {
			fmt.Printf("Failed to marshal login request:%v", err)
			continue
		}
		reqBody := bytes.NewBuffer(raw)

		req, err := http.NewRequest("POST", url, reqBody)
		if err != nil {
			fmt.Printf("Failed to create login request:%v", err)
			continue
		}

		resp, err := apicClient.Do(req)
		if err != nil {
			fmt.Printf("Failed to send login request:%v", err)
			continue
		}
		var apicresp apicapi.ApicResponse
		err = json.NewDecoder(resp.Body).Decode(&apicresp)
		if err != nil {
			return "", -1, err
		}
		for _, obj := range apicresp.Imdata {
			lresp, ok := obj["aaaLogin"]
			if !ok {
				lresp, ok = obj["webtokenSession"]
				if !ok {
					continue
				}
			}

			token, ok := lresp.Attributes["token"]
			if !ok {
				//fmt.Println("Token not found in login response")
				continue
			}
			stoken, isStr := token.(string)
			if !isStr {
				//fmt.Println("Token is not a string")
				continue
			}
			return stoken, apicIndex, nil
		}

	}
	return "", -1, errors.New("No token was found")
}

func apicRespComplete(resp *http.Response) {
	if resp.StatusCode != http.StatusOK {
		rBody, err := io.ReadAll(resp.Body)
		if err != nil {
			fmt.Printf("ReadAll :%v", err)
		} else {
			fmt.Printf("Resp: %s", rBody)
		}
	}
	resp.Body.Close()
}

func apicPostApicObjects(apicClient *http.Client, apicHost string, uri string, payload apicapi.ApicSlice) error {
	url := fmt.Sprintf("https://%s%s", apicHost, uri)

	raw, err := json.Marshal(payload)
	if err != nil {
		fmt.Println("Could not serialize object: ", err)
		return err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(raw))
	if err != nil {
		fmt.Println("Could not create request: ", err)
		return err
	}

	resp, err := apicClient.Do(req)
	if err != nil {
		fmt.Println("Could not update  ", url, ": ", err)
		return err
	}

	apicRespComplete(resp)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Status: %v", resp.StatusCode)
	}
	return nil
}

func apicGetResponse(apicClient *http.Client, apicHost string, uri string) (apicapi.ApicResponse, error) {
	url := fmt.Sprintf("https://%s%s", apicHost, uri)
	var apicresp apicapi.ApicResponse
	req, err := http.NewRequest("GET", url, http.NoBody)
	if err != nil {
		fmt.Printf("Could not create request: ", err)
		return apicresp, err
	}
	//conn.sign(req, uri, nil)
	resp, err := apicClient.Do(req)
	if err != nil {
		fmt.Printf("Could not get response for ", url, ": ", err)
		return apicresp, err
	}
	defer apicRespComplete(resp)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		fmt.Printf("Could not get subtree for "+url, resp)
		return apicresp, err
	}
	err = json.NewDecoder(resp.Body).Decode(&apicresp)
	if err != nil {
		fmt.Printf("Could not parse APIC response: ", err)
		return apicresp, err
	}
	return apicresp, err

}

func apicFilterfvRsDomAtt(imdata []apicapi.ApicObject, aciConfig *acictrlr.ControllerConfig) []apicapi.ApicObject {

	systemDnsToFilter := []string{
		fmt.Sprintf("uni/tn-%s/ap-aci-containers-%s/epg-aci-containers-system", aciConfig.AciPolicyTenant, aciConfig.AciPrefix),
		fmt.Sprintf("uni/tn-%s/ap-aci-containers-%s/epg-aci-containers-istio", aciConfig.AciPolicyTenant, aciConfig.AciPrefix),
		fmt.Sprintf("uni/tn-%s/ap-aci-containers-%s/epg-aci-containers-nodes", aciConfig.AciPolicyTenant, aciConfig.AciPrefix),
	}

	vmmDomPDn := fmt.Sprintf("uni/vmmp-%s/dom-%s", aciConfig.AciVmmDomainType, aciConfig.AciVmmDomain)

	var fvRsDomAttSlice []apicapi.ApicObject
	for _, fvRsDomAtt := range imdata {
		dn := fvRsDomAtt.GetAttr("dn").(string)

		rsdomAttIndex := strings.LastIndex(dn, "/rsdomAtt-")
		if rsdomAttIndex == -1 {
			continue
		}
		skipEpg := false
		for _, epgDn := range systemDnsToFilter {
			if strings.HasPrefix(dn, epgDn) {
				skipEpg = true
				break
			}
		}
		if skipEpg {
			continue
		}
		rsdomAttDn := dn[rsdomAttIndex+len("/rsdomAtt-"):]
		rsdomAttDn = strings.Trim(rsdomAttDn, "[]")
		if rsdomAttDn == vmmDomPDn {
			fvRsDomAttSlice = append(fvRsDomAttSlice, fvRsDomAtt)
		}
	}

	return fvRsDomAttSlice
}

func apicUpdateFvRsDomAttInstrImedcy(fvRsDomAttSlice []apicapi.ApicObject, immediacy string) []apicapi.ApicObject {
	apicSlice := apicapi.ApicSlice{}
	for _, fvRsDomAtt := range fvRsDomAttSlice {
		dn := fvRsDomAtt.GetAttr("dn").(string)
		fvRsDomAttNew := apicapi.EmptyApicObject("fvRsDomAtt", dn)
		fvRsDomAttNew.SetAttr("tDn", fvRsDomAtt.GetAttr("tDn"))
		fvRsDomAttNew.SetAttr("instrImedcy", immediacy)
		if immediacy == "immediate" {
			//preprovision is supposedly the setting for immediate resolution
			fvRsDomAttNew.SetAttr("resImedcy", "pre-provision")
		} else {
			fvRsDomAttNew.SetAttr("resImedcy", immediacy)
		}
		apicSlice = append(apicSlice, fvRsDomAttNew)
	}
	return apicSlice
}

func apicGetNodesFromInterfacePolicyProfiles(apicClient *http.Client, apicHost string, imdata []apicapi.ApicObject) map[string][]int {
	fabricNodeMap := make(map[string][]int)
	nodePodMap := make(map[int]int)
	for _, intfProf := range imdata {
		pathDn := ""
		isVpc := false
		isDisAggPort := false
		dn := intfProf.GetAttr("dn").(string)
		after, found := strings.CutPrefix(dn, "uni/infra/funcprof/")
		if !found {
			continue
		}
		portGrp, found2 := strings.CutSuffix(after, "/rsattEntP")
		if !found2 {
			continue
		}
		portName := ""
		if strings.HasPrefix(portGrp, "accbundle") {
			portName = strings.TrimPrefix(portGrp, "accbundle-")
		} else {
			if strings.HasPrefix(portGrp, "accportgrp") {
				portName = strings.TrimPrefix(portGrp, "accportgrp-")
			}
			isDisAggPort = true
		}
		infraRtAccBaseGrpUri := fmt.Sprintf("/api/node/mo/uni/infra/funcprof/%s.json?query-target=subtree&target-subtree-class=infraRtAccBaseGrp,infraAccBndlGrp", portGrp)
		apicResp, err := apicGetResponse(apicClient, apicHost, infraRtAccBaseGrpUri)
		if err != nil {
			fmt.Printf("\nUnable to fetch accbundle/accportgrp: %v", err)
			continue
		}
		nodes := []int{}
		for _, infraRtAccBaseGrp := range apicResp.Imdata {
			foundBndl := false
			for mo, _ := range infraRtAccBaseGrp {
				if mo == "infraAccBndlGrp" {
					lagT := infraRtAccBaseGrp.GetAttr("lagT").(string)
					if lagT == "node" {
						isVpc = true
					}
					foundBndl = true
					break
				}
			}
			if foundBndl {
				continue
			}
			dn := infraRtAccBaseGrp.GetAttr("tDn").(string)
			var fromCard, toCard string
			var fromPort, toPort int
			var fromCardParts, toCardParts []int
			if isDisAggPort {
				infraPortBlkUri := fmt.Sprintf("/api/node/mo/%s.json?query-target=children&target-subtree-class=infraPortBlk", dn)
				apicResp5, err := apicGetResponse(apicClient, apicHost, infraPortBlkUri)
				if err != nil {
					fmt.Printf("\nUnable to fetch infraPortBlk: %v", err)
					continue
				}
				for _, infraPortBlk := range apicResp5.Imdata {
					fromCard = infraPortBlk.GetAttr("fromCard").(string)
					fromPort = infraPortBlk.GetAttr("fromPort").(int)
					toCard = infraPortBlk.GetAttr("toCard").(string)
					toPort = infraPortBlk.GetAttr("toPort").(int)
					fromCardPartsStr := strings.Split(fromCard, "/")
					toCardPartsStr := strings.Split(toCard, "/")
					for i := 0; i < len(fromCardPartsStr); i++ {
						cardId, _ := strconv.Atoi(fromCardPartsStr[i])
						fromCardParts = append(fromCardParts, cardId)
						cardId, _ = strconv.Atoi(toCardPartsStr[i])
						toCardParts = append(toCardParts, cardId)
					}

				}
			}
			dnParts := strings.Split(dn, "/")
			infraAccPortPDn := dnParts[0] + "/" + dnParts[1] + "/" + dnParts[2]
			infraRtAccPortPUri := fmt.Sprintf("/api/node/mo/%s.json?query-target=children&target-subtree-class=infraRtAccPortP", infraAccPortPDn)
			apicResp2, err := apicGetResponse(apicClient, apicHost, infraRtAccPortPUri)
			if err != nil {
				fmt.Printf("\nUnable to fetch infraRtAccPortP: %v", err)
				continue
			}
			nodeSet := []int{}
			for _, infraRtAccPortP := range apicResp2.Imdata {
				infraNodePDn := infraRtAccPortP.GetAttr("tDn").(string)
				infraNodeBlkUri := fmt.Sprintf("/api/node/mo/%s.json?query-target=subtree&target-subtree-class=infraNodeBlk", infraNodePDn)
				apicResp3, err := apicGetResponse(apicClient, apicHost, infraNodeBlkUri)
				if err != nil {
					fmt.Printf("\nUnable to fetch infraNodeBlk: %v", err)
					continue
				}
				for _, infraNodeBlk := range apicResp3.Imdata {
					fromNodeStr := infraNodeBlk.GetAttr("from_").(string)
					toNodeStr := infraNodeBlk.GetAttr("to_").(string)
					fromNode, err := strconv.Atoi(fromNodeStr)
					if err != nil {
						continue
					}
					toNode, err := strconv.Atoi(toNodeStr)
					if err != nil {
						continue
					}
					for i := fromNode; i <= toNode; i++ {
						nodeSet = append(nodeSet, i)
						nodes = append(nodes, i)
					}
				}
			}
			podId, ok := nodePodMap[nodeSet[0]]
			if !ok {
				infraNodePUri := fmt.Sprintf("/api/node/class/fabricNode.json?query-target-filter=and(eq(fabricNode.id,\"%d\"))", nodeSet[0])
				apicResp4, err := apicGetResponse(apicClient, apicHost, infraNodePUri)
				if err != nil {
					fmt.Printf("\nUnable to fetch infraNodeP: %v", err)
					continue
				}
				for _, infraNodeP := range apicResp4.Imdata {
					infraNodeDn := infraNodeP.GetAttr("dn").(string)
					infraNodeParts := strings.Split(infraNodeDn, "/")
					if len(infraNodeParts) >= 2 {
						podIdStr := strings.TrimPrefix(infraNodeParts[1], "pod-")
						podId, err = strconv.Atoi(podIdStr)
						if err != nil {
							continue
						}
						nodePodMap[nodeSet[0]] = podId
					}
				}
			}
			if isDisAggPort && (len(nodeSet) > 0) {
				if fromCard == toCard {
					for j := fromPort; j <= toPort; j++ {
						pathDn = fmt.Sprintf("topology/pod-%d/paths-%d/pathep-[eth%s/%d]", podId, nodeSet[0], fromCard, j)
						fabricNodeMap[pathDn] = []int{nodeSet[0]}
					}
				} else {
					_ = fromCardParts
					_ = toCardParts
					//TODO: handle breakoutports aka port spread across multiple cards
					//Need to fetch number of ports in each level of the card
				}
			}
		}
		slices.Sort(nodes)
		if (len(nodes) > 0) && !isDisAggPort {
			if isVpc {
				if len(nodes) > 1 {
					pathDn = fmt.Sprintf("topology/pod-%d/protpaths-%d-%d/pathep-[%s]", nodePodMap[nodes[0]], nodes[0], nodes[1], portName)
					fabricNodeMap[pathDn] = []int{nodes[0], nodes[1]}
				}
			} else {
				pathDn = fmt.Sprintf("topology/pod-%d/protpaths-%d/pathep-[%s]", nodePodMap[nodes[0]], nodes[0], portName)
				fabricNodeMap[pathDn] = []int{nodes[0]}
			}
		}
	}
	return fabricNodeMap
}
