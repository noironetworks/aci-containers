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
