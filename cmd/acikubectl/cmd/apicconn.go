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
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/gorilla/websocket"
	"github.com/noironetworks/aci-containers/pkg/apicapi"
	acictrlr "github.com/noironetworks/aci-containers/pkg/controller"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
)

var signed *signer
var req_token string

type signer struct {
	key interface{}
}

func hash(method, url string, body []byte) []byte {
	h := sha256.New()
	h.Write([]byte(method))
	h.Write([]byte(url))
	if body != nil {
		h.Write(body)
	}
	return h.Sum(nil)
}

func (s *signer) sign(method, url string,
	body []byte) (sig string, err error) {
	h := hash(method, url, body)

	var raw []byte
	switch k := s.key.(type) {
	case *rsa.PrivateKey:
		raw, err = rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, h)
		if err != nil {
			return
		}
	default:
		err = errors.New("Unsupported key type")
		return
	}

	sig = base64.StdEncoding.EncodeToString(raw)
	return
}

func sign(user string, req *http.Request, uri string, body []byte, signer *signer) {
	sig, err := signer.sign(req.Method, uri, body)
	if err != nil {
		fmt.Println("Failed to sign request: ", err)
		return
	}

	req.Header.Set("Cookie", apicSigCookie(user, sig, req_token))
}

func apicSigCookie(user string, sig, token string) string {
	tokc := ""
	if token != "" {
		tokc = "; APIC-WebSocket-Session=" + token
	}
	return fmt.Sprintf("APIC-Request-Signature=%s; "+
		"APIC-Certificate-Algorithm=v1.0; "+
		"APIC-Certificate-DN=uni/userext/user-%s/usercert-%s.crt; "+
		"APIC-Certificate-Fingerprint=fingerprint%s",
		sig, user, user, tokc)
}

func newSigner(privKey []byte) (*signer, error) {
	block, _ := pem.Decode(privKey)
	if block == nil {
		return nil, errors.New("Could not decode PEM file")
	}
	if !strings.HasSuffix(block.Type, "PRIVATE KEY") {
		return nil, errors.New("PEM file does not contain private key")
	}
	s := &signer{}
	switch block.Type {
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		s.key = key
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		s.key = key
	default:
		return nil, errors.New("Unsupported key type: " + block.Type)
	}
	return s, nil
}

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

func findCertAndKeyFiles(sysid string) (string, string, error) {
	certFile := fmt.Sprintf("user-%s.crt", sysid)
	keyFile := fmt.Sprintf("user-%s.key", sysid)

	_, err := os.Stat(certFile)
	if err != nil {
		return "", "", err
	}

	_, err = os.Stat(keyFile)
	if err != nil {
		return "", "", err
	}

	return certFile, keyFile, nil
}

func sendLoginRequest(apicClient *http.Client, url string, reqBody io.Reader) (string, error) {
	req, err := http.NewRequest("POST", url, reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to create login request: %v", err)
	}

	resp, err := apicClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send login request: %v", err)
	}
	defer resp.Body.Close()

	var apicresp apicapi.ApicResponse
	err = json.NewDecoder(resp.Body).Decode(&apicresp)
	if err != nil {
		return "", fmt.Errorf("failed to decode login response: %v", err)
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
			continue
		}
		stoken, isStr := token.(string)
		if !isStr {
			continue
		}
		return stoken, nil
	}

	return "", errors.New("token not found in login response")
}

func loginWithTLS(apicClient *http.Client, apicHosts []string, certFile, keyFile, user string) (string, int, error) {
	privKey, err := ioutil.ReadFile(keyFile)

	if err != nil {
		return "", -1, fmt.Errorf("failed to read private key file: %v", err)
	}

	signed, err = newSigner(privKey)
	if err != nil {
		return "", -1, fmt.Errorf("failed to create signer: %v", err)
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return "", -1, fmt.Errorf("failed to load key pair: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
	}

	dialer := &websocket.Dialer{
		TLSClientConfig: tlsConfig,
	}

	apicClient.Transport = &http.Transport{
		Proxy:           http.ProxyFromEnvironment,
		TLSClientConfig: dialer.TLSClientConfig,
	}

	for apicIndex, apicHost := range apicHosts {
		path := "webtokenSession"
		method := "GET"

		uri := fmt.Sprintf("/api/%s.json", path)
		url := fmt.Sprintf("https://%s%s", apicHost, uri)

		req, err := http.NewRequest(method, url, nil)
		if err != nil {
			return "", -1, fmt.Errorf("failed to create request: %v", err)
		}

		sign(user, req, uri, nil, signed)
		req.Header.Set("Content-Type", "application/json")

		resp, err := apicClient.Do(req)
		if err != nil {
			return "", -1, fmt.Errorf("failed to make request: %v", err)
		}
		defer resp.Body.Close()

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
				return "", -1, errors.New("Token not found in login response")
			}
			stoken, isStr := token.(string)
			if !isStr {
				return "", -1, errors.New("Token is not a string")
			}

			req_token = stoken
			return stoken, apicIndex, nil

		}
	}
	return "", -1, errors.New("failed to find valid login response for all hosts: No token found")
}

func loginWithUsernamePassword(apicClient *http.Client, apicHosts []string, apicUser, apicPassword string) (string, int, error) {
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
			fmt.Printf("Failed to marshal login request: %v\n", err)
			continue
		}
		reqBody := bytes.NewBuffer(raw)

		token, err := sendLoginRequest(apicClient, url, reqBody)
		if err == nil {
			return token, apicIndex, nil
		}
	}

	return "", -1, errors.New("username/password login failed for all hosts: No token found")
}

func apicLogin(apicClient *http.Client, apicHosts []string, apicUser, apicPassword, certFile, keyFile, user string) (string, int, error) {

	if certFile != "" && keyFile != "" {
		return loginWithTLS(apicClient, apicHosts, certFile, keyFile, user)
	}

	return loginWithUsernamePassword(apicClient, apicHosts, apicUser, apicPassword)
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

func apicPostApicObjects(apicClient *http.Client, apicHost string, uri string, payload apicapi.ApicSlice, useCert bool, user string) error {
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

	if useCert {
		sign(user, req, uri, raw, signed)
	}

	resp, err := apicClient.Do(req)
	if err != nil {
		fmt.Println("Could not update  ", url, ": ", err)
		return err
	}

	apicRespComplete(resp)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Status: %v\n", resp.StatusCode)
	}
	return nil
}

func apicGetResponse(apicClient *http.Client, apicHost string, uri string, useCert bool, user string) (apicapi.ApicResponse, error) {
	url := fmt.Sprintf("https://%s%s", apicHost, uri)
	var apicresp apicapi.ApicResponse
	req, err := http.NewRequest("GET", url, http.NoBody)
	if err != nil {
		fmt.Printf("Could not create request: ", err)
		return apicresp, err
	}

	if useCert {
		sign(user, req, uri, nil, signed)
	}

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

func apicGetNodesFromInterfacePolicyProfiles(apicClient *http.Client, apicHost string, imdata []apicapi.ApicObject, useCert bool, user string) map[string][]int {
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
		apicResp, err := apicGetResponse(apicClient, apicHost, infraRtAccBaseGrpUri, useCert, user)
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
			dnParts := strings.Split(dn, "/")
			infraAccPortPDn := dnParts[0] + "/" + dnParts[1] + "/" + dnParts[2]
			infraRtAccPortPUri := fmt.Sprintf("/api/node/mo/%s.json?query-target=children&target-subtree-class=infraRtAccPortP", infraAccPortPDn)
			apicResp2, err := apicGetResponse(apicClient, apicHost, infraRtAccPortPUri, useCert, user)
			if err != nil {
				fmt.Printf("\nUnable to fetch infraRtAccPortP: %v", err)
				continue
			}
			nodeSet := []int{}
			for _, infraRtAccPortP := range apicResp2.Imdata {
				infraNodePDn := infraRtAccPortP.GetAttr("tDn").(string)
				infraNodeBlkUri := fmt.Sprintf("/api/node/mo/%s.json?query-target=subtree&target-subtree-class=infraNodeBlk", infraNodePDn)
				apicResp3, err := apicGetResponse(apicClient, apicHost, infraNodeBlkUri, useCert, user)
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
				apicResp4, err := apicGetResponse(apicClient, apicHost, infraNodePUri, useCert, user)
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
				infraPortBlkUri := fmt.Sprintf("/api/node/mo/%s.json?query-target=children&target-subtree-class=infraPortBlk", dn)
				apicResp5, err := apicGetResponse(apicClient, apicHost, infraPortBlkUri, useCert, user)
				if err != nil {
					fmt.Printf("\nUnable to fetch infraPortBlk: %v", err)
					continue
				}
				for _, infraPortBlk := range apicResp5.Imdata {
					var fromCardParts, toCardParts []int
					fromCard := infraPortBlk.GetAttr("fromCard").(string)
					fromPortStr := infraPortBlk.GetAttr("fromPort").(string)
					fromPort, _ := strconv.Atoi(fromPortStr)
					toCard := infraPortBlk.GetAttr("toCard").(string)
					toPortStr := infraPortBlk.GetAttr("toPort").(string)
					toPort, _ := strconv.Atoi(toPortStr)
					fromCardPartsStr := strings.Split(fromCard, "/")
					toCardPartsStr := strings.Split(toCard, "/")
					for i := 0; i < len(fromCardPartsStr); i++ {
						cardId, _ := strconv.Atoi(fromCardPartsStr[i])
						fromCardParts = append(fromCardParts, cardId)
						cardId, _ = strconv.Atoi(toCardPartsStr[i])
						toCardParts = append(toCardParts, cardId)
					}
					if fromCard == toCard {
						for j := fromPort; j <= toPort; j++ {
							pathDn = fmt.Sprintf("topology/pod-%d/paths-%d/pathep-[eth%s/%d]", podId, nodeSet[0], fromCard, j)
							fabricNodeMap[pathDn] = []int{nodeSet[0]}
						}
					} else {
						_ = fromCardParts
						_ = toCardParts
						// TODO: handle breakoutports aka port spread across multiple cards
						// Need to fetch number of ports in each level of the card
					}
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
