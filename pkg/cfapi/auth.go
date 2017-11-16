// Copyright 2017 Cisco Systems, Inc.
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

package cfapi

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"time"
)

type TokenInfo struct {
	Scope    []string `json:"scope"`
	UserId   string   `json:"user_id"`
	UserName string   `json:"user_name"`
}

func (t *TokenInfo) IsNetworkAdmin() bool {
	for _, s := range t.Scope {
		if s == "network.admin" {
			return true
		}
	}
	return false
}

type CfAuthClient interface {
	FetchTokenInfo(token string) (*TokenInfo, error)
}

type cfAuthUaa struct {
	http.Client
	ApiUrl       string
	ClientName   string
	ClientSecret string
}

func NewCfAuthClient(uaaApiUrl, caCertFile, clientName, clientSecret string) (CfAuthClient, error) {
	certBytes, err := ioutil.ReadFile(caCertFile)
	if err != nil {
		return nil, err
	}
	caCertPool := x509.NewCertPool()
	if ok := caCertPool.AppendCertsFromPEM(certBytes); !ok {
		return nil, fmt.Errorf("Failed to load UAA CA Cert")
	}
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    caCertPool,
	}
	t := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		Dial: (&net.Dialer{
			// values taken from http.DefaultTransport
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).Dial,
		// value taken from http.DefaultTransport
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig:     tlsConfig,
	}

	auth := cfAuthUaa{Client: http.Client{Transport: t, Timeout: 30 * time.Second},
		ApiUrl: uaaApiUrl, ClientName: clientName, ClientSecret: clientSecret}
	return &auth, nil
}

func (auth *cfAuthUaa) FetchTokenInfo(token string) (*TokenInfo, error) {
	reqURL := auth.ApiUrl + "/check_token"
	body := "token=" + token

	req, err := http.NewRequest("POST", reqURL, strings.NewReader(body))
	req.SetBasicAuth(auth.ClientName, auth.ClientSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := auth.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusBadRequest {
		return nil, nil
	}
	resBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var ti TokenInfo
	err = json.Unmarshal(resBody, &ti)
	if err != nil {
		return nil, err
	}
	return &ti, nil
}

func ExtractToken(req *http.Request) string {
	auth := req.Header["Authorization"]
	if len(auth) < 1 {
		return ""
	}

	token := auth[0]
	token = strings.TrimPrefix(token, "Bearer ")
	token = strings.TrimPrefix(token, "bearer ")
	return token
}

func HasAccess(cc CcClient, auth CfAuthClient, req *http.Request, kind, id, access string) (bool, error) {
	tok := ExtractToken(req)
	if tok == "" {
		return false, nil
	}
	ti, err := auth.FetchTokenInfo(tok)
	if err != nil {
		return false, err
	}
	if ti == nil {
		return false, nil
	}
	if kind == "app" {
		sp, err := cc.GetAppSpace(id)
		if err != nil {
			return false, nil // TODO handle app-not-found different from other errors
		}
		id = sp
		kind = "space"
	}
	if ti.IsNetworkAdmin() {
		return true, nil
	}
	ur, err := cc.GetUserRoleInfo(ti.UserId)
	if err != nil {
		return false, err
	}
	if kind == "space" && access == "read" {
		return ur.CanReadSpace(id), nil
	} else if kind == "space" && access == "write" {
		return ur.CanWriteSpace(id), nil
	} else if kind == "org" && access == "read" {
		return ur.CanReadOrg(id), nil
	} else if kind == "org" && access == "write" {
		return ur.CanWriteOrg(id), nil
	}
	return false, nil
}
