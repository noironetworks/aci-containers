/***
Copyright 2018 Cisco Systems Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package integ

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/noironetworks/aci-containers/pkg/apicapi"
	"github.com/noironetworks/aci-containers/pkg/apiserver"
	//etcd_integ "github.com/etcd-io/etcd/integration"
	"github.com/coreos/etcd/embed"
)

var etcdClientURLs = []string{"http://localhost:12379"}

func TestBasic(t *testing.T) {
	var lcURLs []url.URL

	for _, u := range etcdClientURLs {
		uu, err := url.Parse(u)
		if err != nil {
			t.Fatal(err)
		}

		lcURLs = append(lcURLs, *uu)
	}
	// start an etcd server
	tempDir, err := ioutil.TempDir("", "api_etcd_")
	if err != nil {
		t.Fatal(err)
	}

	defer os.RemoveAll(tempDir)
	cfg := embed.NewConfig()
	cfg.Dir = tempDir
	cfg.LCUrls = lcURLs
	e, err := embed.StartEtcd(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	select {
	case <-e.Server.ReadyNotify():
		log.Infof("Server is ready!")
	case <-time.After(60 * time.Second):
		e.Server.Stop() // trigger a shutdown
		log.Infof("Server took too long to start!")
	}

	lPort := fmt.Sprintf(":%s", apiserver.ListenPort)
	clientCert, err := apiserver.StartNewServer(etcdClientURLs, lPort)
	if err != nil {
		t.Errorf("Starting api server: %v", err)
	}
	log.Infof("=> Started API server")
	logger := log.New()
	logger.Level = log.DebugLevel

	cert := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: clientCert,
	})
	conn, err := apicapi.New(logger, []string{"127.0.0.1:8899"},
		"admin", "noir0123", nil, cert, "kube", 60)
	if err != nil {
		t.Errorf("Starting apicapi : %v", err)
		t.FailNow()
	}
	stopCh := make(chan struct{})
	go conn.Run(stopCh)
	time.Sleep(2 * time.Second)

	// Inject some Apic Writes
	var as apicapi.ApicSlice
	as = append(as, apicapi.NewFvBD("common", "test"))
	dn1 := as[0].GetDn()
	conn.WriteApicObjects("serverKey1", as)
	time.Sleep(1 * time.Second)

	cli, err := getClient(cert)
	if err != nil {
		log.Info(err)
		t.Fail()
	}

	url1 := fmt.Sprintf("https://example.com:8899/api/mo/%s.json", dn1)
	url2 := "https://example.com:8899/api/node/mo/uni/userext/user-demo.json"

	urlList := []string{url1, url2}

	for _, u := range urlList {
		req, err := http.NewRequest("GET", u, nil)
		if err != nil {
			log.Info(err)
			t.Fail()
		}

		resp, err := cli.Do(req)
		if err != nil {
			log.Info(err)
			t.Fail()
		}

		res, err := ioutil.ReadAll(resp.Body)
		defer resp.Body.Close()
		if err != nil {
			log.Info(err)
			t.Fail()
		}

		log.Infof("==>> Response: %s", res)
	}

	time.Sleep(5 * time.Second)
	close(stopCh)
	addContract(t)
	addEPGs(t)
	addEPs(t)
	apiserver.DoAll()
}

func getClient(cert []byte) (*http.Client, error) {
	var tlsCfg tls.Config

	if cert == nil {
		tlsCfg.InsecureSkipVerify = true
	} else {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(cert) {
			return nil, errors.New("Could not load CA certificates")
		}

		tlsCfg.RootCAs = pool
	}

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tlsCfg,
		},
	}, nil
}

func addContract(t *testing.T) {

	rule := apiserver.WLRule{
		Protocol: "tcp",
		Ports: apiserver.IntRange{
			Start: 6443,
			End:   6443,
		},
	}

	c := &apiserver.Contract{
		Name:   "kubeAPI",
		Tenant: "common",
		AllowList: []apiserver.WLRule{
			rule,
		},
	}

	err := c.Make()
	if err != nil {
		log.Errorf("Contract make - %v", err)
		t.FailNow()
	}
}

func addEPGs(t *testing.T) {
	epgA := &apiserver.EPG{
		Name:   "epgA",
		Tenant: "common",
		ProvContracts: []string{
			"kubeAPI",
		},
	}

	err := epgA.Make()
	if err != nil {
		log.Errorf("epgA make - %v", err)
		t.FailNow()
	}

	epgB := &apiserver.EPG{
		Name:   "epgB",
		Tenant: "common",
		ConsContracts: []string{
			"kubeAPI",
		},
	}

	err = epgB.Make()
	if err != nil {
		log.Errorf("epgB make - %v", err)
		t.FailNow()
	}

	epgC := &apiserver.EPG{
		Name:   "epgC",
		Tenant: "common",
		ConsContracts: []string{
			"kubeAPI",
		},
		ProvContracts: []string{
			"kubeAPI",
		},
	}

	err = epgC.Make()
	if err != nil {
		log.Errorf("epgB make - %v", err)
		t.FailNow()
	}
}

func addEPs(t *testing.T) {
	epList := []apiserver.Endpoint{
		{EPG: "epgA", VTEP: "101.10.1.1"},
		{EPG: "epgC", VTEP: "101.10.1.1"},
		{EPG: "epgA", VTEP: "101.10.1.2"},
		{EPG: "epgB", VTEP: "101.10.1.2"},
		{EPG: "epgB", VTEP: "101.10.1.3"},
		{EPG: "epgB", VTEP: "101.10.1.3"},
		{EPG: "epgA", VTEP: "101.10.1.3"},
	}

	for ix, ep := range epList {
		ep.Uuid = fmt.Sprintf("2d62c0ca-049d-11e9-9d5e-005056986463_4646341552ed73d23d688a8578ed51236610a0dec385418%d_veth10%d", ix, ix)
		ep.MacAddr = fmt.Sprintf("ca:17:aa:10:aa:%d%d", ix, ix)
		ep.IPAddr = fmt.Sprintf("121.1.1.%d", ix)
		err := ep.Add()
		if err != nil {
			log.Errorf("ep make - %v", err)
			t.FailNow()
		}

	}
}
