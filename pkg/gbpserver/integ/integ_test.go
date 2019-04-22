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
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/noironetworks/aci-containers/pkg/apicapi"
	"github.com/noironetworks/aci-containers/pkg/gbpserver"
	//etcd_integ "github.com/etcd-io/etcd/integration"
	"github.com/coreos/etcd/embed"
)

const (
	testTenant = "gbpKubeTenant"
	testVrf    = "gbpKubeVrf1"
	testRegion = "us-west-1"
	kubeTenant = "kube"
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

	dataDir, err := ioutil.TempDir("", "_gbpdata")
	if err != nil {
		t.Fatal(err)
	}

	defer os.RemoveAll(dataDir)
	//gbpserver.InitDB(dataDir, "18.217.5.107:443")
	gbpserver.InitDB(dataDir, "None", "None")

	lPort := fmt.Sprintf(":%s", gbpserver.ListenPort)
	clientCert, _, err := gbpserver.StartNewServer(etcdClientURLs, lPort, "")
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
		log.Infof("Verify gets")
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

	time.Sleep(2 * time.Second)
	addContract(t)
	addEPGs(t)
	addEPs(t)
	verifyRest(t, cli)
	close(stopCh)
	gbpserver.DoAll()
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

	rule := gbpserver.WLRule{
		Protocol: "tcp",
		Ports: gbpserver.IntRange{
			Start: 6443,
			End:   6443,
		},
	}

	c := &gbpserver.Contract{
		Name:   "kubeAPI",
		Tenant: kubeTenant,
		AllowList: []gbpserver.WLRule{
			rule,
		},
	}

	err := c.Make()
	if err != nil {
		log.Errorf("Contract make - %v", err)
		t.FailNow()
	}

	emptyRule := gbpserver.WLRule{}
	emptyC := &gbpserver.Contract{
		Name:   "any",
		Tenant: kubeTenant,
		AllowList: []gbpserver.WLRule{
			emptyRule,
		},
	}
	err = emptyC.Make()
	if err != nil {
		log.Errorf("Contract make - %v", err)
		t.FailNow()
	}
}

func addEPGs(t *testing.T) {
	epgList := []*gbpserver.EPG{
		{
			Name:   "epgA",
			Tenant: kubeTenant,
			ProvContracts: []string{
				"kubeAPI",
			},
		},

		{
			Name:   "epgB",
			Tenant: kubeTenant,
			ConsContracts: []string{
				"kubeAPI",
			},
		},

		{
			Name:   "epgC",
			Tenant: kubeTenant,
			ConsContracts: []string{
				"kubeAPI",
			},
			ProvContracts: []string{
				"kubeAPI",
			},
		},

		{
			Name:          "kubernetes-kube-system",
			Tenant:        kubeTenant,
			ConsContracts: []string{},
			ProvContracts: []string{},
		},

		{
			Name:          "kubernetes-kube-default",
			Tenant:        kubeTenant,
			ConsContracts: []string{},
			ProvContracts: []string{},
		},
	}

	for _, e := range epgList {
		err := e.Make()
		if err != nil {
			log.Errorf("%s make - %v", e.Name, err)
			t.FailNow()
		}
	}
}

func addEPs(t *testing.T) {
	epList := []gbpserver.Endpoint{
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
		ep.IPAddr = fmt.Sprintf("10.2.52.%d", ix)
		_, err := ep.Add()
		if err != nil {
			log.Errorf("ep make - %v", err)
			t.FailNow()
		}

	}
}

func verifyRest(t *testing.T, c *http.Client) {
	// Contract
	emptyRule := gbpserver.WLRule{}
	testContract := &gbpserver.Contract{
		Name:      "all-ALL",
		Tenant:    kubeTenant,
		AllowList: []gbpserver.WLRule{emptyRule},
	}
	testEpg := &gbpserver.EPG{
		Tenant:        kubeTenant,
		Name:          "Roses",
		ConsContracts: []string{"all-ALL"},
		ProvContracts: []string{"all-ALL"},
	}
	testEP := &gbpserver.Endpoint{
		Uuid:    "testEP-xxx-yyy-zzz",
		MacAddr: "58:ef:68:e2:71:0d",
		IPAddr:  "10.2.50.55",
		EPG:     "Roses",
		VTEP:    "8.8.8.8",
	}

	testNPjson := []byte("{\"hostprotPol\":{\"attributes\":{\"dn\":\"uni/tn-vk8s_1/pol-vk8s_1_node_vk8s-node1\",\"name\":\"vk8s_1_node_vk8s-node1\"},\"children\":[{\"hostprotSubj\":{\"attributes\":{\"dn\":\"uni/tn-vk8s_1/pol-vk8s_1_node_vk8s-node1/subj-local-node\",\"name\":\"local-node\"},\"children\":[{\"hostprotRule\":{\"attributes\":{\"connTrack\":\"normal\",\"direction\":\"egress\",\"dn\":\"uni/tn-vk8s_1/pol-vk8s_1_node_vk8s-node1/subj-local-node/rule-allow-all-egress\",\"ethertype\":\"ipv4\",\"fromPort\":\"unspecified\",\"name\":\"allow-all-egress\",\"protocol\":\"unspecified\",\"toPort\":\"unspecified\"},\"children\":[{\"hostprotRemoteIp\":{\"attributes\":{\"addr\":\"1.100.201.12\",\"dn\":\"uni/tn-vk8s_1/pol-vk8s_1_node_vk8s-node1/subj-local-node/rule-allow-all-egress/ip-[1.100.201.12]\"},\"children\":[{\"tagInst\":{\"attributes\":{\"dn\":\"uni/tn-vk8s_1/pol-vk8s_1_node_vk8s-node1/subj-local-node/rule-allow-all-egress/ip-[1.100.201.12]/tag-vk8s_1-523d2f252a0f4b0aeb22f43c11c7a1c2\",\"name\":\"vk8s_1-523d2f252a0f4b0aeb22f43c11c7a1c2\"}}}]}},{\"tagInst\":{\"attributes\":{\"dn\":\"uni/tn-vk8s_1/pol-vk8s_1_node_vk8s-node1/subj-local-node/rule-allow-all-egress/tag-vk8s_1-523d2f252a0f4b0aeb22f43c11c7a1c2\",\"name\":\"vk8s_1-523d2f252a0f4b0aeb22f43c11c7a1c2\"}}}]}},{\"hostprotRule\":{\"attributes\":{\"connTrack\":\"normal\",\"direction\":\"ingress\",\"dn\":\"uni/tn-vk8s_1/pol-vk8s_1_node_vk8s-node1/subj-local-node/rule-allow-all-ingress\",\"ethertype\":\"ipv4\",\"fromPort\":\"unspecified\",\"name\":\"allow-all-ingress\",\"protocol\":\"unspecified\",\"toPort\":\"unspecified\"},\"children\":[{\"hostprotRemoteIp\":{\"attributes\":{\"addr\":\"1.100.201.12\",\"dn\":\"uni/tn-vk8s_1/pol-vk8s_1_node_vk8s-node1/subj-local-node/rule-allow-all-ingress/ip-[1.100.201.12]\"},\"children\":[{\"tagInst\":{\"attributes\":{\"dn\":\"uni/tn-vk8s_1/pol-vk8s_1_node_vk8s-node1/subj-local-node/rule-allow-all-ingress/ip-[1.100.201.12]/tag-vk8s_1-523d2f252a0f4b0aeb22f43c11c7a1c2\",\"name\":\"vk8s_1-523d2f252a0f4b0aeb22f43c11c7a1c2\"}}}]}},{\"tagInst\":{\"attributes\":{\"dn\":\"uni/tn-vk8s_1/pol-vk8s_1_node_vk8s-node1/subj-local-node/rule-allow-all-ingress/tag-vk8s_1-523d2f252a0f4b0aeb22f43c11c7a1c2\",\"name\":\"vk8s_1-523d2f252a0f4b0aeb22f43c11c7a1c2\"}}}]}},{\"tagInst\":{\"attributes\":{\"dn\":\"uni/tn-vk8s_1/pol-vk8s_1_node_vk8s-node1/subj-local-node/tag-vk8s_1-523d2f252a0f4b0aeb22f43c11c7a1c2\",\"name\":\"vk8s_1-523d2f252a0f4b0aeb22f43c11c7a1c2\"}}}]}},{\"tagInst\":{\"attributes\":{\"dn\":\"uni/tn-vk8s_1/pol-vk8s_1_node_vk8s-node1/tag-vk8s_1-523d2f252a0f4b0aeb22f43c11c7a1c2\",\"name\":\"vk8s_1-523d2f252a0f4b0aeb22f43c11c7a1c2\"}}}]}}")

	postList := []struct {
		url string
		obj interface{}
	}{
		{"https://example.com:8899/gbp/contracts", testContract},
		{"https://example.com:8899/gbp/epgs", testEpg},
		{"https://example.com:8899/gbp/endpoints", testEP},
		{"https://example.com:8899/api/mo/uni/tn-kube/pol-vk8s_1_node_vk8s-node1", testNPjson},
	}

	for _, p := range postList {
		var err error
		content, ok := p.obj.([]byte)
		if !ok {
			content, err = json.Marshal(p.obj)
			if err != nil {
				log.Errorf("json.Marshal :% v", err)
				t.FailNow()
			}
		}
		resp, err := c.Post(p.url, "application/json", strings.NewReader(string(content)))
		if err != nil {
			log.Errorf("Post :% v", err)
			t.FailNow()
		}

		defer resp.Body.Close()

		rBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Errorf("ReadAll :% v", err)
			t.FailNow()
		}

		var reply gbpserver.PostResp

		err = json.Unmarshal(rBody, &reply)
		if err != nil {
			log.Errorf("Unmarshal :% v", err)
			t.FailNow()
		}

		log.Infof("reply: %+v", reply)
	}

	getter := func(uri string) []byte {
		getResp, err := c.Get(uri)
		if err != nil {
			log.Errorf("Get :% v", err)
			t.FailNow()
		}

		defer getResp.Body.Close()
		gBody, err := ioutil.ReadAll(getResp.Body)
		if err != nil {
			log.Errorf("ReadAll :% v", err)
			t.FailNow()
		}

		return gBody
	}

	l := getter("https://example.com:8899/gbp/epgs/")
	var getList gbpserver.ListResp

	err := json.Unmarshal(l, &getList)
	if err != nil {
		log.Errorf("Marshal get list :% v", err)
		t.FailNow()
	}
	for _, reqUri := range getList.URIs {
		gb := getter(fmt.Sprintf("https://example.com:8899/gbp/epg/?key=%s", reqUri))
		log.Infof("EPG Get Resp: %s", gb)
	}

	l = getter("https://example.com:8899/gbp/contracts/")

	err = json.Unmarshal(l, &getList)
	if err != nil {
		log.Errorf("Marshal get list :% v", err)
		t.FailNow()
	}

	log.Infof("contractlist: %+v", getList)
	for _, reqUri := range getList.URIs {
		gb := getter(fmt.Sprintf("https://example.com:8899/gbp/contract/?key=%s", reqUri))
		log.Infof("Contract Get Resp: %s", gb)
	}

	l = getter("https://example.com:8899/gbp/endpoints/")

	err = json.Unmarshal(l, &getList)
	if err != nil {
		log.Errorf("Marshal get list :% v", err)
		t.FailNow()
	}

	log.Infof("eplist: %+v", getList)
	for _, reqUri := range getList.URIs {
		gb := getter(fmt.Sprintf("https://example.com:8899/gbp/endpoint/?key=%s", reqUri))
		log.Infof("Endpoint Get Resp: %s", gb)
	}

	for _, reqUri := range getList.URIs {
		req, _ := http.NewRequest("DELETE", fmt.Sprintf("https://example.com:8899/gbp/endpoint/?key=%s", reqUri), nil)
		_, err = c.Do(req)
		if err != nil {
			log.Errorf("Delete %s :% v", reqUri, err)
			t.FailNow()
		}
	}

	l = getter("https://example.com:8899/gbp/endpoints/")

	err = json.Unmarshal(l, &getList)
	if err != nil {
		log.Errorf("Marshal get list :% v", err)
		t.FailNow()
	}

	if len(getList.URIs) != 0 {
		log.Errorf("EPs present: %q", getList.URIs)
		t.FailNow()
	}
	req, _ := http.NewRequest("DELETE", "https://example.com:8899/api/mo/uni/tn-kube/pol-vk8s_1_node_vk8s-node1", nil)
	_, err = c.Do(req)
	if err != nil {
		log.Errorf("Delete :% v", err)
		t.FailNow()
	}
}

func TestAPIC(t *testing.T) {
	log1 := log.New()
	log1.Level = log.DebugLevel
	log1.Formatter = &log.TextFormatter{
		DisableColors: true,
	}

	conn, err := apicapi.New(log1, []string{"18.217.5.107:443"}, "admin", "noir0!234", nil, nil, "test", 60)
	if err != nil {
		log.Errorf("New connection -- %v", err)
		t.FailNow()
	}

	log.Infof("Posting tenant...")
	vrfMo := apicapi.NewFvCtx(testTenant, testVrf)
	cCtxMo := apicapi.NewCloudCtxProfile(testTenant, "gbpKubeVrf1-west-1")
	cidrMo := apicapi.NewCloudCidr(cCtxMo.GetDn(), "102.176.0.0/16")
	cCtxMoBody := cCtxMo["cloudCtxProfile"]
	ctxChildren := []apicapi.ApicObject{
		cidrMo,
		apicapi.NewCloudRsToCtx(cCtxMo.GetDn(), testVrf),
		apicapi.NewCloudRsCtxProfileToRegion(cCtxMo.GetDn(), "uni/clouddomp/provp-aws/region-us-west-1"),
	}

	for _, child := range ctxChildren {
		cCtxMoBody.Children = append(cCtxMoBody.Children, child)
	}

	//	epgASel := apicapi.EmptyApicObject("cloudEPSelector", "")
	//	epgASel["cloudEPSelector"].Attributes["name"] = "selSubnet102.176.1.0"
	//	epgASel["cloudEPSelector"].Attributes["matchExpression"] = "IP=='102.176.1.0/24'"

	epgToVrf := apicapi.EmptyApicObject("cloudRsCloudEPgCtx", "")
	epgToVrf["cloudRsCloudEPgCtx"].Attributes["tnFvCtxName"] = testVrf
	cepgA := apicapi.NewCloudEpg(testTenant, "gbpApp1", "cEPG-A")
	//	cepgA["cloudEPg"].Children = append(cepgA["cloudEPg"].Children, epgASel)
	cepgA["cloudEPg"].Children = append(cepgA["cloudEPg"].Children, epgToVrf)
	var cfgMos = []apicapi.ApicObject{
		apicapi.NewFvTenant(testTenant),
		vrfMo,
		apicapi.NewCloudAwsProvider(testTenant, testRegion, "gmeouw1"),
		cCtxMo,
		apicapi.NewCloudSubnet(cidrMo.GetDn(), "102.176.1.0/24"),
		apicapi.NewCloudApp(testTenant, "gbpApp1"),
		cepgA,
	}
	for _, cmo := range cfgMos {
		err = conn.PostDnInline(cmo.GetDn(), cmo)
		if err != nil {
			log.Errorf("Post %s -- %v", cmo.GetDn(), err)
			t.FailNow()
		}
	}

	time.Sleep(5 * time.Second)
	AddEP(t, testTenant, testRegion, testVrf, cepgA.GetDn(), true)
	time.Sleep(5 * time.Second)
	AddEP(t, testTenant, testRegion, testVrf, cepgA.GetDn(), false)
}

func AddEP(t *testing.T, tenant, region, vrf, epgDn string, add bool) {
	log1 := log.New()
	log1.Level = log.DebugLevel
	log1.Formatter = &log.TextFormatter{
		DisableColors: true,
	}

	conn, err := apicapi.New(log1, []string{"18.217.5.107:443"}, "admin", "noir0!234", nil, nil, "test", 60)
	if err != nil {
		log.Errorf("New connection -- %v", err)
		t.FailNow()
	}

	getSgDn := func() string {
		n := fmt.Sprintf("acct-[%s]/region-[%s]/context-[%s]/sgroup-[%s]",
			tenant, region, vrf, epgDn)
		return n
	}

	log.Infof("Posting EP...")
	epToSg := apicapi.EmptyApicObject("hcloudRsEpToSecurityGroup", "")
	epToSg["hcloudRsEpToSecurityGroup"].Attributes["tDn"] = getSgDn()
	cEP := apicapi.EmptyApicObject("hcloudEndPoint", "")
	cEP["hcloudEndPoint"].Attributes["name"] = "eni-testGbpEP"
	cEP["hcloudEndPoint"].Attributes["primaryIpV4Addr"] = "102.176.1.2"
	cEP["hcloudEndPoint"].Children = append(cEP["hcloudEndPoint"].Children, epToSg)
	if !add {
		cEP["hcloudEndPoint"].Attributes["status"] = "deleted"
	}

	cSN := apicapi.EmptyApicObject("hcloudSubnet", "")
	cSN["hcloudSubnet"].Attributes["addr"] = "102.176.1.0/24"
	cSN["hcloudSubnet"].Children = append(cSN["hcloudSubnet"].Children, cEP)

	cCidr := apicapi.EmptyApicObject("hcloudCidr", "")
	cCidr["hcloudCidr"].Attributes["addr"] = "102.176.0.0/16"
	cCidr["hcloudCidr"].Children = append(cCidr["hcloudCidr"].Children, cSN)

	cCtx := apicapi.EmptyApicObject("hcloudCtx", "")
	cCtx["hcloudCtx"].Attributes["name"] = vrf
	cCtx["hcloudCtx"].Children = append(cCtx["hcloudCtx"].Children, cCidr)

	cRegion := apicapi.EmptyApicObject("hcloudRegion", "")
	cRegion["hcloudRegion"].Attributes["regionName"] = region
	cRegion["hcloudRegion"].Children = append(cRegion["hcloudRegion"].Children, cCtx)

	cAcc := apicapi.EmptyApicObject("hcloudAccount", "")
	cAcc["hcloudAccount"].Attributes["name"] = tenant
	cAcc["hcloudAccount"].Children = append(cAcc["hcloudAccount"].Children, cRegion)

	err = conn.PostTestAPI(cAcc)
	if err != nil {
		log.Errorf("Post %+v -- %v", cAcc, err)
		t.FailNow()
	}
}
