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

package gbpserver

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/noironetworks/aci-containers/pkg/apicapi"
	"google.golang.org/grpc"
	//etcd_integ "github.com/etcd-io/etcd/integration"
	"github.com/coreos/etcd/embed"
	"github.com/noironetworks/aci-containers/pkg/gbpcrd/apis/acipolicy/v1"
	"github.com/stretchr/testify/assert"
)

const (
	testTenant = "gbpKubeTenant"
	testVrf    = "gbpKubeVrf1"
	testRegion = "us-west-1"
)

var etcdClientURLs = []string{"http://localhost:12379"}

// implements StateDriver
type testSD struct {
	s v1.GBPSState
}

func (sd *testSD) Init(unused int) error {
	sm := make(map[string]uint)
	sm["/PolicyUniverse/PolicySpace/gbpKubeTenant/GbpRoutingDomain/defaultVrf/GbpeInstContext/"] = 32000
	sm["/PolicyUniverse/PolicySpace/gbpKubeTenant/GbpBridgeDomain/defaultBD/GbpeInstContext/"] = 32001
	sm["/PolicyUniverse/PolicySpace/gbpKubeTenant/GbpBridgeDomain/nodeBD/GbpeInstContext/"] = 32002
	sm["/PolicyUniverse/PolicySpace/gbpKubeTenant/GbpEpGroup/kubernetes%7ckube-default/GbpeInstContext/"] = 32003
	sm["/PolicyUniverse/PolicySpace/gbpKubeTenant/GbpEpGroup/kubernetes%7ckube-system/GbpeInstContext/"] = 32004
	sm["/PolicyUniverse/PolicySpace/gbpKubeTenant/GbpEpGroup/kubernetes%7ckube-nodes/GbpeInstContext/"] = 32005
	sd.s.Status.ClassIDs = sm
	return nil
}

func stateCopy(src, dest *v1.GBPSState) error {
	b, err := json.Marshal(src)
	if err != nil {
		return err
	}

	return json.Unmarshal(b, dest)
}

func (sd *testSD) Get() (*v1.GBPSState, error) {
	out := &v1.GBPSState{}
	return out, stateCopy(&sd.s, out)
}

func (sd *testSD) Update(s *v1.GBPSState) error {
	log.Debugf("Update: %+v", s.Status.ClassIDs)
	sd.s = v1.GBPSState{}
	return stateCopy(s, &sd.s)
}

type testSuite struct {
	e       *embed.Etcd
	tempDir string
	dataDir string
	sd      *testSD
}

func (ts *testSuite) tearDown() {
	ts.e.Close()
	os.RemoveAll(ts.tempDir)
	os.RemoveAll(ts.dataDir)
}

func (ts *testSuite) setupGBPServer(t *testing.T) *Server {
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

	ts.tempDir = tempDir
	cfg := embed.NewConfig()
	cfg.Dir = tempDir
	cfg.LCUrls = lcURLs
	cfg.EnableV2 = true
	e, err := embed.StartEtcd(cfg)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-e.Server.ReadyNotify():
		log.Infof("Server is ready!")
	case <-time.After(60 * time.Second):
		e.Server.Stop() // trigger a shutdown
		log.Infof("Server took too long to start!")
		t.Fatal("Etcd Server took too long to start!")
	}

	ts.e = e

	dataDir, err := ioutil.TempDir("", "_gbpdata")
	assert.Equal(t, err, nil)

	ts.dataDir = dataDir
	ts.sd = &testSD{}
	err = ts.sd.Init(0)
	assert.Equal(t, err, nil)

	gCfg := &GBPServerConfig{}
	gCfg.LogLevel = "info"
	gCfg.GRPCLogLevel = "info"
	gCfg.WatchLogLevel = "info"
	gCfg.GRPCPort = 19999
	gCfg.ProxyListenPort = 8899
	gCfg.PodSubnet = "10.2.56.1/21"
	gCfg.NodeSubnet = "1.100.201.0/24"
	gCfg.AciPolicyTenant = testTenant
	gCfg.AciVmmDomain = "testDom"
	gCfg.AciVrf = "defaultVrf"

	s, err := StartNewServer(gCfg, ts.sd, etcdClientURLs)
	if err != nil {
		t.Fatalf("Starting api server: %v", err)
	}

	return s
}

func TestBasic(t *testing.T) {
	var apicCert []byte
	var apicKey []byte

	suite := &testSuite{}
	s := suite.setupGBPServer(t)
	defer s.Stop()
	defer suite.tearDown()
	logger := log.New()
	logger.Level = log.DebugLevel

	conn, err := apicapi.New(logger, []string{"127.0.0.1:8899"},
		"admin", "noir0123", apicKey, apicCert, testTenant, 60, 5)
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

	cli, err := getClient(apicCert)
	if err != nil {
		log.Info(err)
		t.Fail()
	}

	url1 := fmt.Sprintf("https://127.0.0.1:8899/api/mo/%s.json", dn1)
	url2 := "https://127.0.0.1:8899/api/node/mo/uni/userext/user-demo.json"

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
	addContract(t, nil)
	addEPGs(t, nil)
	addEPs(t, nil)
	verifyRest(t, cli)
	close(stopCh)
	DoAll()
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

func addContract(t *testing.T, srv *Server) {

	rule := v1.WLRule{
		Protocol: "tcp",
		Ports: v1.IntRange{
			Start: 6443,
			End:   6443,
		},
	}

	c := &Contract{
		Name:   "kubeAPI",
		Tenant: testTenant,
		AllowList: []v1.WLRule{
			rule,
		},
	}

	if srv != nil {
		srv.AddContract(*c)
	} else {
		err := c.Make()
		if err != nil {
			log.Errorf("Contract make - %v", err)
			t.FailNow()
		}
	}

	emptyRule := v1.WLRule{}
	emptyC := &Contract{
		Name:   "any",
		Tenant: testTenant,
		AllowList: []v1.WLRule{
			emptyRule,
		},
	}
	err := emptyC.Make()
	if err != nil {
		log.Errorf("Contract make - %v", err)
		t.FailNow()
	}
}

func addEPGs(t *testing.T, srv *Server) {
	epgList := []*EPG{
		{
			Name:   "epgA",
			Tenant: testTenant,
			ProvContracts: []string{
				"kubeAPI",
			},
		},

		{
			Name:   "epgB",
			Tenant: testTenant,
			ConsContracts: []string{
				"kubeAPI",
			},
		},

		{
			Name:   "epgC",
			Tenant: testTenant,
			ConsContracts: []string{
				"kubeAPI",
			},
			ProvContracts: []string{
				"kubeAPI",
			},
		},

		{
			Name:          "kubernetes-kube-system",
			Tenant:        testTenant,
			ConsContracts: []string{},
			ProvContracts: []string{},
		},

		{
			Name:          "kubernetes-kube-default",
			Tenant:        testTenant,
			ConsContracts: []string{},
			ProvContracts: []string{},
		},
	}

	for _, e := range epgList {
		if srv != nil {
			srv.AddEPG(*e)
		} else {
			err := e.Make()
			if err != nil {
				log.Errorf("%s make - %v", e.Name, err)
				t.FailNow()
			}
		}
	}
}

func addEPs(t *testing.T, srv *Server) {
	epList := []Endpoint{
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
		ep.IPAddr = []string{fmt.Sprintf("10.2.52.%d", ix)}
		if srv != nil {
			srv.AddEP(ep)
		} else {
			_, err := ep.Add()
			if err != nil {
				log.Errorf("ep make - %v", err)
				t.FailNow()
			}
		}

	}

	extEPList := []Endpoint{
		{EPG: "epgD", Uuid: "extNet1", IPAddr: []string{"33.33.0.0/16"}},
		{EPG: "epgE", Uuid: "extNets2", IPAddr: []string{"34.1.1.0/24", "34.1.2.1/32", "35.1.1.1/32"}},
	}
	for _, ep := range extEPList {
		if srv != nil {
			srv.AddEP(ep)
		} else {
			_, err := ep.Add()
			if err != nil {
				log.Errorf("ep make - %v", err)
				t.FailNow()
			}
		}
	}
}

func verifyRest(t *testing.T, c *http.Client) {
	// Contract
	emptyRule := v1.WLRule{}
	testContract := &Contract{
		Name:      "all-ALL",
		Tenant:    testTenant,
		AllowList: []v1.WLRule{emptyRule},
	}
	testEpg := &EPG{
		Tenant:        testTenant,
		Name:          "Roses",
		ConsContracts: []string{"all-ALL"},
		ProvContracts: []string{"all-ALL"},
	}
	testEP := &Endpoint{
		Uuid:    "testEP-xxx-yyy-zzz",
		MacAddr: "58:ef:68:e2:71:0d",
		IPAddr:  []string{"10.2.50.55"},
		EPG:     "Roses",
		VTEP:    "8.8.8.8",
	}

	testNPjson := []byte("{\"hostprotPol\":{\"attributes\":{\"dn\":\"uni/tn-vk8s_1/pol-vk8s_1_node_vk8s-node1\",\"name\":\"vk8s_1_node_vk8s-node1\"},\"children\":[{\"hostprotSubj\":{\"attributes\":{\"dn\":\"uni/tn-vk8s_1/pol-vk8s_1_node_vk8s-node1/subj-local-node\",\"name\":\"local-node\"},\"children\":[{\"hostprotRule\":{\"attributes\":{\"connTrack\":\"normal\",\"direction\":\"egress\",\"dn\":\"uni/tn-vk8s_1/pol-vk8s_1_node_vk8s-node1/subj-local-node/rule-allow-all-egress\",\"ethertype\":\"ipv4\",\"fromPort\":\"unspecified\",\"name\":\"allow-all-egress\",\"protocol\":\"unspecified\",\"toPort\":\"unspecified\"},\"children\":[{\"hostprotRemoteIp\":{\"attributes\":{\"addr\":\"1.100.201.12\",\"dn\":\"uni/tn-vk8s_1/pol-vk8s_1_node_vk8s-node1/subj-local-node/rule-allow-all-egress/ip-[1.100.201.12]\"},\"children\":[{\"tagInst\":{\"attributes\":{\"dn\":\"uni/tn-vk8s_1/pol-vk8s_1_node_vk8s-node1/subj-local-node/rule-allow-all-egress/ip-[1.100.201.12]/tag-vk8s_1-523d2f252a0f4b0aeb22f43c11c7a1c2\",\"name\":\"vk8s_1-523d2f252a0f4b0aeb22f43c11c7a1c2\"}}}]}},{\"tagInst\":{\"attributes\":{\"dn\":\"uni/tn-vk8s_1/pol-vk8s_1_node_vk8s-node1/subj-local-node/rule-allow-all-egress/tag-vk8s_1-523d2f252a0f4b0aeb22f43c11c7a1c2\",\"name\":\"vk8s_1-523d2f252a0f4b0aeb22f43c11c7a1c2\"}}}]}},{\"hostprotRule\":{\"attributes\":{\"connTrack\":\"normal\",\"direction\":\"ingress\",\"dn\":\"uni/tn-vk8s_1/pol-vk8s_1_node_vk8s-node1/subj-local-node/rule-allow-all-ingress\",\"ethertype\":\"ipv4\",\"fromPort\":\"unspecified\",\"name\":\"allow-all-ingress\",\"protocol\":\"unspecified\",\"toPort\":\"unspecified\"},\"children\":[{\"hostprotRemoteIp\":{\"attributes\":{\"addr\":\"1.100.201.12\",\"dn\":\"uni/tn-vk8s_1/pol-vk8s_1_node_vk8s-node1/subj-local-node/rule-allow-all-ingress/ip-[1.100.201.12]\"},\"children\":[{\"tagInst\":{\"attributes\":{\"dn\":\"uni/tn-vk8s_1/pol-vk8s_1_node_vk8s-node1/subj-local-node/rule-allow-all-ingress/ip-[1.100.201.12]/tag-vk8s_1-523d2f252a0f4b0aeb22f43c11c7a1c2\",\"name\":\"vk8s_1-523d2f252a0f4b0aeb22f43c11c7a1c2\"}}}]}},{\"tagInst\":{\"attributes\":{\"dn\":\"uni/tn-vk8s_1/pol-vk8s_1_node_vk8s-node1/subj-local-node/rule-allow-all-ingress/tag-vk8s_1-523d2f252a0f4b0aeb22f43c11c7a1c2\",\"name\":\"vk8s_1-523d2f252a0f4b0aeb22f43c11c7a1c2\"}}}]}},{\"tagInst\":{\"attributes\":{\"dn\":\"uni/tn-vk8s_1/pol-vk8s_1_node_vk8s-node1/subj-local-node/tag-vk8s_1-523d2f252a0f4b0aeb22f43c11c7a1c2\",\"name\":\"vk8s_1-523d2f252a0f4b0aeb22f43c11c7a1c2\"}}}]}},{\"tagInst\":{\"attributes\":{\"dn\":\"uni/tn-vk8s_1/pol-vk8s_1_node_vk8s-node1/tag-vk8s_1-523d2f252a0f4b0aeb22f43c11c7a1c2\",\"name\":\"vk8s_1-523d2f252a0f4b0aeb22f43c11c7a1c2\"}}}]}}")

	postList := []struct {
		url string
		obj interface{}
	}{
		{"https://127.0.0.1:8899/gbp/contracts", testContract},
		{"https://127.0.0.1:8899/gbp/epgs", testEpg},
		{"https://127.0.0.1:8899/gbp/endpoints", testEP},
		{fmt.Sprintf("https://127.0.0.1:8899/api/mo/uni/tn-%s/pol-vk8s_1_node_vk8s-node1", testTenant), testNPjson},
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

		var reply PostResp

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

	l := getter("https://127.0.0.1:8899/gbp/epgs/")
	var getList ListResp

	err := json.Unmarshal(l, &getList)
	if err != nil {
		log.Errorf("Marshal get list :% v", err)
		t.FailNow()
	}
	for _, reqUri := range getList.URIs {
		gb := getter(fmt.Sprintf("https://127.0.0.1:8899/gbp/epg/?key=%s", reqUri))
		log.Infof("EPG Get Resp: %s", gb)
	}

	l = getter("https://127.0.0.1:8899/gbp/contracts/")

	err = json.Unmarshal(l, &getList)
	if err != nil {
		log.Errorf("Marshal get list :% v", err)
		t.FailNow()
	}

	log.Infof("contractlist: %+v", getList)
	for _, reqUri := range getList.URIs {
		gb := getter(fmt.Sprintf("https://127.0.0.1:8899/gbp/contract/?key=%s", reqUri))
		log.Infof("Contract Get Resp: %s", gb)
	}

	l = getter("https://127.0.0.1:8899/gbp/endpoints/")

	err = json.Unmarshal(l, &getList)
	if err != nil {
		log.Errorf("Marshal get list :% v", err)
		t.FailNow()
	}

	log.Infof("eplist: %+v", getList)
	for _, reqUri := range getList.URIs {
		gb := getter(fmt.Sprintf("https://127.0.0.1:8899/gbp/endpoint/?key=%s", reqUri))
		log.Infof("Endpoint Get Resp: %s", gb)
	}

	for _, reqUri := range getList.URIs {
		req, _ := http.NewRequest("DELETE", fmt.Sprintf("https://127.0.0.1:8899/gbp/endpoint/?key=%s", reqUri), nil)
		_, err = c.Do(req)
		if err != nil {
			log.Errorf("Delete %s :% v", reqUri, err)
			t.FailNow()
		}
	}

	l = getter("https://127.0.0.1:8899/gbp/endpoints/")

	err = json.Unmarshal(l, &getList)
	if err != nil {
		log.Errorf("Marshal get list :% v", err)
		t.FailNow()
	}

	if len(getList.URIs) != 0 {
		log.Errorf("EPs present: %q", getList.URIs)
		t.FailNow()
	}
	req, _ := http.NewRequest("DELETE", fmt.Sprintf("https://127.0.0.1:8899/api/mo/uni/tn-%s/pol-vk8s_1_node_vk8s-node1", testTenant), nil)
	_, err = c.Do(req)
	if err != nil {
		log.Errorf("Delete :% v", err)
		t.FailNow()
	}
}

func TestAPIC(t *testing.T) {
	t.Skip()
	log1 := log.New()
	log1.Level = log.DebugLevel
	log1.Formatter = &log.TextFormatter{
		DisableColors: true,
	}

	conn, err := apicapi.New(log1, []string{"18.217.5.107:443"}, "admin", "noir0!234", nil, nil, "test", 60, 5)
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

	conn, err := apicapi.New(log1, []string{"18.217.5.107:443"}, "admin", "noir0!234", nil, nil, "test", 60, 5)
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

func TestGRPC(t *testing.T) {
	suite := &testSuite{}
	s := suite.setupGBPServer(t)
	defer s.Stop()
	defer suite.tearDown()
	addContract(t, s)
	addEPGs(t, s)
	addEPs(t, s)

	// setup a connection to grpc server

	conn, err := grpc.Dial("localhost:19999", grpc.WithInsecure())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	listCh := make(chan *GBPOperation)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	listVerify := func(lCh chan *GBPOperation) {
		c := NewGBPClient(conn)

		lc, err := c.ListObjects(ctx, &Version{}, grpc.WaitForReady(true))
		if err != nil {
			t.Fatal(err)
		}

		go func() {
			for {
				gbpOp, err := lc.Recv()
				if err != nil {
					log.Info(err)
					break
				}
				lCh <- gbpOp
			}
		}()

		rcv := <-lCh
		log.Infof("List opcode: %+v, count:% d", rcv.Opcode, len(rcv.ObjectList))
		moMap := make(map[string]*GBPObject)
		for _, o := range rcv.ObjectList {
			moMap[o.Uri] = o
		}

		//testPrintSorted(moMap, "testPolicy.json")
		verifyPolicy(t, moMap)
	}

	listVerify(listCh)

	// inject an update into gbp server
	var contract = Contract{
		Name:      "tcp-6020",
		Tenant:    testTenant,
		AllowList: []v1.WLRule{{Protocol: "tcp", Ports: v1.IntRange{Start: 6020, End: 6020}}},
	}

	s.AddContract(contract)

rcvLoop:
	for {
		select {
		case rcv := <-listCh:
			assert.Equal(t, 8, len(rcv.ObjectList))
			log.Infof("Update opcode: %+v, count:% d", rcv.Opcode, len(rcv.ObjectList))
			break rcvLoop
		case <-ctx.Done():
			t.Error("Update not received")
			break rcvLoop
		}
	}

	// add an epg and verify state update.
	epg := EPG{
		Tenant: testTenant,
		Name:   "newComer",
	}

	s.AddEPG(epg)

	assert.Eventually(t, func() bool {
		state, err := suite.sd.Get()
		assert.Equal(t, err, nil)
		class := state.Status.ClassIDs["/PolicyUniverse/PolicySpace/gbpKubeTenant/GbpEpGroup/newComer/GbpeInstContext/"]
		return class >= uint(32000) && class <= uint(64000)
	}, time.Second, time.Millisecond)

	// delete epg and verify state update
	s.DelEPG(epg)
	assert.Eventually(t, func() bool {
		state, err := suite.sd.Get()
		assert.Equal(t, err, nil)
		_, found := state.Status.ClassIDs["/PolicyUniverse/PolicySpace/gbpKubeTenant/GbpEpGroup/newComer/GbpeInstContext/"]
		return !found
	}, 2*time.Second, time.Millisecond)

	// delete the contract.
	s.DelContract(contract)
	time.Sleep(2 * time.Second)

	newCh := make(chan *GBPOperation)
	listVerify(newCh)
}

func verifyPolicy(t *testing.T, moMap map[string]*GBPObject) {
	data, err := ioutil.ReadFile("./testPolicy.json")
	if err != nil {
		log.Infof("Reading ./testPolicy.json - %v", err)
		t.Fatal(err)
	}

	var moList []*GBPObject
	err = json.Unmarshal(data, &moList)
	if err != nil {
		log.Infof("Decoding ./testPolicy.json %v", err)
		t.Fatal(err)
	}

	assert.Equal(t, len(moList), len(moMap))
	for _, m := range moList {
		n, found := moMap[m.Uri]
		if !found {
			t.Fatal(fmt.Errorf("Object %s not found in received policy", m.Uri))
		}

		if strings.Contains(m.Uri, subjEIC) {
			continue // skip comparison because of randomness ofIDs
		}
		if !reflect.DeepEqual(m, n) {
			log.Infof("%+v  not equal to %+v", m, n)
			t.Fatal(fmt.Errorf("Object %s did not match in received policy", m.Uri))
		}
	}
}

func testPrintSorted(mos map[string]*GBPObject, outFile string) {
	var keys []string

	for k := range mos {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	var sortedMos []*GBPObject
	for _, kk := range keys {
		m, ok := mos[kk]
		if !ok {
			fmt.Printf("ERROR: missing mo %s", kk)
			continue
		}
		sortedMos = append(sortedMos, m)
	}

	policyJson, err := json.MarshalIndent(sortedMos, "", "    ")
	if err != nil {
		fmt.Printf("ERROR: %v", err)
	}
	err = ioutil.WriteFile(outFile, policyJson, 0644)
	if err != nil {
		log.Errorf("%s - %v", outFile, err)
	}
}
