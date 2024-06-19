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
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"

	"github.com/noironetworks/aci-containers/pkg/gbpcrd/apis/acipolicy/v1"
)

const (
	testTenant = "gbpKubeTenant"
)

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
	dataDir string
	sd      *testSD
}

func (ts *testSuite) tearDown() {
	os.RemoveAll(ts.dataDir)
}

func (ts *testSuite) setupGBPServer(t *testing.T) *Server {
	dataDir, err := os.MkdirTemp("", "_gbpdata")
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

	s, err := StartNewServer(gCfg, ts.sd)
	if err != nil {
		t.Fatalf("Starting api server: %v", err)
	}

	return s
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

	for ix := range epList {
		epList[ix].Uuid = fmt.Sprintf("2d62c0ca-049d-11e9-9d5e-005056986463_4646341552ed73d23d688a8578ed51236610a0dec385418%d_veth10%d", ix, ix)
		epList[ix].MacAddr = fmt.Sprintf("ca:17:aa:10:aa:%d%d", ix, ix)
		epList[ix].IPAddr = []string{fmt.Sprintf("10.2.52.%d", ix)}
		if srv != nil {
			srv.AddEP(epList[ix])
		} else {
			_, err := epList[ix].Add()
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
	for ix := range extEPList {
		if srv != nil {
			srv.AddEP(extEPList[ix])
		} else {
			_, err := extEPList[ix].Add()
			if err != nil {
				log.Errorf("ep make - %v", err)
				t.FailNow()
			}
		}
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

	c := NewGBPClient(conn)

	vl, err := c.ListVTEPs(ctx, &EmptyMsg{}, grpc.WaitForReady(true))
	if err != nil {
		t.Fatal(err)
	}

	expVTEPs := map[string]bool{
		"101.10.1.1": true,
		"101.10.1.2": true,
		"101.10.1.3": true,
		"":           true,
	}
	for _, vtep := range vl.Vteps {
		assert.True(t, expVTEPs[vtep], fmt.Sprintf("unexpected %s in vtep list", vtep))
		delete(expVTEPs, vtep)
	}

	assert.Zero(t, len(expVTEPs), "Some vteps not listed")

	snap, err := c.GetSnapShot(ctx, &VTEP{Vtep: "none"}, grpc.WaitForReady(true))
	if err != nil {
		t.Fatal(err)
	}
	moMap := make(map[string]*GBPObject)
	for _, mo := range snap.MoList {
		moMap[mo.Uri] = mo
	}
	verifyPolicy(t, moMap)
}

func verifyPolicy(t *testing.T, moMap map[string]*GBPObject) {
	data, err := os.ReadFile("./testPolicy.json")
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

	// we explicitly remove topRoot from map returned to clients
	assert.Equal(t, len(moList)-1, len(moMap))
	for _, m := range moList {
		if len(m.Uri) <= 1 {
			// skip topRoot
			continue
		}
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
