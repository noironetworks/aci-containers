/***
Copyright 2019 Cisco Systems Inc. All rights reserved.

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

package watchers

import (
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"github.com/noironetworks/aci-containers/pkg/gbpcrd/apis/acipolicy/v1"
	"github.com/noironetworks/aci-containers/pkg/gbpserver"
	"github.com/sirupsen/logrus"
	"reflect"
	"testing"
	"time"
)

type k8s_suite struct {
	s  *gbpserver.Server
	kw *K8sWatcher
}

func (s *k8s_suite) setup() {
	gCfg := &gbpserver.GBPServerConfig{}
	gCfg.GRPCPort = 19999
	gCfg.ProxyListenPort = 8899
	gCfg.PodSubnet = "10.2.56.1/21"
	gCfg.NodeSubnet = "1.100.201.0/24"
	gCfg.AciPolicyTenant = "defaultTenant"
	log := logrus.WithField("mod", "test")
	s.s = gbpserver.NewServer(gCfg)

	s.kw = &K8sWatcher{
		log: log,
		gs:  s.s,
		idb: newIntentDB(s.s, log),
	}
}

func (s *k8s_suite) expectMsg(op int, msg interface{}) error {
	gotOp, gotMsg, err := s.s.UTReadMsg(200 * time.Millisecond)
	if err != nil {
		return err
	}

	if gotOp != op {
		return fmt.Errorf("Exp op: %d, got: %d", op, gotOp)
	}

	if !reflect.DeepEqual(msg, gotMsg) {
		spew.Dump(msg)
		spew.Dump(gotMsg)
		return fmt.Errorf("msgs don't match")
	}

	return nil
}

func (s *k8s_suite) expectOp(op int) error {
	gotOp, _, err := s.s.UTReadMsg(200 * time.Millisecond)
	if err != nil {
		return err
	}

	if gotOp != op {
		return fmt.Errorf("Exp op: %d, got: %d", op, gotOp)
	}

	return nil
}

var k8s_epgA = v1.EpgSpec{
	Name:          "epg-a",
	ProvContracts: []string{"tcp-6020"},
	ConsContracts: []string{"tcp-6020"},
}
var k8s_epgA_trim = v1.EpgSpec{
	Name:          "epg-a",
	ProvContracts: []string{"tcp-6020"},
}

var k8s_contract = v1.ContractSpec{
	Name:      "tcp-6020",
	AllowList: []v1.WLRule{{Protocol: "tcp", Ports: v1.IntRange{Start: 6020, End: 6020}}},
}
var k8s_gbp_epgA = &gbpserver.EPG{
	Tenant:        "defaultTenant",
	Name:          "epg-a",
	ConsContracts: []string{"defaultTenant/tcp-6020"},
	ProvContracts: []string{"defaultTenant/tcp-6020"},
}

var k8s_gbp_epgA_trim = &gbpserver.EPG{
	Tenant:        "defaultTenant",
	Name:          "epg-a",
	ProvContracts: []string{"defaultTenant/tcp-6020"},
}

func TestK8sEPG(t *testing.T) {
	ts := &k8s_suite{}
	ts.setup()
	ts.kw.epgAdded(&v1.Epg{Spec: k8s_epgA})
	err := ts.expectMsg(gbpserver.OpaddEPG, k8s_gbp_epgA)
	if err != nil {
		t.Error(err)
	}

	// make an update and verify
	ts.kw.epgAdded(&v1.Epg{Spec: k8s_epgA_trim})
	err = ts.expectMsg(gbpserver.OpaddEPG, k8s_gbp_epgA_trim)
	if err != nil {
		t.Error(err)
	}

	// inject a contract
	ts.kw.contractAdded(&v1.Contract{Spec: k8s_contract})
	err = ts.expectOp(gbpserver.OpaddContract)
	if err != nil {
		t.Error(err)
	}

	err = ts.expectMsg(gbpserver.OpaddEPG, k8s_gbp_epgA_trim)
	if err != nil {
		t.Error(err)
	}
}
