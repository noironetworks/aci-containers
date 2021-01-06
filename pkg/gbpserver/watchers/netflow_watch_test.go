/***
Copyright 2021 Cisco Systems Inc. All rights reserved.

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
	"github.com/noironetworks/aci-containers/pkg/gbpserver"
	netflowpolicy "github.com/noironetworks/aci-containers/pkg/netflowpolicy/apis/aci.netflow/v1alpha"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"reflect"
	"testing"
	"time"
)

var err error

type netflow_suite struct {
	s     *gbpserver.Server
	nf    *NetflowWatcher
	nfgbp *netflowCRD
}

func (s *netflow_suite) setup() {

	gCfg := &gbpserver.GBPServerConfig{}
	gCfg.AciVmmDomain = "test-dom"
	gCfg.WatchLogLevel = "info"
	log := log.WithField("mod", "test")
	s.s = gbpserver.NewServer(gCfg)
	s.nf, err = NewNetflowWatcher(s.s)

	s.nf = &NetflowWatcher{
		log: log,
		gs:  s.s,
	}
}

func (s *netflow_suite) expectMsg(op int, msg interface{}) error {
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

var netflowPolicyType = netflowpolicy.NetflowType{
	DstAddr:           "1.1.1.1",
	DstPort:           2055,
	FlowType:          "netflow",
	ActiveFlowTimeOut: 60,
	IdleFlowTimeOut:   15,
	SamplingRate:      5,
}

var netflowPolicy = netflowpolicy.NetflowPolicySpec{
	FlowSamplingPolicy: netflowPolicyType,
}

var netflowPolicyGBP = &netflowCRD{
	DstAddr:           "1.1.1.1",
	DstPort:           2055,
	FlowType:          "netflow",
	ActiveFlowTimeOut: 60,
	IdleFlowTimeOut:   15,
	SamplingRate:      5,
}

func TestNetflowGBP(t *testing.T) {
	ns := &netflow_suite{}
	ns.setup()

	ns.nf.netflowAdded(&netflowpolicy.NetflowPolicy{Spec: netflowPolicy})
	err := ns.expectMsg(gbpserver.OpaddGBPCustomMo, netflowPolicyGBP)
	if err != nil {
		t.Error(err)
	}

	ns.nf.netflowDeleted(&netflowpolicy.NetflowPolicy{Spec: netflowPolicy})
	err = ns.expectMsg(gbpserver.OpdelGBPCustomMo, netflowPolicyGBP)
	if err != nil {
		t.Error(err)
	}
}

func TestNetflowGBPConfig(t *testing.T) {
	ns := &netflow_suite{}
	ns.setup()

	nfgbp := netflowCRD{
		DstAddr:           "1.1.1.1",
		DstPort:           2055,
		FlowType:          "v5",
		ActiveFlowTimeOut: 60,
		IdleFlowTimeOut:   15,
		SamplingRate:      5,
		Name:              "netflow-policy",
	}
	testData := []struct {
		sub        string
		parenturi  string
		parentSubj string
		uri        string
		children   []string
		properties map[string]interface{}
	}{
		{
			"NetflowExporterConfig",
			"/PolicyUniverse/PlatformConfig/comp%2fprov-Kubernetes%2fctrlr-%5btest-dom%5d-test-dom%2fsw-InsiemeLSOid/",
			"PlatformConfig",
			"/PolicyUniverse/PlatformConfig/comp%2fprov-Kubernetes%2fctrlr-%5btest-dom%5d-test-dom%2fsw-InsiemeLSOid/NetflowExporterConfig/" + nfgbp.Name + "/",
			[]string{},
			map[string]interface{}{
				"dstAddr":           nfgbp.DstAddr,
				"dstPort":           nfgbp.DstPort,
				"version":           nfgbp.FlowType,
				"activeFlowTimeOut": nfgbp.ActiveFlowTimeOut,
				"idleFlowTimeOut":   nfgbp.IdleFlowTimeOut,
				"samplingRate":      nfgbp.SamplingRate,
				"name":              nfgbp.Name,
			}},
	}

	for _, td := range testData {
		sub := nfgbp.Subject()
		assert.Equal(t, td.sub, sub)

		uri := nfgbp.URI(ns.s)
		assert.Equal(t, td.uri, uri)

		parentsub := nfgbp.ParentSub()
		assert.Equal(t, td.parentSubj, parentsub)

		properties := nfgbp.Properties()
		assert.Equal(t, td.properties, properties)

		parenturi := nfgbp.ParentURI(ns.s)
		assert.Equal(t, td.parenturi, parenturi)

		children := nfgbp.Children()
		assert.Equal(t, td.children, children)
	}
}
