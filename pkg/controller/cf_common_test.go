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

package controller

import (
	"database/sql"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"code.cloudfoundry.org/bbs/events/eventfakes"
	"code.cloudfoundry.org/bbs/fake_bbs"
	"code.cloudfoundry.org/bbs/models"
	"code.cloudfoundry.org/lager"
	"github.com/sirupsen/logrus"
	cfclient "github.com/cloudfoundry-community/go-cfclient"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	wq "k8s.io/client-go/util/workqueue"

	apic "github.com/noironetworks/aci-containers/pkg/apicapi"
	"github.com/noironetworks/aci-containers/pkg/cf_common"
	"github.com/noironetworks/aci-containers/pkg/cfapi"
	"github.com/noironetworks/aci-containers/pkg/cfapi/cfapi_fakes"
	"github.com/noironetworks/aci-containers/pkg/ipam"
	rkv "github.com/noironetworks/aci-containers/pkg/keyvalueservice"
	md "github.com/noironetworks/aci-containers/pkg/metadata"
)

func fakeApicConnection(t *testing.T, log *logrus.Logger) *apic.ApicConnection {
	conn, _ := apic.New(log, []string{}, "admin", "", nil, nil, "test", 60, 5)
	assert.NotNil(t, conn)
	return conn
}

func testCfEnvironmentNoMigration(t *testing.T) *CfEnvironment {
	env := CfEnvironment{indexLock: &sync.Mutex{}, appVips: newNetIps()}
	log := logrus.New()
	log.Level = logrus.DebugLevel
	log.Formatter = &logrus.TextFormatter{
		DisableColors: true,
	}
	cont := NewController(NewConfig(), &env, log)
	cont.config.DefaultEg.Name = "default|cf-app-default"
	cont.config.DefaultEg.PolicySpace = "cf"
	cont.config.AciPolicyTenant = "cf"
	cont.config.AciPrefix = "cf"
	cont.config.AciVmmDomainType = "CloudFoundry"
	cont.config.AciVmmDomain = "cf-dom"
	cont.config.AciVmmController = "cf-ctrl"
	cont.configuredPodNetworkIps.V4.AddRange(net.ParseIP("10.10.0.0"), net.ParseIP("10.10.255.255"))
	cont.configuredPodNetworkIps.V6.AddRange(net.ParseIP("::fe00"), net.ParseIP("::feff"))
	cont.nodeServiceIps.V4.AddRange(net.ParseIP("1.0.0.1"), net.ParseIP("1.0.0.24"))
	cont.nodeServiceIps.V6.AddRange(net.ParseIP("a1::"), net.ParseIP("a1::ff"))
	cont.staticServiceIps.V4.AddRange(net.ParseIP("1.2.3.1"), net.ParseIP("1.2.3.20"))
	cont.staticServiceIps.V6.AddRange(net.ParseIP("::2f00"), net.ParseIP("::2fff"))
	cont.serviceIps.LoadRanges([]ipam.IpRange{
		{Start: net.ParseIP("1.2.4.1"), End: net.ParseIP("1.2.4.20")},
		{Start: net.ParseIP("::2e00"), End: net.ParseIP("::2eff")}})
	env.appVips.V4.AddRange(net.ParseIP("10.250.4.1"), net.ParseIP("10.250.4.20"))
	env.appVips.V6.AddRange(net.ParseIP("aa::2e00"), net.ParseIP("aa::2eff"))
	cont.apicConn = fakeApicConnection(t, log)
	env.cont = cont
	env.log = log
	db, err := sql.Open("sqlite3", ":memory:")
	db.SetMaxOpenConns(1) // workaround for sqlite3 memory-only DB
	assert.Nil(t, err)
	env.db = db
	env.cfconfig = &CfConfig{}
	env.cfconfig.ApiPathPrefix = "/networking-aci"
	env.cfconfig.DefaultAppProfile = "auto"
	env.cfconfig.AppPort = 8080
	env.cfconfig.SshPort = 2222
	env.cfconfig.CfNetIntfAddress = "169.254.169.254"
	env.ccClient = &cfapi_fakes.FakeCcClient{}
	env.cfAuthClient = &cfapi_fakes.FakeCfAuthClient{}
	env.bbsClient = new(fake_bbs.FakeClient)
	env.netpolClient = &cfapi_fakes.FakePolicyClient{}
	env.cfLogger = lager.NewLogger("CfEnv")

	env.kvmgr = rkv.NewKvManager()
	env.initIndexes()
	env.setupIndexes()
	env.setupCcClientFakes()
	return &env
}

func testCfEnvironment(t *testing.T) *CfEnvironment {
	env := testCfEnvironmentNoMigration(t)
	err := env.RunDbMigration()
	assert.Nil(t, err)
	return env
}

func (e *CfEnvironment) fakeCcClient() *cfapi_fakes.FakeCcClient {
	return e.ccClient.(*cfapi_fakes.FakeCcClient)
}

func (e *CfEnvironment) fakeCfAuthClient() *cfapi_fakes.FakeCfAuthClient {
	return e.cfAuthClient.(*cfapi_fakes.FakeCfAuthClient)
}

func (e *CfEnvironment) fakePolicyClient() *cfapi_fakes.FakePolicyClient {
	return e.netpolClient.(*cfapi_fakes.FakePolicyClient)
}

func (e *CfEnvironment) fakeBbsClient() *fake_bbs.FakeClient {
	return e.bbsClient.(*fake_bbs.FakeClient)
}

func (e *CfEnvironment) setBbsFakeEventSource(ch chan models.Event) {
	fake_bbs_client := e.fakeBbsClient()
	fake_bbs_es := new(eventfakes.FakeEventSource)
	fake_bbs_es.NextStub = func() (models.Event, error) {
		ev, ok := <-ch
		if !ok {
			return nil, fmt.Errorf("BBS event channel closed")
		}
		return ev, nil
	}
	fake_bbs_es.CloseStub = func() error {
		close(ch)
		return nil
	}
	fake_bbs_client.SubscribeToEventsReturns(fake_bbs_es, nil)
	fake_bbs_client.SubscribeToTaskEventsReturns(fake_bbs_es, nil)
}

func (e *CfEnvironment) setupIndexes() {
	e.contIdx["c-1"] = &ContainerInfo{ContainerId: "c-1", CellId: "cell-1", IpAddress: "1.2.3.4", AppId: "app-1"}
	e.contIdx["c-1"].Ports = []*models.PortMapping{
		{ContainerPort: 8080, HostPort: 22},
		{ContainerPort: 2222, HostPort: 23}}
	e.contIdx["c-2"] = &ContainerInfo{ContainerId: "c-2", CellId: "cell-1", IpAddress: "1.2.3.5", AppId: "app-1"}
	e.contIdx["c-3"] = &ContainerInfo{ContainerId: "c-3", CellId: "cell-1", IpAddress: "1.2.3.6", AppId: "app-2"}
	e.contIdx["c-4"] = &ContainerInfo{ContainerId: "c-4", CellId: "cell-1", IpAddress: "1.2.3.7", AppId: "app-3"}

	e.appIdx["app-1"] = &AppInfo{AppId: "app-1", SpaceId: "space-1", AppName: "app-1-name",
		ContainerIps: map[string]string{
			"c-1": "1.2.3.4",
			"c-2": "1.2.3.5",
		},
		VipV4: "10.250.4.1", VipV6: "aa::2e00",
		ExternalIp: []string{"150.150.0.3", "aaaa::bbbb"},
	}
	e.appIdx["app-2"] = &AppInfo{AppId: "app-2", SpaceId: "space-1", AppName: "app-2-name",
		ContainerIps: map[string]string{"c-3": "1.2.3.6"},
	}
	e.appIdx["app-3"] = &AppInfo{AppId: "app-3", SpaceId: "space-2", AppName: "app-3-name",
		ContainerIps: map[string]string{"c-4": "1.2.3.7"},
	}
	e.spaceIdx["space-1"] = &SpaceInfo{SpaceId: "space-1", OrgId: "org-1",
		SpaceName:             "SPACE1",
		RunningSecurityGroups: []string{"ASG_R1", "ASG_PUB"},
		StagingSecurityGroups: []string{"ASG_S1", "ASG_PUB"}}
	e.spaceIdx["space-2"] = &SpaceInfo{SpaceId: "space-2", OrgId: "org-1",
		SpaceName: "SPACE2"}

	e.orgIdx["org-1"] = &OrgInfo{OrgId: "org-1", OrgName: "ORG1"}

	e.netpolIdx["app-1"] = nil
	e.netpolIdx["app-101"] = map[string][]cfapi.Destination{
		"app-1": {
			{Protocol: "tcp", Ports: cfapi.Ports{Start: 10, End: 20}}},
		"app-2": nil}
	e.netpolIdx["app-102"] = map[string][]cfapi.Destination{
		"app-1": {
			{Protocol: "udp", Ports: cfapi.Ports{Start: 20, End: 30}}},
		"app-2": nil}

	e.isoSegIdx["is1"] = &IsoSegInfo{Id: "is1", Name: "isolate1"}

	e.asgIdx["ASG_PUB"] = &cfclient.SecGroup{Guid: "ASG_PUB",
		Rules: []cfclient.SecGroupRule{
			{Protocol: "tcp",
				Ports:       "50,100-200",
				Destination: "100.100.100.1-100.100.100.8, 100.100.200.0/24"},
			{Protocol: "tcp", Ports: "1000, 1200, 5000"}}}
	e.asgIdx["ASG_R1"] = &cfclient.SecGroup{Guid: "ASG_R1",
		Rules: []cfclient.SecGroupRule{
			{Protocol: "udp",
				Destination: "101.101.101.101", Log: true},
			{Protocol: "all",
				Destination: "201.201.201.201"}}}
	e.asgIdx["ASG_S1"] = &cfclient.SecGroup{Guid: "ASG_S1",
		Rules: []cfclient.SecGroupRule{
			{Protocol: "icmp", Destination: "201.201.202.202",
				Code: 10, Type: 12},
			{Protocol: "arp"}}}

	cont := e.cont
	for i := 0; i < 4; i++ {
		num := fmt.Sprintf("%d", i)
		cell := "diego-cell-cell-" + num
		cont.nodeServiceMetaCache[cell] = &nodeServiceMeta{
			serviceEp: md.ServiceEndpoint{Mac: "99:99:99:88:88:8" + num, Ipv4: net.ParseIP("1.0.0." + num)}}
		odev := apic.EmptyApicObject("opflexDev", "odev-"+num)
		odev.SetAttr("fabricPathDn", "topo/node-101/port-[eth1/33]_"+num)
		cont.nodeOpflexDevice["diego-cell-cell-1"] = apic.ApicSlice{odev}
	}
}

func (e *CfEnvironment) setupCcClientFakes() {
	admin_token := cfapi.TokenInfo{Scope: []string{"network.admin"},
		UserId:   "admin",
		UserName: "admin"}
	auth := e.fakeCfAuthClient()
	auth.On("FetchTokenInfo", "testtoken").Return(&admin_token, nil)

	cc := e.fakeCcClient()
	cc.On("GetAppSpace", "app-1").Return("space-1", nil)
	cc.On("GetAppSpace", "app-2").Return("space-1", nil)
	cc.On("GetAppSpace", "app-3").Return("space-2", nil)
}

func (e *CfEnvironment) GetKvEpInfo(cell, cont string) *cf_common.EpInfo {
	v, err := e.kvmgr.Get("cell/"+cell, "ct/"+cont)
	if err == nil {
		return v.Value.(*cf_common.EpInfo)
	}
	return nil
}

func (e *CfEnvironment) GetKvAppInfo(appId string) *cf_common.AppInfo {
	v, err := e.kvmgr.Get("apps", appId)
	if err == nil {
		return v.Value.(*cf_common.AppInfo)
	}
	return nil
}

func strip_tag(obj apic.ApicObject) {
	// remove 'tagInst'/'tagAnnotation' children recursively
	for _, body := range obj {
		newChildren := apic.ApicSlice{}
		if body.Attributes != nil {
			delete(body.Attributes, "annotation")
		}
		for _, c := range body.Children {
			tag := false
			for class := range c {
				if class == "tagInst" || class == "tagAnnotation" {
					tag = true
				}
				break
			}
			if tag == false {
				strip_tag(c)
				newChildren = append(newChildren, c)
			}
		}
		body.Children = newChildren
		break
	}
}

func (e *CfEnvironment) checkApicDesiredState(t *testing.T, key string,
	expected apic.ApicObject) {
	actual := e.cont.apicConn.GetDesiredState(key)
	if expected == nil {
		assert.Nil(t, actual)
	} else {
		assert.Equal(t, 1, len(actual))
		strip_tag(actual[0])
		assert.Equal(t, expected.String(), actual[0].String())
	}
}

func txn(db *sql.DB, f func(txn *sql.Tx)) {
	txn, _ := db.Begin()
	defer txn.Commit()
	f(txn)
}

func waitForGetList(t *testing.T, q wq.RateLimitingInterface, timeout time.Duration, items []interface{}) {
	ch := make(chan struct{})
	var objs []interface{}
	go func() {
		for {
			obj, quit := q.Get()
			if quit {
				assert.False(t, quit, "WaitForGet - Unexpected queue shutdown")
				return
			}
			objs = append(objs, obj)
			q.Forget(obj)
			q.Done(obj)
			if len(objs) == len(items) {
				close(ch)
				return
			}
		}
	}()
	select {
	case <-time.After(timeout):
		assert.False(t, true, fmt.Sprintf("WaitForGet timed-out for items: %+v", items))
	case <-ch:
		for i := range items {
			assert.Contains(t, objs, items[i])
		}
	}
}

func waitForGet(t *testing.T, q wq.RateLimitingInterface, timeout time.Duration, item interface{}) {
	waitForGetList(t, q, timeout, []interface{}{item})
}

func getExpectedEpInfo() *cf_common.EpInfo {
	ep := &cf_common.EpInfo{
		AppId:         "app-1",
		AppName:       "app-1-name",
		SpaceId:       "space-1",
		OrgId:         "org-1",
		IpAddress:     "1.2.3.4",
		InstanceIndex: 0,
		PortMapping: []cf_common.PortMap{
			{ContainerPort: 8080, HostPort: 22},
			{ContainerPort: 2222, HostPort: 23}},
		EpgTenant: "cf",
		Epg:       "default|cf-app-default",
		SecurityGroups: []cf_common.GroupInfo{
			{Tenant: "cf", Group: "cf_hpp_static"},
			{Tenant: "cf", Group: "cf_hpp_cf-components"},
			{Tenant: "cf", Group: "cf_asg_ASG_R1"},
			{Tenant: "cf", Group: "cf_asg_ASG_PUB"},
			{Tenant: "cf", Group: "cf_np_app-1"},
			{Tenant: "cf", Group: "cf_hpp_app-ext-ip"}},
	}
	return ep
}

func getExpectedAppInfo() *cf_common.AppInfo {
	app := &cf_common.AppInfo{
		ContainerIps: []string{"1.2.3.4", "1.2.3.5"},
		VirtualIp:    []string{"10.250.4.1", "aa::2e00"},
		ExternalIp:   []string{"150.150.0.3", "aaaa::bbbb"},
	}
	return app
}

func getExpectedApicHppForAsg() (m map[string]apic.ApicObject) {
	m = make(map[string]apic.ApicObject)

	exp_hpp_pub := apic.NewHostprotPol("cf", "cf_asg_ASG_PUB")
	m["ASG_PUB"] = exp_hpp_pub
	{
		exp_hpp_pub.SetAttr("nameAlias", "asg_")
		exp_hpp_pub_subj := apic.NewHostprotSubj(exp_hpp_pub.GetDn(), "egress")
		exp_hpp_pub.AddChild(exp_hpp_pub_subj)
		rule0_remotes := []string{"100.100.100.1/32", "100.100.100.2/31",
			"100.100.100.4/30", "100.100.100.8/32", "100.100.200.0/24"}
		{
			exp_hpp_pub_rule0_0 := apic.NewHostprotRule(exp_hpp_pub_subj.GetDn(),
				"rule0_0")
			exp_hpp_pub_subj.AddChild(exp_hpp_pub_rule0_0)
			exp_hpp_pub_rule0_0.SetAttr("direction", "egress")
			exp_hpp_pub_rule0_0.SetAttr("ethertype", "ipv4")
			exp_hpp_pub_rule0_0.SetAttr("protocol", "tcp")
			exp_hpp_pub_rule0_0.SetAttr("fromPort", "50")
			exp_hpp_pub_rule0_0.SetAttr("toPort", "50")
			for _, h := range rule0_remotes {
				exp_hpp_pub_rule0_0.AddChild(
					apic.NewHostprotRemoteIp(exp_hpp_pub_rule0_0.GetDn(), h))
			}
		}
		{
			exp_hpp_pub_rule0_1 := apic.NewHostprotRule(exp_hpp_pub_subj.GetDn(),
				"rule0_1")
			exp_hpp_pub_subj.AddChild(exp_hpp_pub_rule0_1)
			exp_hpp_pub_rule0_1.SetAttr("direction", "egress")
			exp_hpp_pub_rule0_1.SetAttr("ethertype", "ipv4")
			exp_hpp_pub_rule0_1.SetAttr("protocol", "tcp")
			exp_hpp_pub_rule0_1.SetAttr("fromPort", "100")
			exp_hpp_pub_rule0_1.SetAttr("toPort", "200")
			for _, h := range rule0_remotes {
				exp_hpp_pub_rule0_1.AddChild(
					apic.NewHostprotRemoteIp(exp_hpp_pub_rule0_1.GetDn(), h))
			}
		}
		{
			exp_hpp_pub_rule1_0 := apic.NewHostprotRule(exp_hpp_pub_subj.GetDn(),
				"rule1_0")
			exp_hpp_pub_subj.AddChild(exp_hpp_pub_rule1_0)
			exp_hpp_pub_rule1_0.SetAttr("direction", "egress")
			exp_hpp_pub_rule1_0.SetAttr("ethertype", "ipv4")
			exp_hpp_pub_rule1_0.SetAttr("protocol", "tcp")
			exp_hpp_pub_rule1_0.SetAttr("fromPort", "1000")
			exp_hpp_pub_rule1_0.SetAttr("toPort", "1000")
			exp_hpp_pub_rule1_0.AddChild(
				apic.NewHostprotRemoteIp(exp_hpp_pub_rule1_0.GetDn(),
					"0.0.0.0/0"))
		}
		{
			exp_hpp_pub_rule1_1 := apic.NewHostprotRule(exp_hpp_pub_subj.GetDn(),
				"rule1_1")
			exp_hpp_pub_subj.AddChild(exp_hpp_pub_rule1_1)
			exp_hpp_pub_rule1_1.SetAttr("direction", "egress")
			exp_hpp_pub_rule1_1.SetAttr("ethertype", "ipv4")
			exp_hpp_pub_rule1_1.SetAttr("protocol", "tcp")
			exp_hpp_pub_rule1_1.SetAttr("fromPort", "1200")
			exp_hpp_pub_rule1_1.SetAttr("toPort", "1200")
			exp_hpp_pub_rule1_1.AddChild(
				apic.NewHostprotRemoteIp(exp_hpp_pub_rule1_1.GetDn(),
					"0.0.0.0/0"))
		}
		{
			exp_hpp_pub_rule1_2 := apic.NewHostprotRule(exp_hpp_pub_subj.GetDn(),
				"rule1_2")
			exp_hpp_pub_subj.AddChild(exp_hpp_pub_rule1_2)
			exp_hpp_pub_rule1_2.SetAttr("direction", "egress")
			exp_hpp_pub_rule1_2.SetAttr("ethertype", "ipv4")
			exp_hpp_pub_rule1_2.SetAttr("protocol", "tcp")
			exp_hpp_pub_rule1_2.SetAttr("fromPort", "5000")
			exp_hpp_pub_rule1_2.SetAttr("toPort", "5000")
			exp_hpp_pub_rule1_2.AddChild(
				apic.NewHostprotRemoteIp(exp_hpp_pub_rule1_2.GetDn(),
					"0.0.0.0/0"))
		}
	}

	exp_hpp_r1 := apic.NewHostprotPol("cf", "cf_asg_ASG_R1")
	m["ASG_R1"] = exp_hpp_r1
	{
		exp_hpp_r1.SetAttr("nameAlias", "asg_")
		exp_hpp_r1_subj := apic.NewHostprotSubj(exp_hpp_r1.GetDn(), "egress")
		exp_hpp_r1.AddChild(exp_hpp_r1_subj)
		exp_hpp_r1_rule0 := apic.NewHostprotRule(exp_hpp_r1_subj.GetDn(),
			"rule0_0")
		exp_hpp_r1_subj.AddChild(exp_hpp_r1_rule0)
		exp_hpp_r1_rule0.SetAttr("direction", "egress")
		exp_hpp_r1_rule0.SetAttr("ethertype", "ipv4")
		exp_hpp_r1_rule0.SetAttr("protocol", "udp")
		exp_hpp_r1_rule0.SetAttr("fromPort", "unspecified")
		exp_hpp_r1_rule0.SetAttr("toPort", "unspecified")
		exp_hpp_r1_rule0.AddChild(
			apic.NewHostprotRemoteIp(exp_hpp_r1_rule0.GetDn(),
				"101.101.101.101/32"))
		exp_hpp_r1_rule1 := apic.NewHostprotRule(exp_hpp_r1_subj.GetDn(),
			"rule1_0")
		exp_hpp_r1_subj.AddChild(exp_hpp_r1_rule1)
		exp_hpp_r1_rule1.SetAttr("direction", "egress")
		exp_hpp_r1_rule1.SetAttr("ethertype", "ipv4")
		exp_hpp_r1_rule1.SetAttr("protocol", "unspecified")
		exp_hpp_r1_rule1.SetAttr("fromPort", "unspecified")
		exp_hpp_r1_rule1.SetAttr("toPort", "unspecified")
		exp_hpp_r1_rule1.AddChild(
			apic.NewHostprotRemoteIp(exp_hpp_r1_rule1.GetDn(),
				"201.201.201.201/32"))
	}

	exp_hpp_s1 := apic.NewHostprotPol("cf", "cf_asg_ASG_S1")
	m["ASG_S1"] = exp_hpp_s1
	{
		exp_hpp_s1.SetAttr("nameAlias", "asg_")
		exp_hpp_s1_subj := apic.NewHostprotSubj(exp_hpp_s1.GetDn(), "egress")
		exp_hpp_s1.AddChild(exp_hpp_s1_subj)
		exp_hpp_s1_rule0 := apic.NewHostprotRule(exp_hpp_s1_subj.GetDn(),
			"rule0_0")
		exp_hpp_s1_subj.AddChild(exp_hpp_s1_rule0)
		exp_hpp_s1_rule0.SetAttr("direction", "egress")
		exp_hpp_s1_rule0.SetAttr("ethertype", "ipv4")
		exp_hpp_s1_rule0.SetAttr("protocol", "icmp")
		exp_hpp_s1_rule0.SetAttr("fromPort", "unspecified")
		exp_hpp_s1_rule0.SetAttr("toPort", "unspecified")
		exp_hpp_s1_rule0.SetAttr("icmpType", "12")
		exp_hpp_s1_rule0.SetAttr("icmpCode", "10")
		exp_hpp_s1_rule0.AddChild(
			apic.NewHostprotRemoteIp(exp_hpp_s1_rule0.GetDn(),
				"201.201.202.202/32"))
	}

	return
}
