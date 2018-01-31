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
	"net"
	"testing"
	"time"

	"code.cloudfoundry.org/bbs/models"
	cfclient "github.com/cloudfoundry-community/go-cfclient"
	"github.com/stretchr/testify/assert"

	"github.com/noironetworks/aci-containers/pkg/apicapi"
	"github.com/noironetworks/aci-containers/pkg/cfapi"
	"github.com/noironetworks/aci-containers/pkg/ipam"
)

func TestCfSpaceFetchQueueHandler(t *testing.T) {
	env := testCfEnvironment(t)
	cc := env.fakeCcClient()

	sp := cfclient.Space{Guid: "space-2", Name: "SPACE2", OrganizationGuid: "org-1"}
	cc.On("GetSpaceByGuid", "space-2").Return(sp, nil)
	cc.On("GetSpaceIsolationSegment", "space-2").Return("", nil).Once()
	cc.On("GetOrgDefaultIsolationSegment", "org-1").Return("iso-org-1", nil)

	org := cfclient.Org{Guid: "org-1", Name: "ORG1-NAME"}
	cc.On("GetOrgByGuid", "org-1").Return(org, nil)

	is_space_2 := &cfclient.IsolationSegment{GUID: "iso-space-2", Name: "space-private"}
	is_org_1 := &cfclient.IsolationSegment{GUID: "iso-org-1", Name: "org-private"}
	cc.On("GetIsolationSegmentByGUID", "iso-space-2").Return(is_space_2, nil)
	cc.On("GetIsolationSegmentByGUID", "iso-org-1").Return(is_org_1, nil)

	asg_stage := cfclient.SecGroup{Guid: "stagesg"}
	asg_run := cfclient.SecGroup{Guid: "runsg"}
	asg_s1 := cfclient.SecGroup{Guid: "ASG_S1"}
	asg_r1 := cfclient.SecGroup{Guid: "ASG_R1"}
	cc.On("ListSecGroupsBySpace", "space-2", true).Return(
		[]cfclient.SecGroup{asg_stage, asg_s1}, nil)
	cc.On("ListSecGroupsBySpace", "space-2", false).Return(
		[]cfclient.SecGroup{asg_run, asg_r1}, nil)

	delete(env.spaceIdx, "space-2")
	env.spaceFetchQueueHandler("space-2")
	exp_sp2 := &SpaceInfo{SpaceId: "space-2", OrgId: "org-1",
		SpaceName:             "SPACE2",
		RunningSecurityGroups: []string{"runsg", "ASG_R1"},
		StagingSecurityGroups: []string{"stagesg", "ASG_S1"},
		IsolationSegment:      "iso-org-1"}
	assert.Equal(t, exp_sp2, env.spaceIdx["space-2"])
	assert.Equal(t,
		&IsoSegInfo{Id: "iso-org-1", Name: "org-private"}, env.isoSegIdx["iso-org-1"])
	assert.Equal(t, &asg_stage, env.asgIdx["stagesg"])
	assert.Equal(t, &asg_run, env.asgIdx["runsg"])
	assert.Equal(t, &asg_s1, env.asgIdx["ASG_S1"])
	assert.Equal(t, &asg_r1, env.asgIdx["ASG_R1"])
	waitForGet(t, env.containerUpdateQ, 500*time.Millisecond, "c-4")
	waitForGet(t, env.asgUpdateQ, 500*time.Millisecond, "runsg")
	waitForGet(t, env.asgUpdateQ, 500*time.Millisecond, "ASG_R1")
	waitForGet(t, env.asgUpdateQ, 500*time.Millisecond, "stagesg")
	waitForGet(t, env.asgUpdateQ, 500*time.Millisecond, "ASG_S1")
	waitForGet(t, env.spaceChangesQ, 500*time.Millisecond, "space-2")
	waitForGet(t, env.orgChangesQ, 500*time.Millisecond, "org-1")

	cc.On("GetSpaceIsolationSegment", "space-2").Return("iso-space-2", nil)
	exp_sp2.IsolationSegment = "iso-space-2"
	env.spaceFetchQueueHandler("space-2")
	assert.Equal(t, exp_sp2, env.spaceIdx["space-2"])
	assert.Equal(t,
		&IsoSegInfo{Id: "iso-space-2", Name: "space-private"}, env.isoSegIdx["iso-space-2"])
}

func TestCfManageAppExtIp(t *testing.T) {
	env := testCfEnvironment(t)
	env.cont.staticServiceIps.V4.RemoveIp(net.ParseIP("1.2.3.2"))
	env.cont.staticServiceIps.V4.RemoveIp(net.ParseIP("1.2.3.3"))
	env.cont.staticServiceIps.V6.RemoveIp(net.ParseIP("::2f01"))
	env.cont.staticServiceIps.V6.RemoveIp(net.ParseIP("::2f02"))

	curr := []ExtIpAlloc{{"1.2.3.2", false, ""},
		{"1.2.3.3", false, ""},
		{"::2f01", false, ""},
		{"::2f02", false, ""},
	}

	// allocate static
	req := []ExtIpAlloc{{"1.2.3.3", false, ""},
		{"1.2.3.4", false, ""},
		{"::2f02", false, ""},
		{"::2f03", false, ""},
	}
	res, err := env.ManageAppExtIp(curr, req, false)
	assert.Nil(t, err)
	assert.Equal(t, req, res)
	assert.True(t, env.cont.staticServiceIps.V4.RemoveIp(net.ParseIP("1.2.3.2")))
	assert.True(t, env.cont.staticServiceIps.V6.RemoveIp(net.ParseIP("::2f01")))

	// allocate unavailable IP
	env.cont.staticServiceIps.V4.RemoveIp(net.ParseIP("1.2.3.6"))
	env.cont.staticServiceIps.V6.RemoveIp(net.ParseIP("::2f05"))
	v4copy := ipam.NewFromRanges(env.cont.staticServiceIps.V4.FreeList)
	v6copy := ipam.NewFromRanges(env.cont.staticServiceIps.V6.FreeList)
	req = []ExtIpAlloc{{"1.2.3.5", false, ""}, {"1.2.3.6", false, ""}}
	res1, err := env.ManageAppExtIp(res, req, false)
	assert.NotNil(t, err)
	assert.Nil(t, res1)
	assert.Equal(t, v4copy, env.cont.staticServiceIps.V4)
	assert.Equal(t, v6copy, env.cont.staticServiceIps.V6)

	req = []ExtIpAlloc{{"::2f04", false, ""}, {"::2f05", false, ""}}
	res1, err = env.ManageAppExtIp(res, req, false)
	assert.NotNil(t, err)
	assert.Nil(t, res1)
	assert.Equal(t, v4copy, env.cont.staticServiceIps.V4)
	assert.Equal(t, v6copy, env.cont.staticServiceIps.V6)

	// deallocate static
	req = []ExtIpAlloc{{"1.2.3.3", false, ""}, {"::2f02", false, ""}}
	res1, err = env.ManageAppExtIp(res, req, false)
	assert.Nil(t, err)
	assert.Equal(t, req, res1)
	v4copy.AddIp(net.ParseIP("1.2.3.4"))
	v6copy.AddIp(net.ParseIP("::2f03"))
	assert.Equal(t, v4copy, env.cont.staticServiceIps.V4)
	assert.Equal(t, v6copy, env.cont.staticServiceIps.V6)

	// allocate dynamic
	res, err = env.ManageAppExtIp(res, nil, true)
	assert.Nil(t, err)
	assert.Equal(t, 2, len(res))
	assert.Equal(t, "1.2.4", res[0].IP[0:5])
	assert.Equal(t, "::2e0", res[1].IP[0:5])
	assert.False(t, ipam.HasIp(env.cont.serviceIps.GetV4IpCache()[0], net.ParseIP(res[0].IP)))
	assert.False(t, ipam.HasIp(env.cont.serviceIps.GetV4IpCache()[1], net.ParseIP(res[0].IP)))
	assert.False(t, ipam.HasIp(env.cont.serviceIps.GetV6IpCache()[0], net.ParseIP(res[1].IP)))
	assert.False(t, ipam.HasIp(env.cont.serviceIps.GetV6IpCache()[1], net.ParseIP(res[1].IP)))

	// allocate once again -> no-op
	ipc := ipam.NewIpCache()
	ipc.LoadRanges(env.cont.serviceIps.GetV4IpCache()[0].FreeList)
	ipc.LoadRanges(env.cont.serviceIps.GetV6IpCache()[0].FreeList)
	res1, err = env.ManageAppExtIp(res, nil, true)
	assert.Nil(t, err)
	assert.Equal(t, 2, len(res1))
	assert.Equal(t, res, res1)
	assert.Equal(t, ipc, env.cont.serviceIps)

	// deallocate dynamic
	ipc.DeallocateIp(net.ParseIP(res1[0].IP))
	ipc.DeallocateIp(net.ParseIP(res1[1].IP))
	res1, err = env.ManageAppExtIp(res1, nil, false)
	assert.Nil(t, err)
	assert.Nil(t, res1)
	assert.Equal(t, ipc, env.cont.serviceIps)
}

func TestCfLoadAppExtIp(t *testing.T) {
	env := testCfEnvironment(t)
	ipdb := AppExtIpDb{}

	ip1 := ExtIpAlloc{"1.2.3.4", false, "p1"}
	ip2 := ExtIpAlloc{"1.2.4.4", true, "p2"}
	ip3 := ExtIpAlloc{"::2f02", false, "p1"}
	ip4 := ExtIpAlloc{"::2e01", true, "p1"}

	txn(env.db, func(txn *sql.Tx) {
		err := ipdb.Set(txn, "1", []ExtIpAlloc{ip1, ip3})
		assert.Nil(t, err)
		err = ipdb.Set(txn, "2", []ExtIpAlloc{ip2, ip4})
		assert.Nil(t, err)
	})
	env.LoadAppExtIps()

	ainfo_1 := env.appIdx["1"]
	assert.NotNil(t, ainfo_1)
	assert.Equal(t, ainfo_1.ExternalIp, []string{"1.2.3.4", "::2f02"})

	ainfo_2 := env.appIdx["2"]
	assert.Equal(t, ainfo_2.ExternalIp, []string{"1.2.4.4", "::2e01"})

	v4 := env.cont.serviceIps.GetV4IpCache()
	v6 := env.cont.serviceIps.GetV4IpCache()

	assert.False(t, ipam.HasIp(v4[0], net.ParseIP("1.2.3.4")))
	assert.False(t, ipam.HasIp(v4[1], net.ParseIP("1.2.3.4")))
	assert.False(t, ipam.HasIp(v6[0], net.ParseIP("::2f02")))
	assert.False(t, ipam.HasIp(v6[1], net.ParseIP("::2f02")))

	assert.False(t, ipam.HasIp(v4[0], net.ParseIP("1.2.4.4")))
	assert.False(t, ipam.HasIp(v4[1], net.ParseIP("1.2.4.4")))
	assert.False(t, ipam.HasIp(v6[0], net.ParseIP("::2e01")))
	assert.False(t, ipam.HasIp(v6[1], net.ParseIP("::2e01")))
}

func TestCfLoadAppVip(t *testing.T) {
	env := testCfEnvironment(t)
	ipdb := AppVipDb{}

	txn(env.db, func(txn *sql.Tx) {
		err := ipdb.Set(txn, "app-1", "10.250.4.3", "aa::2e02")
		assert.Nil(t, err)
		err = ipdb.Set(txn, "2", "10.250.4.4", "aa::2e03")
		assert.Nil(t, err)
	})
	env.LoadAppVips()

	ainfo_1 := env.appIdx["app-1"]
	assert.NotNil(t, ainfo_1)
	assert.Equal(t, ainfo_1.VipV4, "10.250.4.3")
	assert.Equal(t, ainfo_1.VipV6, "aa::2e02")

	ainfo_2 := env.appIdx["2"]
	assert.Equal(t, ainfo_2.VipV4, "10.250.4.4")
	assert.Equal(t, ainfo_2.VipV6, "aa::2e03")

	assert.False(t, env.appVips.V4.RemoveIp(net.ParseIP("10.250.4.3")))
	assert.False(t, env.appVips.V6.RemoveIp(net.ParseIP("aa::2e02")))

	assert.False(t, env.appVips.V4.RemoveIp(net.ParseIP("10.250.4.4")))
	assert.False(t, env.appVips.V6.RemoveIp(net.ParseIP("aa::2e03")))
}

func TestCfLoadEpgAnnotations(t *testing.T) {
	env := testCfEnvironment(t)
	epgdb := EpgAnnotationDb{}

	txn(env.db, func(txn *sql.Tx) {
		err := epgdb.UpdateAnnotation(txn, "app-1", CF_OBJ_APP, "app-1")
		assert.Nil(t, err)
		err = epgdb.UpdateAnnotation(txn, "a2", CF_OBJ_APP, "app-2")
		assert.Nil(t, err)
		err = epgdb.UpdateAnnotation(txn, "space-1", CF_OBJ_SPACE, "space-1")
		assert.Nil(t, err)
		err = epgdb.UpdateAnnotation(txn, "s2", CF_OBJ_SPACE, "space-2")
		assert.Nil(t, err)
		err = epgdb.UpdateAnnotation(txn, "org-1", CF_OBJ_ORG, "org-1")
		assert.Nil(t, err)
		err = epgdb.UpdateAnnotation(txn, "o2", CF_OBJ_ORG, "org-2")
		assert.Nil(t, err)
	})
	env.LoadEpgAnnotations()

	assert.NotNil(t, env.appIdx["app-1"])
	assert.NotNil(t, env.appIdx["a2"])
	assert.NotNil(t, env.spaceIdx["space-1"])
	assert.NotNil(t, env.spaceIdx["s2"])
	assert.NotNil(t, env.orgIdx["org-1"])
	assert.NotNil(t, env.orgIdx["o2"])
}

func TestCfNetworkPolicyPoller(t *testing.T) {
	env := testCfEnvironment(t)
	npc := env.fakePolicyClient()
	npp_func := NewNetworkPolicyPoller(env).Poller()
	nph_func := NewNetworkPolicyPoller(env).Handler()

	pol_0 := cfapi.Policy{Source: cfapi.Source{ID: "app-1"},
		Destination: cfapi.Destination{ID: "app-100", Protocol: "tcp",
			Ports: cfapi.Ports{Start: 100, End: 200}}}
	pol_1 := cfapi.Policy{Source: cfapi.Source{ID: "app-1"},
		Destination: cfapi.Destination{ID: "app-100", Protocol: "tcp",
			Ports: cfapi.Ports{Start: 10, End: 20}}}
	pol_2 := cfapi.Policy{Source: cfapi.Source{ID: "app-2"},
		Destination: cfapi.Destination{ID: "app-200", Protocol: "udp",
			Ports: cfapi.Ports{Start: 30, End: 40}}}
	pol_3 := cfapi.Policy{Source: cfapi.Source{ID: "app-3"},
		Destination: cfapi.Destination{ID: "app-100", Protocol: "tcp",
			Ports: cfapi.Ports{Start: 30, End: 40}}}
	npc.On("GetPolicies").Return([]cfapi.Policy{pol_0, pol_1, pol_2, pol_3}, nil).Twice()

	store1, hash1, _ := npp_func()
	exp_app_100 := map[string][]cfapi.Destination{
		"app-1": {
			{ID: "app-1", Protocol: "tcp", Ports: cfapi.Ports{Start: 100, End: 200}},
			{ID: "app-1", Protocol: "tcp", Ports: cfapi.Ports{Start: 10, End: 20}},
		},
		"app-3": {
			{ID: "app-3", Protocol: "tcp", Ports: cfapi.Ports{Start: 30, End: 40}},
		},
	}
	exp_app_200 := map[string][]cfapi.Destination{
		"app-2": {
			{ID: "app-2", Protocol: "udp", Ports: cfapi.Ports{Start: 30, End: 40}},
		}}
	assert.Equal(t, exp_app_100, store1["app-100"])
	assert.Equal(t, exp_app_200, store1["app-200"])

	store2, hash2, _ := npp_func()
	assert.Equal(t, store1, store2)
	assert.Equal(t, hash1, hash2)

	npc.On("GetPolicies").Return([]cfapi.Policy{pol_1, pol_2}, nil)
	store3, _, _ := npp_func()
	exp_app_100["app-1"] = exp_app_100["app-1"][1:]
	delete(exp_app_100, "app-3")
	assert.Equal(t, exp_app_100, store3["app-100"])
	assert.Equal(t, exp_app_200, store3["app-200"])

	env.contIdx["c-5"] = &ContainerInfo{ContainerId: "c-5", CellId: "cell-2", AppId: "app-100"}
	env.contIdx["c-6"] = &ContainerInfo{ContainerId: "c-6", CellId: "cell-3", AppId: "app-100"}
	env.appIdx["app-100"] = &AppInfo{AppId: "app-100", SpaceId: "space-1", AppName: "app-100-name",
		ContainerIps: map[string]string{"c-5": "", "c-6": ""}}

	nph_func(map[string]interface{}{"app-100": exp_app_100, "app-200": exp_app_200}, nil)
	assert.Equal(t, exp_app_100, env.netpolIdx["app-100"])
	assert.Equal(t, exp_app_200, env.netpolIdx["app-200"])
	assert.NotNil(t, env.cont.apicConn.GetDesiredState("np:app-100"))
	assert.NotNil(t, env.cont.apicConn.GetDesiredState("np:app-200"))
	waitForGetList(t, env.containerUpdateQ, 500*time.Millisecond, []interface{}{"c-5", "c-6"})

	nph_func(nil, map[string]interface{}{"app-100": exp_app_100})
	assert.Nil(t, env.netpolIdx["app-100"])
	assert.Nil(t, env.cont.apicConn.GetDesiredState("np:app-100"))
	waitForGetList(t, env.containerUpdateQ, 500*time.Millisecond, []interface{}{"c-5", "c-6"})
}

func TestCfBbsCellPoller(t *testing.T) {
	env := testCfEnvironment(t)
	bbs := env.fakeBbsClient()
	cp := NewCfBbsCellPoller(env)
	cp_poll_func := cp.Poller()
	cp_handle_func := cp.Handler()

	c1 := &models.CellPresence{CellId: "cell-1",
		RepAddress: "http://10.10.0.12:1800"}
	c2 := &models.CellPresence{CellId: "cell-2",
		RepAddress: "http://10.10.0.13:1800"}
	c3 := &models.CellPresence{CellId: "cell-3",
		RepAddress: "http://10.10.0.14:1800"}
	bbs.CellsReturns([]*models.CellPresence{c1, c2}, nil)

	store1, hash1, _ := cp_poll_func()
	assert.Equal(t, c1, store1["cell-1"])
	assert.Equal(t, c2, store1["cell-2"])

	bbs.CellsReturns([]*models.CellPresence{c2, c3}, nil)
	store2, hash2, _ := cp_poll_func()
	assert.NotEqual(t, hash1, hash2)
	assert.Nil(t, store2["cell-1"])
	assert.Equal(t, c2, store2["cell-2"])
	assert.Equal(t, c3, store2["cell-3"])

	exp_inj_node_cell1 := apicapi.NewVmmInjectedHost("CloudFoundry",
		"cf-dom", "cf-ctrl", "diego-cell-cell-1")
	exp_inj_node_cell1.SetAttr("mgmtIp", "10.10.0.12")
	exp_inj_node_cell2 := apicapi.NewVmmInjectedHost("CloudFoundry",
		"cf-dom", "cf-ctrl", "diego-cell-cell-2")
	exp_inj_node_cell2.SetAttr("mgmtIp", "10.10.0.13")

	cp_handle_func(map[string]interface{}{"cell-1": c1, "cell-2": c2}, nil)
	env.checkApicDesiredState(t, "inj_node:cell-1", exp_inj_node_cell1)
	env.checkApicDesiredState(t, "inj_node:cell-2", exp_inj_node_cell2)

	c1.RepAddress = "http://10.10.0.11:1800"
	exp_inj_node_cell1.SetAttr("mgmtIp", "10.10.0.11")
	cp_handle_func(map[string]interface{}{"cell-1": c1},
		map[string]interface{}{"cell-2": c2})
	env.checkApicDesiredState(t, "inj_node:cell-1", exp_inj_node_cell1)
	env.checkApicDesiredState(t, "inj_node:cell-2", nil)
}
