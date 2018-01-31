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
	"fmt"
	"testing"
	"time"

	"code.cloudfoundry.org/bbs/models"
	"github.com/stretchr/testify/assert"

	tu "github.com/noironetworks/aci-containers/pkg/testutil"
)

var TO500 time.Duration = 500 * time.Millisecond

func testCfEnvironmentWithBbsChannel(t *testing.T) (*CfEnvironment, chan models.Event) {
	env := testCfEnvironment(t)
	ch := make(chan models.Event)
	env.setBbsFakeEventSource(ch)
	return env, ch
}

func actionForApp(appId, spaceId, appName, taskName string) *models.Action {
	js := "{\"application_id\": \"%s\", \"space_id\": \"%s\", \"application_name\": \"%s\"}"
	e := models.EnvironmentVariable{Name: "VCAP_APPLICATION",
		Value: fmt.Sprintf(js, appId, spaceId, appName)}
	ra := &models.RunAction{}
	ra.Env = append(ra.Env, &e)
	if taskName != "" {
		ra.LogSource = "APP/TASK/" + taskName
	}
	raw := &models.Action{RunAction: ra}
	toa := &models.Action{TimeoutAction: &models.TimeoutAction{Action: raw}}
	epa := &models.Action{EmitProgressAction: &models.EmitProgressAction{Action: toa}}
	ta := &models.Action{TryAction: &models.TryAction{Action: epa}}
	pa := &models.Action{ParallelAction: &models.ParallelAction{Actions: []*models.Action{ta}}}
	sa := &models.Action{SerialAction: &models.SerialAction{Actions: []*models.Action{pa}}}
	ca := &models.Action{CodependentAction: &models.CodependentAction{Actions: []*models.Action{sa}}}
	return ca
}

func TestCfBbsTaskListener(t *testing.T) {
	env, ch := testCfEnvironmentWithBbsChannel(t)
	f_bbs := env.fakeBbsClient()
	tl := NewCfBbsTaskListener(env)

	t1 := &models.Task{TaskGuid: "c-tsk-1", Domain: "cf-staging", CellId: "cell1"}
	t1.TaskDefinition = &models.TaskDefinition{Action: actionForApp("a1", "sp1", "a-app", "")}
	t2 := &models.Task{TaskGuid: "c-tsk-2", Domain: "cf-tasks", CellId: "cell2"}
	t2.TaskDefinition = &models.TaskDefinition{Action: actionForApp("a2", "sp2", "b-app", "errand")}
	f_bbs.TasksReturns([]*models.Task{t1, t2}, nil)

	env.appIdx["a1"] = &AppInfo{AppId: "a1", Instances: 4,
		ContainerIps: make(map[string]string)}

	stopCh := make(chan struct{})
	runEnded := false
	go func() {
		tl.Run(stopCh)
		runEnded = true
	}()

	// Test initial fetch
	tu.WaitFor(t, "BBS task listener synced", TO500,
		func(bool) (bool, error) { return tl.Synced(), nil })

	exp_a1 := &AppInfo{AppId: "a1", AppName: "a-app", SpaceId: "sp1", Instances: 4,
		ContainerIps: make(map[string]string), VipV4: "10.250.4.1", VipV6: "aa::2e00"}
	exp_a1.ContainerIps["c-tsk-1"] = ""
	exp_tsk_1 := &ContainerInfo{ContainerId: "c-tsk-1", CellId: "cell1", InstanceIndex: -1, AppId: "a1"}
	assert.Equal(t, exp_a1, env.appIdx["a1"])
	assert.Equal(t, exp_tsk_1, env.contIdx["c-tsk-1"])

	exp_a2 := &AppInfo{AppId: "a2", AppName: "b-app", SpaceId: "sp2",
		ContainerIps: make(map[string]string), VipV4: "10.250.4.2", VipV6: "aa::2e01"}
	exp_a2.ContainerIps["c-tsk-2"] = ""
	exp_tsk_2 := &ContainerInfo{ContainerId: "c-tsk-2", CellId: "cell2", InstanceIndex: -2, AppId: "a2",
		TaskName: "errand"}
	assert.Equal(t, exp_a2, env.appIdx["a2"])
	assert.Equal(t, exp_tsk_2, env.contIdx["c-tsk-2"])

	waitForGet(t, env.appUpdateQ, TO500, "a1")
	waitForGet(t, env.appUpdateQ, TO500, "a2")
	waitForGet(t, env.spaceFetchQ, TO500, "sp1")
	waitForGet(t, env.spaceFetchQ, TO500, "sp2")
	waitForGet(t, env.containerUpdateQ, TO500, "c-tsk-1")
	waitForGet(t, env.containerUpdateQ, TO500, "c-tsk-2")

	// Test task create
	t3 := &models.Task{TaskGuid: "c-tsk-3", Domain: "cf-tasks", CellId: "cell3"}
	t3.TaskDefinition = &models.TaskDefinition{Action: actionForApp("a3", "sp3", "c-app", "another")}
	t3_create := &models.TaskCreatedEvent{Task: t3}
	ch <- t3_create

	exp_a3 := &AppInfo{AppId: "a3", AppName: "c-app", SpaceId: "sp3",
		ContainerIps: make(map[string]string), VipV4: "10.250.4.3", VipV6: "aa::2e02"}
	exp_a3.ContainerIps["c-tsk-3"] = ""
	exp_tsk_3 := &ContainerInfo{ContainerId: "c-tsk-3", CellId: "cell3", InstanceIndex: -2, AppId: "a3",
		TaskName: "another"}
	tu.WaitFor(t, "BBS task create - app", TO500,
		func(last bool) (bool, error) {
			return tu.WaitEqual(t, last, exp_a3, env.appIdx["a3"]), nil
		})
	tu.WaitFor(t, "BBS task create - container", TO500,
		func(last bool) (bool, error) {
			return tu.WaitEqual(t, last, exp_tsk_3, env.contIdx["c-tsk-3"]), nil
		})

	waitForGet(t, env.appUpdateQ, TO500, "a3")
	waitForGet(t, env.spaceFetchQ, TO500, "sp3")
	waitForGet(t, env.containerUpdateQ, TO500, "c-tsk-3")

	// Test task update
	t1.CellId = "cell2"
	t1_update := &models.TaskChangedEvent{After: t1}
	ch <- t1_update

	exp_tsk_1.CellId = "cell2"
	tu.WaitFor(t, "BBS task update - container", TO500,
		func(last bool) (bool, error) {
			return tu.WaitEqual(t, last, exp_tsk_1, env.contIdx["c-tsk-1"]), nil
		})
	waitForGet(t, env.containerUpdateQ, TO500, "c-tsk-1")

	// Test task delete
	t2_delete := &models.TaskRemovedEvent{Task: t2}
	ch <- t2_delete

	delete(exp_a2.ContainerIps, "c-tsk-2")
	tu.WaitFor(t, "BBS task delete - app", TO500,
		func(last bool) (bool, error) {
			return tu.WaitEqual(t, last, exp_a2, env.appIdx["a2"]), nil
		})
	tu.WaitFor(t, "BBS task delete - container", TO500,
		func(last bool) (bool, error) {
			return tu.WaitNil(t, last, env.contIdx["c-tsk-2"]), nil
		})
	waitForGet(t, env.appUpdateQ, TO500, "a2")
	waitForGet(t, env.containerDeleteQ, TO500, exp_tsk_2)

	close(stopCh)
	tu.WaitFor(t, "BBS task loop ended", TO500,
		func(last bool) (bool, error) { return runEnded, nil })
}

func desiredLrp(pguid, appId, spaceId, appName string) *models.DesiredLRP {
	return &models.DesiredLRP{ProcessGuid: pguid,
		Action: actionForApp(appId, spaceId, appName, "")}
}

func actualLrp(pguid, contId, cellId, ip string) *models.ActualLRPGroup {
	alrp := &models.ActualLRP{
		ActualLRPKey: models.ActualLRPKey{ProcessGuid: pguid},
		ActualLRPInstanceKey: models.ActualLRPInstanceKey{
			InstanceGuid: contId, CellId: cellId},
		ActualLRPNetInfo: models.ActualLRPNetInfo{
			InstanceAddress: ip,
			Ports: []*models.PortMapping{
				{ContainerPort: 1001, HostPort: 22},
				{ContainerPort: 1002, HostPort: 23}}}}
	return &models.ActualLRPGroup{Instance: alrp}
}

func TestCfBbsLrpListener(t *testing.T) {
	env, ch := testCfEnvironmentWithBbsChannel(t)
	f_bbs := env.fakeBbsClient()
	ll := NewCfBbsLrpListener(env)

	// Test intial fetch
	a1_dlrp := desiredLrp("a1-v1", "a1", "sp1", "a-app")
	a1_dlrp.Instances = 2
	a1_alrp1 := actualLrp("a1-v1", "c-a-1", "cell1", "10.255.0.42")
	a2_dlrp := desiredLrp("a2-v1", "a2", "sp2", "b-app")
	a2_alrp1 := actualLrp("a2-v1", "c-a-2", "cell2", "10.255.0.43")

	f_bbs.ActualLRPGroupsReturns(
		[]*models.ActualLRPGroup{a1_alrp1, a2_alrp1}, nil)
	f_bbs.DesiredLRPsReturns(
		[]*models.DesiredLRP{a1_dlrp, a2_dlrp}, nil)

	stopCh := make(chan struct{})
	runEnded := false
	go func() {
		ll.Run(stopCh)
		runEnded = true
	}()

	tu.WaitFor(t, "BBS LRP listener synced", TO500,
		func(bool) (bool, error) { return ll.Synced(), nil })

	exp_a1 := &AppInfo{AppId: "a1", AppName: "a-app", SpaceId: "sp1",
		ContainerIps: make(map[string]string), Instances: 2,
		VipV4: "10.250.4.1", VipV6: "aa::2e00"}
	exp_a1.ContainerIps["c-a-1"] = "10.255.0.42"
	exp_a1_lrp1 := &ContainerInfo{ContainerId: "c-a-1", CellId: "cell1", InstanceIndex: 0,
		AppId: "a1", IpAddress: "10.255.0.42", Ports: a1_alrp1.Instance.Ports}
	assert.Equal(t, exp_a1, env.appIdx["a1"])
	assert.Equal(t, exp_a1_lrp1, env.contIdx["c-a-1"])

	exp_a2 := &AppInfo{AppId: "a2", AppName: "b-app", SpaceId: "sp2",
		ContainerIps: make(map[string]string), VipV4: "10.250.4.2", VipV6: "aa::2e01"}
	exp_a2.ContainerIps["c-a-2"] = "10.255.0.43"
	exp_a2_lrp1 := &ContainerInfo{ContainerId: "c-a-2", CellId: "cell2", InstanceIndex: 0,
		AppId: "a2", IpAddress: "10.255.0.43", Ports: a2_alrp1.Instance.Ports}
	assert.Equal(t, exp_a2, env.appIdx["a2"])
	assert.Equal(t, exp_a2_lrp1, env.contIdx["c-a-2"])

	waitForGet(t, env.appUpdateQ, TO500, "a1")
	waitForGet(t, env.appUpdateQ, TO500, "a2")
	waitForGet(t, env.spaceFetchQ, TO500, "sp1")
	waitForGet(t, env.spaceFetchQ, TO500, "sp2")
	waitForGet(t, env.containerUpdateQ, TO500, "c-a-1")
	waitForGet(t, env.containerUpdateQ, TO500, "c-a-2")

	// Test Actual LRP create (no desired LRP), then create desired LRP
	a3_alrp1 := actualLrp("a3-v1", "c-a-3", "cell3", "10.255.0.44")
	a3_alrp1_create := &models.ActualLRPCreatedEvent{ActualLrpGroup: a3_alrp1}
	ch <- a3_alrp1_create
	time.Sleep(TO500)
	assert.Nil(t, env.contIdx["c-a-3"])

	a3_dlrp := desiredLrp("a3-v1", "a3", "sp3", "c-app")
	a3_dlrp_create := &models.DesiredLRPCreatedEvent{DesiredLrp: a3_dlrp}
	ch <- a3_dlrp_create

	exp_a3 := &AppInfo{AppId: "a3", AppName: "c-app", SpaceId: "sp3",
		ContainerIps: make(map[string]string), VipV4: "10.250.4.3", VipV6: "aa::2e02"}
	exp_a3.ContainerIps["c-a-3"] = "10.255.0.44"
	exp_a3_lrp1 := &ContainerInfo{ContainerId: "c-a-3", CellId: "cell3", InstanceIndex: 0,
		AppId: "a3", IpAddress: "10.255.0.44", Ports: a3_alrp1.Instance.Ports}
	tu.WaitFor(t, "BBS LRP create - app", TO500,
		func(last bool) (bool, error) {
			return tu.WaitEqual(t, last, exp_a3, env.appIdx["a3"]), nil
		})
	tu.WaitFor(t, "BBS LRP create - container", TO500,
		func(last bool) (bool, error) {
			return tu.WaitEqual(t, last, exp_a3_lrp1, env.contIdx["c-a-3"]), nil
		})
	waitForGet(t, env.appUpdateQ, TO500, "a3")
	waitForGet(t, env.spaceFetchQ, TO500, "sp3")
	waitForGet(t, env.containerUpdateQ, TO500, "c-a-3")

	// Test Actual LRP create (desired LRP present)
	a3_alrp2 := actualLrp("a3-v1", "c-a-4", "cell1", "10.255.0.45")
	a3_alrp2.Instance.Index = 1
	a3_alrp2_create := &models.ActualLRPCreatedEvent{ActualLrpGroup: a3_alrp2}
	ch <- a3_alrp2_create

	exp_a3.ContainerIps["c-a-4"] = "10.255.0.45"
	exp_a3_lrp2 := &ContainerInfo{ContainerId: "c-a-4", CellId: "cell1", InstanceIndex: 1,
		AppId: "a3", IpAddress: "10.255.0.45", Ports: a3_alrp1.Instance.Ports}
	tu.WaitFor(t, "BBS LRP create another - app", TO500,
		func(last bool) (bool, error) {
			return tu.WaitEqual(t, last, exp_a3, env.appIdx["a3"]), nil
		})
	tu.WaitFor(t, "BBS LRP create another - container", TO500,
		func(last bool) (bool, error) {
			return tu.WaitEqual(t, last, exp_a3_lrp2, env.contIdx["c-a-4"]), nil
		})
	waitForGet(t, env.appUpdateQ, TO500, "a3")
	waitForGet(t, env.spaceFetchQ, TO500, "sp3")
	waitForGet(t, env.containerUpdateQ, TO500, "c-a-4")

	// Test Actual LRP change
	a1_alrp1.Instance.CellId = "cell3"
	a1_alrp1.Instance.InstanceAddress = "10.255.0.10"
	a1_alrp1_update := &models.ActualLRPChangedEvent{After: a1_alrp1}
	ch <- a1_alrp1_update

	exp_a1.ContainerIps["c-a-1"] = "10.255.0.10"
	exp_a1_lrp1.CellId = "cell3"
	exp_a1_lrp1.IpAddress = "10.255.0.10"
	tu.WaitFor(t, "BBS LRP update - app", TO500,
		func(last bool) (bool, error) {
			return tu.WaitEqual(t, last, exp_a1, env.appIdx["a1"]), nil
		})
	tu.WaitFor(t, "BBS LRP update - container", TO500,
		func(last bool) (bool, error) {
			return tu.WaitEqual(t, last, exp_a1_lrp1, env.contIdx["c-a-1"]), nil
		})
	waitForGet(t, env.appUpdateQ, TO500, "a1")
	waitForGet(t, env.spaceFetchQ, TO500, "sp1")
	waitForGet(t, env.containerUpdateQ, TO500, "c-a-1")

	// Test Actual LRP delete
	a1_alrp1_delete := &models.ActualLRPRemovedEvent{ActualLrpGroup: a1_alrp1}
	ch <- a1_alrp1_delete

	delete(exp_a1.ContainerIps, "c-a-1")
	tu.WaitFor(t, "BBS LRP delete - app", TO500,
		func(last bool) (bool, error) {
			return tu.WaitEqual(t, last, exp_a1, env.appIdx["a1"]), nil
		})
	tu.WaitFor(t, "BBS LRP delete - container", TO500,
		func(last bool) (bool, error) {
			return tu.WaitNil(t, last, env.contIdx["c-a-1"]), nil
		})
	waitForGet(t, env.appUpdateQ, TO500, "a1")
	waitForGet(t, env.containerDeleteQ, TO500, exp_a1_lrp1)

	// Test Desired LRP change
	a1_dlrp = desiredLrp("a1-v1", "a1", "sp1", "a-new-app")
	a1_dlrp.Instances = 5
	a1_dlrp_update := &models.DesiredLRPChangedEvent{After: a1_dlrp}
	ch <- a1_dlrp_update

	exp_a1.AppName = "a-new-app"
	exp_a1.Instances = 5
	tu.WaitFor(t, "BBS LRP desired update - app", TO500,
		func(last bool) (bool, error) {
			return tu.WaitEqual(t, last, exp_a1, env.appIdx["a1"]), nil
		})
	waitForGet(t, env.appUpdateQ, TO500, "a1")
	waitForGet(t, env.spaceFetchQ, TO500, "sp1")

	// Test Desired LRP delete
	a1_dlrp_delete := &models.DesiredLRPRemovedEvent{DesiredLrp: a1_dlrp}
	ch <- a1_dlrp_delete
	time.Sleep(TO500)
	assert.Equal(t, exp_a1, env.appIdx["a1"])

	close(stopCh)
	tu.WaitFor(t, "BBS LRP loop ended", TO500,
		func(last bool) (bool, error) { return runEnded, nil })
}
