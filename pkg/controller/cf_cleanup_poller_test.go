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
	"testing"
	"time"

	cfclient "github.com/cloudfoundry-community/go-cfclient"
	"github.com/stretchr/testify/assert"
)

func TestCfAppCloudControllerPoller(t *testing.T) {
	env := testCfEnvironment(t)
	cp := NewAppCloudControllerPoller(env)

	env.appIdx["app-51"] = NewAppInfo("app-51")
	env.appIdx["app-52"] = NewAppInfo("app-52")

	cc := env.fakeCcClient()
	apps := []cfclient.App{cfclient.App{Guid: "app-1"},
		cfclient.App{Guid: "app-51", Name: "51", SpaceURL: "/space-1",
			Instances: 1},
		cfclient.App{Guid: "app-52", Name: "52", SpaceURL: "/space-20",
			Instances: 2},
		cfclient.App{Guid: "app-100", Name: "100", SpaceURL: "/space-2",
			Instances: 3},
		cfclient.App{Guid: "app-200", Name: "200", SpaceURL: "/space-20",
			Instances: 4}}
	cc.On("ListApps").Return(apps, nil)
	to_del := []interface{}{env.appIdx["app-2"], env.appIdx["app-3"]}

	cp.Poller()()
	exp_app_51 := &AppInfo{AppId: "app-51", AppName: "51", Instances: 1,
		SpaceId: "space-1", ContainerIps: make(map[string]string)}
	exp_app_100 := &AppInfo{AppId: "app-100", AppName: "100", Instances: 3,
		SpaceId: "space-2", ContainerIps: make(map[string]string)}
	assert.Equal(t, exp_app_51, env.appIdx["app-51"])
	assert.Equal(t, "", env.appIdx["app-52"].SpaceId)
	assert.Equal(t, exp_app_100, env.appIdx["app-100"])
	assert.Nil(t, env.appIdx["app-200"])
	waitForGetList(t, env.appUpdateQ, 500*time.Millisecond,
		[]interface{}{"app-51", "app-100"})

	assert.Nil(t, env.appIdx["app-2"])
	assert.Nil(t, env.appIdx["app-3"])
	waitForGetList(t, env.appDeleteQ, 500*time.Millisecond, to_del)

	// app-52, app-200 should now be processed because space-20 is present
	env.spaceIdx["space-20"] = &SpaceInfo{SpaceId: "space-20", OrgId: "org-1"}
	cp.Poller()()
	exp_app_52 := &AppInfo{AppId: "app-52", AppName: "52", Instances: 2,
		SpaceId: "space-20", ContainerIps: make(map[string]string)}
	exp_app_200 := &AppInfo{AppId: "app-200", AppName: "200", Instances: 4,
		SpaceId: "space-20", ContainerIps: make(map[string]string)}
	assert.Equal(t, exp_app_52, env.appIdx["app-52"])
	assert.Equal(t, exp_app_200, env.appIdx["app-200"])
	waitForGetList(t, env.appUpdateQ, 500*time.Millisecond,
		[]interface{}{"app-52", "app-200"})
}

func TestCfSpaceCloudControllerPoller(t *testing.T) {
	env := testCfEnvironment(t)
	cp := NewSpaceCloudControllerPoller(env)

	env.spaceIdx["space-51"] = &SpaceInfo{SpaceId: "space-51"}

	cc := env.fakeCcClient()
	spaces := []cfclient.Space{cfclient.Space{Guid: "space-1"},
		cfclient.Space{Guid: "space-51", Name: "SPACE51",
			OrganizationGuid: "org-1"},
		cfclient.Space{Guid: "space-20", Name: "SPACE20",
			OrganizationGuid: "org-2"}}
	cc.On("ListSpaces").Return(spaces, nil)
	changes := []interface{}{"space-20", "space-51", env.spaceIdx["space-2"]}

	cp.Poller()()
	exp_space_20 := &SpaceInfo{SpaceId: "space-20", SpaceName: "SPACE20",
		OrgId: "org-2"}
	exp_space_51 := &SpaceInfo{SpaceId: "space-51", SpaceName: "SPACE51",
		OrgId: "org-1"}
	assert.Equal(t, exp_space_20, env.spaceIdx["space-20"])
	assert.Equal(t, exp_space_51, env.spaceIdx["space-51"])
	assert.Nil(t, env.spaceIdx["space-2"])
	waitForGetList(t, env.spaceChangesQ, 500*time.Millisecond, changes)
}

func TestCfOrgCloudControllerPoller(t *testing.T) {
	env := testCfEnvironment(t)
	cp := NewOrgCloudControllerPoller(env)

	env.orgIdx["org-51"] = &OrgInfo{OrgId: "org-51"}

	cc := env.fakeCcClient()
	orgs := []cfclient.Org{cfclient.Org{Guid: "org-1"},
		cfclient.Org{Guid: "org-20", Name: "ORG20"},
		cfclient.Org{Guid: "org-51", Name: "ORG51"}}
	cc.On("ListOrgs").Return(orgs, nil)

	env.orgIdx["org-2"] = &OrgInfo{OrgId: "org-2"}
	env.orgIdx["org-3"] = &OrgInfo{OrgId: "org-3"}
	changes := []interface{}{"org-20", "org-51", env.orgIdx["org-2"], env.orgIdx["org-3"]}

	cp.Poller()()
	exp_org_20 := &OrgInfo{OrgId: "org-20", OrgName: "ORG20"}
	exp_org_51 := &OrgInfo{OrgId: "org-51", OrgName: "ORG51"}
	assert.Equal(t, exp_org_20, env.orgIdx["org-20"])
	assert.Equal(t, exp_org_51, env.orgIdx["org-51"])
	assert.Nil(t, env.orgIdx["org-2"])
	assert.Nil(t, env.orgIdx["org-3"])
	waitForGetList(t, env.orgChangesQ, 500*time.Millisecond, changes)
}

func TestCfAsgCleanupPoller(t *testing.T) {
	env := testCfEnvironment(t)
	cp := NewAsgCleanupPoller(env)

	cc := env.fakeCcClient()
	asgs := []cfclient.SecGroup{cfclient.SecGroup{Guid: "ASG_PUB"}}
	cc.On("ListSecGroups").Return(asgs, nil)
	to_del := []interface{}{env.asgIdx["ASG_S1"], env.asgIdx["ASG_S1"]}

	cp.Poller()()
	assert.Nil(t, env.asgIdx["ASG_S1"])
	assert.Nil(t, env.asgIdx["ASG_R1"])
	waitForGetList(t, env.asgDeleteQ, 500*time.Millisecond, to_del)
}
