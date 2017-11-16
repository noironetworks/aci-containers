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

func TestCfAppCleanupPoller(t *testing.T) {
	env := testCfEnvironment(t)
	cp := NewAppCleanupPoller(env)

	cc := env.fakeCcClient()
	apps := []cfclient.App{cfclient.App{Guid: "app-1"}}
	cc.On("ListApps").Return(apps, nil)
	to_del := []interface{}{env.appIdx["app-2"], env.appIdx["app-3"]}

	cp.Poller()()
	assert.Nil(t, env.appIdx["app-2"])
	assert.Nil(t, env.appIdx["app-3"])
	waitForGetList(t, env.appDeleteQ, 500*time.Millisecond, to_del)
}

func TestCfSpaceCleanupPoller(t *testing.T) {
	env := testCfEnvironment(t)
	cp := NewSpaceCleanupPoller(env)

	cc := env.fakeCcClient()
	spaces := []cfclient.Space{cfclient.Space{Guid: "space-1"}}
	cc.On("ListSpaces").Return(spaces, nil)
	to_del := []interface{}{env.spaceIdx["space-2"]}

	cp.Poller()()
	assert.Nil(t, env.spaceIdx["space-2"])
	waitForGetList(t, env.spaceDeleteQ, 500*time.Millisecond, to_del)
}

func TestCfOrgCleanupPoller(t *testing.T) {
	env := testCfEnvironment(t)
	cp := NewOrgCleanupPoller(env)

	cc := env.fakeCcClient()
	orgs := []cfclient.Org{cfclient.Org{Guid: "org-1"}}
	cc.On("ListOrgs").Return(orgs, nil)

	env.orgIdx["org-2"] = &OrgInfo{OrgId: "org-2"}
	env.orgIdx["org-3"] = &OrgInfo{OrgId: "org-3"}
	to_del := []interface{}{env.orgIdx["org-2"], env.orgIdx["org-3"]}

	cp.Poller()()
	assert.Nil(t, env.orgIdx["org-2"])
	assert.Nil(t, env.orgIdx["org-3"])
	waitForGetList(t, env.orgDeleteQ, 500*time.Millisecond, to_del)
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
