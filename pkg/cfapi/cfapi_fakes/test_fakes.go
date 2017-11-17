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

//
// This file defines fake versions of various client that are meant to be used
// for testing ONLY.
//

package cfapi_fakes

import (
	"github.com/stretchr/testify/mock"

	cfclient "github.com/cloudfoundry-community/go-cfclient"

	"github.com/noironetworks/aci-containers/pkg/cfapi"
)

type FakeCcClient struct {
	mock.Mock
}

func (c *FakeCcClient) GetSpaceByGuid(spaceGUID string) (cfclient.Space, error) {
	res := c.Called(spaceGUID)
	return res.Get(0).(cfclient.Space), res.Error(1)
}

func (c *FakeCcClient) GetOrgByGuid(guid string) (cfclient.Org, error) {
	res := c.Called(guid)
	return res.Get(0).(cfclient.Org), res.Error(1)
}

func (c *FakeCcClient) ListSecGroupsBySpace(spaceGuid string, staging bool) ([]cfclient.SecGroup, error) {
	res := c.Called(spaceGuid, staging)
	return res.Get(0).([]cfclient.SecGroup), res.Error(1)
}

func (c *FakeCcClient) GetIsolationSegmentByGUID(guid string) (*cfclient.IsolationSegment, error) {
	res := c.Called(guid)
	return res.Get(0).(*cfclient.IsolationSegment), res.Error(1)
}

func (c *FakeCcClient) GetOrgDefaultIsolationSegment(orgGuid string) (string, error) {
	res := c.Called(orgGuid)
	return res.String(0), res.Error(1)
}

func (c *FakeCcClient) GetSpaceIsolationSegment(spaceGuid string) (string, error) {
	res := c.Called(spaceGuid)
	return res.String(0), res.Error(1)
}

func (c *FakeCcClient) GetUserRoleInfo(userGuid string) (*cfapi.UserRoleInfo, error) {
	res := c.Called(userGuid)
	return res.Get(0).(*cfapi.UserRoleInfo), res.Error(1)
}

func (c *FakeCcClient) GetAppSpace(appGuid string) (string, error) {
	res := c.Called(appGuid)
	return res.String(0), res.Error(1)
}

func (c *FakeCcClient) ListApps() ([]cfclient.App, error) {
	res := c.Called()
	return res.Get(0).([]cfclient.App), res.Error(1)
}

func (c *FakeCcClient) ListOrgs() ([]cfclient.Org, error) {
	res := c.Called()
	return res.Get(0).([]cfclient.Org), res.Error(1)
}

func (c *FakeCcClient) ListSpaces() ([]cfclient.Space, error) {
	res := c.Called()
	return res.Get(0).([]cfclient.Space), res.Error(1)
}

func (c *FakeCcClient) ListSecGroups() ([]cfclient.SecGroup, error) {
	res := c.Called()
	return res.Get(0).([]cfclient.SecGroup), res.Error(1)
}

type FakeCfAuthClient struct {
	mock.Mock
}

func (c *FakeCfAuthClient) FetchTokenInfo(token string) (*cfapi.TokenInfo, error) {
	res := c.Called(token)
	return res.Get(0).(*cfapi.TokenInfo), res.Error(1)
}

type FakePolicyClient struct {
	mock.Mock
}

func (c *FakePolicyClient) GetPolicies(ids ...string) ([]cfapi.Policy, error) {
	var l []interface{}
	for _, s := range ids {
		l = append(l, s)
	}
	res := c.Called(l...)
	return res.Get(0).([]cfapi.Policy), res.Error(1)
}
