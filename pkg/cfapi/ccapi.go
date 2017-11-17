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

package cfapi

import (
	"encoding/json"
	"io/ioutil"
	"strings"

	cfclient "github.com/cloudfoundry-community/go-cfclient"
)

type CcClient interface {
	GetSpaceByGuid(spaceGUID string) (cfclient.Space, error)

	GetOrgByGuid(guid string) (cfclient.Org, error)

	ListSecGroupsBySpace(spaceGuid string, staging bool) ([]cfclient.SecGroup, error)

	GetIsolationSegmentByGUID(guid string) (*cfclient.IsolationSegment, error)

	GetOrgDefaultIsolationSegment(orgGuid string) (string, error)

	GetSpaceIsolationSegment(spaceGuid string) (string, error)

	GetUserRoleInfo(userGuid string) (*UserRoleInfo, error)

	GetAppSpace(appGuid string) (string, error)

	ListOrgs() ([]cfclient.Org, error)

	ListSpaces() ([]cfclient.Space, error)

	ListApps() ([]cfclient.App, error)

	ListSecGroups() ([]cfclient.SecGroup, error)
}

type ccClientImpl struct {
	cfclient.Client
}

func NewCcClient(apiUrl string, username string, password string) (CcClient, error) {
	ccConfig := &cfclient.Config{
		ApiAddress:        apiUrl,
		Username:          username,
		Password:          password,
		SkipSslValidation: true,
	}
	cfc, err := cfclient.NewClient(ccConfig)
	if err != nil {
		return nil, err
	}
	return &ccClientImpl{*cfc}, nil
}

func (ccClient *ccClientImpl) ListSecGroupsBySpace(spaceGuid string, staging bool) ([]cfclient.SecGroup, error) {
	stageStr := ""
	if staging {
		stageStr = "staging_"
	}
	requestURL := "/v2/spaces/" + spaceGuid + "/" + stageStr + "security_groups"
	var secGroups []cfclient.SecGroup
	for requestURL != "" {
		var secGroupResp cfclient.SecGroupResponse
		r := ccClient.NewRequest("GET", requestURL)
		resp, err := ccClient.DoRequest(r)

		if err != nil {
			return nil, err
		}
		resBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}

		err = json.Unmarshal(resBody, &secGroupResp)
		if err != nil {
			return nil, err
		}

		for _, secGroup := range secGroupResp.Resources {
			secGroup.Entity.Guid = secGroup.Meta.Guid
			secGroups = append(secGroups, secGroup.Entity)
		}

		requestURL = secGroupResp.NextUrl
		resp.Body.Close()
	}
	return secGroups, nil
}

func (ccClient *ccClientImpl) GetOrgDefaultIsolationSegment(orgGuid string) (string, error) {
	requestUrl := "/v3/organizations/" + orgGuid + "/relationships/default_isolation_segment"
	return ccClient.getIsolationSegment(requestUrl)
}

func (ccClient *ccClientImpl) GetSpaceIsolationSegment(spaceGuid string) (string, error) {
	requestUrl := "/v3/spaces/" + spaceGuid + "/relationships/isolation_segment"
	return ccClient.getIsolationSegment(requestUrl)
}

func (ccClient *ccClientImpl) getIsolationSegment(requestURL string) (string, error) {
	r := ccClient.NewRequest("GET", requestURL)
	resp, err := ccClient.DoRequest(r)

	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	resBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var isr struct {
		Data struct {
			Guid string `json:"guid"`
		} `json:"data"`
	}

	err = json.Unmarshal(resBody, &isr)
	if err != nil {
		return "", err
	}
	return isr.Data.Guid, nil
}

func (ccClient *ccClientImpl) GetUserRoleInfo(userGuid string) (*UserRoleInfo, error) {
	r := ccClient.NewRequest("GET", "/v2/users/"+userGuid+"/summary")
	resp, err := ccClient.DoRequest(r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	resBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	type EntityMeta struct {
		Meta cfclient.Meta `json:"metadata"`
	}
	var userSummaryResp struct {
		Meta   cfclient.Meta `json:"metadata"`
		Entity struct {
			Organizations               []EntityMeta `json:"organizations"`
			AuditedOrganizations        []EntityMeta `json:"audited_organizations"`
			ManagedOrganizations        []EntityMeta `json:"managed_organizations"`
			BillingManagedOrganizations []EntityMeta `json:"billing_managed_organizations"`
			Spaces                      []EntityMeta `json:"spaces"`
			AuditedSpaces               []EntityMeta `json:"audited_spaces"`
			ManagedSpaces               []EntityMeta `json:"managed_spaces"`
		} `json:"entity"`
	}
	err = json.Unmarshal(resBody, &userSummaryResp)
	if err != nil {
		return nil, err
	}
	ri := NewUserRoleInfo(userSummaryResp.Meta.Guid)
	for _, e := range userSummaryResp.Entity.Organizations {
		ri.Organizations[e.Meta.Guid] = struct{}{}
	}
	for _, e := range userSummaryResp.Entity.AuditedOrganizations {
		ri.AuditedOrganizations[e.Meta.Guid] = struct{}{}
	}
	for _, e := range userSummaryResp.Entity.ManagedOrganizations {
		ri.ManagedOrganizations[e.Meta.Guid] = struct{}{}
	}
	for _, e := range userSummaryResp.Entity.BillingManagedOrganizations {
		ri.BillingManagedOrganizations[e.Meta.Guid] = struct{}{}
	}
	for _, e := range userSummaryResp.Entity.Spaces {
		ri.Spaces[e.Meta.Guid] = struct{}{}
	}
	for _, e := range userSummaryResp.Entity.AuditedSpaces {
		ri.AuditedSpaces[e.Meta.Guid] = struct{}{}
	}
	for _, e := range userSummaryResp.Entity.ManagedSpaces {
		ri.ManagedSpaces[e.Meta.Guid] = struct{}{}
	}
	return ri, nil
}

func (ccClient *ccClientImpl) GetAppSpace(appGuid string) (string, error) {
	requestURL := "/v3/apps/" + appGuid

	r := ccClient.NewRequest("GET", requestURL)
	resp, err := ccClient.DoRequest(r)

	if err != nil {
		return "", err
	}
	resBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var appResp struct {
		Guid  string `json:"guid"`
		Links struct {
			Space struct {
				Href string `json:"href"`
			} `json:"space"`
		} `json:"links"`
	}
	err = json.Unmarshal(resBody, &appResp)
	if err != nil {
		return "", err
	}
	parts := strings.Split(appResp.Links.Space.Href, "/")
	return parts[len(parts)-1], nil
}
