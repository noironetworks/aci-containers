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
	"strings"
	"time"

	cfclient "github.com/cloudfoundry-community/go-cfclient"
)

func NewAppCloudControllerPoller(env *CfEnvironment) *CfPoller {

	pollFunc := func() (map[string]interface{}, interface{}, error) {
		allApps, err := env.ccClient.ListApps()
		if err != nil {
			return nil, nil, err
		}
		existApps := make(map[string]*cfclient.App)
		for i := 0; i < len(allApps); i++ {
			existApps[allApps[i].Guid] = &allApps[i]
		}
		toDelete := make(map[string]struct{})
		env.indexLock.Lock()
		defer env.indexLock.Unlock()
		for k, a := range env.appIdx {
			if _, ok := existApps[k]; !ok {
				toDelete[k] = struct{}{}
			}
			if a.AppName != "" && a.SpaceId != "" {
				delete(existApps, k)
			}
		}
		for k, v := range existApps {
			parts := strings.Split(v.SpaceURL, "/")
			spaceId := parts[len(parts)-1]
			if env.spaceIdx[spaceId] == nil {
				env.log.Debug("Defer new app found by polling ", k)
				continue
			}
			ainfo := env.appIdx[k]
			if ainfo == nil {
				ainfo = NewAppInfo(k)
			}
			ainfo.AppName = v.Name
			ainfo.SpaceId = spaceId
			ainfo.Instances = int32(v.Instances)
			env.appIdx[k] = ainfo
			env.log.Debug(fmt.Sprintf("New app found by polling %v", ainfo))
			env.appUpdateQ.Add(k)
		}
		for k := range toDelete {
			env.log.Debug("Delete app on cleanup ", k)
			ainfo := env.appIdx[k]
			delete(env.appIdx, k)
			env.appDeleteQ.Add(ainfo)
		}
		return nil, "0", nil
	}

	handleFunc := func(updates map[string]interface{}, deletes map[string]interface{}) {}
	pollInterval := time.Duration(env.cfconfig.CleanupPollingInterval) * time.Second
	return NewCfPoller("App-CC", pollInterval, 0, pollFunc, handleFunc, env.log)
}

func NewSpaceCloudControllerPoller(env *CfEnvironment) *CfPoller {

	pollFunc := func() (map[string]interface{}, interface{}, error) {
		allSpaces, err := env.ccClient.ListSpaces()
		if err != nil {
			return nil, nil, err
		}
		existSpaces := make(map[string]*cfclient.Space)
		for i := 0; i < len(allSpaces); i++ {
			existSpaces[allSpaces[i].Guid] = &allSpaces[i]
		}
		toDelete := make(map[string]struct{})
		env.indexLock.Lock()
		defer env.indexLock.Unlock()
		for k, s := range env.spaceIdx {
			if _, ok := existSpaces[k]; !ok {
				toDelete[k] = struct{}{}
			}
			if s.SpaceName != "" && s.OrgId != "" {
				delete(existSpaces, k)
			}
		}
		for k, v := range existSpaces {
			spi := env.spaceIdx[k]
			if spi == nil {
				spi = &SpaceInfo{SpaceId: v.Guid}
			}
			spi.SpaceName = v.Name
			spi.OrgId = v.OrganizationGuid
			env.spaceIdx[k] = spi
			env.log.Debug("New space found by polling ", k)
			env.spaceChangesQ.Add(k)
		}
		for k := range toDelete {
			env.log.Debug("Delete space on cleanup ", k)
			sinfo := env.spaceIdx[k]
			delete(env.spaceIdx, k)
			env.spaceChangesQ.Add(sinfo)
		}
		return nil, "0", nil
	}

	handleFunc := func(updates map[string]interface{}, deletes map[string]interface{}) {}
	pollInterval := time.Duration(env.cfconfig.CleanupPollingInterval) * time.Second
	return NewCfPoller("Space-CC", pollInterval, 0, pollFunc, handleFunc, env.log)
}

func NewOrgCloudControllerPoller(env *CfEnvironment) *CfPoller {

	pollFunc := func() (map[string]interface{}, interface{}, error) {
		allOrgs, err := env.ccClient.ListOrgs()
		if err != nil {
			return nil, nil, err
		}
		existOrgs := make(map[string]*cfclient.Org)
		for i := 0; i < len(allOrgs); i++ {
			existOrgs[allOrgs[i].Guid] = &allOrgs[i]
		}
		toDelete := make(map[string]struct{})
		env.indexLock.Lock()
		defer env.indexLock.Unlock()
		for k, o := range env.orgIdx {
			if _, ok := existOrgs[k]; !ok {
				toDelete[k] = struct{}{}
			}
			if o.OrgName != "" {
				delete(existOrgs, k)
			}
		}
		for k, v := range existOrgs {
			oinfo := env.orgIdx[k]
			if oinfo == nil {
				oinfo = &OrgInfo{OrgId: v.Guid}
			}
			oinfo.OrgName = v.Name
			env.orgIdx[k] = oinfo
			env.log.Debug("New org found by polling ", k)
			env.orgChangesQ.Add(k)
		}
		for k := range toDelete {
			env.log.Debug("Delete org on cleanup ", k)
			oinfo := env.orgIdx[k]
			delete(env.orgIdx, k)
			env.orgChangesQ.Add(oinfo)
		}
		return nil, "0", nil
	}

	handleFunc := func(updates map[string]interface{}, deletes map[string]interface{}) {}
	pollInterval := time.Duration(env.cfconfig.CleanupPollingInterval) * time.Second
	return NewCfPoller("Org-CC", pollInterval, 0, pollFunc, handleFunc, env.log)
}

func NewAsgCleanupPoller(env *CfEnvironment) *CfPoller {

	pollFunc := func() (map[string]interface{}, interface{}, error) {
		allAsgs, err := env.ccClient.ListSecGroups()
		if err != nil {
			return nil, nil, err
		}
		existAsgs := make(map[string]struct{})
		for i := 0; i < len(allAsgs); i++ {
			existAsgs[allAsgs[i].Guid] = struct{}{}
		}
		toDelete := make(map[string]struct{})
		env.indexLock.Lock()
		defer env.indexLock.Unlock()
		for k := range env.asgIdx {
			if _, ok := existAsgs[k]; !ok {
				toDelete[k] = struct{}{}
			}
		}
		for k := range toDelete {
			env.log.Debug("Delete ASG on cleanup ", k)
			asgInfo := env.asgIdx[k]
			delete(env.asgIdx, k)
			env.asgDeleteQ.Add(asgInfo)
		}
		return nil, "0", nil
	}

	handleFunc := func(updates map[string]interface{}, deletes map[string]interface{}) {}
	pollInterval := time.Duration(env.cfconfig.CleanupPollingInterval) * time.Second
	return NewCfPoller("ASG-cleanup", pollInterval, 0, pollFunc, handleFunc, env.log)
}
