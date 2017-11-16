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
	"time"
)

func NewAppCleanupPoller(env *CfEnvironment) *CfPoller {

	pollFunc := func() (map[string]interface{}, interface{}, error) {
		allApps, err := env.ccClient.ListApps()
		if err != nil {
			return nil, nil, err
		}
		existApps := make(map[string]struct{})
		for i := 0; i < len(allApps); i++ {
			existApps[allApps[i].Guid] = struct{}{}
		}
		toDelete := make(map[string]struct{})
		env.indexLock.Lock()
		defer env.indexLock.Unlock()
		for k, _ := range env.appIdx {
			if _, ok := existApps[k]; !ok {
				toDelete[k] = struct{}{}
			}
		}
		for k, _ := range toDelete {
			env.log.Debug("Delete app on cleanup ", k)
			ainfo := env.appIdx[k]
			delete(env.appIdx, k)
			env.appDeleteQ.Add(ainfo)
		}
		return nil, "0", nil
	}

	handleFunc := func(updates map[string]interface{}, deletes map[string]interface{}) {}
	pollInterval := time.Duration(env.cfconfig.CleanupPollingInterval) * time.Second
	return NewCfPoller("App-cleanup", pollInterval, 0, pollFunc, handleFunc, env.log)
}

func NewSpaceCleanupPoller(env *CfEnvironment) *CfPoller {

	pollFunc := func() (map[string]interface{}, interface{}, error) {
		allSpaces, err := env.ccClient.ListSpaces()
		if err != nil {
			return nil, nil, err
		}
		existSpaces := make(map[string]struct{})
		for i := 0; i < len(allSpaces); i++ {
			existSpaces[allSpaces[i].Guid] = struct{}{}
		}
		toDelete := make(map[string]struct{})
		env.indexLock.Lock()
		defer env.indexLock.Unlock()
		for k, _ := range env.spaceIdx {
			if _, ok := existSpaces[k]; !ok {
				toDelete[k] = struct{}{}
			}
		}
		for k, _ := range toDelete {
			env.log.Debug("Delete space on cleanup ", k)
			sinfo := env.spaceIdx[k]
			delete(env.spaceIdx, k)
			env.spaceDeleteQ.Add(sinfo)
		}
		return nil, "0", nil
	}

	handleFunc := func(updates map[string]interface{}, deletes map[string]interface{}) {}
	pollInterval := time.Duration(env.cfconfig.CleanupPollingInterval) * time.Second
	return NewCfPoller("Space-cleanup", pollInterval, 0, pollFunc, handleFunc, env.log)
}

func NewOrgCleanupPoller(env *CfEnvironment) *CfPoller {

	pollFunc := func() (map[string]interface{}, interface{}, error) {
		allOrgs, err := env.ccClient.ListOrgs()
		if err != nil {
			return nil, nil, err
		}
		existOrgs := make(map[string]struct{})
		for i := 0; i < len(allOrgs); i++ {
			existOrgs[allOrgs[i].Guid] = struct{}{}
		}
		toDelete := make(map[string]struct{})
		env.indexLock.Lock()
		defer env.indexLock.Unlock()
		for k, _ := range env.orgIdx {
			if _, ok := existOrgs[k]; !ok {
				toDelete[k] = struct{}{}
			}
		}
		for k, _ := range toDelete {
			env.log.Debug("Delete org on cleanup ", k)
			oinfo := env.orgIdx[k]
			delete(env.orgIdx, k)
			env.orgDeleteQ.Add(oinfo)
		}
		return nil, "0", nil
	}

	handleFunc := func(updates map[string]interface{}, deletes map[string]interface{}) {}
	pollInterval := time.Duration(env.cfconfig.CleanupPollingInterval) * time.Second
	return NewCfPoller("Org-cleanup", pollInterval, 0, pollFunc, handleFunc, env.log)
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
		for k, _ := range env.asgIdx {
			if _, ok := existAsgs[k]; !ok {
				toDelete[k] = struct{}{}
			}
		}
		for k, _ := range toDelete {
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
