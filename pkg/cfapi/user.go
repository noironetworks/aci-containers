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

type UserRoleInfo struct {
	Guid                        string
	Spaces                      map[string]struct{}
	AuditedSpaces               map[string]struct{}
	ManagedSpaces               map[string]struct{}
	Organizations               map[string]struct{}
	AuditedOrganizations        map[string]struct{}
	ManagedOrganizations        map[string]struct{}
	BillingManagedOrganizations map[string]struct{}
}

func NewUserRoleInfo(userId string) *UserRoleInfo {
	return &UserRoleInfo{Guid: userId,
		Spaces:                      make(map[string]struct{}),
		AuditedSpaces:               make(map[string]struct{}),
		ManagedSpaces:               make(map[string]struct{}),
		Organizations:               make(map[string]struct{}),
		AuditedOrganizations:        make(map[string]struct{}),
		ManagedOrganizations:        make(map[string]struct{}),
		BillingManagedOrganizations: make(map[string]struct{}),
	}
}

func (ur *UserRoleInfo) CanReadSpace(spaceGuid string) bool {
	if _, ok := ur.Spaces[spaceGuid]; ok {
		return true
	}
	if _, ok := ur.AuditedSpaces[spaceGuid]; ok {
		return true
	}
	if _, ok := ur.ManagedSpaces[spaceGuid]; ok {
		return true
	}
	return false
}

func (ur *UserRoleInfo) CanWriteSpace(spaceGuid string) bool {
	_, ok := ur.ManagedSpaces[spaceGuid]
	return ok
}

func (ur *UserRoleInfo) CanReadOrg(orgGuid string) bool {
	if _, ok := ur.Organizations[orgGuid]; ok {
		return true
	}
	if _, ok := ur.AuditedOrganizations[orgGuid]; ok {
		return true
	}
	if _, ok := ur.ManagedOrganizations[orgGuid]; ok {
		return true
	}
	return false
}

func (ur *UserRoleInfo) CanWriteOrg(orgGuid string) bool {
	_, ok := ur.ManagedOrganizations[orgGuid]
	return ok
}
