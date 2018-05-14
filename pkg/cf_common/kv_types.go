// Copyright 2018 Cisco Systems, Inc.
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

package cf_common

import (
	"fmt"
)

const (
	INST_IDX_STAGING int32 = -1
	INST_IDX_TASK    int32 = -2
)

type GroupInfo struct {
	Tenant string `json:"tenant"`
	Group  string `json:"group"`
}

type PortMap struct {
	ContainerPort uint32 `json:"container_port"`
	HostPort      uint32 `json:"host_port"`
}

type EpInfo struct {
	AppId          string      `json:"app_id"`
	AppName        string      `json:"app_name"`
	SpaceId        string      `json:"space_id"`
	OrgId          string      `json:"org_id"`
	IpAddress      string      `json:"ip_address"`
	InstanceIndex  int32       `json:"instance_index"`
	PortMapping    []PortMap   `json:"port_mapping"`
	EpgTenant      string      `json:"epg_tenant"`
	Epg            string      `json:"epg"`
	SecurityGroups []GroupInfo `json:"sg"`
	TaskName       string      `json:"task_name"`
}

func (ep *EpInfo) EpName(ctId string) string {
	if ep.AppName != "" {
		if ep.InstanceIndex == INST_IDX_TASK {
			if ep.TaskName != "" {
				return ep.AppName + " (task " + ep.TaskName + ")"
			} else {
				return ep.AppName + " (task)"
			}
		} else if ep.InstanceIndex < 0 {
			return ep.AppName + " (staging)"
		} else {
			return fmt.Sprintf("%s (%d)", ep.AppName, ep.InstanceIndex)
		}
	} else {
		return ctId
	}
}

type AppInfo struct {
	ContainerIps []string `json:"container_ips"`
	VirtualIp    []string `json:"virtual_ip"`
	ExternalIp   []string `json:"external_ip"`
}
