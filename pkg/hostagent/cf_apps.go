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

package hostagent

import (
	"net"
	"reflect"

	"github.com/noironetworks/aci-containers/pkg/cf_common"
	md "github.com/noironetworks/aci-containers/pkg/metadata"
)

func (env *CfEnvironment) updateContainerMetadata(metadataKey *string) {
	ctId := extractContainerIdFromMetadataKey(metadataKey)
	if ctId == "" {
		return
	}

	env.agent.indexMutex.Lock()
	md, mdok := env.agent.epMetadata[*metadataKey]
	env.agent.indexMutex.Unlock()

	if !mdok || md[ctId] == nil {
		env.kvmgr.Delete("container", ctId)
	} else {
		env.kvmgr.Set("container", ctId, md[ctId].Ifaces)
	}
}

func (env *CfEnvironment) cfAppContainerChanged(ctId *string,
	ep *cf_common.EpInfo) {
	if ep == nil {
		return
	}
	metaKey := "_cf_/" + *ctId

	epGroup := &md.OpflexGroup{PolicySpace: ep.EpgTenant, Name: ep.Epg}
	secGroup := make([]md.OpflexGroup, len(ep.SecurityGroups))
	for i, s := range ep.SecurityGroups {
		secGroup[i].PolicySpace = s.Tenant
		secGroup[i].Name = s.Group
	}

	epAttributes := make(map[string]string)
	epAttributes["vm-name"] = ep.EpName(*ctId)
	epAttributes["app-id"] = ep.AppId
	epAttributes["space-id"] = ep.SpaceId
	epAttributes["org-id"] = ep.OrgId
	epAttributes["container-id"] = *ctId

	env.agent.indexMutex.Lock()
	env.agent.epChanged(ctId, &metaKey, epGroup, secGroup, epAttributes, nil)
	env.agent.indexMutex.Unlock()
	env.agent.ScheduleSync("iptables")
}

func (env *CfEnvironment) cfAppContainerDeleted(ctId *string,
	ep *cf_common.EpInfo) {
	env.agent.indexMutex.Lock()
	env.agent.epDeleted(ctId)
	env.agent.indexMutex.Unlock()
	env.agent.ScheduleSync("iptables")
}

func (env *CfEnvironment) updateLegacyCfNetService(portmap map[uint32]struct{}) error {
	uuid := "cf-net-" + env.cfconfig.CellID
	new_svc := opflexService{Uuid: uuid,
		DomainPolicySpace: env.agent.config.AciVrfTenant,
		DomainName:        env.agent.config.AciVrf,
		ServiceMac:        env.cfNetLink.Attrs().HardwareAddr.String(),
		InterfaceName:     env.cfconfig.CfNetOvsPort}
	for p := range portmap {
		svc_map := opflexServiceMapping{ServiceIp: env.cfconfig.CfNetIntfAddress,
			ServicePort: uint16(p),
			NextHopIps:  make([]string, 0)}
		new_svc.ServiceMappings = append(new_svc.ServiceMappings, svc_map)
	}
	env.agent.indexMutex.Lock()
	defer env.agent.indexMutex.Unlock()
	exist, ok := env.agent.opflexServices[uuid]
	if !ok || !reflect.DeepEqual(*exist, new_svc) {
		env.log.Debug("Updating CF legacy-networking service ", uuid)
		env.agent.opflexServices[uuid] = &new_svc
		env.agent.scheduleSyncServices()
	}
	return nil
}

func (env *CfEnvironment) cfAppDeleted(appId *string,
	app *cf_common.AppInfo) {
	env.agent.indexMutex.Lock()
	defer env.agent.indexMutex.Unlock()
	uuid := *appId
	_, vip_ok := env.agent.opflexServices[uuid]
	if vip_ok {
		env.log.Debug("Removing service CF app vip/ext-ip ", uuid)
		delete(env.agent.opflexServices, uuid)
	}
	uuid += "-external"
	_, ext_ip_ok := env.agent.opflexServices[uuid]
	if ext_ip_ok {
		env.log.Debug("Removing service CF app vip/ext-ip ", uuid)
		delete(env.agent.opflexServices, uuid)
	}
	if vip_ok || ext_ip_ok {
		env.agent.scheduleSyncServices()
	}
}

// 0 -> ipv4, 1 -> ipv6, anything else -> invalid IP
func getIpType(ip_str string) int {
	ip := net.ParseIP(ip_str)
	if ip == nil {
		return -1
	}
	if ip.To4() != nil {
		return 0
	}
	if ip.To16() != nil {
		return 1
	}
	return -2
}

func (env *CfEnvironment) cfAppIdChanged(appId *string) {
	env.indexLock.Lock()
	appInfo := env.appIdx[*appId]
	env.indexLock.Unlock()
	if appInfo != nil {
		env.cfAppChanged(appId, appInfo)
	}
}

func (env *CfEnvironment) cfAppChanged(appId *string,
	app *cf_common.AppInfo) {
	env.updateCfAppServiceEp(appId, app, false)
	env.updateCfAppServiceEp(appId, app, true)
}

func (env *CfEnvironment) updateCfAppServiceEp(appId *string,
	app *cf_common.AppInfo, external bool) {
	agent := env.agent
	uuid := *appId
	if external {
		uuid += "-external"
	}
	appas := opflexService{
		Uuid:              uuid,
		DomainPolicySpace: agent.config.AciVrfTenant,
		DomainName:        agent.config.AciVrf,
		ServiceMode:       "loadbalancer",
		ServiceMappings:   make([]opflexServiceMapping, 0),
	}
	if external && agent.config.UplinkIface != "" && agent.serviceEp.Mac != "" &&
		(agent.serviceEp.Ipv4 != nil || agent.serviceEp.Ipv6 != nil) {

		appas.InterfaceName = agent.config.UplinkIface
		appas.InterfaceVlan = uint16(agent.config.ServiceVlan)
		appas.ServiceMac = agent.serviceEp.Mac
		if agent.serviceEp.Ipv4 != nil {
			appas.InterfaceIp = agent.serviceEp.Ipv4.String()
		} else {
			appas.InterfaceIp = agent.serviceEp.Ipv6.String() // TODO dual stack?
		}
	}
	ips := app.VirtualIp
	if external {
		ips = app.ExternalIp
	}
	localContainerIps := make([]string, 0)
	agent.indexMutex.Lock()
	defer agent.indexMutex.Unlock()
	if external {
		for _, c := range env.epIdx {
			if c != nil && c.AppId == *appId {
				localContainerIps = append(localContainerIps, c.IpAddress)
			}
		}
	}
	for _, vip := range ips {
		ipt := getIpType(vip)
		if ipt != 0 && ipt != 1 {
			continue
		}
		sm := opflexServiceMapping{
			ServiceIp:  vip,
			NextHopIps: make([]string, 0),
			Conntrack:  true,
		}
		containers := app.ContainerIps
		if external {
			containers = localContainerIps
		}
		for _, cip := range containers {
			if ipt != getIpType(cip) {
				continue
			}
			sm.NextHopIps = append(sm.NextHopIps, cip)
		}
		if len(sm.NextHopIps) > 0 {
			appas.ServiceMappings = append(appas.ServiceMappings, sm)
		}
	}
	valid := len(appas.ServiceMappings) > 0

	exist, ok := env.agent.opflexServices[uuid]
	if valid && (!ok || !reflect.DeepEqual(*exist, appas)) {
		env.log.Debug("Updating CF app vip/ext-ip service ", uuid)
		env.agent.opflexServices[uuid] = &appas
		env.agent.scheduleSyncServices()
	} else if !valid && ok {
		env.log.Debug("Removing CF app vip/ext-ip service ", uuid)
		delete(env.agent.opflexServices, uuid)
		env.agent.scheduleSyncServices()
	}
}
