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
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"

	cfclient "github.com/cloudfoundry-community/go-cfclient"
	etcdclient "github.com/coreos/etcd/client"
	"golang.org/x/net/context"

	"github.com/noironetworks/aci-containers/pkg/apicapi"
	etcd "github.com/noironetworks/aci-containers/pkg/cf_etcd"
	"github.com/noironetworks/aci-containers/pkg/ipam"
	"github.com/noironetworks/aci-containers/pkg/metadata"
)

func (env *CfEnvironment) handleContainerUpdate(contId string) bool {
	env.indexLock.Lock()
	defer env.indexLock.Unlock()
	return env.handleContainerUpdateLocked(contId)
}

func (env *CfEnvironment) handleContainerDelete(cinfo *ContainerInfo) bool {
	env.indexLock.Lock()
	defer env.indexLock.Unlock()
	return env.handleContainerDeleteLocked(cinfo)
}

func (env *CfEnvironment) handleContainerUpdateLocked(contId string) bool {
	retry := false
	cinfo := env.contIdx[contId]
	if cinfo == nil || cinfo.AppId == "" {
		return false
	}
	epgTenant := env.cont.config.DefaultEg.PolicySpace
	epg := env.cont.config.DefaultEg.Name

	appInfo, ok := env.appIdx[cinfo.AppId]
	var sg *[]string
	var spaceInfo *SpaceInfo
	if ok && appInfo != nil && appInfo.SpaceId != "" {
		spaceInfo = env.spaceIdx[appInfo.SpaceId]
		if spaceInfo != nil {
			if cinfo.IsStaging() {
				sg = &spaceInfo.StagingSecurityGroups
			} else {
				sg = &spaceInfo.RunningSecurityGroups
			}
			if is := env.isoSegIdx[spaceInfo.IsolationSegment]; is != nil && is.Name != "" {
				epg = env.cfconfig.DefaultAppProfile + "|" + is.Name
			} else {
				epg_ann_db := EpgAnnotationDb{}
				txn, _ := env.db.Begin()
				v, err := epg_ann_db.ResolveAnnotation(txn, cinfo.AppId,
					appInfo.SpaceId, spaceInfo.OrgId)
				if err != nil {
					env.log.Error("Failed to resolve EPG annotation: ", err)
					retry = true
				} else if v != "" {
					if strings.Contains(v, "|") {
						epg = v
					} else {
						epg = env.cfconfig.DefaultAppProfile + "|" + v
					}
				}
				txn.Commit()
			}
		}
	}
	ep := etcd.EpInfo{AppId: cinfo.AppId,
		AppName:       appInfo.AppName,
		InstanceIndex: cinfo.InstanceIndex,
		IpAddress:     cinfo.IpAddress,
		EpgTenant:     epgTenant,
		Epg:           epg,
		TaskName:      cinfo.TaskName}
	env.log.Debug(fmt.Sprintf("Handling container update: %+v", cinfo))
	if cinfo.CellId != "" {
		env.cont.indexMutex.Lock()
		env.LoadCellNetworkInfo(cinfo.CellId)
		newCellSvc := env.LoadCellServiceInfo(cinfo.CellId)
		env.cont.addPodToNode(cinfo.CellId, contId)
		env.cont.indexMutex.Unlock()
		if newCellSvc {
			env.log.Info("Updating device-cluster for new cell ", cinfo.CellId)
			env.cont.updateDeviceCluster()
		}

		ctKey := etcd.CELL_KEY_BASE + "/" + cinfo.CellId + "/containers/" + cinfo.ContainerId
		if spaceInfo != nil {
			ep.SpaceId = spaceInfo.SpaceId
			ep.OrgId = spaceInfo.OrgId
		}
		for _, pm := range cinfo.Ports {
			ep.PortMapping = append(ep.PortMapping,
				etcd.PortMap{ContainerPort: pm.ContainerPort, HostPort: pm.HostPort})
		}
		ep.SecurityGroups = append(ep.SecurityGroups,
			etcd.GroupInfo{Group: env.cont.aciNameForKey("hpp", "static"),
				Tenant: env.cont.config.AciPolicyTenant})
		ep.SecurityGroups = append(ep.SecurityGroups,
			etcd.GroupInfo{Group: env.cont.aciNameForKey("hpp", "cf-components"),
				Tenant: env.cont.config.AciPolicyTenant})
		if sg != nil {
			for _, s := range *sg {
				ep.SecurityGroups = append(ep.SecurityGroups,
					etcd.GroupInfo{Group: env.cont.aciNameForKey("asg", s),
						Tenant: env.cont.config.AciPolicyTenant})
			}
		}
		_, ok := env.netpolIdx[cinfo.AppId]
		if ok {
			ep.SecurityGroups = append(ep.SecurityGroups,
				etcd.GroupInfo{Group: env.cont.aciNameForKey("np", cinfo.AppId),
					Tenant: env.cont.config.AciPolicyTenant})
		}
		if len(appInfo.ExternalIp) > 0 {
			ep.SecurityGroups = append(ep.SecurityGroups,
				etcd.GroupInfo{Group: env.cont.aciNameForKey("hpp", "app-ext-ip"),
					Tenant: env.cont.config.AciPolicyTenant})
		}
		if len(env.GetAdditionalPorts(cinfo)) > 0 {
			ep.SecurityGroups = append(ep.SecurityGroups,
				etcd.GroupInfo{Group: env.cont.aciNameForKey("hpp", "app-port:"+cinfo.AppId),
					Tenant: env.cont.config.AciPolicyTenant})
		}
		ep_json, err := json.Marshal(ep)
		if err != nil {
			env.log.Error("Unable to serialize EP info: ", err)
		} else {
			kapi := env.etcdKeysApi
			_, err = kapi.Set(context.Background(), ctKey+"/ep", string(ep_json), nil)
			if err != nil {
				env.log.Error("Error setting container info: ", err)
				retry = true
			} else {
				env.log.Debug(fmt.Sprintf("Wrote to etcd %s = %s", ctKey+"/ep", string(ep_json)))
			}
		}
	}
	if spaceInfo != nil {
		conf := env.cont.config
		injContGrp := apicapi.NewVmmInjectedOrgUnitContGrp(conf.AciVmmDomainType,
			conf.AciVmmDomain, conf.AciVmmController, spaceInfo.OrgId,
			spaceInfo.SpaceId, cinfo.ContainerId)
		injContGrp.SetAttr("deploymentName", cinfo.AppId)
		// TODO Uncomment when ACI supports 'descr'
		//injContGrp.SetAttr("descr", ep.EpName(cinfo.ContainerId))
		if cinfo.CellId != "" {
			node := "diego-cell-" + cinfo.CellId
			injContGrp.SetAttr("hostName", node)
			injContGrp.SetAttr("computeNodeName", node)
		}
		env.cont.apicConn.WriteApicObjects("inj_contgrp:"+cinfo.ContainerId,
			apicapi.ApicSlice{injContGrp})
	}
	return retry
}

func (env *CfEnvironment) handleContainerDeleteLocked(cinfo *ContainerInfo) bool {
	retry := false
	env.log.Debug(fmt.Sprintf("Handling container delete: %+v", *cinfo))
	if cinfo.CellId != "" {
		env.cont.indexMutex.Lock()
		env.cont.removePodFromNode(cinfo.CellId, cinfo.ContainerId)
		env.cont.indexMutex.Unlock()

		kapi := env.etcdKeysApi
		ctKey := etcd.CELL_KEY_BASE + "/" + cinfo.CellId + "/containers/" + cinfo.ContainerId
		_, err := kapi.Delete(context.Background(), ctKey, &etcdclient.DeleteOptions{Recursive: true})
		if err != nil {
			env.log.Error("Error deleting container node: ", err)
			retry = true
		}
	}
	env.cont.apicConn.ClearApicObjects("inj_contgrp:" + cinfo.ContainerId)
	return retry
}

func (env *CfEnvironment) handleAppUpdateLocked(appId string) bool {
	retry := false
	ainfo, ok := env.appIdx[appId]
	if !ok || ainfo == nil {
		return false
	}
	spi := env.spaceIdx[ainfo.SpaceId]
	env.log.Debug(fmt.Sprintf("Handling app update: %+v", ainfo))

	ai := etcd.AppInfo{}
	if ainfo.VipV4 != "" {
		ai.VirtualIp = append(ai.VirtualIp, ainfo.VipV4)
	}
	if ainfo.VipV6 != "" {
		ai.VirtualIp = append(ai.VirtualIp, ainfo.VipV6)
	}
	addPorts := make(map[int]struct{})
	for cid, cip := range ainfo.ContainerIps {
		if cinfo := env.contIdx[cid]; cinfo != nil {
			if cinfo.IsApp() {
				ai.ContainerIps = append(ai.ContainerIps, cip)
			}
			for p := range env.GetAdditionalPorts(cinfo) {
				addPorts[p] = struct{}{}
			}
		}
	}
	sort.Strings(ai.ContainerIps) // mainly done for unit-tests
	for _, eip := range ainfo.ExternalIp {
		ai.ExternalIp = append(ai.ExternalIp, eip)
	}
	app_json, err := json.Marshal(ai)
	if err != nil {
		env.log.Error("Unable to serialize App info: ", err)
	} else {
		kapi := env.etcdKeysApi
		appKey := etcd.APP_KEY_BASE + "/" + appId
		_, err = kapi.Set(context.Background(), appKey, string(app_json), nil)
		if err != nil {
			env.log.Error("Error setting app info: ", err)
			retry = true
		}
	}
	if len(ai.ExternalIp) > 0 {
		sgobjs := env.createAppServiceGraph(appId, ai.ExternalIp)
		env.cont.apicConn.WriteApicObjects("app_ext_ip:"+appId, sgobjs)
	} else {
		env.cont.apicConn.ClearApicObjects("app_ext_ip:" + appId)
	}

	if len(addPorts) > 0 && (len(ai.ExternalIp) > 0 ||
		len(env.goRouterIps) > 0 ||
		len(env.tcpRouterIps) > 0) {
		appHppName := env.cont.aciNameForKey("hpp", "app-port:"+appId)
		hpp := apicapi.NewHostprotPol(env.cont.config.AciPolicyTenant, appHppName)

		appSubj := apicapi.NewHostprotSubj(hpp.GetDn(), "app-ingress")
		appDn := appSubj.GetDn()
		for p, _ := range addPorts {
			ps := fmt.Sprintf("%d", p)
			appPort := apicapi.NewHostprotRule(appDn, "app-port:"+ps)
			appPort.SetAttr("direction", "ingress")
			appPort.SetAttr("ethertype", "ipv4") // TODO separate out v6
			appPort.SetAttr("toPort", ps)
			appPort.SetAttr("protocol", "tcp")
			if len(ai.ExternalIp) == 0 {
				for _, ip := range env.goRouterIps {
					remote := apicapi.NewHostprotRemoteIp(appPort.GetDn(), ip)
					appPort.AddChild(remote)
				}
				for _, ip := range env.tcpRouterIps {
					remote := apicapi.NewHostprotRemoteIp(appPort.GetDn(), ip)
					appPort.AddChild(remote)
				}
			}
			appSubj.AddChild(appPort)
		}
		hpp.AddChild(appSubj)
		env.cont.apicConn.WriteApicObjects("app-port:"+appId, apicapi.ApicSlice{hpp})
	} else {
		env.cont.apicConn.ClearApicObjects("app-port:" + appId)
	}

	// find destination PolIds for which this App is a source
	var dstPolIds []string
	for k, info := range env.netpolIdx {
		if _, ok := info[appId]; ok {
			dstPolIds = append(dstPolIds, k)
		}
	}
	env.log.Debug("Dst policy Ids to update: ", dstPolIds)
	for _, d := range dstPolIds {
		hpp := env.createHppForNetPol(&d)
		env.cont.apicConn.WriteApicObjects("np:"+d, hpp)
	}

	if spi != nil {
		conf := env.cont.config
		injDepl := apicapi.NewVmmInjectedOrgUnitDepl(conf.AciVmmDomainType,
			conf.AciVmmDomain, conf.AciVmmController, spi.OrgId,
			spi.SpaceId, ainfo.AppId)
		injDepl.SetAttr("nameAlias", ainfo.AppName)
		injDepl.SetAttr("replicas", fmt.Sprintf("%d", ainfo.Instances))
		env.cont.apicConn.WriteApicObjects("inj_depl:"+ainfo.AppId,
			apicapi.ApicSlice{injDepl})
	}
	return retry
}

func (env *CfEnvironment) handleAppUpdate(appId string) bool {
	env.indexLock.Lock()
	defer env.indexLock.Unlock()
	return env.handleAppUpdateLocked(appId)
}

// must be called with indexLock locked
func (env *CfEnvironment) createAppServiceGraph(appId string, extIps []string) apicapi.ApicSlice {
	ainfo := env.appIdx[appId]
	if ainfo == nil {
		return nil
	}
	cont := env.cont
	cont.indexMutex.Lock()
	nodeMap := make(map[string]*metadata.ServiceEndpoint)
	for cid, _ := range ainfo.ContainerIps {
		if cinfo, _ := env.contIdx[cid]; cinfo != nil {
			nodename := "diego-cell-" + cinfo.CellId
			nodeMeta, ok := cont.nodeServiceMetaCache[nodename]
			if !ok {
				continue
			}
			_, ok = cont.fabricPathForNode(nodename)
			if !ok {
				continue
			}
			nodeMap[nodename] = &nodeMeta.serviceEp
		}
	}
	cont.indexMutex.Unlock()

	var nodes []string
	for node, _ := range nodeMap {
		nodes = append(nodes, node)
	}
	sort.Strings(nodes)

	name := cont.aciNameForKey("ext", appId)
	graphName := cont.aciNameForKey("svc", "global")
	var serviceObjs apicapi.ApicSlice

	if len(nodes) > 0 {
		// 1. Service redirect policy
		rp, rpDn :=
			apicRedirectPol(name, cont.config.AciVrfTenant, nodes, nodeMap)
		serviceObjs = append(serviceObjs, rp)

		// 2. Service graph contract and external network
		serviceObjs = append(serviceObjs,
			apicExtNet(name, cont.config.AciVrfTenant,
				cont.config.AciL3Out, extIps))

		serviceObjs = append(serviceObjs,
			apicContract(name, cont.config.AciVrfTenant, graphName))

		for _, net := range cont.config.AciExtNetworks {
			serviceObjs = append(serviceObjs,
				apicExtNetCons(name, cont.config.AciVrfTenant,
					cont.config.AciL3Out, net))
		}
		{
			filter := apicapi.NewVzFilter(cont.config.AciVrfTenant, name)
			fe := apicapi.NewVzEntry(filter.GetDn(), "tcp")
			fe.SetAttr("etherT", "ip")
			fe.SetAttr("prot", "tcp")
			filter.AddChild(fe)
			serviceObjs = append(serviceObjs, filter)
		}

		// 3. Device cluster context
		serviceObjs = append(serviceObjs,
			apicDevCtx(name, cont.config.AciVrfTenant, graphName,
				cont.aciNameForKey("bd", cont.env.ServiceBd()), rpDn))
	}
	return serviceObjs
}

func (env *CfEnvironment) handleAppDeleteLocked(appId string, ainfo *AppInfo) bool {
	retry := false
	kapi := env.etcdKeysApi
	appKey := etcd.APP_KEY_BASE + "/" + appId
	_, err := kapi.Delete(context.Background(), appKey, &etcdclient.DeleteOptions{Recursive: true})
	if err != nil {
		env.log.Error("Error deleting app etcd node: ", err)
		retry = true
	}

	env.cleanupEpgAnnotation(appId, CF_OBJ_APP)
	env.releaseAppVip(appId)
	env.releaseAppExtIp(appId)
	env.cont.apicConn.ClearApicObjects("app_ext_ip:" + appId)
	env.cont.apicConn.ClearApicObjects("app-port:" + appId)
	env.cont.apicConn.ClearApicObjects("inj_depl:" + appId)
	return retry
}

func (env *CfEnvironment) handleAppDelete(ainfo *AppInfo) bool {
	env.indexLock.Lock()
	defer env.indexLock.Unlock()
	return env.handleAppDeleteLocked(ainfo.AppId, ainfo)
}

func (env *CfEnvironment) scheduleAppContainersUpdateLocked(appId string) {
	ai := env.appIdx[appId]
	if ai == nil {
		return
	}
	for k := range ai.ContainerIps {
		env.containerUpdateQ.Add(k)
	}
}

func (env *CfEnvironment) scheduleAppContainersUpdate(appId string) {
	env.indexLock.Lock()
	defer env.indexLock.Unlock()
	env.scheduleAppContainersUpdateLocked(appId)
}

func (env *CfEnvironment) processSpaceChanges(obj interface{}) bool {
	switch obj := obj.(type) {
	case string:
		return env.handleSpaceUpdate(obj)
	case *SpaceInfo:
		return env.handleSpaceDelete(obj)
	}
	return false
}

func (env *CfEnvironment) handleSpaceUpdate(spaceId string) bool {
	env.indexLock.Lock()
	defer env.indexLock.Unlock()

	retry := false
	spi := env.spaceIdx[spaceId]
	if spi == nil {
		return retry
	}
	conf := env.cont.config
	injSpace := apicapi.NewVmmInjectedOrgUnit(conf.AciVmmDomainType,
		conf.AciVmmDomain, conf.AciVmmController, spi.OrgId, spi.SpaceId)
	injSpace.SetAttr("nameAlias", spi.SpaceName)
	env.cont.apicConn.WriteApicObjects("inj_orgunit:"+spi.SpaceId,
		apicapi.ApicSlice{injSpace})
	return retry
}

func (env *CfEnvironment) handleSpaceDelete(sinfo *SpaceInfo) bool {
	env.indexLock.Lock()
	defer env.indexLock.Unlock()
	return env.handleSpaceDeleteLocked(sinfo.SpaceId, sinfo)
}

func (env *CfEnvironment) handleSpaceDeleteLocked(spaceId string, sinfo *SpaceInfo) bool {
	retry := false
	env.cleanupEpgAnnotation(spaceId, CF_OBJ_SPACE)
	env.cont.apicConn.ClearApicObjects("inj_orgunit:" + spaceId)
	return retry
}

func (env *CfEnvironment) scheduleSpaceContainersUpdateLocked(spaceId string) {
	for id, a := range env.appIdx {
		if a != nil && a.SpaceId == spaceId {
			env.scheduleAppContainersUpdateLocked(id)
		}
	}
}

func (env *CfEnvironment) scheduleSpaceContainersUpdate(spaceId string) {
	env.indexLock.Lock()
	defer env.indexLock.Unlock()
	env.scheduleSpaceContainersUpdateLocked(spaceId)
}

func (env *CfEnvironment) processOrgChanges(obj interface{}) bool {
	switch obj := obj.(type) {
	case string:
		return env.handleOrgUpdate(obj)
	case *OrgInfo:
		return env.handleOrgDelete(obj)
	}
	return false
}

func (env *CfEnvironment) scheduleOrgContainersUpdateLocked(orgId string) {
	for id, s := range env.spaceIdx {
		if s != nil && s.OrgId == orgId {
			env.scheduleSpaceContainersUpdateLocked(id)
		}
	}
}

func (env *CfEnvironment) handleOrgUpdate(orgId string) bool {
	env.indexLock.Lock()
	defer env.indexLock.Unlock()

	retry := false
	oinfo := env.orgIdx[orgId]
	if oinfo == nil {
		return retry
	}
	conf := env.cont.config
	injOrg := apicapi.NewVmmInjectedOrg(conf.AciVmmDomainType,
		conf.AciVmmDomain, conf.AciVmmController, oinfo.OrgId)
	injOrg.SetAttr("nameAlias", oinfo.OrgName)
	env.cont.apicConn.WriteApicObjects("inj_org:"+oinfo.OrgId,
		apicapi.ApicSlice{injOrg})
	return retry
}

func (env *CfEnvironment) handleOrgDelete(oinfo *OrgInfo) bool {
	env.indexLock.Lock()
	defer env.indexLock.Unlock()
	return env.handleOrgDeleteLocked(oinfo.OrgId, oinfo)
}

func (env *CfEnvironment) handleOrgDeleteLocked(orgId string, oinfo *OrgInfo) bool {
	retry := false
	env.cleanupEpgAnnotation(orgId, CF_OBJ_ORG)
	env.cont.apicConn.ClearApicObjects("inj_org:" + orgId)
	return retry
}

func (env *CfEnvironment) scheduleOrgContainersUpdate(orgId string) {
	env.indexLock.Lock()
	defer env.indexLock.Unlock()
	env.scheduleOrgContainersUpdateLocked(orgId)
}

type Range struct {
	start string
	end   string
}

func splitIntoRanges(input *string) []Range {
	var ranges []Range
	if *input == "" {
		return ranges
	}
	for _, cp := range strings.Split(*input, ",") {
		parts := strings.Split(cp, "-")
		if len(parts) <= 2 {
			ranges = append(ranges,
				Range{start: strings.TrimSpace(parts[0]),
					end: strings.TrimSpace(parts[len(parts)-1])})
		}
	}
	return ranges
}

func (env *CfEnvironment) convertAsgRule(rule *cfclient.SecGroupRule,
	parentDn *string, baseName *string) apicapi.ApicSlice {
	var remotes []*net.IPNet
	if rule.Destination == "" {
		remotes = append(remotes, &net.IPNet{IP: net.IPv4(0, 0, 0, 0), Mask: net.IPv4Mask(0, 0, 0, 0)})
	} else {
		dsts := splitIntoRanges(&rule.Destination)
		for _, d := range dsts {
			if strings.Contains(d.start, "/") {
				_, n, _ := net.ParseCIDR(d.start)
				remotes = append(remotes, n)
			} else {
				for _, n := range ipam.Range2Cidr(net.ParseIP(d.start), net.ParseIP(d.end)) {
					remotes = append(remotes, n)
				}
			}
		}
	}

	var ports []Range
	if rule.Ports == "" {
		ports = []Range{Range{start: "unspecified", end: "unspecified"}}
	} else {
		ports = splitIntoRanges(&rule.Ports)
	}

	proto := "unspecified"
	if rule.Protocol == "tcp" || rule.Protocol == "udp" || rule.Protocol == "icmp" {
		proto = rule.Protocol
	} else {
		env.log.Debug(fmt.Sprintf("Unsupported protocol in rule %v", *rule))
		return apicapi.ApicSlice{}
	}
	// TODO convert Log

	var hprs apicapi.ApicSlice
	for pi, port := range ports {
		hpr := apicapi.NewHostprotRule(*parentDn, fmt.Sprintf("%s_%d", *baseName, pi))
		hpr.SetAttr("direction", "egress")
		hpr.SetAttr("ethertype", "ipv4") // TODO use dst address
		hpr.SetAttr("protocol", proto)
		if proto == "icmp" {
			hpr.SetAttr("icmpType", fmt.Sprintf("%d", rule.Type))
			hpr.SetAttr("icmpCode", fmt.Sprintf("%d", rule.Code))
		}
		hpr.SetAttr("fromPort", port.start)
		hpr.SetAttr("toPort", port.end)
		for _, r := range remotes {
			hpremote := apicapi.NewHostprotRemoteIp(hpr.GetDn(), r.String())
			hpr.AddChild(hpremote)
		}
		hprs = append(hprs, hpr)
	}
	return hprs
}

func (env *CfEnvironment) handleAsgUpdate(asgId string) bool {
	env.indexLock.Lock()
	defer env.indexLock.Unlock()

	retry := false
	sginfo := env.asgIdx[asgId]
	if sginfo == nil {
		return false
	}
	env.log.Debug(fmt.Sprintf("Handling ASG update %s: rules %v", asgId, sginfo.Rules))

	cont := env.cont

	asgApicName := cont.aciNameForKey("asg", asgId)
	hpp := apicapi.NewHostprotPol(cont.config.AciPolicyTenant, asgApicName)
	hpp.SetAttr("nameAlias", "asg_"+sginfo.Name)
	egressSubj := apicapi.NewHostprotSubj(hpp.GetDn(), "egress")
	subjDn := egressSubj.GetDn()
	for ri, rule := range sginfo.Rules {
		baseName := fmt.Sprintf("rule%d", ri)
		for _, hpr := range env.convertAsgRule(&rule, &subjDn, &baseName) {
			egressSubj.AddChild(hpr)
		}
	}
	hpp.AddChild(egressSubj)

	cont.apicConn.WriteApicObjects("asg:"+asgId, apicapi.ApicSlice{hpp})
	return retry
}

func (env *CfEnvironment) handleAsgDelete(sginfo *cfclient.SecGroup) bool {
	env.indexLock.Lock()
	defer env.indexLock.Unlock()
	return env.handleAsgDeleteLocked(sginfo.Guid, sginfo)
}

func (env *CfEnvironment) handleAsgDeleteLocked(asgId string, sginfo *cfclient.SecGroup) bool {
	retry := false
	env.cont.apicConn.ClearApicObjects("asg:" + asgId)
	return retry
}
