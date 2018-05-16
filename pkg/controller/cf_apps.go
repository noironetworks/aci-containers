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
	"hash/fnv"
	"net"
	"net/url"
	"reflect"
	"strings"
	"time"

	"code.cloudfoundry.org/bbs/models"

	cfclient "github.com/cloudfoundry-community/go-cfclient"

	"github.com/noironetworks/aci-containers/pkg/apicapi"
	"github.com/noironetworks/aci-containers/pkg/cf_common"
	"github.com/noironetworks/aci-containers/pkg/cfapi"
)

type ContainerInfo struct {
	ContainerId   string
	CellId        string
	InstanceIndex int32
	IpAddress     string
	Ports         []*models.PortMapping
	AppId         string
	TaskName      string
}

func (a *ContainerInfo) IsStaging() bool {
	return a.InstanceIndex == cf_common.INST_IDX_STAGING
}

func (a *ContainerInfo) IsApp() bool {
	return a.InstanceIndex >= 0
}

type AppInfo struct {
	AppId        string
	SpaceId      string
	AppName      string
	Instances    int32
	ContainerIps map[string]string
	VipV4        string
	VipV6        string
	ExternalIp   []string
}

func NewAppInfo(appId string) *AppInfo {
	return &AppInfo{AppId: appId, ContainerIps: make(map[string]string)}
}

type SpaceInfo struct {
	SpaceId               string
	SpaceName             string
	OrgId                 string
	RunningSecurityGroups []string
	StagingSecurityGroups []string
	IsolationSegment      string
}

type OrgInfo struct {
	OrgId   string
	OrgName string
}

type IsoSegInfo struct {
	Id   string
	Name string
}

func (env *CfEnvironment) constructAppInfo(app *AppAndSpace) *AppInfo {
	appInfo := NewAppInfo(app.AppId)
	appInfo.AppName = app.AppName
	appInfo.SpaceId = app.SpaceId

	aei_db := AppExtIpDb{}
	txn, _ := env.db.Begin()
	ext_ip_alloc, err := aei_db.Get(txn, app.AppId)
	if err != nil {
		env.log.Error("Failed to get app external IPs: ", err)
	} else {
		for _, i := range ext_ip_alloc {
			appInfo.ExternalIp = append(appInfo.ExternalIp, i.IP)
		}
	}
	txn.Commit()

	appInfo.VipV4, appInfo.VipV6 = env.getOrAllocateAppVip(app.AppId)
	return appInfo
}

func (env *CfEnvironment) mergeAppInfo(nw *AppInfo, updateInstances bool) bool {
	old := env.appIdx[nw.AppId]
	if old == nil {
		env.appIdx[nw.AppId] = nw
		return true
	}
	if nw.AppName == "" {
		nw.AppName = old.AppName
	}
	if nw.SpaceId == "" {
		nw.SpaceId = old.SpaceId
	}
	for k, v := range old.ContainerIps {
		_, ok := nw.ContainerIps[k]
		if !ok {
			nw.ContainerIps[k] = v
		}
	}
	if !updateInstances {
		nw.Instances = old.Instances
	}
	if !reflect.DeepEqual(old, nw) {
		env.appIdx[nw.AppId] = nw
		return true
	}
	return false
}

func (env *CfEnvironment) mergeContainerInfo(nw *ContainerInfo) bool {
	old := env.contIdx[nw.ContainerId]
	if old == nil {
		env.contIdx[nw.ContainerId] = nw
		return true
	}
	if nw.AppId == "" {
		nw.AppId = old.AppId
	}
	if nw.CellId == "" {
		nw.CellId = old.CellId
	}
	if nw.IpAddress == "" {
		nw.IpAddress = old.IpAddress
	}
	if !reflect.DeepEqual(old, nw) {
		env.contIdx[nw.ContainerId] = nw
		return true
	}
	return false
}

func (env *CfEnvironment) scheduleAppAndSpaceUpdate(appInfo *AppInfo) {
	if appInfo.SpaceId != "" {
		env.spaceFetchQ.Add(appInfo.SpaceId)
	}
	env.appUpdateQ.Add(appInfo.AppId)
}

func hashJsonSerializable(obj interface{}) (uint64, error) {
	js, err := json.Marshal(obj)
	if err != nil {
		return 0, err
	}
	hasher := fnv.New64()
	hasher.Reset()
	_, err = hasher.Write(js)
	if err != nil {
		return 0, err
	}
	return hasher.Sum64(), nil
}

func (env *CfEnvironment) GetAdditionalPorts(cinfo *ContainerInfo) []uint32 {
	var res []uint32
	for _, pm := range cinfo.Ports {
		if pm.ContainerPort != env.cfconfig.AppPort && pm.ContainerPort != env.cfconfig.SshPort {
			res = append(res, pm.ContainerPort)
		}
	}
	return res
}

func (env *CfEnvironment) fetchSpaceInfo(spaceId *string) (*SpaceInfo, []*cfclient.SecGroup, error) {
	sp, err := env.ccClient.GetSpaceByGuid(*spaceId)
	if err != nil {
		env.log.Error("Error fetching info for space "+*spaceId+": ", err)
		return nil, nil, err
	}
	spi := SpaceInfo{SpaceId: sp.Guid, OrgId: sp.OrganizationGuid,
		SpaceName: sp.Name}

	// fetch isolation segment info
	isoseg, err := env.ccClient.GetSpaceIsolationSegment(sp.Guid)
	if err != nil {
		env.log.Error("Error fetching isolation segment for space "+*spaceId+": ", err)
		return &spi, nil, err
	}
	if isoseg == "" {
		isoseg, err = env.ccClient.GetOrgDefaultIsolationSegment(sp.OrganizationGuid)
		if err != nil {
			env.log.Error("Error fetching default segment for org "+sp.OrganizationGuid+": ", err)
			return &spi, nil, err
		}
	}
	spi.IsolationSegment = isoseg

	// fetch ASG info
	runsg, err := env.ccClient.ListSecGroupsBySpace(*spaceId, false)
	if err != nil {
		env.log.Error("Error fetching running ASGs for space "+*spaceId+": ", err)
		return &spi, nil, err
	}
	stagesg, err := env.ccClient.ListSecGroupsBySpace(*spaceId, true)
	if err != nil {
		env.log.Error("Error fetching staging ASGs for space "+*spaceId+": ", err)
		return &spi, nil, err
	}
	var allsgs []*cfclient.SecGroup
	for i := range runsg {
		spi.RunningSecurityGroups = append(spi.RunningSecurityGroups, runsg[i].Guid)
		allsgs = append(allsgs, &runsg[i])
	}
	for i := range stagesg {
		spi.StagingSecurityGroups = append(spi.StagingSecurityGroups, stagesg[i].Guid)
		allsgs = append(allsgs, &stagesg[i])
	}
	return &spi, allsgs, nil
}

func (env *CfEnvironment) spaceFetchQueueHandler(spaceId interface{}) bool {
	var err error
	id := spaceId.(string)
	spi, allsgs, err := env.fetchSpaceInfo(&id)
	if err != nil {
		return true
	}
	var iseg *cfclient.IsolationSegment
	if spi.IsolationSegment != "" {
		iseg, err = env.ccClient.GetIsolationSegmentByGUID(spi.IsolationSegment)
		if err != nil {
			env.log.Error("Error fetching info for isolation segment "+spi.IsolationSegment+": ", err)
			return true
		}
	}
	org, err := env.ccClient.GetOrgByGuid(spi.OrgId)
	if err != nil {
		env.log.Error("Error fetching org info for "+spi.OrgId+": ", err)
		return true
	}
	oinfo := &OrgInfo{OrgId: org.Guid, OrgName: org.Name}

	env.indexLock.Lock()
	defer env.indexLock.Unlock()

	// update org
	oldorg := env.orgIdx[oinfo.OrgId]
	if oldorg == nil || !reflect.DeepEqual(oldorg, oinfo) {
		env.orgIdx[oinfo.OrgId] = oinfo
		env.orgChangesQ.Add(oinfo.OrgId)
	}
	// update space
	oldspace := env.spaceIdx[spi.SpaceId]
	if oldspace == nil || !reflect.DeepEqual(oldspace, spi) {
		env.spaceIdx[spi.SpaceId] = spi
		env.spaceChangesQ.Add(spi.SpaceId)
		env.log.Debug("Updating containers in space ", spi.SpaceId)
		env.scheduleSpaceContainersUpdateLocked(spi.SpaceId)
	}
	// update ASGs
	for _, sg := range allsgs {
		oldsg := env.asgIdx[sg.Guid]
		newsg := sg
		if oldsg == nil || !reflect.DeepEqual(oldsg, newsg) {
			env.asgIdx[sg.Guid] = newsg
			env.log.Debug("Updating ASG ", newsg.Guid)
			env.asgUpdateQ.Add(newsg.Guid)
		}
	}
	// update isolation-segment
	if iseg != nil {
		env.isoSegIdx[iseg.GUID] = &IsoSegInfo{Id: iseg.GUID, Name: iseg.Name}
		// TODO: Check if name has changed, and if so update all containers in the isolation segment
	}
	return false
}

func NewNetworkPolicyPoller(env *CfEnvironment) *CfPoller {

	pollFunc := func() (map[string]interface{}, interface{}, error) {
		allNetPol, err := env.netpolClient.GetPolicies()
		if err != nil {
			return nil, nil, err
		}
		var newRespHashIf interface{}
		newRespHash, err := hashJsonSerializable(allNetPol)
		if err != nil {
			env.log.Warning("Failed to hash network policies response: ", err)
			newRespHashIf = nil
		} else {
			newRespHashIf = &newRespHash
		}
		npRead := make(map[string]interface{})
		for _, npol := range allNetPol {
			dst := npol.Destination.ID
			npol.Destination.ID = npol.Source.ID

			npDstIf, ok := npRead[dst]
			var npDst map[string][]cfapi.Destination
			if !ok {
				npDst = make(map[string][]cfapi.Destination)
			} else {
				npDst = npDstIf.(map[string][]cfapi.Destination)
			}
			npDst[npol.Source.ID] = append(npDst[npol.Source.ID], npol.Destination)
			npRead[dst] = npDst
		}
		return npRead, newRespHashIf, nil
	}

	handleFunc := func(updates map[string]interface{}, deletes map[string]interface{}) {
		env.indexLock.Lock()
		defer env.indexLock.Unlock()

		for k, v := range updates {
			env.log.Debug(fmt.Sprintf("Add/update net pol %s: %+v", k, v))
			env.netpolIdx[k] = v.(map[string][]cfapi.Destination)

			hpp := env.createHppForNetPol(&k)
			env.cont.apicConn.WriteApicObjects("np:"+k, hpp)
			env.scheduleAppContainersUpdateLocked(k)
		}
		for k := range deletes {
			env.log.Debug("Delete net pol ", k)
			delete(env.netpolIdx, k)
			env.cont.apicConn.ClearApicObjects("np:" + k)
			env.scheduleAppContainersUpdateLocked(k)
		}
	}
	pollInterval := time.Duration(env.cfconfig.NetPolPollingInterval) * time.Second
	errDelay := 10 * time.Second
	return NewCfPoller("Network-policy", pollInterval, errDelay, pollFunc, handleFunc, env.log)
}

func (env *CfEnvironment) createHppForNetPol(polId *string) apicapi.ApicSlice {
	// must be called with index lock

	npApicName := env.cont.aciNameForKey("np", *polId)
	hpp := apicapi.NewHostprotPol(env.cont.config.AciPolicyTenant, npApicName)
	for srcId, info := range env.netpolIdx[*polId] {
		ingressSubj := apicapi.NewHostprotSubj(hpp.GetDn(), "in-"+srcId)
		subjDn := ingressSubj.GetDn()
		for i, rule := range info {
			hpr := apicapi.NewHostprotRule(subjDn, fmt.Sprintf("rule_%d", i))
			hpr.SetAttr("direction", "ingress")
			hpr.SetAttr("ethertype", "ipv4") // TODO fix for v6
			hpr.SetAttr("protocol", rule.Protocol)
			hpr.SetAttr("fromPort", fmt.Sprintf("%d", rule.Ports.Start))
			hpr.SetAttr("toPort", fmt.Sprintf("%d", rule.Ports.End))

			app := env.appIdx[srcId]
			if app != nil {
				for _, ip := range app.ContainerIps {
					hpremote := apicapi.NewHostprotRemoteIp(hpr.GetDn(), ip)
					hpr.AddChild(hpremote)
				}
			}
			ingressSubj.AddChild(hpr)
		}
		hpp.AddChild(ingressSubj)
	}
	return apicapi.ApicSlice{hpp}
}

func (env *CfEnvironment) getOrAllocateAppVip(appId string) (string, string) {
	txn, _ := env.db.Begin()
	defer txn.Commit()
	ipdb := AppVipDb{}

	db_v4, db_v6, err := ipdb.Get(txn, appId)
	if err != nil {
		env.log.Error("Failed to get app virtual IP: ", err)
		return "", ""
	}

	var v4, v6 net.IP
	var new_v4, new_v6 string
	if db_v4 != "" {
		v4 = net.ParseIP(db_v4)
	}
	if v4 == nil {
		v4, _ = env.appVips.V4.GetIp()
		if v4 != nil {
			env.log.Debug(fmt.Sprintf("Allocated v4 VIP %s to app %s", v4.String(), appId))
		}
	}
	if v4 != nil {
		new_v4 = v4.String()
	}

	if db_v6 != "" {
		v6 = net.ParseIP(db_v6)
	}
	if v6 == nil {
		v6, _ = env.appVips.V6.GetIp()
		if v6 != nil {
			env.log.Debug(fmt.Sprintf("Allocated v6 VIP %s to app %s", v6.String(), appId))
		}
	}
	if v6 != nil {
		new_v6 = v6.String()
	}

	if db_v4 != new_v4 || db_v6 != new_v6 {
		err = ipdb.Set(txn, appId, new_v4, new_v6)
		if err != nil {
			env.log.Error("Failed to set app virtual IP: ", err)
			if v4 != nil {
				env.appVips.V4.AddIp(v4)
			}
			if v6 != nil {
				env.appVips.V6.AddIp(v6)
			}
			return "", ""
		}
	}
	return new_v4, new_v6
}

func (env *CfEnvironment) LoadEpgAnnotations() {
	txn, _ := env.db.Begin()
	defer txn.Commit()
	epgdb := EpgAnnotationDb{}

	objs, err := epgdb.List(txn, CF_OBJ_LAST)
	if err != nil {
		env.log.Warn("Unable to load EPG annotations from DB: ", err)
		return
	}

	env.indexLock.Lock()
	defer env.indexLock.Unlock()

	for _, obj := range objs {
		env.lookupOrCreate(obj.Guid, obj.Kind)
	}
}

// must be called with index lock
func (env *CfEnvironment) lookupOrCreate(objId string, kind int) interface{} {
	var res interface{}
	switch kind {
	case CF_OBJ_APP:
		ainfo := env.appIdx[objId]
		if ainfo == nil {
			ainfo = NewAppInfo(objId)
		}
		env.appIdx[objId] = ainfo
		res = ainfo
	case CF_OBJ_SPACE:
		sinfo := env.spaceIdx[objId]
		if sinfo == nil {
			sinfo = &SpaceInfo{SpaceId: objId}
		}
		env.spaceIdx[objId] = sinfo
		res = sinfo
	case CF_OBJ_ORG:
		oinfo := env.orgIdx[objId]
		if oinfo == nil {
			oinfo = &OrgInfo{OrgId: objId}
		}
		env.orgIdx[objId] = oinfo
		res = oinfo
	}
	return res
}

func (env *CfEnvironment) cleanupEpgAnnotation(objId string, kind int) {
	ea_db := EpgAnnotationDb{}
	txn, _ := env.db.Begin()

	err := ea_db.DeleteAnnotation(txn, objId, kind)
	if err == nil {
		txn.Commit()
	} else {
		env.log.Error("Failed to delete epg annotation: ", err)
		txn.Rollback()
	}
}

func (env *CfEnvironment) releaseAppVip(appId string) {
	txn, _ := env.db.Begin()
	ipdb := AppVipDb{}

	db_v4, db_v6, err := ipdb.Get(txn, appId)
	if err != nil {
		env.log.Error("Failed to get app virtual IP: ", err)
		return
	}
	err = ipdb.Delete(txn, appId)
	if err != nil {
		env.log.Error("Failed to delete app virtual IP: ", err)
		txn.Rollback()
		return
	}
	if db_v4 != "" {
		v4 := net.ParseIP(db_v4)
		if v4 != nil {
			env.appVips.V4.AddIp(v4)
		}
	}
	if db_v6 != "" {
		v6 := net.ParseIP(db_v6)
		if v6 != nil {
			env.appVips.V6.AddIp(v6)
		}
	}
	txn.Commit()
}

func (env *CfEnvironment) LoadAppVips() {
	txn, _ := env.db.Begin()
	defer txn.Commit()
	ipdb := AppVipDb{}

	ips, err := ipdb.List(txn)
	if err != nil {
		env.log.Warn("Unable to load app virtual IPs from DB: ", err)
		return
	}

	env.indexLock.Lock()
	defer env.indexLock.Unlock()

	for _, ipa := range ips {
		ainfo := env.appIdx[ipa.Guid]
		if ainfo == nil {
			ainfo = NewAppInfo(ipa.Guid)
		}
		ainfo.VipV4 = ipa.IPv4
		ainfo.VipV6 = ipa.IPv6
		env.appIdx[ipa.Guid] = ainfo
		v4 := net.ParseIP(ipa.IPv4)
		if v4 != nil && v4.To4() != nil {
			env.appVips.V4.RemoveIp(v4) // TODO reset IP if this fails
		}
		v6 := net.ParseIP(ipa.IPv6)
		if v6 != nil && v6.To16() != nil {
			env.appVips.V6.RemoveIp(v6) // TODO reset IP if this fails
		}
	}
}

func (env *CfEnvironment) releaseAppExtIp(appId string) {
	aei_db := AppExtIpDb{}
	txn, _ := env.db.Begin()

	ips, err := aei_db.Get(txn, appId)
	if err != nil {
		env.log.Warn("Failed to read app external IP: ", err)
		return
	}
	err = aei_db.Delete(txn, appId)
	if err != nil {
		env.log.Error("Failed to delete app external IP: ", err)
		txn.Rollback()
		return
	}
	env.ManageAppExtIp(ips, nil, false)
	txn.Commit()
}

func (env *CfEnvironment) LoadAppExtIps() {
	txn, _ := env.db.Begin()
	defer txn.Commit()
	ipdb := AppExtIpDb{}

	ips, err := ipdb.List(txn)
	if err != nil {
		env.log.Warn("Unable to load app external IPs from DB: ", err)
		return
	}

	env.indexLock.Lock()
	defer env.indexLock.Unlock()

	env.cont.indexMutex.Lock()
	defer env.cont.indexMutex.Unlock()

	for _, ipa := range ips {
		ainfo := env.appIdx[ipa.Guid]
		if ainfo == nil {
			ainfo = NewAppInfo(ipa.Guid)
		}
		ainfo.ExternalIp = append(ainfo.ExternalIp, ipa.IP)
		env.appIdx[ipa.Guid] = ainfo
		ip := net.ParseIP(ipa.IP)
		if ip == nil {
			continue
		}
		if ipa.Dynamic {
			env.cont.serviceIps.RemoveIp(ip)
		} else {
			if ip.To4() != nil {
				env.cont.staticServiceIps.V4.RemoveIp(ip)
			} else if ip != nil && ip.To16() != nil {
				env.cont.staticServiceIps.V6.RemoveIp(ip)
			}
		}
	}
}

func (env *CfEnvironment) ManageAppExtIp(current []ExtIpAlloc, requestedStatic []ExtIpAlloc,
	requestedDynamic bool) ([]ExtIpAlloc, error) {

	currentDynamic := make([]*ExtIpAlloc, 0)
	currentStatic := make(map[string]*ExtIpAlloc, 0)
	for i := range current {
		if current[i].Dynamic {
			currentDynamic = append(currentDynamic, &current[i])
		} else {
			currentStatic[current[i].IP] = &current[i]
		}
	}

	env.cont.indexMutex.Lock()
	defer env.cont.indexMutex.Unlock()

	// cleanup function on errors
	staticAllocatedV4 := make([]net.IP, 0)
	staticAllocatedV6 := make([]net.IP, 0)
	var err error
	defer func() {
		if err != nil {
			for _, i := range staticAllocatedV4 {
				env.log.Debug("Error, returned static external IP: ", i.String())
				env.cont.staticServiceIps.V4.AddIp(i)
			}
			for _, i := range staticAllocatedV6 {
				env.log.Debug("Error, returned static external IP: ", i.String())
				env.cont.staticServiceIps.V6.AddIp(i)
			}
		}
	}()

	// Allocate requested new static IPs
	for i := range requestedStatic {
		ipa := &requestedStatic[i]
		if _, ok := currentStatic[ipa.IP]; ok {
			continue
		}
		ip := net.ParseIP(ipa.IP)
		if ip == nil {
			err = fmt.Errorf("Invalid IP requested %s", ipa.IP)
			return nil, err
		}
		if ip.To4() != nil {
			if !env.cont.staticServiceIps.V4.RemoveIp(ip) {
				err = fmt.Errorf("Requested IP %s unavailable", ipa.IP)
				env.log.Debug("Requested static IP unavailable: ", ipa.IP)
				return nil, err
			}
			env.log.Debug("Allocated static external IP ", ipa.IP)
			staticAllocatedV4 = append(staticAllocatedV4, ip)
		} else if ip.To16() != nil {
			if !env.cont.staticServiceIps.V6.RemoveIp(ip) {
				err = fmt.Errorf("Requested IP %s unavailable", ipa.IP)
				env.log.Debug("Requested static IP unavailable: ", ipa.IP)
				return nil, err
			}
			env.log.Debug("Allocated static external IP ", ipa.IP)
			staticAllocatedV6 = append(staticAllocatedV6, ip)
		} else {
			err = fmt.Errorf("Invalid IP requested %s", ipa.IP)
			return nil, err
		}
	}
	// remove processed IPs from currentStatic
	for i := range requestedStatic {
		delete(currentStatic, requestedStatic[i].IP)
	}

	if requestedDynamic {
		// Allocate dynamic IPs and append them to requestedStatic
		if len(currentDynamic) == 0 {
			ipv4, _ := env.cont.serviceIps.AllocateIp(true)
			if ipv4 != nil {
				requestedStatic = append(requestedStatic, ExtIpAlloc{IP: ipv4.String(), Dynamic: true, Pool: ""})
				env.log.Debug("Allocated dynamic external IP ", ipv4.String())
			}
			ipv6, _ := env.cont.serviceIps.AllocateIp(false)
			if ipv6 != nil {
				requestedStatic = append(requestedStatic, ExtIpAlloc{IP: ipv6.String(), Dynamic: true, Pool: ""})
				env.log.Debug("Allocated dynamic external IP ", ipv6.String())
			}
			if ipv4 == nil && ipv6 == nil {
				err = fmt.Errorf("Unable to assign dynamic address")
				env.log.Debug("Dynamic external IP unavailable")
				return nil, err
			}
		}
		// Add current dynamic IPs if any
		for _, ipa := range currentDynamic {
			requestedStatic = append(requestedStatic, *ipa)
		}
	}
	// At this point new allocations are done, and we don't expect any more errors

	// Return unused static IPs
	for _, ipa := range currentStatic {
		ip := net.ParseIP(ipa.IP)
		if ip != nil && ip.To4() != nil {
			env.log.Debug("Unused, returned static external IP: ", ip.String())
			env.cont.staticServiceIps.V4.AddIp(ip)
		} else if ip != nil && ip.To16() != nil {
			env.log.Debug("Unused, returned static external IP: ", ip.String())
			env.cont.staticServiceIps.V6.AddIp(ip)
		}
	}
	// Return unused dynamic IPs
	if !requestedDynamic && len(currentDynamic) > 0 {
		for _, ipa := range currentDynamic {
			ip := net.ParseIP(ipa.IP)
			if ip != nil {
				env.log.Debug("Unused, returned dynamic external IP: ", ip.String())
				env.cont.serviceIps.DeallocateIp(ip)
			}
		}
	}
	return requestedStatic, nil
}

func NewCfBbsCellPoller(env *CfEnvironment) *CfPoller {

	pollFunc := func() (map[string]interface{}, interface{}, error) {
		allCells, err := env.bbsClient.Cells(env.cfLogger)
		if err != nil {
			return nil, nil, err
		}
		var newRespHashIf interface{}
		newRespHash, err := hashJsonSerializable(allCells)
		if err != nil {
			env.log.Warning("Failed to hash cells response: ", err)
			newRespHashIf = nil
		} else {
			newRespHashIf = &newRespHash
		}
		result := make(map[string]interface{})
		for _, cp := range allCells {
			result[cp.CellId] = cp
		}
		return result, newRespHashIf, nil
	}

	handleFunc := func(updates map[string]interface{}, deletes map[string]interface{}) {
		for k, v := range updates {
			cell := v.(*models.CellPresence)
			env.log.Debug(fmt.Sprintf("Add/update cell %s: %+v", k, cell))
			conf := env.cont.config
			injNode := apicapi.NewVmmInjectedHost(conf.AciVmmDomainType,
				conf.AciVmmDomain, conf.AciVmmController, "diego-cell-"+k)
			url, err := url.Parse(cell.RepAddress)
			if err == nil {
				hp := strings.Split(url.Host, ":")
				injNode.SetAttr("mgmtIp", hp[0])
			}
			env.cont.apicConn.WriteApicObjects("inj_node:"+k,
				apicapi.ApicSlice{injNode})
		}
		for k := range deletes {
			env.log.Debug("Delete cell ", k)
			env.cont.apicConn.ClearApicObjects("inj_node:" + k)
		}
	}
	pollInterval := time.Duration(env.cfconfig.CleanupPollingInterval) * time.Second
	errDelay := 10 * time.Second
	return NewCfPoller("BBS-cell", pollInterval, errDelay, pollFunc, handleFunc, env.log)
}
