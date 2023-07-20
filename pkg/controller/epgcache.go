// Copyright 2021 Cisco Systems, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package controller

import (
	"github.com/noironetworks/aci-containers/pkg/apicapi"
	"github.com/noironetworks/aci-containers/pkg/metadata"

	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

func (cont *AciController) clearFaultInstances() {
	queryfilter := fmt.Sprintf("query-target-filter=and(wcard(vmmClusterFaultInfo.dn,\"comp/prov-%s/ctrlr-\\[%s\\]-%s\"))",
		cont.vmmDomainProvider(), cont.config.AciVmmDomain, cont.config.AciVmmDomain)
	args := []string{
		queryfilter,
		"order-by=vmmClusterFaultInfo.modTs|desc",
	}

	faultUri := fmt.Sprintf("/api/node/class/vmmClusterFaultInfo.json?%s", strings.Join(args, "&"))
	apicresp, err := cont.apicConn.GetApicResponse(faultUri)
	if err != nil {
		return
	}
	for _, obj := range apicresp.Imdata {
		for _, body := range obj {
			dn, ok := body.Attributes["dn"].(string)
			if ok {
				cont.indexMutex.Lock()
				cont.apicConn.DeleteDn(dn)
				cont.log.Debug("Clearing existing Fault Instance: ", dn)
				cont.indexMutex.Unlock()
			}
		}
	}
}

func (cont *AciController) getEpgFromEppd(dn string) string {
	delimiterStringEpg := fmt.Sprintf("uni/vmmp-%s/dom-%s/eppd-[", cont.vmmDomainProvider(), cont.config.AciVmmDomain)
	epgDn := strings.Split(dn, delimiterStringEpg)[1]
	epgDn = strings.Replace(epgDn, "]", "", -1)
	return epgDn
}

func (cont *AciController) vmmEpPDChanged(obj apicapi.ApicObject) {
	dn := obj.GetAttrStr("dn")
	epgDn := cont.getEpgFromEppd(dn)
	cont.indexMutex.Lock()
	if ok := !cont.contains(cont.cachedEpgDns, epgDn); ok {
		cont.cachedEpgDns = append(cont.cachedEpgDns, epgDn)
	}
	sort.Strings(cont.cachedEpgDns)
	cont.indexMutex.Unlock()
}

func (cont *AciController) vmmEpPDDeleted(dn string) {
	epgDn := cont.getEpgFromEppd(dn)
	cont.indexMutex.Lock()
	if cont.contains(cont.cachedEpgDns, epgDn) {
		cont.removeSlice(cont.cachedEpgDns, epgDn)
	}
	cont.indexMutex.Unlock()
}

func (cont *AciController) removeSlice(s []string, searchterm string) {
	i := sort.SearchStrings(s, searchterm)
	if i < len(s) && s[i] == searchterm {
		s = append(s[:i], s[i+1:]...)
	}
}

func (cont *AciController) checkEpgCache(epGroup, comment string) (bool, metadata.OpflexGroup, bool) {
	var egval metadata.OpflexGroup
	var setFaultInst bool

	if len(epGroup) != 0 {
		err := json.Unmarshal([]byte(epGroup), &egval)
		if err != nil {
			cont.log.Error("Could not decode the annotation, Format not right : ", comment)
			return false, egval, setFaultInst
		}
	}

	if len(egval.Tenant) == 0 || len(egval.AppProfile) == 0 || len(egval.Name) == 0 {
		cont.log.Error("Annotation failed: Tenant/AppProfile/EPG not specified")
		return false, egval, setFaultInst
	}

	if len(egval.Name) != 0 {
		if len(cont.cachedEpgDns) != 0 {
			if egval.Tenant != "" && egval.AppProfile != "" {
				dn := fmt.Sprintf("uni/tn-%s/ap-%s/epg-%s", egval.Tenant, egval.AppProfile, egval.Name)
				cont.indexMutex.Lock()
				exist := cont.contains(cont.cachedEpgDns, dn)
				cont.indexMutex.Unlock()
				if !exist {
					setFaultInst = true
					return false, egval, setFaultInst
				} else {
					//We subscribe for EPG dns and the EPG dns are stored in cache.If the epg exist in the cache, return true
					return true, egval, setFaultInst
				}
			}
		}
	}
	return false, egval, setFaultInst
}
