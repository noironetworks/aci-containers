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

	args := []string{
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
				if cont.apicConn.DeleteDn(dn) {
					cont.log.Debug("Cleared existing Fault Instance", dn)
				} else {
					cont.log.Warn("Failed to clear existing Fault Instance", dn)
				}
			}
		}
	}
	return
}

func (cont *AciController) epgClassChanged(obj apicapi.ApicObject) {

	if !cont.faultInstCleared {
		cont.clearFaultInstances()
		cont.faultInstCleared = true
	}
	dn := obj.GetAttrStr("dn")
	cont.indexMutex.Lock()
	if ok := !cont.contains(cont.cachedVRFDns, dn); ok {
		cont.cachedVRFDns = append(cont.cachedVRFDns, dn)
	}
	cont.indexMutex.Unlock()
	sort.Strings(cont.cachedVRFDns)
}

func (cont *AciController) epgClassDeleted(dn string) {

	if cont.contains(cont.cachedVRFDns, dn) {
		cont.indexMutex.Lock()
		cont.removeSlice(cont.cachedVRFDns, dn)
		cont.indexMutex.Unlock()
	}
}

func (cont *AciController) removeSlice(s []string, searchterm string) {
	i := sort.SearchStrings(s, searchterm)
	if i < len(s) && s[i] == searchterm {
		s = append(s[:i], s[i+1:]...)
	}
	return
}

func (cont *AciController) getCachedVRFDns() []string {
	return cont.cachedVRFDns
}

func (cont *AciController) checkVrfCache(epGroup string, comment string) (bool, metadata.OpflexGroup, bool) {
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
		epgDns := cont.getCachedVRFDns()

		if len(epgDns) != 0 {
			if egval.Tenant != "" && egval.AppProfile != "" {
				dn := fmt.Sprintf("uni/tn-%s/ap-%s/epg-%s", egval.Tenant, egval.AppProfile, egval.Name)
				exist := cont.contains(epgDns, dn)
				if !exist {
					setFaultInst = true
					return false, egval, setFaultInst
				} else {
					//We subscribe for EPG dns and the EPG dns are stored in cache.If the epg exist in the cache, return true
					return true, egval, setFaultInst
				}
			}
		} else {
			cont.log.Warn("EPG dn cache is empty")
		}
	}
	return false, egval, setFaultInst
}
