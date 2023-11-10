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
	"sort"
	"strings"

	"github.com/noironetworks/aci-containers/pkg/apicapi"
)

func (cont *AciController) SubnetChanged(obj apicapi.ApicObject, aciVrfDn string) {
	subnetDn := obj.GetAttrStr("dn")
	subnetIp := obj.GetAttrStr("ip")
	cont.log.Debug("SubnetChanged for dn: ", subnetDn)
	if _, ok := cont.apicConn.CachedSubnetDns[subnetDn]; !ok {
		cont.UpdateSubnetDnCache(subnetDn, subnetIp, aciVrfDn)
		cont.scheduleRdConfig()
	}
}

func (cont *AciController) SubnetDeleted(dn string) {
	cont.log.Debug("Before deleting dn: ", dn, " CachedSubnets.subnetDns Map:  ", cont.apicConn.CachedSubnetDns)
	if _, ok := cont.apicConn.CachedSubnetDns[dn]; ok {
		delete(cont.apicConn.CachedSubnetDns, dn)
		cont.scheduleRdConfig()
	} else {
		cont.log.Debug("This shouldn't happen!")
	}
	cont.log.Debug("After Delete: CachedSubnets.subnetDns Map:  ", cont.apicConn.CachedSubnetDns)
}

func (cont *AciController) UpdateSubnetDnCache(subnetDn, subnetIp, aciVrfDn string) {
	cont.log.Debug("aciVrfDn: ", aciVrfDn, "; Processing SubnetDn: ", subnetDn)
	subnetDelimiter := "/subnet"
	subnetParentDn := strings.Split(subnetDn, subnetDelimiter)[0]
	var inCache = false
	for k := range cont.apicConn.CachedSubnetDns {
		if subnetParentDn == strings.Split(k, subnetDelimiter)[0] {
			cont.log.Debug("subnetParentDn is in cachedSubnets:", subnetParentDn)
			cont.apicConn.CachedSubnetDns[subnetDn] = subnetIp
			inCache = true
			cont.log.Debug("cachedSubnetDns Map:  ", cont.apicConn.CachedSubnetDns)
			continue
		}
	}
	if !inCache {
		cont.UpdateSubnetDnCacheForDn(subnetDn, subnetIp)
		cont.scheduleRdConfig()
	}
}

func (cont *AciController) isBdPresentInVrf(bdDn string) bool {
	bdsubnetParentArgs := []string{
		"query-target=children&target-subtree-class=fvRsCtx",
	}
	bdsubnetParentDnUri := "/api/node/mo/" + bdDn + ".json?" + strings.Join(bdsubnetParentArgs, "&")
	apicresp, err := cont.apicConn.GetApicResponse(bdsubnetParentDnUri)
	if err != nil {
		cont.log.Debugf("Failed to get APIC response, err: %v", err)
		return false
	}
	for _, obj := range apicresp.Imdata {
		for _, body := range obj {
			tDn, ok := body.Attributes["tDn"].(string)
			if !ok {
				continue
			}
			if tDn == cont.config.AciVrfDn {
				return true
			}
		}
	}
	return false
}

func (cont *AciController) UpdateSubnetDnCacheForDn(subnetDn, subnetIp string) {
	cont.log.Debug("Updating SubnetDnCache for dn: ", subnetDn, "ip: ", subnetIp)
	subnetDelimiter := "/subnet"
	subnetParentDn := strings.Split(subnetDn, subnetDelimiter)[0]
	subnetParentArgs := []string{
		"query-target=self",
	}
	subnetParentDnUri := "/api/node/mo/" + subnetParentDn + ".json?" + strings.Join(subnetParentArgs, "&")
	apicresp, err := cont.apicConn.GetApicResponse(subnetParentDnUri)
	if err != nil {
		cont.log.Debugf("Failed to get APIC response, err: %v", err)
		return
	}
	for _, obj := range apicresp.Imdata {
		for class := range obj {
			if class == "fvBD" {
				if cont.isBdPresentInVrf(subnetParentDn) {
					cont.indexMutex.Lock()
					cont.apicConn.CachedSubnetDns[subnetDn] = subnetIp
					cont.log.Debug("fvBD: Adding to CachedSubnetDns: ", subnetDn)
					cont.indexMutex.Unlock()
				}
				//if objClass is not fvBD, it will be fvAEPg
			} else {
				epgsubnetParentArgs := []string{
					"query-target=children&target-subtree-class=fvRsBd",
				}
				epgsubnetParentDnUri := "/api/node/mo/" + subnetParentDn + ".json?" + strings.Join(epgsubnetParentArgs, "&")
				apicepgresp, epgerr := cont.apicConn.GetApicResponse(epgsubnetParentDnUri)
				if epgerr != nil {
					cont.log.Debugf("Failed to get APIC response, err: %v", epgerr)
					return
				}
				for _, epgobj := range apicepgresp.Imdata {
					for _, epgbody := range epgobj {
						epgParentDn, ok := epgbody.Attributes["tDn"].(string)
						if !ok {
							continue
						}
						if cont.isBdPresentInVrf(epgParentDn) {
							cont.indexMutex.Lock()
							cont.apicConn.CachedSubnetDns[subnetDn] = subnetIp
							cont.log.Debug("fvAEPg: Adding to CachedSubnetDns: ", subnetDn)
							cont.indexMutex.Unlock()
						}
					}
				}
			}
		}
	}
}

func (cont *AciController) BuildSubnetDnCache(dn, aciVrfDn string) {
	cont.log.Debug("aciVrfDn: ", aciVrfDn, "; Processing dn: ", dn)
	var vrfBdDns []string
	var vrfEpgDns []string

	// Get all the BDs related to aciVrf and then all EPGs related to those BDs
	bdRsDelimiter := "/rsctx"
	epgRsDelimiter := "/rsbd"
	subnetDelimiter := "/subnet"
	fvRsFilter := fmt.Sprintf("query-target-filter=and(wcard(fvRsCtx.tDn,\"%s\"))", aciVrfDn)
	fvRsArgs := []string{
		"rsp-prop-include=config-only",
		fvRsFilter,
	}

	subnetArgs := []string{
		"rsp-prop-include=config-only",
	}

	fvRsUri := fmt.Sprintf("/api/node/class/fvRsCtx.json?%s", strings.Join(fvRsArgs, "&"))
	epgUri := fmt.Sprintf("/api/node/class/fvRsBd.json")
	SubnetUri := fmt.Sprintf("/api/node/class/fvSubnet.json?%s", strings.Join(subnetArgs, "&"))

	apicresp, err := cont.apicConn.GetApicResponse(fvRsUri)
	if err != nil {
		cont.log.Debugf("Failed to get APIC response, err: %v", err)
		return
	}
	for _, obj := range apicresp.Imdata {
		for _, body := range obj {
			dn, ok := body.Attributes["dn"].(string)
			if !ok {
				continue
			}
			vrfBdDns = append(vrfBdDns, strings.Split(dn, bdRsDelimiter)[0])
		}
	}
	sort.Strings(vrfBdDns)
	cont.log.Debug("aciVrfBdDns: ", vrfBdDns)

	apicresp, err = cont.apicConn.GetApicResponse(epgUri)
	if err != nil {
		cont.log.Debugf("Failed to get APIC response, err: %v", err)
		return
	}
	for _, obj := range apicresp.Imdata {
		for _, body := range obj {
			epgParentDn, ok := body.Attributes["tDn"].(string)
			cont.log.Debug("epgParentDn: ", epgParentDn)
			if !ok || !cont.contains(vrfBdDns, epgParentDn) {
				continue
			}
			epgDn, ok := body.Attributes["dn"].(string)
			if !ok {
				continue
			}
			vrfEpgDns = append(vrfEpgDns, strings.Split(epgDn, epgRsDelimiter)[0])
		}
	}
	sort.Strings(vrfEpgDns)
	cont.log.Debug("aciVrfEpgDns: ", vrfEpgDns)
	apicresp, err = cont.apicConn.GetApicResponse(SubnetUri)
	if err != nil {
		cont.log.Debugf("Failed to get APIC response, err: %v", err)
		return
	}
	for _, obj := range apicresp.Imdata {
		for _, body := range obj {
			subnetDn, ok := body.Attributes["dn"].(string)
			if !ok {
				continue
			}
			subnetParentDn := strings.Split(subnetDn, subnetDelimiter)[0]
			subnetIp, _ := body.Attributes["ip"].(string)
			cont.log.Debug("subnetDn: ", subnetDn, " subnetParentDn: ", subnetParentDn, " subnetIp: ", subnetIp)
			if cont.contains(vrfBdDns, subnetParentDn) || cont.contains(vrfEpgDns, subnetParentDn) {
				cont.indexMutex.Lock()
				cont.apicConn.CachedSubnetDns[subnetDn] = subnetIp
				cont.indexMutex.Unlock()
			}
		}
	}
	cont.log.Debug("cachedSubnetsDns Map:  ", cont.apicConn.CachedSubnetDns)
}

func (cont *AciController) contains(s []string, searchterm string) bool {
	i := sort.SearchStrings(s, searchterm)
	return i < len(s) && s[i] == searchterm
}
