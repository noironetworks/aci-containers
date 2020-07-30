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
	"github.com/noironetworks/aci-containers/pkg/apicapi"
	"sort"
	"strings"
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

func (cont *AciController) UpdateSubnetDnCache(subnetDn string, subnetIp string, aciVrfDn string) {
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
		cont.BuildSubnetDnCache(subnetDn, aciVrfDn)
		cont.scheduleRdConfig()
	}
}

func (cont *AciController) BuildSubnetDnCache(dn string, aciVrfDn string) {
	cont.log.Debug("aciVrfDn: ", aciVrfDn, "; Processing dn: ", dn)
	var vrfBdDns []string
	var vrfEpgDns []string

	// Get all the BDs related to aciVrf and then all EPGs related to those BDs
	bdRsDelimiter := "/rsctx"
	epgRsDelimiter := "/rsbd"
	subnetDelimiter := "/subnet"
	bdFilter := fmt.Sprintf("query-target-filter=and(wcard(fvRsCtx.tDn,\"%s\"))", aciVrfDn)
	bdArgs := []string{
		"rsp-prop-include=config-only",
		"query-target=subtree",
		bdFilter,
	}

	epgArgs := []string{
		"query-target=subtree",
		"target-subtree-class=fvRsBd",
	}

	subnetArgs := []string{
		"rsp-prop-include=config-only",
	}

	bdUri := fmt.Sprintf("/api/node/class/fvBD.json?%s", strings.Join(bdArgs, "&"))
	epgUri := fmt.Sprintf("/api/node/class/fvAEPg.json?%s", strings.Join(epgArgs, "&"))
	SubnetUri := fmt.Sprintf("/api/node/class/fvSubnet.json?%s", strings.Join(subnetArgs, "&"))

	apicresp, err := cont.apicConn.GetApicResponse(bdUri)
	if err != nil {
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
				cont.apicConn.CachedSubnetDns[subnetDn] = subnetIp
			}
		}
	}
	cont.log.Debug("cachedSubnetsDns Map:  ", cont.apicConn.CachedSubnetDns)
	return
}

func (cont *AciController) contains(s []string, searchterm string) bool {
	i := sort.SearchStrings(s, searchterm)
	return i < len(s) && s[i] == searchterm
}
