/***
Copyright 2018 Cisco Systems Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
// GBP ep inventory definitions

package apiserver

import (
	"fmt"
)

type gbpInvMo struct {
	gbpCommonMo
}

const (
	epInvURI = "/InvUniverse/InvRemoteEndpointInventory/"
)

var InvDB = make(map[string]map[string]*gbpInvMo)

func (g *gbpInvMo) save(vtep string) {
	_, ok := InvDB[vtep]
	if !ok {
		InvDB[vtep] = make(map[string]*gbpInvMo)
	}

	db := InvDB[vtep]
	db[g.URI] = g
}

func getInvMo(vtep, uri string) *gbpInvMo {
	db := InvDB[vtep]
	if db != nil {
		return db[uri]
	}

	return nil
}

func removeInvMo(vtep, uri string) {
	db := InvDB[vtep]
	if db != nil {
		delete(db, uri)
	}
}

func GetInvMoList(vtep string) []*gbpCommonMo {
	res := make([]*gbpCommonMo, 0, 64)
	for k, m := range InvDB {
		if k == vtep {
			continue	// skip this vtep
		}

		for _, mo := range m {
			res = append(res, &mo.gbpCommonMo)
		}
	}	

	return res
}

type Endpoint struct {
	Uuid    string `json:"uuid,omitempty"`
	MacAddr string `json:"macaddr,omitempty"`
	IPAddr  string `json:"ipaddr,omitempty"`
	EPG     string `json:"epg,omitempty"`
	VTEP    string `json:"vtep,omitempty"`
}

func (ep *Endpoint) Add() error {
	createChild := func(p *gbpCommonMo, childSub, name string) *gbpInvMo {
		var cURI string
		if name == "" {
			cURI = fmt.Sprintf("%s%s/", p.URI, childSub)
		} else {
			cURI = fmt.Sprintf("%s%s/%s/", p.URI, childSub, name)
		}
		child := &gbpInvMo{
			gbpCommonMo{
				Subject: childSub,
				URI:     cURI,
			},
		}
		child.SetParent(p.Subject, childSub, p.URI)
		child.save(ep.VTEP)
		p.AddChild(child.URI)
		return child
	}

	invMo := MoDB[epInvURI]
	if invMo == nil {
		return fmt.Errorf("epInventory not found")
	}

	epMo := createChild(&invMo.gbpCommonMo, "InvRemoteInventoryEp", ep.Uuid)

	props := []Property{
		{Name: "mac", Data: ep.MacAddr},
		{Name: "nextHopTunnel", Data: ep.VTEP},
		{Name: "uuid", Data: ep.Uuid},
	}

	epMo.Properties = props

	ipMo := createChild(&epMo.gbpCommonMo, "InvRemoteIp", ep.IPAddr)
	ipMo.AddProperty("ip", ep.IPAddr)

	epgRefMo := createChild(&epMo.gbpCommonMo, "InvRemoteInventoryEpToGroupRSrc", "")
	epgURI := fmt.Sprintf("/PolicyUniverse/PolicySpace/common/GbpEpGroup/%s/", ep.EPG)
	ref := RefProperty{
		Subject: "GbpEpGroup",
		RefURI:  epgURI,
	}

	epgRefMo.AddProperty("target", ref)

	return nil
}

func (ep *Endpoint) Delete() error {
	epURI := fmt.Sprintf("%sInvRemoteInventoryEp/%s", epInvURI, ep.Uuid)
	epMo := getInvMo(ep.VTEP, epURI)
	if epMo == nil {
		return fmt.Errorf("Not found")
	}

	for _, u := range epMo.Children {
		removeInvMo(ep.VTEP, u)
	}
	removeInvMo(ep.VTEP, epURI)

	return nil
}
