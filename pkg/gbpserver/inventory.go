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

package gbpserver

import (
	"fmt"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

type gbpInvMo struct {
	gbpCommonMo
	childGetter func(string) *gbpInvMo
}

const (
	epInvURI        = "/InvUniverse/InvRemoteEndpointInventory/"
	subjRemoteEP    = "InvRemoteInventoryEp"
	subjNhl         = "InvNextHopLink"
	propNht         = "nextHopTunnel"
	propInvProxyMac = "proxyMac"
	propAddBounce   = "addBounce"
	csrDefMac       = "00:00:5e:00:52:13"
)

func (g *gbpInvMo) save(vtep string) {
	db := getInvDB(vtep)
	db[g.Uri] = g
}

func (g *gbpInvMo) clone() *gbpInvMo {
	newMo, err := g.gbpCommonMo.clone()
	if err != nil {
		log.Fatal(err)
	}

	return &gbpInvMo{gbpCommonMo: *newMo}
}

func getInvDB(vtep string) map[string]*gbpInvMo {
	db := theServer.invDB[vtep]
	if db == nil {
		theServer.invDB[vtep] = make(map[string]*gbpInvMo)
		db = theServer.invDB[vtep]
	}

	return db
}

func getVteps() []string {
	var vteps []string
	for k := range theServer.invDB {
		vteps = append(vteps, k)
	}

	return vteps
}

func getInvSubTree(url, vtep string) []*GBPObject {
	var res []*GBPObject
	var db map[string]*gbpInvMo

	for k := range theServer.invDB {
		if k == vtep { // skip this vtep
			continue
		}

		db = getInvDB(k)
		if db == nil {
			log.Warnf("InvDB vtep %s not found", vtep)
			continue
		}

		im := db[url]
		if im == nil {
			log.Warnf("InvDB mo %s/%s not found", vtep, url)
			continue
		}
		res = append(res, im.getSubTree(k)...)
	}

	return res
}

// returns the preOrder traversal of the GBP subtree rooted at g.
func (g *gbpInvMo) getSubTree(vtep string) []*GBPObject {
	st := make([]*GBPObject, 0, 8)

	root := g.clone()
	return root.preOrder(st, vtep)
}

func (g *gbpInvMo) preOrder(moList []*GBPObject, vtep string) []*GBPObject {
	// append self first
	moList = append(moList, &g.GBPObject)
	db := getInvDB(vtep)
	if db == nil {
		log.Errorf("InvDB vtep %s not found", vtep)
	}

	getChild := func(uri string) *gbpInvMo {
		var c *gbpInvMo
		if g.childGetter != nil {
			c = g.childGetter(uri)
			if c != nil {
				return c
			}
		}

		c = db[uri]
		return c
	}

	// append child subtrees
	for _, c := range g.Children {
		cMo := getChild(c)
		if cMo == nil {
			log.Errorf("Child %s missing for %s", c, g.Uri)
			continue
		}
		moList = cMo.preOrder(moList, vtep)
	}

	return moList
}

func getInvMo(vtep, uri string) *gbpInvMo {
	db := getInvDB(vtep)
	if db != nil {
		return db[uri]
	}

	return nil
}

func removeInvMo(vtep, uri string) {
	db := getInvDB(vtep)
	if db != nil {
		delete(db, uri)
		log.Infof("Deleted %s, %s", uri, vtep)
	}
}

func GetInvMoMap(vtep string) map[string]*gbpCommonMo {
	res := make(map[string]*gbpCommonMo)

	invMo := getMoDB()[epInvURI]
	for _, cUri := range invMo.Children {
		st := getInvSubTree(cUri, vtep)
		for _, mo := range st {
			res[mo.Uri] = &gbpCommonMo{GBPObject: *mo}
		}
	}

	return res
}

type Endpoint struct {
	Uuid      string   `json:"uuid,omitempty"`
	MacAddr   string   `json:"macaddr,omitempty"`
	IPAddr    []string `json:"ipaddr,omitempty"`
	EPG       string   `json:"epg,omitempty"`
	VTEP      string   `json:"vtep,omitempty"`
	IFName    string   `json:"ifname,omitempty"`
	Namespace string   `json:"namespace,omitempty"`
	PodName   string   `json:"podname,omitempty"`
}

type parsedIP struct {
	Addr      string
	PrefixLen int
}

func parseIPs(ips []string) []parsedIP {
	var result []parsedIP
	var parsed parsedIP
	for _, ip := range ips {
		parts := strings.Split(ip, "/")
		parsed.Addr = parts[0]
		parsed.PrefixLen = 32 // default
		if len(parts) > 1 {
			pLen, err := strconv.Atoi(parts[1])
			if err != nil {
				log.Warnf("Parse error: %+v", ips)
			} else {
				parsed.PrefixLen = pLen
			}
		}

		result = append(result, parsed)
	}

	return result
}

func (ep *Endpoint) Add() (string, error) {
	createChild := func(p *gbpCommonMo, childSub, name string) *gbpInvMo {
		var cURI string
		if name == "" {
			cURI = fmt.Sprintf("%s%s/", p.Uri, childSub)
		} else {
			cURI = fmt.Sprintf("%s%s/%s/", p.Uri, childSub, name)
		}
		child := &gbpInvMo{
			gbpCommonMo{
				GBPObject{
					Subject: childSub,
					Uri:     cURI,
				},
				false,
				false,
			},
			nil,
		}

		child.SetParent(p.Subject, childSub, p.Uri)
		child.save(ep.VTEP)
		p.AddChild(child.Uri)
		return child
	}

	invMo := getMoDB()[epInvURI]
	if invMo == nil {
		return "", fmt.Errorf("epInventory not found")
	}
	// if it already exists, delete it from the tree
	epURI := ep.getURI()
	invMo.DelChild(epURI)

	epMo := createChild(&invMo.gbpCommonMo, subjRemoteEP, ep.Uuid)

	props := []struct {
		Name string
		Data string
	}{
		{Name: "mac", Data: ep.MacAddr},
		{Name: propNht, Data: ep.VTEP},
		{Name: "uuid", Data: ep.Uuid},
	}

	for _, v := range props {
		if v.Data != "" {
			epMo.AddProperty(v.Name, v.Data)
		}
	}

	ipList := parseIPs(ep.IPAddr)
	for _, ip := range ipList {
		ipMo := createChild(&epMo.gbpCommonMo, "InvRemoteIp", ip.Addr)
		ipMo.AddProperty("ip", ip.Addr)
		ipMo.AddProperty(propPrefix, ip.PrefixLen)
	}

	epgRefMo := createChild(&epMo.gbpCommonMo, "InvRemoteInventoryEpToGroupRSrc", "")
	epgURI := fmt.Sprintf("/PolicyUniverse/PolicySpace/%s/GbpEpGroup/%s/", getTenantName(), strings.Replace(ep.EPG, "|", "%7c", -1))
	ref := Reference{
		Subject:      "GbpEpGroup",
		ReferenceUri: epgURI,
	}

	epgRefMo.AddProperty("target", ref)

	return epMo.Uri, nil
}

func (ep *Endpoint) getURI() string {
	return fmt.Sprintf("%sInvRemoteInventoryEp/%s/", epInvURI, ep.Uuid)
}

func (ep *Endpoint) FromMo(mo *gbpInvMo) error {
	if mo.Subject != subjRemoteEP {
		return fmt.Errorf("Mo class %s is not remote EP", mo.Subject)
	}

	ep.MacAddr = mo.GetStringProperty("mac")
	ep.VTEP = mo.GetStringProperty(propNht)
	ep.Uuid = mo.GetStringProperty("uuid")

	m := getInvDB(ep.VTEP)

	for _, c := range mo.Children {
		cMo, ok := m[c]
		if !ok {
			return fmt.Errorf("Child %s not found", c)
		}

		if cMo.Subject == "InvRemoteIp" {
			pLen := cMo.GetIntProperty(propPrefix)
			addr := cMo.GetStringProperty("ip")
			if pLen != -1 {
				addr = fmt.Sprintf("%s/%d", addr, pLen)
			}
			ep.IPAddr = append(ep.IPAddr, addr)
		}

		if cMo.Subject == "InvRemoteInventoryEpToGroupRSrc" {
			if len(cMo.Properties) != 1 {
				return fmt.Errorf("Bad refmo %s", c)
			}
			rp := cMo.Properties[0].GetRefVal()
			if rp == nil {
				return fmt.Errorf("Bad prop refmo %s", c)
			}

			epgURI := strings.Split(rp.ReferenceUri, "/")
			if len(epgURI) < 6 {
				return fmt.Errorf("Malformed refuri %s", rp.ReferenceUri)
			}
			ep.EPG = epgURI[5]
		}
	}

	return nil
}

func (ep *Endpoint) Delete() error {
	epURI := ep.getURI()
	epMo := getInvMo(ep.VTEP, epURI)
	if epMo == nil {
		return fmt.Errorf("%s Not found", epURI)
	}

	for _, u := range epMo.Children {
		removeInvMo(ep.VTEP, u)
	}
	removeInvMo(ep.VTEP, epURI)
	invMo := getMoDB()[epInvURI]
	if invMo == nil {
		return fmt.Errorf("epInventory not found")
	}
	invMo.DelChild(epURI)
	return nil
}
