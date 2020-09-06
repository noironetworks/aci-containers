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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	osexec "os/exec"
	"strconv"
	"strings"

	"github.com/noironetworks/aci-containers/pkg/apicapi"
	"github.com/pkg/errors"
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
	getVtepsPath    = "/usr/local/bin/get_vteps.sh"
	propInvProxyMac = "proxyMac"
	propAddBounce   = "addBounce"
	csrDefMac       = "00:00:5e:00:52:13"
)

var InvDB = make(map[string]map[string]*gbpInvMo)

func ReadInvFile(vtep, file string) {
	data, err := ioutil.ReadFile(file)
	if err != nil {
		log.Errorf("Reading %s - %v", file, err)
		return
	}

	var moList []gbpInvMo

	err = json.Unmarshal(data, &moList)
	if err != nil {
		log.Infof("Decoding %s - %v", file, err)
		return
	}

	moMap := make(map[string]*gbpInvMo)
	for _, mo := range moList {
		mm := new(gbpInvMo)
		*mm = mo
		moMap[mo.Uri] = mm
	}
	InvDB[vtep] = moMap
}

func InitInvDB() {
	// fetch VTEPs and init them
	vtepList, err := osexec.Command(getVtepsPath).Output()
	if err != nil {
		log.Errorf("Getting vteps: %v", err)
		return
	}

	vteps := strings.TrimPrefix(strings.TrimSuffix(string(vtepList), "\n"), "\n")
	for _, vtep := range strings.Split(vteps, "\n") {
		log.Infof("Adding VTEP %s", vtep)
		_, ok := InvDB[vtep]
		if !ok {
			InvDB[vtep] = make(map[string]*gbpInvMo)
		}
	}

	DoAll()
}

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
		res = append(res, im.getSubTree(k, vtep)...)
	}

	return res
}

// returns the preOrder traversal of the GBP subtree rooted at g.
func (g *gbpInvMo) getSubTree(vtep, reqVtep string) []*GBPObject {
	st := make([]*GBPObject, 0, 8)

	root := g.xformVteps(reqVtep)
	return root.preOrder(st, vtep)
}

// Applies vtep transformation for forwarding via CSR
func (g *gbpInvMo) xformVteps(reqVtep string) *gbpInvMo {
	auxChildren := make(map[string]*gbpInvMo)
	// find nextHop aka vtep
	nh := g.GetStringProperty(propNht)

	tunnels := strings.Split(nh, ",")
	nhCount := len(tunnels)
	if nhCount < 2 { // no change required
		return g
	}

	// clone the mo and modify the clone
	// add nexthops as children instead of property
	// return this mo
	newMo := g.clone()
	newMo.DelProperty(propNht)
	newMo.AddProperty(propInvProxyMac, csrDefMac)
	needBounce := checkBounce(reqVtep)
	log.Debugf("needBounce: %v, reqVtep: %s", needBounce, reqVtep)
	if needBounce {
		tunnels = theServer.bounceList
		newMo.AddProperty(propAddBounce, 0)
	} else {
		// add bounce is set for nodes that have a tunnel
		newMo.AddProperty(propAddBounce, 1)
	}

	for _, vtep := range tunnels {
		cURI := fmt.Sprintf("%s%s/%s/", newMo.Uri, subjNhl, vtep)
		child := &gbpInvMo{
			gbpCommonMo{
				GBPObject{
					Subject: subjNhl,
					Uri:     cURI,
				},
				false,
				false,
			},
			nil,
		}
		child.AddProperty("ip", vtep)
		child.SetParent(newMo.Subject, subjNhl, newMo.Uri)

		newMo.AddChild(child.Uri)
		auxChildren[child.Uri] = child
	}

	childGetter := func(uri string) *gbpInvMo {
		c := auxChildren[uri]
		if c != nil {
			return c
		}

		return nil
	}

	newMo.childGetter = childGetter
	return newMo
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

	return epMo.Uri, ep.pushTocAPIC(true)
}

func (ep *Endpoint) getURI() string {
	return fmt.Sprintf("%sInvRemoteInventoryEp/%s/", epInvURI, ep.Uuid)
}

func (ep *Endpoint) pushTocAPIC(add bool) error {
	if apicCon == nil {
		return nil
	}

	epToSg := apicapi.EmptyApicObject("hcloudRsEpToSecurityGroup", "")
	epToSg["hcloudRsEpToSecurityGroup"].Attributes["tDn"] = getSgDn(cApicName(ep.EPG))
	cEP := apicapi.EmptyApicObject("hcloudEndPoint", "")
	epName := string(ep.Uuid[len(ep.Uuid)-12:])
	epName = fmt.Sprintf("%s.%s", epName, ep.VTEP)
	cEP["hcloudEndPoint"].Attributes["name"] = epName
	cEP["hcloudEndPoint"].Attributes["primaryIpV4Addr"] = ep.IPAddr[0]
	if !add {
		cEP["hcloudEndPoint"].Attributes["status"] = "deleted"
	}
	cEP["hcloudEndPoint"].Children = append(cEP["hcloudEndPoint"].Children, epToSg)

	cSN := apicapi.EmptyApicObject("hcloudSubnet", "")
	cSN["hcloudSubnet"].Attributes["addr"] = defCAPICSubnet
	cSN["hcloudSubnet"].Children = append(cSN["hcloudSubnet"].Children, cEP)

	cCidr := apicapi.EmptyApicObject("hcloudCidr", "")
	cCidr["hcloudCidr"].Attributes["addr"] = defCAPICCidr
	cCidr["hcloudCidr"].Children = append(cCidr["hcloudCidr"].Children, cSN)

	cCtx := apicapi.EmptyApicObject("hcloudCtx", "")
	cCtx["hcloudCtx"].Attributes["name"] = defVrfName
	cCtx["hcloudCtx"].Attributes["primaryCidr"] = defCAPICCidr
	cCtx["hcloudCtx"].Children = append(cCtx["hcloudCtx"].Children, cCidr)

	cRegion := apicapi.EmptyApicObject("hcloudRegion", "")
	cRegion["hcloudRegion"].Attributes["regionName"] = defRegion
	cRegion["hcloudRegion"].Children = append(cRegion["hcloudRegion"].Children, cCtx)

	cAcc := apicapi.EmptyApicObject("hcloudAccount", "")
	cAcc["hcloudAccount"].Attributes["name"] = getTenantName()
	cAcc["hcloudAccount"].Children = append(cAcc["hcloudAccount"].Children, cRegion)

	err := apicCon.PostTestAPI(cAcc)
	log.Errorf("pushTocAPIC: %v", err)
	return err
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

	return ep.pushTocAPIC(false)
}

func getSgDn(epgName string) string {
	cepg := apicapi.NewCloudEpg(getTenantName(), defCloudApp, epgName)
	n := fmt.Sprintf("acct-[%s]/region-[%s]/context-[%s]/sgroup-[%s]",
		getTenantName(), defRegion, defVrfName, cepg.GetDn())
	return n
}

// postEndpoint rest handler to create an endpoint
func postEndpoint(w http.ResponseWriter, r *http.Request, vars map[string]string) (interface{}, error) {
	gMutex.Lock()
	defer gMutex.Unlock()

	content, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, errors.Wrap(err, "ioutil.ReadAll")
	}

	ep := &Endpoint{}
	err = json.Unmarshal(content, ep)
	if err != nil {
		return nil, errors.Wrap(err, "json.Unmarshal")
	}

	uri, err := ep.Add()
	DoAll()
	return &PostResp{URI: uri}, err
}

func getAllEPs() map[string]*gbpInvMo {
	allEPs := make(map[string]*gbpInvMo)

	for _, m := range theServer.invDB {
		for _, mo := range m {
			if mo.Subject == subjRemoteEP {
				allEPs[mo.Uri] = mo
			}
		}
	}

	return allEPs
}

func listEndpoints(w http.ResponseWriter, r *http.Request, vars map[string]string) (interface{}, error) {
	gMutex.Lock()
	defer gMutex.Unlock()

	var resp ListResp

	allEPs := getAllEPs()
	for u := range allEPs {
		resp.URIs = append(resp.URIs, u)
	}

	return &resp, nil
}

func fetchEP(r *http.Request) (*Endpoint, error) {
	params := r.URL.Query()
	key, ok := params["key"]
	if !ok {
		return nil, fmt.Errorf("key is missing")
	}

	allEPs := getAllEPs()
	epMo, ok := allEPs[key[0]]
	if !ok {
		return nil, fmt.Errorf("Not found - %s", key)
	}

	ep := &Endpoint{}
	err := ep.FromMo(epMo)
	return ep, err
}
func getEndpoint(w http.ResponseWriter, r *http.Request, vars map[string]string) (interface{}, error) {
	gMutex.Lock()
	defer gMutex.Unlock()

	return fetchEP(r)
}
func deleteEndpoint(w http.ResponseWriter, r *http.Request, vars map[string]string) (interface{}, error) {
	gMutex.Lock()
	defer gMutex.Unlock()

	ep, err := fetchEP(r)
	if err != nil {
		return nil, err
	}

	log.Debugf("deleteEndpoint - VTEP: %s", ep.VTEP)
	err = ep.Delete()
	DoAll()
	return nil, err
}

func checkBounce(reqVtep string) bool {
	_, found := theServer.tunnels[reqVtep]
	return !found
}
