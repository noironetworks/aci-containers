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
// GBP definitions -- will eventually move to a generator

package apiserver

import (
	"encoding/json"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/noironetworks/aci-containers/pkg/apicapi"
	"github.com/pkg/errors"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
)

// Following restrictions apply for container contracts
// - Bidirectional only
// - Whitelist model (i.e. implicit allow for a rule)
// -  tcp, udp, icmp

type IntRange struct {
	Start int `json:"start,omitempty"`
	End   int `json:"end,omitempty"`
}

// WLRules are implicit allow
type WLRule struct {
	Protocol string   `json:"protocol,omitempty"`
	Ports    IntRange `json:"ports,omitempty"`
}

type Contract struct {
	Name      string   `json:"name,omitempty"`
	Tenant    string   `json:"tenant,omitempty"`
	AllowList []WLRule `json:"allow-list,omitempty"`
}

func (c *Contract) Make() error {
	// if the contract exists, just update its classifier
	currMo := MoDB[c.getURI()]
	if currMo != nil {
		return c.makeClassifiers()
	}

	// make a contract mo and its children
	cmo := &GBPContract{}
	cmo.Make(c.Name, c.getURI())

	// subject
	subjName := fmt.Sprintf("%s-subj", c.Name)
	subjURI := fmt.Sprintf("%sGbpSubject/%s/", cmo.URI, subjName)
	smo := &GBPSubject{}
	smo.Make(subjName, subjURI)
	smo.SetParent(subjContract, subjSubject, cmo.URI)
	cmo.AddChild(smo.URI)

	// filter
	fmo := &GBPRule{}
	furi := c.getFilterURI()
	fname := fmt.Sprintf("%s-%s", c.Name, "filter")
	fmo.Make(fname, furi)
	fmo.SetParent(subjSubject, subjRule, smo.URI)
	fmo.AddProperty("direction", "bidirectional")
	fmo.AddProperty("order", 1)
	smo.AddChild(fmo.URI)
	err := c.makeClassifiers()
	if err != nil {
		return err
	}

	// action and action ref
	aMo := &GBPAction{}
	amoURI := fmt.Sprintf("/PolicyUniverse/PolicySpace/%s/GbpAllowDenyAction/allow/", c.Tenant)
	aMo.Make("allow", amoURI)
	aMo.AddProperty("allow", 1)

	aRef := &gbpToMo{}
	aRef.setSubject(subjActionRsrc)
	arefName := escapeName(aMo.URI, false)
	arefURI := fmt.Sprintf("%sGbpRuleToActionRSrc/286/%s/", furi, arefName)
	aRef.Make("", arefURI)
	ref := RefProperty{
		Subject: aMo.Subject,
		RefURI:  aMo.URI,
	}
	aRef.AddProperty(propTarget, ref)
	aRef.SetParent(fmo.Subject, aRef.Subject, fmo.URI)
	fmo.AddChild(aRef.URI)

	return nil
}

func (c *Contract) makeClassifiers() error {
	for _, wRule := range c.AllowList {
		err := c.addRule(wRule)
		if err != nil {
			return err
		}
	}

	// TODO remove stale classifiers.
	return c.pushTocAPIC()
}

func (c *Contract) addRule(r WLRule) error {
	uri, cname := r.getClassifierURI(c.Tenant)
	log.Infof("uri: %s, name: %s", uri, cname)
	baseMo := MoDB[uri]

	if baseMo != nil {
		log.Infof("==> Mo exists")
		return nil
	}

	furi := c.getFilterURI()
	fMo := MoDB[furi]
	if fMo == nil {
		return fmt.Errorf("FilterMO missing")
	}

	// make classifier
	cfMo := &GBPL24Classifier{}
	cfMo.Make(cname, uri)
	cfMo.AddProperty(propName, cname)
	cfMo.AddProperty(propConnTrack, "normal")
	cfMo.AddProperty(propOrder, 0)

	prot, ether, err := protToValues(r.Protocol)
	if err == nil {
		cfMo.AddProperty(propProt, prot)
		cfMo.AddProperty(propEther, ether)
	}

	if r.Ports.Start != 0 {
		cfMo.AddProperty(propDFromPort, r.Ports.Start)
	}
	if r.Ports.End != 0 {
		cfMo.AddProperty(propDToPort, r.Ports.End)
	}

	// make reference
	tocfURI := c.getToCfURI(escapeName(uri, false))
	toCF := &gbpToMo{}
	toCF.setSubject(subjClassRsrc)
	toCF.Make("", tocfURI)

	cfRef := RefProperty{
		Subject: subjL24Class,
		RefURI:  uri,
	}
	toCF.AddProperty(propTarget, cfRef)

	// add reference to filterMo
	fMo.AddChild(toCF.URI)
	toCF.SetParent(fMo.Subject, toCF.Subject, fMo.URI)

	return nil
}

func protToValues(prot string) (int, string, error) {
	switch prot {
	case "":
		return 0, "", fmt.Errorf("unspecified")
	case "udp":
		return 17, "ipv4", nil
	case "icmp":
		return 1, "ipv4", nil
	default:
		return 6, "ipv4", nil
	}
}

func (c *Contract) getURI() string {
	return fmt.Sprintf("/PolicyUniverse/PolicySpace/%s/GbpContract/%s/", c.Tenant, c.Name)
}

func (c *Contract) getFilterURI() string {
	return fmt.Sprintf("%sGbpSubject/%s-subj/GbpRule/%s-filter/", c.getURI(), c.Name, c.Name)
}

func (c *Contract) getToCfURI(name string) string {
	return fmt.Sprintf("%sGbpRuleToClassifierRSrc/178/%s/", c.getFilterURI(), name)
}
func (c *Contract) pushTocAPIC() error {
	if apicCon == nil {
		return nil
	}

	// create contract
	ac := apicapi.NewVzBrCP(c.Tenant, c.Name)
	acs := apicapi.NewVzSubj(ac.GetDn(), "subj-"+c.Name)
	acs.AddChild(apicapi.NewVzRsSubjFiltAtt(acs.GetDn(), c.Name))
	ac.AddChild(acs)

	// create filter
	filter := apicapi.NewVzFilter(c.Tenant, c.Name)
	filterDn := filter.GetDn()
	for ix, r := range c.AllowList {
		fe := apicapi.NewVzEntry(filterDn, strconv.Itoa(ix))
		fe.SetAttr("etherT", "ip")
		if r.Protocol != "" {
			fe.SetAttr("prot", r.Protocol)
		}
		if r.Ports.Start != 0 {
			fe.SetAttr("dFromPort", fmt.Sprintf("%d", r.Ports.Start))
		}
		if r.Ports.End != 0 {
			fe.SetAttr("dToPort", fmt.Sprintf("%d", r.Ports.End))
		}
		filter.AddChild(fe)

	}

	moList := []apicapi.ApicObject{
		filter,
		ac,
	}
	for _, mo := range moList {
		err := apicCon.PostDnInline(mo.GetDn(), mo)
		if err != nil {
			return err
		}
	}

	return nil
}

func (wr *WLRule) getClassifierURI(tenant string) (string, string) {
	un := wr.Protocol
	if un == "" {
		un = "ANY"
	}
	un = fmt.Sprintf("%s-%d-%d", un, wr.Ports.Start, wr.Ports.End)

	return fmt.Sprintf("/PolicyUniverse/PolicySpace/%s/GbpeL24Classifier/%s/", tenant, un), un
}

func (c *Contract) FromMo(mo *gbpBaseMo) error {
	if mo.Subject != subjContract {
		return fmt.Errorf("Mo class %s is not contract", mo.Subject)
	}

	c.Name = mo.GetStringProperty(propName)
	comps := strings.Split(mo.URI, "/")
	if len(comps) < 4 {
		return fmt.Errorf("Malformed URI %s", mo.URI)
	}

	c.Tenant = comps[3]

	for _, subjMo := range mo.getChildMos() {
		if subjMo.Subject != subjSubject {
			continue
		}

		for _, fMo := range subjMo.getChildMos() {
			if fMo.Subject != subjRule {
				continue
			}

			for _, toCMo := range fMo.getChildMos() {
				if toCMo.Subject != subjClassRsrc {
					continue
				}

				cURI, err := toCMo.getTarget()
				if err != nil {
					return err
				}

				cMo := MoDB[cURI]
				if cMo == nil {
					return fmt.Errorf("Classifier %s not found", cURI)
				}

				cname := cMo.GetStringProperty(propName)
				cc := strings.Split(cname, "-")
				if len(cc) != 3 {
					return fmt.Errorf("Malformed classifier %s ", cname)
				}

				rule := WLRule{}
				if cc[0] != "ANY" {
					rule.Protocol = cc[0]
				}

				if cc[1] != "0" {
					start, _ := strconv.Atoi(cc[1])
					rule.Ports.Start = start
				}

				if cc[2] != "0" {
					end, _ := strconv.Atoi(cc[2])
					rule.Ports.End = end
				}

				c.AllowList = append(c.AllowList, rule)
			}
		}
	}

	return nil
}

type EPG struct {
	Tenant        string   `json:"tenant,omitempty"`
	Name          string   `json:"name,omitempty"`
	ConsContracts []string `json:"consumed-contracts,omitempty"`
	ProvContracts []string `json:"provided-contracts,omitempty"`
	bds           *BDSubnet
}

func (e *EPG) Make() error {
	if e.bds == nil {
		e.bds = podBDS
	}
	eUri := e.getURI()

	base := MoDB[eUri]
	if base == nil {
		base = e.bds.CreateEPG(e.Name, eUri)
	}
	err := e.setContracts(base, e.ConsContracts, subjEPGToCC)
	if err != nil {
		return err
	}
	err = e.setContracts(base, e.ProvContracts, subjEPGToPC)
	if err != nil {
		return err
	}

	return e.pushTocAPIC()
}
func (e *EPG) pushTocAPIC() error {
	if apicCon == nil {
		return nil
	}

	cepg := apicapi.NewCloudEpg(e.Tenant, defCloudApp, e.Name)
	for _, cc := range e.ConsContracts {
		ccMo := apicapi.NewFvRsCons(cepg.GetDn(), cc)
		cepg.AddChild(ccMo)
	}
	for _, pc := range e.ProvContracts {
		pcMo := apicapi.NewFvRsProv(cepg.GetDn(), pc)
		cepg.AddChild(pcMo)
	}

	epgToVrf := apicapi.EmptyApicObject("cloudRsCloudEPgCtx", "")
	epgToVrf["cloudRsCloudEPgCtx"].Attributes["tnFvCtxName"] = defVrfName
	cepg.AddChild(epgToVrf)

	return apicCon.PostDnInline(cepg.GetDn(), cepg)
}

func (e *EPG) getURI() string {
	escName := escapeName(e.Name, false)
	return fmt.Sprintf("/PolicyUniverse/PolicySpace/%s/GbpEpGroup/%s/", e.Tenant, escName)
}

func (e *EPG) setContracts(mo *gbpBaseMo, contracts []string, refSubj string) error {

	desiredC := e.getContractURIs(contracts)
	currentC, err := mo.GetRefURIs(refSubj)
	if err != nil {
		return err
	}

	// delete any ref no longer required
	for tgt, ref := range currentC {
		if desiredC[tgt] == false {
			mo.DelChild(ref)
			delete(currentC, tgt)
			delete(MoDB, ref)
		}
	}

	// add any new ref
	for tgt := range desiredC {
		_, ok := currentC[tgt]
		if !ok {
			err = mo.AddRef(refSubj, tgt)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (e *EPG) getContractURIs(contracts []string) map[string]bool {
	result := make(map[string]bool)

	for _, c := range contracts {
		uri := fmt.Sprintf("/PolicyUniverse/PolicySpace/%s/GbpContract/%s/", e.Tenant, c)
		result[uri] = true
	}

	return result
}

func (e *EPG) FromMo(mo *gbpBaseMo) error {
	if mo.Subject != subjEPG {
		return fmt.Errorf("Mo class %s is not epg", mo.Subject)
	}

	e.Name = mo.GetStringProperty(propName)
	comps := strings.Split(mo.URI, "/")
	if len(comps) < 4 {
		return fmt.Errorf("Malformed URI %s", mo.URI)
	}

	e.Tenant = comps[3]

	// get provided contracts
	readContracts := func(sub string) []string {
		var res []string
		for _, c := range mo.Children {
			cMo := MoDB[c]
			if cMo == nil {
				log.Errorf("Child %s not found", c)
				continue
			}
			if cMo != nil && cMo.isRef && cMo.Subject == sub {
				target, err := cMo.getTarget()
				if err != nil {
					log.Errorf("Target not found for %s", c)
					continue

				}

				comps := strings.Split(target, "/")
				if len(comps) != 7 {
					log.Errorf("Malformed uri %s, %q", target, comps)
					continue
				}

				res = append(res, comps[5])
			}
		}

		return res
	}

	e.ProvContracts = readContracts(subjEPGToPC)
	e.ConsContracts = readContracts(subjEPGToCC)

	return nil
}

// postEpg rest handler to create an epg
func postEpg(w http.ResponseWriter, r *http.Request, vars map[string]string) (interface{}, error) {
	gMutex.Lock()
	defer gMutex.Unlock()

	content, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, errors.Wrap(err, "ioutil.ReadAll")
	}

	epg := &EPG{}
	err = json.Unmarshal(content, epg)
	if err != nil {
		return nil, errors.Wrap(err, "json.Unmarshal")
	}

	err = epg.Make()
	if err != nil {
		return nil, errors.Wrap(err, "epg.Make")
	}

	DoAll()
	return &PostResp{URI: epg.getURI()}, nil
}

func listEpgs(w http.ResponseWriter, r *http.Request, vars map[string]string) (interface{}, error) {
	gMutex.Lock()
	defer gMutex.Unlock()

	var resp ListResp

	for _, mo := range MoDB {
		if mo.Subject == subjEPG {
			resp.URIs = append(resp.URIs, mo.URI)
		}
	}

	return &resp, nil
}

func getEpg(w http.ResponseWriter, r *http.Request, vars map[string]string) (interface{}, error) {
	gMutex.Lock()
	defer gMutex.Unlock()

	params := r.URL.Query()
	uri, ok := params["key"]
	if !ok {
		return nil, fmt.Errorf("key is missing")
	}

	k := strings.Replace(uri[0], "|", "%7c", -1)
	eMo, ok := MoDB[k]
	if !ok {
		return nil, fmt.Errorf("%s - Not found", k)
	}

	e := &EPG{}
	e.FromMo(eMo)

	log.Infof("Key: %s", uri)
	return e, nil
}

// postContracte rest handler to create an epg
func postContract(w http.ResponseWriter, r *http.Request, vars map[string]string) (interface{}, error) {
	gMutex.Lock()
	defer gMutex.Unlock()

	content, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, errors.Wrap(err, "ioutil.ReadAll")
	}

	c := &Contract{}
	err = json.Unmarshal(content, c)
	if err != nil {
		return nil, errors.Wrap(err, "json.Unmarshal")
	}

	err = c.Make()
	if err != nil {
		return nil, errors.Wrap(err, "c.Make")
	}

	DoAll()
	return &PostResp{URI: c.getURI()}, nil
}

func listContracts(w http.ResponseWriter, r *http.Request, vars map[string]string) (interface{}, error) {
	gMutex.Lock()
	defer gMutex.Unlock()

	var resp ListResp

	for _, mo := range MoDB {
		if mo.Subject == subjContract {
			resp.URIs = append(resp.URIs, mo.URI)
		}
	}

	return &resp, nil
}

func getContract(w http.ResponseWriter, r *http.Request, vars map[string]string) (interface{}, error) {
	gMutex.Lock()
	defer gMutex.Unlock()

	params := r.URL.Query()
	uri, ok := params["key"]
	if !ok {
		return nil, fmt.Errorf("key is missing")
	}

	k := strings.Replace(uri[0], "|", "%7c", -1)
	cMo, ok := MoDB[k]
	if !ok {
		return nil, fmt.Errorf("%s - Not found", k)
	}

	c := &Contract{}
	c.FromMo(cMo)

	log.Infof("Key: %s", uri)
	return c, nil
}

func deleteObject(w http.ResponseWriter, r *http.Request, vars map[string]string) (interface{}, error) {
	gMutex.Lock()
	defer gMutex.Unlock()

	params := r.URL.Query()
	uri, ok := params["key"]
	if !ok {
		return nil, fmt.Errorf("key is missing")
	}

	k := strings.Replace(uri[0], "|", "%7c", -1)
	delete(MoDB, k)
	log.Infof("%s deleted", k)
	DoAll()
	return nil, nil
}
