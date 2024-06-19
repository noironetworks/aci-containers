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

package gbpserver

import (
	"fmt"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/noironetworks/aci-containers/pkg/gbpcrd/apis/acipolicy/v1"
)

const revClassify = "rev"

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
	Name           string      `json:"name,omitempty"`
	Tenant         string      `json:"tenant,omitempty"`
	AllowList      []v1.WLRule `json:"allow-list,omitempty"`
	classifierUris []string
}

func (c *Contract) Make() error {
	// if the contract exists, just update its classifier
	//	currMo := MoDB[c.getURI()]
	//	if currMo != nil {
	//		return c.makeClassifiers()
	//	}

	// make a contract mo and its children
	cmo := &GBPContract{}
	cmo.Make(c.Name, c.getURI())

	// subject
	subjName := fmt.Sprintf("%s-subj", c.Name)
	subjURI := fmt.Sprintf("%sGbpSubject/%s/", cmo.Uri, subjName)
	smo := &GBPSubject{}
	smo.Make(subjName, subjURI)
	smo.SetParent(subjContract, subjSubject, cmo.Uri)
	cmo.AddChild(smo.Uri)

	// filter
	fmo := &GBPRule{}
	furi := c.getFilterURI()
	fname := fmt.Sprintf("%s-%s", c.Name, "filter")
	fmo.Make(fname, furi)
	fmo.SetParent(subjSubject, subjRule, smo.Uri)
	fmo.AddProperty("direction", "bidirectional")
	fmo.AddProperty("order", 1)
	smo.AddChild(fmo.Uri)
	err := c.makeClassifiers()
	if err != nil {
		log.Errorf("makeClassifiers returned %v", err)
		return err
	}

	addActionRef(&fmo.gbpCommonMo)
	return nil
}

func (c *Contract) Delete() error {
	return nil
}

func addActionRef(p *gbpCommonMo) {
	// action and action ref
	aMo := &GBPAction{}
	amoURI := fmt.Sprintf("/PolicyUniverse/PolicySpace/%s/GbpAllowDenyAction/allow/", getTenantName())
	aMo.Make("allow", amoURI)
	aMo.AddProperty("allow", 1)

	aRef := &gbpToMo{}
	aRef.setSubject(subjActionRsrc)
	arefName := escapeName(aMo.Uri, false)
	arefURI := fmt.Sprintf("%sGbpRuleToActionRSrc/286/%s/", p.Uri, arefName)
	aRef.Make("", arefURI)
	ref := Reference{
		Subject:      aMo.Subject,
		ReferenceUri: aMo.Uri,
	}
	aRef.AddProperty(propTarget, ref)
	linkParentChild(p, &aRef.gbpCommonMo)
}
func (c *Contract) makeClassifiers() error {
	// if AllowList is empty, add an empty rule.
	if len(c.AllowList) == 0 {
		emptyRule := v1.WLRule{}
		c.AllowList = append(c.AllowList, emptyRule)
	}

	for _, wRule := range c.AllowList {
		err := c.addRule(wRule, "")
		if err != nil {
			return err
		}

		if wRule.Ports.Start != 0 || wRule.Ports.End != 0 {
			// add a reverse rule
			log.Debugf("Adding revserse rule for %+v", wRule)
			err := c.addRule(wRule, revClassify)
			if err != nil {
				return err
			}
		}
	}

	// TODO remove stale classifiers.
	return nil
}

func (c *Contract) addRule(r v1.WLRule, dir string) error {
	uri, cname := c.getClassifierURI(dir, &r)
	log.Debugf("uri: %s, name: %s", uri, cname)
	c.classifierUris = append(c.classifierUris, uri)
	moDB := getMoDB()

	furi := c.getFilterURI()
	fMo := moDB[furi]
	if fMo == nil {
		return fmt.Errorf("FilterMO missing")
	}

	// make classifier
	cfMo := &GBPL24Classifier{}
	cfMo.Make(cname, uri)
	cfMo.AddProperty(propName, cname)
	cfMo.AddProperty(propConnTrack, "normal")
	cfMo.AddProperty(propOrder, 1)

	prot, ether, err := protToValues(r.Protocol)
	log.Debugf("Contract: %s, prot: %d, err: %v", c.Name, prot, err)
	if err == nil {
		cfMo.AddProperty(propProt, prot)
		cfMo.AddProperty(propEther, ether)
	}

	if r.Ports.Start != 0 {
		if dir == revClassify {
			cfMo.AddProperty(propSFromPort, r.Ports.Start)
		} else {
			cfMo.AddProperty(propDFromPort, r.Ports.Start)
		}
	}
	if r.Ports.End != 0 {
		if dir == revClassify {
			cfMo.AddProperty(propSToPort, r.Ports.End)
		} else {
			cfMo.AddProperty(propDToPort, r.Ports.End)
		}
	}

	// make reference
	tocfURI := c.getToCfURI(escapeName(uri, false))
	toCF := &gbpToMo{}
	toCF.setSubject(subjClassRsrc)
	toCF.Make("", tocfURI)

	cfRef := Reference{
		Subject:      subjL24Class,
		ReferenceUri: uri,
	}
	toCF.AddProperty(propTarget, cfRef)

	// add reference to filterMo
	fMo.AddChild(toCF.Uri)
	toCF.SetParent(fMo.Subject, toCF.Subject, fMo.Uri)

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

func (c *Contract) getAllURIs() []string {
	return append(c.classifierUris, c.getURI())
}

func (c *Contract) getFilterURI() string {
	return fmt.Sprintf("%sGbpSubject/%s-subj/GbpRule/%s-filter/", c.getURI(), c.Name, c.Name)
}

func (c *Contract) getToCfURI(name string) string {
	return fmt.Sprintf("%sGbpRuleToClassifierRSrc/178/%s/", c.getFilterURI(), name)
}

func (c *Contract) getClassifierURI(dir string, wr *v1.WLRule) (string, string) {
	un := wr.Protocol
	if un == "" {
		un = "ANY"
	}
	un = fmt.Sprintf("%s-%s-%s-%d-%d", c.Name, un, dir, wr.Ports.Start, wr.Ports.End)

	return fmt.Sprintf("/PolicyUniverse/PolicySpace/%s/GbpeL24Classifier/%s/", c.Tenant, un), un
}

func (c *Contract) FromMo(mo *gbpBaseMo) error {
	if mo.Subject != subjContract {
		return fmt.Errorf("Mo class %s is not contract", mo.Subject)
	}

	moDB := getMoDB()
	c.Name = mo.GetStringProperty(propName)
	comps := strings.Split(mo.Uri, "/")
	if len(comps) < 4 {
		return fmt.Errorf("Malformed URI %s", mo.Uri)
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

				cMo := moDB[cURI]
				if cMo == nil {
					return fmt.Errorf("Classifier %s not found", cURI)
				}

				cname := cMo.GetStringProperty(propName)
				cc := strings.Split(cname, "-")
				if len(cc) != 3 {
					return fmt.Errorf("Malformed classifier %s ", cname)
				}

				rule := v1.WLRule{}
				if cc[0] != "ANY" {
					rule.Protocol = cc[0]
				}

				if cc[1] != "0" {
					start := convNameToPort(cc[0], cc[1])
					rule.Ports.Start = start
				}

				if cc[2] != "0" {
					end := convNameToPort(cc[0], cc[2])
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
	ApicDN        string
	bds           *BDSubnet
}

func (e *EPG) Make() error {
	if e.bds == nil {
		e.bds = podBDS
	}
	eUri := e.getURI()
	moDB := getMoDB()

	base := moDB[eUri]
	if base == nil {
		base = e.bds.CreateEPG(e.Name, eUri)
	}
	err := e.setContracts(base, e.ConsContracts, subjEPGToCC)
	if err != nil {
		log.Infof("epg %s consumed contracts: %v", e.Name, err)
	}
	err = e.setContracts(base, e.ProvContracts, subjEPGToPC)
	if err != nil {
		log.Infof("epg %s provided contracts: %v", e.Name, err)
	}

	return nil
}

func (e *EPG) Delete() {
	eUri := e.getURI()
	moDB := getMoDB()

	base := moDB[eUri]
	if base == nil {
		log.Errorf("EPG %s not founc", eUri)
		return
	}

	// delete all children
	for _, cUri := range base.Children {
		cMo := moDB[cUri]
		if cMo != nil && cMo.Subject == subjEIC {
			// free encap and class
			freeEncapClass(cMo.Uri)
		}
		delete(moDB, cUri)
	}

	delete(moDB, eUri)
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
		if !desiredC[tgt] {
			mo.DelChild(ref)
			delete(currentC, tgt)
			delete(getMoDB(), ref)
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

	parseName := func(name string) (string, string) {
		parts := strings.Split(name, "/")
		if len(parts) == 1 {
			return e.Tenant, name
		}

		return parts[0], parts[1]
	}
	for _, c := range contracts {
		tenant, contract := parseName(c)
		uri := fmt.Sprintf("/PolicyUniverse/PolicySpace/%s/GbpContract/%s/", tenant, contract)
		result[uri] = true
	}

	return result
}

func (e *EPG) FromMo(mo *gbpBaseMo) error {
	if mo.Subject != subjEPG {
		return fmt.Errorf("Mo class %s is not epg", mo.Subject)
	}
	moDB := getMoDB()

	e.Name = mo.GetStringProperty(propName)
	comps := strings.Split(mo.Uri, "/")
	if len(comps) < 4 {
		return fmt.Errorf("Malformed URI %s", mo.Uri)
	}

	e.Tenant = comps[3]

	// get provided contracts
	readContracts := func(sub string) []string {
		var res []string
		for _, c := range mo.Children {
			cMo := moDB[c]
			if cMo == nil {
				log.Errorf("Child %s not found", c)
				continue
			}
			if cMo.isRef && cMo.Subject == sub {
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

type NetworkPolicy struct {
	HostprotPol Hpp `json:"hostprotPol,omitempty"`
}

type Hpp struct {
	Attributes map[string]string    `json:"attributes,omitempty"`
	Children   []map[string]*HpSubj `json:"children,omitempty"`
}

type HpSubj struct {
	Attributes   map[string]string        `json:"attributes,omitempty"`
	Children     []map[string]HpSubjChild `json:"children,omitempty"`
	referredUris []string
}

type HpSubjChild struct {
	Attributes    map[string]string             `json:"attributes,omitempty"`
	Children      []map[string]HpSubjGrandchild `json:"children,omitempty"`
	classifierUri string
	subnetSetUri  string
}

type HpSubjGrandchild struct {
	Attributes map[string]string        `json:"attributes,omitempty"`
	Children   []map[string]interface{} `json:"children,omitempty"`
}

func linkParentChild(p, c *gbpCommonMo) {
	p.AddChild(c.Uri)
	c.SetParent(p.Subject, c.Subject, p.Uri)
}

func (np *NetworkPolicy) getURI() string {
	return fmt.Sprintf("/PolicyUniverse/PolicySpace/%s/%s/%s/", getTenantName(), subjSecGroup, np.HostprotPol.Attributes[propName])
}

func (np *NetworkPolicy) getAllURIs() []string {
	c := np.HostprotPol.getChild("hostprotSubj")
	return append(c.referredUris, np.getURI())
}

func (np *NetworkPolicy) Make() error {
	if np.HostprotPol.Attributes == nil {
		return fmt.Errorf("Malformed network policy")
	}

	hpp := &gbpBaseMo{}
	hpp.Subject = subjSecGroup
	hpp.Uri = np.getURI()
	hpp.AddProperty(propName, np.HostprotPol.Attributes[propName])
	log.Debugf("NP make name: %s uri: %s pol: %+v", np.HostprotPol.Attributes[propName], hpp.Uri, np)
	hpp.save()
	c := np.HostprotPol.getChild("hostprotSubj")
	if c == nil {
		return fmt.Errorf("hostprotSubj not found")
	}

	if c.Attributes == nil {
		return fmt.Errorf("Malformed network policy subject")
	}
	hppSub := &gbpBaseMo{}
	hppSub.Subject = subjSGSubj
	hppSub.Uri = fmt.Sprintf("%s%s/%s/", hpp.Uri, subjSGSubj, c.Attributes[propName])
	hppSub.AddProperty(propName, c.Attributes[propName])
	hppSub.save()
	linkParentChild(&hpp.gbpCommonMo, &hppSub.gbpCommonMo)
	err := c.Make(&hppSub.gbpCommonMo, np.HostprotPol.Attributes[propName]) // make the remaining subtree
	if err != nil {
		return err
	}

	log.Debugf("All uris: %+v", c.referredUris)

	return nil
}

func (hpp *Hpp) getChild(key string) *HpSubj {
	for _, cm := range hpp.Children {
		res, ok := cm[key]
		if ok {
			return res
		}
	}

	return nil
}

func (hs *HpSubj) Make(hsMo *gbpCommonMo, npName string) error {
	cList := hs.getChildren("hostprotRule")
	// add an arp rule
	if len(cList) > 0 {
		cList = append(cList, hs.arpRule())
	}

	for _, c := range cList {
		if c.Attributes == nil {
			return fmt.Errorf("Malformed network policy rule")
		}
		hppRule := new(gbpBaseMo)
		hppRule.Subject = subjSGRule
		hppRule.Uri = fmt.Sprintf("%s%s/%s/", hsMo.Uri, subjSGRule, c.Attributes[propName])
		hppRule.AddProperty(propName, c.Attributes[propName])
		dir := "bidirectional"
		if c.Attributes["direction"] == "ingress" {
			dir = "in"
		}
		if c.Attributes["direction"] == "egress" {
			dir = "out"
		}
		hppRule.AddProperty("direction", dir)
		hppRule.AddProperty("order", 1)
		hppRule.save()
		linkParentChild(hsMo, &hppRule.gbpCommonMo)
		err := c.Make(&hppRule.gbpCommonMo, hs.Attributes[propName], npName) // make the remaining subtree
		if err != nil {
			return err
		}
		hs.referredUris = append(hs.referredUris, c.classifierUri, c.subnetSetUri)
	}
	return nil
}

func (hs *HpSubj) arpRule() *HpSubjChild {
	hsc := new(HpSubjChild)
	hsc.Attributes = make(map[string]string)
	hsc.Attributes["ethertype"] = "arp"
	hsc.Attributes["direction"] = "bidirectional"
	hsc.Attributes["connTrack"] = "normal"
	hsc.Attributes["name"] = hs.Attributes[propName] + "-arp"
	return hsc
}

func (hs *HpSubj) getChildren(key string) []*HpSubjChild {
	var res []*HpSubjChild

	for _, cm := range hs.Children {
		obj, ok := cm[key]
		if ok {
			hsc := new(HpSubjChild)
			*hsc = obj
			res = append(res, hsc)
		}
	}

	return res
}

func attrToProperties(a map[string]string) map[string]interface{} {
	p := make(map[string]interface{})

	p[propEther] = a["ethertype"]
	ct, ok := a["connTrack"]
	if ok {
		p[propConnTrack] = ct
	}
	switch a["protocol"] {
	case "udp":
		p[propProt] = 17
	case "icmp":
		p[propProt] = 1
	case "tcp":
		p[propProt] = 6
	}

	return p
}

func (hsc *HpSubjChild) Make(ruleMo *gbpCommonMo, subjName, npName string) error {
	// make a classifier mo
	cfMo := &GBPL24Classifier{}
	cname := fmt.Sprintf("%s|%s|%s", npName, subjName, hsc.Attributes[propName])
	uri := fmt.Sprintf("/PolicyUniverse/PolicySpace/%s/GbpeL24Classifier/%s/", getTenantName(), escapeName(cname, false))
	hsc.classifierUri = uri
	cfMo.Make(cname, uri)
	cfMo.AddProperty(propName, cname)

	props := attrToProperties(hsc.Attributes)
	for p, v := range props {
		cfMo.AddProperty(p, v)
	}

	protocol := hsc.Attributes["protocol"]
	portSpec := []struct {
		apicName string
		gbpName  string
	}{
		{apicName: "toPort", gbpName: propDToPort},
		{apicName: "fromPort", gbpName: propDFromPort},
	}
	log.Debugf("hscAttr: %+v", hsc.Attributes)
	for _, s := range portSpec {
		att := hsc.Attributes[s.apicName]
		if att != "unspecified" && att != "" {
			attInt := convNameToPort(protocol, att)
			cfMo.AddProperty(s.gbpName, attInt)
		}
	}

	// make reference
	tocfURI := fmt.Sprintf("%s%s/42/%s", ruleMo.Uri, subjClassRsrc, escapeName(cname, false))
	toCF := &gbpToMo{}
	toCF.setSubject(subjClassRsrc)
	toCF.Make("", tocfURI)

	cfRef := Reference{
		Subject:      subjL24Class,
		ReferenceUri: uri,
	}
	toCF.AddProperty(propTarget, cfRef)
	linkParentChild(ruleMo, &toCF.gbpCommonMo)
	addActionRef(ruleMo)
	hsc.addSubnets(ruleMo, cname)
	return nil
}

func (hsc *HpSubjChild) getRemoteIPs() []string {
	var res []string
	for _, cm := range hsc.Children {
		hri, ok := cm["hostprotRemoteIp"]
		if ok {
			addr, ok := hri.Attributes["addr"]
			if ok {
				res = append(res, addr)
			}
		}
	}

	return res
}

func (hsc *HpSubjChild) addSubnets(p *gbpCommonMo, name string) {
	ipSet := hsc.getRemoteIPs()
	log.Debugf("Subnets are: %v", ipSet)
	ss := &GBPSubnetSet{}
	ssUri := fmt.Sprintf("/PolicyUniverse/PolicySpace/%s/GbpSubnets/%s/", getTenantName(), escapeName(name, false))
	ss.Make(name, ssUri)
	hsc.subnetSetUri = ssUri
	for _, addr := range ipSet {
		if len(strings.Split(addr, "/")) == 1 {
			addr += "/32"
		}
		s := &GBPSubnet{}
		sUri := fmt.Sprintf("%sGbpSubnet/%s/", ssUri, escapeName(addr, false))
		s.Make(addr, sUri)
		linkParentChild(&ss.gbpCommonMo, &s.gbpCommonMo)
	}

	ssRef := &gbpToMo{}
	ssRef.setSubject(subjSGRuleToCidr)
	ssRefURI := fmt.Sprintf("%sGbpSecGroupRuleToRemoteAddressRSrc/205/%s/", p.Uri, escapeName(name, false))
	ssRef.Make("", ssRefURI)
	ref := Reference{
		Subject:      ss.Subject,
		ReferenceUri: ss.Uri,
	}
	ssRef.AddProperty(propTarget, ref)
	linkParentChild(p, &ssRef.gbpCommonMo)
}

func npNameFromDn(dn string) string {
	trimDn := strings.TrimPrefix(dn, fmt.Sprintf("/api/mo/uni/tn-%s/pol-", getTenantName()))
	trimDn = strings.TrimSuffix(trimDn, ".json")
	npName := strings.Split(trimDn, "/")[0]
	return npName
}

func convNameToPort(prot, port string) int {
	// based on net pkg
	var services = map[string]map[string]int{
		"udp": {
			"domain": 53,
		},
		"tcp": {
			"ftp":    21,
			"ftps":   990,
			"gopher": 70,
			"http":   80,
			"https":  443,
			"imap2":  143,
			"imap3":  220,
			"imaps":  993,
			"pop3":   110,
			"pop3s":  995,
			"smtp":   25,
			"ssh":    22,
			"telnet": 23,
		},
	}

	prot = strings.ToLower(prot)
	port = strings.ToLower(port)

	portMap := services[prot]
	if portMap != nil {
		res, ok := portMap[port]
		if ok {
			return res
		}
	}

	res, _ := strconv.Atoi(port)
	return res
}
