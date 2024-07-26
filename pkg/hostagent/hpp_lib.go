// Copyright 2024 Cisco Systems, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRATIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package hostagent

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

type GBPConfig struct {
	policyDB []*gbpBaseMo
	tenant   string
}

func (agent *HostAgent) initGbpConfig() {
	GbpConfig = &GBPConfig{}
	GbpConfig.policyDB = make([]*gbpBaseMo, 0)
	GbpConfig.tenant = agent.config.DefaultEg.PolicySpace
}

const (
	propName         = "name"
	subjSecGroup     = "GbpLocalSecGroup"
	subjSGSubj       = "GbpLocalSecGroupSubject"
	subjSGRule       = "GbpLocalSecGroupRule"
	propEther        = "etherT"
	propProt         = "prot"
	propConnTrack    = "connectionTracking"
	subjL24Class     = "GbpeLocalL24Classifier"
	propDToPort      = "dToPort"
	propDFromPort    = "dFromPort"
	propSToPort      = "sToPort"
	propSFromPort    = "sFromPort"
	subjClassRsrc    = "GbpLocalSecGroupRuleToClassifierRSrc"
	propTarget       = "target"
	subjAction       = "GbpLocalAllowDenyAction"
	subjActionRsrc   = "GbpLocalSecGroupRuleToActionRSrc"
	subjSubnetSet    = "GbpLocalSubnets"
	subjSubnet       = "GbpLocalSubnet"
	propGw           = "virtualRouterIp"
	propPrefix       = "prefixLen"
	propNw           = "address"
	subjSGRuleToCidr = "GbpLocalSecGroupRuleToRemoteAddressRSrc"
)

type Property struct {
	Name  string      `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Value interface{} `protobuf:"bytes,2,opt,name=data,proto3" json:"data,omitempty"`
}

type GBPObject struct {
	Subject        string      `protobuf:"bytes,1,opt,name=subject,proto3" json:"subject,omitempty"`
	Uri            string      `protobuf:"bytes,2,opt,name=uri,proto3" json:"uri,omitempty"`
	Properties     []*Property `protobuf:"bytes,3,rep,name=properties,proto3" json:"properties,omitempty"`
	Children       []string    `protobuf:"bytes,4,rep,name=children,proto3" json:"children,omitempty"`
	ParentSubject  string      `protobuf:"bytes,5,opt,name=parent_subject,json=parentSubject,proto3" json:"parent_subject,omitempty"`
	ParentUri      string      `protobuf:"bytes,6,opt,name=parent_uri,json=parentUri,proto3" json:"parent_uri,omitempty"`
	ParentRelation string      `protobuf:"bytes,7,opt,name=parent_relation,json=parentRelation,proto3" json:"parent_relation,omitempty"`
}

type gbpCommonMo struct {
	GBPObject
	isRef     bool
	permanent bool // do not delete
}

type gbpBaseMo struct {
	gbpCommonMo
}

type GBPContract struct {
	gbpBaseMo
}

type GBPL24Classifier struct {
	gbpBaseMo
}

func (c *GBPL24Classifier) Make(name, uri string) error {
	c.Subject = subjL24Class
	c.Uri = uri
	c.save()
	return nil
}

func (c *GBPL24Classifier) Validate() error {
	return nil
}

type isProperty_Value interface {
	isProperty_Value()
}

func (g *gbpCommonMo) AddChild(uri string) {
	g.Children = append(g.Children, uri)
}

func (g *gbpCommonMo) SetParent(subj, rel, uri string) {
	g.ParentSubject, g.ParentRelation, g.ParentUri = subj, rel, uri
}

func getTenantName() string {
	return GbpConfig.tenant
}

func (g *gbpCommonMo) AddProperty(name string, data interface{}) {
	var p *Property

	switch data := data.(type) {
	case string:
		p = &Property{Name: name, Value: data}
	case int32:
		p = &Property{Name: name, Value: data}
	case uint:
		p = &Property{Name: name, Value: int32(data)}
	case int:
		p = &Property{Name: name, Value: int32(data)}
	case Reference:
		p = &Property{Name: name, Value: data}
	default:
		log.Fatalf("Unknown type for property %s", name)
	}
	g.Properties = append(g.Properties, p)
}

func (g *gbpCommonMo) DelProperty(name string) {
	p := g.Properties

	for ix, prop := range p {
		if prop.Name == name {
			copy(p[ix:], p[ix+1:])
		}
	}

	g.Properties = p[:len(p)-1]
}

type Property_StrVal struct {
	StrVal string `protobuf:"bytes,2,opt,name=strVal,proto3,oneof"`
}

type Property_IntVal struct {
	IntVal int32 `protobuf:"varint,3,opt,name=intVal,proto3,oneof"`
}

type Property_RefVal struct {
	RefVal *Reference `protobuf:"bytes,4,opt,name=refVal,proto3,oneof"`
}

func (*Property_StrVal) isProperty_Value() {}

func (*Property_IntVal) isProperty_Value() {}

func (*Property_RefVal) isProperty_Value() {}

type Reference struct {
	Subject      string `protobuf:"bytes,1,opt,name=subject,proto3" json:"subject,omitempty"`
	ReferenceUri string `protobuf:"bytes,2,opt,name=reference_uri,json=referenceUri,proto3" json:"reference_uri,omitempty"`
}

func (g *gbpBaseMo) save() {
	// json fixup
	if g.Children == nil {
		g.Children = []string{}
	}
	if g.Properties == nil {
		g.Properties = []*Property{}
	}

	modb := getMoDB()
	if modb == nil {
		log.Fatalf("save %s, MoDB not found", g.Uri)
	}
	*modb = append(*modb, g)
}

func getMoDB() *[]*gbpBaseMo {
	return &GbpConfig.policyDB
}

func escapeName(n string, undo bool) string {
	escs := []struct {
		Orig   string
		Escape string
	}{
		{
			Orig:   "/",
			Escape: "%2f",
		},
		{
			Orig:   "[",
			Escape: "%5b",
		},
		{
			Orig:   "]",
			Escape: "%5d",
		},
		{
			Orig:   "|",
			Escape: "%7c",
		},
	}

	if undo {
		for _, e := range escs {
			n = strings.Replace(n, e.Escape, e.Orig, -1)
		}
	} else {
		for _, e := range escs {
			n = strings.Replace(n, e.Orig, e.Escape, -1)
		}
	}

	return n
}

type gbpToMo struct {
	gbpBaseMo
}

func (to *gbpToMo) setSubject(subj string) {
	to.Subject = subj
}

func (to *gbpToMo) Make(name, uri string) error {
	if to.Subject == "" {
		return fmt.Errorf("subject not initialized")
	}

	to.Uri = uri
	to.isRef = true
	to.save()
	return nil
}

func (to *gbpToMo) Validate() error {
	if to.ParentUri == "" || to.ParentRelation == "" || to.ParentSubject == "" {
		return fmt.Errorf("missing parent info")
	}

	if len(to.Properties) != 1 {
		return fmt.Errorf("expected single property, have %d", len(to.Properties))
	}

	if to.Properties[0].Name != propTarget {
		return fmt.Errorf("expected target property, have %s", to.Properties[0].Name)
	}
	return nil
}

type GBPAction struct {
	gbpBaseMo
}

func (a *GBPAction) Make(name, uri string) error {
	a.Subject = subjAction
	a.Uri = uri
	a.AddProperty(propName, name)
	a.permanent = true // as we use a single instance of this action
	a.save()
	return nil
}

func (a *GBPAction) Validate() error {
	return nil
}

type GBPSubnetSet struct {
	gbpBaseMo
}

func (ss *GBPSubnetSet) Make(name, uri string) error {
	ss.Subject = subjSubnetSet
	ss.Uri = uri
	ss.AddProperty(propName, name)
	ss.save()
	return nil
}

func (ss *GBPSubnetSet) Validate() error {
	return nil
}

type GBPSubnet struct {
	gbpBaseMo
}

func (s *GBPSubnet) Make(name, uri string) error {
	fields := strings.Split(name, "/")
	if len(fields) != 2 {
		return fmt.Errorf("bad name %s for subnet -- need gw/len", name)
	}

	pLen, _ := strconv.Atoi(fields[1])
	_, ipnet, err := net.ParseCIDR(name)
	if err != nil {
		return err
	}

	s.Subject = subjSubnet
	s.Uri = uri
	s.AddProperty(propName, fields[0])
	s.AddProperty(propGw, fields[0])
	s.AddProperty(propPrefix, pLen)
	s.AddProperty(propNw, strings.Split(ipnet.String(), "/")[0])
	s.save()
	return nil
}

func (s *GBPSubnet) Validate() error {
	return nil
}

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

func addActionRef(p *gbpCommonMo) {
	// action and action ref
	aRef := &gbpToMo{}
	aRef.setSubject(subjActionRsrc)
	arefURI := fmt.Sprintf("%sGbpLocalSecGroupRuleToActionRSrc/%s/%s/", p.Uri, subjAction, "allow")
	aRef.Make("", arefURI)
	ref := Reference{
		Subject:      subjAction,
		ReferenceUri: "/PolicyUniverse/PolicySpace/common/GbpLocalAllowDenyAction/allow/",
	}
	aRef.AddProperty(propTarget, ref)
	linkParentChild(p, &aRef.gbpCommonMo)
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
		return fmt.Errorf("malformed network policy")
	}

	hpp := &gbpBaseMo{}
	hpp.Subject = subjSecGroup
	hpp.Uri = np.getURI()
	hpp.AddProperty(propName, np.HostprotPol.Attributes[propName])
	log.Debugf("NP make name: %s uri: %s pol: %+v", np.HostprotPol.Attributes[propName], hpp.Uri, np)
	hpp.save()
	clist := np.HostprotPol.getChildren("hostprotSubj")
	for _, c := range clist {
		if c == nil {
			return fmt.Errorf("hostprotSubj not found")
		}

		if c.Attributes == nil {
			return fmt.Errorf("malformed network policy subject")
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
	}

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

func (hpp *Hpp) getChildren(key string) []*HpSubj {
	var res []*HpSubj

	for _, cm := range hpp.Children {
		obj, ok := cm[key]
		if ok {
			hs := new(HpSubj)
			*hs = *obj
			res = append(res, hs)
		}
	}

	return res
}

func (hs *HpSubj) Make(hsMo *gbpCommonMo, npName string) error {
	cList := hs.getChildren("hostprotRule")

	for _, c := range cList {
		if c.Attributes == nil {
			return fmt.Errorf("malformed network policy rule")
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
	uri := fmt.Sprintf("/PolicyUniverse/PolicySpace/%s/GbpeLocalL24Classifier/%s/", getTenantName(), escapeName(cname, false))
	hsc.classifierUri = uri
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
	tocfURI := fmt.Sprintf("%s%s/%s/%s", ruleMo.Uri, subjClassRsrc, subjL24Class, escapeName(cname, false))
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

	ipSet := hsc.getRemoteIPs()
	log.Debugf("Subnets are: %v", ipSet)
	ss := &GBPSubnetSet{}
	ssUri := fmt.Sprintf("/PolicyUniverse/PolicySpace/%s/GbpLocalSubnets/%s/", getTenantName(), escapeName(cname, false))

	hsc.subnetSetUri = ssUri

	ssRef := &gbpToMo{}
	ssRef.setSubject(subjSGRuleToCidr)
	ssRefURI := fmt.Sprintf("%sGbpLocalSecGroupRuleToRemoteAddressRSrc/%s/%s/", ruleMo.Uri, subjSubnetSet, escapeName(cname, false))
	ssRef.Make("", ssRefURI)

	cfMo.Make(cname, uri)
	ss.Make(cname, ssUri)
	for _, addr := range ipSet {
		if len(strings.Split(addr, "/")) == 1 {
			addr += "/32"
		}
		s := &GBPSubnet{}
		sUri := fmt.Sprintf("%sGbpLocalSubnet/%s/", ssUri, escapeName(strings.Split(addr, "/")[0], false))
		s.Make(addr, sUri)
		linkParentChild(&ss.gbpCommonMo, &s.gbpCommonMo)
	}
	ref := Reference{
		Subject:      ss.Subject,
		ReferenceUri: ss.Uri,
	}
	ssRef.AddProperty(propTarget, ref)
	linkParentChild(ruleMo, &ssRef.gbpCommonMo)

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
