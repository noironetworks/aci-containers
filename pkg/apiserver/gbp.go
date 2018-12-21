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
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

const (
	propName          = "name"
	propIntraPolicy   = "intraGroupPolicy"
	defIntraPolicy    = "allow"
	subjEPG           = "GbpEpGroup"
	subjBD            = "GbpBridgeDomain"
	subjEIC           = "GbpeInstContext"
	subjBDNW          = "GbpBridgeDomainToNetworkRSrc"
	subjSubnetRsrc    = "GbpForwardingBehavioralGroupToSubnetsRSrc"
	subjContract      = "GbpContract"
	subjSubject       = "GbpSubject"
	subjRule          = "GbpRule"
	subjClassRsrc     = "GbpRuleToClassifierRSrc"
	subjL24Class      = "GbpeL24Classifier"
	subjAction        = "GbpAllowDenyAction"
	subjActionRsrc    = "GbpRuleToActionRSrc"
	subjVRF           = "GbpRoutingDomain"
	subjVRFIntSubnets = "GbpRoutingDomainToIntSubnetsRSrc"
	subjSubnetSet     = "GbpSubnets"
	subjSubnet        = "GbpSubnet"
	propRoutingMode   = "routingMode"
	defRoutingMode    = "enabled"
	propEncapID       = "encapId"
	propClassID       = "classid"
	propTarget        = "target"
	propGw            = "virtualRouterIp"
	propPrefix        = "prefixLen"
	propNw            = "address"
	propMac           = "macAddress"
	defRMac           = "00:22:bd:f8:19:ff"
	defSubnetsURI     = "/PolicyUniverse/PolicySpace/common/GbpSubnets/allsubnets/"
	defVrfURI         = "/PolicyUniverse/PolicySpace/common/GbpRoutingDomain/defaultVrf/"
	defVrfName        = "defaultVrf"
	defBDURI          = "/PolicyUniverse/PolicySpace/common/GbpBridgeDomain/defaultBD/"
	defBDName         = "defaultBD"
)

var encapID = uint(5000)
var classID = uint(5000)
var gMutex sync.Mutex
var MoList []*gbpBaseMo

type GBPMo interface {
	Make(name, uri string) error
	FromJSON(j []byte) error
	SetParent(subj, rel, uri string)
	AddChild(uri string)
	AddProperty(name string, data interface{})
	WriteJSON() []byte
	Validate() error
	GetStringProperty(name string) string
}

type Property struct {
	Name string      `json:"name,omitempty"`
	Data interface{} `json:"data,omitempty"`
}

type RefProperty struct {
	Subject string `json:"subject,omitempty"`
	RefURI  string `json:"reference_uri,omitempty"`
}

type gbpBaseMo struct {
	Subject    string     `json:"subject,omitempty"`
	URI        string     `json:"uri",omitempty"`
	Properties []Property `json:"properties",omitempty"`
	Children   []string   `json:"children",omitempty"`
	ParentSub  string     `json:"parent_subject,omitempty"`
	ParentURI  string     `json:"parent_uri,omitempty"`
	ParentRel  string     `json:"parent_relation,omitempty"`
}

func (g *gbpBaseMo) FromJSON(j []byte) error {
	return json.Unmarshal(j, g)
}

func (g *gbpBaseMo) SetParent(subj, rel, uri string) {
	g.ParentSub, g.ParentRel, g.ParentURI = subj, rel, uri
}

func (g *gbpBaseMo) AddChild(uri string) {
	g.Children = append(g.Children, uri)
}

func (g *gbpBaseMo) AddProperty(name string, data interface{}) {
	p := Property{Name: name, Data: data}
	g.Properties = append(g.Properties, p)
}

func (g *gbpBaseMo) WriteJSON() ([]byte, error) {
	return json.Marshal(g)
}

func (g *gbpBaseMo) save() {
	gMutex.Lock()
	defer gMutex.Unlock()

	// json fixup
	if g.Children == nil {
		g.Children = []string{}
	}
	if g.Properties == nil {
		g.Properties = []Property{}
	}
	MoList = append(MoList, g)
}

func (g *gbpBaseMo) GetStringProperty(name string) string {
	for _, p := range g.Properties {
		if p.Name == name {
			res, ok := p.Data.(string)
			if ok {
				return res
			}

			break
		}
	}

	return ""
}

type GBPEpGroup struct {
	gbpBaseMo
}

func (epg *GBPEpGroup) Make(name, uri string) error {
	epg.Subject = subjEPG
	epg.URI = uri
	epg.AddProperty(propName, name)
	epg.AddProperty(propIntraPolicy, defIntraPolicy)
	epg.save()
	return nil
}

func (epg *GBPEpGroup) Validate() error {
	return nil
}

type GBPBridgeDomain struct {
	gbpBaseMo
}

func (bd *GBPBridgeDomain) Make(name, uri string) error {
	bd.Subject = subjBD
	bd.URI = uri
	bd.AddProperty(propName, name)
	bd.AddProperty(propRoutingMode, defRoutingMode)
	// create GBPeInstContext
	eic, err := createEIC(subjBD, uri)
	if err != nil {
		return err
	}
	bd.AddChild(eic.URI)

	// create subnets resource
	netRs := &GBPSubnetRsrc{}
	netRsUri := filepath.Join(uri, subjSubnetRsrc)
	netRs.Make("", netRsUri+"/")
	netRs.SetParent(subjBD, subjSubnetRsrc, uri)

	netsRef := RefProperty{
		Subject: subjSubnetSet,
		RefURI:  defSubnetsURI,
	}

	netRs.AddProperty(propTarget, netsRef)
	bd.AddChild(netRs.URI)

	// create GbpBridgeDomainToNetworkRSrc
	bdnw := &GBPBDToNW{}
	bdnwUri := filepath.Join(uri, subjBDNW)
	bdnw.Make("", bdnwUri)
	vrfRef := RefProperty{
		Subject: subjVRF,
		RefURI:  defVrfURI,
	}
	bdnw.AddProperty(propTarget, vrfRef)
	bd.AddChild(bdnw.URI)
	bd.save()
	return nil
}

func (bd *GBPBridgeDomain) Validate() error {
	return nil
}

func (bd *GBPBridgeDomain) AddSubnet() error {
	return nil
}

type GBPeInstContext struct {
	gbpBaseMo
}

func (eic *GBPeInstContext) Make(name, uri string) error {
	eic.Subject = subjEIC
	eic.URI = uri
	eic.save()
	return nil
}

func (eic *GBPeInstContext) Validate() error {
	if eic.ParentURI == "" || eic.ParentRel == "" || eic.ParentSub == "" {
		return fmt.Errorf("Missing parent info")
	}

	if eic.GetStringProperty(propEncapID) == "" {
		return fmt.Errorf("Missing encapID")
	}

	if eic.GetStringProperty(propClassID) == "" {
		return fmt.Errorf("Missing classID")
	}

	return nil
}

type GBPBDToNW struct {
	gbpBaseMo
}

func (bdnw *GBPBDToNW) Make(name, uri string) error {
	bdnw.Subject = subjBDNW
	bdnw.URI = uri
	bdnw.save()
	return nil
}

func (bdnw *GBPBDToNW) Validate() error {
	if bdnw.ParentURI == "" || bdnw.ParentRel == "" || bdnw.ParentSub == "" {
		return fmt.Errorf("Missing parent info")
	}

	return nil
}

type GBPSubnetRsrc struct {
	gbpBaseMo
}

func (snet *GBPSubnetRsrc) Make(name, uri string) error {
	snet.Subject = subjSubnetRsrc
	snet.URI = uri
	snet.save()
	return nil
}

func (snet *GBPSubnetRsrc) Validate() error {
	if snet.ParentURI == "" || snet.ParentRel == "" || snet.ParentSub == "" {
		return fmt.Errorf("Missing parent info")
	}

	return nil
}

type GBPContract struct {
	gbpBaseMo
}

func (c *GBPContract) Make(name, uri string) error {
	c.Subject = subjContract
	c.URI = uri
	c.AddProperty(propName, name)
	c.save()
	return nil
}

func (c *GBPContract) Validate() error {
	if len(c.Children) < 1 {
		return fmt.Errorf("Missing subject info")
	}
	return nil
}

type GBPSubject struct {
	gbpBaseMo
}

func (s *GBPSubject) Make(name, uri string) error {
	s.Subject = subjSubject
	s.URI = uri
	s.AddProperty(propName, name)
	s.save()
	return nil
}

func (s *GBPSubject) Validate() error {
	return nil
}

type GBPRule struct {
	gbpBaseMo
}

func (r *GBPRule) Make(name, uri string) error {
	r.Subject = subjRule
	r.URI = uri
	r.AddProperty(propName, name)
	r.save()
	return nil
}

func (r *GBPRule) Validate() error {
	return nil
}

type GBPClassifierRsrc struct {
	gbpBaseMo
}

func (cr *GBPClassifierRsrc) Make(name, uri string) error {
	cr.Subject = subjClassRsrc
	cr.URI = uri
	cr.AddProperty(propName, name)
	cr.save()
	return nil
}

func (cr *GBPClassifierRsrc) Validate() error {
	return nil
}

type GBPL24Classifier struct {
	gbpBaseMo
}

func (c *GBPL24Classifier) Make(name, uri string) error {
	c.Subject = subjL24Class
	c.URI = uri
	c.save()
	return nil
}

func (c *GBPL24Classifier) Validate() error {
	return nil
}

type GBPActionRsrc struct {
	gbpBaseMo
}

func (ar *GBPActionRsrc) Make(name, uri string) error {
	ar.Subject = subjActionRsrc
	ar.URI = uri
	ar.save()
	return nil
}

func (ar *GBPActionRsrc) Validate() error {
	return nil
}

type GBPAction struct {
	gbpBaseMo
}

func (a *GBPAction) Make(name, uri string) error {
	a.Subject = subjAction
	a.URI = uri
	a.AddProperty(propName, name)
	a.save()
	return nil
}

func (a *GBPAction) Validate() error {
	return nil
}

type GBPRoutingDomain struct {
	gbpBaseMo
}

func getEncapClass() (uint, uint) {
	gMutex.Lock()
	defer gMutex.Unlock()
	e, c := encapID, classID
	encapID++
	classID++

	if encapID > 64000 {
		encapID = 5000
	}

	if classID > 64000 {
		classID = 5000
	}

	return e, c
}

func createEIC(pSub, pURI string) (*GBPeInstContext, error) {
	uURI := filepath.Join(pURI, subjEIC)
	uURI = uURI + "/"
	eic := &GBPeInstContext{}
	err := eic.Make("", uURI)
	if err != nil {
		return nil, err
	}

	eic.SetParent(pSub, subjEIC, pURI)
	enc, class := getEncapClass()
	eic.AddProperty(propEncapID, enc)
	eic.AddProperty(propClassID, class)

	return eic, nil
}

func (rd *GBPRoutingDomain) Make(name, uri string) error {
	rd.Subject = subjVRF
	rd.URI = uri
	rd.AddProperty(propName, name)

	// create GBPeInstContext
	eic, err := createEIC(subjVRF, uri)
	if err != nil {
		return err
	}
	rd.AddChild(eic.URI)
	rd.save()
	return nil
}

func (a *GBPRoutingDomain) Validate() error {
	return nil
}

type GBPVrfIntSubnet struct {
	gbpBaseMo
}

func (vi *GBPVrfIntSubnet) Make(name, uri string) error {
	vi.Subject = subjVRFIntSubnets
	vi.URI = uri
	vi.save()
	return nil
}

func (vi *GBPVrfIntSubnet) Validate() error {
	return nil
}

type GBPSubnetSet struct {
	gbpBaseMo
}

func (ss *GBPSubnetSet) Make(name, uri string) error {
	ss.Subject = subjSubnetSet
	ss.URI = uri
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
		return fmt.Errorf("Bad name %s for subnet -- need gw/len", name)
	}

	pLen, _ := strconv.Atoi(fields[1])
	_, ipnet, err := net.ParseCIDR(name)
	if err != nil {
		return err
	}

	s.Subject = subjSubnet
	s.URI = uri
	s.AddProperty(propName, name)
	s.AddProperty(propGw, fields[0])
	s.AddProperty(propPrefix, pLen)
	s.AddProperty(propMac, defRMac)
	s.AddProperty(propNw, ipnet.String())
	s.save()
	return nil
}

func (s *GBPSubnet) Validate() error {
	return nil
}

func CreateDefSubnet(subnet string) {
	snUri := strings.Replace(subnet, "/", "%2f", 1)
	uri := filepath.Join(defSubnetsURI, snUri)
	s := &GBPSubnet{}
	s.Make(subnet, uri)
}

func CreateDefVrf() {
	vrf := &GBPRoutingDomain{}
	// TODO: add subnet ref if necessary
	vrf.Make(defVrfName, defVrfURI)
}

func CreateDefBD() {
	bd := &GBPBridgeDomain{}
	bd.Make(defBDName, defBDURI)
}

func DoAll() {
	CreateDefSubnet("101.1.1.1/23")
	CreateDefVrf()
	CreateDefBD()
	policyJson, _ := json.MarshalIndent(MoList, "", "    ")
	fmt.Printf("policy.json: %s", policyJson)
}
