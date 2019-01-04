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
	"io/ioutil"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

var encapID = uint(5000)
var classID = uint(5000)
var gMutex sync.Mutex
var MoDB = make(map[string]*gbpBaseMo)

// BaseMo methods refer the underlying MoDB.
type gbpBaseMo struct {
	gbpCommonMo
}

func (g *gbpBaseMo) save() {

	// json fixup
	if g.Children == nil {
		g.Children = []string{}
	}
	if g.Properties == nil {
		g.Properties = []Property{}
	}
	MoDB[g.URI] = g
}

// returns refMo URI, indexed by the actual target uri
func (g *gbpBaseMo) GetRefURIs(subject string) (map[string]string, error) {
	result := make(map[string]string)

	for _, c := range g.Children {
		cMo := MoDB[c]
		if cMo == nil {
			return nil, fmt.Errorf("Child %s not found", c)
		}

		if cMo.isRef && cMo.Subject == subject {
			target, err := cMo.getTarget()
			if err != nil {
				return nil, fmt.Errorf("Target for %s not found - %v", c, err)
			}

			result[target] = c
		}
	}

	return result, nil
}

func (g *gbpBaseMo) AddRef(refSubj, targetURI string) error {
	targetMo := MoDB[targetURI]
	if targetMo == nil {
		return fmt.Errorf("Mo %s not found", targetURI)
	}
	targetName := targetMo.GetStringProperty(propName)
	refMo := &gbpToMo{}
	refMo.setSubject(refSubj)
	refURI := fmt.Sprintf("%s%s/%s/", g.URI, refSubj, targetName)
	refMo.Make("", refURI)

	p := RefProperty{
		Subject: targetMo.Subject,
		RefURI:  targetURI,
	}
	refMo.AddProperty(propTarget, p)
	refMo.SetParent(g.Subject, refMo.Subject, g.URI)
	g.AddChild(refURI)

	return nil
}

type GBPEpGroup struct {
	gbpBaseMo
}

func (epg *GBPEpGroup) Make(name, uri string) error {
	epg.Subject = subjEPG
	epg.URI = uri
	epg.AddProperty(propName, name)
	epg.AddProperty(propIntraPolicy, defIntraPolicy)
	// create GBPeInstContext
	eic, err := createEIC(subjEPG, uri)
	if err != nil {
		return err
	}
	epg.AddChild(eic.URI)
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
	netRs := &GBPBDToSubnets{}
	netRs.setSubject(subjBDToSubnets)
	netRsUri := filepath.Join(uri, subjBDToSubnets)
	netRs.Make("", netRsUri+"/")
	netRs.SetParent(subjBD, subjBDToSubnets, uri)

	netsRef := RefProperty{
		Subject: subjSubnetSet,
		RefURI:  defSubnetsURI,
	}

	netRs.AddProperty(propTarget, netsRef)
	bd.AddChild(netRs.URI)

	// create GbpBridgeDomainToNetworkRSrc
	bdnw := &GBPBDToVrf{}
	bdnwUri := filepath.Join(uri, subjBDToVrf)
	bdnw.setSubject(subjBDToVrf)
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

// gbpToMo implements a forward reference
type gbpToMo struct {
	gbpBaseMo
}

func (to *gbpToMo) setSubject(subj string) {
	to.Subject = subj
}

func (to *gbpToMo) Make(name, uri string) error {
	if to.Subject == "" {
		return fmt.Errorf("Subject not initialized")
	}

	to.URI = uri
	to.isRef = true
	to.save()
	return nil
}

func (to *gbpToMo) Validate() error {
	if to.ParentURI == "" || to.ParentRel == "" || to.ParentSub == "" {
		return fmt.Errorf("Missing parent info")
	}

	if len(to.Properties) != 1 {
		return fmt.Errorf("Expected single property. Have %d", len(to.Properties))
	}

	if to.Properties[0].Name != propTarget {
		return fmt.Errorf("Expected target property. Have %s", to.Properties[0].Name)
	}
	return nil
}

type GBPBDToVrf struct {
	gbpToMo
}
type GBPBDToSubnets struct {
	gbpToMo
}
type GBPEPGToFD struct {
	gbpToMo
}
type GBPFDToBD struct {
	gbpToMo
}
type GBPEPGToSnet struct {
	gbpToMo
}
type GBPRuleToClass struct {
	gbpToMo
}
type GBPRuleToAct struct {
	gbpToMo
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

type GBPFloodDomain struct {
	gbpBaseMo
}

func (fd *GBPFloodDomain) Make(name, uri string) error {
	fd.Subject = subjFD
	fd.URI = uri
	fd.AddProperty(propName, name)
	fd.save()
	return nil
}

func (ss *GBPFloodDomain) Validate() error {
	return nil
}

type GBPFloodMcast struct {
	gbpBaseMo
}

func (fm *GBPFloodMcast) Make(name, uri string) error {
	fm.Subject = subjFDMcast
	fm.URI = uri
	fm.save()
	return nil
}

func (ss *GBPFloodMcast) Validate() error {
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

func CreateDefFD() {
	// create child 1: default Mcast
	fm := &GBPFloodMcast{}
	fm.Make("", defFDMcastURI)
	fm.AddProperty(propMcast, defMcastGroup)
	fm.SetParent(subjFD, subjFDMcast, defFDURI)

	// create child 2: FD to DefaultBD reference
	bdRef := &GBPFDToBD{}
	bdRef.setSubject(subjFDToBD)
	bdRef.Make("", defFDToBDURI)

	to := RefProperty{
		Subject: subjBD,
		RefURI:  defBDURI,
	}

	bdRef.AddProperty(propTarget, to)

	fd := &GBPFloodDomain{}
	fd.Make(defFDName, defFDURI)
	fd.AddChild(fm.URI)
	fd.AddChild(bdRef.URI)

	// set properties
	fd.AddProperty("unknownFloodMode", "drop")
	fd.AddProperty("arpMode", "unicast")
	fd.AddProperty("neighborDiscMode", "unicast")
}

func CreateEPG(name, uri string) *gbpBaseMo {
	epg := &GBPEpGroup{}
	epg.Make(name, uri)

	fdRef := GBPEPGToFD{}
	fdRef.setSubject(subjEPGToFD)
	fdRef.Make("", uri+"GbpEpGroupToNetworkRSrc/")
	to := RefProperty{
		Subject: subjFD,
		RefURI:  defFDURI,
	}

	fdRef.AddProperty(propTarget, to)
	epg.AddChild(fdRef.URI)

	snetRef := GBPEPGToSnet{}
	snetRef.setSubject(subjEPGToSnet)
	snetRef.Make("", uri+"GbpEpGroupToSubnetsRSrc/")
	tosnet := RefProperty{
		Subject: subjSubnetSet,
		RefURI:  defSubnetsURI,
	}

	snetRef.AddProperty(propTarget, tosnet)
	epg.AddChild(snetRef.URI)
	return MoDB[uri]
}

func init() {
	CreateRoot()
}
func DoAll() {
	CreateDefSubnet("101.1.1.1/23")
	CreateDefVrf()
	CreateDefBD()
	CreateEPG(defEPGName, defEPGURI)

	moList := make([]*gbpCommonMo, 0, len(MoDB))
	for _, mo := range MoDB {
		moList = append(moList, &mo.gbpCommonMo)
	}

	for vtep := range InvDB {
		invMos := GetInvMoList(vtep)
		invMos = append(invMos, moList...)
		policyJson, _ := json.MarshalIndent(invMos, "", "    ")
		fileName := fmt.Sprintf("/tmp/gen_policy.%s.json", vtep)
		ioutil.WriteFile(fileName, policyJson, 0644)
	}

	//	fmt.Printf("policy.json: %s", policyJson)
}
