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
	"net"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/noironetworks/aci-containers/pkg/gbpcrd/apis/acipolicy/v1"
)

const (
	numClassIDs  = 32000
	firstClassID = 32000
	RdClassID    = 31999
	RdEncapID    = 7699999
	firstEncapID = 7700000
)

var gMutex sync.Mutex
var theServer *Server

func encapFromClass(class uint) uint {
	return firstEncapID + class
}

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
		g.Properties = []*Property{}
	}

	modb := getMoDB()
	if modb == nil {
		log.Fatalf("save %s, MoDB not found", g.Uri)
	}
	modb[g.Uri] = g
}

func getMoDB() map[string]*gbpBaseMo {
	return theServer.policyDB
}

func getMoSubTree(url string) []*GBPObject {
	mo := getMoDB()[url]
	if mo == nil {
		log.Errorf("mo %s not found", url)
		return nil
	}

	return mo.getSubTree()
}

// returns the preOrder traversal of the GBP subtree rooted at g.
func (g *gbpBaseMo) getSubTree() []*GBPObject {
	st := make([]*GBPObject, 0, 8)
	return g.preOrder(st)
}

func (g *gbpBaseMo) preOrder(moList []*GBPObject) []*GBPObject {
	// append self first
	moList = append(moList, &g.GBPObject)

	// append child subtrees
	for _, c := range g.Children {
		cMo := getMoDB()[c]
		if cMo == nil {
			log.Errorf("Child %s missing for %s", c, g.Uri)
			continue
		}
		moList = cMo.preOrder(moList)
	}

	return moList
}

// delete children and then self from the DB
func (g *gbpBaseMo) delRecursive() {
	if g.permanent {
		log.Debugf("delRecursive: %s - permanent", g.Uri)
		return
	}

	log.Debugf("delRecursive: %s", g.Uri)
	for _, c := range g.Children {
		cMo := getMoDB()[c]
		if cMo != nil {
			cMo.delRecursive()
		}
	}

	// delete any reference as well
	ref, err := g.getTarget()
	if err == nil {
		rMo := getMoDB()[ref]
		if rMo != nil {
			rMo.delRecursive()
		} else {
			log.Errorf("delRecursive: %s not found", ref)
		}
	}

	delete(getMoDB(), g.Uri)
}

// returns refMo URI, indexed by the actual target uri
func (g *gbpBaseMo) GetRefURIs(subject string) (map[string]string, error) {
	result := make(map[string]string)

	moDB := getMoDB()
	for _, c := range g.Children {
		cMo := moDB[c]
		if cMo == nil {
			return nil, fmt.Errorf("Child %s not found", c)
		}

		if cMo.isRef && cMo.Subject == subject {
			target, err := cMo.getTarget()
			if err != nil {
				return nil, fmt.Errorf("Target for %s not found - %w", c, err)
			}

			result[target] = c
		}
	}

	return result, nil
}

func (g *gbpBaseMo) AddRef(refSubj, targetURI string) error {
	targetMo := getMoDB()[targetURI]
	if targetMo == nil {
		return fmt.Errorf("Mo %s not found", targetURI)
	}
	targetName := targetMo.GetStringProperty(propName)
	refMo := &gbpToMo{}
	refMo.setSubject(refSubj)
	refURI := fmt.Sprintf("%s%s/288/%s/", g.Uri, refSubj, escapeName(targetName, false))
	refMo.Make("", refURI)

	p := Reference{
		Subject:      targetMo.Subject,
		ReferenceUri: targetURI,
	}
	refMo.AddProperty(propTarget, p)
	refMo.SetParent(g.Subject, refMo.Subject, g.Uri)
	g.AddChild(refURI)

	return nil
}

type GBPEpGroup struct {
	gbpBaseMo
}

func (epg *GBPEpGroup) Make(name, uri string) error {
	epg.Subject = subjEPG
	epg.Uri = uri
	epg.AddProperty(propName, name)
	epg.AddProperty(propIntraPolicy, defIntraPolicy)
	// create GBPeInstContext
	eic, err := createEIC(subjEPG, uri)
	if err != nil {
		return err
	}
	eic.AddProperty("multicastGroupIP", "225.107.24.233")
	eic.SetParent(epg.Subject, eic.Subject, epg.Uri)
	epg.AddChild(eic.Uri)
	epg.save()
	return nil
}

func (epg *GBPEpGroup) Validate() error {
	return nil
}

type GBPBridgeDomain struct {
	gbpBaseMo
}

func (bd *GBPBridgeDomain) Make(name, uri, subnetsUri string) error {
	bd.Subject = subjBD
	bd.Uri = uri
	bd.AddProperty(propName, name)
	bd.AddProperty(propRoutingMode, defRoutingMode)
	// create GBPeInstContext
	eic, err := createEIC(subjBD, uri)
	if err != nil {
		return err
	}
	bd.AddChild(eic.Uri)
	eic.SetParent(bd.Subject, eic.Subject, bd.Uri)

	// create subnets resource
	netRs := &GBPBDToSubnets{}
	netRs.setSubject(subjBDToSubnets)
	netRsUri := filepath.Join(uri, subjBDToSubnets)
	netRs.Make("", netRsUri+"/")
	netRs.SetParent(subjBD, subjBDToSubnets, uri)

	netsRef := Reference{
		Subject:      subjSubnetSet,
		ReferenceUri: subnetsUri,
	}

	netRs.AddProperty(propTarget, netsRef)
	bd.AddChild(netRs.Uri)
	netRs.SetParent(bd.Subject, netRs.Subject, bd.Uri)

	// create GbpBridgeDomainToNetworkRSrc
	bdnw := &GBPBDToVrf{}
	bdnwUri := filepath.Join(uri, subjBDToVrf)
	bdnw.setSubject(subjBDToVrf)
	bdnw.Make("", bdnwUri+"/")
	vrfRef := Reference{
		Subject:      subjVRF,
		ReferenceUri: getVrfUri(),
	}
	bdnw.AddProperty(propTarget, vrfRef)
	bdnw.SetParent(bd.Subject, bdnw.Subject, bd.Uri)
	bd.AddChild(bdnw.Uri)
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
	eic.Uri = uri
	eic.save()
	return nil
}

func (eic *GBPeInstContext) Validate() error {
	if eic.ParentUri == "" || eic.ParentRelation == "" || eic.ParentSubject == "" {
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

	to.Uri = uri
	to.isRef = true
	to.save()
	return nil
}

func (to *gbpToMo) Validate() error {
	if to.ParentUri == "" || to.ParentRelation == "" || to.ParentSubject == "" {
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
	c.Uri = uri
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
	s.Uri = uri
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
	r.Uri = uri
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
	cr.Uri = uri
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
	c.Uri = uri
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
	a.Uri = uri
	a.AddProperty(propName, name)
	a.permanent = true // as we use a single instance of this action
	a.save()
	return nil
}

func (a *GBPAction) Validate() error {
	return nil
}

type GBPRoutingDomain struct {
	gbpBaseMo
}

func getEncapClass(objURI string) (uint, uint) {
	return theServer.getEncapClass(objURI)
}

func freeEncapClass(objURI string) {
	theServer.freeEncapClass(objURI)
}

func createEIC(pSub, pURI string) (*GBPeInstContext, error) {
	uURI := filepath.Join(pURI, subjEIC)
	uURI += "/"
	enc, class := getEncapClass(uURI)
	return createEICWithEncap(pSub, pURI, enc, class)
}

func createEICWithEncap(pSub, pURI string, enc, class uint) (*GBPeInstContext, error) {
	uURI := filepath.Join(pURI, subjEIC)
	uURI += "/"
	eic := &GBPeInstContext{}
	err := eic.Make("", uURI)
	if err != nil {
		return nil, err
	}

	eic.SetParent(pSub, subjEIC, pURI)
	eic.AddProperty(propEncapID, enc)
	eic.AddProperty(propClassID, class)

	return eic, nil
}

func (rd *GBPRoutingDomain) Make(name, uri string) error {
	rd.Subject = subjVRF
	rd.Uri = uri
	rd.AddProperty(propName, name)

	// create GBPeInstContext
	enc := uint(theServer.config.VrfEncapID)
	class := uint(RdClassID)
	eic, err := createEICWithEncap(subjVRF, uri, enc, class)
	if err != nil {
		return err
	}
	rd.AddChild(eic.Uri)
	eic.SetParent(rd.Subject, eic.Subject, rd.Uri)
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
	vi.Uri = uri
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
		return fmt.Errorf("Bad name %s for subnet -- need gw/len", name)
	}

	pLen, _ := strconv.Atoi(fields[1])
	_, ipnet, err := net.ParseCIDR(name)
	if err != nil {
		return err
	}

	s.Subject = subjSubnet
	s.Uri = uri
	s.AddProperty(propName, name)
	s.AddProperty(propGw, fields[0])
	s.AddProperty(propPrefix, pLen)
	s.AddProperty(propNw, strings.Split(ipnet.String(), "/")[0])
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
	fd.Uri = uri
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
	fm.Uri = uri
	fm.save()
	return nil
}

func (ss *GBPFloodMcast) Validate() error {
	return nil
}

func CreateDefVrf() {
	vrf := &GBPRoutingDomain{}
	// TODO: add subnet ref if necessary
	vrf.Make(getVrfName(), getVrfUri())
}

// Initializes the Mo DB
func (s *Server) InitDB() {
	theServer = s
	s.policyDB = make(map[string]*gbpBaseMo)
	s.invDB = make(map[string]map[string]*gbpInvMo)

	CreateRoot(s.config)
	CreateDefVrf()
	podBDS = &BDSubnet{
		bdName:      defBDName,
		mcastGroup:  defMcastGroup,
		fdName:      defFDName,
		subnetsName: defSubnets,
		snet:        s.config.PodSubnet,
	}
	podBDS.Setup()

	nodeBDS := &BDSubnet{
		bdName:      nodeBDName,
		mcastGroup:  nodeMcastGroup,
		fdName:      nodeFDName,
		subnetsName: nodeSubnets,
		snet:        s.config.NodeSubnet,
	}

	nodeBDS.Setup()

	// create a wildcard contract
	emptyRule := v1.WLRule{}
	emptyC := Contract{
		Name:   anyConName,
		Tenant: getTenantName(),
		AllowList: []v1.WLRule{
			emptyRule,
		},
	}

	emptyC.Make()

	epgList := []*EPG{
		{
			Name:   defEPGName,
			Tenant: getTenantName(),
			ProvContracts: []string{
				anyConName,
			},
			ConsContracts: []string{
				anyConName,
			},
		},
		{
			Name:   kubeSysEPGName,
			Tenant: getTenantName(),
			ProvContracts: []string{
				anyConName,
			},
			ConsContracts: []string{
				anyConName,
			},
		},
		{
			Name:   kubeNodeEPGName,
			Tenant: getTenantName(),
			ProvContracts: []string{
				anyConName,
			},
			ConsContracts: []string{
				anyConName,
			},
			bds: nodeBDS,
		},
	}

	for _, e := range epgList {
		err := e.Make()
		if err != nil {
			log.Errorf("%v making %+v", err, e)
		}
	}
}

func addToMap(sum, addend map[string]*gbpCommonMo) {
	for k, m := range addend {
		sum[k] = m
	}
}

func getMoMap() map[string]*gbpCommonMo {
	moMap := make(map[string]*gbpCommonMo)
	for k, mo := range getMoDB() {
		moMap[k] = &mo.gbpCommonMo
	}

	return moMap
}

func getSnapShot(vtep string) []*GBPObject {
	moMap := getMoMap()
	addToMap(moMap, GetInvMoMap(vtep))

	var keys []string
	for k := range moMap {
		if len(k) > 1 { // skip topRoot
			keys = append(keys, k)
		}
	}

	sort.Strings(keys)

	moList := make([]*GBPObject, len(keys))
	for ix, k := range keys {
		mo := moMap[k]
		moList[ix] = &mo.GBPObject
	}

	return moList
}
