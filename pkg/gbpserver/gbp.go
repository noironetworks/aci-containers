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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	osexec "os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/noironetworks/aci-containers/pkg/apicapi"
	"github.com/noironetworks/aci-containers/pkg/gbpcrd/apis/aci.aw/v1"
)

const (
	gbpUpdPath = "/usr/local/bin/gbp_update.sh"
	tokenTime  = 20 * time.Second
)

var debugDB = false
var encapID = uint(7700000)
var classID = uint(32000)
var gMutex sync.Mutex
var MoDB = make(map[string]*gbpBaseMo)
var dbDataDir string
var apicCon *apicapi.ApicConnection

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

// delete children and then self from the DB
func (g *gbpBaseMo) delRecursive() {
	if g.permanent {
		log.Infof("delRecursive: %s - permanent", g.URI)
		return
	}

	log.Infof("delRecursive: %s", g.URI)
	for _, c := range g.Children {
		cMo := MoDB[c]
		if cMo != nil {
			cMo.delRecursive()
		}
	}

	// delete any reference as well
	ref, err := g.getTarget()
	if err == nil {
		rMo := MoDB[ref]
		if rMo != nil {
			rMo.delRecursive()
		} else {
			log.Errorf("delRecursive: %s not found", ref)
		}
	}

	delete(MoDB, g.URI)
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
	refURI := fmt.Sprintf("%s%s/288/%s/", g.URI, refSubj, escapeName(targetName, false))
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
	eic.AddProperty("multicastGroupIP", "225.107.24.233")
	eic.SetParent(epg.Subject, eic.Subject, epg.URI)
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

func (bd *GBPBridgeDomain) Make(name, uri, subnetsUri string) error {
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
	eic.SetParent(bd.Subject, eic.Subject, bd.URI)

	// create subnets resource
	netRs := &GBPBDToSubnets{}
	netRs.setSubject(subjBDToSubnets)
	netRsUri := filepath.Join(uri, subjBDToSubnets)
	netRs.Make("", netRsUri+"/")
	netRs.SetParent(subjBD, subjBDToSubnets, uri)

	netsRef := RefProperty{
		Subject: subjSubnetSet,
		RefURI:  subnetsUri,
	}

	netRs.AddProperty(propTarget, netsRef)
	bd.AddChild(netRs.URI)
	netRs.SetParent(bd.Subject, netRs.Subject, bd.URI)

	// create GbpBridgeDomainToNetworkRSrc
	bdnw := &GBPBDToVrf{}
	bdnwUri := filepath.Join(uri, subjBDToVrf)
	bdnw.setSubject(subjBDToVrf)
	bdnw.Make("", bdnwUri+"/")
	vrfRef := RefProperty{
		Subject: subjVRF,
		RefURI:  defVrfURI,
	}
	bdnw.AddProperty(propTarget, vrfRef)
	bdnw.SetParent(bd.Subject, bdnw.Subject, bd.URI)
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

func getEncapClass() (uint, uint) {
	e, c := encapID, classID
	encapID++
	classID++

	if classID > 64000 {
		classID = 32000
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
	eic.SetParent(rd.Subject, eic.Subject, rd.URI)
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
	//	s.AddProperty(propMac, defRMac)
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
	// create subnet set
	ss := &GBPSubnetSet{}
	ss.Make("allsubnets", defSubnetsURI)
	sn := escapeName(subnet, false)
	uri := fmt.Sprintf("%sGbpSubnet/%s/", defSubnetsURI, sn)
	s := &GBPSubnet{}
	s.Make(subnet, uri)

	ss.AddChild(s.URI)
	s.SetParent(subjSubnetSet, subjSubnet, ss.URI)
}

func CreateDefVrf() {
	vrf := &GBPRoutingDomain{}
	// TODO: add subnet ref if necessary
	vrf.Make(defVrfName, defVrfURI)
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
	fm.SetParent(fd.Subject, fm.Subject, fd.URI)
	fd.AddChild(bdRef.URI)
	bdRef.SetParent(fd.Subject, bdRef.Subject, fd.URI)

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
	// setparent
	fdRef.SetParent(epg.Subject, fdRef.Subject, epg.URI)

	snetRef := GBPEPGToSnet{}
	snetRef.setSubject(subjEPGToSnet)
	snetRef.Make("", uri+"GbpEpGroupToSubnetsRSrc/")
	tosnet := RefProperty{
		Subject: subjSubnetSet,
		RefURI:  defSubnetsURI,
	}

	snetRef.AddProperty(propTarget, tosnet)
	epg.AddChild(snetRef.URI)
	snetRef.SetParent(epg.Subject, snetRef.Subject, epg.URI)
	return MoDB[uri]
}

func InitDB(dataDir, apic, region string) {
	if region != "None" {
		defRegion = region
	}
	log.Infof("InitDB(%s, %s, %s)", dataDir, apic, region)
	if apic != "None" {
		var err error
		log1 := log.New()
		apicCon, err = apicapi.New(log1, []string{apic}, "admin", "noir0!234", nil, nil, "test", 60, 5)
		if err != nil {
			log.Fatalf("Connecting to APIC: %v", err)
		}
	}

	dbDataDir = dataDir
	//	if restoreDB() == nil {
	//		return
	//	}

	CreateRoot()
	CreateDefVrf()
	podBDS = &BDSubnet{
		bdName:      defBDName,
		mcastGroup:  defMcastGroup,
		fdName:      defFDName,
		subnetsName: defSubnets,
		snet:        defSubnet,
	}
	podBDS.Setup()

	nodeBDS := &BDSubnet{
		bdName:      nodeBDName,
		mcastGroup:  nodeMcastGroup,
		fdName:      nodeFDName,
		subnetsName: nodeSubnets,
		snet:        nodeSubnet,
	}

	nodeBDS.Setup()
	SendDefaultsToAPIC()

	// create a wildcard contract
	emptyRule := v1.WLRule{}
	emptyC := Contract{
		Name:   anyConName,
		Tenant: kubeTenant,
		AllowList: []v1.WLRule{
			emptyRule,
		},
	}

	emptyC.Make()

	epgList := []*EPG{
		{
			Name:   defEPGName,
			Tenant: kubeTenant,
			ProvContracts: []string{
				anyConName,
			},
			ConsContracts: []string{
				anyConName,
			},
		},
		{
			Name:   kubeSysEPGName,
			Tenant: kubeTenant,
			ProvContracts: []string{
				anyConName,
			},
			ConsContracts: []string{
				anyConName,
			},
		},
		{
			Name:   kubeNodeEPGName,
			Tenant: kubeTenant,
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

func getMoFile() string {
	return filepath.Join(dbDataDir, "mo.json")
}

func getInvDir() string {
	return filepath.Join(dbDataDir, "inventory")
}

func restoreDB() error {
	mofile := getMoFile()
	data, err := ioutil.ReadFile(mofile)
	if err != nil {
		log.Infof("Reading %s - %v", mofile, err)
		return err
	}

	var moList []gbpBaseMo

	err = json.Unmarshal(data, &moList)
	if err != nil {
		log.Infof("Decoding %s - %v", mofile, err)
		return err
	}

	for _, mo := range moList {
		mm := new(gbpBaseMo)
		*mm = mo
		MoDB[mo.URI] = mm
	}

	invdir := getInvDir()
	vteps, err := ioutil.ReadDir(invdir)
	if err != nil {
		log.Infof("Reading %s - %v", invdir, err)
		return nil // ignore the error
	}

	for _, vtep := range vteps {
		ReadInvFile(vtep.Name(), filepath.Join(invdir, vtep.Name()))
	}

	return nil
}

func addToMap(sum, addend map[string]*gbpCommonMo) {
	for k, m := range addend {
		sum[k] = m
	}
}

func getMoMap() map[string]*gbpCommonMo {
	moMap := make(map[string]*gbpCommonMo)
	for k, mo := range MoDB {
		moMap[k] = &mo.gbpCommonMo
	}

	return moMap
}

func DoAll() {

	for vtep := range InvDB {
		moMap := getMoMap()
		addToMap(moMap, GetInvMoMap(vtep))
		fileName := fmt.Sprintf("/tmp/gen_policy.%s.json", vtep)
		printSorted(moMap, fileName, false)
		out, err := osexec.Command(gbpUpdPath, vtep).CombinedOutput()
		if err != nil {
			log.Errorf("%s returned %v", gbpUpdPath, err)
		} else {
			log.Infof("wrote vtep %s -- %s", vtep, out)
		}
	}

	saveDBToFile()

	//	fmt.Printf("policy.json: %s", policyJson)
}
func invToCommon(vtep string) map[string]*gbpCommonMo {
	moMap := make(map[string]*gbpCommonMo)

	invM := InvDB[vtep]
	for k, mo := range invM {
		moMap[k] = &mo.gbpCommonMo
	}

	return moMap
}

func saveDBToFile() {
	invDir := getInvDir()
	err := os.MkdirAll(invDir, 0777)
	if err != nil {
		log.Errorf("os.MkDirAll: %s - %v", invDir, err)
		return
	}

	moMap := getMoMap()
	printSorted(moMap, getMoFile(), debugDB)
	for vtep := range InvDB {
		vtepFile := filepath.Join(invDir, vtep)
		printSorted(invToCommon(vtep), vtepFile, debugDB)
	}

}

func VerifyFile(pFile string, print bool) {
	data, err := ioutil.ReadFile(pFile)
	if err != nil {
		fmt.Printf("Reading %s - %v", pFile, err)
		return
	}

	var moList []gbpCommonMo

	err = json.Unmarshal(data, &moList)
	if err != nil {
		fmt.Printf("Decoding %s - %v", pFile, err)
		return
	}

	db := make(map[string]*gbpCommonMo)

	for _, m := range moList {
		mm := new(gbpCommonMo)
		*mm = m
		db[m.URI] = mm
	}

	for _, m := range moList {
		err = m.Verify(db)
		if err != nil {
			fmt.Printf("%v\n", err)
		}

	}

	if print {
		printSorted(db, pFile+".sorted", false)
	}
}

func printSorted(mos map[string]*gbpCommonMo, outFile string, debug bool) {
	var keys []string

	for k := range mos {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	var sortedMos []*gbpCommonMo

	for _, kk := range keys {
		m, ok := mos[kk]
		if !ok {
			fmt.Printf("ERROR: missing mo")
			continue
		} else {
			if debug {
				fmt.Printf("Appending mo %s\n", m.URI)
			}
		}
		sortedMos = append(sortedMos, m)
	}
	policyJson, err := json.MarshalIndent(sortedMos, "", "    ")
	if err != nil {
		fmt.Printf("ERROR: %v", err)
	}
	err = ioutil.WriteFile(outFile, policyJson, 0644)
	if err != nil {
		log.Errorf("%s - %v", outFile, err)
	} else {
		if debug {
			log.Infof("Wrote %s", outFile)
		}
	}
}

func SendDefaultsToAPIC() {
	if apicCon == nil {
		return
	}

	log.Infof("Posting tenant to cAPIC")
	vrfMo := apicapi.NewFvCtx(kubeTenant, defVrfName)
	cCtxMo := apicapi.NewCloudCtxProfile(kubeTenant, cctxProfName())
	cidrMo := apicapi.NewCloudCidr(cCtxMo.GetDn(), defCAPICCidr)
	cCtxMoBody := cCtxMo["cloudCtxProfile"]
	ctxChildren := []apicapi.ApicObject{
		cidrMo,
		apicapi.NewCloudRsToCtx(cCtxMo.GetDn(), defVrfName),
		apicapi.NewCloudRsCtxProfileToRegion(cCtxMo.GetDn(), "uni/clouddomp/provp-aws/region-"+defRegion),
		//		apicapi.NewCloudRsCtxProfileToRegion(cCtxMo.GetDn(), "uni/clouddomp/provp-aws/region-us-west-1"),
	}

	for _, child := range ctxChildren {
		cCtxMoBody.Children = append(cCtxMoBody.Children, child)
	}

	epgToVrf := apicapi.EmptyApicObject("cloudRsCloudEPgCtx", "")
	epgToVrf["cloudRsCloudEPgCtx"].Attributes["tnFvCtxName"] = defVrfName
	cepgA := apicapi.NewCloudEpg(kubeTenant, defCloudApp, cApicName(defEPGName))
	cepgA["cloudEPg"].Children = append(cepgA["cloudEPg"].Children, epgToVrf)

	awsProvider := apicapi.NewCloudAwsProvider(kubeTenant, defRegion, "gmeouw1")
	awsProvider["cloudAwsProvider"].Attributes["accountId"] = "878180092573"
	var cfgMos = []apicapi.ApicObject{
		apicapi.NewFvTenant(kubeTenant),
		vrfMo,
		awsProvider,
		cCtxMo,
		apicapi.NewCloudSubnet(cidrMo.GetDn(), defCAPICSubnet),
		apicapi.NewCloudApp(kubeTenant, defCloudApp),
		cepgA,
	}
	for _, cmo := range cfgMos {
		err := apicCon.PostDnInline(cmo.GetDn(), cmo)
		if err != nil {
			log.Errorf("Post %s -- %v", cmo.GetDn(), err)
			return
		}
	}

	log.Infof("Done posting...")

	go func() {
		ticker := time.NewTicker(tokenTime)
		for range ticker.C {
			gMutex.Lock()
			apicCon.ForceRelogin()
			gMutex.Unlock()
		}
	}()
	time.Sleep(3 * time.Second) // delay before any EP can be attached
}
