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
	log "github.com/Sirupsen/logrus"
	"github.com/davecgh/go-spew/spew"
	"strings"
)

const (
	kubeTenant        = "kube"
	propName          = "name"
	propIntraPolicy   = "intraGroupPolicy"
	defIntraPolicy    = "allow"
	subjRoot          = "DmtreeRoot"
	subjEPG           = "GbpEpGroup"
	subjEPGToFD       = "GbpEpGroupToNetworkRSrc"
	subjEPGToSnet     = "GbpEpGroupToSubnetsRSrc"
	subjEPGToCC       = "GbpEpGroupToConsContractRSrc"
	subjEPGToPC       = "GbpEpGroupToProvContractRSrc"
	subjFD            = "GbpFloodDomain"
	subjFDMcast       = "GbpeFloodContext"
	subjFDToBD        = "GbpFloodDomainToNetworkRSrc"
	subjBD            = "GbpBridgeDomain"
	subjEIC           = "GbpeInstContext"
	subjBDToVrf       = "GbpBridgeDomainToNetworkRSrc"
	subjBDToSubnets   = "GbpForwardingBehavioralGroupToSubnetsRSrc"
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
	subjSecGroup      = "GbpSecGroup"
	subjSGSubj        = "GbpSecGroupSubject"
	subjSGRule        = "GbpSecGroupRule"
	subjSGRuleToCidr  = "GbpSecGroupRuleToRemoteAddressRSrc"
	propRoutingMode   = "routingMode"
	defRoutingMode    = "enabled"
	propEncapID       = "encapId"
	propClassID       = "classid"
	propTarget        = "target"
	propGw            = "virtualRouterIp"
	propPrefix        = "prefixLen"
	propNw            = "address"
	propMac           = "macAddress"
	propEther         = "etherT"
	propProt          = "prot"
	propDToPort       = "dToPort"
	propDFromPort     = "dFromPort"
	propSToPort       = "sToPort"
	propSFromPort     = "sFromPort"
	defRMac           = "00:22:bd:f8:19:ff"
	defSubnets        = "allsubnets"
	nodeSubnets       = "nodesubnets"
	defSubnetsURI     = "/PolicyUniverse/PolicySpace/kube/GbpSubnets/allsubnets/"
	defVrfURI         = "GbpRoutingDomain/defaultVrf/"
	defVrfName        = "defaultVrf"
	defBDURI          = "/PolicyUniverse/PolicySpace/kube/GbpBridgeDomain/defaultBD/"
	defBDName         = "defaultBD"
	defFDName         = "defaultFD"
	nodeBDName        = "nodeBD"
	nodeFDName        = "nodeFD"
	defFDURI          = "/PolicyUniverse/PolicySpace/kube/GbpFloodDomain/defaultFD/"
	defFDMcastURI     = defFDURI + "GbpeFloodContext/"
	defFDToBDURI      = defFDURI + "GbpFloodDomainToNetworkRSrc/"
	defMcastGroup     = "225.0.193.80"
	nodeMcastGroup    = "225.0.193.81"
	propMcast         = "multicastGroupIP"
	defEPGURI         = "/PolicyUniverse/PolicySpace/kube/GbpEpGroup/"
	// make cAPIC happy
	defEPGName      = "kubernetes|kube-default"
	kubeSysEPGName  = "kubernetes|kube-system"
	kubeNodeEPGName = "kubernetes|kube-nodes"
	//defEPGName     = "kubernetes-kube-default"
	//kubeSysEPGName  = "kubernetes-kube-system"
	//kubeNodeEPGName = "kubernetes-kube-nodes"
	defPConfigName = "comp/prov-Kubernetes/ctrlr-[kube]-kube/sw-InsiemeLSOid"
	propConnTrack  = "connectionTracking"
	propOrder      = "order"
	nodeSubnet     = "1.100.201.0/24"
	anyConName     = "all-all"
	defSubnet      = "10.2.56.1/21"
	defCAPICSubnet = "10.2.50.0/21"
	defCAPICCidr   = "10.2.0.0/16"
	defCloudApp    = "kubeApp1"
)

var (
	defRegion = "us-east-2"
)

type BDSubnet struct {
	bdName      string
	mcastGroup  string
	fdName      string
	subnetsName string
	snet        string
}

var podBDS *BDSubnet

func getTenantName() string {
	if theServer != nil {
		return theServer.config.AciPolicyTenant
	}

	return "undefined"
}

func getVrfName() string {
	if theServer != nil {
		return theServer.config.AciVrf
	}

	return "undefined"
}

func getTenantUri() string {
	return fmt.Sprintf("/PolicyUniverse/PolicySpace/%s/", getTenantName())
}

func getVrfUri() string {
	return fmt.Sprintf("/PolicyUniverse/PolicySpace/%s/GbpRoutingDomain/%s/", getTenantName(), getVrfName())
}

func cctxProfName() string {
	return defVrfName + "_" + defRegion
}
func (bds *BDSubnet) SubnetsUri() string {
	return fmt.Sprintf("/PolicyUniverse/PolicySpace/%s/GbpSubnets/%s/", getTenantName(), bds.subnetsName)
}

func (bds *BDSubnet) SnUri() string {
	sn := escapeName(bds.snet, false)
	return fmt.Sprintf("/PolicyUniverse/PolicySpace/%s/GbpSubnets/%s/GbpSubnet/%s/", getTenantName(), bds.subnetsName, sn)
}

func (bds *BDSubnet) BDUri() string {
	return fmt.Sprintf("/PolicyUniverse/PolicySpace/%s/GbpBridgeDomain/%s/", getTenantName(), bds.bdName)
}

func (bds *BDSubnet) FDUri() string {
	return fmt.Sprintf("/PolicyUniverse/PolicySpace/%s/GbpFloodDomain/%s/", getTenantName(), bds.fdName)
}
func (bds *BDSubnet) FDMcastUri() string {
	return fmt.Sprintf("/PolicyUniverse/PolicySpace/%s/GbpFloodDomain/%s/GbpeFloodContext/", getTenantName(), bds.fdName)
}
func (bds *BDSubnet) FDToBDUri() string {
	return fmt.Sprintf("/PolicyUniverse/PolicySpace/%s/GbpFloodDomain/%s/GbpFloodDomainToNetworkRSrc/", getTenantName(), bds.fdName)
}

func (bds *BDSubnet) CreateSubnet() {
	// create subnet set
	ss := &GBPSubnetSet{}
	ss.Make(bds.subnetsName, bds.SubnetsUri())
	s := &GBPSubnet{}
	s.Make(bds.snet, bds.SnUri())

	ss.AddChild(s.Uri)
	s.SetParent(subjSubnetSet, subjSubnet, ss.Uri)
}

func (bds *BDSubnet) CreateBD() {
	bd := &GBPBridgeDomain{}
	bd.Make(bds.bdName, bds.BDUri(), bds.SubnetsUri())
}

func (bds *BDSubnet) CreateFD() {
	// create child 1: default Mcast
	fm := &GBPFloodMcast{}
	fm.Make("", bds.FDMcastUri())
	fm.AddProperty(propMcast, bds.mcastGroup)
	fm.SetParent(subjFD, subjFDMcast, bds.FDUri())

	// create child 2: FD to DefaultBD reference
	bdRef := &GBPFDToBD{}
	bdRef.setSubject(subjFDToBD)
	bdRef.Make("", bds.FDToBDUri())

	to := Reference{
		Subject:      subjBD,
		ReferenceUri: bds.BDUri(),
	}

	bdRef.AddProperty(propTarget, to)

	fd := &GBPFloodDomain{}
	fd.Make(bds.fdName, bds.FDUri())
	fd.AddChild(fm.Uri)
	fm.SetParent(fd.Subject, fm.Subject, fd.Uri)
	fd.AddChild(bdRef.Uri)
	bdRef.SetParent(fd.Subject, bdRef.Subject, fd.Uri)

	// set properties
	fd.AddProperty("unknownFloodMode", "drop")
	fd.AddProperty("arpMode", "unicast")
	fd.AddProperty("neighborDiscMode", "unicast")
}

func (bds *BDSubnet) Setup() {
	bds.CreateSubnet()
	bds.CreateBD()
	bds.CreateFD()
}

func (bds *BDSubnet) CreateEPG(name, uri string) *gbpBaseMo {
	epg := &GBPEpGroup{}
	epg.Make(name, uri)

	fdRef := GBPEPGToFD{}
	fdRef.setSubject(subjEPGToFD)
	fdRef.Make("", uri+"GbpEpGroupToNetworkRSrc/")
	to := Reference{
		Subject:      subjFD,
		ReferenceUri: bds.FDUri(),
	}

	fdRef.AddProperty(propTarget, to)
	epg.AddChild(fdRef.Uri)
	// setparent
	fdRef.SetParent(epg.Subject, fdRef.Subject, epg.Uri)

	snetRef := GBPEPGToSnet{}
	snetRef.setSubject(subjEPGToSnet)
	snetRef.Make("", uri+"GbpEpGroupToSubnetsRSrc/")
	tosnet := Reference{
		Subject:      subjSubnetSet,
		ReferenceUri: bds.SnUri(),
	}

	snetRef.AddProperty(propTarget, tosnet)
	epg.AddChild(snetRef.Uri)
	snetRef.SetParent(epg.Subject, snetRef.Subject, epg.Uri)
	return getMoDB()[uri]

}

type GBPMo interface {
	Make(name, uri string) error
	FromJSON(j []byte) error
	SetParent(subj, rel, uri string)
	AddChild(uri string)
	DelChild(uri string)
	AddProperty(name string, data interface{})
	WriteJSON() []byte
	Validate() error
	GetStringProperty(name string) string
	GetIntProperty(name string) int
	GetRefURIs(subject string) (map[string]string, error)
}

type gbpCommonMo struct {
	GBPObject
	isRef     bool
	permanent bool // do not delete
}

func (g *gbpCommonMo) needParent() bool {
	switch g.Subject {
	case subjContract:
		return false
	case subjEPG:
		return false
	case subjVRF:
		return false
	case subjFD:
		return false
	case subjBD:
		return false
	case subjL24Class:
		return false
	case subjAction:
		return false
	case subjSubnetSet:
		return false
	}

	return true
}

func (g *gbpCommonMo) Verify(db map[string]*gbpCommonMo) error {
	// verify parent is set
	if g.needParent() {
		if g.ParentSubject == "" || g.ParentUri == "" || g.ParentRelation == "" {
			return fmt.Errorf("%s -- parent not set", g.Uri)
		}
	}

	// verify children are present in db
	for _, u := range g.Children {
		_, ok := db[u]
		if !ok {
			return fmt.Errorf("%s -- child %s not present", g.Uri, u)
		}
	}

	// verify references are present
	for _, p := range g.Properties {
		if p.Name == propTarget {
			var ref Reference
			js, err := json.Marshal(p.Value)
			if err != nil {
				spew.Dump(p)
				return fmt.Errorf("%s -- bad target", g.Uri)
			}

			err = json.Unmarshal(js, &ref)
			if err != nil {
				spew.Dump(p)
				return fmt.Errorf("%s -- bad target", g.Uri)
			}

			_, ok := db[ref.ReferenceUri]
			if !ok {
				return fmt.Errorf("%s -- reference %s not present", g.Uri, ref.ReferenceUri)
			}
		}
	}

	return nil
}

func (g *gbpCommonMo) FromJSON(j []byte) error {
	return json.Unmarshal(j, g)
}

func (g *gbpCommonMo) SetParent(subj, rel, uri string) {
	g.ParentSubject, g.ParentRelation, g.ParentUri = subj, rel, uri
}

func (g *gbpCommonMo) AddChild(uri string) {
	g.Children = append(g.Children, uri)
}

func (g *gbpCommonMo) DelChild(uri string) {
	for ix, u := range g.Children {
		if u == uri {
			g.Children = append(g.Children[:ix], g.Children[ix+1:]...)
		}
	}
}

func (g *gbpCommonMo) getChildMos() []*gbpCommonMo {
	res := make([]*gbpCommonMo, 0, len(g.Children))
	moDB := getMoDB()
	for _, u := range g.Children {
		mo := moDB[u]
		if mo != nil {
			res = append(res, &mo.gbpCommonMo)
		}
	}

	return res
}

func (g *gbpCommonMo) AddProperty(name string, data interface{}) {
	var pVal isProperty_Value

	switch data.(type) {
	case string:
		pVal = &Property_StrVal{StrVal: data.(string)}
	case int32:
		pVal = &Property_IntVal{IntVal: data.(int32)}
	case uint:
		pVal = &Property_IntVal{IntVal: int32(data.(uint))}
	case int:
		pVal = &Property_IntVal{IntVal: int32(data.(int))}
	case Reference:
		ref := data.(Reference)
		pVal = &Property_RefVal{RefVal: &ref}
	default:
		log.Fatalf("Unknown type for property %s", name)
	}

	p := &Property{Name: name, Value: pVal}
	g.Properties = append(g.Properties, p)
}

func (g *gbpCommonMo) WriteJSON() ([]byte, error) {
	return json.Marshal(g)
}

func (g *gbpCommonMo) GetStringProperty(name string) string {
	for _, p := range g.Properties {
		if p.Name == name {
			return p.GetStrVal()
		}
	}

	return ""
}

func (g *gbpCommonMo) GetIntProperty(name string) int {
	for _, p := range g.Properties {
		if p.Name == name {
			return int(p.GetIntVal())
		}
	}

	return -1
}

func (g *gbpCommonMo) getTarget() (string, error) {

	for _, p := range g.Properties {
		if p.Name == propTarget {
			ref := p.GetRefVal()
			if ref == nil {
				return "", fmt.Errorf("Bad property type for %s", g.Uri)
			}

			return ref.ReferenceUri, nil
		}
	}

	return "", fmt.Errorf("Not found")
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

func getDefPConfigName(domain string) string {
	return fmt.Sprintf("comp/prov-Kubernetes/ctrlr-[%s]-%s/sw-InsiemeLSOid", domain, domain)
}

func CreateRoot(config *GBPServerConfig) {
	// DmtreeRoot
	rMo := &gbpBaseMo{
		gbpCommonMo{
			GBPObject{
				Subject: subjRoot,
				Uri:     "/",
			},
			false,
			false,
		},
	}
	rMo.save()

	createChild := func(p *gbpBaseMo, childSub, name string) *gbpBaseMo {
		var cURI string
		if name == "" {
			cURI = fmt.Sprintf("%s%s/", p.Uri, childSub)
		} else {
			cURI = fmt.Sprintf("%s%s/%s/", p.Uri, childSub, escapeName(name, false))
		}
		child := &gbpBaseMo{
			gbpCommonMo{
				GBPObject{
					Subject: childSub,
					Uri:     cURI,
				},
				false,
				false,
			},
		}
		child.SetParent(p.Subject, childSub, p.Uri)
		child.save()
		p.AddChild(child.Uri)
		return child
	}

	rootChildren := []string{
		"RelatorUniverse",
		"GbpeVMUniverse",
		"DomainConfig",
		"InvUniverse",
		"PolicyUniverse",
	}

	for _, c := range rootChildren {
		createChild(rMo, c, "")
	}

	// attach platform config to policyuniverse
	puMo := getMoDB()["/PolicyUniverse/"]
	if puMo == nil {
		log.Fatal("PolicyUniverse not found")
	}

	pConfigName := getDefPConfigName(config.AciVmmDomain)
	pcMo := createChild(puMo, "PlatformConfig", pConfigName)
	pcProps := []struct {
		Name string
		Data string
	}{
		{Name: "multicastGroupIP", Data: "225.1.2.3"},
		{Name: "inventoryType", Data: "ON_LINK"},
		{Name: "encapType", Data: "vxlan"},
		{Name: "mode", Data: "intra_epg"},
		{Name: "name", Data: pConfigName},
	}

	for _, v := range pcProps {
		pcMo.AddProperty(v.Name, v.Data)
	}

	// attach remoteepinventory to Invuniverse
	iuMo := getMoDB()["/InvUniverse/"]
	if iuMo == nil {
		log.Fatal("InvUniverse not found")
	}
	createChild(iuMo, "InvRemoteEndpointInventory", "")

	// attach references to domainconfig
	dcMo := getMoDB()["/DomainConfig/"]
	if dcMo == nil {
		log.Fatal("DomainConfig not found")
	}

	dcToCR := createChild(dcMo, "DomainConfigToConfigRSrc", "")
	pConfURI := fmt.Sprintf("/PolicyUniverse/PlatformConfig/%s/", escapeName(pConfigName, false))
	refP := Reference{Subject: "PlatformConfig", ReferenceUri: pConfURI}
	dcToCR.AddProperty(propTarget, refP)

	dcToREI := createChild(dcMo, "DomainConfigToRemoteEndpointInventoryRSrc", "")
	refP = Reference{Subject: "InvRemoteEndpointInventory",
		ReferenceUri: "/InvUniverse/InvRemoteEndpointInventory/",
	}
	dcToREI.AddProperty(propTarget, refP)
}
