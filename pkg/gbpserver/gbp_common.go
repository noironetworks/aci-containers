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
	defVrfURI         = "/PolicyUniverse/PolicySpace/kube/GbpRoutingDomain/defaultVrf/"
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

func cctxProfName() string {
	return defVrfName + "_" + defRegion
}
func (bds *BDSubnet) SubnetsUri() string {
	return fmt.Sprintf("/PolicyUniverse/PolicySpace/%s/GbpSubnets/%s/", kubeTenant, bds.subnetsName)
}

func (bds *BDSubnet) SnUri() string {
	sn := escapeName(bds.snet, false)
	return fmt.Sprintf("/PolicyUniverse/PolicySpace/%s/GbpSubnets/%s/GbpSubnet/%s/", kubeTenant, bds.subnetsName, sn)
}

func (bds *BDSubnet) BDUri() string {
	return fmt.Sprintf("/PolicyUniverse/PolicySpace/%s/GbpBridgeDomain/%s/", kubeTenant, bds.bdName)
}

func (bds *BDSubnet) FDUri() string {
	return fmt.Sprintf("/PolicyUniverse/PolicySpace/%s/GbpFloodDomain/%s/", kubeTenant, bds.fdName)
}
func (bds *BDSubnet) FDMcastUri() string {
	return fmt.Sprintf("/PolicyUniverse/PolicySpace/%s/GbpFloodDomain/%s/GbpeFloodContext/", kubeTenant, bds.fdName)
}
func (bds *BDSubnet) FDToBDUri() string {
	return fmt.Sprintf("/PolicyUniverse/PolicySpace/%s/GbpFloodDomain/%s/GbpFloodDomainToNetworkRSrc/", kubeTenant, bds.fdName)
}

func (bds *BDSubnet) CreateSubnet() {
	// create subnet set
	ss := &GBPSubnetSet{}
	ss.Make(bds.subnetsName, bds.SubnetsUri())
	s := &GBPSubnet{}
	s.Make(bds.snet, bds.SnUri())

	ss.AddChild(s.URI)
	s.SetParent(subjSubnetSet, subjSubnet, ss.URI)
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

	to := RefProperty{
		Subject: subjBD,
		RefURI:  bds.BDUri(),
	}

	bdRef.AddProperty(propTarget, to)

	fd := &GBPFloodDomain{}
	fd.Make(bds.fdName, bds.FDUri())
	fd.AddChild(fm.URI)
	fm.SetParent(fd.Subject, fm.Subject, fd.URI)
	fd.AddChild(bdRef.URI)
	bdRef.SetParent(fd.Subject, bdRef.Subject, fd.URI)

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
	to := RefProperty{
		Subject: subjFD,
		RefURI:  bds.FDUri(),
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
		RefURI:  bds.SnUri(),
	}

	snetRef.AddProperty(propTarget, tosnet)
	epg.AddChild(snetRef.URI)
	snetRef.SetParent(epg.Subject, snetRef.Subject, epg.URI)
	return MoDB[uri]

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
	GetRefURIs(subject string) (map[string]string, error)
}

type Property struct {
	Name string      `json:"name,omitempty"`
	Data interface{} `json:"data,omitempty"`
}

type RefProperty struct {
	Subject string `json:"subject,omitempty"`
	RefURI  string `json:"reference_uri,omitempty"`
}

type gbpCommonMo struct {
	Subject    string     `json:"subject,omitempty"`
	URI        string     `json:"uri",omitempty"`
	Properties []Property `json:"properties",omitempty"`
	Children   []string   `json:"children",omitempty"`
	ParentSub  string     `json:"parent_subject,omitempty"`
	ParentURI  string     `json:"parent_uri,omitempty"`
	ParentRel  string     `json:"parent_relation,omitempty"`
	isRef      bool
	permanent  bool // do not delete
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
		if g.ParentSub == "" || g.ParentURI == "" || g.ParentRel == "" {
			return fmt.Errorf("%s -- parent not set", g.URI)
		}
	}

	// verify children are present in db
	for _, u := range g.Children {
		_, ok := db[u]
		if !ok {
			return fmt.Errorf("%s -- child %s not present", g.URI, u)
		}
	}

	// verify references are present
	for _, p := range g.Properties {
		if p.Name == propTarget {
			var ref RefProperty
			js, err := json.Marshal(p.Data)
			if err != nil {
				spew.Dump(p)
				return fmt.Errorf("%s -- bad target", g.URI)
			}

			err = json.Unmarshal(js, &ref)
			if err != nil {
				spew.Dump(p)
				return fmt.Errorf("%s -- bad target", g.URI)
			}

			_, ok := db[ref.RefURI]
			if !ok {
				return fmt.Errorf("%s -- reference %s not present", g.URI, ref.RefURI)
			}
		}
	}

	return nil
}

func (g *gbpCommonMo) FromJSON(j []byte) error {
	return json.Unmarshal(j, g)
}

func (g *gbpCommonMo) SetParent(subj, rel, uri string) {
	g.ParentSub, g.ParentRel, g.ParentURI = subj, rel, uri
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
	for _, u := range g.Children {
		mo := MoDB[u]
		if mo != nil {
			res = append(res, &mo.gbpCommonMo)
		}
	}

	return res
}

func (g *gbpCommonMo) AddProperty(name string, data interface{}) {
	p := Property{Name: name, Data: data}
	g.Properties = append(g.Properties, p)
}

func (g *gbpCommonMo) WriteJSON() ([]byte, error) {
	return json.Marshal(g)
}

func (g *gbpCommonMo) GetStringProperty(name string) string {
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

func (g *gbpCommonMo) getTarget() (string, error) {

	for _, p := range g.Properties {
		if p.Name == propTarget {
			ref, ok := p.Data.(RefProperty)
			if !ok {
				return "", fmt.Errorf("Bad property type for %s", g.URI)
			}

			return ref.RefURI, nil
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

func CreateRoot() {
	// DmtreeRoot
	rMo := &gbpBaseMo{
		gbpCommonMo{
			Subject: subjRoot,
			URI:     "/",
		},
	}
	rMo.save()

	createChild := func(p *gbpBaseMo, childSub, name string) *gbpBaseMo {
		var cURI string
		if name == "" {
			cURI = fmt.Sprintf("%s%s/", p.URI, childSub)
		} else {
			cURI = fmt.Sprintf("%s%s/%s/", p.URI, childSub, escapeName(name, false))
		}
		child := &gbpBaseMo{
			gbpCommonMo{
				Subject: childSub,
				URI:     cURI,
			},
		}
		child.SetParent(p.Subject, childSub, p.URI)
		child.save()
		p.AddChild(child.URI)
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
	puMo := MoDB["/PolicyUniverse/"]
	if puMo == nil {
		log.Fatal("PolicyUniverse not found")
	}

	pcMo := createChild(puMo, "PlatformConfig", defPConfigName)
	pcProps := []Property{
		{Name: "multicastGroupIP", Data: "225.1.2.3"},
		{Name: "inventoryType", Data: "ON_LINK"},
		{Name: "encapType", Data: "vxlan"},
		{Name: "mode", Data: "intra_epg"},
		{Name: "name", Data: defPConfigName},
	}
	pcMo.Properties = pcProps

	// attach remoteepinventory to Invuniverse
	iuMo := MoDB["/InvUniverse/"]
	if iuMo == nil {
		log.Fatal("InvUniverse not found")
	}
	createChild(iuMo, "InvRemoteEndpointInventory", "")

	// attach references to domainconfig
	dcMo := MoDB["/DomainConfig/"]
	if dcMo == nil {
		log.Fatal("DomainConfig not found")
	}

	dcToCR := createChild(dcMo, "DomainConfigToConfigRSrc", "")
	pConfURI := fmt.Sprintf("/PolicyUniverse/PlatformConfig/%s/", escapeName(defPConfigName, false))
	refP := RefProperty{Subject: "PlatformConfig", RefURI: pConfURI}
	dcToCR.AddProperty(propTarget, refP)

	dcToREI := createChild(dcMo, "DomainConfigToRemoteEndpointInventoryRSrc", "")
	refP = RefProperty{Subject: "InvRemoteEndpointInventory",
		RefURI: "/InvUniverse/InvRemoteEndpointInventory/",
	}
	dcToREI.AddProperty(propTarget, refP)
}
