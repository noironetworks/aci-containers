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
	"strings"
	log "github.com/Sirupsen/logrus"
)

const (
	kubeTenant        = "vk8s_1"
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
	subjFDMcast       = "GbpFloodContext"
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
	propRoutingMode   = "routingMode"
	defRoutingMode    = "enabled"
	propEncapID       = "encapId"
	propClassID       = "classid"
	propTarget        = "target"
	propGw            = "virtualRouterIp"
	propPrefix        = "prefixLen"
	propNw            = "address"
	propMac           = "macAddress"
	propProt          = "prot"
	propDToPort       = "dToPort"
	propDFromPort     = "dFromPort"
	defRMac           = "00:22:bd:f8:19:ff"
	defSubnetsURI     = "/PolicyUniverse/PolicySpace/common/GbpSubnets/allsubnets/"
	defVrfURI         = "/PolicyUniverse/PolicySpace/common/GbpRoutingDomain/defaultVrf/"
	defVrfName        = "defaultVrf"
	defBDURI          = "/PolicyUniverse/PolicySpace/common/GbpBridgeDomain/defaultBD/"
	defBDName         = "defaultBD"
	defFDName         = "defaultFD"
	defFDURI          = "/PolicyUniverse/PolicySpace/common/GbpFloodDomain/defaultFD/"
	defFDMcastURI     = defFDURI + "GbpeFloodContext/"
	defFDToBDURI      = defFDURI + "GbpFloodDomainToNetworkRSrc/"
	defMcastGroup     = "225.0.193.80"
	propMcast         = "multicastGroupIP"
	defEPGURI         = "/PolicyUniverse/PolicySpace/common/GbpEpGroup/default/"
	defEPGName        = "default"
	defPConfigName    = "comp/prov-Kubernetes/ctrlr-[kube]-kube/sw-InsiemeLSOid"
)

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

func escapeName(n string) string {
	escs := []struct {
			Orig string
			Escape string
		} {
			{
				Orig: "/",
				Escape: "%2f",
			},
			{
				Orig: "[",
				Escape: "%5b",
			},
			{
				Orig: "]",
				Escape: "%5d",
			},
			{
				Orig: "|",
				Escape: "%7c",
			},
		}

	for _, e := range escs {
		n = strings.Replace(n, e.Orig, e.Escape, -1)
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
			cURI = fmt.Sprintf("%s%s/%s/", p.URI, childSub, escapeName(name))
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

	pConfURI := fmt.Sprintf("/PolicyUniverse/PlatformConfig/%s/", escapeName(defPConfigName))
	err := dcMo.AddRef("DomainConfigToConfigRSrc", pConfURI)
	if err != nil {
		log.Fatalf("Failed to add DomainConfigToConfigRSrc - %v", err)
	}
	err = dcMo.AddRef("DomainConfigToRemoteEndpointInventoryRSrc", "/InvUniverse/InvRemoteEndpointInventory/")
	if err != nil {
		log.Fatalf("Failed to add DomainConfigToRemoteEndpointInventoryRSrc - %v", err)
	}
}
