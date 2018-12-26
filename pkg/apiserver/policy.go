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
	"fmt"
	log "github.com/Sirupsen/logrus"
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
	Protocol string
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
	arefURI := fmt.Sprintf("%sGbpRuleToActionRSrc/allow", furi)
	aRef.Make("", arefURI)
	ref := RefProperty{
		Subject: aMo.Subject,
		RefURI:  aMo.URI,
	}
	aRef.AddProperty(propTarget, ref)
	aRef.SetParent(fmo.Subject, aRef.Subject, fmo.URI)

	return nil
}

func (c *Contract) makeClassifiers() error {
	for _, wRule := range c.AllowList {
		err := c.addRule(wRule)
		if err != nil {
			return err
		}
	}

	return nil
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

	cfMo.AddProperty(propProt, protToInt(r.Protocol))
	cfMo.AddProperty(propDFromPort, r.Ports.Start)
	cfMo.AddProperty(propDToPort, r.Ports.End)

	// make reference
	tocfURI := c.getToCfURI(cname)
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

	return nil
}

func protToInt(prot string) int {
	switch prot {
	case "udp":
		return 17
	case "icmp":
		return 1
	default:
		return 6
	}
}

func (c *Contract) getURI() string {
	return fmt.Sprintf("/PolicyUniverse/PolicySpace/%s/GbpContract/%s/", c.Tenant, c.Name)
}

func (c *Contract) getFilterURI() string {
	return fmt.Sprintf("%sGbpSubject/%s-subj/GbpRule/%s-filter/", c.getURI(), c.Name, c.Name)
}

func (c *Contract) getToCfURI(name string) string {
	return fmt.Sprintf("%sGbpRuleToClassifierRSrc/%s", c.getFilterURI(), name)
}
func (wr *WLRule) getClassifierURI(tenant string) (string, string) {
	un := wr.Protocol
	un = fmt.Sprintf("%s-%d-%d", un, wr.Ports.Start, wr.Ports.End)

	return fmt.Sprintf("/PolicyUniverse/PolicySpace/%s/GbpeL24Classifier/%s/", tenant, un), un
}
