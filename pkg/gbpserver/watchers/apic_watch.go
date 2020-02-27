/***
Copyright 2019 Cisco Systems Inc. All rights reserved.

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

package watchers

import (
	"encoding/json"
	"fmt"
	"github.com/sirupsen/logrus"
	"github.com/noironetworks/aci-containers/pkg/apicapi"
	"github.com/noironetworks/aci-containers/pkg/gbpcrd/apis/acipolicy/v1"
	"github.com/noironetworks/aci-containers/pkg/gbpserver"
	"strconv"
	"strings"
	"sync"
)

const (
	refreshTime  = 0 // cAPIC folks recommend 0
	commonTenant = "common"
)

type ApicWatcher struct {
	sync.Mutex
	logger         *logrus.Logger
	log            *logrus.Entry
	apicConn       *apicapi.ApicConnection
	gs             *gbpserver.Server
	idb            *intentDB
	tenant         string
	apName         string
	hostProtPrefix string
	apicInfo       ApicInfo
	eps            *EPSyncer
}

type ApicInfo struct {
	user     string
	password string
	privKey  []byte
	cert     []byte
	prefix   string
}

func NewApicWatcher(gs *gbpserver.Server) *ApicWatcher {
	level, err := logrus.ParseLevel(gs.Config().WatchLogLevel)
	if err != nil {
		panic(err.Error())
	}
	logger := logrus.New()
	logger.Level = level
	log := logger.WithField("mod", "cAPIC-W")

	vmmDomain := gs.Config().AciVmmDomain
	return &ApicWatcher{
		logger:         logger,
		log:            log,
		gs:             gs,
		idb:            newIntentDB(gs, log),
		tenant:         gs.Config().AciPolicyTenant,
		apName:         vmmDomain,
		hostProtPrefix: fmt.Sprintf("uni/tn-%s/pol-%s", gs.Config().AciPolicyTenant, vmmDomain),
		apicInfo: ApicInfo{
			user:     gs.Config().Apic.Username,
			password: gs.Config().Apic.Password,
			prefix:   "k8s",
		},
	}
}

func (aw *ApicWatcher) Init(apicUrl []string, stopCh <-chan struct{}) error {
	// eventually, the url and credentials will come from the crd
	ai := aw.apicInfo
	conn, err := apicapi.New(aw.logger, apicUrl, ai.user, ai.password,
		ai.privKey, ai.cert, ai.prefix, refreshTime, 5)

	if err != nil {
		return err
	}

	aw.apicConn = conn

	// add subscriptions
	aw.apicConn.AddSubscriptionTree("cloudEPg", []string{"cloudEPg", "fvRsCons", "fvRsProv"}, "")
	aw.apicConn.SetSubscriptionHooks("cloudEPg",
		func(obj apicapi.ApicObject) bool {
			aw.EpgChanged(obj)
			return true
		},
		func(dn string) {
			aw.EpgDeleted(dn)
		})
	aw.apicConn.AddSubscriptionTree("vzBrCP", []string{"vzBrCP"}, "")
	aw.apicConn.SetSubscriptionHooks("vzBrCP",
		func(obj apicapi.ApicObject) bool {
			aw.ContractChanged(obj)
			return true
		},
		func(dn string) {
			aw.ContractDeleted(dn)
		})

	aw.apicConn.AddSubscriptionTree("vzFilter", []string{"vzFilter"}, "")
	aw.apicConn.SetSubscriptionHooks("vzFilter",
		func(obj apicapi.ApicObject) bool {
			aw.FilterChanged(obj)
			return true
		},
		func(dn string) {
			aw.FilterDeleted(dn)
		})

	aw.apicConn.AddSubscriptionTree("hostprotPol",
		[]string{"hostprotPol", "hostprotSubj", "hostprotRule", "hostprotRemoteIp"}, "")
	aw.apicConn.SetSubscriptionHooks("hostprotPol",
		func(obj apicapi.ApicObject) bool {
			aw.NetPolChanged(obj)
			return true
		},
		func(dn string) {
			if strings.Contains(dn, aw.hostProtPrefix) {
				aw.log.Infof("Received delete hostprotPol: %s", dn)
				aw.NetPolDeleted(dn)
			}
		})

	eps := &EPSyncer{
		log:      aw.log,
		gs:       aw.gs,
		apicConn: aw.apicConn,
		aw:       aw,
	}
	err = eps.Init()
	if err != nil {
		return err
	}
	aw.eps = eps
	go aw.apicConn.Run(stopCh)
	if aw.gs.Config().SyncRemEps {
		go aw.eps.Run(stopCh)
	}
	return nil
}

func (aw *ApicWatcher) EpgChanged(obj apicapi.ApicObject) {
	epgDn := obj.GetAttrStr("dn")
	tenant := dnToTenant(epgDn)
	if tenant != aw.tenant && tenant != commonTenant {
		aw.log.Debugf("== epg: %s ignored tenant: %s", epgDn, tenant)
		return
	}

	aw.ProcessEpg(tenant, epgDn, obj)
}

func (aw *ApicWatcher) ProcessEpg(tenant, epgDn string, obj apicapi.ApicObject) {
	aw.Lock()
	defer aw.Unlock()
	aw.log.Infof("== epg: %s ==", epgDn)
	// construct the EPG
	epg := gbpserver.EPG{
		Tenant: tenant,
		Name:   aw.dnToEpgName(epgDn),
		ApicDN: epgDn,
	}

	for _, body := range obj {
		for _, cc := range body.Children {
			for class := range cc {
				switch class {
				case "fvRsProv":
					if cname, err := xtractContract(cc); err == nil {
						epg.ProvContracts = append(epg.ProvContracts, cname)
					} else {
						aw.log.Errorf("epg: %s error: %v", epg.Name, err)
					}

				case "fvRsCons":
					if cname, err := xtractContract(cc); err == nil {
						epg.ConsContracts = append(epg.ConsContracts, cname)
					} else {
						aw.log.Errorf("epg: %s error: %v", epg.Name, err)
					}
				}
			}
		}
	}

	aw.idb.saveEPG(&epg)
	aw.log.Debugf("epgAdded: %v", epg)
}

func getEpgKey(e *gbpserver.EPG) string {
	return fmt.Sprintf("%s/%s", e.Tenant, e.Name)
}

func xtractContract(c apicapi.ApicObject) (string, error) {
	Dn := c.GetAttrStr("tDn")
	if Dn == "" {
		return "", fmt.Errorf("Missing tDn")
	}
	cname := c.GetAttrStr("tnVzBrCPName")
	if cname == "" {
		return "", fmt.Errorf("contract: %s missing tnVzBrCPName", Dn)
	}

	// add tenant name for namespacing
	tenant := dnToTenant(Dn)
	return fmt.Sprintf("%s/%s", tenant, cname), nil
}

func (aw *ApicWatcher) EpgDeleted(dn string) {
	tenant := dnToTenant(dn)
	if tenant != aw.tenant && tenant != commonTenant {
		aw.log.Debugf("== contract: %s ignored tenant: %s", dn, tenant)
		return
	}
	epg := gbpserver.EPG{
		Tenant: tenant,
		Name:   aw.dnToEpgName(dn),
	}

	aw.idb.deleteEPG(&epg)
}

func dnToTenant(dn string) string {
	s := strings.TrimPrefix(dn, "uni/tn-")
	parts := strings.Split(s, "/")
	if len(parts) > 1 {
		return parts[0]
	}

	return ""
}

func (aw *ApicWatcher) dnToEpgName(dn string) string {
	parts := strings.Split(dn, "/")
	if len(parts) > 3 {
		apName := strings.TrimPrefix(parts[2], "cloudapp-")
		epgName := strings.TrimPrefix(parts[3], "cloudepg-")
		if apName == aw.apName {
			return epgName
		}

		return fmt.Sprintf("%s|%s", apName, epgName)
	}

	return ""
}

func (aw *ApicWatcher) ContractChanged(obj apicapi.ApicObject) {
	dn := obj.GetAttrStr("dn")
	tenant := dnToTenant(dn)
	if tenant != aw.tenant && tenant != commonTenant {
		aw.log.Debugf("== contract: %s ignored tenant: %s", dn, tenant)
		return
	}

	name := obj.GetAttrStr("name")
	aw.log.Infof("== contract: %s", dn)
	contract := &apicContract{
		Tenant: tenant,
		Name:   name,
	}
	for _, body := range obj {
		for _, cc := range body.Children {
			for class, o := range cc {
				switch class {
				case "vzSubj":
					fDn := getFilterDn(o)
					contract.Filters = append(contract.Filters, dnToCN(fDn))
				}
			}
		}
	}

	aw.log.Debugf("== apic-contract: %s", dn)
	aw.idb.saveApicContract(contract)
}

func getFilterDn(body *apicapi.ApicObjectBody) string {
	for _, cc := range body.Children {
		for class := range cc {
			switch class {
			case "vzRsSubjFiltAtt":
				return cc.GetAttrStr("tDn")
			}
		}
	}

	return "unknown"
}

func dnToCN(dn string) string {
	parts := strings.Split(dn, "/")
	if len(parts) != 3 {
		return "unknown"
	}

	return fmt.Sprintf("%s/%s", dnToTenant(dn), parts[2])
}

func (aw *ApicWatcher) ContractDeleted(dn string) {
	parts := strings.Split(dn, "/")
	if len(parts) != 3 {
		aw.log.Errorf("Bad contract dn: %s", dn)
		return
	}

	tenant := dnToTenant(dn)
	if tenant != aw.tenant && tenant != commonTenant {
		aw.log.Debugf("== contract: %s ignored tenant: %s", dn, tenant)
		return
	}
	contract := &apicContract{
		Tenant: tenant,
		Name:   parts[2],
	}
	aw.idb.deleteApicContract(contract)
}

func (aw *ApicWatcher) FilterChanged(obj apicapi.ApicObject) {
	var ruleset []v1.WLRule
	dn := obj.GetAttrStr("dn")
	tenant := dnToTenant(dn)
	if tenant != aw.tenant && tenant != commonTenant {
		aw.log.Debugf("== filter: %s ignored tenant: %s", dn, tenant)
		return
	}
	name := dnToCN(dn)
	aw.log.Infof("== filter: %s", dn)
	for _, body := range obj {
		for _, cc := range body.Children {
			for class := range cc {
				switch class {
				case "vzEntry":
					r := new(v1.WLRule)
					prot := cc.GetAttrStr("prot")
					if prot != "unspecified" {
						r.Protocol = prot
					}
					start := cc.GetAttrStr("dFromPort")
					p, err := strconv.Atoi(start)
					if err == nil {
						r.Ports.Start = p
					}
					end := cc.GetAttrStr("dToPort")
					p, err = strconv.Atoi(end)
					if err == nil {
						r.Ports.End = p
					}
					ruleset = append(ruleset, *r)
				}
			}
			aw.log.Debugf("Filter: %s, %+v", name, cc)
		}
	}

	aw.idb.saveFilter(name, ruleset)
}

func (aw *ApicWatcher) FilterDeleted(dn string) {
	name := dnToCN(dn)
	aw.idb.deleteFilter(name)
}

func (aw *ApicWatcher) NetPolChanged(obj apicapi.ApicObject) {

	aw.Lock()
	defer aw.Unlock()
	dn := obj.GetAttrStr("dn")
	if !strings.Contains(dn, aw.hostProtPrefix) {
		return
	}

	aw.log.Infof("Received hostprotPol")
	jsonStr, err := json.Marshal(obj)
	if err != nil {
		aw.log.Errorf("Error marshaling %v", err)
		return
	}

	np := gbpserver.NetworkPolicy{}
	err = json.Unmarshal(jsonStr, &np)
	if err != nil {
		aw.log.Errorf("Error unmarshaling %v", err)
		return
	}
	aw.gs.AddNetPol(np)
	aw.log.Infof("NetPol Added: %s", dn)
}

func (aw *ApicWatcher) NetPolDeleted(dn string) {

	aw.Lock()
	defer aw.Unlock()
	aw.gs.DelNetPol(dn)
	aw.log.Infof("NetPol Deleted: %s", dn)
}
