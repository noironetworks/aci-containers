/***
Copyright 2020 Cisco Systems Inc. All rights reserved.

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
	"fmt"
	"github.com/noironetworks/aci-containers/pkg/apicapi"
	crdv1 "github.com/noironetworks/aci-containers/pkg/gbpcrd/apis/acipolicy/v1"
	crdclientset "github.com/noironetworks/aci-containers/pkg/gbpcrd/clientset/versioned"
	aciv1 "github.com/noironetworks/aci-containers/pkg/gbpcrd/clientset/versioned/typed/acipolicy/v1"
	"github.com/noironetworks/aci-containers/pkg/gbpserver"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	restclient "k8s.io/client-go/rest"
	"strings"
	"time"
)

const (
	syncInterval   = 15 * time.Second
	remoteEPGQuery = "/api/mo/%s.json?query-target=children&target-subtree-class=vzRtCons,vzRtProv"
	contractQuery  = "/api/mo/%s.json?query-target=children&target-subtree-class=fvRsCons,fvRsProv"
	epgFetchQuery  = "/api/mo/%s.json?rsp-subtree=full"
)

type EPSyncer struct {
	log       *logrus.Entry
	gs        *gbpserver.Server
	apicConn  *apicapi.ApicConnection
	aw        *ApicWatcher
	epgQuery  string
	crdClient aciv1.AciV1Interface
}

func (eps *EPSyncer) Init() error {
	tenant := eps.gs.Config().AciPolicyTenant
	vrf := eps.gs.Config().AciVrf
	eps.epgQuery = fmt.Sprintf("/api/mo/uni/tn-%s/ctx-%s.json?query-target=children&target-subtree-class=fvRtCloudEPgCtx", tenant, vrf)
	k8sCfg, err := restclient.InClusterConfig()
	if err != nil {
		return errors.Wrap(err, "InClusterConfig()")
	}

	aciawClient, err := crdclientset.NewForConfig(k8sCfg)
	if err != nil {
		return errors.Wrap(err, "crdclientset.NewForConfig()")
	}

	eps.crdClient = aciawClient.AciV1()
	return nil
}

func (eps *EPSyncer) Run(stopCh <-chan struct{}) {
	ticker := time.NewTicker(syncInterval)
	for {
		select {
		case <-stopCh:
			fmt.Println("Done!")
			return
		case <-ticker.C:
			eps.syncRemoteEPs()
		}
	}
}

func (eps *EPSyncer) syncRemoteEPs() {
	l_epgs := eps.getLocalEPGs()
	contracts := eps.getContracts(l_epgs)
	r_epgs := eps.getRemoteEPGs(contracts, l_epgs)
	eps.syncRemoteEPGs(r_epgs)
}

func (eps *EPSyncer) tDnsFromQry(q string, out map[string]bool) {
	resp, err := eps.apicConn.GetApicResponse(q)
	if err != nil {
		eps.log.Error(err)
		return
	}

	for _, obj := range resp.Imdata {
		dn := obj.GetAttrStr("tDn")
		if dn != "" {
			out[dn] = true
		}
	}
}
func (eps *EPSyncer) getLocalEPGs() map[string]bool {
	epgDNs := make(map[string]bool)
	eps.tDnsFromQry(eps.epgQuery, epgDNs)
	return epgDNs
}

func (eps *EPSyncer) getContracts(epgDNs map[string]bool) map[string]bool {
	c_dns := make(map[string]bool)
	for dn := range epgDNs {
		query := fmt.Sprintf(contractQuery, dn)
		eps.tDnsFromQry(query, c_dns)
	}

	return c_dns
}

func (eps *EPSyncer) getRemoteEPGs(cons, lEpgs map[string]bool) map[string]bool {
	r_epgs := make(map[string]bool)
	for dn := range cons {
		query := fmt.Sprintf(remoteEPGQuery, dn)
		eps.tDnsFromQry(query, r_epgs)
	}

	// delete local epgs from the contract epg list
	for dn := range lEpgs {
		delete(r_epgs, dn)
	}

	return r_epgs
}

func (eps *EPSyncer) syncRemoteEPGs(r_epgs map[string]bool) {
	for dn := range r_epgs {
		q := fmt.Sprintf(epgFetchQuery, dn)
		resp, err := eps.apicConn.GetApicResponse(q)
		if err != nil {
			eps.log.Error(err)
			continue
		}

		if len(resp.Imdata) > 0 {
			eps.processRemoteEPG(resp.Imdata[0])
		}
	}
}

func (eps *EPSyncer) processRemoteEPG(obj apicapi.ApicObject) {
	var sel string
	// look for an ep selector
	for _, body := range obj {
		for _, cc := range body.Children {
			for class := range cc {
				switch class {
				case "cloudEPSelector":
					sel = cc.GetAttrStr("matchExpression")
				}
			}
		}
	}

	if sel == "" {
		eps.log.Debugf("%s no epSel", obj.GetDn())
		return
	}

	parts := strings.Split(sel, "==")
	if len(parts) == 2 && parts[0] == "IP" {
		epgDn := obj.GetDn()
		tenant := dnToTenant(epgDn)
		eps.AddExtEP(parts[1], epgDn)
		eps.aw.ProcessEpg(tenant, epgDn, obj)
		return
	}

	eps.log.Debugf("epSel %s ignored for %s", sel, obj.GetDn())
}

func (eps *EPSyncer) AddExtEP(subnet, epgDn string) {
	subnet = strings.TrimLeft(subnet, " '")
	subnet = strings.Split(subnet, "'")[0]
	epgName := eps.aw.dnToEpgName(epgDn)
	pi_name := epgName + subnet
	pi_name = strings.Split(pi_name, "/")[0]
	// k8s doesn't like the | character in names
	pi_name = strings.Replace(pi_name, "|", "-", -1)
	pi_name = strings.Replace(pi_name, "_", "-", -1)
	_, err := eps.crdClient.PodIFs("kube-system").Get(pi_name, metav1.GetOptions{})
	ep := &crdv1.PodIF{Status: crdv1.PodIFStatus{IPAddr: subnet, EPG: epgName}}
	ep.ObjectMeta.Name = pi_name
	if err != nil {
		_, err = eps.crdClient.PodIFs("kube-system").Create(ep)
	}

	if err != nil {
		eps.log.Errorf("== AddExtEP: %s err: %v", pi_name, err)
	} else {
		eps.log.Infof("== AddExtEP: %s (%s)", subnet, epgDn)
	}
}
