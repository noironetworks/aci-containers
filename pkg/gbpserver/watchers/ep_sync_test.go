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
	"encoding/pem"
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"github.com/noironetworks/aci-containers/pkg/apicapi"
	fakev1 "github.com/noironetworks/aci-containers/pkg/gbpcrd/clientset/versioned/fake"
	"github.com/noironetworks/aci-containers/pkg/gbpserver"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"
	"time"
)

const (
	epsTenant = "kuber"
	epsVrf    = "cluster1_overlay"
)

type testServer struct {
	mux    *http.ServeMux
	server *httptest.Server
}
type eps_suite struct {
	s        *gbpserver.Server
	aw       *ApicWatcher
	fakeApic *testServer
	eps      *EPSyncer
}

func newTestServer() *testServer {
	mux := http.NewServeMux()
	server := httptest.NewTLSServer(mux)

	ts := &testServer{
		mux:    mux,
		server: server,
	}

	return ts
}

func (server *testServer) testConn(key []byte) (*apicapi.ApicConnection, error) {
	u, _ := url.Parse(server.server.URL)
	apic := fmt.Sprintf("%s:%s", u.Hostname(), u.Port())

	log := logrus.New()
	log.Level = logrus.DebugLevel
	log.Formatter = &logrus.TextFormatter{
		DisableColors: true,
	}

	cert := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: server.server.TLS.Certificates[0].Certificate[0],
	})

	n, err := apicapi.New(log, []string{apic}, "admin", "noir0123", key, cert, "kube",
		60, 5)
	if err != nil {
		return nil, err
	}
	n.ReconnectInterval = 5 * time.Millisecond
	return n, nil
}

func (s *eps_suite) setup() {
	gCfg := &gbpserver.GBPServerConfig{}
	gCfg.LogLevel = "info"
	gCfg.GRPCLogLevel = "info"
	gCfg.WatchLogLevel = "info"
	gCfg.GRPCPort = 19999
	gCfg.ProxyListenPort = 8899
	gCfg.PodSubnet = "10.2.56.1/21"
	gCfg.NodeSubnet = "1.100.201.0/24"
	gCfg.AciVmmDomain = "cluster1"
	gCfg.AciPolicyTenant = epsTenant
	gCfg.Apic = &gbpserver.ApicInfo{}
	s.s = gbpserver.NewServer(gCfg)
	s.aw = NewApicWatcher(s.s)
	s.fakeApic = newTestServer()
	eps := &EPSyncer{}
	clientSet := fakev1.NewSimpleClientset()
	eps.crdClient = clientSet.AciV1()
	conn, _ := s.fakeApic.testConn(nil)
	eps.apicConn = conn
	eps.gs = s.s
	eps.aw = s.aw
	eps.log = logrus.New().WithField("mod", "epsync-test")
	eps.epgQuery = fmt.Sprintf("/api/mo/uni/tn-%s/ctx-%s.json?query-target=children&target-subtree-class=fvRtCloudEPgCtx", epsTenant, epsVrf)
	s.eps = eps
}

func (s *eps_suite) expectMsg(op int, msg interface{}) error {
	gotOp, gotMsg, err := s.s.UTReadMsg(200 * time.Millisecond)
	if err != nil {
		return err
	}

	if gotOp != op {
		return fmt.Errorf("Exp op: %d, got: %d", op, gotOp)
	}

	if !reflect.DeepEqual(msg, gotMsg) {
		spew.Dump(msg)
		spew.Dump(gotMsg)
		return fmt.Errorf("msgs don't match")
	}

	return nil
}

func (s *eps_suite) expectOp(op int) error {
	gotOp, _, err := s.s.UTReadMsg(200 * time.Millisecond)
	if err != nil {
		return err
	}

	if gotOp != op {
		return fmt.Errorf("Exp op: %d, got: %d", op, gotOp)
	}

	return nil
}

func fvRtCloudEPgCtxHandler(w http.ResponseWriter, r *http.Request) {
	resp := `
	{
	    "imdata": [
	        {
	            "fvRtCloudEPgCtx": {
	                "attributes": {
	                    "dn": "uni/tn-kuber/ctx-cluster1_overlay/rtcloudCloudEPgCtx-[uni/tn-kuber/cloudapp-cluster1/cloudepg-aci-containers-nodes]", 
	                    "lcOwn": "local", 
	                    "tDn": "uni/tn-kuber/cloudapp-cluster1/cloudepg-aci-containers-nodes", 
	                    "tCl": "cloudEPg", 
	                    "status": "", 
	                    "modTs": "2020-03-30T01:52:09.142+00:00", 
	                    "childAction": ""
	                }
	            }
	        }, 
	        {
	            "fvRtCloudEPgCtx": {
	                "attributes": {
	                    "dn": "uni/tn-kuber/ctx-cluster1_overlay/rtcloudCloudEPgCtx-[uni/tn-kuber/cloudapp-cluster1/cloudepg-aci-containers-default]", 
	                    "lcOwn": "local", 
	                    "tDn": "uni/tn-kuber/cloudapp-cluster1/cloudepg-aci-containers-default", 
	                    "tCl": "cloudEPg", 
	                    "status": "", 
	                    "modTs": "2020-03-30T01:52:09.142+00:00", 
	                    "childAction": ""
	                }
	            }
	        }, 
	        {
	            "fvRtCloudEPgCtx": {
	                "attributes": {
	                    "dn": "uni/tn-kuber/ctx-cluster1_overlay/rtcloudCloudEPgCtx-[uni/tn-kuber/cloudapp-cluster1/cloudepg-aci-containers-system]", 
	                    "lcOwn": "local", 
	                    "tDn": "uni/tn-kuber/cloudapp-cluster1/cloudepg-aci-containers-system", 
	                    "tCl": "cloudEPg", 
	                    "status": "", 
	                    "modTs": "2020-03-30T01:52:09.142+00:00", 
	                    "childAction": ""
	                }
	            }
	        }, 
	        {
	            "fvRtCloudEPgCtx": {
	                "attributes": {
	                    "dn": "uni/tn-kuber/ctx-cluster1_overlay/rtcloudCloudEPgCtx-[uni/tn-kuber/cloudapp-cluster1/cloudepg-epg-a]", 
	                    "lcOwn": "local", 
	                    "tDn": "uni/tn-kuber/cloudapp-cluster1/cloudepg-epg-a", 
	                    "tCl": "cloudEPg", 
	                    "status": "", 
	                    "modTs": "2020-03-31T22:20:04.821+00:00", 
	                    "childAction": ""
	                }
	            }
	        }, 
	        {
	            "fvRtCloudEPgCtx": {
	                "attributes": {
	                    "dn": "uni/tn-kuber/ctx-cluster1_overlay/rtcloudCloudEPgCtx-[uni/tn-kuber/cloudapp-cluster1/cloudepg-epg-b]", 
	                    "lcOwn": "local", 
	                    "tDn": "uni/tn-kuber/cloudapp-cluster1/cloudepg-epg-b", 
	                    "tCl": "cloudEPg", 
	                    "status": "", 
	                    "modTs": "2020-04-01T18:19:46.284+00:00", 
	                    "childAction": ""
	                }
	            }
	        }
	    ], 
	    "totalCount": "5"
	}
	`

	targets, ok := r.URL.Query()["query-target"]
	if !ok || len(targets) != 1 || targets[0] != "children" {
		return
	}
	class, ok := r.URL.Query()["target-subtree-class"]
	if !ok || len(class) != 1 || class[0] != "fvRtCloudEPgCtx" {
		return
	}

	w.Write([]byte(resp))
}

func cloudEPgHandler(w http.ResponseWriter, r *http.Request) {
	resps := map[string]string{
		`/api/mo/uni/tn-kuber/cloudapp-cluster1/cloudepg-aci-containers-default.json?query-target=children&target-subtree-class=fvRsCons,fvRsProv`: `{
    	"imdata": [
	        {
	            "fvRsProv": {
	                "attributes": {
	                    "status": "", 
	                    "stateQual": "none", 
	                    "uid": "15374", 
	                    "prio": "unspecified", 
	                    "extMngdBy": "", 
	                    "forceResolve": "yes", 
	                    "userdom": ":all:", 
	                    "tType": "name", 
	                    "matchT": "AtleastOne", 
	                    "tDn": "", 
	                    "rType": "mo", 
	                    "ctrctUpd": "ctrct", 
	                    "state": "missing-target", 
	                    "tContextDn": "", 
	                    "modTs": "2020-03-30T02:40:52.102+00:00", 
	                    "updateCollection": "no", 
	                    "monPolDn": "uni/tn-common/monepg-default", 
	                    "dn": "uni/tn-kuber/cloudapp-cluster1/cloudepg-aci-containers-default/rsprov-allow-kube", 
	                    "tRn": "brc-allow-kube", 
	                    "triggerSt": "triggerable", 
	                    "intent": "install", 
	                    "annotation": "", 
	                    "childAction": "", 
	                    "lcOwn": "local", 
	                    "tnVzBrCPName": "allow-kube", 
	                    "tCl": "vzBrCP"
	                }
	            }
	        }, 
	        {
	            "fvRsProv": {
	                "attributes": {
	                    "status": "", 
	                    "stateQual": "none", 
	                    "uid": "15374", 
	                    "prio": "unspecified", 
	                    "extMngdBy": "", 
	                    "forceResolve": "yes", 
	                    "userdom": ":all:", 
	                    "tType": "name", 
	                    "matchT": "AtleastOne", 
	                    "tDn": "", 
	                    "rType": "mo", 
	                    "ctrctUpd": "ctrct", 
	                    "state": "missing-target", 
	                    "tContextDn": "", 
	                    "modTs": "2020-03-30T02:40:52.102+00:00", 
	                    "updateCollection": "no", 
	                    "monPolDn": "uni/tn-common/monepg-default", 
	                    "dn": "uni/tn-kuber/cloudapp-cluster1/cloudepg-aci-containers-default/rsprov-cluster1_aci-containers-default", 
	                    "tRn": "brc-cluster1_aci-containers-default", 
	                    "triggerSt": "triggerable", 
	                    "intent": "install", 
	                    "annotation": "", 
	                    "childAction": "", 
	                    "lcOwn": "local", 
	                    "tnVzBrCPName": "cluster1_aci-containers-default", 
	                    "tCl": "vzBrCP"
	                }
	            }
	        }, 
	        {
	            "fvRsProv": {
	                "attributes": {
	                    "status": "", 
	                    "stateQual": "none", 
	                    "uid": "15374", 
	                    "prio": "unspecified", 
	                    "extMngdBy": "", 
	                    "forceResolve": "yes", 
	                    "userdom": ":all:", 
	                    "tType": "name", 
	                    "matchT": "AtleastOne", 
	                    "tDn": "uni/tn-kuber/brc-cluster1_allow-kube", 
	                    "rType": "mo", 
	                    "ctrctUpd": "ctrct", 
	                    "state": "formed", 
	                    "tContextDn": "", 
	                    "modTs": "2020-03-30T02:40:52.102+00:00", 
	                    "updateCollection": "no", 
	                    "monPolDn": "uni/tn-common/monepg-default", 
	                    "dn": "uni/tn-kuber/cloudapp-cluster1/cloudepg-aci-containers-default/rsprov-cluster1_allow-kube", 
	                    "tRn": "brc-cluster1_allow-kube", 
	                    "triggerSt": "triggerable", 
	                    "intent": "install", 
	                    "annotation": "", 
	                    "childAction": "", 
	                    "lcOwn": "local", 
	                    "tnVzBrCPName": "cluster1_allow-kube", 
	                    "tCl": "vzBrCP"
	                }
	            }
	        }, 
	        {
	            "fvRsCons": {
	                "attributes": {
	                    "status": "", 
	                    "uid": "15374", 
	                    "prio": "unspecified", 
	                    "extMngdBy": "", 
	                    "rType": "mo", 
	                    "forceResolve": "yes", 
	                    "userdom": ":all:", 
	                    "tType": "name", 
	                    "tDn": "uni/tn-kuber/brc-cluster1_allow-kube", 
	                    "stateQual": "none", 
	                    "ctrctUpd": "ctrct", 
	                    "state": "formed", 
	                    "tContextDn": "", 
	                    "modTs": "2020-03-30T02:40:52.102+00:00", 
	                    "updateCollection": "no", 
	                    "monPolDn": "uni/tn-common/monepg-default", 
	                    "dn": "uni/tn-kuber/cloudapp-cluster1/cloudepg-aci-containers-default/rscons-cluster1_allow-kube", 
	                    "tRn": "brc-cluster1_allow-kube", 
	                    "triggerSt": "triggerable", 
	                    "intent": "install", 
	                    "deplInfo": "", 
	                    "annotation": "", 
	                    "childAction": "", 
	                    "lcOwn": "local", 
	                    "tnVzBrCPName": "cluster1_allow-kube", 
	                    "tCl": "vzBrCP"
	                }
	            }
	        }
	    ], 
	    "totalCount": "4"
	}`,
		`/api/mo/uni/tn-kuber/cloudapp-cluster1/cloudepg-aci-containers-nodes.json?query-target=children&target-subtree-class=fvRsCons,fvRsProv`: `{
	    "imdata": [
	        {
	            "fvRsProv": {
	                "attributes": {
	                    "status": "", 
	                    "stateQual": "none", 
	                    "uid": "15374", 
	                    "prio": "unspecified", 
	                    "extMngdBy": "", 
	                    "forceResolve": "yes", 
	                    "userdom": ":all:", 
	                    "tType": "name", 
	                    "matchT": "AtleastOne", 
	                    "tDn": "", 
	                    "rType": "mo", 
	                    "ctrctUpd": "ctrct", 
	                    "state": "missing-target", 
	                    "tContextDn": "", 
	                    "modTs": "2020-03-30T02:40:52.102+00:00", 
	                    "updateCollection": "no", 
	                    "monPolDn": "uni/tn-common/monepg-default", 
	                    "dn": "uni/tn-kuber/cloudapp-cluster1/cloudepg-aci-containers-nodes/rsprov-allow-kube", 
	                    "tRn": "brc-allow-kube", 
	                    "triggerSt": "triggerable", 
	                    "intent": "install", 
	                    "annotation": "", 
	                    "childAction": "", 
	                    "lcOwn": "local", 
	                    "tnVzBrCPName": "allow-kube", 
	                    "tCl": "vzBrCP"
	                }
	            }
	        }, 
	        {
	            "fvRsProv": {
	                "attributes": {
	                    "status": "", 
	                    "stateQual": "none", 
	                    "uid": "15374", 
	                    "prio": "unspecified", 
	                    "extMngdBy": "", 
	                    "forceResolve": "yes", 
	                    "userdom": ":all:", 
	                    "tType": "name", 
	                    "matchT": "AtleastOne", 
	                    "tDn": "", 
	                    "rType": "mo", 
	                    "ctrctUpd": "ctrct", 
	                    "state": "missing-target", 
	                    "tContextDn": "", 
	                    "modTs": "2020-03-30T02:40:52.102+00:00", 
	                    "updateCollection": "no", 
	                    "monPolDn": "uni/tn-common/monepg-default", 
	                    "dn": "uni/tn-kuber/cloudapp-cluster1/cloudepg-aci-containers-nodes/rsprov-cluster1_aci-containers-nodes", 
	                    "tRn": "brc-cluster1_aci-containers-nodes", 
	                    "triggerSt": "triggerable", 
	                    "intent": "install", 
	                    "annotation": "", 
	                    "childAction": "", 
	                    "lcOwn": "local", 
	                    "tnVzBrCPName": "cluster1_aci-containers-nodes", 
	                    "tCl": "vzBrCP"
	                }
	            }
	        }, 
	        {
	            "fvRsProv": {
	                "attributes": {
	                    "status": "", 
	                    "stateQual": "none", 
	                    "uid": "15374", 
	                    "prio": "unspecified", 
	                    "extMngdBy": "", 
	                    "forceResolve": "yes", 
	                    "userdom": ":all:", 
	                    "tType": "name", 
	                    "matchT": "AtleastOne", 
	                    "tDn": "uni/tn-kuber/brc-cluster1_allow-kube", 
	                    "rType": "mo", 
	                    "ctrctUpd": "ctrct", 
	                    "state": "formed", 
	                    "tContextDn": "", 
	                    "modTs": "2020-03-30T02:40:52.102+00:00", 
	                    "updateCollection": "no", 
	                    "monPolDn": "uni/tn-common/monepg-default", 
	                    "dn": "uni/tn-kuber/cloudapp-cluster1/cloudepg-aci-containers-nodes/rsprov-cluster1_allow-kube", 
	                    "tRn": "brc-cluster1_allow-kube", 
	                    "triggerSt": "triggerable", 
	                    "intent": "install", 
	                    "annotation": "", 
	                    "childAction": "", 
	                    "lcOwn": "local", 
	                    "tnVzBrCPName": "cluster1_allow-kube", 
	                    "tCl": "vzBrCP"
	                }
	            }
	        }, 
	        {
	            "fvRsCons": {
	                "attributes": {
	                    "status": "", 
	                    "uid": "15374", 
	                    "prio": "unspecified", 
	                    "extMngdBy": "", 
	                    "rType": "mo", 
	                    "forceResolve": "yes", 
	                    "userdom": ":all:", 
	                    "tType": "name", 
	                    "tDn": "", 
	                    "stateQual": "none", 
	                    "ctrctUpd": "ctrct", 
	                    "state": "missing-target", 
	                    "tContextDn": "", 
	                    "modTs": "2020-03-30T02:40:52.102+00:00", 
	                    "updateCollection": "no", 
	                    "monPolDn": "uni/tn-common/monepg-default", 
	                    "dn": "uni/tn-kuber/cloudapp-cluster1/cloudepg-aci-containers-nodes/rscons-allow-kube", 
	                    "tRn": "brc-allow-kube", 
	                    "triggerSt": "triggerable", 
	                    "intent": "install", 
	                    "deplInfo": "", 
	                    "annotation": "", 
	                    "childAction": "", 
	                    "lcOwn": "local", 
	                    "tnVzBrCPName": "allow-kube", 
	                    "tCl": "vzBrCP"
	                }
	            }
	        }, 
	        {
	            "fvRsCons": {
	                "attributes": {
	                    "status": "", 
	                    "uid": "15374", 
	                    "prio": "unspecified", 
	                    "extMngdBy": "", 
	                    "rType": "mo", 
	                    "forceResolve": "yes", 
	                    "userdom": ":all:", 
	                    "tType": "name", 
	                    "tDn": "uni/tn-kuber/brc-cluster1_allow-kube", 
	                    "stateQual": "none", 
	                    "ctrctUpd": "ctrct", 
	                    "state": "formed", 
	                    "tContextDn": "", 
	                    "modTs": "2020-03-30T02:40:52.102+00:00", 
	                    "updateCollection": "no", 
	                    "monPolDn": "uni/tn-common/monepg-default", 
	                    "dn": "uni/tn-kuber/cloudapp-cluster1/cloudepg-aci-containers-nodes/rscons-cluster1_allow-kube", 
	                    "tRn": "brc-cluster1_allow-kube", 
	                    "triggerSt": "triggerable", 
	                    "intent": "install", 
	                    "deplInfo": "", 
	                    "annotation": "", 
	                    "childAction": "", 
	                    "lcOwn": "local", 
	                    "tnVzBrCPName": "cluster1_allow-kube", 
	                    "tCl": "vzBrCP"
	                }
	            }
	        }
	    ], 
	    "totalCount": "5"
	}`,
		`/api/mo/uni/tn-kuber/cloudapp-cluster1/cloudepg-aci-containers-system.json?query-target=children&target-subtree-class=fvRsCons,fvRsProv`: `{
	    "imdata": [
	        {
	            "fvRsProv": {
	                "attributes": {
	                    "status": "", 
	                    "stateQual": "none", 
	                    "uid": "15374", 
	                    "prio": "unspecified", 
	                    "extMngdBy": "", 
	                    "forceResolve": "yes", 
	                    "userdom": ":all:", 
	                    "tType": "name", 
	                    "matchT": "AtleastOne", 
	                    "tDn": "", 
	                    "rType": "mo", 
	                    "ctrctUpd": "ctrct", 
	                    "state": "missing-target", 
	                    "tContextDn": "", 
	                    "modTs": "2020-04-07T00:45:14.440+00:00", 
	                    "updateCollection": "no", 
	                    "monPolDn": "uni/tn-common/monepg-default", 
	                    "dn": "uni/tn-kuber/cloudapp-cluster1/cloudepg-aci-containers-system/rsprov-allow-kube", 
	                    "tRn": "brc-allow-kube", 
	                    "triggerSt": "triggerable", 
	                    "intent": "install", 
	                    "annotation": "", 
	                    "childAction": "", 
	                    "lcOwn": "local", 
	                    "tnVzBrCPName": "allow-kube", 
	                    "tCl": "vzBrCP"
	                }
	            }
	        }, 
	        {
	            "fvRsProv": {
	                "attributes": {
	                    "status": "", 
	                    "stateQual": "none", 
	                    "uid": "15374", 
	                    "prio": "unspecified", 
	                    "extMngdBy": "", 
	                    "forceResolve": "yes", 
	                    "userdom": ":all:", 
	                    "tType": "name", 
	                    "matchT": "AtleastOne", 
	                    "tDn": "", 
	                    "rType": "mo", 
	                    "ctrctUpd": "ctrct", 
	                    "state": "missing-target", 
	                    "tContextDn": "", 
	                    "modTs": "2020-04-07T00:45:14.440+00:00", 
	                    "updateCollection": "no", 
	                    "monPolDn": "uni/tn-common/monepg-default", 
	                    "dn": "uni/tn-kuber/cloudapp-cluster1/cloudepg-aci-containers-system/rsprov-cluster1_aci-containers-system", 
	                    "tRn": "brc-cluster1_aci-containers-system", 
	                    "triggerSt": "triggerable", 
	                    "intent": "install", 
	                    "annotation": "", 
	                    "childAction": "", 
	                    "lcOwn": "local", 
	                    "tnVzBrCPName": "cluster1_aci-containers-system", 
	                    "tCl": "vzBrCP"
	                }
	            }
	        }, 
	        {
	            "fvRsProv": {
	                "attributes": {
	                    "status": "", 
	                    "stateQual": "none", 
	                    "uid": "15374", 
	                    "prio": "unspecified", 
	                    "extMngdBy": "", 
	                    "forceResolve": "yes", 
	                    "userdom": ":all:", 
	                    "tType": "name", 
	                    "matchT": "AtleastOne", 
	                    "tDn": "uni/tn-kuber/brc-cluster1_allow-kube", 
	                    "rType": "mo", 
	                    "ctrctUpd": "ctrct", 
	                    "state": "formed", 
	                    "tContextDn": "", 
	                    "modTs": "2020-04-07T00:45:14.440+00:00", 
	                    "updateCollection": "no", 
	                    "monPolDn": "uni/tn-common/monepg-default", 
	                    "dn": "uni/tn-kuber/cloudapp-cluster1/cloudepg-aci-containers-system/rsprov-cluster1_allow-kube", 
	                    "tRn": "brc-cluster1_allow-kube", 
	                    "triggerSt": "triggerable", 
	                    "intent": "install", 
	                    "annotation": "", 
	                    "childAction": "", 
	                    "lcOwn": "local", 
	                    "tnVzBrCPName": "cluster1_allow-kube", 
	                    "tCl": "vzBrCP"
	                }
	            }
	        }, 
	        {
	            "fvRsCons": {
	                "attributes": {
	                    "status": "", 
	                    "uid": "15374", 
	                    "prio": "unspecified", 
	                    "extMngdBy": "", 
	                    "rType": "mo", 
	                    "forceResolve": "yes", 
	                    "userdom": ":all:", 
	                    "tType": "name", 
	                    "tDn": "", 
	                    "stateQual": "none", 
	                    "ctrctUpd": "ctrct", 
	                    "state": "missing-target", 
	                    "tContextDn": "", 
	                    "modTs": "2020-04-07T00:45:14.440+00:00", 
	                    "updateCollection": "no", 
	                    "monPolDn": "uni/tn-common/monepg-default", 
	                    "dn": "uni/tn-kuber/cloudapp-cluster1/cloudepg-aci-containers-system/rscons-allow-kube", 
	                    "tRn": "brc-allow-kube", 
	                    "triggerSt": "triggerable", 
	                    "intent": "install", 
	                    "deplInfo": "", 
	                    "annotation": "", 
	                    "childAction": "", 
	                    "lcOwn": "local", 
	                    "tnVzBrCPName": "allow-kube", 
	                    "tCl": "vzBrCP"
	                }
	            }
	        }, 
	        {
	            "fvRsCons": {
	                "attributes": {
	                    "status": "", 
	                    "uid": "15374", 
	                    "prio": "unspecified", 
	                    "extMngdBy": "", 
	                    "rType": "mo", 
	                    "forceResolve": "yes", 
	                    "userdom": ":all:", 
	                    "tType": "name", 
	                    "tDn": "", 
	                    "stateQual": "none", 
	                    "ctrctUpd": "ctrct", 
	                    "state": "missing-target", 
	                    "tContextDn": "", 
	                    "modTs": "2020-04-07T00:45:14.440+00:00", 
	                    "updateCollection": "no", 
	                    "monPolDn": "uni/tn-common/monepg-default", 
	                    "dn": "uni/tn-kuber/cloudapp-cluster1/cloudepg-aci-containers-system/rscons-cluster1_aci-containers-system", 
	                    "tRn": "brc-cluster1_aci-containers-system", 
	                    "triggerSt": "triggerable", 
	                    "intent": "install", 
	                    "deplInfo": "", 
	                    "annotation": "", 
	                    "childAction": "", 
	                    "lcOwn": "local", 
	                    "tnVzBrCPName": "cluster1_aci-containers-system", 
	                    "tCl": "vzBrCP"
	                }
	            }
	        }, 
	        {
	            "fvRsCons": {
	                "attributes": {
	                    "status": "", 
	                    "uid": "15374", 
	                    "prio": "unspecified", 
	                    "extMngdBy": "", 
	                    "rType": "mo", 
	                    "forceResolve": "yes", 
	                    "userdom": ":all:", 
	                    "tType": "name", 
	                    "tDn": "uni/tn-kuber/brc-cluster1_allow-kube", 
	                    "stateQual": "none", 
	                    "ctrctUpd": "ctrct", 
	                    "state": "formed", 
	                    "tContextDn": "", 
	                    "modTs": "2020-04-07T00:45:14.440+00:00", 
	                    "updateCollection": "no", 
	                    "monPolDn": "uni/tn-common/monepg-default", 
	                    "dn": "uni/tn-kuber/cloudapp-cluster1/cloudepg-aci-containers-system/rscons-cluster1_allow-kube", 
	                    "tRn": "brc-cluster1_allow-kube", 
	                    "triggerSt": "triggerable", 
	                    "intent": "install", 
	                    "deplInfo": "", 
	                    "annotation": "", 
	                    "childAction": "", 
	                    "lcOwn": "local", 
	                    "tnVzBrCPName": "cluster1_allow-kube", 
	                    "tCl": "vzBrCP"
	                }
	            }
	        }
	    ], 
	    "totalCount": "6"
	}`,
		`/api/mo/uni/tn-kuber/cloudapp-cluster1/cloudepg-epg-a.json?query-target=children&target-subtree-class=fvRsCons,fvRsProv`: `{
	    "imdata": [
	        {
	            "fvRsProv": {
	                "attributes": {
	                    "status": "", 
	                    "stateQual": "none", 
	                    "uid": "15374", 
	                    "prio": "unspecified", 
	                    "extMngdBy": "", 
	                    "forceResolve": "yes", 
	                    "userdom": ":all:", 
	                    "tType": "name", 
	                    "matchT": "AtleastOne", 
	                    "tDn": "uni/tn-kuber/brc-icmp-allow", 
	                    "rType": "mo", 
	                    "ctrctUpd": "ctrct", 
	                    "state": "formed", 
	                    "tContextDn": "", 
	                    "modTs": "2020-04-11T20:08:09.484+00:00", 
	                    "updateCollection": "no", 
	                    "monPolDn": "uni/tn-common/monepg-default", 
	                    "dn": "uni/tn-kuber/cloudapp-cluster1/cloudepg-epg-a/rsprov-icmp-allow", 
	                    "tRn": "brc-icmp-allow", 
	                    "triggerSt": "triggerable", 
	                    "intent": "install", 
	                    "annotation": "", 
	                    "childAction": "", 
	                    "lcOwn": "local", 
	                    "tnVzBrCPName": "icmp-allow", 
	                    "tCl": "vzBrCP"
	                }
	            }
	        }, 
	        {
	            "fvRsCons": {
	                "attributes": {
	                    "status": "", 
	                    "uid": "15374", 
	                    "prio": "unspecified", 
	                    "extMngdBy": "", 
	                    "rType": "mo", 
	                    "forceResolve": "yes", 
	                    "userdom": ":all:", 
	                    "tType": "name", 
	                    "tDn": "uni/tn-kuber/brc-c-tcp6020", 
	                    "stateQual": "none", 
	                    "ctrctUpd": "ctrct", 
	                    "state": "formed", 
	                    "tContextDn": "", 
	                    "modTs": "2020-04-11T20:08:09.484+00:00", 
	                    "updateCollection": "no", 
	                    "monPolDn": "uni/tn-common/monepg-default", 
	                    "dn": "uni/tn-kuber/cloudapp-cluster1/cloudepg-epg-a/rscons-c-tcp6020", 
	                    "tRn": "brc-c-tcp6020", 
	                    "triggerSt": "triggerable", 
	                    "intent": "install", 
	                    "deplInfo": "", 
	                    "annotation": "", 
	                    "childAction": "", 
	                    "lcOwn": "local", 
	                    "tnVzBrCPName": "c-tcp6020", 
	                    "tCl": "vzBrCP"
	                }
	            }
	        }, 
	        {
	            "fvRsCons": {
	                "attributes": {
	                    "status": "", 
	                    "uid": "15374", 
	                    "prio": "unspecified", 
	                    "extMngdBy": "", 
	                    "rType": "mo", 
	                    "forceResolve": "yes", 
	                    "userdom": ":all:", 
	                    "tType": "name", 
	                    "tDn": "uni/tn-kuber/brc-icmp-allow", 
	                    "stateQual": "none", 
	                    "ctrctUpd": "ctrct", 
	                    "state": "formed", 
	                    "tContextDn": "", 
	                    "modTs": "2020-04-11T20:08:09.484+00:00", 
	                    "updateCollection": "no", 
	                    "monPolDn": "uni/tn-common/monepg-default", 
	                    "dn": "uni/tn-kuber/cloudapp-cluster1/cloudepg-epg-a/rscons-icmp-allow", 
	                    "tRn": "brc-icmp-allow", 
	                    "triggerSt": "triggerable", 
	                    "intent": "install", 
	                    "deplInfo": "", 
	                    "annotation": "", 
	                    "childAction": "", 
	                    "lcOwn": "local", 
	                    "tnVzBrCPName": "icmp-allow", 
	                    "tCl": "vzBrCP"
	                }
	            }
	        }, 
	        {
	            "fvRsCons": {
	                "attributes": {
	                    "status": "", 
	                    "uid": "15374", 
	                    "prio": "unspecified", 
	                    "extMngdBy": "", 
	                    "rType": "mo", 
	                    "forceResolve": "yes", 
	                    "userdom": ":all:", 
	                    "tType": "name", 
	                    "tDn": "uni/tn-kuber/brc-kuber-global-icmp", 
	                    "stateQual": "none", 
	                    "ctrctUpd": "ctrct", 
	                    "state": "formed", 
	                    "tContextDn": "", 
	                    "modTs": "2020-04-11T20:08:09.484+00:00", 
	                    "updateCollection": "no", 
	                    "monPolDn": "uni/tn-common/monepg-default", 
	                    "dn": "uni/tn-kuber/cloudapp-cluster1/cloudepg-epg-a/rscons-kuber-global-icmp", 
	                    "tRn": "brc-kuber-global-icmp", 
	                    "triggerSt": "triggerable", 
	                    "intent": "install", 
	                    "deplInfo": "", 
	                    "annotation": "", 
	                    "childAction": "", 
	                    "lcOwn": "local", 
	                    "tnVzBrCPName": "kuber-global-icmp", 
	                    "tCl": "vzBrCP"
	                }
	            }
	        }
	    ], 
	    "totalCount": "4"
	}`,
		`/api/mo/uni/tn-kuber/cloudapp-cluster1/cloudepg-epg-b.json?query-target=children&target-subtree-class=fvRsCons,fvRsProv`: `{
	    "imdata": [
	        {
	            "fvRsProv": {
	                "attributes": {
	                    "status": "", 
	                    "stateQual": "none", 
	                    "uid": "15374", 
	                    "prio": "unspecified", 
	                    "extMngdBy": "", 
	                    "forceResolve": "yes", 
	                    "userdom": ":all:", 
	                    "tType": "name", 
	                    "matchT": "AtleastOne", 
	                    "tDn": "uni/tn-kuber/brc-c-tcp6020", 
	                    "rType": "mo", 
	                    "ctrctUpd": "ctrct", 
	                    "state": "formed", 
	                    "tContextDn": "", 
	                    "modTs": "2020-04-11T20:10:24.784+00:00", 
	                    "updateCollection": "no", 
	                    "monPolDn": "uni/tn-common/monepg-default", 
	                    "dn": "uni/tn-kuber/cloudapp-cluster1/cloudepg-epg-b/rsprov-c-tcp6020", 
	                    "tRn": "brc-c-tcp6020", 
	                    "triggerSt": "triggerable", 
	                    "intent": "install", 
	                    "annotation": "", 
	                    "childAction": "", 
	                    "lcOwn": "local", 
	                    "tnVzBrCPName": "c-tcp6020", 
	                    "tCl": "vzBrCP"
	                }
	            }
	        }, 
	        {
	            "fvRsProv": {
	                "attributes": {
	                    "status": "", 
	                    "stateQual": "none", 
	                    "uid": "15374", 
	                    "prio": "unspecified", 
	                    "extMngdBy": "", 
	                    "forceResolve": "yes", 
	                    "userdom": ":all:", 
	                    "tType": "name", 
	                    "matchT": "AtleastOne", 
	                    "tDn": "uni/tn-kuber/brc-icmp-allow", 
	                    "rType": "mo", 
	                    "ctrctUpd": "ctrct", 
	                    "state": "formed", 
	                    "tContextDn": "", 
	                    "modTs": "2020-04-11T20:10:24.784+00:00", 
	                    "updateCollection": "no", 
	                    "monPolDn": "uni/tn-common/monepg-default", 
	                    "dn": "uni/tn-kuber/cloudapp-cluster1/cloudepg-epg-b/rsprov-icmp-allow", 
	                    "tRn": "brc-icmp-allow", 
	                    "triggerSt": "triggerable", 
	                    "intent": "install", 
	                    "annotation": "", 
	                    "childAction": "", 
	                    "lcOwn": "local", 
	                    "tnVzBrCPName": "icmp-allow", 
	                    "tCl": "vzBrCP"
	                }
	            }
	        }, 
	        {
	            "fvRsProv": {
	                "attributes": {
	                    "status": "", 
	                    "stateQual": "none", 
	                    "uid": "15374", 
	                    "prio": "unspecified", 
	                    "extMngdBy": "", 
	                    "forceResolve": "yes", 
	                    "userdom": ":all:", 
	                    "tType": "name", 
	                    "matchT": "AtleastOne", 
	                    "tDn": "uni/tn-kuber/brc-kuber-global-icmp", 
	                    "rType": "mo", 
	                    "ctrctUpd": "ctrct", 
	                    "state": "formed", 
	                    "tContextDn": "", 
	                    "modTs": "2020-04-11T20:10:24.784+00:00", 
	                    "updateCollection": "no", 
	                    "monPolDn": "uni/tn-common/monepg-default", 
	                    "dn": "uni/tn-kuber/cloudapp-cluster1/cloudepg-epg-b/rsprov-kuber-global-icmp", 
	                    "tRn": "brc-kuber-global-icmp", 
	                    "triggerSt": "triggerable", 
	                    "intent": "install", 
	                    "annotation": "", 
	                    "childAction": "", 
	                    "lcOwn": "local", 
	                    "tnVzBrCPName": "kuber-global-icmp", 
	                    "tCl": "vzBrCP"
	                }
	            }
	        }, 
	        {
	            "fvRsCons": {
	                "attributes": {
	                    "status": "", 
	                    "uid": "15374", 
	                    "prio": "unspecified", 
	                    "extMngdBy": "", 
	                    "rType": "mo", 
	                    "forceResolve": "yes", 
	                    "userdom": ":all:", 
	                    "tType": "name", 
	                    "tDn": "uni/tn-kuber/brc-icmp-allow", 
	                    "stateQual": "none", 
	                    "ctrctUpd": "ctrct", 
	                    "state": "formed", 
	                    "tContextDn": "", 
	                    "modTs": "2020-04-11T20:10:24.784+00:00", 
	                    "updateCollection": "no", 
	                    "monPolDn": "uni/tn-common/monepg-default", 
	                    "dn": "uni/tn-kuber/cloudapp-cluster1/cloudepg-epg-b/rscons-icmp-allow", 
	                    "tRn": "brc-icmp-allow", 
	                    "triggerSt": "triggerable", 
	                    "intent": "install", 
	                    "deplInfo": "", 
	                    "annotation": "", 
	                    "childAction": "", 
	                    "lcOwn": "local", 
	                    "tnVzBrCPName": "icmp-allow", 
	                    "tCl": "vzBrCP"
	                }
	            }
	        }, 
	        {
	            "fvRsCons": {
	                "attributes": {
	                    "status": "", 
	                    "uid": "15374", 
	                    "prio": "unspecified", 
	                    "extMngdBy": "", 
	                    "rType": "mo", 
	                    "forceResolve": "yes", 
	                    "userdom": ":all:", 
	                    "tType": "name", 
	                    "tDn": "uni/tn-kuber/brc-kuber-global-tcp6020", 
	                    "stateQual": "none", 
	                    "ctrctUpd": "ctrct", 
	                    "state": "formed", 
	                    "tContextDn": "", 
	                    "modTs": "2020-04-11T20:10:24.784+00:00", 
	                    "updateCollection": "no", 
	                    "monPolDn": "uni/tn-common/monepg-default", 
	                    "dn": "uni/tn-kuber/cloudapp-cluster1/cloudepg-epg-b/rscons-kuber-global-tcp6020", 
	                    "tRn": "brc-kuber-global-tcp6020", 
	                    "triggerSt": "triggerable", 
	                    "intent": "install", 
	                    "deplInfo": "", 
	                    "annotation": "", 
	                    "childAction": "", 
	                    "lcOwn": "local", 
	                    "tnVzBrCPName": "kuber-global-tcp6020", 
	                    "tCl": "vzBrCP"
	                }
	            }
	        }
	    ], 
	    "totalCount": "5"
	}`,
	}

	resp := resps[r.URL.RequestURI()]
	w.Write([]byte(resp))
}

func vzBrCPHandler(w http.ResponseWriter, r *http.Request) {
	resps := map[string]string{
		`/api/mo/uni/tn-kuber/brc-c-tcp6020.json?query-target=children&target-subtree-class=vzRtCons,vzRtProv`: `{
    "imdata": [
        {
            "vzRtProv": {
                "attributes": {
                    "dn": "uni/tn-kuber/brc-c-tcp6020/rtfvProv-[uni/tn-kuber/cloudapp-cluster1/cloudepg-epg-b]", 
                    "lcOwn": "local", 
                    "tDn": "uni/tn-kuber/cloudapp-cluster1/cloudepg-epg-b", 
                    "tCl": "cloudEPg", 
                    "status": "", 
                    "modTs": "2020-04-04T16:56:49.422+00:00", 
                    "childAction": ""
                }
            }
        }, 
        {
            "vzRtCons": {
                "attributes": {
                    "dn": "uni/tn-kuber/brc-c-tcp6020/rtfvCons-[uni/tn-kuber/cloudapp-cluster1/cloudepg-epg-a]", 
                    "lcOwn": "local", 
                    "tDn": "uni/tn-kuber/cloudapp-cluster1/cloudepg-epg-a", 
                    "tCl": "cloudEPg", 
                    "status": "", 
                    "modTs": "2020-04-04T23:08:29.357+00:00", 
                    "childAction": ""
                }
            }
        }
    ], 
    "totalCount": "2"
}`,
		`/api/mo/uni/tn-kuber/brc-cluster1_allow-kube.json?query-target=children&target-subtree-class=vzRtCons,vzRtProv`: `{
    "imdata": [
        {
            "vzRtProv": {
                "attributes": {
                    "dn": "uni/tn-kuber/brc-cluster1_allow-kube/rtfvProv-[uni/tn-kuber/cloudapp-cluster1/cloudepg-aci-containers-nodes]", 
                    "lcOwn": "local", 
                    "tDn": "uni/tn-kuber/cloudapp-cluster1/cloudepg-aci-containers-nodes", 
                    "tCl": "cloudEPg", 
                    "status": "", 
                    "modTs": "2020-03-30T02:40:52.102+00:00", 
                    "childAction": ""
                }
            }
        }, 
        {
            "vzRtProv": {
                "attributes": {
                    "dn": "uni/tn-kuber/brc-cluster1_allow-kube/rtfvProv-[uni/tn-kuber/cloudapp-cluster1/cloudepg-aci-containers-default]", 
                    "lcOwn": "local", 
                    "tDn": "uni/tn-kuber/cloudapp-cluster1/cloudepg-aci-containers-default", 
                    "tCl": "cloudEPg", 
                    "status": "", 
                    "modTs": "2020-03-30T02:40:52.102+00:00", 
                    "childAction": ""
                }
            }
        }, 
        {
            "vzRtProv": {
                "attributes": {
                    "dn": "uni/tn-kuber/brc-cluster1_allow-kube/rtfvProv-[uni/tn-kuber/cloudapp-cluster1/cloudepg-aci-containers-system]", 
                    "lcOwn": "local", 
                    "tDn": "uni/tn-kuber/cloudapp-cluster1/cloudepg-aci-containers-system", 
                    "tCl": "cloudEPg", 
                    "status": "", 
                    "modTs": "2020-03-30T02:40:52.102+00:00", 
                    "childAction": ""
                }
            }
        }, 
        {
            "vzRtCons": {
                "attributes": {
                    "dn": "uni/tn-kuber/brc-cluster1_allow-kube/rtfvCons-[uni/tn-kuber/cloudapp-cluster1/cloudepg-aci-containers-system]", 
                    "lcOwn": "local", 
                    "tDn": "uni/tn-kuber/cloudapp-cluster1/cloudepg-aci-containers-system", 
                    "tCl": "cloudEPg", 
                    "status": "", 
                    "modTs": "2020-03-30T02:40:52.102+00:00", 
                    "childAction": ""
                }
            }
        }, 
        {
            "vzRtCons": {
                "attributes": {
                    "dn": "uni/tn-kuber/brc-cluster1_allow-kube/rtfvCons-[uni/tn-kuber/cloudapp-cluster1/cloudepg-aci-containers-default]", 
                    "lcOwn": "local", 
                    "tDn": "uni/tn-kuber/cloudapp-cluster1/cloudepg-aci-containers-default", 
                    "tCl": "cloudEPg", 
                    "status": "", 
                    "modTs": "2020-03-30T02:40:52.102+00:00", 
                    "childAction": ""
                }
            }
        }, 
        {
            "vzRtCons": {
                "attributes": {
                    "dn": "uni/tn-kuber/brc-cluster1_allow-kube/rtfvCons-[uni/tn-kuber/cloudapp-cluster1/cloudepg-aci-containers-nodes]", 
                    "lcOwn": "local", 
                    "tDn": "uni/tn-kuber/cloudapp-cluster1/cloudepg-aci-containers-nodes", 
                    "tCl": "cloudEPg", 
                    "status": "", 
                    "modTs": "2020-03-30T02:40:52.102+00:00", 
                    "childAction": ""
                }
            }
        }
    ], 
    "totalCount": "6"
}`,
		`/api/mo/uni/tn-kuber/brc-icmp-allow.json?query-target=children&target-subtree-class=vzRtCons,vzRtProv`: `{
    "imdata": [
        {
            "vzRtProv": {
                "attributes": {
                    "dn": "uni/tn-kuber/brc-icmp-allow/rtfvProv-[uni/tn-kuber/cloudapp-cluster1/cloudepg-epg-a]", 
                    "lcOwn": "local", 
                    "tDn": "uni/tn-kuber/cloudapp-cluster1/cloudepg-epg-a", 
                    "tCl": "cloudEPg", 
                    "status": "", 
                    "modTs": "2020-04-05T16:46:34.966+00:00", 
                    "childAction": ""
                }
            }
        }, 
        {
            "vzRtProv": {
                "attributes": {
                    "dn": "uni/tn-kuber/brc-icmp-allow/rtfvProv-[uni/tn-kuber/cloudapp-cluster1/cloudepg-epg-b]", 
                    "lcOwn": "local", 
                    "tDn": "uni/tn-kuber/cloudapp-cluster1/cloudepg-epg-b", 
                    "tCl": "cloudEPg", 
                    "status": "", 
                    "modTs": "2020-04-05T16:46:34.966+00:00", 
                    "childAction": ""
                }
            }
        }, 
        {
            "vzRtCons": {
                "attributes": {
                    "dn": "uni/tn-kuber/brc-icmp-allow/rtfvCons-[uni/tn-kuber/cloudapp-cluster1/cloudepg-epg-a]", 
                    "lcOwn": "local", 
                    "tDn": "uni/tn-kuber/cloudapp-cluster1/cloudepg-epg-a", 
                    "tCl": "cloudEPg", 
                    "status": "", 
                    "modTs": "2020-04-05T16:46:34.966+00:00", 
                    "childAction": ""
                }
            }
        }, 
        {
            "vzRtCons": {
                "attributes": {
                    "dn": "uni/tn-kuber/brc-icmp-allow/rtfvCons-[uni/tn-kuber/cloudapp-cluster1/cloudepg-epg-b]", 
                    "lcOwn": "local", 
                    "tDn": "uni/tn-kuber/cloudapp-cluster1/cloudepg-epg-b", 
                    "tCl": "cloudEPg", 
                    "status": "", 
                    "modTs": "2020-04-05T16:46:34.966+00:00", 
                    "childAction": ""
                }
            }
        }
    ], 
    "totalCount": "4"
}`,
		`/api/mo/uni/tn-kuber/brc-kuber-global-icmp.json?query-target=children&target-subtree-class=vzRtCons,vzRtProv`: `{
    "imdata": [
        {
            "vzRtProv": {
                "attributes": {
                    "dn": "uni/tn-kuber/brc-kuber-global-icmp/rtfvProv-[uni/tn-kuber/cloudapp-cluster1/cloudepg-epg-b]", 
                    "lcOwn": "local", 
                    "tDn": "uni/tn-kuber/cloudapp-cluster1/cloudepg-epg-b", 
                    "tCl": "cloudEPg", 
                    "status": "", 
                    "modTs": "2020-04-11T20:08:09.484+00:00", 
                    "childAction": ""
                }
            }
        }, 
        {
            "vzRtProv": {
                "attributes": {
                    "dn": "uni/tn-kuber/brc-kuber-global-icmp/rtfvProv-[uni/tn-kuber/cloudapp-ul2/cloudepg-vm-pingers]", 
                    "lcOwn": "local", 
                    "tDn": "uni/tn-kuber/cloudapp-ul2/cloudepg-vm-pingers", 
                    "tCl": "cloudEPg", 
                    "status": "", 
                    "modTs": "2020-04-11T20:08:09.484+00:00", 
                    "childAction": ""
                }
            }
        }, 
        {
            "vzRtCons": {
                "attributes": {
                    "dn": "uni/tn-kuber/brc-kuber-global-icmp/rtfvCons-[uni/tn-kuber/cloudapp-cluster1/cloudepg-epg-a]", 
                    "lcOwn": "local", 
                    "tDn": "uni/tn-kuber/cloudapp-cluster1/cloudepg-epg-a", 
                    "tCl": "cloudEPg", 
                    "status": "", 
                    "modTs": "2020-04-11T20:08:09.484+00:00", 
                    "childAction": ""
                }
            }
        }
    ], 
    "totalCount": "3"
}`,
		`/api/mo/uni/tn-kuber/brc-kuber-global-tcp6020.json?query-target=children&target-subtree-class=vzRtCons,vzRtProv`: `{
    "imdata": [
        {
            "vzRtProv": {
                "attributes": {
                    "dn": "uni/tn-kuber/brc-kuber-global-tcp6020/rtfvProv-[uni/tn-kuber/cloudapp-ul2/cloudepg-vm-tcp6020ers]", 
                    "lcOwn": "local", 
                    "tDn": "uni/tn-kuber/cloudapp-ul2/cloudepg-vm-tcp6020ers", 
                    "tCl": "cloudEPg", 
                    "status": "", 
                    "modTs": "2020-04-11T20:10:24.784+00:00", 
                    "childAction": ""
                }
            }
        }, 
        {
            "vzRtCons": {
                "attributes": {
                    "dn": "uni/tn-kuber/brc-kuber-global-tcp6020/rtfvCons-[uni/tn-kuber/cloudapp-cluster1/cloudepg-epg-b]", 
                    "lcOwn": "local", 
                    "tDn": "uni/tn-kuber/cloudapp-cluster1/cloudepg-epg-b", 
                    "tCl": "cloudEPg", 
                    "status": "", 
                    "modTs": "2020-04-11T20:10:24.784+00:00", 
                    "childAction": ""
                }
            }
        }
    ], 
    "totalCount": "2"
}`,
	}
	resp := resps[r.URL.RequestURI()]
	w.Write([]byte(resp))
}

func cEpgFetchHandler(w http.ResponseWriter, r *http.Request) {
	resps := map[string]string{
		`/api/mo/uni/tn-kuber/cloudapp-ul2/cloudepg-vm-pingers.json?rsp-subtree=full`: `{
    "imdata": [
        {
            "cloudEPg": {
                "attributes": {
                    "status": "", 
                    "uid": "15374", 
                    "prio": "unspecified", 
                    "extMngdBy": "", 
                    "userdom": ":all:", 
                    "matchT": "AtleastOne", 
                    "descr": "", 
                    "prefGrMemb": "exclude", 
                    "monPolDn": "uni/tn-common/monepg-default", 
                    "modTs": "2020-04-11T20:08:09.576+00:00", 
                    "scope": "2424832", 
                    "dn": "uni/tn-kuber/cloudapp-ul2/cloudepg-vm-pingers", 
                    "nameAlias": "", 
                    "accessPrivilege": "USER", 
                    "configIssues": "", 
                    "configSt": "applied", 
                    "isSharedSrvMsiteEPg": "no", 
                    "triggerSt": "triggerable", 
                    "txId": "10376293541462227058", 
                    "annotation": "", 
                    "childAction": "", 
                    "lcOwn": "local", 
                    "name": "vm-pingers", 
                    "pcTag": "10930", 
                    "exceptionTag": "", 
                    "floodOnEncap": "disabled"
                }, 
                "children": [
                    {
                        "fvSharedService": {
                            "attributes": {
                                "lcOwn": "local", 
                                "status": "", 
                                "name": "", 
                                "modTs": "2020-04-11T20:08:09.550+00:00", 
                                "monPolDn": "uni/tn-common/monepg-default", 
                                "nameAlias": "", 
                                "rn": "sharedServiceAlloc", 
                                "childAction": "deleteNonPresent"
                            }, 
                            "children": [
                                {
                                    "vzCreatedBy": {
                                        "attributes": {
                                            "lcOwn": "local", 
                                            "status": "", 
                                            "name": "", 
                                            "nameAlias": "", 
                                            "hasGraph": "no", 
                                            "ownerDn": "uni/tn-kuber/brc-kuber-global-icmp/dirass/prov-[uni/tn-kuber/cloudapp-ul2/cloudepg-vm-pingers]-any-no", 
                                            "priorityOverride": "default", 
                                            "directives": "", 
                                            "crType": "", 
                                            "modTs": "2020-04-11T20:08:09.550+00:00", 
                                            "action": "permit", 
                                            "scope": "context", 
                                            "rn": "by-[uni/tn-kuber/brc-kuber-global-icmp/dirass/prov-[uni/tn-kuber/cloudapp-ul2/cloudepg-vm-pingers]-any-no]", 
                                            "childAction": "deleteNonPresent"
                                        }
                                    }
                                }
                            ]
                        }
                    }, 
                    {
                        "fvRsProv": {
                            "attributes": {
                                "stateQual": "none", 
                                "uid": "15374", 
                                "prio": "unspecified", 
                                "extMngdBy": "", 
                                "forceResolve": "yes", 
                                "userdom": ":all:", 
                                "tType": "name", 
                                "matchT": "AtleastOne", 
                                "tDn": "uni/tn-kuber/brc-kuber-global-icmp", 
                                "rType": "mo", 
                                "ctrctUpd": "ctrct", 
                                "state": "formed", 
                                "tContextDn": "", 
                                "modTs": "2020-04-11T20:08:09.576+00:00", 
                                "rn": "rsprov-kuber-global-icmp", 
                                "updateCollection": "no", 
                                "monPolDn": "uni/tn-common/monepg-default", 
                                "status": "", 
                                "tRn": "brc-kuber-global-icmp", 
                                "triggerSt": "triggerable", 
                                "intent": "install", 
                                "annotation": "", 
                                "childAction": "", 
                                "lcOwn": "local", 
                                "tnVzBrCPName": "kuber-global-icmp", 
                                "tCl": "vzBrCP"
                            }, 
                            "children": [
                                {
                                    "fvCollectionCont": {
                                        "attributes": {
                                            "lcOwn": "local", 
                                            "status": "", 
                                            "name": "", 
                                            "nameAlias": "", 
                                            "monPolDn": "uni/tn-common/monepg-default", 
                                            "modTs": "2020-04-11T20:08:09.484+00:00", 
                                            "collectionDn": "uni/tn-kuber/brc-kuber-global-icmp", 
                                            "rn": "collectionDn-[uni/tn-kuber/brc-kuber-global-icmp]", 
                                            "childAction": "deleteNonPresent"
                                        }
                                    }
                                }
                            ]
                        }
                    }, 
                    {
                        "fvRsCustQosPol": {
                            "attributes": {
                                "lcOwn": "local", 
                                "status": "", 
                                "tRn": "qoscustom-default", 
                                "stateQual": "default-target", 
                                "tDn": "uni/tn-common/qoscustom-default", 
                                "tnQosCustomPolName": "", 
                                "extMngdBy": "", 
                                "rType": "mo", 
                                "tCl": "qosCustomPol", 
                                "tContextDn": "", 
                                "state": "formed", 
                                "forceResolve": "yes", 
                                "userdom": "all", 
                                "monPolDn": "uni/tn-common/monepg-default", 
                                "modTs": "2020-04-11T20:04:48.773+00:00", 
                                "uid": "0", 
                                "tType": "name", 
                                "rn": "rscustQosPol", 
                                "annotation": "", 
                                "childAction": ""
                            }
                        }
                    }, 
                    {
                        "cloudRsCloudEPgCtx": {
                            "attributes": {
                                "lcOwn": "local", 
                                "status": "", 
                                "tRn": "ctx-kUL2", 
                                "stateQual": "none", 
                                "tDn": "uni/tn-kuber/ctx-kUL2", 
                                "extMngdBy": "", 
                                "rType": "mo", 
                                "tCl": "fvCtx", 
                                "tnFvCtxName": "kUL2", 
                                "tContextDn": "", 
                                "state": "formed", 
                                "forceResolve": "yes", 
                                "userdom": "all", 
                                "monPolDn": "uni/tn-common/monepg-default", 
                                "modTs": "2020-04-11T20:04:48.773+00:00", 
                                "uid": "0", 
                                "tType": "name", 
                                "rn": "rsCloudEPgCtx", 
                                "annotation": "", 
                                "childAction": ""
                            }
                        }
                    }, 
                    {
                        "cloudEPSelector": {
                            "attributes": {
                                "lcOwn": "local", 
                                "status": "", 
                                "matchExpression": "IP=='51.1.1.0/24'", 
                                "matchClass": "cloudAAEPg", 
                                "name": "pingSel", 
                                "descr": "", 
                                "extMngdBy": "", 
                                "accessPrivilege": "USER", 
                                "props": "", 
                                "expressionHash": "9449972573502754972", 
                                "ownerKey": "", 
                                "subnet": "0.0.0.0", 
                                "userdom": ":all:", 
                                "modTs": "2020-04-11T20:04:48.773+00:00", 
                                "ownerTag": "", 
                                "uid": "15374", 
                                "nameAlias": "", 
                                "rn": "epselector-pingSel", 
                                "matchScope": "uni/tn-kuber/cloudapp-ul2/cloudepg-vm-pingers", 
                                "annotation": "", 
                                "childAction": ""
                            }
                        }
                    }
                ]
            }
        }
    ], 
    "totalCount": "1"
}`,
		`/api/mo/uni/tn-kuber/cloudapp-ul2/cloudepg-vm-tcp6020ers.json?rsp-subtree=full`: `{
    "imdata": [
        {
            "cloudEPg": {
                "attributes": {
                    "status": "", 
                    "uid": "15374", 
                    "prio": "unspecified", 
                    "extMngdBy": "", 
                    "userdom": ":all:", 
                    "matchT": "AtleastOne", 
                    "descr": "", 
                    "prefGrMemb": "exclude", 
                    "monPolDn": "uni/tn-common/monepg-default", 
                    "modTs": "2020-04-11T20:10:24.833+00:00", 
                    "scope": "2424832", 
                    "dn": "uni/tn-kuber/cloudapp-ul2/cloudepg-vm-tcp6020ers", 
                    "nameAlias": "", 
                    "accessPrivilege": "USER", 
                    "configIssues": "", 
                    "configSt": "applied", 
                    "isSharedSrvMsiteEPg": "no", 
                    "triggerSt": "triggerable", 
                    "txId": "10376293541462227092", 
                    "annotation": "", 
                    "childAction": "", 
                    "lcOwn": "local", 
                    "name": "vm-tcp6020ers", 
                    "pcTag": "5474", 
                    "exceptionTag": "", 
                    "floodOnEncap": "disabled"
                }, 
                "children": [
                    {
                        "fvSharedService": {
                            "attributes": {
                                "lcOwn": "local", 
                                "status": "", 
                                "name": "", 
                                "modTs": "2020-04-11T20:10:24.817+00:00", 
                                "monPolDn": "uni/tn-common/monepg-default", 
                                "nameAlias": "", 
                                "rn": "sharedServiceAlloc", 
                                "childAction": "deleteNonPresent"
                            }, 
                            "children": [
                                {
                                    "vzCreatedBy": {
                                        "attributes": {
                                            "lcOwn": "local", 
                                            "status": "", 
                                            "name": "", 
                                            "nameAlias": "", 
                                            "hasGraph": "no", 
                                            "ownerDn": "uni/tn-kuber/brc-kuber-global-tcp6020/dirass/prov-[uni/tn-kuber/cloudapp-ul2/cloudepg-vm-tcp6020ers]-any-no", 
                                            "priorityOverride": "default", 
                                            "directives": "", 
                                            "crType": "", 
                                            "modTs": "2020-04-11T20:10:24.817+00:00", 
                                            "action": "permit", 
                                            "scope": "context", 
                                            "rn": "by-[uni/tn-kuber/brc-kuber-global-tcp6020/dirass/prov-[uni/tn-kuber/cloudapp-ul2/cloudepg-vm-tcp6020ers]-any-no]", 
                                            "childAction": "deleteNonPresent"
                                        }
                                    }
                                }
                            ]
                        }
                    }, 
                    {
                        "fvRsProv": {
                            "attributes": {
                                "stateQual": "none", 
                                "uid": "15374", 
                                "prio": "unspecified", 
                                "extMngdBy": "", 
                                "forceResolve": "yes", 
                                "userdom": ":all:", 
                                "tType": "name", 
                                "matchT": "AtleastOne", 
                                "tDn": "uni/tn-kuber/brc-kuber-global-tcp6020", 
                                "rType": "mo", 
                                "ctrctUpd": "ctrct", 
                                "state": "formed", 
                                "tContextDn": "", 
                                "modTs": "2020-04-11T20:10:24.833+00:00", 
                                "rn": "rsprov-kuber-global-tcp6020", 
                                "updateCollection": "no", 
                                "monPolDn": "uni/tn-common/monepg-default", 
                                "status": "", 
                                "tRn": "brc-kuber-global-tcp6020", 
                                "triggerSt": "triggerable", 
                                "intent": "install", 
                                "annotation": "", 
                                "childAction": "", 
                                "lcOwn": "local", 
                                "tnVzBrCPName": "kuber-global-tcp6020", 
                                "tCl": "vzBrCP"
                            }, 
                            "children": [
                                {
                                    "fvCollectionCont": {
                                        "attributes": {
                                            "lcOwn": "local", 
                                            "status": "", 
                                            "name": "", 
                                            "nameAlias": "", 
                                            "monPolDn": "uni/tn-common/monepg-default", 
                                            "modTs": "2020-04-11T20:10:24.784+00:00", 
                                            "collectionDn": "uni/tn-kuber/brc-kuber-global-tcp6020", 
                                            "rn": "collectionDn-[uni/tn-kuber/brc-kuber-global-tcp6020]", 
                                            "childAction": "deleteNonPresent"
                                        }
                                    }
                                }
                            ]
                        }
                    }, 
                    {
                        "fvRsCustQosPol": {
                            "attributes": {
                                "lcOwn": "local", 
                                "status": "", 
                                "tRn": "qoscustom-default", 
                                "stateQual": "default-target", 
                                "tDn": "uni/tn-common/qoscustom-default", 
                                "tnQosCustomPolName": "", 
                                "extMngdBy": "", 
                                "rType": "mo", 
                                "tCl": "qosCustomPol", 
                                "tContextDn": "", 
                                "state": "formed", 
                                "forceResolve": "yes", 
                                "userdom": "all", 
                                "monPolDn": "uni/tn-common/monepg-default", 
                                "modTs": "2020-04-11T20:05:46.588+00:00", 
                                "uid": "0", 
                                "tType": "name", 
                                "rn": "rscustQosPol", 
                                "annotation": "", 
                                "childAction": ""
                            }
                        }
                    }, 
                    {
                        "cloudRsCloudEPgCtx": {
                            "attributes": {
                                "lcOwn": "local", 
                                "status": "", 
                                "tRn": "ctx-kUL2", 
                                "stateQual": "none", 
                                "tDn": "uni/tn-kuber/ctx-kUL2", 
                                "extMngdBy": "", 
                                "rType": "mo", 
                                "tCl": "fvCtx", 
                                "tnFvCtxName": "kUL2", 
                                "tContextDn": "", 
                                "state": "formed", 
                                "forceResolve": "yes", 
                                "userdom": "all", 
                                "monPolDn": "uni/tn-common/monepg-default", 
                                "modTs": "2020-04-11T20:05:46.588+00:00", 
                                "uid": "0", 
                                "tType": "name", 
                                "rn": "rsCloudEPgCtx", 
                                "annotation": "", 
                                "childAction": ""
                            }
                        }
                    }, 
                    {
                        "cloudEPSelector": {
                            "attributes": {
                                "lcOwn": "local", 
                                "status": "", 
                                "matchExpression": "IP=='51.1.2.0/24'", 
                                "matchClass": "cloudAAEPg", 
                                "name": "tcpSel", 
                                "descr": "", 
                                "extMngdBy": "", 
                                "accessPrivilege": "USER", 
                                "props": "", 
                                "expressionHash": "14488062191700160651", 
                                "ownerKey": "", 
                                "subnet": "0.0.0.0", 
                                "userdom": ":all:", 
                                "modTs": "2020-04-11T20:05:46.588+00:00", 
                                "ownerTag": "", 
                                "uid": "15374", 
                                "nameAlias": "", 
                                "rn": "epselector-tcpSel", 
                                "matchScope": "uni/tn-kuber/cloudapp-ul2/cloudepg-vm-tcp6020ers", 
                                "annotation": "", 
                                "childAction": ""
                            }
                        }
                    }
                ]
            }
        }
    ], 
    "totalCount": "1"
}`,
	}
	resp := resps[r.URL.RequestURI()]
	w.Write([]byte(resp))
}

func TestEPSync(t *testing.T) {
	var l_epg_uris = []string{
		"uni/tn-kuber/cloudapp-cluster1/cloudepg-aci-containers-default",
		"uni/tn-kuber/cloudapp-cluster1/cloudepg-aci-containers-nodes",
		"uni/tn-kuber/cloudapp-cluster1/cloudepg-aci-containers-system",
		"uni/tn-kuber/cloudapp-cluster1/cloudepg-epg-a",
		"uni/tn-kuber/cloudapp-cluster1/cloudepg-epg-b",
	}

	var exp_contracts = []string{
		"uni/tn-kuber/brc-c-tcp6020",
		"uni/tn-kuber/brc-cluster1_allow-kube",
		"uni/tn-kuber/brc-icmp-allow",
		"uni/tn-kuber/brc-kuber-global-icmp",
		"uni/tn-kuber/brc-kuber-global-tcp6020",
	}

	var exp_r_epgs = []string{
		"uni/tn-kuber/cloudapp-ul2/cloudepg-vm-pingers",
		"uni/tn-kuber/cloudapp-ul2/cloudepg-vm-tcp6020ers",
	}

	var exp_subnets = map[string]bool{
		"51.1.1.0/24": true,
		"51.1.2.0/24": true,
	}

	ts := &eps_suite{}
	ts.setup()
	ts.fakeApic.mux.HandleFunc(fmt.Sprintf("/api/mo/uni/tn-%s/ctx-%s.json", epsTenant, epsVrf), fvRtCloudEPgCtxHandler)
	for _, epg_uri := range l_epg_uris {
		ts.fakeApic.mux.HandleFunc(fmt.Sprintf("/api/mo/%s.json", epg_uri), cloudEPgHandler)
	}
	for _, c_uri := range exp_contracts {
		ts.fakeApic.mux.HandleFunc(fmt.Sprintf("/api/mo/%s.json", c_uri), vzBrCPHandler)
	}
	for _, r_epg := range exp_r_epgs {
		ts.fakeApic.mux.HandleFunc(fmt.Sprintf("/api/mo/%s.json", r_epg), cEpgFetchHandler)
	}

	l_epgs := ts.eps.getLocalEPGs()
	assert.Equal(t, len(l_epgs), len(l_epg_uris), "number of epgs on overlay vrf")
	for _, epg_uri := range l_epg_uris {
		assert.True(t, l_epgs[epg_uri], "epgdn match")
	}

	cons := ts.eps.getContracts(l_epgs)
	assert.Equal(t, len(exp_contracts), len(cons), "number of contracts")
	for _, c := range exp_contracts {
		assert.True(t, cons[c], "contractdn match")
	}
	r_epgs := ts.eps.getRemoteEPGs(cons, l_epgs)
	ts.eps.log.Infof("r_epgs: %+v", r_epgs)
	assert.Equal(t, len(r_epgs), len(exp_r_epgs), "number of remote epgs")
	for _, e := range exp_r_epgs {
		assert.True(t, r_epgs[e], "remote_epgdn match")
	}

	ts.eps.syncRemoteEPGs(r_epgs)
	crdList, err := ts.eps.crdClient.PodIFs("kube-system").List(metav1.ListOptions{})
	assert.Nil(t, err, "reading podifs")
	assert.Equal(t, len(crdList.Items), len(exp_subnets), "number of rem podifs")
	for _, p := range crdList.Items {
		assert.True(t, exp_subnets[p.Status.IPAddr], "remote_podif match")
	}
}
