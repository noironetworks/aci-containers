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

package stateinit

import (
	"fmt"
	"os"

	"github.com/sirupsen/logrus"

	"github.com/noironetworks/aci-containers/pkg/apicapi"
	"github.com/noironetworks/aci-containers/pkg/gbpserver"
	"github.com/noironetworks/aci-containers/pkg/gbpserver/watchers"
)

const (
	refreshTime = 0
)

var skipList = map[string]bool{
	"vmmInjectedClusterInfo": true,
}

func Run(cfg *gbpserver.GBPServerConfig) {
	if !isColdStart() {
		logrus.Infof("Not a cold start, skipping init")
		return
	}

	if len(cfg.Apic.Hosts) == 0 {
		return
	}

	cleanupInjected(cfg)
}

func cleanupInjected(cfg *gbpserver.GBPServerConfig) {
	apicConn := setupApicConn(cfg)

	vmmDomain := cfg.AciVmmDomain
	inj_path := fmt.Sprintf("/api/node/mo/comp/prov-Kubernetes/ctrlr-[%s]-%s/injcont.json", vmmDomain, vmmDomain)
	query := fmt.Sprintf("%s?query-target=children&rsp-prop-include=naming-only", inj_path)
	objList := DnsFromQry(apicConn, query)
	logrus.Debugf("%d objects to delete", len(objList))
	for _, dn := range objList {
		err := apicConn.DeleteDnInline(dn)
		if err != nil {
			panic(err)
		}
	}
}

func DnsFromQry(conn *apicapi.ApicConnection, q string) []string {
	var result []string
	resp, err := conn.GetApicResponse(q)
	if err != nil {
		panic(err)
	}

	logrus.Infof("Query: %s", q)
	logrus.Infof("Resp: %+v", resp)

	for _, obj := range resp.Imdata {
		if skipObj(obj) {
			continue
		}

		dn := obj.GetAttrStr("dn")
		if dn != "" {
			result = append(result, dn)
		}
	}
	return result
}

func skipObj(obj apicapi.ApicObject) bool {
	for key := range obj {
		if skipList[key] {
			logrus.Infof("Skipping %s", key)
			return true
		}
	}

	return false
}

func setupApicConn(cfg *gbpserver.GBPServerConfig) *apicapi.ApicConnection {
	var privKey []byte
	var apicCert []byte
	var err error

	level, err := logrus.ParseLevel(cfg.WatchLogLevel)
	if err != nil {
		panic(err.Error())
	}
	logger := logrus.New()
	logger.Level = level

	if cfg.Apic.PrivateKeyPath != "" {
		privKey, err = os.ReadFile(cfg.Apic.PrivateKeyPath)
		if err != nil {
			panic(err)
		}
	}
	if cfg.Apic.CertPath != "" {
		apicCert, err = os.ReadFile(cfg.Apic.CertPath)
		if err != nil {
			panic(err)
		}
	}

	conn, err := apicapi.New(logger, cfg.Apic.Hosts, cfg.Apic.Username, cfg.Apic.Username,
		privKey, apicCert, "k8s", refreshTime, 5, 5, cfg.AciVrfTenant)
	if err != nil {
		panic(err)
	}

	return conn
}

func isColdStart() bool {
	stateDriver := &watchers.K8sStateDriver{}
	exists, err := stateDriver.StateExists()
	if err != nil {
		panic(fmt.Sprintf("Cannot determine state: %v", err))
	}

	return !exists
}
