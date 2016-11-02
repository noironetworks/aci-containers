// Copyright 2016 Cisco Systems, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/Sirupsen/logrus"

	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/client/cache"
)

type opflexServiceMapping struct {
	ServiceIp    string `json:"service-ip"`
	ServiceProto string `json:"service-proto,omitempty"`
	ServicePort  uint16 `json:"service-port,omitempty"`

	NextHopIps  []string `json:"next-hop-ips,omitempty"`
	NextHopPort uint16   `json:"next-hop-port,omitempty"`
}

type opflexService struct {
	Uuid string `json:"uuid"`

	DomainPolicySpace string `json:"domain-policy-space,omitempty"`
	DomainName        string `json:"domain-name,omitempty"`

	ServiceMappings []opflexServiceMapping `json:"service-mapping,omitempty"`
}

func getAs(asfile string) (*opflexService, error) {
	data := &opflexService{}

	raw, err := ioutil.ReadFile(asfile)
	if err != nil {
		return data, err
	}
	err = json.Unmarshal(raw, data)
	return data, err
}

func writeAs(asfile string, as *opflexService) error {
	datacont, err := json.MarshalIndent(as, "", "  ")
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(asfile, datacont, 0644)
	if err != nil {
		log.WithFields(
			logrus.Fields{"asfile": asfile, "uuid": as.Uuid},
		).Error("Error writing service file: " + err.Error())
	}
	return err
}

func serviceLogger(as *api.Service) *logrus.Entry {
	return log.WithFields(logrus.Fields{
		"namespace": as.ObjectMeta.Namespace,
		"name":      as.ObjectMeta.Name,
		"type":      as.Spec.Type,
	})
}

func opflexServiceLogger(as *opflexService) *logrus.Entry {
	return log.WithFields(logrus.Fields{
		"Uuid":   as.Uuid,
		"tenant": as.DomainPolicySpace,
		"vrf":    as.DomainName,
	})
}

func syncServices() {
	if !syncEnabled {
		return
	}

	files, err := ioutil.ReadDir(*serviceDir)
	if err != nil {
		log.WithFields(
			logrus.Fields{"serviceDir": serviceDir},
		).Error("Could not read directory " + err.Error())
		return
	}
	seen := make(map[string]bool)
	for _, f := range files {
		if !strings.HasSuffix(f.Name(), ".as") {
			continue
		}

		asfile := filepath.Join(*serviceDir, f.Name())
		logger := log.WithFields(
			logrus.Fields{"asfile": asfile},
		)
		as, err := getAs(asfile)
		if err != nil {
			logger.Error("Error reading AS file: " + err.Error())
			os.Remove(asfile)
		} else {
			existing, ok := opflexServices[as.Uuid]
			if ok {
				if !reflect.DeepEqual(existing, as) {
					opflexServiceLogger(as).Info("Updating service")
					writeAs(asfile, existing)
				}
				seen[as.Uuid] = true
			} else {
				opflexServiceLogger(as).Info("Removing service")
				os.Remove(asfile)
			}
		}
	}

	for _, as := range opflexServices {
		if seen[as.Uuid] {
			continue
		}

		opflexServiceLogger(as).Info("Adding service")
		writeAs(filepath.Join(*serviceDir, as.Uuid+".as"), as)
	}
}

func endpointsUpdated(_ interface{}, obj interface{}) {
	endpointsChanged(obj)
}

func doUpdateService(key string) {
	endpointsobj, exists, err := endpointsInformer.GetStore().GetByKey(key)
	if err != nil {
		log.Error("Could not retrieve endpoints for " +
			key + ": " + err.Error())
		return
	}
	if !exists || endpointsobj == nil {
		return
	}
	asobj, exists, err := serviceInformer.GetStore().GetByKey(key)
	if err != nil {
		log.Error("Could not retrieve service for " +
			key + ": " + err.Error())
		return
	}
	if !exists || asobj == nil {
		return
	}

	endpoints := endpointsobj.(*api.Endpoints)
	as := asobj.(*api.Service)

	ofas := &opflexService{
		Uuid:              string(as.ObjectMeta.UID),
		DomainPolicySpace: *vrfTenant,
		DomainName:        *vrf,
		ServiceMappings:   make([]opflexServiceMapping, 0),
	}

	for _, sp := range as.Spec.Ports {
		for _, e := range endpoints.Subsets {
			for _, p := range e.Ports {
				if p.Protocol != sp.Protocol {
					continue
				}

				sm := &opflexServiceMapping{
					ServiceIp:    as.Spec.ClusterIP,
					ServicePort:  uint16(sp.Port),
					ServiceProto: strings.ToLower(string(sp.Protocol)),
					NextHopIps:   make([]string, 0),
					NextHopPort:  uint16(p.Port),
				}
				for _, a := range e.Addresses {
					sm.NextHopIps = append(sm.NextHopIps, a.IP)
				}
				ofas.ServiceMappings = append(ofas.ServiceMappings, *sm)
			}
		}
	}

	existing, ok := opflexServices[ofas.Uuid]
	if (ok && !reflect.DeepEqual(existing, ofas)) || !ok {
		opflexServices[ofas.Uuid] = ofas
		syncServices()
	}
}

func endpointsChanged(obj interface{}) {
	indexMutex.Lock()
	defer indexMutex.Unlock()

	endpoints := obj.(*api.Endpoints)

	key, err := cache.MetaNamespaceKeyFunc(endpoints)
	if err != nil {
		log.Error("Could not create key:" + err.Error())
		return
	}
	doUpdateService(key)
}

func serviceUpdated(_ interface{}, obj interface{}) {
	serviceAdded(obj)
}

func serviceAdded(obj interface{}) {
	indexMutex.Lock()
	defer indexMutex.Unlock()

	as := obj.(*api.Service)

	key, err := cache.MetaNamespaceKeyFunc(as)
	if err != nil {
		serviceLogger(as).Error("Could not create key:" + err.Error())
		return
	}

	doUpdateService(key)
}

func serviceDeleted(obj interface{}) {
	indexMutex.Lock()
	defer indexMutex.Unlock()

	as := obj.(*api.Service)

	u := string(as.ObjectMeta.UID)
	if _, ok := opflexServices[u]; ok {
		delete(opflexServices, u)
		syncServices()
	}
}
