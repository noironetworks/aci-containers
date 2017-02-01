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
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/Sirupsen/logrus"

	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/client/cache"
	clientset "k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset"
	"k8s.io/kubernetes/pkg/controller"
	"k8s.io/kubernetes/pkg/runtime"
	"k8s.io/kubernetes/pkg/util/wait"
	"k8s.io/kubernetes/pkg/watch"
)

type opflexServiceMapping struct {
	ServiceIp    string `json:"service-ip,omitempty"`
	ServiceProto string `json:"service-proto,omitempty"`
	ServicePort  uint16 `json:"service-port,omitempty"`

	NextHopIps  []string `json:"next-hop-ips"`
	NextHopPort uint16   `json:"next-hop-port,omitempty"`

	Conntrack bool `json:"conntrack-enabled"`
}

type opflexService struct {
	Uuid string `json:"uuid"`

	DomainPolicySpace string `json:"domain-policy-space,omitempty"`
	DomainName        string `json:"domain-name,omitempty"`

	ServiceMode   string `json:"service-mode,omitempty"`
	ServiceMac    string `json:"service-mac,omitempty"`
	InterfaceName string `json:"interface-name,omitempty"`
	InterfaceIp   string `json:"interface-ip,omitempty"`
	InterfaceVlan uint16 `json:"interface-vlan,omitempty"`

	ServiceMappings []opflexServiceMapping `json:"service-mapping"`

	Attributes map[string]string `json:"attributes,omitempty"`
}

func initEndpointsInformer(kubeClient *clientset.Clientset) {
	endpointsInformer = cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options api.ListOptions) (runtime.Object, error) {
				return kubeClient.Core().Endpoints(api.NamespaceAll).List(options)
			},
			WatchFunc: func(options api.ListOptions) (watch.Interface, error) {
				return kubeClient.Core().Endpoints(api.NamespaceAll).Watch(options)
			},
		},
		&api.Endpoints{},
		controller.NoResyncPeriodFunc(),
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	endpointsInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    endpointsChanged,
		UpdateFunc: endpointsUpdated,
		DeleteFunc: endpointsChanged,
	})

	go endpointsInformer.GetController().Run(wait.NeverStop)
	go endpointsInformer.Run(wait.NeverStop)
}

func initServiceInformer(kubeClient *clientset.Clientset) {
	serviceInformer = cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options api.ListOptions) (runtime.Object, error) {
				return kubeClient.Core().Services(api.NamespaceAll).List(options)
			},
			WatchFunc: func(options api.ListOptions) (watch.Interface, error) {
				return kubeClient.Core().Services(api.NamespaceAll).Watch(options)
			},
		},
		&api.Service{},
		controller.NoResyncPeriodFunc(),
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	serviceInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    serviceAdded,
		UpdateFunc: serviceUpdated,
		DeleteFunc: serviceDeleted,
	})

	go serviceInformer.GetController().Run(wait.NeverStop)
	go serviceInformer.Run(wait.NeverStop)
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

	log.Debug("Syncing services")

	files, err := ioutil.ReadDir(config.OpFlexServiceDir)
	if err != nil {
		log.WithFields(
			logrus.Fields{"serviceDir": config.OpFlexServiceDir},
		).Error("Could not read directory " + err.Error())
		return
	}
	seen := make(map[string]bool)
	for _, f := range files {
		if !strings.HasSuffix(f.Name(), ".as") &&
			!strings.HasSuffix(f.Name(), ".service") {
			continue
		}

		asfile := filepath.Join(config.OpFlexServiceDir, f.Name())
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
		writeAs(filepath.Join(config.OpFlexServiceDir, as.Uuid+".service"), as)
	}

	log.Debug("Finished service sync")
}

func endpointsUpdated(_ interface{}, obj interface{}) {
	endpointsChanged(obj)
}

func updateServiceDesc(external bool, as *api.Service, endpoints *api.Endpoints) bool {
	ofas := &opflexService{
		Uuid:              string(as.ObjectMeta.UID),
		DomainPolicySpace: config.AciVrfTenant,
		DomainName:        config.AciVrf,
		ServiceMode:       "loadbalancer",
		ServiceMappings:   make([]opflexServiceMapping, 0),
	}

	if external {
		if config.ServiceIface == "" ||
			serviceEp.Ipv4 == nil ||
			serviceEp.Mac == "" {
			return false
		}

		ofas.InterfaceName = config.ServiceIface
		ofas.InterfaceVlan = uint16(config.ServiceIfaceVlan)
		ofas.ServiceMac = serviceEp.Mac
		ofas.InterfaceIp = serviceEp.Ipv4.String()
		ofas.Uuid = ofas.Uuid + "-external"
	}

	hasValidMapping := false
	for _, sp := range as.Spec.Ports {
		for _, e := range endpoints.Subsets {
			for _, p := range e.Ports {
				if p.Protocol != sp.Protocol {
					continue
				}

				sm := &opflexServiceMapping{
					ServicePort:  uint16(sp.Port),
					ServiceProto: strings.ToLower(string(sp.Protocol)),
					NextHopIps:   make([]string, 0),
					NextHopPort:  uint16(p.Port),
					Conntrack:    true,
				}

				if external {
					sm.ServiceIp = as.Spec.LoadBalancerIP
				} else {
					sm.ServiceIp = as.Spec.ClusterIP
				}

				for _, a := range e.Addresses {
					if !external ||
						(a.NodeName != nil && *a.NodeName == config.NodeName) {
						sm.NextHopIps = append(sm.NextHopIps, a.IP)
					}
				}
				if sm.ServiceIp != "" && len(sm.NextHopIps) > 0 {
					hasValidMapping = true
				}
				ofas.ServiceMappings = append(ofas.ServiceMappings, *sm)
			}
		}
	}

	id := fmt.Sprintf("%s_%s", as.ObjectMeta.Namespace, as.ObjectMeta.Name)
	ofas.Attributes = as.ObjectMeta.Labels
	ofas.Attributes["service-name"] = id

	existing, ok := opflexServices[ofas.Uuid]
	if hasValidMapping {
		if (ok && !reflect.DeepEqual(existing, ofas)) || !ok {
			opflexServices[ofas.Uuid] = ofas
			return true
		}
	} else {
		if ok {
			delete(opflexServices, ofas.Uuid)
			return true
		}
	}

	return false
}

func doUpdateService(key string) {
	endpointsobj, exists, err := endpointsInformer.GetStore().GetByKey(key)
	if err != nil {
		log.Error("Could not lookup endpoints for " +
			key + ": " + err.Error())
		return
	}
	if !exists || endpointsobj == nil {
		return
	}
	asobj, exists, err := serviceInformer.GetStore().GetByKey(key)
	if err != nil {
		log.Error("Could not lookup service for " +
			key + ": " + err.Error())
		return
	}
	if !exists || asobj == nil {
		return
	}

	endpoints := endpointsobj.(*api.Endpoints)
	as := asobj.(*api.Service)

	doSync := false
	doSync = updateServiceDesc(false, as, endpoints) || doSync
	doSync = updateServiceDesc(true, as, endpoints) || doSync
	if doSync {
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

func updateAllServices() {
	indexMutex.Lock()
	defer indexMutex.Unlock()

	if serviceInformer == nil {
		return
	}
	store := serviceInformer.GetStore()
	if store == nil {
		return
	}
	keys := serviceInformer.GetStore().ListKeys()
	if keys == nil {
		return
	}

	for _, key := range keys {
		doUpdateService(key)
	}
}
