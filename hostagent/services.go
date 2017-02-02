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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	v1 "k8s.io/client-go/pkg/api/v1"
	"k8s.io/client-go/tools/cache"

	"k8s.io/kubernetes/pkg/controller"
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

func (agent *hostAgent) initEndpointsInformer() {
	agent.endpointsInformer = cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				return agent.kubeClient.Core().Endpoints(metav1.NamespaceAll).List(options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				return agent.kubeClient.Core().Endpoints(metav1.NamespaceAll).Watch(options)
			},
		},
		&v1.Endpoints{},
		controller.NoResyncPeriodFunc(),
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	agent.endpointsInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			agent.endpointsChanged(obj)
		},
		UpdateFunc: func(_ interface{}, obj interface{}) {
			agent.endpointsChanged(obj)
		},
		DeleteFunc: func(obj interface{}) {
			agent.endpointsChanged(obj)
		},
	})

	go agent.endpointsInformer.GetController().Run(wait.NeverStop)
	go agent.endpointsInformer.Run(wait.NeverStop)
}

func (agent *hostAgent) initServiceInformer() {
	agent.serviceInformer = cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				return agent.kubeClient.Core().Services(metav1.NamespaceAll).List(options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				return agent.kubeClient.Core().Services(metav1.NamespaceAll).Watch(options)
			},
		},
		&v1.Service{},
		controller.NoResyncPeriodFunc(),
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	agent.serviceInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			agent.serviceChanged(obj)
		},
		UpdateFunc: func(_ interface{}, obj interface{}) {
			agent.serviceChanged(obj)
		},
		DeleteFunc: func(obj interface{}) {
			agent.serviceDeleted(obj)
		},
	})

	go agent.serviceInformer.GetController().Run(wait.NeverStop)
	go agent.serviceInformer.Run(wait.NeverStop)
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

func serviceLogger(as *v1.Service) *logrus.Entry {
	return log.WithFields(logrus.Fields{
		"namespace": as.ObjectMeta.Namespace,
		"name":      as.ObjectMeta.Name,
		"type":      as.Spec.Type,
	})
}

func opflexServiceLogger(as *opflexService) *logrus.Entry {
	return log.WithFields(logrus.Fields{
		"namespace": as.Attributes["namespace"],
		"name":      as.Attributes["name"],
		"uuid":      as.Uuid,
		"tenant":    as.DomainPolicySpace,
		"vrf":       as.DomainName,
	})
}

func (agent *hostAgent) syncServices() {
	if !agent.syncEnabled {
		return
	}

	log.Debug("Syncing services")

	files, err := ioutil.ReadDir(agent.config.OpFlexServiceDir)
	if err != nil {
		log.WithFields(
			logrus.Fields{"serviceDir": agent.config.OpFlexServiceDir},
		).Error("Could not read directory " + err.Error())
		return
	}
	seen := make(map[string]bool)
	for _, f := range files {
		if !strings.HasSuffix(f.Name(), ".as") &&
			!strings.HasSuffix(f.Name(), ".service") {
			continue
		}

		asfile := filepath.Join(agent.config.OpFlexServiceDir, f.Name())
		logger := log.WithFields(
			logrus.Fields{"asfile": asfile},
		)
		as, err := getAs(asfile)
		if err != nil {
			logger.Error("Error reading AS file: " + err.Error())
			os.Remove(asfile)
		} else {
			existing, ok := agent.opflexServices[as.Uuid]
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

	for _, as := range agent.opflexServices {
		if seen[as.Uuid] {
			continue
		}

		opflexServiceLogger(as).Info("Adding service")
		writeAs(filepath.Join(agent.config.OpFlexServiceDir, as.Uuid+".service"), as)
	}

	log.Debug("Finished service sync")
}

func (agent *hostAgent) updateServiceDesc(external bool, as *v1.Service,
	endpoints *v1.Endpoints) bool {
	ofas := &opflexService{
		Uuid:              string(as.ObjectMeta.UID),
		DomainPolicySpace: agent.config.AciVrfTenant,
		DomainName:        agent.config.AciVrf,
		ServiceMode:       "loadbalancer",
		ServiceMappings:   make([]opflexServiceMapping, 0),
	}

	if external {
		if agent.config.ServiceIface == "" ||
			agent.serviceEp.Ipv4 == nil ||
			agent.serviceEp.Mac == "" {
			return false
		}

		ofas.InterfaceName = agent.config.ServiceIface
		ofas.InterfaceVlan = uint16(agent.config.ServiceIfaceVlan)
		ofas.ServiceMac = agent.serviceEp.Mac
		ofas.InterfaceIp = agent.serviceEp.Ipv4.String()
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
						(a.NodeName != nil && *a.NodeName == agent.config.NodeName) {
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
	ofas.Attributes["namespace"] = as.ObjectMeta.Namespace
	ofas.Attributes["name"] = as.ObjectMeta.Name
	ofas.Attributes["service-name"] = id

	existing, ok := agent.opflexServices[ofas.Uuid]
	if hasValidMapping {
		if (ok && !reflect.DeepEqual(existing, ofas)) || !ok {
			agent.opflexServices[ofas.Uuid] = ofas
			return true
		}
	} else {
		if ok {
			delete(agent.opflexServices, ofas.Uuid)
			return true
		}
	}

	return false
}

func (agent *hostAgent) doUpdateService(key string) {
	endpointsobj, exists, err :=
		agent.endpointsInformer.GetStore().GetByKey(key)
	if err != nil {
		log.Error("Could not lookup endpoints for " +
			key + ": " + err.Error())
		return
	}
	if !exists || endpointsobj == nil {
		return
	}
	asobj, exists, err := agent.serviceInformer.GetStore().GetByKey(key)
	if err != nil {
		log.Error("Could not lookup service for " +
			key + ": " + err.Error())
		return
	}
	if !exists || asobj == nil {
		return
	}

	endpoints := endpointsobj.(*v1.Endpoints)
	as := asobj.(*v1.Service)

	doSync := false
	doSync = agent.updateServiceDesc(false, as, endpoints) || doSync
	doSync = agent.updateServiceDesc(true, as, endpoints) || doSync
	if doSync {
		agent.syncServices()
	}
}

func (agent *hostAgent) endpointsChanged(obj interface{}) {
	agent.indexMutex.Lock()
	defer agent.indexMutex.Unlock()

	endpoints := obj.(*v1.Endpoints)

	key, err := cache.MetaNamespaceKeyFunc(endpoints)
	if err != nil {
		log.Error("Could not create key:" + err.Error())
		return
	}
	agent.doUpdateService(key)
}

func (agent *hostAgent) serviceChanged(obj interface{}) {
	agent.indexMutex.Lock()
	defer agent.indexMutex.Unlock()

	as := obj.(*v1.Service)

	key, err := cache.MetaNamespaceKeyFunc(as)
	if err != nil {
		serviceLogger(as).Error("Could not create key:" + err.Error())
		return
	}

	agent.doUpdateService(key)
}

func (agent *hostAgent) serviceDeleted(obj interface{}) {
	agent.indexMutex.Lock()
	defer agent.indexMutex.Unlock()

	as := obj.(*v1.Service)

	u := string(as.ObjectMeta.UID)
	if _, ok := agent.opflexServices[u]; ok {
		delete(agent.opflexServices, u)
		agent.syncServices()
	}
}

func (agent *hostAgent) updateAllServices() {
	agent.indexMutex.Lock()
	defer agent.indexMutex.Unlock()

	if agent.serviceInformer == nil {
		return
	}
	store := agent.serviceInformer.GetStore()
	if store == nil {
		return
	}
	keys := agent.serviceInformer.GetStore().ListKeys()
	if keys == nil {
		return
	}

	for _, key := range keys {
		agent.doUpdateService(key)
	}
}
