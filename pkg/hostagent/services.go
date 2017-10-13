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

package hostagent

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/Sirupsen/logrus"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
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

func (agent *HostAgent) initEndpointsInformerFromClient(
	kubeClient *kubernetes.Clientset) {
	agent.initEndpointsInformerBase(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				return kubeClient.Core().Endpoints(metav1.NamespaceAll).List(options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				return kubeClient.Core().Endpoints(metav1.NamespaceAll).Watch(options)
			},
		})
}

func (agent *HostAgent) initEndpointsInformerBase(listWatch *cache.ListWatch) {
	agent.endpointsInformer = cache.NewSharedIndexInformer(
		listWatch,
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
}

func (agent *HostAgent) initServiceInformerFromClient(
	kubeClient *kubernetes.Clientset) {
	agent.initServiceInformerBase(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				return kubeClient.Core().Services(metav1.NamespaceAll).List(options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				return kubeClient.Core().Services(metav1.NamespaceAll).Watch(options)
			},
		})
}

func (agent *HostAgent) initServiceInformerBase(listWatch *cache.ListWatch) {
	agent.serviceInformer = cache.NewSharedIndexInformer(
		listWatch,
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
}

func getAs(asfile string) (string, error) {
	raw, err := ioutil.ReadFile(asfile)
	if err != nil {
		return "", err
	}
	return string(raw), err
}

func writeAs(asfile string, as *opflexService) (bool, error) {
	newdata, err := json.MarshalIndent(as, "", "  ")
	if err != nil {
		return true, err
	}
	existingdata, err := ioutil.ReadFile(asfile)
	if err == nil && reflect.DeepEqual(existingdata, newdata) {
		return false, nil
	}

	err = ioutil.WriteFile(asfile, newdata, 0644)
	return true, err
}

func serviceLogger(log *logrus.Logger, as *v1.Service) *logrus.Entry {
	return log.WithFields(logrus.Fields{
		"namespace": as.ObjectMeta.Namespace,
		"name":      as.ObjectMeta.Name,
		"type":      as.Spec.Type,
	})
}

func opflexServiceLogger(log *logrus.Logger, as *opflexService) *logrus.Entry {
	return log.WithFields(logrus.Fields{
		"namespace": as.Attributes["namespace"],
		"name":      as.Attributes["name"],
		"uuid":      as.Uuid,
		"tenant":    as.DomainPolicySpace,
		"vrf":       as.DomainName,
	})
}

func (agent *HostAgent) syncServices() bool {
	if !agent.syncEnabled {
		return false
	}

	agent.log.Debug("Syncing services")
	agent.indexMutex.Lock()
	opflexServices := make(map[string]*opflexService)
	for k, v := range agent.opflexServices {
		opflexServices[k] = v
	}
	agent.indexMutex.Unlock()

	files, err := ioutil.ReadDir(agent.config.OpFlexServiceDir)
	if err != nil {
		agent.log.WithFields(
			logrus.Fields{"serviceDir": agent.config.OpFlexServiceDir},
		).Error("Could not read directory " + err.Error())
		return true
	}
	seen := make(map[string]bool)
	for _, f := range files {
		uuid := f.Name()
		if strings.HasSuffix(uuid, ".as") {
			uuid = uuid[:len(uuid)-3]
		} else if strings.HasSuffix(f.Name(), ".service") {
			uuid = uuid[:len(uuid)-8]
		} else {
			continue
		}

		asfile := filepath.Join(agent.config.OpFlexServiceDir, f.Name())
		logger := agent.log.WithFields(
			logrus.Fields{"Uuid": uuid},
		)

		existing, ok := opflexServices[uuid]
		if ok {
			wrote, err := writeAs(asfile, existing)
			if err != nil {
				opflexServiceLogger(agent.log, existing).
					Error("Error writing service file: ", err)
			} else if wrote {
				opflexServiceLogger(agent.log, existing).Info("Updated service")
			}
			seen[uuid] = true
		} else {
			logger.Info("Removing service")
			os.Remove(asfile)
		}
	}

	for _, as := range opflexServices {
		if seen[as.Uuid] {
			continue
		}

		opflexServiceLogger(agent.log, as).Info("Adding service")
		asfile :=
			filepath.Join(agent.config.OpFlexServiceDir, as.Uuid+".service")
		_, err = writeAs(asfile, as)
		if err != nil {
			opflexServiceLogger(agent.log, as).
				Error("Error writing service file: ", err)
		}
	}

	agent.log.Debug("Finished service sync")
	return false
}

// Must have index lock
func (agent *HostAgent) updateServiceDesc(external bool, as *v1.Service,
	endpoints *v1.Endpoints) bool {
	ofas := &opflexService{
		Uuid:              string(as.ObjectMeta.UID),
		DomainPolicySpace: agent.config.AciVrfTenant,
		DomainName:        agent.config.AciVrf,
		ServiceMode:       "loadbalancer",
		ServiceMappings:   make([]opflexServiceMapping, 0),
	}

	if external {
		if agent.config.UplinkIface == "" ||
			agent.serviceEp.Ipv4 == nil ||
			agent.serviceEp.Mac == "" {
			return false
		}

		ofas.InterfaceName = agent.config.UplinkIface
		ofas.InterfaceVlan = uint16(agent.config.ServiceVlan)
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
				if p.Name != sp.Name {
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
					if as.Spec.Type == v1.ServiceTypeLoadBalancer &&
						len(as.Status.LoadBalancer.Ingress) > 0 {
						sm.ServiceIp = as.Status.LoadBalancer.Ingress[0].IP
					}
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
	if ofas.Attributes == nil {
		ofas.Attributes = make(map[string]string)
	}
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

// must have index lock
func (agent *HostAgent) doUpdateService(key string) {
	endpointsobj, exists, err :=
		agent.endpointsInformer.GetStore().GetByKey(key)
	if err != nil {
		agent.log.Error("Could not lookup endpoints for " +
			key + ": " + err.Error())
		return
	}
	if !exists || endpointsobj == nil {
		return
	}
	asobj, exists, err := agent.serviceInformer.GetStore().GetByKey(key)
	if err != nil {
		agent.log.Error("Could not lookup service for " +
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
		agent.scheduleSyncServices()
	}
}

func (agent *HostAgent) endpointsChanged(obj interface{}) {
	agent.indexMutex.Lock()
	defer agent.indexMutex.Unlock()

	endpoints := obj.(*v1.Endpoints)

	key, err := cache.MetaNamespaceKeyFunc(endpoints)
	if err != nil {
		agent.log.Error("Could not create key:" + err.Error())
		return
	}
	agent.doUpdateService(key)
}

func (agent *HostAgent) serviceChanged(obj interface{}) {
	agent.indexMutex.Lock()
	defer agent.indexMutex.Unlock()

	as := obj.(*v1.Service)

	key, err := cache.MetaNamespaceKeyFunc(as)
	if err != nil {
		serviceLogger(agent.log, as).
			Error("Could not create key:" + err.Error())
		return
	}

	agent.doUpdateService(key)
}

func (agent *HostAgent) serviceDeleted(obj interface{}) {
	agent.indexMutex.Lock()
	defer agent.indexMutex.Unlock()

	as := obj.(*v1.Service)

	u := string(as.ObjectMeta.UID)
	if _, ok := agent.opflexServices[u]; ok {
		delete(agent.opflexServices, u)
		delete(agent.opflexServices, u+"-external")
		agent.scheduleSyncServices()
	}
}

func (agent *HostAgent) updateAllServices() {
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

	agent.indexMutex.Lock()
	defer agent.indexMutex.Unlock()
	for _, key := range keys {
		agent.doUpdateService(key)
	}
}
