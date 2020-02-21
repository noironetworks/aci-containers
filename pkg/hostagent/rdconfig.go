// Copyright 2019 Cisco Systems, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRATIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// creates snat crs.

package hostagent

import (
	"encoding/json"
	rdConfig "github.com/noironetworks/aci-containers/pkg/rdconfig/apis/aci.snat/v1"
	rdConClSet "github.com/noironetworks/aci-containers/pkg/rdconfig/clientset/versioned"
	"io/ioutil"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
	"k8s.io/kubernetes/pkg/controller"
	"os"
	"path/filepath"
	"reflect"
)

type opflexRdConfig struct {
	InternalSubnets   []string `json:"internal-subnets",omitempty"`
	DomainPolicySpace string   `json:"domain-policy-space",omitempty"`
	DomainName        string   `json:"domain-name",omitempty"`
}

func (agent *HostAgent) initRdConfigInformerFromClient(
	rdConClient *rdConClSet.Clientset) {
	agent.initRdConfigInformerBase(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				return rdConClient.AciV1().RdConfigs(metav1.NamespaceAll).List(options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				return rdConClient.AciV1().RdConfigs(metav1.NamespaceAll).Watch(options)
			},
		})
}

func (agent *HostAgent) initRdConfigInformerBase(listWatch *cache.ListWatch) {
	agent.rdConfigInformer = cache.NewSharedIndexInformer(
		listWatch,
		&rdConfig.RdConfig{},
		controller.NoResyncPeriodFunc(),
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	agent.rdConfigInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			agent.rdConfigUpdate(obj)
		},
		UpdateFunc: func(_ interface{}, obj interface{}) {
			agent.rdConfigUpdate(obj)
		},
		DeleteFunc: func(obj interface{}) {
			agent.rdConfigDelete(obj)
		},
	})
	agent.log.Info("Initializing RdConfig Informers")
}

func (agent *HostAgent) rdConfigUpdate(obj interface{}) {
	agent.indexMutex.Lock()
	defer agent.indexMutex.Unlock()
	rdCon := obj.(*rdConfig.RdConfig)
	agent.log.Info("RdConfig  Added: ", rdCon)
	var intsubnets []string
	intsubnets = append(intsubnets, rdCon.Spec.UserSubnets...)
	intsubnets = append(intsubnets, rdCon.Spec.DiscoveredSubnets...)
	agent.log.Info("intsubnets: ", intsubnets)
	opflexRdConfig := &opflexRdConfig{
		InternalSubnets:   intsubnets,
		DomainPolicySpace: agent.config.AciVrfTenant,
		DomainName:        agent.config.AciVrf,
	}
	if !reflect.DeepEqual(agent.rdConfig, opflexRdConfig) {
		agent.rdConfig = opflexRdConfig
		agent.log.Info("synrdConfig: ", opflexRdConfig)
		agent.scheduleSyncRdConfig()
	}
}

func (agent *HostAgent) rdConfigDelete(obj interface{}) {
	agent.indexMutex.Lock()
	defer agent.indexMutex.Unlock()
	rdCon := obj.(*rdConfig.RdConfig)
	agent.log.Info("RdConfig  Deleted: ", rdCon.ObjectMeta.Name)
	agent.rdConfig = &opflexRdConfig{}
	agent.scheduleSyncRdConfig()
}

func writeRdFile(rdfile string, rdconfig *opflexRdConfig) error {
	newdata, err := json.MarshalIndent(rdconfig, "", "  ")
	if err != nil {
		return err
	}
	existingdata, err := ioutil.ReadFile(rdfile)
	if err == nil && reflect.DeepEqual(existingdata, newdata) {
		return nil
	}
	err = ioutil.WriteFile(rdfile, newdata, 0644)
	return err
}

func (agent *HostAgent) FormRdFilePath() string {
	return filepath.Join(agent.config.OpFlexEndpointDir, agent.config.AciVrf+".rdconfig")
}

func (agent *HostAgent) syncRdConfig() bool {
	if !agent.syncEnabled {
		return false
	}
	rdfile := agent.FormRdFilePath()
	if !reflect.DeepEqual(*agent.rdConfig, opflexRdConfig{}) {
		err := writeRdFile(rdfile, agent.rdConfig)
		if err != nil {
			agent.log.Error("Error writing Rd file:", err)
			return true

		}
	} else {
		os.Remove(rdfile)
	}
	return false
}
