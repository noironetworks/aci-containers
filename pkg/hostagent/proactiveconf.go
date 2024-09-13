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

// Handlers for ProactiveConf CR updates.

package hostagent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"

	pcv1 "github.com/noironetworks/aci-containers/pkg/proactiveconf/apis/aci.pc/v1"
	proactiveconfclientset "github.com/noironetworks/aci-containers/pkg/proactiveconf/clientset/versioned"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
	"k8s.io/kubernetes/pkg/controller"
)

func (agent *HostAgent) initProactiveConfInformerFromClient(
	proactiveConfClient *proactiveconfclientset.Clientset) {
	agent.initProactiveConfInformerBase(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				return proactiveConfClient.AciV1().ProactiveConfs().List(context.TODO(), options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				return proactiveConfClient.AciV1().ProactiveConfs().Watch(context.TODO(), options)
			},
		})
}

func (agent *HostAgent) initProactiveConfInformerBase(listWatch *cache.ListWatch) {
	agent.proactiveConfInformer = cache.NewSharedIndexInformer(
		listWatch,
		&pcv1.ProactiveConf{},
		controller.NoResyncPeriodFunc(),
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	agent.proactiveConfInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			agent.proactiveConfAdded(obj)
		},
		UpdateFunc: func(oldobj interface{}, newobj interface{}) {
			agent.proactiveConfUpdate(oldobj, newobj)
		},
		DeleteFunc: func(obj interface{}) {
			agent.proactiveConfDelete(obj)
		},
	})
}

type oobData struct {
	TunnelEpAdvertisementInterval uint64 `json:"tunnel-ep-advertisement-interval"`
}

func (agent *HostAgent) proactiveConfAdded(obj interface{}) {
	policy := obj.(*pcv1.ProactiveConf)
	agent.log.Infof("ProactiveConf added: %s", policy.Name)
	agent.updateProactiveConf(policy)
}

func (agent *HostAgent) proactiveConfUpdate(oldobj interface{}, newobj interface{}) {
	oldpolicy := oldobj.(*pcv1.ProactiveConf)
	newpolicy := newobj.(*pcv1.ProactiveConf)
	agent.log.Infof("ProactiveConf updated: %s", newpolicy.Name)
	if oldpolicy.Spec.TunnelEpAdvertisementInterval == newpolicy.Spec.TunnelEpAdvertisementInterval &&
		oldpolicy.Spec.VmmEpgDeploymentImmediacy == newpolicy.Spec.VmmEpgDeploymentImmediacy {
		agent.log.Infof("ProactiveConf update: No change in policy")
		return
	}
	agent.updateProactiveConf(newpolicy)
}

func (agent *HostAgent) proactiveConfDelete(obj interface{}) {
	agent.proactiveConfMutex.Lock()
	defer agent.proactiveConfMutex.Unlock()
	policy := obj.(*pcv1.ProactiveConf)
	agent.log.Infof("ProactiveConf deleted: %s", policy.Name)
	agent.deleteProactiveConf()
}

func (agent *HostAgent) updateProactiveConf(policy *pcv1.ProactiveConf) {
	agent.proactiveConfMutex.Lock()
	defer agent.proactiveConfMutex.Unlock()

	tunnelEpAdvertisementInterval := policy.Spec.TunnelEpAdvertisementInterval
	vmmEpgDeploymentImmediacy := policy.Spec.VmmEpgDeploymentImmediacy

	if vmmEpgDeploymentImmediacy == pcv1.VmmEpgDeploymentImmediacyTypeImmediate {
		oobData := oobData{
			TunnelEpAdvertisementInterval: tunnelEpAdvertisementInterval,
		}
		filePath := filepath.Join(agent.config.OOBPolicyDir, "aci-containers-system.oob")
		agent.log.Infof("Updating ProactiveConf file %s", filePath)
		err := agent.writeOOBPolicyFile(filePath, oobData)
		if err != nil {
			agent.log.Errorf("Failed to update ProactiveConf file %s: %v", filePath, err)
		}
	} else {
		agent.deleteProactiveConf()
	}
}

func (agent *HostAgent) deleteProactiveConf() {
	filePath := filepath.Join(agent.config.OOBPolicyDir, "aci-containers-system.oob")
	agent.log.Infof("Deleting oob policy data file %s", filePath)
	err := agent.deleteOOBPolicyFile(filePath)
	if err != nil {
		agent.log.Errorf("Failed to delete oob policy data %s: %v", filePath, err)
	}
}

func (agent *HostAgent) writeOOBPolicyFile(filePath string, oobData oobData) error {
	oobJson, err := json.MarshalIndent(oobData, "", "  ")
	if err != nil {
		return err
	}
	err = os.WriteFile(filePath, oobJson, 0644)
	if err != nil {
		agent.log.Fatalf("Failed to write oob policy data to file: %v", err)
		return err
	} else {
		agent.log.Infof("File %s updated", filePath)
	}

	return nil

}

func (agent *HostAgent) deleteOOBPolicyFile(filePath string) error {
	err := os.Remove(filePath)
	if err != nil {
		agent.log.Fatalf("Failed to delete oob policy data file: %v", err)
		return err
	} else {
		agent.log.Infof("File %s deleted", filePath)
	}
	return nil
}
