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

// Handlers for outofbandpolicy updates.

package hostagent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"

	oobv1 "github.com/noironetworks/aci-containers/pkg/oobpolicy/apis/aci.oob/v1"
	oobpolicyclientset "github.com/noironetworks/aci-containers/pkg/oobpolicy/clientset/versioned"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
	"k8s.io/kubernetes/pkg/controller"
)

func (agent *HostAgent) initOOBPolicyInformerFromClient(
	oobPolicyClient *oobpolicyclientset.Clientset) {
	agent.initOOBPolicyInformerBase(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				return oobPolicyClient.AciV1().OutOfBandPolicies(metav1.NamespaceAll).List(context.TODO(), options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				return oobPolicyClient.AciV1().OutOfBandPolicies(metav1.NamespaceAll).Watch(context.TODO(), options)
			},
		})
}

func (agent *HostAgent) initOOBPolicyInformerBase(listWatch *cache.ListWatch) {
	agent.oobPolicyInformer = cache.NewSharedIndexInformer(
		listWatch,
		&oobv1.OutOfBandPolicy{},
		controller.NoResyncPeriodFunc(),
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	agent.oobPolicyInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			agent.oobPolicyAdded(obj)
		},
		UpdateFunc: func(oldobj interface{}, newobj interface{}) {
			agent.oobPolicyUpdate(oldobj, newobj)
		},
		DeleteFunc: func(obj interface{}) {
			agent.oobPolicyDelete(obj)
		},
	})
}

type oobData struct {
	TunnelEpAdvertisementInterval uint64 `json:"tunnel-ep-advertisement-interval"`
}

func (agent *HostAgent) oobPolicyAdded(obj interface{}) {
	policy := obj.(*oobv1.OutOfBandPolicy)
	agent.log.Infof("OutOfBandPolicy added: %s", policy.Name)
	agent.updateOOBPolicy(policy)
}

func (agent *HostAgent) oobPolicyUpdate(oldobj interface{}, newobj interface{}) {
	oldpolicy := oldobj.(*oobv1.OutOfBandPolicy)
	newpolicy := newobj.(*oobv1.OutOfBandPolicy)
	agent.log.Infof("OutOfBandPolicy updated: %s", newpolicy.Name)
	if oldpolicy.Spec.TunnelEpAdvertisementInterval == newpolicy.Spec.TunnelEpAdvertisementInterval &&
		oldpolicy.Spec.VmmEpgDeploymentImmediacy == newpolicy.Spec.VmmEpgDeploymentImmediacy {
		agent.log.Infof("OutOfBandPolicy update: No change in policy")
		return
	}
	agent.updateOOBPolicy(newpolicy)
}

func (agent *HostAgent) oobPolicyDelete(obj interface{}) {
	agent.oobPolicyMutex.Lock()
	defer agent.oobPolicyMutex.Unlock()
	policy := obj.(*oobv1.OutOfBandPolicy)
	agent.log.Infof("OutOfBandPolicy deleted: %s", policy.Name)
	agent.deleteOOBPolicy()
}

func (agent *HostAgent) updateOOBPolicy(policy *oobv1.OutOfBandPolicy) {
	agent.oobPolicyMutex.Lock()
	defer agent.oobPolicyMutex.Unlock()

	tunnelEpAdvertisementInterval := policy.Spec.TunnelEpAdvertisementInterval
	vmmEpgDeploymentImmediacy := policy.Spec.VmmEpgDeploymentImmediacy

	if vmmEpgDeploymentImmediacy == oobv1.VmmEpgDeploymentImmediacyTypeImmediate {
		oobData := oobData{
			TunnelEpAdvertisementInterval: tunnelEpAdvertisementInterval,
		}
		filePath := filepath.Join(agent.config.OOBPolicyDir, "aci-containers-system.oob")
		agent.log.Infof("Updating OutOfBandPolicy file %s", filePath)
		err := agent.writeOOBPolicyFile(filePath, oobData)
		if err != nil {
			agent.log.Errorf("Failed to update OutOfBandPolicy file %s: %v", filePath, err)
		}
	} else {
		agent.deleteOOBPolicy()
	}
}

func (agent *HostAgent) deleteOOBPolicy() {
	filePath := filepath.Join(agent.config.OOBPolicyDir, "aci-containers-system.oob")
	agent.log.Infof("Deleting OutOfBandPolicy file %s", filePath)
	err := agent.deleteOOBPolicyFile(filePath)
	if err != nil {
		agent.log.Errorf("Failed to delete OutOfBandPolicy file %s: %v", filePath, err)
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
