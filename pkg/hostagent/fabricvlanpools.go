// Copyright 2023 Cisco Systems, Inc.
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
	"context"
	fabattv1 "github.com/noironetworks/aci-containers/pkg/fabricattachment/apis/aci.fabricattachment/v1"
	fabattclientset "github.com/noironetworks/aci-containers/pkg/fabricattachment/clientset/versioned"
	"github.com/noironetworks/aci-containers/pkg/util"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
	"k8s.io/kubernetes/pkg/controller"
)

//APIs

func (agent *HostAgent) getGlobalFabricVlanPool() (combinedStr string) {
	agent.indexMutex.Lock()
	defer agent.indexMutex.Unlock()
	for ns := range agent.fabricVlanPoolMap {
		vlanStr := agent.getFabricVlanPoolNamespaceLocked(ns)
		if len(vlanStr) == 0 {
			continue
		}
		if len(combinedStr) == 0 {
			combinedStr = vlanStr
			continue
		}
		combinedStr += "," + vlanStr
	}
	return combinedStr
}

func (agent *HostAgent) getFabricVlanPool(namespace string, locked bool) string {
	if !locked {
		agent.indexMutex.Lock()
		defer agent.indexMutex.Unlock()
	}
	if _, ok := agent.fabricVlanPoolMap[namespace]; ok {
		return agent.getFabricVlanPoolNamespaceLocked(namespace)
	}
	return agent.getFabricVlanPoolNamespaceLocked(fabNetAttDefNamespace)
}

// End APIs

func (agent *HostAgent) getFabricVlanPoolNamespaceLocked(namespace string) (combinedStr string) {
	if nsVlanPoolMap, ok := agent.fabricVlanPoolMap[namespace]; ok {
		for _, vlanStr := range nsVlanPoolMap {
			if len(vlanStr) == 0 {
				continue
			}
			if len(combinedStr) == 0 {
				combinedStr = vlanStr
				continue
			}
			combinedStr += "," + vlanStr
		}
	}
	return combinedStr
}

func (agent *HostAgent) initFabricVlanPoolsInformerFromClient(client *fabattclientset.Clientset) {
	agent.initFabricVlanPoolsInformerBase(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				return client.AciV1().FabricVlanPools(metav1.NamespaceAll).List(context.TODO(), options)
			},

			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				return client.AciV1().FabricVlanPools(metav1.NamespaceAll).Watch(context.TODO(), options)
			},
		})
}

func (agent *HostAgent) initFabricVlanPoolsInformerBase(listWatch *cache.ListWatch) {
	agent.fabricVlanPoolInformer = cache.NewSharedIndexInformer(
		listWatch, &fabattv1.FabricVlanPool{}, controller.NoResyncPeriodFunc(),
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	agent.fabricVlanPoolInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			agent.fabricVlanPoolAdded(obj)
		},
		UpdateFunc: func(oldobj interface{}, newobj interface{}) {
			agent.fabricVlanPoolUpdated(oldobj, newobj)
		},
		DeleteFunc: func(obj interface{}) {
			agent.fabricVlanPoolDeleted(obj)
		},
	})
}

func (agent *HostAgent) fabricVlanPoolChanged(fabricVlanPool *fabattv1.FabricVlanPool) {
	agent.indexMutex.Lock()
	defer agent.indexMutex.Unlock()
	nsVlanPoolMap, ok := agent.fabricVlanPoolMap[fabricVlanPool.Namespace]
	if !ok {
		agent.fabricVlanPoolMap[fabricVlanPool.Namespace] = make(map[string]string)
		nsVlanPoolMap = agent.fabricVlanPoolMap[fabricVlanPool.Namespace]
	}
	_, _, combinedStr, err := util.ParseVlanList(fabricVlanPool.Spec.Vlans)
	if err != nil {
		agent.log.Error(err)
	}
	nsVlanPoolMap[fabricVlanPool.Name] = combinedStr
	agent.fabricVlanPoolMap[fabricVlanPool.Namespace] = nsVlanPoolMap
	agent.updateNodeFabricNetworkAttachmentForFabricVlanPoolLocked()
}

func (agent *HostAgent) fabricVlanPoolAdded(obj interface{}) {
	fabricVlanPool, ok := obj.(*fabattv1.FabricVlanPool)
	if !ok {
		agent.log.Error("Non FabricVlanPool object")
		return
	}
	agent.log.Infof("fabricVlanPool %s/%s added", fabricVlanPool.Namespace, fabricVlanPool.Name)
	agent.fabricVlanPoolChanged(fabricVlanPool)

}

func (agent *HostAgent) fabricVlanPoolUpdated(oldObj interface{}, newObj interface{}) {
	fabricVlanPool, ok := newObj.(*fabattv1.FabricVlanPool)
	if !ok {
		agent.log.Error("Non FabricVlanPool object")
		return
	}
	agent.log.Infof("fabricVlanPool %s/%s updated", fabricVlanPool.Namespace, fabricVlanPool.Name)
	agent.fabricVlanPoolChanged(fabricVlanPool)
}

func (agent *HostAgent) fabricVlanPoolDeleted(obj interface{}) {
	fabricVlanPool, ok := obj.(*fabattv1.FabricVlanPool)
	if !ok {
		agent.log.Error("Non FabricVlanPool object")
		return
	}
	agent.log.Infof("fabricVlanPool %s/%s deleted", fabricVlanPool.Namespace, fabricVlanPool.Name)
	agent.indexMutex.Lock()
	defer agent.indexMutex.Unlock()
	nsVlanPoolMap, ok := agent.fabricVlanPoolMap[fabricVlanPool.Namespace]
	if ok {
		if _, ok = nsVlanPoolMap[fabricVlanPool.Name]; ok {
			delete(nsVlanPoolMap, fabricVlanPool.Name)
			agent.updateNodeFabricNetworkAttachmentForFabricVlanPoolLocked()
		}
		if len(nsVlanPoolMap) != 0 {
			agent.fabricVlanPoolMap[fabricVlanPool.Namespace] = nsVlanPoolMap
		} else {
			delete(agent.fabricVlanPoolMap, fabricVlanPool.Namespace)
		}
	}
}
