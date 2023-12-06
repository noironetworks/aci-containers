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

package controller

import (
	fabattv1 "github.com/noironetworks/aci-containers/pkg/fabricattachment/apis/aci.fabricattachment/v1"
	fabattclset "github.com/noironetworks/aci-containers/pkg/fabricattachment/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	"reflect"

	"context"
	"github.com/noironetworks/aci-containers/pkg/apicapi"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/kubernetes/pkg/controller"
)

const (
	netFabConfigCRDName = "networkfabricconfigurations.aci.fabricattachment"
)

func (cont *AciController) queueFabNetConfigByKey(key string) {
	cont.netFabConfigQueue.Add(key)
}

func (cont *AciController) netFabConfigChanged(obj interface{}) {

	netFabConfig, ok := obj.(*fabattv1.NetworkFabricConfiguration)
	if !ok {
		cont.log.Error("netFabConfigChanged: Bad object type")
		return
	}
	key, err := cache.MetaNamespaceKeyFunc(netFabConfig)
	if err != nil {
		return
	}
	cont.queueFabNetConfigByKey(key)
}

func (cont *AciController) netFabConfigDeleted(obj interface{}) {

	netFabConfig, ok := obj.(*fabattv1.NetworkFabricConfiguration)
	if !ok {
		deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			cont.log.Errorf("Received unexpected object: ")
			return
		}
		netFabConfig, ok = deletedState.Obj.(*fabattv1.NetworkFabricConfiguration)
		if !ok {
			cont.log.Errorf("DeletedFinalStateUnknown contained non-networkfabricconfiguration object: %v", deletedState.Obj)
			return
		}
	}

	key, err := cache.MetaNamespaceKeyFunc(netFabConfig)
	if err != nil {
		return
	}
	cont.queueFabNetConfigByKey("DELETED_" + key)
}

func (cont *AciController) initFabNetConfigInformerBase(listWatch *cache.ListWatch) {

	cont.netFabConfigInformer = cache.NewSharedIndexInformer(
		listWatch, &fabattv1.NetworkFabricConfiguration{}, controller.NoResyncPeriodFunc(),
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	cont.netFabConfigInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			cont.netFabConfigChanged(obj)
		},
		UpdateFunc: func(_ interface{}, newobj interface{}) {
			cont.netFabConfigChanged(newobj)
		},
		DeleteFunc: func(obj interface{}) {
			cont.netFabConfigDeleted(obj)
		},
	})
}

func (cont *AciController) initFabNetConfigInformerFromClient(fabAttClient *fabattclset.Clientset) {
	cont.initFabNetConfigInformerBase(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				return fabAttClient.AciV1().NetworkFabricConfigurations(metav1.NamespaceAll).List(context.TODO(), options)
			},

			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				return fabAttClient.AciV1().NetworkFabricConfigurations(metav1.NamespaceAll).Watch(context.TODO(), options)
			},
		})
}

func netFabConfigInit(cont *AciController, stopCh <-chan struct{}) {
	cont.log.Debug("Initializing networkfabricconfiguration client")
	restconfig := cont.env.RESTConfig()
	fabNetAttClient, err := fabattclset.NewForConfig(restconfig)
	if err != nil {
		cont.log.Errorf("Failed to intialize networkfabricconfiguration client")
		return
	}
	cont.initFabNetConfigInformerFromClient(fabNetAttClient)
	go cont.netFabConfigInformer.Run(stopCh)
	go cont.processQueue(cont.netFabConfigQueue, cont.netFabConfigInformer.GetIndexer(),
		func(obj interface{}) bool {
			return cont.handleNetworkFabricConfigurationUpdate(obj)
		}, func(key string) bool {
			return cont.handleNetworkFabricConfigurationDelete(key)
		}, nil, stopCh)
	cache.WaitForCacheSync(stopCh, cont.netFabConfigInformer.HasSynced)
}

func (cont *AciController) updateNfcVlanMap(sfna *fabattv1.NetworkFabricConfiguration) {
	cont.sharedEncapNfcVlanMap = make(map[int]map[string]bool)
	for _, vlanRef := range sfna.Spec.VlanRefs {
		vlans, _, err := cont.parseNodeFabNetAttVlanList(vlanRef.Vlans)
		if err != nil {
			continue
		}
		for _, vlan := range vlans {
			if _, ok := cont.sharedEncapNfcVlanMap[vlan]; !ok {
				cont.sharedEncapNfcVlanMap[vlan] = make(map[string]bool)
			}
			for _, aep := range vlanRef.Aeps {
				cont.sharedEncapNfcVlanMap[vlan][aep] = true
			}
		}
	}
}

func (cont *AciController) updateNfcLabelMap(sfna *fabattv1.NetworkFabricConfiguration) {
	cont.sharedEncapNfcLabelMap = make(map[string]map[string]bool)
	for _, nadVlanRef := range sfna.Spec.NADVlanRefs {
		if _, ok := cont.sharedEncapNfcLabelMap[nadVlanRef.NadVlanLabel]; !ok {
			cont.sharedEncapNfcLabelMap[nadVlanRef.NadVlanLabel] = make(map[string]bool)
		} else {
			cont.log.Errorf("Label %s has more than 1 mapping", nadVlanRef.NadVlanLabel)
		}
		for _, aep := range nadVlanRef.Aeps {
			cont.sharedEncapNfcLabelMap[nadVlanRef.NadVlanLabel][aep] = true
		}
	}
}

func (cont *AciController) updateNfcCombinedCache() (affectedVlans []int) {
	var combinedAttVlanMap map[int]map[string]bool
	cont.indexMutex.Lock()
	combinedAttVlanMap = make(map[int]map[string]bool)
	for vlan, AepMap := range cont.sharedEncapNfcVlanMap {
		combinedAttVlanMap[vlan] = make(map[string]bool)
		for aep := range AepMap {
			combinedAttVlanMap[vlan][aep] = true
		}
	}
	for label, AepMap := range cont.sharedEncapNfcLabelMap {
		vlans, ok := cont.sharedEncapLabelMap[label]
		if !ok {
			continue
		}
		for _, vlan := range vlans {
			if _, ok := combinedAttVlanMap[vlan]; !ok {
				combinedAttVlanMap[vlan] = make(map[string]bool)
			}
			for aep := range AepMap {
				combinedAttVlanMap[vlan][aep] = true
			}
		}
	}
	// Add/update mapping
	for vlan := range combinedAttVlanMap {
		if _, ok := cont.sharedEncapNfcCache[vlan]; !ok {
			cont.sharedEncapNfcCache[vlan] = combinedAttVlanMap[vlan]
			affectedVlans = append(affectedVlans, vlan)
		} else if !reflect.DeepEqual(cont.sharedEncapNfcCache[vlan], combinedAttVlanMap[vlan]) {
			cont.sharedEncapNfcCache[vlan] = combinedAttVlanMap[vlan]
			affectedVlans = append(affectedVlans, vlan)
		}
	}
	// Delete old mapping
	for vlan := range cont.sharedEncapNfcCache {
		if _, ok := combinedAttVlanMap[vlan]; !ok {
			delete(cont.sharedEncapNfcCache, vlan)
			affectedVlans = append(affectedVlans, vlan)
		}
	}

	cont.indexMutex.Unlock()

	return affectedVlans
}

func (cont *AciController) handleNetworkFabricConfigurationUpdate(obj interface{}) bool {
	progMap := make(map[string]apicapi.ApicSlice)
	netFabConfig, ok := obj.(*fabattv1.NetworkFabricConfiguration)
	if !ok {
		cont.log.Error("handleNetworkFabricConfigUpdate: Bad object type")
		return false
	}
	cont.log.Info("networkFabricConfiguration update: ")
	cont.updateNfcVlanMap(netFabConfig)
	cont.updateNfcLabelMap(netFabConfig)
	affectedVlans := cont.updateNfcCombinedCache()
	cont.updateNodeFabNetAttStaticAttachments(affectedVlans, progMap)
	for labelKey, apicSlice := range progMap {
		if apicSlice == nil {
			cont.apicConn.ClearApicObjects(labelKey)
			continue
		}
		cont.apicConn.WriteApicObjects(labelKey, apicSlice)
	}
	return false
}

func (cont *AciController) handleNetworkFabricConfigurationDelete(key string) bool {
	cont.log.Infof("networkFabricConfiguration delete: %s", key)
	progMap := make(map[string]apicapi.ApicSlice)
	var affectedVlans []int
	cont.indexMutex.Lock()
	cont.sharedEncapNfcVlanMap = nil
	cont.sharedEncapNfcLabelMap = nil
	// Delete old mapping
	for vlan := range cont.sharedEncapNfcCache {
		affectedVlans = append(affectedVlans, vlan)
	}
	cont.sharedEncapNfcCache = make(map[int]map[string]bool)
	cont.indexMutex.Unlock()
	cont.updateNodeFabNetAttStaticAttachments(affectedVlans, progMap)
	for labelKey, apicSlice := range progMap {
		if apicSlice == nil {
			cont.apicConn.ClearApicObjects(labelKey)
			continue
		}
		cont.apicConn.WriteApicObjects(labelKey, apicSlice)
	}
	return false
}
