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
	staticFabNetAttCRDName = "staticfabricnetworkattachments.aci.fabricattachment"
)

func (cont *AciController) queueStaticFabNetAttByKey(key string) {
	cont.staticFabNetAttQueue.Add(key)
}

func (cont *AciController) staticFabNetAttChanged(obj interface{}) {

	staticFabNetAtt, ok := obj.(*fabattv1.StaticFabricNetworkAttachment)
	if !ok {
		cont.log.Error("staticFabNetAttChanged: Bad object type")
		return
	}
	key, err := cache.MetaNamespaceKeyFunc(staticFabNetAtt)
	if err != nil {
		return
	}
	cont.queueStaticFabNetAttByKey(key)
}

func (cont *AciController) staticFabNetAttDeleted(obj interface{}) {

	staticFabNetAtt, ok := obj.(*fabattv1.StaticFabricNetworkAttachment)
	if !ok {
		deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			cont.log.Errorf("Received unexpected object: ")
			return
		}
		staticFabNetAtt, ok = deletedState.Obj.(*fabattv1.StaticFabricNetworkAttachment)
		if !ok {
			cont.log.Errorf("DeletedFinalStateUnknown contained non-staticfabricnetworkattachment object: %v", deletedState.Obj)
			return
		}
	}

	key, err := cache.MetaNamespaceKeyFunc(staticFabNetAtt)
	if err != nil {
		return
	}
	cont.queueStaticFabNetAttByKey("DELETED_" + key)
}

func (cont *AciController) initStaticFabNetAttInformerBase(listWatch *cache.ListWatch) {

	cont.staticFabNetAttInformer = cache.NewSharedIndexInformer(
		listWatch, &fabattv1.StaticFabricNetworkAttachment{}, controller.NoResyncPeriodFunc(),
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	cont.staticFabNetAttInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			cont.staticFabNetAttChanged(obj)
		},
		UpdateFunc: func(_ interface{}, newobj interface{}) {
			cont.staticFabNetAttChanged(newobj)
		},
		DeleteFunc: func(obj interface{}) {
			cont.staticFabNetAttDeleted(obj)
		},
	})
}

func (cont *AciController) initStaticFabNetAttInformerFromClient(fabAttClient *fabattclset.Clientset) {
	cont.initStaticFabNetAttInformerBase(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				return fabAttClient.AciV1().StaticFabricNetworkAttachments(metav1.NamespaceAll).List(context.TODO(), options)
			},

			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				return fabAttClient.AciV1().StaticFabricNetworkAttachments(metav1.NamespaceAll).Watch(context.TODO(), options)
			},
		})
}

func staticFabNetAttInit(cont *AciController, stopCh <-chan struct{}) {
	cont.log.Debug("Initializing staticfabricnetworkattachment client")
	restconfig := cont.env.RESTConfig()
	fabNetAttClient, err := fabattclset.NewForConfig(restconfig)
	if err != nil {
		cont.log.Errorf("Failed to intialize staticfabricnetworkattachment client")
		return
	}
	cont.initStaticFabNetAttInformerFromClient(fabNetAttClient)
	go cont.staticFabNetAttInformer.Run(stopCh)
	go cont.processQueue(cont.staticFabNetAttQueue, cont.staticFabNetAttInformer.GetIndexer(),
		func(obj interface{}) bool {
			return cont.handleStaticFabricNetworkAttachmentUpdate(obj)
		}, func(key string) bool {
			return cont.handleStaticFabricNetworkAttachmentDelete(key)
		}, nil, stopCh)
	cache.WaitForCacheSync(stopCh, cont.staticFabNetAttInformer.HasSynced)
}

func (cont *AciController) updateSfnaVlanMap(sfna *fabattv1.StaticFabricNetworkAttachment) {
	cont.sharedEncapSfnaVlanMap = make(map[int]map[string]bool)
	for _, vlanRef := range sfna.Spec.VlanRefs {
		vlans, _, err := cont.parseNodeFabNetAttVlanList(vlanRef.Vlans)
		if err != nil {
			continue
		}
		for _, vlan := range vlans {
			if _, ok := cont.sharedEncapSfnaVlanMap[vlan]; !ok {
				cont.sharedEncapSfnaVlanMap[vlan] = make(map[string]bool)
			}
			for _, aep := range vlanRef.Aeps {
				cont.sharedEncapSfnaVlanMap[vlan][aep] = true
			}
		}
	}
}

func (cont *AciController) updateSfnaLabelMap(sfna *fabattv1.StaticFabricNetworkAttachment) {
	cont.sharedEncapSfnaLabelMap = make(map[string]map[string]bool)
	for _, nadVlanRef := range sfna.Spec.NADVlanRefs {
		if _, ok := cont.sharedEncapSfnaLabelMap[nadVlanRef.NadVlanLabel]; !ok {
			cont.sharedEncapSfnaLabelMap[nadVlanRef.NadVlanLabel] = make(map[string]bool)
		} else {
			cont.log.Errorf("Label %s has more than 1 mapping", nadVlanRef.NadVlanLabel)
		}
		for _, aep := range nadVlanRef.Aeps {
			cont.sharedEncapSfnaLabelMap[nadVlanRef.NadVlanLabel][aep] = true
		}
	}
}

func (cont *AciController) updateSfnaCombinedCache() (affectedVlans []int) {
	var combinedAttVlanMap map[int]map[string]bool
	cont.indexMutex.Lock()
	combinedAttVlanMap = make(map[int]map[string]bool)
	for vlan, AepMap := range cont.sharedEncapSfnaVlanMap {
		combinedAttVlanMap[vlan] = make(map[string]bool)
		for aep := range AepMap {
			combinedAttVlanMap[vlan][aep] = true
		}
	}
	for label, AepMap := range cont.sharedEncapSfnaLabelMap {
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
		if _, ok := cont.sharedEncapSfnaCache[vlan]; !ok {
			cont.sharedEncapSfnaCache[vlan] = combinedAttVlanMap[vlan]
			affectedVlans = append(affectedVlans, vlan)
		} else if !reflect.DeepEqual(cont.sharedEncapSfnaCache[vlan], combinedAttVlanMap[vlan]) {
			cont.sharedEncapSfnaCache[vlan] = combinedAttVlanMap[vlan]
			affectedVlans = append(affectedVlans, vlan)
		}
	}
	// Delete old mapping
	for vlan := range cont.sharedEncapSfnaCache {
		if _, ok := combinedAttVlanMap[vlan]; !ok {
			delete(cont.sharedEncapSfnaCache, vlan)
			affectedVlans = append(affectedVlans, vlan)
		}
	}

	cont.indexMutex.Unlock()

	return affectedVlans
}

func (cont *AciController) handleStaticFabricNetworkAttachmentUpdate(obj interface{}) bool {
	progMap := make(map[string]apicapi.ApicSlice)
	staticFabNetAtt, ok := obj.(*fabattv1.StaticFabricNetworkAttachment)
	if !ok {
		cont.log.Error("handleStaticFabricNetworkAttUpdate: Bad object type")
		return false
	}
	cont.log.Info("staticFabricNetworkAttachment update: ")
	cont.updateSfnaVlanMap(staticFabNetAtt)
	cont.updateSfnaLabelMap(staticFabNetAtt)
	affectedVlans := cont.updateSfnaCombinedCache()
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

func (cont *AciController) handleStaticFabricNetworkAttachmentDelete(key string) bool {
	cont.log.Infof("staticFabricNetworkAttachment delete: %s", key)
	progMap := make(map[string]apicapi.ApicSlice)
	var affectedVlans []int
	cont.indexMutex.Lock()
	cont.sharedEncapSfnaVlanMap = nil
	cont.sharedEncapSfnaLabelMap = nil
	// Delete old mapping
	for vlan := range cont.sharedEncapSfnaCache {
		affectedVlans = append(affectedVlans, vlan)
	}
	cont.sharedEncapSfnaCache = make(map[int]map[string]bool)
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
