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
	"reflect"

	fabattv1 "github.com/noironetworks/aci-containers/pkg/fabricattachment/apis/aci.fabricattachment/v1"
	fabattclset "github.com/noironetworks/aci-containers/pkg/fabricattachment/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"

	"context"

	"github.com/noironetworks/aci-containers/pkg/apicapi"
	"github.com/noironetworks/aci-containers/pkg/util"
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
	cont.log.Info("NetworkFabricConfigurationChanged")
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

func (cont *AciController) updateNfcVlanMap(sfna *fabattv1.NetworkFabricConfiguration, progMap map[string]apicapi.ApicSlice) {
	cont.sharedEncapNfcVlanMap = make(map[int]*NfcData)
	currAppProfs := make(map[string]bool)
	for _, vlanRef := range sfna.Spec.VlanRefs {
		vlans, _, _, err := util.ParseVlanList([]string{vlanRef.Vlans})
		if err != nil {
			continue
		}
		for _, vlan := range vlans {
			if _, ok := cont.sharedEncapNfcVlanMap[vlan]; !ok {
				cont.sharedEncapNfcVlanMap[vlan] = &NfcData{
					Epg:  vlanRef.Epg,
					Aeps: make(map[string]bool),
				}
			}
			if vlanRef.Epg.ApplicationProfile != "" {
				appProfile := vlanRef.Epg.ApplicationProfile
				tenantName := cont.getNodeFabNetAttTenant(vlanRef.Epg.Tenant)
				appProfKey := "tenant_" + tenantName + "_" + appProfile
				currAppProfs[appProfKey] = true
			}
			for _, aep := range vlanRef.Aeps {
				cont.sharedEncapNfcVlanMap[vlan].Aeps[aep] = true
			}
		}
	}
	for appProfile := range cont.sharedEncapNfcAppProfileMap {
		if _, ok := currAppProfs[appProfile]; !ok {
			delete(cont.sharedEncapNfcAppProfileMap, appProfile)
			labelKey := cont.aciNameForKey("ap", appProfile)
			cont.log.Errorf("Deleting AP %s", appProfile)
			progMap[labelKey] = nil
		}
	}
}

func (cont *AciController) updateNfcLabelMap(sfna *fabattv1.NetworkFabricConfiguration) {
	cont.sharedEncapNfcLabelMap = make(map[string]*NfcData)
	for _, nadVlanRef := range sfna.Spec.NADVlanRefs {
		if _, ok := cont.sharedEncapNfcLabelMap[nadVlanRef.NadVlanLabel]; !ok {
			cont.sharedEncapNfcLabelMap[nadVlanRef.NadVlanLabel] = &NfcData{
				Aeps: make(map[string]bool),
			}
		} else {
			cont.log.Errorf("Label %s has more than 1 mapping", nadVlanRef.NadVlanLabel)
		}
		for _, aep := range nadVlanRef.Aeps {
			cont.sharedEncapNfcLabelMap[nadVlanRef.NadVlanLabel].Aeps[aep] = true
		}
	}
}

func (cont *AciController) updateNfcCombinedCache() (affectedVlans []int) {
	var combinedAttVlanMap map[int]*NfcData
	cont.indexMutex.Lock()
	combinedAttVlanMap = make(map[int]*NfcData)
	for vlan, nfcData := range cont.sharedEncapNfcVlanMap {
		combinedAttVlanMap[vlan] = nfcData
	}
	for label, nfcData := range cont.sharedEncapNfcLabelMap {
		vlans, ok := cont.sharedEncapLabelMap[label]
		if !ok {
			continue
		}
		for _, vlan := range vlans {
			// In case there is dual definition for the same vlan,
			// direct vlan mapping will prevail
			if _, ok := combinedAttVlanMap[vlan]; !ok {
				combinedAttVlanMap[vlan] = nfcData
			}
		}
	}
	// Add/update mapping
	for vlan := range combinedAttVlanMap {
		if _, ok := cont.sharedEncapNfcCache[vlan]; !ok {
			cont.sharedEncapNfcCache[vlan] = combinedAttVlanMap[vlan]
			affectedVlans = append(affectedVlans, vlan)
			cont.log.Infof("Added nfc data for vlan %d", vlan)
		} else if !reflect.DeepEqual(cont.sharedEncapNfcCache[vlan], combinedAttVlanMap[vlan]) {
			cont.sharedEncapNfcCache[vlan] = combinedAttVlanMap[vlan]
			affectedVlans = append(affectedVlans, vlan)
			cont.log.Infof("Updated nfc data for vlan %d", vlan)
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

func (cont *AciController) updateNetworkFabricConfigurationObj(obj interface{}) map[string]apicapi.ApicSlice {
	progMap := make(map[string]apicapi.ApicSlice)
	netFabConfig, ok := obj.(*fabattv1.NetworkFabricConfiguration)
	if !ok {
		cont.log.Error("handleNetworkFabricConfigUpdate: Bad object type")
		return progMap
	}
	cont.log.Info("networkFabricConfiguration update: ")
	cont.updateNfcVlanMap(netFabConfig, progMap)
	cont.updateNfcLabelMap(netFabConfig)
	affectedVlans := cont.updateNfcCombinedCache()
	cont.updateNodeFabNetAttStaticAttachments(affectedVlans, progMap)
	return progMap
}

func (cont *AciController) handleNetworkFabricConfigurationUpdate(obj interface{}) bool {
	progMap := cont.updateNetworkFabricConfigurationObj(obj)
	for labelKey, apicSlice := range progMap {
		if apicSlice == nil {
			cont.apicConn.ClearApicObjects(labelKey)
			continue
		}
		cont.apicConn.WriteApicObjects(labelKey, apicSlice)
	}
	return false
}

func (cont *AciController) deleteNetworkFabricConfigurationObj(key string) map[string]apicapi.ApicSlice {
	cont.log.Infof("networkFabricConfiguration delete: %s", key)
	progMap := make(map[string]apicapi.ApicSlice)
	var affectedVlans []int
	cont.indexMutex.Lock()
	for appProfile := range cont.sharedEncapNfcAppProfileMap {
		delete(cont.sharedEncapNfcAppProfileMap, appProfile)
		labelKey := cont.aciNameForKey("ap", appProfile)
		cont.log.Errorf("Deleting AP %s", appProfile)
		progMap[labelKey] = nil
	}
	cont.sharedEncapNfcVlanMap = nil
	cont.sharedEncapNfcLabelMap = nil
	// Delete old mapping
	for vlan := range cont.sharedEncapNfcCache {
		affectedVlans = append(affectedVlans, vlan)
	}
	cont.sharedEncapNfcCache = make(map[int]*NfcData)
	cont.indexMutex.Unlock()
	cont.updateNodeFabNetAttStaticAttachments(affectedVlans, progMap)
	return progMap
}

func (cont *AciController) handleNetworkFabricConfigurationDelete(key string) bool {
	progMap := cont.deleteNetworkFabricConfigurationObj(key)
	for labelKey, apicSlice := range progMap {
		if apicSlice == nil {
			cont.apicConn.ClearApicObjects(labelKey)
			continue
		}
		cont.apicConn.WriteApicObjects(labelKey, apicSlice)
	}
	return false
}

// Internal API - Only used in GlobalScopeVlan mode
func (cont *AciController) getSharedEncapNfcCacheEpgLocked(encap int) (nfcEpgTenant, nfcBd, nfcEpgAp, nfcEpg string, nfcEpgConsumers, nfcEpgProviders []string, discoveryType fabattv1.StaticPathMgmtType) {
	if nfcData, nfcExists := cont.sharedEncapNfcCache[encap]; nfcExists {
		nfcEpgTenant = nfcData.Epg.Tenant
		nfcEpgAp = ""
		if !(((nfcEpgTenant == "") || (nfcEpgTenant == cont.config.AciPolicyTenant)) && (nfcData.Epg.ApplicationProfile == "netop-"+cont.config.AciPrefix)) && !((nfcEpgTenant == "common") && (nfcData.Epg.ApplicationProfile == "netop-common")) {
			nfcEpgAp = nfcData.Epg.ApplicationProfile
		}
		nfcBd = nfcData.Epg.BD.Name
		nfcEpg = nfcData.Epg.Name
		nfcEpgConsumers = nfcData.Epg.Contracts.Consumer
		nfcEpgProviders = nfcData.Epg.Contracts.Provider
		discoveryType = nfcData.Epg.DiscoveryType
	} else {
		discoveryType = fabattv1.StaticPathMgmtTypeAll
	}
	return

}
func (cont *AciController) getSharedEncapNfcCacheBDLocked(encap int) (nfcBdTenant, nfcVrf, nfcBd string, nfcBdSubnets []string) {
	if nfcData, nfcExists := cont.sharedEncapNfcCache[encap]; nfcExists {
		nfcBdTenant = nfcData.Epg.Tenant
		if nfcData.Epg.BD.CommonTenant {
			nfcBdTenant = "common"
		}
		nfcBd = nfcData.Epg.BD.Name
		nfcVrf = nfcData.Epg.BD.Vrf.Name
		nfcBdSubnets = nfcData.Epg.BD.Subnets
	}
	return
}
