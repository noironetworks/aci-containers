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

// Handlers for AaepMonitor CR updates.

package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	amv1 "github.com/noironetworks/aci-containers/pkg/aaepmonitor/apis/aci.attachmentmonitor/v1"
	aaepmonitorclientset "github.com/noironetworks/aci-containers/pkg/aaepmonitor/clientset/versioned"
	"github.com/noironetworks/aci-containers/pkg/apicapi"

	nadapi "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
	"k8s.io/kubernetes/pkg/controller"
)

const (
	aaepMonitorCRDName = "aaepmonitors.aci.attachmentmonitor"
)

func (cont *AciController) queueAaepMonitorConfigByKey(key string) {
	cont.aaepMonitorConfigQueue.Add(key)
}

func aaepMonitorInit(cont *AciController, stopCh <-chan struct{}) {
	restconfig := cont.env.RESTConfig()
	aaepMonitorClient, err := aaepmonitorclientset.NewForConfig(restconfig)
	if err != nil {
		cont.log.Errorf("Failed to intialize aaepMonitorClient")
		return
	}

	cont.initAaepMonitorInformerFromClient(aaepMonitorClient)
	go cont.aaepMonitorInformer.Run(stopCh)
	go cont.processQueue(cont.aaepMonitorConfigQueue, cont.aaepMonitorInformer.GetIndexer(),
		func(obj interface{}) bool {
			return cont.handleAaepMonitorConfigurationUpdate(obj)
		}, func(key string) bool {
			return cont.handleAaepMonitorConfigurationDelete(key)
		}, nil, stopCh)
	cache.WaitForCacheSync(stopCh, cont.aaepMonitorInformer.HasSynced)
}

func (cont *AciController) initAaepMonitorInformerFromClient(
	aaepMonitorClient *aaepmonitorclientset.Clientset) {
	cont.initAaepMonitorInformerBase(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				return aaepMonitorClient.AciV1().AaepMonitors().List(context.TODO(), options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				return aaepMonitorClient.AciV1().AaepMonitors().Watch(context.TODO(), options)
			},
		})
}

func (cont *AciController) initAaepMonitorInformerBase(listWatch *cache.ListWatch) {
	cont.aaepMonitorInformer = cache.NewSharedIndexInformer(
		listWatch,
		&amv1.AaepMonitor{},
		controller.NoResyncPeriodFunc(),
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	cont.aaepMonitorInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			cont.aaepMonitorConfAdded(obj)
		},
		UpdateFunc: func(oldobj interface{}, newobj interface{}) {
			cont.aaepMonitorConfUpdate(oldobj, newobj)
		},
		DeleteFunc: func(obj interface{}) {
			cont.aaepMonitorConfDelete(obj)
		},
	})
}

func (cont *AciController) aaepMonitorConfAdded(obj interface{}) {
	aaepMonitorConfig, ok := obj.(*amv1.AaepMonitor)
	if !ok {
		cont.log.Error("aaepMonitorConfAdded: Bad object type")
		return
	}
	key, err := cache.MetaNamespaceKeyFunc(aaepMonitorConfig)
	if err != nil {
		return
	}
	cont.queueAaepMonitorConfigByKey(key)
}

func (cont *AciController) aaepMonitorConfUpdate(oldobj interface{}, newobj interface{}) {
	newAaepMonitorConfig := newobj.(*amv1.AaepMonitor)

	key, err := cache.MetaNamespaceKeyFunc(newAaepMonitorConfig)
	if err != nil {
		return
	}
	cont.queueAaepMonitorConfigByKey(key)
}

func (cont *AciController) aaepMonitorConfDelete(obj interface{}) {
	cont.indexMutex.Lock()
	defer cont.indexMutex.Unlock()
	aaepMonitorConfig, ok := obj.(*amv1.AaepMonitor)

	if !ok {
		deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			cont.log.Errorf("Received unexpected object: ")
			return
		}
		aaepMonitorConfig, ok = deletedState.Obj.(*amv1.AaepMonitor)
		if !ok {
			cont.log.Errorf("DeletedFinalStateUnknown contained non-aaepmonitorconfiguration object: %v", deletedState.Obj)
			return
		}
	}

	key, err := cache.MetaNamespaceKeyFunc(aaepMonitorConfig)
	if err != nil {
		return
	}
	cont.queueAaepMonitorConfigByKey("DELETED_" + key)
}

func (cont *AciController) handleAaepMonitorConfigurationUpdate(obj interface{}) bool {
	aaepMonitorConfig, ok := obj.(*amv1.AaepMonitor)
	if !ok {
		cont.log.Error("handleAaepMonitorConfigurationUpdate: Bad object type")
		return false
	}

	cont.indexMutex.Lock()
	allEpgToSubscribe := make(map[string]bool)
	cont.log.Infof("Started processing of aaepmonitor CR creation/modification")
	addedAaeps, removedAaeps := cont.getAaepDiff(aaepMonitorConfig.Spec.Aaeps)
	for _, aaepName := range addedAaeps {
		epgsToSubscribe := cont.reconcileNadData(aaepName)
		for epgDn := range epgsToSubscribe {
			allEpgToSubscribe[epgDn] = true
		}
	}

	for _, aaepName := range removedAaeps {
		cont.cleanAnnotationSubscriptions(aaepName)

		aaepEpgAttachDataMap := cont.sharedAaepMonitor[aaepName]
		delete(cont.sharedAaepMonitor, aaepName)

		for epgDn, aaepEpgAttachData := range aaepEpgAttachDataMap {
			cont.deleteNetworkAttachmentDefinition(aaepName, epgDn, aaepEpgAttachData, "AaepRemovedFromCR")
		}
	}
	cont.indexMutex.Unlock()
	for epgDn := range allEpgToSubscribe {
		cont.subscribeSafely(epgDn)
	}
	cont.log.Infof("Completed processing of aaepmonitor CR creation/modification")
	return false
}

func (cont *AciController) handleAaepMonitorConfigurationDelete(key string) bool {
	cont.indexMutex.Lock()
	defer cont.indexMutex.Unlock()
	cont.log.Infof("Started processing of aaepmonitor CR deletion")
	for aaepName, aaepEpgAttachDataMap := range cont.sharedAaepMonitor {
		cont.cleanAnnotationSubscriptions(aaepName)

		for epgDn, aaepEpgAttachData := range aaepEpgAttachDataMap {
			cont.deleteNetworkAttachmentDefinition(aaepName, epgDn, aaepEpgAttachData, "CRDeleted")
		}
	}

	cont.sharedAaepMonitor = make(map[string]map[string]*AaepEpgAttachData)
	cont.log.Infof("Completed processing of aaepmonitor CR deletion")
	return false
}

func (cont *AciController) handleAaepEpgAttach(infraRsObj apicapi.ApicObject) {
	infraRsObjDn := infraRsObj.GetDn()
	aaepName := cont.matchesAEPFilter(infraRsObjDn)
	cont.log.Infof("Started processing of EPG: %s attached with AAEP: %s", infraRsObj.GetAttrStr("tDn"), aaepName)
	if aaepName == "" {
		cont.log.Debugf("Unable to find AAEP from %s in monitoring list", infraRsObjDn)
		return
	}

	state := infraRsObj.GetAttrStr("state")
	if state != "formed" {
		cont.indexMutex.Lock()
		cont.log.Debugf("Skipping NAD creation: %s is with state: %s", infraRsObjDn, state)
		cont.cleanStaleNADLocked(aaepName, infraRsObj.GetAttrStr("tDn"))
		cont.indexMutex.Unlock()
		return
	}

	epgDn := infraRsObj.GetAttrStr("tDn")
	encap := infraRsObj.GetAttrStr("encap")
	vlanID := cont.getVlanId(encap)

	if cont.checkDuplicateAaepEpgAttachRequest(aaepName, epgDn, vlanID) {
		cont.log.Infof("AAEP %s EPG %s attachment data already exists", aaepName, epgDn)
		return
	}

	cont.indexMutex.Lock()
	oldAaepMonitorData := cont.getAaepEpgAttachDataLocked(aaepName, epgDn)
	cont.indexMutex.Unlock()

	if cont.checkVlanUsedInCluster(vlanID) {
		// This is needed when user updates vlan to the vlan already used in cluster
		cont.handleOldNadDeletion(aaepName, epgDn, oldAaepMonitorData, "AaepEpgAttachedWithVlanInUse")
		cont.log.Errorf("Skipping NAD creation: VLAN %d is already used in cluster", vlanID)
		return
	}

	defer cont.subscribeSafely(epgDn)
	epgVlanMap := &EpgVlanMap{
		epgDn:     epgDn,
		encapVlan: vlanID,
	}

	aaepEpgAttachData := cont.collectNadData(epgVlanMap)
	if aaepEpgAttachData == nil {
		return
	}

	if cont.checkIfEpgWithOverlappingVlan(aaepName, vlanID, epgDn, false) {
		// This is needed when user updates vlan from non-overlapping to overlapping
		cont.handleOldNadDeletion(aaepName, epgDn, oldAaepMonitorData, "AaepEpgAttachedWithOverlappingVlan")

		// Add new entry with nadCreated as false
		cont.indexMutex.Lock()
		if cont.sharedAaepMonitor[aaepName] == nil {
			cont.sharedAaepMonitor[aaepName] = make(map[string]*AaepEpgAttachData)
		}
		aaepEpgAttachData.nadCreated = false
		cont.sharedAaepMonitor[aaepName][epgDn] = aaepEpgAttachData
		cont.indexMutex.Unlock()
		cont.log.Errorf("Skipping NAD creation: EPG %s with AAEP %s has overlapping VLAN %d", epgDn, aaepName, vlanID)
		return
	}
	cont.syncNADsWithAciState(aaepName, epgDn, oldAaepMonitorData, aaepEpgAttachData, "AaepEpgAttached")
	cont.log.Infof("Completed processing of EPG: %s attached with AAEP: %s", epgDn, aaepName)
}

func (cont *AciController) handleAaepEpgDetach(infraRsObjDn string) {
	aaepName := cont.matchesAEPFilter(infraRsObjDn)
	if aaepName == "" {
		cont.log.Debugf("Unable to find AAEP from %s in monitoring list", infraRsObjDn)
		return
	}

	epgDn := cont.getEpgDnFromInfraRsDn(infraRsObjDn)

	if epgDn == "" {
		cont.log.Errorf("Unable to find EPG from %s", infraRsObjDn)
		return
	}

	cont.log.Infof("Started processing of EPG: %s detached from AAEP: %s", infraRsObjDn, aaepName)
	// Need to check if EPG is not attached with any other AAEP
	if !cont.isEpgAttachedWithAaep("", epgDn, false) {
		cont.apicConn.UnsubscribeImmediateDnLocked(epgDn, []string{"tagAnnotation"})
	}

	cont.indexMutex.Lock()
	aaepEpgAttachData := cont.getAaepEpgAttachDataLocked(aaepName, epgDn)
	cont.indexMutex.Unlock()

	if aaepEpgAttachData == nil {
		cont.log.Debugf("Monitoring data not available for EPG %s with AAEP %s", epgDn, aaepName)
		return
	}
	if !cont.namespaceChecks(aaepEpgAttachData.namespaceName, epgDn) {
		cont.log.Debugf("Namespace %s not found", aaepEpgAttachData.namespaceName)
		return
	}

	cont.handleOldNadDeletion(aaepName, epgDn, aaepEpgAttachData, "AaepEpgDetached")
	cont.log.Infof("Completed processing of EPG: %s detached from AAEP: %s", epgDn, aaepName)
}

func (cont *AciController) handleAnnotationAdded(obj apicapi.ApicObject) bool {
	annotationDn := obj.GetDn()
	epgDn := annotationDn[:strings.Index(annotationDn, "/annotationKey-")]
	aaepMonitorDataMap := cont.getAaepMonitoringDataForEpg(epgDn)

	cont.log.Infof("Started processing of EPG: %s annotation %s addition/modification", epgDn, annotationDn)
	for aaepName, aaepMonitorData := range aaepMonitorDataMap {
		cont.indexMutex.Lock()
		oldAaepMonitorData := cont.getAaepEpgAttachDataLocked(aaepName, epgDn)
		cont.indexMutex.Unlock()

		if len(aaepMonitorData) == 0 {
			// No new monitoring data available for this EPG with this AAEP but old data exists
			// delete old NAD if exists and remove from monitoring map
			// create NAD for next EPG with old VLAN
			cont.handleOldNadDeletion(aaepName, epgDn, oldAaepMonitorData, "NamespaceAnnotationAdded")
			cont.log.Debugf("Insufficient data for NAD creation: Monitoring data not available for EPG %s with AAEP %s", epgDn, aaepName)
			continue
		}

		aaepEpgAttachData, exists := aaepMonitorData[epgDn]
		if !exists || aaepEpgAttachData == nil {
			cont.handleOldNadDeletion(aaepName, epgDn, oldAaepMonitorData, "NamespaceAnnotationAdded")
			cont.log.Debugf("Insufficient data for NAD creation: Monitoring data not available for EPG %s with AAEP %s", epgDn, aaepName)
			continue
		}

		if !cont.checkMonitorDataModified(oldAaepMonitorData, aaepEpgAttachData) {
			cont.log.Debugf("No changes in annotation for EPG %s with AAEP %s", epgDn, aaepName)
			continue
		}

		if !cont.namespaceChecks(aaepEpgAttachData.namespaceName, epgDn) {
			// Namespace not exist, need to delete old NAD if exists and remove from monitoring map
			// create NAD for next EPG with old VLAN
			cont.handleOldNadDeletion(aaepName, epgDn, oldAaepMonitorData, "NamespaceAnnotationAdded")
			cont.log.Debugf("Insufficient data in annotation for NAD creation: Namespace not exist, in case of EPG %s with AAEP %s", epgDn, aaepName)
			continue
		}

		// This is needed when user updates annotation and VLAN is already overlapping
		if cont.checkIfEpgWithOverlappingVlan(aaepName, aaepEpgAttachData.encapVlan, epgDn, false) {
			// Add new entry with nadCreated as false
			aaepEpgAttachData.nadCreated = false
			cont.indexMutex.Lock()
			if cont.sharedAaepMonitor[aaepName] == nil {
				cont.sharedAaepMonitor[aaepName] = make(map[string]*AaepEpgAttachData)
			}
			cont.sharedAaepMonitor[aaepName][epgDn] = aaepEpgAttachData
			cont.indexMutex.Unlock()
			cont.log.Debugf("Skipping EPG annotation add handling: EPG %s with AAEP %s has overlapping VLAN %d", epgDn,
				aaepName, aaepEpgAttachData.encapVlan)
			continue
		}

		cont.syncNADsWithAciState(aaepName, epgDn, oldAaepMonitorData, aaepEpgAttachData, "NamespaceAnnotationAdded")
	}
	cont.log.Infof("Completed processing annotation addition/modification for EPG: %s, AnnotationDn: %s", epgDn, annotationDn)
	return true
}

func (cont *AciController) handleAnnotationDeleted(annotationDn string) {
	epgDn := annotationDn[:strings.Index(annotationDn, "/annotationKey-")]
	cont.log.Infof("Started processing of EPG: %s annotation %s deletion", epgDn, annotationDn)
	aaepMonitorDataMap := cont.getAaepMonitoringDataForEpg(epgDn)

	var reason string
	if !cont.checkIfEPGExists(epgDn) {
		reason = "EpgDeleted"
	} else {
		reason = "NamespaceAnnotationRemoved"
	}

	for aaepName, aaepMonitorData := range aaepMonitorDataMap {
		cont.indexMutex.Lock()
		oldAaepMonitorData := cont.getAaepEpgAttachDataLocked(aaepName, epgDn)
		cont.indexMutex.Unlock()

		if oldAaepMonitorData == nil {
			cont.log.Debugf("Monitoring data not available for EPG %s with AAEP %s", epgDn, aaepName)
			continue
		}

		if oldAaepMonitorData.nadCreated == false {
			cont.indexMutex.Lock()
			delete(cont.sharedAaepMonitor[aaepName], epgDn)
			cont.indexMutex.Unlock()
			continue
		}

		if aaepMonitorData == nil {
			cont.indexMutex.Lock()
			delete(cont.sharedAaepMonitor[aaepName], epgDn)
			cont.deleteNetworkAttachmentDefinition(aaepName, epgDn, oldAaepMonitorData, reason)
			cont.indexMutex.Unlock()
			cont.createNadForNextEpg(aaepName, oldAaepMonitorData.encapVlan)
			continue
		}

		aaepEpgAttachData, exists := aaepMonitorData[epgDn]
		if !exists || aaepEpgAttachData == nil {
			cont.indexMutex.Lock()
			delete(cont.sharedAaepMonitor[aaepName], epgDn)
			cont.deleteNetworkAttachmentDefinition(aaepName, epgDn, oldAaepMonitorData, reason)
			cont.indexMutex.Unlock()
			cont.createNadForNextEpg(aaepName, oldAaepMonitorData.encapVlan)
			continue
		}

		cont.syncNADsWithAciState(aaepName, epgDn, oldAaepMonitorData, aaepEpgAttachData, reason)
	}
	cont.log.Infof("Completed processing annotation deletion for EPG: %s, AnnotationDn: %s", epgDn, annotationDn)
}

func (cont *AciController) collectNadData(epgVlanMap *EpgVlanMap) *AaepEpgAttachData {
	epgDn := epgVlanMap.epgDn
	epgAnnotations := cont.getEpgAnnotations(epgDn)
	if epgAnnotations == nil {
		cont.log.Debugf("No annotations found for EPG %s", epgDn)
		return nil
	}
	namespaceName, nadName := cont.getSpecificEPGAnnotation(epgAnnotations)

	if !cont.namespaceChecks(namespaceName, epgDn) {
		cont.log.Debugf("Namespace not exist, in case of EPG %s", epgDn)
		return nil
	}

	aaepMonitoringData := &AaepEpgAttachData{
		encapVlan:     epgVlanMap.encapVlan,
		nadName:       nadName,
		namespaceName: namespaceName,
		nadCreated:    true,
	}

	return aaepMonitoringData
}

func (cont *AciController) getAaepEpgAttachDataLocked(aaepName, epgDn string) *AaepEpgAttachData {
	aaepEpgAttachDataMap, exists := cont.sharedAaepMonitor[aaepName]
	if !exists || aaepEpgAttachDataMap == nil {
		cont.log.Debugf("AAEP %s EPG %s attachment data not found", aaepName, epgDn)
		return nil
	}

	aaepEpgAttachData, exists := aaepEpgAttachDataMap[epgDn]
	if !exists || aaepEpgAttachData == nil {
		cont.log.Debugf("AAEP %s EPG %s attachment data not found", aaepName, epgDn)
		return nil
	}

	cont.log.Infof("Found attachment data: %v for EPG : %s AAEP: %s", *aaepEpgAttachData, epgDn, aaepName)
	return aaepEpgAttachData
}

func (cont *AciController) matchesAEPFilter(infraRsObjDn string) string {
	cont.indexMutex.Lock()
	defer cont.indexMutex.Unlock()
	var aaepName string
	for aaepName = range cont.sharedAaepMonitor {
		expectedPrefix := fmt.Sprintf("uni/infra/attentp-%s/", aaepName)
		if strings.HasPrefix(infraRsObjDn, expectedPrefix) {
			return aaepName
		}
	}
	return ""
}

func (cont *AciController) getEpgDnFromInfraRsDn(infraRsObjDn string) string {
	re := regexp.MustCompile(`\[(.*?)\]`)
	match := re.FindStringSubmatch(infraRsObjDn)

	var epgDn string
	if len(match) > 1 {
		epgDn = match[1]
		return epgDn
	}

	return epgDn
}

func (cont *AciController) getAaepMonitoringDataForEpg(epgDn string) map[string]map[string]*AaepEpgAttachData {
	aaepEpgAttachData := make(map[string]map[string]*AaepEpgAttachData)

	cont.indexMutex.Lock()
	defer cont.indexMutex.Unlock()
	for aaepName := range cont.sharedAaepMonitor {
		encap := ""
		aaepEpgAttachObj := cont.getEncapFromAaepEpgAttachObj(aaepName, epgDn)
		if aaepEpgAttachObj == nil {
			cont.log.Debugf("infraRsFuncToEpg not available for EPG %s attached with AAEP %s", epgDn, aaepName)
			continue
		}
		if val, ok := aaepEpgAttachObj.Attributes["encap"]; ok {
			encap = val.(string)
		} else {
			cont.log.Debugf("Encap missing for infraRsFuncToEpg object of AAEP: %s and EPG: %s", aaepName, epgDn)
		}

		if encap != "" {
			vlanID := cont.getVlanId(encap)
			epgVlanMap := EpgVlanMap{
				epgDn:     epgDn,
				encapVlan: vlanID,
			}
			if aaepEpgAttachData[aaepName] == nil {
				aaepEpgAttachData[aaepName] = make(map[string]*AaepEpgAttachData)
			}
			nadData := cont.collectNadData(&epgVlanMap)
			if nadData != nil {
				aaepEpgAttachData[aaepName][epgDn] = nadData
			}
		}
	}

	return aaepEpgAttachData
}

func (cont *AciController) cleanAnnotationSubscriptions(aaepName string) {
	epgVlanMapList := cont.getAaepEpgAttObjDetails(aaepName)
	if epgVlanMapList == nil {
		return
	}

	for _, epgVlanMap := range epgVlanMapList {
		cont.apicConn.UnsubscribeImmediateDnLocked(epgVlanMap.epgDn, []string{"tagAnnotation"})
	}
}

func (cont *AciController) syncNADsWithAciState(aaepName string, epgDn string, oldAaepEpgAttachData,
	aaepEpgAttachData *AaepEpgAttachData, syncReason string) {
	if oldAaepEpgAttachData != nil {
		if cont.checkAnnotationModified(oldAaepEpgAttachData, aaepEpgAttachData) {
			if oldAaepEpgAttachData.namespaceName != aaepEpgAttachData.namespaceName {
				cont.indexMutex.Lock()
				if oldAaepEpgAttachData.nadCreated == true {
					cont.deleteNetworkAttachmentDefinition(aaepName, epgDn, oldAaepEpgAttachData, syncReason)
				}
				delete(cont.sharedAaepMonitor[aaepName], epgDn)
				cont.indexMutex.Unlock()
			}
		} else if oldAaepEpgAttachData.encapVlan != aaepEpgAttachData.encapVlan {
			cont.handleOldNadDeletion(aaepName, epgDn, oldAaepEpgAttachData, syncReason)
		} else {
			NADAlreadyInCluster, _ := cont.isNADWithSameVlanAlreadyPresent(aaepName, epgDn, aaepEpgAttachData)
			if NADAlreadyInCluster == nil {
				cont.handleNewNadCreation(aaepName, epgDn, aaepEpgAttachData, syncReason, false)
			}
			return
		}
	}
	cont.handleNewNadCreation(aaepName, epgDn, aaepEpgAttachData, syncReason, false)
}

func (cont *AciController) addDeferredNADs(namespaceName string) {
	aaepEpgVlanMap := make(map[string][]EpgVlanMap)

	// Collect all AAEP EPG attachment details
	cont.indexMutex.Lock()
	for aaepName := range cont.sharedAaepMonitor {
		epgVlanMapList := cont.getAaepEpgAttObjDetails(aaepName)

		if epgVlanMapList == nil {
			continue
		}

		aaepEpgVlanMap[aaepName] = epgVlanMapList
	}
	cont.indexMutex.Unlock()

	// Process each AAEP EPG attachment details
	for aaepName, epgVlanMapList := range aaepEpgVlanMap {
		for _, epgVlanMap := range epgVlanMapList {
			aaepEpgAttachData := cont.collectNadData(&epgVlanMap)
			if aaepEpgAttachData == nil || aaepEpgAttachData.namespaceName != namespaceName {
				continue
			}

			if cont.checkIfEpgWithOverlappingVlan(aaepName, aaepEpgAttachData.encapVlan, epgVlanMap.epgDn, false) {
				cont.indexMutex.Lock()
				if cont.sharedAaepMonitor[aaepName] == nil {
					cont.sharedAaepMonitor[aaepName] = make(map[string]*AaepEpgAttachData)
				}
				aaepEpgAttachData.nadCreated = false
				cont.sharedAaepMonitor[aaepName][epgVlanMap.epgDn] = aaepEpgAttachData
				cont.indexMutex.Unlock()

				cont.log.Errorf("Skipping NAD creation: EPG %s with AAEP %s has overlapping VLAN %d", epgVlanMap.epgDn,
					aaepName, aaepEpgAttachData.encapVlan)
				continue
			} else if cont.checkVlanUsedInCluster(aaepEpgAttachData.encapVlan) {
				cont.log.Errorf("Skipping NAD creation: VLAN %d is already used in cluster", aaepEpgAttachData.encapVlan)
				continue
			} else {
				epgDn := epgVlanMap.epgDn
				cont.handleNewNadCreation(aaepName, epgDn, aaepEpgAttachData, "NamespaceCreated", false)
			}
		}
	}
}

func (cont *AciController) getAaepEpgAttObjDetails(aaepName string) []EpgVlanMap {
	uri := fmt.Sprintf("/api/node/mo/uni/infra/attentp-%s.json?query-target=subtree&target-subtree-class=infraRsFuncToEpg", aaepName)

	resp, err := cont.apicConn.GetApicResponse(uri)
	if err != nil {
		cont.log.Errorf("Failed to get response from APIC: %v", err)
		return nil
	}

	if len(resp.Imdata) == 0 {
		cont.log.Debugf("Can't find EPGs attached with AAEP %s", aaepName)
		return nil
	}

	epgVlanMapList := make([]EpgVlanMap, 0)
	for _, respImdata := range resp.Imdata {
		aaepEpgAttachObj, ok := respImdata["infraRsFuncToEpg"]
		if !ok {
			cont.log.Debugf("Empty AAEP EPG attachment object")
			continue
		}

		if state, hasState := aaepEpgAttachObj.Attributes["state"].(string); hasState {
			if state != "formed" {
				aaepEpgAttchDn := aaepEpgAttachObj.Attributes["dn"].(string)
				cont.log.Debugf("%s is with state: %s", aaepEpgAttchDn, state)
				cont.cleanStaleNADLocked(aaepName, aaepEpgAttachObj.Attributes["tDn"].(string))
				continue
			}
		}
		vlanID := 0
		if encap, hasEncap := aaepEpgAttachObj.Attributes["encap"].(string); hasEncap {
			vlanID = cont.getVlanId(encap)
		}

		epgVlanMap := EpgVlanMap{
			epgDn:     aaepEpgAttachObj.Attributes["tDn"].(string),
			encapVlan: vlanID,
		}
		epgVlanMapList = append(epgVlanMapList, epgVlanMap)
	}

	return epgVlanMapList
}

func (cont *AciController) getEpgAnnotations(epgDn string) map[string]string {
	uri := fmt.Sprintf("/api/node/mo/%s.json?query-target=subtree&target-subtree-class=tagAnnotation", epgDn)
	resp, err := cont.apicConn.GetApicResponse(uri)
	if err != nil {
		cont.log.Errorf("Failed to get response from APIC: %v", err)
		return nil
	}

	annotationsMap := make(map[string]string)
	for _, respImdata := range resp.Imdata {
		annotationObj, ok := respImdata["tagAnnotation"]
		if !ok {
			cont.log.Debugf("Empty tag annotation of EPG %s", epgDn)
			continue
		}

		key := annotationObj.Attributes["key"].(string)
		annotationsMap[key] = annotationObj.Attributes["value"].(string)
	}

	return annotationsMap
}

func (cont *AciController) checkIfEPGExists(epgDn string) bool {
	uri := fmt.Sprintf("/api/node/mo/%s.json", epgDn)
	resp, err := cont.apicConn.GetApicResponse(uri)
	if err != nil {
		cont.log.Errorf("Failed to get response from APIC: %v", err)
		return false
	}
	if len(resp.Imdata) == 0 {
		cont.log.Debugf("EPG %s does not exist", epgDn)
		return false
	}
	return true
}

func (cont *AciController) getSpecificEPGAnnotation(annotations map[string]string) (string, string) {
	namespaceNameAnnotationKey := cont.config.CnoIdentifier + "-namespace"
	namespaceName, exists := annotations[namespaceNameAnnotationKey]
	if !exists {
		cont.log.Debugf("Annotation with key '%s' not found", namespaceNameAnnotationKey)
	}

	nadNameAnnotationKey := cont.config.CnoIdentifier + "-nad"
	nadName, exists := annotations[nadNameAnnotationKey]
	if !exists {
		cont.log.Debugf("Annotation with key '%s' not found", nadNameAnnotationKey)
	}
	return namespaceName, nadName
}

func (cont *AciController) namespaceChecks(namespaceName string, epgDn string) bool {
	if namespaceName == "" {
		cont.log.Debugf("Defering NAD operation for EPG %s: Namespace name not provided in EPG annotation", epgDn)
		return false
	}

	kubeClient := cont.env.(*K8sEnvironment).kubeClient
	_, err := kubeClient.CoreV1().Namespaces().Get(context.TODO(), namespaceName, metav1.GetOptions{})
	namespaceExists := err == nil
	if !namespaceExists {
		cont.log.Debugf("Defering NAD operation for EPG %s: Namespace %s not exists", epgDn, namespaceName)
		return false
	}

	return true
}

func (cont *AciController) reconcileNadData(aaepName string) map[string]bool {
	epgsToSubscribe := make(map[string]bool)
	epgVlanMapList := cont.getAaepEpgAttObjDetails(aaepName)

	for _, epgVlanMap := range epgVlanMapList {
		if cont.checkVlanUsedInCluster(epgVlanMap.encapVlan) {
			cont.log.Errorf("Skipping NAD creation: VLAN %d is already used in cluster", epgVlanMap.encapVlan)
			continue
		}
		aaepEpgAttachData := cont.collectNadData(&epgVlanMap)
		if aaepEpgAttachData == nil {
			epgsToSubscribe[epgVlanMap.epgDn] = true
			continue
		}

		epgDn := epgVlanMap.epgDn
		if cont.checkIfEpgWithOverlappingVlan(aaepName, aaepEpgAttachData.encapVlan, epgDn, true) {
			aaepEpgAttachData.nadCreated = false
			if cont.sharedAaepMonitor[aaepName] == nil {
				cont.sharedAaepMonitor[aaepName] = make(map[string]*AaepEpgAttachData)
			}
			cont.sharedAaepMonitor[aaepName][epgDn] = aaepEpgAttachData
			epgsToSubscribe[epgDn] = true
			cont.log.Errorf("Skipping NAD creation: EPG %s with AAEP %s has overlapping VLAN %d",
				epgDn, aaepName, aaepEpgAttachData.encapVlan)
			continue
		}

		OldepgDn := cont.handleNewNadCreation(aaepName, epgDn, aaepEpgAttachData, "AaepAddedInCR", true)
		if OldepgDn != "" {
			epgsToSubscribe[OldepgDn] = true
		}

		epgsToSubscribe[epgDn] = true
	}

	if _, ok := cont.sharedAaepMonitor[aaepName]; !ok {
		cont.sharedAaepMonitor[aaepName] = make(map[string]*AaepEpgAttachData)
	}

	return epgsToSubscribe
}

// clean converts a string to lowercase, removes underscores and dots,
// and replaces any other invalid character with a hyphen.
func cleanApicResourceNames(apicResource string) string {
	apicResource = strings.ToLower(apicResource)
	var stringBuilder strings.Builder
	for _, character := range apicResource {
		switch {
		case character == '_' || character == '.':
			continue
		case (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '-':
			stringBuilder.WriteRune(character)
		default:
			stringBuilder.WriteRune('-')
		}
	}
	return strings.Trim(stringBuilder.String(), "-")
}

func (cont *AciController) generateDefaultNadName(aaepName, epgDn string) string {
	parts := strings.Split(epgDn, "/")

	tenant := parts[1][3:]
	appProfile := parts[2][3:]
	epgName := parts[3][4:]

	apicResourceNames := tenant + appProfile + epgName + aaepName
	hashBytes := sha256.Sum256([]byte(apicResourceNames))
	hash := hex.EncodeToString(hashBytes[:])[:16]

	return fmt.Sprintf("%s-%s-%s-%s",
		cleanApicResourceNames(tenant), cleanApicResourceNames(appProfile), cleanApicResourceNames(epgName), hash)
}

func (cont *AciController) isNADUpdateRequired(aaepName string, epgDn string, nadData *AaepEpgAttachData,
	existingNAD *nadapi.NetworkAttachmentDefinition) bool {
	vlanID := nadData.encapVlan
	namespaceName := nadData.namespaceName
	customNadName := nadData.nadName
	defaultNadName := cont.generateDefaultNadName(aaepName, epgDn)
	existingAnnotaions := existingNAD.ObjectMeta.Annotations
	if existingAnnotaions != nil {
		if existingNAD.ObjectMeta.Annotations["aci-sync-status"] == "out-of-sync" || existingNAD.ObjectMeta.Annotations["cno-name"] != customNadName {
			return true
		}
	} else {
		// NAD exists, check if VLAN needs to be updated
		existingConfig := existingNAD.Spec.Config
		if existingConfig != "" {
			var existingCNVConfig map[string]interface{}
			if json.Unmarshal([]byte(existingConfig), &existingCNVConfig) == nil {
				if existingVLAN, ok := existingCNVConfig["vlan"].(float64); ok {
					if int(existingVLAN) == vlanID {
						// VLAN hasn't changed, no update needed
						cont.log.Infof("NetworkAttachmentDefinition %s already exists with correct VLAN %d in namespace %s",
							defaultNadName, vlanID, namespaceName)
						return false
					}
				} else if vlanID == 0 {
					// Both existing and new have no VLAN, no update needed
					cont.log.Infof("NetworkAttachmentDefinition %s already exists with no VLAN in namespace %s", defaultNadName, namespaceName)
					return false
				}
			}
		}
	}

	return true
}

func (cont *AciController) createNetworkAttachmentDefinition(aaepName string, epgDn string, nadData *AaepEpgAttachData, createReason string) bool {
	bridge := cont.config.BridgeName
	if bridge == "" {
		cont.log.Errorf("Linux bridge name must be specified when creating NetworkAttachmentDefinitions")
		return false
	}

	vlanID := nadData.encapVlan
	namespaceName := nadData.namespaceName
	customNadName := nadData.nadName
	defaultNadName := cont.generateDefaultNadName(aaepName, epgDn)
	nadClient := cont.env.(*K8sEnvironment).nadClient
	mtu := 1500

	// Check if NAD already exists
	existingNAD, err := nadClient.K8sCniCncfIoV1().NetworkAttachmentDefinitions(namespaceName).Get(context.TODO(), defaultNadName, metav1.GetOptions{})
	nadExists := err == nil

	if nadExists && !cont.isNADUpdateRequired(aaepName, epgDn, nadData, existingNAD) {
		return true
	}

	cnvBridgeConfig := map[string]any{
		"cniVersion": "0.3.1",
		"name":       defaultNadName,
		"type":       "bridge",
		"bridge":     bridge,
	}

	if !nadExists {
		cnvBridgeConfig["mtu"] = mtu
		cnvBridgeConfig["disableContainerInterface"] = true
		// Add optional parameters from controller config if they are set
		if cont.config.IsGateway != nil {
			cnvBridgeConfig["isGateway"] = *cont.config.IsGateway
		}
		if cont.config.IsDefaultGateway != nil {
			cnvBridgeConfig["isDefaultGateway"] = *cont.config.IsDefaultGateway
		}
		if cont.config.ForceAddress != nil {
			cnvBridgeConfig["forceAddress"] = *cont.config.ForceAddress
		}
		if cont.config.IpMasq != nil {
			cnvBridgeConfig["ipMasq"] = *cont.config.IpMasq
		}
		if cont.config.IpMasqBackend != "" {
			cnvBridgeConfig["ipMasqBackend"] = cont.config.IpMasqBackend
		}
		if cont.config.Mtu != nil {
			cnvBridgeConfig["mtu"] = *cont.config.Mtu
		}
		if cont.config.HairpinMode != nil {
			cnvBridgeConfig["hairpinMode"] = *cont.config.HairpinMode
		}
		if cont.config.PromiscMode != nil {
			cnvBridgeConfig["promiscMode"] = *cont.config.PromiscMode
		}
		if cont.config.Enabledad != nil {
			cnvBridgeConfig["enabledad"] = *cont.config.Enabledad
		}
		if cont.config.Macspoofchk != nil {
			cnvBridgeConfig["macspoofchk"] = *cont.config.Macspoofchk
		}
		if cont.config.DisableContainerInterface != nil {
			cnvBridgeConfig["disableContainerInterface"] = *cont.config.DisableContainerInterface
		}
		if cont.config.PortIsolation != nil {
			cnvBridgeConfig["portIsolation"] = *cont.config.PortIsolation
		}
		if len(cont.config.Ipam) > 0 {
			cnvBridgeConfig["ipam"] = cont.config.Ipam
		}
	} else {
		// Preserve existing optional parameters from existing NAD
		existingConfig := existingNAD.Spec.Config
		if existingConfig != "" {
			var existingCNVConfig map[string]interface{}
			if json.Unmarshal([]byte(existingConfig), &existingCNVConfig) == nil {
				optionalParams := []string{"isGateway", "isDefaultGateway", "forceAddress", "ipMasq",
					"ipMasqBackend", "mtu", "hairpinMode", "promiscMode", "enabledad", "macspoofchk",
					"disableContainerInterface", "portIsolation", "ipam"}
				for _, param := range optionalParams {
					if value, ok := existingCNVConfig[param]; ok {
						cnvBridgeConfig[param] = value
					}
				}
			}
		}
	}
	if vlanID > 0 {
		cnvBridgeConfig["vlan"] = vlanID
	}

	configJSON, err := json.Marshal(cnvBridgeConfig)
	if err != nil {
		cont.log.Errorf("Failed to marshal CNV bridge config: %v", err)
		return false
	}

	nad := &nadapi.NetworkAttachmentDefinition{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "k8s.cni.cncf.io/v1",
			Kind:       "NetworkAttachmentDefinition",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      defaultNadName,
			Namespace: namespaceName,
			Labels: map[string]string{
				"managed-by": "cisco-network-operator",
				"vlan":       strconv.Itoa(vlanID),
			},
			Annotations: map[string]string{
				"managed-by":      "cisco-network-operator",
				"vlan":            strconv.Itoa(vlanID),
				"cno-name":        customNadName,
				"aci-sync-status": "in-sync",
				"aaep-name":       aaepName,
				"epg-dn":          epgDn,
			},
		},
		Spec: nadapi.NetworkAttachmentDefinitionSpec{
			Config: string(configJSON),
		},
	}

	if nadExists {
		nad.ObjectMeta.ResourceVersion = existingNAD.ObjectMeta.ResourceVersion

		updatedNad, err := nadClient.K8sCniCncfIoV1().NetworkAttachmentDefinitions(namespaceName).Update(context.TODO(), nad, metav1.UpdateOptions{})

		if err != nil {
			cont.log.Errorf("Failed to update NetworkAttachmentDefinition %s from namespace %s : %v", customNadName, namespaceName, err)
			return false
		}

		cont.log.Debugf("Existing NAD Annotations: %v, %s", existingNAD.ObjectMeta.Annotations, createReason)
		if existingNAD.ObjectMeta.Annotations["aci-sync-status"] == "out-of-sync" {
			cont.submitEvent(updatedNad, createReason, cont.getNADRevampMessage(createReason))
		}
		cont.log.Infof("Updated NetworkAttachmentDefinition %s from namespace %s", defaultNadName, namespaceName)
	} else {
		_, err = nadClient.K8sCniCncfIoV1().NetworkAttachmentDefinitions(namespaceName).Create(context.TODO(), nad, metav1.CreateOptions{})
		if err != nil {
			cont.log.Errorf("Failed to create NetworkAttachmentDefinition %s in namespace %s : %v", customNadName, namespaceName, err)
			return false
		}
		cont.log.Infof("Created NetworkAttachmentDefinition %s in namespace %s", defaultNadName, namespaceName)
	}

	return true
}

func (cont *AciController) deleteNetworkAttachmentDefinition(aaepName string, epgDn string, nadData *AaepEpgAttachData, deleteReason string) {
	namespaceName := nadData.namespaceName

	kubeClient := cont.env.(*K8sEnvironment).kubeClient
	_, err := kubeClient.CoreV1().Namespaces().Get(context.TODO(), namespaceName, metav1.GetOptions{})
	namespaceExists := err == nil
	if !namespaceExists {
		cont.log.Debugf("Defering NAD deletion for EPG %s: Namespace %s not exists", epgDn, namespaceName)
		return
	}

	nadName := cont.generateDefaultNadName(aaepName, epgDn)
	nadClient := cont.env.(*K8sEnvironment).nadClient

	nadDetails, err := nadClient.K8sCniCncfIoV1().NetworkAttachmentDefinitions(namespaceName).Get(context.TODO(), nadName, metav1.GetOptions{})
	nadExists := err == nil

	if nadExists {
		if !cont.isVmmLiteNAD(nadDetails) {
			return
		}

		if cont.isNADinUse(namespaceName, nadName) {
			nadDetails.ObjectMeta.Annotations["aci-sync-status"] = "out-of-sync"
			_, err = nadClient.K8sCniCncfIoV1().NetworkAttachmentDefinitions(namespaceName).Update(context.TODO(), nadDetails, metav1.UpdateOptions{})
			if err != nil {
				cont.log.Errorf("Failed to add out-of-sync annotation to the NAD %s from namespace %s : %v", nadName, namespaceName, err)
				return
			}
			cont.submitEvent(nadDetails, deleteReason, cont.getNADDeleteMessage(deleteReason))
			cont.log.Infof("Added annotation out-of-sync for NAD %s from namespace %s", nadName, namespaceName)
			return
		}

		delete(nadDetails.ObjectMeta.Annotations, "managed-by")
		_, err = nadClient.K8sCniCncfIoV1().NetworkAttachmentDefinitions(namespaceName).Update(context.TODO(), nadDetails, metav1.UpdateOptions{})
		if err != nil {
			cont.log.Errorf("Failed to remove VMM lite annotation from NetworkAttachmentDefinition %s from namespace %s: %v", nadName, namespaceName, err)
			return
		}
		err := nadClient.K8sCniCncfIoV1().NetworkAttachmentDefinitions(namespaceName).Delete(context.TODO(), nadName, metav1.DeleteOptions{})
		if err != nil {
			cont.log.Errorf("Failed to delete NetworkAttachmentDefinition %s from namespace %s : %v", nadName, namespaceName, err)
			return
		}
		cont.log.Infof("Deleted NAD %s from %s namespace", nadName, namespaceName)
	} else {
		cont.log.Debugf("NAD %s not there to delete in namespace %s", nadName, namespaceName)
	}
}

func (cont *AciController) getVlanId(encap string) int {
	if after, ok := strings.CutPrefix(encap, "vlan-"); ok {
		vlanStr := after
		if vlanID, err := strconv.Atoi(vlanStr); err == nil && vlanID > 0 {
			return vlanID
		}
	} else if after, ok := strings.CutPrefix(encap, "vlan"); ok {
		vlanStr := after
		if vlanID, err := strconv.Atoi(vlanStr); err == nil && vlanID > 0 {
			return vlanID
		}
	}

	return 0
}

func (cont *AciController) getAaepDiff(crAaeps []string) (addedAaeps, removedAaeps []string) {
	crAaepMap := make(map[string]bool)
	for _, crAaep := range crAaeps {
		crAaepMap[crAaep] = true
	}

	for _, crAaep := range crAaeps {
		if _, ok := cont.sharedAaepMonitor[crAaep]; !ok {
			addedAaeps = append(addedAaeps, crAaep)
		}
	}

	for cachedAaep := range cont.sharedAaepMonitor {
		if !crAaepMap[cachedAaep] {
			removedAaeps = append(removedAaeps, cachedAaep)
		}
	}

	return
}

func (cont *AciController) getEncapFromAaepEpgAttachObj(aaepName, epgDn string) *apicapi.ApicObjectBody {
	uri := fmt.Sprintf("/api/node/mo/uni/infra/attentp-%s/gen-default/rsfuncToEpg-[%s].json?query-target=self", aaepName, epgDn)
	resp, err := cont.apicConn.GetApicResponse(uri)
	if err != nil {
		cont.log.Errorf("Failed to get response from APIC: AAEP %s and EPG %s ERROR: %v", aaepName, epgDn, err)
		return nil
	}

	if len(resp.Imdata) == 0 {
		cont.log.Debugf("Can't find infraRsFuncToEpg object for AAEP %s and EPG %s", aaepName, epgDn)
		return nil
	}
	lresp, ok := resp.Imdata[0]["infraRsFuncToEpg"]
	if !ok {
		cont.log.Errorf("InfraRsFuncToEpg object not found in response for AAEP %s and EPG %s", aaepName, epgDn)
		return nil
	}

	return lresp
}

func (cont *AciController) isVmmLiteNAD(nadDetails *nadapi.NetworkAttachmentDefinition) bool {
	return nadDetails.ObjectMeta.Annotations["managed-by"] == "cisco-network-operator"
}

func (cont *AciController) isNADinUse(namespaceName string, nadName string) bool {
	kubeClient := cont.env.(*K8sEnvironment).kubeClient
	pods, err := kubeClient.CoreV1().Pods(namespaceName).List(context.TODO(), metav1.ListOptions{})
	if err == nil {
		var networks []map[string]string
		for _, pod := range pods.Items {
			networksAnn, ok := pod.Annotations["k8s.v1.cni.cncf.io/networks"]
			if ok && (networksAnn == nadName) {
				cont.log.Infof("NAD %s is still used by Pod %s/%s", nadName, namespaceName, pod.Name)
				return true
			}
			if err := json.Unmarshal([]byte(networksAnn), &networks); err != nil {
				cont.log.Errorf("Error while getting pod annotations: %v", err)
				return false
			}
			for _, network := range networks {
				if ok && (network["name"] == nadName) {
					cont.log.Infof("NAD %s is still used by VM %s/%s", nadName, namespaceName, pod.Name)
					return true
				}
			}
		}
	}
	return false
}

func (cont *AciController) getNADDeleteMessage(deleteReason string) string {
	messagePrefix := "NAD is in use by pods: "
	switch {
	case deleteReason == "EpgDeleted":
		return messagePrefix + "EPG deleted"
	case deleteReason == "NamespaceAnnotationRemoved":
		return messagePrefix + "Namespace name EPG annotaion removed"
	case deleteReason == "NamespaceAnnotationModified":
		return messagePrefix + "Namespace name EPG annotation modified"
	case deleteReason == "AaepEpgDetached":
		return messagePrefix + "EPG detached from AAEP"
	case deleteReason == "CRDeleted":
		return messagePrefix + "aaepmonitor CR deleted"
	case deleteReason == "AaepRemovedFromCR":
		return messagePrefix + "AAEP removed from aaepmonitor CR"
	case deleteReason == "AaepEpgAttachedWithVlanUsedInCluster":
		return messagePrefix + "EPG with AAEP has overlapping VLAN with existing cluster VLAN"
	case deleteReason == "AaepEpgAttachedWithOverlappingVlan":
		return messagePrefix + "EPG with AAEP has overlapping VLAN with another EPG"
	case deleteReason == "NamespaceDeleted":
		return messagePrefix + "Namespace deleted"
	case deleteReason == "AaepEpgAttachedWithVlanInUse":
		return messagePrefix + "EPG with AAEP has VLAN already used in cluster"
	case deleteReason == "VlanUpdatedInAaepEpgAttach":
		return messagePrefix + "VLAN updated in AAEP EPG attachment"
	case deleteReason == "StaleNadCleanup":
		return messagePrefix + "Stale NAD detected"
	}
	return messagePrefix + "One or many pods are using NAD"
}

func (cont *AciController) getNADRevampMessage(createReason string) string {
	messagePrefix := "NAD is in sync: "
	switch {
	case createReason == "NamespaceAnnotationAdded":
		return messagePrefix + "Namespace name EPG annotaion added"
	case createReason == "AaepEpgAttached":
		return messagePrefix + "EPG attached with AAEP"
	case createReason == "AaepAddedInCR":
		return messagePrefix + "AAEP added back in aaepmonitor CR"
	case createReason == "NamespaceCreated":
		return messagePrefix + "Namespace created back"
	case createReason == "NextEpgNadCreation":
		return messagePrefix + "NAD creation for next EPG with same VLAN"
	}
	return messagePrefix + "NAD synced with ACI"
}

func (cont *AciController) isEpgAttachedWithAaep(aaepName, epgDn string, locked bool) bool {
	if !locked {
		cont.indexMutex.Lock()
		defer cont.indexMutex.Unlock()
	}
	if aaepName != "" {
		// Used in sync process to check if EPG is still attached with AAEP
		// if EPG not attached, then need to delete NAD
		aaepEpgAttachObj := cont.getEncapFromAaepEpgAttachObj(aaepName, epgDn)
		if aaepEpgAttachObj == nil {
			return false
		}
		if state, hasState := aaepEpgAttachObj.Attributes["state"].(string); hasState {
			if state == "formed" {
				return true
			}
		}
	} else {
		for aaepName := range cont.sharedAaepMonitor {
			aaepEpgAttachObj := cont.getEncapFromAaepEpgAttachObj(aaepName, epgDn)
			if aaepEpgAttachObj == nil {
				continue
			}
			if _, ok := aaepEpgAttachObj.Attributes["encap"]; ok {
				return true
			}
		}
	}
	return false
}

func (cont *AciController) checkDuplicateAaepEpgAttachRequest(aaepName, epgDn string, vlanID int) bool {
	cont.indexMutex.Lock()
	defer cont.indexMutex.Unlock()
	aaepEpgAttachDataMap, exists := cont.sharedAaepMonitor[aaepName]
	if !exists || aaepEpgAttachDataMap == nil {
		return false
	}

	aaepEpgAttachData, exists := aaepEpgAttachDataMap[epgDn]
	if !exists || aaepEpgAttachData == nil {
		return false
	}

	if vlanID == aaepEpgAttachData.encapVlan && aaepEpgAttachData.nadCreated {
		return true
	}
	return false
}

func (cont *AciController) checkIfEpgWithOverlappingVlan(aaepName string, vlanId int, epgDn string, locked bool) bool {
	if !locked {
		cont.indexMutex.Lock()
		defer cont.indexMutex.Unlock()
	}
	oldAaepEpgAttachData := cont.getAaepEpgAttachDataLocked(aaepName, epgDn)

	if oldAaepEpgAttachData != nil {
		// If old data exists with NAD created and VLAN is same in old and new data, skip checking for overlapping VLAN for the same EPG
		if oldAaepEpgAttachData.encapVlan == vlanId && oldAaepEpgAttachData.nadCreated {
			return false
		}
	}
	aaepEpgAttachDataMap, exists := cont.sharedAaepMonitor[aaepName]
	if !exists || aaepEpgAttachDataMap == nil {
		return false
	}

	for _, aaepEpgData := range aaepEpgAttachDataMap {
		if vlanId == aaepEpgData.encapVlan && aaepEpgData.nadCreated {
			return true
		}
	}
	return false
}

func (cont *AciController) createNadForNextEpg(aaepName string, vlanId int) {
	cont.indexMutex.Lock()
	defer cont.indexMutex.Unlock()

	aaepEpgAttachDataMap := cont.sharedAaepMonitor[aaepName]
	for epgDn, aaepEpgAttachData := range aaepEpgAttachDataMap {
		if aaepEpgAttachData.encapVlan != vlanId || aaepEpgAttachData.nadCreated {
			continue
		} else if !cont.namespaceChecks(aaepEpgAttachData.namespaceName, epgDn) {
			cont.log.Debugf("Skipping NAD creation for next EPG %s with AAEP %s and VLAN %d: Namespace checks failed", epgDn, aaepName, vlanId)
			continue
		} else {
			cont.log.Infof("Creating NAD for next EPG %s with AAEP %s and VLAN %d, for which previously NAD not created due to overlapping Vlan",
				epgDn, aaepName, vlanId)
			needCacheChange := cont.createNetworkAttachmentDefinition(aaepName, epgDn, aaepEpgAttachData, "NextEpgNadCreation")
			if needCacheChange {
				aaepEpgAttachData.nadCreated = true
				if cont.sharedAaepMonitor[aaepName] == nil {
					cont.sharedAaepMonitor[aaepName] = make(map[string]*AaepEpgAttachData)
				}
				cont.sharedAaepMonitor[aaepName][epgDn] = aaepEpgAttachData
			}
			cont.log.Infof("Created NAD for next EPG %s with AAEP %s and VLAN %d", epgDn, aaepName, vlanId)
			break
		}
	}
}

func (cont *AciController) checkVlanUsedInCluster(vlanId int) bool {
	if vlanId == cont.config.KubeapiVlan {
		return true
	}
	return false
}

func (cont *AciController) checkMonitorDataModified(oldData, newData *AaepEpgAttachData) bool {
	if oldData == nil {
		return true
	}
	if oldData.namespaceName != newData.namespaceName ||
		oldData.nadName != newData.nadName ||
		oldData.encapVlan != newData.encapVlan {
		return true
	}
	return false
}

func (cont *AciController) handleOldNadDeletion(aaepName, epgDn string,
	oldAaepMonitorData *AaepEpgAttachData, deleteReason string) {
	if oldAaepMonitorData == nil {
		return
	}
	cont.indexMutex.Lock()
	delete(cont.sharedAaepMonitor[aaepName], epgDn)
	if oldAaepMonitorData.nadCreated {
		cont.log.Debugf("Deleting NAD for EPG %s with AAEP %s due to %s", epgDn, aaepName, deleteReason)
		cont.deleteNetworkAttachmentDefinition(aaepName, epgDn, oldAaepMonitorData, deleteReason)
	}
	cont.indexMutex.Unlock()
	if oldAaepMonitorData.nadCreated {
		cont.createNadForNextEpg(aaepName, oldAaepMonitorData.encapVlan)
	}
}

func (cont *AciController) handleNewNadCreation(aaepName, epgDn string,
	newAaepMonitorData *AaepEpgAttachData, createReason string, locked bool) string {
	if !locked {
		cont.indexMutex.Lock()
		defer cont.indexMutex.Unlock()
	}
	// If there are multiple EPGs associated with same vlan for an aaep,
	// then only one NAD will be there.
	// After controller restart, if any other EPG notification comes before the already present NAD
	// it will result in 2 NADs.
	// Below check is to avoid the condition
	NADAlreadyInCluster, oldEpgDn := cont.isNADWithSameVlanAlreadyPresent(aaepName, epgDn, newAaepMonitorData)
	if NADAlreadyInCluster != nil {
		cont.log.Errorf("Cannot create NAD for EPG %s as there is a NAD already present %v with EPG %s attached to AAEP %s", epgDn, NADAlreadyInCluster, oldEpgDn, aaepName)
		if cont.sharedAaepMonitor[aaepName] == nil {
			cont.sharedAaepMonitor[aaepName] = make(map[string]*AaepEpgAttachData)
		}
		cont.sharedAaepMonitor[aaepName][oldEpgDn] = NADAlreadyInCluster
		newAaepMonitorData.nadCreated = false
		cont.sharedAaepMonitor[aaepName][epgDn] = newAaepMonitorData
		return oldEpgDn
	}
	needCacheChange := cont.createNetworkAttachmentDefinition(aaepName, epgDn, newAaepMonitorData, createReason)
	if needCacheChange {
		if cont.sharedAaepMonitor[aaepName] == nil {
			cont.sharedAaepMonitor[aaepName] = make(map[string]*AaepEpgAttachData)
		}
		cont.sharedAaepMonitor[aaepName][epgDn] = newAaepMonitorData
	}
	return ""
}

func (cont *AciController) checkAnnotationModified(oldAaepEpgAttachData, newAaepEpgAttachData *AaepEpgAttachData) bool {
	if oldAaepEpgAttachData.nadName != newAaepEpgAttachData.nadName || oldAaepEpgAttachData.namespaceName != newAaepEpgAttachData.namespaceName {
		return true
	}
	return false
}

func (cont *AciController) isNADWithSameVlanAlreadyPresent(aaepName string, epgDn string, newAaepMonitorData *AaepEpgAttachData) (*AaepEpgAttachData, string) {
	allNADs, err := cont.getAllNADs()
	if err != nil {
		cont.log.Errorf("Failed to get all NADs: %v", err)
		return nil, ""
	}

	for _, nad := range allNADs {
		ns := nad.Namespace
		annotations := nad.ObjectMeta.Annotations
		if annotations == nil {
			continue
		}
		// Check for required annotations
		if annotations["managed-by"] != "cisco-network-operator" ||
			annotations["aci-sync-status"] != "in-sync" ||
			annotations["aaep-name"] != aaepName {
			continue
		}

		existingEpgDn := annotations["epg-dn"]
		// Skip if same EPG DN
		if existingEpgDn == epgDn {
			cont.log.Infof("Found existing NAD %s/%s for epg %s ", ns, nad.Name, epgDn)
			return nil, ""
		}
		// Compare VLAN
		existingVlan, err := strconv.Atoi(annotations["vlan"])
		if err != nil {
			cont.log.Warnf("Invalid VLAN in NAD %s/%s: %v", ns, nad.Name, err)
			continue
		}

		if existingVlan == newAaepMonitorData.encapVlan {
			cont.log.Infof("Found existing NAD %s/%s with same VLAN %d for aaep %s", ns, nad.Name, existingVlan, aaepName)

			return &AaepEpgAttachData{
				nadName:       annotations["cno-name"],
				namespaceName: ns,
				encapVlan:     existingVlan,
				nadCreated:    true,
			}, existingEpgDn
		}
	}

	return nil, ""
}

func (cont *AciController) getAllNADs() ([]nadapi.NetworkAttachmentDefinition, error) {
	nadClient := cont.env.(*K8sEnvironment).nadClient.K8sCniCncfIoV1().NetworkAttachmentDefinitions("")

	nadList, err := nadClient.List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list all NADs: %v", err)
	}

	return nadList.Items, nil
}

func (cont *AciController) syncAndCleanNadCache() {
	var reason string
	cont.indexMutex.Lock()
	defer cont.indexMutex.Unlock()
	cont.log.Infof("Starting sync and clean of NAD cache")
	for aaepName, aaepEpgAttachDataMap := range cont.sharedAaepMonitor {
		// Get the latest EPG attachment details from APIC for the AAEP
		epgVlanMapList := cont.getAaepEpgAttObjDetails(aaepName)

		// Create a set of EPGs from the APIC state for quick lookup
		apicEpgSet := make(map[string]*EpgVlanMap)
		for _, epgVlanMap := range epgVlanMapList {
			apicEpgSet[epgVlanMap.epgDn] = &epgVlanMap
		}

		var namespaceName string
		// Iterate through the cache and find entries not in the APIC state
		for epgDn, oldAaepEpgAttachData := range aaepEpgAttachDataMap {
			if oldAaepEpgAttachData == nil {
				continue
			}
			epgAnnotations := cont.getEpgAnnotations(epgDn)
			if epgAnnotations == nil {
				namespaceName = ""
			} else {
				namespaceName, _ = cont.getSpecificEPGAnnotation(epgAnnotations)
			}
			if _, exists := apicEpgSet[epgDn]; !exists {
				cont.log.Infof("Deleting stale cache entry: EPG %s for AAEP %s. Reason: EPG detached or deleted.", epgDn, aaepName)
				delete(cont.sharedAaepMonitor[aaepName], epgDn)
				if oldAaepEpgAttachData.nadCreated {
					cont.log.Debugf("Deleting NAD for EPG %s with AAEP %s due to AaepEpgDetached", epgDn, aaepName)
					cont.deleteNetworkAttachmentDefinition(aaepName, epgDn, oldAaepEpgAttachData, "AaepEpgDetached")
				}
				cont.log.Infof("Successfully deleted cache entry: EPG %s for AAEP %s.", epgDn, aaepName)
			} else if namespaceName != aaepEpgAttachDataMap[epgDn].namespaceName {
				cont.log.Infof("Deleting stale cache entry: EPG %s for AAEP %s. Reason: namespace annotation changed from %s to %s",
					epgDn, aaepName, aaepEpgAttachDataMap[epgDn].namespaceName, namespaceName)
				delete(cont.sharedAaepMonitor[aaepName], epgDn)
				if oldAaepEpgAttachData.nadCreated {
					if cont.checkIfEPGExists(epgDn) {
						if namespaceName == "" {
							reason = "NamespaceAnnotationRemoved"
						} else {
							reason = "NamespaceAnnotationModified"
						}
					} else {
						reason = "EpgDeleted"
					}
					cont.log.Debugf("Deleting NAD for EPG %s with AAEP %s due to AaepEpgDetached", epgDn, aaepName)
					cont.deleteNetworkAttachmentDefinition(aaepName, epgDn, oldAaepEpgAttachData, reason)
				}
				cont.log.Infof("Successfully deleted cache entry: EPG %s for AAEP %s.", epgDn, aaepName)
			} else if apicEpgSet[epgDn].encapVlan != aaepEpgAttachDataMap[epgDn].encapVlan {
				cont.log.Infof("Updating NAD for EPG %s with AAEP %s due to VLAN change from %d to %d",
					epgDn, aaepName, aaepEpgAttachDataMap[epgDn].encapVlan, apicEpgSet[epgDn].encapVlan)
				delete(cont.sharedAaepMonitor[aaepName], epgDn)
				if oldAaepEpgAttachData.nadCreated {
					cont.log.Debugf("Deleting NAD for EPG %s with AAEP %s due to AaepEpgDetached", epgDn, aaepName)
					cont.deleteNetworkAttachmentDefinition(aaepName, epgDn, oldAaepEpgAttachData, "VlanUpdatedInAaepEpgAttach")
				}
				cont.log.Infof("Successfully deleted cache entry: EPG %s for AAEP %s.", epgDn, aaepName)
			}
		}
	}
	cont.log.Infof("completed sync and clean of NAD cache")
}

func (cont *AciController) syncAndCleanNads() {
	cont.indexMutex.Lock()
	defer cont.indexMutex.Unlock()
	cont.log.Infof("Starting sync and clean of NADs")
	allNADs, err := cont.getAllNADs()
	if err != nil {
		cont.log.Errorf("Failed to get all NADs during sync and clean: %v", err)
		return
	}

	for _, nad := range allNADs {
		annotations := nad.ObjectMeta.Annotations
		if annotations == nil {
			continue
		}
		// Check for required annotations
		if annotations["managed-by"] != "cisco-network-operator" ||
			annotations["aci-sync-status"] != "in-sync" {
			continue
		}

		aaepName := annotations["aaep-name"]
		epgDn := annotations["epg-dn"]
		// Check if EPG is still attached with AAEP
		if !cont.isEpgAttachedWithAaep(aaepName, epgDn, true) {
			cont.log.Infof("Deleting stale NAD %s/%s: EPG %s not attached to AAEP %s", nad.Namespace, nad.Name, epgDn, aaepName)
			delete(cont.sharedAaepMonitor[aaepName], epgDn)
			aaepEpgAttachData := &AaepEpgAttachData{
				nadName:       annotations["cno-name"],
				namespaceName: nad.Namespace,
				encapVlan:     cont.getVlanId(annotations["vlan"]),
				nadCreated:    true,
			}
			cont.deleteNetworkAttachmentDefinition(aaepName, epgDn, aaepEpgAttachData, "StaleNadCleanup")
		}
	}
	cont.log.Infof("Completed sync and clean of NADs")
}

func (cont *AciController) subscribeSafely(epgDn string) {
	const maxRetries = 5
	retries := 0

	for retries < maxRetries {
		defer func() {
			if r := recover(); r != nil && cont.checkIfEPGExists(epgDn) {
				retries++
				cont.log.Infof("Found issue while subscribing for %s: %v. Retry: %d", epgDn, r, retries)
			}
		}()

		cont.apicConn.AddImmediateSubscriptionDnLocked(epgDn, []string{"tagAnnotation"}, cont.handleAnnotationAdded,
			cont.handleAnnotationDeleted)
		return
	}

	cont.log.Errorf("Failed to subscribe to EPG %s after %d retries", epgDn, maxRetries)
}

func (cont *AciController) getNAD(aaepName, epgDn string) *AaepEpgAttachData {
	allNADs, err := cont.getAllNADs()
	if err != nil {
		cont.log.Errorf("Failed to get all NADs during getting NAD details: %v", err)
		return nil
	}

	for _, nad := range allNADs {
		annotations := nad.ObjectMeta.Annotations
		if annotations == nil {
			continue
		}
		// Check for required annotations
		if annotations["managed-by"] != "cisco-network-operator" ||
			annotations["aci-sync-status"] != "in-sync" {
			continue
		}

		nadAaepName := annotations["aaep-name"]
		nadEpgDn := annotations["epg-dn"]
		// Check if EPG is still attached with AAEP
		if aaepName == nadAaepName && epgDn == nadEpgDn {
			aaepEpgAttachData := &AaepEpgAttachData{
				nadName:       annotations["cno-name"],
				namespaceName: nad.Namespace,
				encapVlan:     cont.getVlanId(annotations["vlan"]),
				nadCreated:    true,
			}
			return aaepEpgAttachData
		}
	}
	return nil
}

func (cont *AciController) cleanStaleNADLocked(aaepName, epgDn string) {
	aaepEpgAttachData := cont.getNAD(aaepName, epgDn)
	if aaepEpgAttachData != nil {
		delete(cont.sharedAaepMonitor[aaepName], epgDn)
		cont.deleteNetworkAttachmentDefinition(aaepName, epgDn, aaepEpgAttachData, "StaleNadCleanup")
		cont.log.Infof("Deleted stale NAD for EPG: %s detached from AAEP: %s", epgDn, aaepName)
	}
}
