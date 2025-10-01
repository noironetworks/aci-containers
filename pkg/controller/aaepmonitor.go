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

	addedAaeps, removedAaeps := cont.getAaepDiff(aaepMonitorConfig.Spec.Aaeps)
	for _, aaepName := range addedAaeps {
		cont.reconcileNadData(aaepName)
	}

	for _, aaepName := range removedAaeps {
		cont.cleanAnnotationSubscriptions(aaepName)

		cont.indexMutex.Lock()
		aaepEpgDataList := cont.sharedAaepMonitor[aaepName]
		delete(cont.sharedAaepMonitor, aaepName)

		for _, aaepEpgData := range aaepEpgDataList {
			cont.deleteNetworkAttachmentDefinition(aaepName, aaepEpgData, "AaepRemovedFromCR")
		}
		cont.indexMutex.Unlock()
	}

	return false
}

func (cont *AciController) handleAaepMonitorConfigurationDelete(key string) bool {
	cont.indexMutex.Lock()
	defer cont.indexMutex.Unlock()
	for aaepName, aaepMonitorDataList := range cont.sharedAaepMonitor {
		cont.cleanAnnotationSubscriptions(aaepName)

		for _, aaepMonitorData := range aaepMonitorDataList {
			cont.deleteNetworkAttachmentDefinition(aaepName, aaepMonitorData, "CRDeleted")
		}
	}

	cont.sharedAaepMonitor = make(map[string][]*AaepMonitoringData)
	return false
}

func (cont *AciController) handleAaepEpgAttach(infraRsObj apicapi.ApicObject) {
	infraRsObjDn := infraRsObj.GetDn()
	aaepName := cont.matchesAEPFilter(infraRsObjDn)
	if aaepName == "" {
		cont.log.Debugf("Unable to find AAEP from %s in monitoring list", infraRsObjDn)
		return
	}

	state := infraRsObj.GetAttrStr("state")
	if state != "formed" {
		cont.log.Debugf("Skipping NAD creation: %s is with state: %s", infraRsObjDn, state)
		return
	}

	epgDn := infraRsObj.GetAttrStr("tDn")

	defer cont.apicConn.AddImmediateSubscriptionDnLocked(epgDn, []string{"tagAnnotation"}, cont.handleAnnotationAdded,
		cont.handleAnnotationDeleted)

	encap := infraRsObj.GetAttrStr("encap")
	vlanID := cont.getVlanId(encap)

	aaepEpgData := &AaepEpgAttachData{
		epgDn:     epgDn,
		encapVlan: vlanID,
	}

	aaepMonitorData := cont.collectNadData(aaepEpgData)
	if aaepMonitorData == nil {
		return
	}

	cont.indexMutex.Lock()
	oldAaepMonitorData, _ := cont.getAaepEpgAttachDataLocked(aaepName, epgDn)
	cont.indexMutex.Unlock()

	cont.syncNADsWithAciState(aaepName, epgDn, oldAaepMonitorData, aaepMonitorData, "AaepEpgAttached")
}

func (cont *AciController) handleAaepEpgDetach(infraRsObjDn string) {
	aaepName := cont.matchesAEPFilter(infraRsObjDn)
	if aaepName == "" {
		cont.log.Debugf("Unable to find AAEP from %s in monitoring list", infraRsObjDn)
		return
	}

	epgDn := cont.getEpgDnFromInfraRsDn(infraRsObjDn)

	if !cont.isEpgAttachedWithAaep(epgDn) {
		cont.apicConn.UnsubscribeImmediateDnLocked(epgDn, []string{"tagAnnotation"})
	}

	cont.indexMutex.Lock()
	aaepMonitorData, _ := cont.getAaepEpgAttachDataLocked(aaepName, epgDn)
	cont.indexMutex.Unlock()

	if aaepMonitorData == nil || !cont.namespaceChecks(aaepMonitorData.namespaceName, epgDn) {
		cont.log.Debugf("Monitoring data not available for EPG %s with AAEP %s or namespace %s not found",
			epgDn, aaepName, aaepMonitorData.namespaceName)
		return
	}

	cont.indexMutex.Lock()
	cont.removeAaepEpgAttachDataLocked(aaepName, epgDn)
	cont.deleteNetworkAttachmentDefinition(aaepName, aaepMonitorData, "AaepEpgDetached")
	cont.indexMutex.Unlock()
}

func (cont *AciController) handleAnnotationAdded(obj apicapi.ApicObject) bool {
	annotationDn := obj.GetDn()
	epgDn := annotationDn[:strings.Index(annotationDn, "/annotationKey-")]
	aaepMonitorDataMap := cont.getAaepMonitoringDataForEpg(epgDn)

	for aaepName, aaepMonitorData := range aaepMonitorDataMap {
		if aaepMonitorData == nil {
			cont.log.Debugf("Insufficient data for NAD creation: Monitoring data not available for EPG %s with AAEP %s", epgDn, aaepName)
			continue
		}

		if !cont.namespaceChecks(aaepMonitorData.namespaceName, epgDn) {
			cont.log.Debugf("Insufficient data for NAD creation: Namespace not exist, in case of EPG %s with AAEP %s", epgDn, aaepName)
			continue
		}

		cont.indexMutex.Lock()
		oldAaepMonitorData, _ := cont.getAaepEpgAttachDataLocked(aaepName, epgDn)
		cont.indexMutex.Unlock()
		cont.syncNADsWithAciState(aaepName, epgDn, oldAaepMonitorData, aaepMonitorData, "NamespaceAnnotationAdded")
	}

	return true
}

func (cont *AciController) handleAnnotationDeleted(annotationDn string) {
	epgDn := annotationDn[:strings.Index(annotationDn, "/annotationKey-")]

	aaepMonitorDataMap := cont.getAaepMonitoringDataForEpg(epgDn)

	for aaepName, aaepMonitorData := range aaepMonitorDataMap {
		cont.indexMutex.Lock()
		oldAaepMonitorData, _ := cont.getAaepEpgAttachDataLocked(aaepName, epgDn)
		cont.indexMutex.Unlock()

		if oldAaepMonitorData == nil {
			cont.log.Debugf("Monitoring data not available for EPG %s with AAEP %s", epgDn, aaepName)
			continue
		}

		if aaepMonitorData == nil {
			cont.indexMutex.Lock()
			cont.removeAaepEpgAttachDataLocked(aaepName, epgDn)
			cont.deleteNetworkAttachmentDefinition(aaepName, oldAaepMonitorData, "NamespaceAnnotationRemoved")
			cont.indexMutex.Unlock()
			continue
		}

		cont.syncNADsWithAciState(aaepName, epgDn, oldAaepMonitorData, aaepMonitorData, "NamespaceAnnotationRemoved")
	}
}

func (cont *AciController) collectNadData(aaepEpgData *AaepEpgAttachData) *AaepMonitoringData {
	epgDn := aaepEpgData.epgDn
	epgAnnotations := cont.getEpgAnnotations(epgDn)
	namespaceName, nadName := cont.getSpecificEPGAnnotation(epgAnnotations)

	if !cont.namespaceChecks(namespaceName, epgDn) {
		return nil
	}

	aaepMonitoringData := &AaepMonitoringData{
		aaepEpgData:   *aaepEpgData,
		nadName:       nadName,
		namespaceName: namespaceName,
	}

	return aaepMonitoringData
}

func (cont *AciController) getAaepEpgAttachDataLocked(aaepName string, epgDn string) (*AaepMonitoringData, int) {
	aaepEpgDataList, exists := cont.sharedAaepMonitor[aaepName]
	if !exists || len(aaepEpgDataList) == 0 {
		cont.log.Debugf("AAEP %s EPG %s attachment data not found", aaepName, epgDn)
		return nil, -1
	}

	for dataIndex, aaepEpgData := range aaepEpgDataList {
		if aaepEpgData.aaepEpgData.epgDn == epgDn {
			cont.log.Infof("Found attachment data: %v for EPG : %s AAEP: %s", aaepEpgData, epgDn, aaepName)
			return aaepEpgData, dataIndex
		}
	}
	return nil, -1
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

func (cont *AciController) getAaepMonitoringDataForEpg(epgDn string) map[string]*AaepMonitoringData {
	aaepMonitorDataMap := make(map[string]*AaepMonitoringData)
	var aaepName string

	cont.indexMutex.Lock()
	defer cont.indexMutex.Unlock()
	for aaepName = range cont.sharedAaepMonitor {
		encap := cont.getEncapFromAaepEpgAttachObj(aaepName, epgDn)

		if encap != "" {
			vlanID := cont.getVlanId(encap)
			aaepEpgData := &AaepEpgAttachData{
				epgDn:     epgDn,
				encapVlan: vlanID,
			}

			aaepMonitorDataMap[aaepName] = cont.collectNadData(aaepEpgData)
		}
	}

	return aaepMonitorDataMap
}

func (cont *AciController) cleanAnnotationSubscriptions(aaepName string) {
	aaepEpgDataList := cont.getAaepEpgAttObjDetails(aaepName)
	if aaepEpgDataList == nil {
		return
	}

	for _, aaepEpgData := range aaepEpgDataList {
		cont.apicConn.UnsubscribeImmediateDnLocked(aaepEpgData.epgDn, []string{"tagAnnotation"})
	}
}

func (cont *AciController) syncNADsWithAciState(aaepName string, epgDn string, oldAaepMonitorData,
	aaepMonitorData *AaepMonitoringData, syncReason string) {
	if oldAaepMonitorData == nil {
		cont.indexMutex.Lock()
		needCacheChange := cont.createNetworkAttachmentDefinition(aaepName, aaepMonitorData, syncReason)
		if needCacheChange {
			cont.sharedAaepMonitor[aaepName] = append(cont.sharedAaepMonitor[aaepName], aaepMonitorData)
		}
		cont.indexMutex.Unlock()
	} else {
		if oldAaepMonitorData.namespaceName != aaepMonitorData.namespaceName {
			cont.indexMutex.Lock()
			cont.removeAaepEpgAttachDataLocked(aaepName, epgDn)
			cont.deleteNetworkAttachmentDefinition(aaepName, oldAaepMonitorData, syncReason)
			cont.indexMutex.Unlock()

			cont.indexMutex.Lock()
			needCacheChange := cont.createNetworkAttachmentDefinition(aaepName, aaepMonitorData, syncReason)
			if needCacheChange {
				cont.sharedAaepMonitor[aaepName] = append(cont.sharedAaepMonitor[aaepName], aaepMonitorData)
			}
			cont.indexMutex.Unlock()
			return
		}

		if oldAaepMonitorData.nadName != aaepMonitorData.nadName || oldAaepMonitorData.aaepEpgData.encapVlan != aaepMonitorData.aaepEpgData.encapVlan {
			cont.indexMutex.Lock()
			needCacheChange := cont.createNetworkAttachmentDefinition(aaepName, aaepMonitorData, syncReason)
			if needCacheChange {
				cont.removeAaepEpgAttachDataLocked(aaepName, epgDn)
				cont.sharedAaepMonitor[aaepName] = append(cont.sharedAaepMonitor[aaepName], aaepMonitorData)
			}
			cont.indexMutex.Unlock()
		}
	}
}

func (cont *AciController) addDeferredNADs(namespaceName string) {
	cont.indexMutex.Lock()
	defer cont.indexMutex.Unlock()
	for aaepName := range cont.sharedAaepMonitor {
		aaepEpgDataList := cont.getAaepEpgAttObjDetails(aaepName)

		if aaepEpgDataList == nil {
			continue
		}

		for _, aaepEpgData := range aaepEpgDataList {
			aaepMonitoringData := cont.collectNadData(&aaepEpgData)
			if aaepMonitoringData == nil || aaepMonitoringData.namespaceName != namespaceName {
				continue
			}

			needCacheChange := cont.createNetworkAttachmentDefinition(aaepName, aaepMonitoringData, "NamespaceCreated")
			if needCacheChange {
				cont.sharedAaepMonitor[aaepName] = append(cont.sharedAaepMonitor[aaepName], aaepMonitoringData)
			}
		}
	}
}

func (cont *AciController) cleanNADs(namespaceName string) {
	cont.indexMutex.Lock()
	defer cont.indexMutex.Unlock()
	for aaepName := range cont.sharedAaepMonitor {
		aaepEpgDataList, exists := cont.sharedAaepMonitor[aaepName]
		if !exists || len(aaepEpgDataList) == 0 {
			continue
		}
		newAaepEpgDataList := []*AaepMonitoringData{}
		for _, aaepEpgData := range aaepEpgDataList {
			if aaepEpgData.namespaceName != namespaceName {
				newAaepEpgDataList = append(newAaepEpgDataList, aaepEpgData)
			}
		}
		cont.sharedAaepMonitor[aaepName] = newAaepEpgDataList
	}
}

func (cont *AciController) getAaepEpgAttObjDetails(aaepName string) []AaepEpgAttachData {
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

	aaepEpgAttchDetails := make([]AaepEpgAttachData, 0)
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
				continue
			}
		}
		vlanID := 0
		if encap, hasEncap := aaepEpgAttachObj.Attributes["encap"].(string); hasEncap {
			vlanID = cont.getVlanId(encap)
		}

		aaepEpgData := AaepEpgAttachData{
			epgDn:     aaepEpgAttachObj.Attributes["tDn"].(string),
			encapVlan: vlanID,
		}
		aaepEpgAttchDetails = append(aaepEpgAttchDetails, aaepEpgData)
	}

	return aaepEpgAttchDetails
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

func (cont *AciController) reconcileNadData(aaepName string) {
	aaepEpgDataList := cont.getAaepEpgAttObjDetails(aaepName)

	for _, aaepEpgData := range aaepEpgDataList {
		aaepMonitoringData := cont.collectNadData(&aaepEpgData)
		if aaepMonitoringData == nil {
			cont.apicConn.AddImmediateSubscriptionDnLocked(aaepEpgData.epgDn,
				[]string{"tagAnnotation"}, cont.handleAnnotationAdded,
				cont.handleAnnotationDeleted)
			continue
		}

		cont.indexMutex.Lock()
		needCacheChange := cont.createNetworkAttachmentDefinition(aaepName, aaepMonitoringData, "AaepAddedInCR")
		if needCacheChange {
			cont.sharedAaepMonitor[aaepName] = append(cont.sharedAaepMonitor[aaepName], aaepMonitoringData)
		}
		cont.indexMutex.Unlock()

		cont.apicConn.AddImmediateSubscriptionDnLocked(aaepEpgData.epgDn,
			[]string{"tagAnnotation"}, cont.handleAnnotationAdded,
			cont.handleAnnotationDeleted)
	}

	cont.indexMutex.Lock()
	if _, ok := cont.sharedAaepMonitor[aaepName]; !ok {
		cont.sharedAaepMonitor[aaepName] = []*AaepMonitoringData{}
	}
	cont.indexMutex.Unlock()
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

func (cont *AciController) isNADUpdateRequired(aaepName string, nadData *AaepMonitoringData, existingNAD *nadapi.NetworkAttachmentDefinition) bool {
	vlanID := nadData.aaepEpgData.encapVlan
	namespaceName := nadData.namespaceName
	customNadName := nadData.nadName
	defaultNadName := cont.generateDefaultNadName(aaepName, nadData.aaepEpgData.epgDn)
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
						cont.log.Infof("NetworkAttachmentDefinition %s already exists with correct VLAN %d in namespace %s", defaultNadName, vlanID, namespaceName)
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

func (cont *AciController) createNetworkAttachmentDefinition(aaepName string, nadData *AaepMonitoringData, createReason string) bool {
	bridge := cont.config.BridgeName
	if bridge == "" {
		cont.log.Errorf("Linux bridge name must be specified when creating NetworkAttachmentDefinitions")
		return false
	}

	vlanID := nadData.aaepEpgData.encapVlan
	namespaceName := nadData.namespaceName
	customNadName := nadData.nadName
	defaultNadName := cont.generateDefaultNadName(aaepName, nadData.aaepEpgData.epgDn)
	nadClient := cont.env.(*K8sEnvironment).nadClient
	mtu := 1500

	// Check if NAD already exists
	existingNAD, err := nadClient.K8sCniCncfIoV1().NetworkAttachmentDefinitions(namespaceName).Get(context.TODO(), defaultNadName, metav1.GetOptions{})
	nadExists := err == nil

	if nadExists && !cont.isNADUpdateRequired(aaepName, nadData, existingNAD) {
		return true
	}

	cnvBridgeConfig := map[string]any{
		"cniVersion":       "0.3.1",
		"name":             defaultNadName,
		"type":             "bridge",
		"isDefaultGateway": true,
		"bridge":           bridge,
		"mtu":              mtu,
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
				"epg-dn":          nadData.aaepEpgData.epgDn,
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

func (cont *AciController) deleteNetworkAttachmentDefinition(aaepName string, nadData *AaepMonitoringData, deleteReason string) {
	namespaceName := nadData.namespaceName
	epgDn := nadData.aaepEpgData.epgDn

	kubeClient := cont.env.(*K8sEnvironment).kubeClient
	_, err := kubeClient.CoreV1().Namespaces().Get(context.TODO(), namespaceName, metav1.GetOptions{})
	namespaceExists := err == nil
	if !namespaceExists {
		cont.log.Debugf("Defering NAD deletion for EPG %s: Namespace %s not exists", epgDn, namespaceName)
		return
	}

	nadName := cont.generateDefaultNadName(aaepName, nadData.aaepEpgData.epgDn)
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

		nadClient.K8sCniCncfIoV1().NetworkAttachmentDefinitions(namespaceName).Delete(context.TODO(), nadName, metav1.DeleteOptions{})
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

	cont.indexMutex.Lock()
	for _, crAaep := range crAaeps {
		if _, ok := cont.sharedAaepMonitor[crAaep]; !ok {
			addedAaeps = append(addedAaeps, crAaep)
		}
	}
	cont.indexMutex.Unlock()

	cont.indexMutex.Lock()
	for cachedAaep := range cont.sharedAaepMonitor {
		if !crAaepMap[cachedAaep] {
			removedAaeps = append(removedAaeps, cachedAaep)
		}
	}
	cont.indexMutex.Unlock()

	return
}

func (cont *AciController) getEncapFromAaepEpgAttachObj(aaepName, epgDn string) string {
	uri := fmt.Sprintf("/api/node/mo/uni/infra/attentp-%s/gen-default/rsfuncToEpg-[%s].json?query-target=self", aaepName, epgDn)
	resp, err := cont.apicConn.GetApicResponse(uri)
	if err != nil {
		cont.log.Errorf("Failed to get response from APIC: AAEP %s and EPG %s ERROR: %v", aaepName, epgDn, err)
		return ""
	}

	for _, obj := range resp.Imdata {
		lresp, ok := obj["infraRsFuncToEpg"]
		if !ok {
			cont.log.Errorf("InfraRsFuncToEpg object not found in response for %s", uri)
			break
		}
		if val, ok := lresp.Attributes["encap"]; ok {
			encap := val.(string)
			return encap
		} else {
			cont.log.Errorf("Encap missing for infraRsFuncToEpg object for %s: %v", uri, err)
			break
		}
	}

	return ""
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
	case deleteReason == "NamespaceAnnotationRemoved":
		return messagePrefix + "Either EPG deleted or namespace name EPG annotaion removed"
	case deleteReason == "AaepEpgDetached":
		return messagePrefix + "EPG detached from AAEP"
	case deleteReason == "CRDeleted":
		return messagePrefix + "aaepmonitor CR deleted"
	case deleteReason == "AaepRemovedFromCR":
		return messagePrefix + "AAEP removed from aaepmonitor CR"
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
	}
	return messagePrefix + "NAD synced with ACI"
}

func (cont *AciController) isEpgAttachedWithAaep(epgDn string) bool {
	for aaepName := range cont.sharedAaepMonitor {
		encap := cont.getEncapFromAaepEpgAttachObj(aaepName, epgDn)
		if encap != "" {
			return true
		}
	}
	return false
}

func (cont *AciController) removeAaepEpgAttachDataLocked(aaepName, epgDn string) {
	aaepEpgAttachDataList, ok := cont.sharedAaepMonitor[aaepName]
	if !ok {
		return
	}
	for dataIndex, aaepEpgAttachData := range aaepEpgAttachDataList {
		if aaepEpgAttachData.aaepEpgData.epgDn == epgDn {
			cont.sharedAaepMonitor[aaepName] = append(aaepEpgAttachDataList[:dataIndex], aaepEpgAttachDataList[dataIndex+1:]...)
			return
		}
	}
}
