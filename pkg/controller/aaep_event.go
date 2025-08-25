// Copyright 2017 Cisco Systems, Inc.
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
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/noironetworks/aci-containers/pkg/apicapi"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var aaepList = []string{
	"deepanshu-test",
}

// HandleAaepEpgAttach processes the AAEP EPG attach event.
func (cont *AciController) HandleAaepEpgAttach(obj apicapi.ApicObject) {
	dn := obj.GetDn()
	// Check if DN contains any of the AAEPs in the list
	aaep, ok := cont.isAAEPInMap(dn)
	if !ok {
		cont.log.Debug("[AAEP-HANDLER] AAEP not in configured map: DN=", dn)
		return
	}
	cont.log.Debug("[AAEP-HANDLER] EPG attached to AAEP in list: AAEP=", aaep, " DN=", dn)

	tdn := obj.GetAttrStr("tDn")
	vlan := strings.TrimPrefix(obj.GetAttrStr("encap"), "vlan-")
	cont.log.Debug("[AAEP-HANDLER] EPG DN=", tdn)
	epg, err := cont.getAciEpgByDn(tdn)
	if err != nil {
		cont.log.Error("Failed to get EPG for DN=", tdn, " err=", err)
		return
	}
	epgName := epg["name"].(string)
	cont.handleEpgAnnotation(tdn, epgName, vlan)
}

// handleEpgAnnotation parses the annotation and triggers NAD creation/defer.
func (cont *AciController) handleEpgAnnotation(tdn string, epgName string, vlan string) {
	namespace, nadName := cont.getEpgAnnotationValues(tdn, epgName)
	if namespace == "" {
		cont.log.Debug("[AAEP-HANDLER] Skipping NAD creation because namespace annotation is missing for EPG=", epgName)
		return
	}
	cont.log.Debug("[AAEP-HANDLER] Final namespace=", namespace, " nad=", nadName, " vlan=", vlan)

	old, exists := cont.epgState[tdn]
	cont.log.Debug("EPG State : ", cont.epgState)
	if exists {
		// If namespace was deleted then we should delete nad else recreate nad
		if cont.namespaceExists(namespace) {
			// If annotation values changed
			if old.Namespace != namespace || old.NadName != nadName || old.Vlan != vlan {
				cont.log.Debug("[AAEP-HANDLER] Change detected for EPG=", epgName,
					" oldNamespace=", old.Namespace, " oldNad=", old.NadName, " oldVlan=", old.Vlan,
					" newNamespace=", namespace, " newNad=", nadName, " newVlan=", vlan)

				// Delete old NAD
				cont.HandleDeleteNAD(tdn)
				cont.HandleCreateNAD(namespace, nadName, vlan, tdn)
			} else {
				cont.log.Debug("[AAEP-HANDLER] No change for EPG=", epgName)
			}
		} else {
			cont.HandleDeleteNAD(tdn)
		}

	} else {
		// First time seeing this EPG
		cont.log.Debug("[AAEP-HANDLER] New EPG=", epgName, " namespace=", namespace, " nad=", nadName)
		cont.HandleCreateNAD(namespace, nadName, vlan, tdn)
	}
}

func (cont *AciController) HandleAaepEpgDetach(dn string) {
	cont.log.Debug("EPG State 2: ", cont.epgState)
	cont.log.Debug("[AAEPDETACH-HANDLER] EPG detached to AAEP: DN=", dn)
	_, exists := cont.epgState[dn]
	if exists {
		cont.HandleDeleteNAD(dn)
	}
}

func (cont *AciController) HandleEpgChange(obj apicapi.ApicObject) {
	dn := obj.GetDn()
	if strings.Contains(dn, "/annotationKey-") {
		dn = dn[:strings.Index(dn, "/annotationKey-")]
		dn, epgName, ok := cont.isEpgAttachedtoAaepinCR(dn)
		if !ok {
			return
		}
		// If we already had nad for the rsobj, then we will have vlan  in state already and will use that. This function will get only annotation change, there will not be vlan change
		vlan := ""
		if old, exists := cont.epgState[dn]; exists {
			vlan = old.Vlan
		} else {
			// Incase the rsobj was already there but nad was not present, in that case we need to have the vlan as well while creating nad
			rsObj, ok := cont.getinfraRsFuncToEpgByEpgDn(dn)
			if !ok {
				cont.log.Error("No infraRsFuncToEpg found for DN:", dn)
				return
			}
			encap := rsObj["encap"].(string)
			vlan = strings.TrimPrefix(encap, "vlan-")
		}

		cont.handleEpgAnnotation(dn, epgName, vlan)
	} else {
		// Incase there is a change in fvaepg
		cont.log.Debug("[EPG-HOOK] EPG MO ADDED, ignoring: DN=", dn)
	}
}

func (cont *AciController) HandleEpgDetach(dn string) {
	cont.log.Debug("EPG State: ", cont.epgState)
	if strings.Contains(dn, "/annotationKey-") {
		dn = dn[:strings.Index(dn, "/annotationKey-")]
		old, exists := cont.epgState[dn]
		if exists {
			// Since this is related to annotation change, we will continue to use the vlan that is already in state
			vlan := old.Vlan
			epg, err := cont.getAciEpgByDn(dn)
			if err != nil {
				cont.log.Error("Failed to get EPG for DN=", dn, " err=", err)
				return
			}
			epgName := epg["name"].(string)
			namespace, nadName := cont.getEpgAnnotationValues(dn, epgName)
			if namespace == "" {
				cont.log.Debug("[EPG DETACHANDLER] Namespace annotaiotn deleted so deleting nad for EPG=", epgName)
				cont.HandleDeleteNAD(dn)
				return
			}
			if old.Namespace != namespace || old.NadName != nadName {
				cont.log.Debug("[EPGDETACH] Change detected for EPG=", epgName,
					" oldNamespace=", old.Namespace, " oldNad=", old.NadName,
					" newNamespace=", namespace, " newNad=", nadName)

				// Delete old NAD
				cont.HandleDeleteNAD(dn)
				cont.HandleCreateNAD(namespace, nadName, vlan, dn)
				return
			} else {
				cont.log.Debug("[EPGDETACH] No change for EPG=", epgName)
			}
		}
		cont.log.Debug("[EPGDETACH] Annotation detach for EPG which is not in state= ", dn)
	} else {
		_, exists := cont.epgState[dn]
		if exists {
			cont.HandleDeleteNAD(dn)
		}
	}
}

// helper to check if epg is attached to aaep
func (cont *AciController) isEpgAttachedtoAaepinCR(dn string) (string, string, bool) {
	cont.log.Debug("[ReSOLVE] DN of the EPG = ", dn)

	epg, err := cont.getAciEpgByDn(dn)
	if err != nil {
		cont.log.Error("Failed to get EPG for DN=", dn, " err=", err)
		return "", "", false
	}

	epgName, ok := epg["name"].(string)
	if !ok {
		cont.log.Error("EPG has no valid name for DN=", dn)
		return "", "", false
	}
	cont.log.Debug("[ReSOLVE] EPG ", epgName)

	aaepdn, _ := cont.findAaepForEpg(dn)
	aaep, ok := cont.isAAEPInMap(aaepdn)
	if !ok {
		cont.log.Debug("[ReSOLVE] AAEP not in configured map: DN=", dn)
		return "", "", false
	}
	cont.log.Debug("[ReSOLVE] EPG attached to AAEP in list: AAEP=", aaep, " DN=", dn)

	return dn, epgName, true
}

func (cont *AciController) findAaepForEpg(epgDn string) (string, bool) {
	// Query all infraRsFuncToEpg objects
	rsObjAttrs, ok := cont.getinfraRsFuncToEpgByEpgDn(epgDn)
	if !ok {
		cont.log.Error("No infraRsFuncToEpg found for DN:", epgDn)
		return "", false
	}
	if tDn, ok := rsObjAttrs["tDn"].(string); ok && tDn == epgDn {
		cont.log.Debug("INFRA RS TDN ", tDn)
		rsDn := rsObjAttrs["dn"].(string)
		aaepDn := rsDn[:strings.Index(rsDn, "/gen-default/rsfuncToEpg-")]
		aaepUrl := fmt.Sprintf("/api/node/mo/%s.json?query-target=self", aaepDn)
		aaepResp, err := cont.apicConn.GetApicResponse(aaepUrl)
		if err != nil {
			cont.log.Error("Failed to query AAEP MO: ", err)
			return "", false
		}
		if len(aaepResp.Imdata) > 0 {
			for _, mo := range aaepResp.Imdata {
				if aObj, ok := mo["infraAttEntityP"]; ok {
					if name, ok := aObj.Attributes["dn"].(string); ok {
						return name, true
					}
				}
			}
		}
	}
	return "", false
}

func (cont *AciController) getinfraRsFuncToEpgByEpgDn(epgDn string) (map[string]interface{}, bool) {
	resp, ok := cont.getinfraRsFuncToEpg()
	if ok {
		for _, obj := range resp {
			if rsObj, ok := obj["infraRsFuncToEpg"]; ok {
				attrs := rsObj.Attributes
				if tDn, ok := attrs["tDn"].(string); ok && tDn == epgDn {
					return rsObj.Attributes, true
				}
			}
		}
	}
	return nil, false
}

func (cont *AciController) getEpgAnnotationValues(epgDn, epgName string) (string, string) {
	var namespace string
	nad := epgName

	nsVal, err := cont.getAnnotationValue(epgDn, "namespace")
	if err == nil && nsVal != "" {
		namespace = nsVal
	} else {
		cont.log.Debug("[ANNOT] Namespace annotation missing")
		return namespace, ""
	}

	nadVal, err := cont.getAnnotationValue(epgDn, "nad")
	if err == nil && nadVal != "" {
		nad = nadVal
	} else {
		nad := cont.buildNadNameFromDn(epgDn)
		cont.log.Debug("[EPGDETACH] No annotation found for nad. Generated NAD name=", nad)
	}

	return namespace, nad
}

func (cont *AciController) buildNadNameFromDn(dn string) string {
	parts := strings.Split(dn, "/")
	var tenant, appProfile, epg string

	for _, p := range parts {
		if strings.HasPrefix(p, "tn-") {
			tenant = strings.TrimPrefix(p, "tn-")
		} else if strings.HasPrefix(p, "ap-") {
			appProfile = strings.TrimPrefix(p, "ap-")
		} else if strings.HasPrefix(p, "epg-") {
			epg = strings.TrimPrefix(p, "epg-")
		}
	}
	return fmt.Sprintf("%s-%s-%s", tenant, appProfile, epg)
}

func (cont *AciController) isAAEPInMap(dn string) (string, bool) {
	for _, aaep := range aaepList {
		if strings.Contains(dn, aaep) {
			return aaep, true
		}
	}
	return "", false
}

func (cont *AciController) HandleCreateNAD(namespace string, nadName string, vlan string, dn string) {
	if cont.namespaceExists(namespace) {
		cont.createNAD(namespace, nadName)
		// Update state
		cont.epgState[dn] = EpgAnnotationState{
			Namespace: namespace,
			NadName:   nadName,
			Vlan:      vlan,
		}
	} else {
		cont.deferNADCreation(namespace, nadName)
	}
	cont.log.Debug("EPG State 3: ", cont.epgState)
}

func (cont *AciController) HandleDeleteNAD(dn string) {
	cont.epgMutex.Lock()
	defer cont.epgMutex.Unlock()
	old, exists := cont.epgState[dn]
	if exists {
		cont.deleteNAD(old.Namespace, old.NadName)
		delete(cont.epgState, dn)
		cont.log.Debug("[EEPGDETACH-ANNNOTATION] Deleted EPG from state:", dn)
	}

	cont.log.Debug("EPG State 4: ", cont.epgState)
}

// Example helper: check if namespace exists
func (cont *AciController) namespaceExists(ns string) bool {
	env := cont.env.(*K8sEnvironment)
	kubeClient := env.kubeClient
	if kubeClient == nil {
		fmt.Fprintln(os.Stderr, "Could not get kubeclient", nil)
		return false
	}
	nsObj, err := kubeClient.CoreV1().Namespaces().Get(context.TODO(), ns, metav1.GetOptions{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "[namespaceExists] Namespace %q NOT found. Error: %v\n", ns, err)
		return false
	}
	fmt.Printf("[namespaceExists] Namespace %q EXISTS (UID: %s)\n", ns, nsObj.UID)
	return true
}

func (cont *AciController) ProcessDeferredNads(ns string) bool {
	rsObjs, ok := cont.getinfraRsFuncToEpg()
	if !ok {
		return false
	}
	for _, obj := range rsObjs {
		cont.HandleAaepEpgAttach(obj)
	}
	return true
}

func (cont *AciController) createNAD(namespace, nadName string) {
	cont.log.Debug("Creating NAD=", nadName, " in namespace=", namespace)
}

func (cont *AciController) deferNADCreation(namespace, nadName string) {
	cont.log.Debug("Namespace ", namespace, " not found, deferring NAD creation for ", nadName)
}

func (cont *AciController) deleteNAD(namespace, nadName string) {
	cont.log.Debug("Deleting NAD=", nadName, " in namespace=", namespace)
}
