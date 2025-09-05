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
	"strconv"
	"strings"

	"github.com/noironetworks/aci-containers/pkg/apicapi"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (cont *AciController) HandleAaepEpgAttach(obj apicapi.ApicObject) {
	for className := range obj {
		cont.log.Debugf("[AAEP-HANDLER] MO class: %s", className)
		if className == "infraRsFuncToEpg" {
			cont.HandleRsAttach(obj)
		} else {
			cont.log.Debugf("[AAEP-HANDLER] MO  ELSE class: %s", className)
			cont.HandleAaep(obj)
		}
	}

}

func (cont *AciController) HandleAaep(obj apicapi.ApicObject) {
	cont.log.Debugf("[AAEP-HANDLER] INSIDE HANDLE AAE")

	dn := obj.GetDn()
	aaep, ok := cont.isAAEPInMap(dn)
	if !ok {
		cont.log.Debug("[AAEP-HANDLER] AAEP not in configured map: AAEP=", aaep)
		return
	}

	for className, body := range obj {
		cont.log.Debugf("[AAEP-HANDLER] MO class: %s", className)
		if body == nil {
			continue
		}

		cont.log.Debugf("[AAEP-HANDLER] Attributes: %+v", body.Attributes)

		// look for "infraGeneric" children
		for _, childMap := range body.Children {
			if childBody, ok := childMap["infraGeneric"]; ok && childBody != nil {
				cont.log.Debugf("[AAEP-HANDLER] Child attributes: %+v", childBody.Attributes)

				// look for "infraRsFuncToEpg" grandchildren
				for _, grandChildMap := range childBody.Children {
					if grandChildBody, ok := grandChildMap["infraRsFuncToEpg"]; ok && grandChildBody != nil {
						cont.log.Debugf("[AAEP-HANDLER] Grandchild attributes: %+v", grandChildBody.Attributes)

						// wrap into ApicObject and delegate
						rsObj := apicapi.ApicObject{
							"infraRsFuncToEpg": grandChildBody,
						}
						cont.HandleRsAttach(rsObj)
					}
				}
			}
		}
	}
}

// HandleAaepEpgAttach processes the AAEP EPG attach event.
func (cont *AciController) HandleRsAttach(obj apicapi.ApicObject) {
	dn := obj.GetDn()
	// Check if DN contains any of the AAEPs in the list
	aaep, ok := cont.isAAEPInMap(dn)
	if !ok {
		cont.log.Debug("[AAEP-HANDLER] AAEP not in configured map: DN=", dn)
		return
	}
	cont.log.Debug("[AAEP-HANDLER] EPG attached to AAEP in list: AAEP=", aaep, " DN=", dn)

	tdn := obj.GetAttrStr("tDn")
	encap := obj.GetAttrStr("encap")
	vlanStr := strings.TrimPrefix(encap, "vlan-")
	vlan, _ := strconv.Atoi(vlanStr)
	cont.log.Debug("[AAEP-HANDLER] EPG DN=", tdn)
	cont.handleEpgAnnotation(aaep, tdn, vlan)
}

// handleEpgAnnotation parses the annotation and triggers NAD creation/defer.
func (cont *AciController) handleEpgAnnotation(aaep string, tdn string, vlan int) {
	namespace, nadName := cont.getEpgAnnotationValues(tdn)
	cont.log.Debug("[AAEP-HANDLER] Final namespace=", namespace, " nad=", nadName, " vlan=", vlan)

	oldEntries, exists := cont.aaepState[aaep]
	cont.log.Debug("EPG State : ", cont.aaepState)
	if !exists {
		cont.log.Debug("AAEP  NOT IN THE CACHE AAEP: ", aaep)
		return
	}
	var found *AaepEntry
	for i := range oldEntries {
		if oldEntries[i].AaepEpgData.EpgDn == tdn {
			found = &oldEntries[i]
			break
		}
	}
	if found != nil {
		if cont.namespaceExists(namespace) {
			if found.NamespaceName != namespace || found.NadName != nadName || found.AaepEpgData.EncapVlan != vlan {
				cont.log.Debug("[AAEP-HANDLER] Change detected for EPG=", tdn,
					" oldNamespace=", found.NamespaceName, " oldNad=", found.NadName, " oldVlan=", found.AaepEpgData.EncapVlan, " newNamespace=", namespace, " newNad=", nadName, " newVlan=", vlan)
				cont.HandleDeleteNAD(aaep, tdn)
				cont.HandleCreateNAD(aaep, namespace, nadName, vlan, tdn)
			} else {
				cont.log.Debug("[AAEP-HANDLER] No change for EPG=", tdn)
			}
		} else {
			cont.HandleDeleteNAD(aaep, tdn)
		}

	} else {
		// First time seeing this EPG
		cont.log.Debug("[AAEP-HANDLER] New EPG=", tdn, " namespace=", namespace, " nad=", nadName)
		cont.HandleCreateNAD(aaep, namespace, nadName, vlan, tdn)
	}
}

func (cont *AciController) HandleAaepEpgDetach(dn string) {
	cont.log.Debug("EPG State 2: ", cont.aaepState)
	cont.log.Debug("[AAEPDETACH-HANDLER] EPG detached to AAEP: DN=", dn)
	for aaepName, entries := range cont.aaepState {
		// Check if AAEP name is part of the DN
		if !strings.Contains(dn, aaepName) {
			continue
		}

		// Find the index of the EPG entry whose EpgDn is part of the DN
		indexToDelete := -1
		for i, entry := range entries {
			if strings.Contains(dn, entry.AaepEpgData.EpgDn) {
				indexToDelete = i
				break
			}
		}

		if indexToDelete != -1 {
			// Delete the NAD
			entryToDelete := entries[indexToDelete]
			cont.HandleDeleteNAD(aaepName, dn)

			// Remove the entry from the slice
			entries = append(entries[:indexToDelete], entries[indexToDelete+1:]...)
			cont.aaepState[aaepName] = entries // Keep AAEP key even if slice becomes empty

			cont.log.Debug("[AAEP-HANDLER] Detached EPG removed:", entryToDelete.AaepEpgData.EpgDn, "from AAEP:", aaepName)
			break // Only one EPG per DN, so we can stop
		}
	}
	cont.log.Debug("EPG State 222: ", cont.aaepState)
}

func (cont *AciController) HandleEpgChange(obj apicapi.ApicObject) {
	dn := obj.GetDn()
	if strings.Contains(dn, "/annotationKey-") {
		dn = dn[:strings.Index(dn, "/annotationKey-")]
		dn, aaep, ok := cont.isEpgAttachedtoAaepinCR(dn)
		if !ok {
			return
		}
		// If we already had nad for the rsobj, then we will have vlan  in state already and will use that. This function will get only annotation change, there will not be vlan change
		vlan := 0
		if oldEntries, exists := cont.aaepState[aaep]; exists {
			var found *AaepEntry
			for i := range oldEntries {
				if oldEntries[i].AaepEpgData.EpgDn == dn {
					found = &oldEntries[i]
					break
				}
			}

			if found != nil {
				vlan = found.AaepEpgData.EncapVlan
			} else {
				// Incase the rsobj was already there but nad was not present, in that case we need to have the vlan as well while creating nad
				rsObj, ok := cont.getinfraRsFuncToEpgByEpgDn(dn)
				if !ok {
					cont.log.Error("No infraRsFuncToEpg found for DN:", dn)
					return
				}
				encap := rsObj["encap"].(string)
				vlanStr := strings.TrimPrefix(encap, "vlan-")
				vlan, _ = strconv.Atoi(vlanStr)
			}
			cont.handleEpgAnnotation(aaep, dn, vlan)
		} else {
			cont.log.Debug("AAEP NOT FOUND IN THE STATE=", aaep)
		}
	} else {
		// Incase there is a change in fvaepg
		cont.log.Debug("[EPG-HOOK] EPG MO ADDED, ignoring: DN=", dn)
	}
}

func (cont *AciController) HandleEpgDetach(dn string) {
	cont.log.Debug(" HandleEpgDetach EPG State: ", cont.aaepState)
	if strings.Contains(dn, "/annotationKey-") {
		dn = dn[:strings.Index(dn, "/annotationKey-")]
		for aaep, entries := range cont.aaepState {
			for _, entry := range entries {
				if entry.AaepEpgData.EpgDn != dn {
					continue
				}
				vlan := entry.AaepEpgData.EncapVlan
				namespace, nadName := cont.getEpgAnnotationValues(dn)
				if namespace == "" {
					cont.log.Debug("[EPG DETACHANDLER] Namespace annotaiotn deleted so deleting nad for EPG=", dn)
					cont.HandleDeleteNAD(aaep, dn)
					cont.log.Debug("HandleEpgDetach EPG State2: ", cont.aaepState)
					return
				}
				if entry.NamespaceName != namespace || entry.NadName != nadName {
					cont.log.Debug("[EPGDETACH] Change detected for EPG=", dn,
						" oldNamespace=", entry.NamespaceName, " oldNad=", entry.NadName,
						" newNamespace=", namespace, " newNad=", nadName)

					// Delete old NAD
					cont.HandleDeleteNAD(aaep, dn)
					cont.HandleCreateNAD(aaep, namespace, nadName, vlan, dn)
					cont.log.Debug("HandleEpgDetach EPG State3: ", cont.aaepState)
					return
				} else {
					cont.log.Debug("[EPGDETACH] No change for EPG=", dn)
				}

			}
		}
		cont.log.Debug("[EPGDETACH] Annotation detach for EPG which is not in state= ", dn)
	} else {
		// When epg is detached, we will check if that is in our state, then delete nad
		for aaep, entries := range cont.aaepState {
			for _, entry := range entries {
				if entry.AaepEpgData.EpgDn != dn {
					continue
				}
				cont.HandleDeleteNAD(aaep, dn)
				cont.log.Debug("HandleEpgDetach EPG State4: ", cont.aaepState)
			}
		}
	}
}

// helper to check if epg is attached to aaep
func (cont *AciController) isEpgAttachedtoAaepinCR(dn string) (string, string, bool) {
	cont.log.Debug("[ReSOLVE] DN of the EPG = ", dn)
	aaepdn, _ := cont.findAaepForEpg(dn)
	aaep, ok := cont.isAAEPInMap(aaepdn)
	if !ok {
		cont.log.Debug("[ReSOLVE] AAEP not in configured map: DN=", dn)
		return "", "", false
	}
	cont.log.Debug("[ReSOLVE] EPG attached to AAEP in list: AAEP=", aaep, " DN=", dn)

	return dn, aaep, true
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

func (cont *AciController) getEpgAnnotationValues(epgDn string) (string, string) {
	var namespace string
	var nad string

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
		nad = cont.buildNadNameFromDn(epgDn)
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
	for aaep := range cont.aaepState {
		if strings.Contains(dn, aaep) {
			return aaep, true
		}
	}
	return "", false
}

func (cont *AciController) HandleCreateNAD(aaep string, namespace string, nadName string, vlan int, dn string) {
	if cont.namespaceExists(namespace) {
		cont.createNAD(namespace, nadName)
		cont.epgMutex.Lock()
		defer cont.epgMutex.Unlock()
		newEntry := AaepEntry{
			AaepEpgData: AaepEpgData{
				EpgDn:     dn,
				EncapVlan: vlan,
			},
			NamespaceName: namespace,
			NadName:       nadName,
		}
		cont.aaepState[aaep] = append(cont.aaepState[aaep], newEntry)
	} else {
		cont.deferNADCreation(namespace, nadName)
	}
	cont.log.Debug("EPG State 3: ", cont.aaepState)
}

func (cont *AciController) HandleDeleteNAD(aaep string, dn string) {
	cont.epgMutex.Lock()
	defer cont.epgMutex.Unlock()
	entries, exists := cont.aaepState[aaep]
	if !exists || len(entries) == 0 {
		cont.log.Debug("[AAEP-HANDLER] No entries found for AAEP:", aaep)
		return
	}
	entryIndex := -1
	for i, entry := range entries {
		if entry.AaepEpgData.EpgDn == dn {
			entryIndex = i
			break
		}
	}
	if entryIndex == -1 {
		cont.log.Debug("[AAEP-HANDLER] EPG DN not found under AAEP:", dn)
		return
	}
	entryToDelete := entries[entryIndex]
	cont.deleteNAD(entryToDelete.NamespaceName, entryToDelete.NadName)
	entries = append(entries[:entryIndex], entries[entryIndex+1:]...)
	cont.aaepState[aaep] = entries
	cont.log.Debug("[AAEP-HANDLER] Deleted EPG from state:", dn)
	cont.log.Debug("[AAEP-HANDLER] Updated AAEP state 4:", cont.aaepState)
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
	for aaep, _ := range cont.aaepState {
		// Convert AaepEntry into an ApicObject
		resp, ok := cont.getAaepObject()
		if ok {
			for _, obj := range resp {
				if rsObj, ok := obj["infraAttEntityP"]; ok {
					attrs := rsObj.Attributes
					if name, ok := attrs["name"].(string); ok && name == aaep {
						cont.HandleAaep(obj)
					}
				}
			}
		}
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
