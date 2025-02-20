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

package apicapi

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/sirupsen/logrus"
)

func (conn *ApicConnection) apicBodyAttrCmp(class string,
	bodyc *ApicObjectBody, bodyd *ApicObjectBody) bool {
	meta, ok := metadata[class]
	if !ok {
		conn.log.Warning("No metadata for class ", class)
		return true
	}
	if bodyc.Attributes == nil {
		bodyc.Attributes = make(map[string]interface{})
	}
	if bodyd.Attributes == nil {
		bodyd.Attributes = make(map[string]interface{})
	}
	for p, def := range meta.attributes {
		if class == "vzRsSubjGraphAtt" && p == "tnVnsAbsGraphName" {
			_, forceResolveExists := bodyc.Attributes["forceResolve"]
			_, customSGAnnoExists := bodyd.Attributes["customSG"]
			if forceResolveExists && customSGAnnoExists {
				bodyd.Attributes["tnVnsAbsGraphName"] = bodyc.Attributes["tnVnsAbsGraphName"]
				conn.log.Debug("Ignoring comparison of tnVnsAbsGraphName attribute of vzRsSubjGraphAtt class")
				continue
			}
		}
		ac, ok := bodyc.Attributes[p]
		if !ok {
			ac = def
		}
		ad, ok := bodyd.Attributes[p]
		if !ok {
			ad = def
		}

		if ac != ad {
			return false
		}
	}
	if class != "tagAnnotation" && class != "tagInst" {
		annotc, ok := bodyc.Attributes["annotation"]
		if !ok {
			annotc = ""
		}
		annotd, ok := bodyd.Attributes["annotation"]
		if !ok {
			annotd = ""
		}
		if annotc != annotd {
			return false
		}
	}

	return true
}

func (conn *ApicConnection) apicCntCmp(current ApicObject,
	desired ApicObject) bool {
	for classc, bodyc := range current {
		for classd, bodyd := range desired {
			if classc != classd {
				conn.log.Warning("Invalid comparison ", classc, " != ", classd)
				return false
			}

			return conn.apicBodyAttrCmp(classc, bodyc, bodyd)
		}
	}
	return true
}

func (conn *ApicConnection) apicObjCmp(current ApicObject,
	desired ApicObject) (update bool, deletes []string) {
	for classc, bodyc := range current {
		for classd, bodyd := range desired {
			if classc != classd {
				conn.log.Warning("Invalid comparison ", classc, " != ", classd)
				return
			}

			if !conn.apicBodyAttrCmp(classc, bodyc, bodyd) {
				update = true
			}

			i := 0
			j := 0
			for i < len(bodyc.Children) && j < len(bodyd.Children) {
				cmp := cmpApicObject(bodyc.Children[i], bodyd.Children[j])
				if cmp < 0 {
					deletable := true
					for class := range bodyc.Children[i] {
						deletable = conn.checkNonDeletable(class)
						if !deletable {
							break
						}
					}
					if !deletable {
						i++
						continue
					}
					deletes = append(deletes, bodyc.Children[i].GetDn())
					i++
				} else if cmp > 0 {
					update = true
					j++
				} else {
					cu, cd := conn.apicObjCmp(bodyc.Children[i],
						bodyd.Children[j])
					if cu {
						update = true
					}
					deletes = append(deletes, cd...)

					i++
					j++
				}
			}
			for i < len(bodyc.Children) {
				deletable := true
				for class := range bodyc.Children[i] {
					deletable = conn.checkNonDeletable(class)
					if !deletable {
						break
					}
				}
				if !deletable {
					i++
					continue
				}
				deletes = append(deletes, bodyc.Children[i].GetDn())
				i++
			}
			if j < len(bodyd.Children) {
				update = true
			}
		}
	}
	return
}

func (conn *ApicConnection) checkNonDeletable(class string) bool {
	deletable := true
	if _, ok := metadata[class]; ok {
		if metadata[class].hints != nil {
			if val, ok := metadata[class].hints["deletable"]; ok {
				deletableValue, ok := val.(bool)
				if ok && deletableValue == false {
					deletable = false
				}
			}
		}
	}
	return deletable
}

func (conn *ApicConnection) diffApicState(currentState ApicSlice,
	desiredState ApicSlice) (updates ApicSlice, deletes, localDeletes []string) {
	i := 0
	j := 0

	update := false
	delete := false

	for i < len(currentState) && j < len(desiredState) {
		cmp := cmpApicObject(currentState[i], desiredState[j])
		if cmp < 0 {
			deletable := true
			for class := range currentState[i] {
				deletable = conn.checkNonDeletable(class)
				if !deletable {
					break
				}
			}
			if !deletable {
				localDeletes = append(localDeletes, currentState[i].GetDn())
				i++
				continue
			}
			deletes = append(deletes, currentState[i].GetDn())
			i++
			delete = true
		} else if cmp > 0 {
			updates = append(updates, desiredState[j])
			j++
			update = true
		} else {
			if conn.containerDns[currentState[i].GetDn()] {
				if !conn.apicCntCmp(currentState[i], desiredState[j]) {
					updates = append(updates, desiredState[j])
					update = true
				}
			} else {
				cu, cd := conn.apicObjCmp(currentState[i], desiredState[j])
				if cu {
					updates = append(updates, desiredState[j])
					update = true
				}
				deletable := true
				for class := range currentState[i] {
					deletable = conn.checkNonDeletable(class)
					if !deletable {
						break
					}
				}
				if !deletable {
					localDeletes = append(localDeletes, currentState[i].GetDn())
					i++
					j++
					continue
				}

				deletes = append(deletes, cd...)
				delete = true
			}
			i++
			j++
		}
	}
	// extra old objects
	for i < len(currentState) {
		deletable := true
		for class := range currentState[i] {
			deletable = conn.checkNonDeletable(class)
			if !deletable {
				break
			}
		}
		if !deletable {
			i++
			localDeletes = append(localDeletes, currentState[i].GetDn())
			continue
		}
		deletes = append(deletes, currentState[i].GetDn())
		i++
		delete = true
	}
	// extra new objects
	for j < len(desiredState) {
		updates = append(updates, desiredState[j])
		j++
		update = true
	}

	if update && len(updates) != 0 {
		conn.log.Debug("Apic object updates are :", updates)
	}
	if delete && len(deletes) != 0 {
		conn.log.Debug("Apic object deletes are :", deletes)
	}

	return
}

func isPriorityObject(dn string) bool {
	priorityObjects := [2]string{"lDevVip", "svcRedirectPol"}
	for _, obj := range priorityObjects {
		if strings.Contains(dn, obj) {
			return true
		}
	}
	return false
}

func isLLDPIfObject(dn string) bool {
	dnParts := strings.Split(dn, "/")
	if len(dnParts) >= 5 {
		if dnParts[4] == "lldp" {
			return true
		}
	}
	return false
}

func (conn *ApicConnection) applyDiff(updates ApicSlice, deletes []string,
	context string) {
	sort.Sort(updates)
	sort.Strings(deletes)

	for _, delete := range deletes {
		conn.log.WithFields(logrus.Fields{"mod": "APICAPI", "DN": delete, "context": context}).
			Debug("Applying APIC object delete")
		if isPriorityObject(delete) {
			conn.queuePriorityDn(delete)
		} else {
			conn.queueDn(delete)
		}
	}
	for _, update := range updates {
		dn := update.GetDn()
		conn.log.WithFields(logrus.Fields{"mod": "APICAPI", "DN": dn, "context": context}).
			Debug("Applying APIC object update")
		if isPriorityObject(dn) {
			conn.queuePriorityDn(dn)
		} else {
			conn.queueDn(dn)
		}
	}
}

func getTagFromKey(prefix, key string) string {
	hash := sha256.Sum256([]byte(key))
	return fmt.Sprintf("%s-%s", prefix, hex.EncodeToString(hash[:16]))
}

func PrepareApicSlice(objects ApicSlice, prefix, key string) ApicSlice {
	return prepareApicSliceTag(objects, getTagFromKey(prefix, key))
}

func prepareApicSliceTag(objects ApicSlice, tag string) ApicSlice {
	sort.Sort(objects)
	for _, obj := range objects {
		for class, body := range obj {
			if class != "tagInst" && class != "tagAnnotation" {
				obj.SetTag(tag)
				if body.Attributes == nil {
					body.Attributes = make(map[string]interface{})
				}
				body.Attributes["annotation"] =
					aciContainersOwnerAnnotation
			}
			prepareApicSliceTag(body.Children, tag)

			if md, ok := metadata[class]; ok {
				if md.normalizer != nil {
					md.normalizer(body)
				}
			}
			break
		}
	}
	return objects
}

func prepareApicCache(parentDn string, obj ApicObject, count *int) {
	for _, body := range obj {
		if body.Attributes == nil {
			body.Attributes = make(map[string]interface{})
		}
		dn := obj.BuildDn(parentDn)
		body.Attributes["dn"] = dn
		(*count)++
		for _, c := range body.Children {
			prepareApicCache(dn, c, count)
		}
		sort.Sort(body.Children)
		break
	}
}

func (conn *ApicConnection) fullSync() {
	conn.log.Info("Starting APIC full sync")
	var updates ApicSlice
	var deletes []string

	conn.indexMutex.Lock()
	for tag, current := range conn.cachedState {
		sort.Sort(current)
		key := conn.keyHashes[tag]
		u, d, _ := conn.diffApicState(current, conn.desiredState[key])
		updates = append(updates, u...)
		deletes = append(deletes, d...)
	}

	for key, desired := range conn.desiredState {
		tag := getTagFromKey(conn.prefix, key)
		if _, ok := conn.cachedState[tag]; !ok {
			// entire key not present in current state
			a, _, _ := conn.diffApicState(nil, desired)
			updates = append(updates, a...)
		}
	}

	conn.syncEnabled = true
	conn.indexMutex.Unlock()

	conn.applyDiff(updates, deletes, "sync")
	conn.log.WithFields(logrus.Fields{
		"mod":     "APICAPI",
		"updates": len(updates),
		"deletes": len(deletes),
	}).Info("APIC full sync completed")

	conn.SyncMutex.Lock()
	conn.SyncDone = true
	conn.SyncMutex.Unlock()
}

func (conn *ApicConnection) checkDeletes(oldState map[string]map[string]bool) {
	conn.indexMutex.Lock()
	for dn, ids := range oldState {
		_, found := conn.cacheDnSubIds[dn]
		if !found {
			for id := range ids {
				value, ok := conn.subscriptions.ids[id]
				if !ok {
					continue
				}
				sub, ok := conn.subscriptions.subs[value]
				if !ok {
					continue
				}
				if sub.deleteHook != nil {
					sub.deleteHook(dn)
				}
			}
		}
	}
	conn.indexMutex.Unlock()
}

func (conn *ApicConnection) updateDnIndex(objects ApicSlice) {
	for _, obj := range objects {
		if obj.GetDn() == "" {
			continue
		}
		conn.desiredStateDn[obj.GetDn()] = obj
		for _, body := range obj {
			conn.updateDnIndex(body.Children)
		}
	}
}

func (conn *ApicConnection) removeFromDnIndex(dn string) {
	if dn == "" {
		return
	}
	if obj, ok := conn.desiredStateDn[dn]; ok {
		delete(conn.desiredStateDn, dn)

		for _, body := range obj {
			for _, child := range body.Children {
				conn.removeFromDnIndex(child.GetDn())
				conn.log.Debug("Removing child dn :", child.GetDn())
			}
		}
	}
}

func (conn *ApicConnection) doWriteApicObjects(key string, objects ApicSlice,
	container bool, areStaticObjs bool) {
	tag := getTagFromKey(conn.prefix, key)
	prepareApicSliceTag(objects, tag)

	conn.indexMutex.Lock()
	updates, deletes, localDeletes := conn.diffApicState(conn.desiredState[key], objects)
	// temp cache to store all the "uni/tn-common/svcCont/svcRedirectPol-kube_svc_default_test-master"
	// found in deletes
	var temp_deletes []string
	for _, delete := range deletes {
		if strings.Contains(delete, "svcRedirectPol") {
			temp_deletes = append(temp_deletes, delete)
		}
	}
	newDelete := false
	for _, temp_del := range temp_deletes {
		vns_svc_redirect_pol_obj, ok := conn.desiredStateDn[temp_del]
		if !ok {
			conn.log.Error("no svc_obj found in desiredStateDn cache")
			return
		}
		// Explicitly remove vnsRedirectDest from svcRedirectPol's list of children
		for _, body := range vns_svc_redirect_pol_obj {
			for _, child := range body.Children {
				for class := range child {
					if class == "vnsRedirectDest" {
						deletes = append(deletes, child.GetDn())
						newDelete = true
					}
				}
			}
		}
	}
	if newDelete && len(deletes) != 0 {
		conn.log.Debug("Updated apic object deletes list is :", deletes)
	}

	conn.updateDnIndex(objects)
	for _, localDel := range localDeletes {
		conn.removeFromDnIndex(localDel)
		if container {
			delete(conn.containerDns, localDel)
		}
	}
	for _, del := range deletes {
		conn.removeFromDnIndex(del)
		if container {
			delete(conn.containerDns, del)
		}
	}
	for _, update := range updates {
		dn := update.GetDn()
		if container {
			conn.containerDns[dn] = true
		}
	}

	if objects == nil {
		delete(conn.desiredState, key)
		delete(conn.keyHashes, tag)
	} else {
		conn.desiredState[key] = objects
		conn.keyHashes[tag] = key
	}

	if conn.syncEnabled {
		conn.indexMutex.Unlock()
		conn.applyDiff(updates, deletes, "write")
	} else {
		conn.indexMutex.Unlock()
	}
}

func (conn *ApicConnection) ClearApicContainer(key string) {
	conn.WriteApicContainer(key, nil)
}

func (conn *ApicConnection) WriteApicContainer(key string, objects ApicSlice) {
	conn.doWriteApicObjects(key, objects, true, false)
}

func (conn *ApicConnection) ClearApicObjects(key string) {
	conn.WriteApicObjects(key, nil)
}

func (conn *ApicConnection) WriteStaticApicObjects(key string, objects ApicSlice) {
	conn.doWriteApicObjects(key, objects, false, true)
}

func (conn *ApicConnection) WriteApicObjects(key string, objects ApicSlice) {
	conn.doWriteApicObjects(key, objects, false, false)
}

func (conn *ApicConnection) reconcileApicObject(aci ApicObject) {
	conn.indexMutex.Lock()
	if !conn.syncEnabled {
		conn.indexMutex.Unlock()
		return
	}

	dn := aci.GetDn()

	var updates ApicSlice
	var deletes []string

	if eobj, ok := conn.desiredStateDn[dn]; ok {
		if conn.containerDns[dn] {
			if !conn.apicCntCmp(aci, eobj) {
				updates = ApicSlice{eobj}
				conn.log.WithFields(logrus.Fields{
					"mod":      "APICAPI",
					"DN":       dn,
					"expected": eobj,
					"actual":   aci,
				}).Warning("Unexpected ACI container alteration")
			}
		} else {
			update, odels := conn.apicObjCmp(aci, eobj)
			if update {
				updates = ApicSlice{eobj}
			}
			deletes = append(deletes, odels...)

			if update || len(odels) != 0 {
				conn.log.WithFields(logrus.Fields{
					"mod":      "APICAPI",
					"DN":       dn,
					"expected": eobj,
					"actual":   aci,
				}).Warning("Unexpected ACI object alteration")
			}
		}
	} else {
		tag := aci.GetTag()
		if conn.isSyncTag(tag) {
			conn.log.WithFields(logrus.Fields{"mod": "APICAPI", "DN": dn}).
				Warning("Deleting unexpected ACI object")
			deletes = append(deletes, dn)
		}
	}

	conn.indexMutex.Unlock()

	conn.applyDiff(updates, deletes, "reconcile "+dn)
}
