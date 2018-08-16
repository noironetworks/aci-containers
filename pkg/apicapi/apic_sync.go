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

	"github.com/Sirupsen/logrus"
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
				deletes = append(deletes, bodyc.Children[i].GetDn())
				i++
			}
			if j < len(bodyd.Children) {
				update = true
			}
		}
	}
	//if update {
	//	conn.log.WithFields(logrus.Fields{
	//		"current": current,
	//		"desired": desired,
	//	}).Debug("Update required")
	//}
	return
}

func (conn *ApicConnection) diffApicState(currentState ApicSlice,
	desiredState ApicSlice) (updates ApicSlice, deletes []string) {

	i := 0
	j := 0

	for i < len(currentState) && j < len(desiredState) {
		cmp := cmpApicObject(currentState[i], desiredState[j])
		if cmp < 0 {
			deletes = append(deletes, currentState[i].GetDn())
			i++
		} else if cmp > 0 {
			updates = append(updates, desiredState[j])
			j++
		} else {
			if conn.containerDns[currentState[i].GetDn()] {
				if !conn.apicCntCmp(currentState[i], desiredState[j]) {
					updates = append(updates, desiredState[j])
				}
			} else {
				cu, cd := conn.apicObjCmp(currentState[i], desiredState[j])
				if cu {
					updates = append(updates, desiredState[j])
				}
				deletes = append(deletes, cd...)
			}

			i++
			j++
		}
	}
	// extra old objects
	for i < len(currentState) {
		deletes = append(deletes, currentState[i].GetDn())
		i++
	}
	// extra new objects
	for j < len(desiredState) {
		updates = append(updates, desiredState[j])
		j++
	}

	return
}

func (conn *ApicConnection) applyDiff(updates ApicSlice, deletes []string,
	context string) {
	sort.Sort(updates)
	sort.Strings(deletes)

	for _, delete := range deletes {
		conn.log.WithFields(logrus.Fields{"DN": delete, "context": context}).
			Debug("Applying APIC object delete")
		conn.queueDn(delete)
	}
	for _, update := range updates {
		dn := update.GetDn()
		conn.log.WithFields(logrus.Fields{"DN": dn, "context": context}).
			Debug("Applying APIC object update")
		conn.queueDn(dn)
	}
}

func getTagFromKey(prefix string, key string) string {
	hash := sha256.Sum256([]byte(key))
	return fmt.Sprintf("%s-%s", prefix, hex.EncodeToString(hash[:16]))
}

func PrepareApicSlice(objects ApicSlice, prefix string, key string) ApicSlice {
	return prepareApicSliceTag(objects, getTagFromKey(prefix, key), false)
}

func prepareApicSliceTag(objects ApicSlice, tag string,
	useAPICInstTag bool) ApicSlice {

	sort.Sort(objects)
	for _, obj := range objects {
		for class, body := range obj {
			if class != "tagInst" && class != "tagAnnotation" {
				obj.SetTag(tag, useAPICInstTag)
				if !useAPICInstTag {
					if body.Attributes == nil {
						body.Attributes = make(map[string]interface{})
					}
					body.Attributes["annotation"] =
						aciContainersOwnerAnnotation
				}
			}
			prepareApicSliceTag(body.Children, tag, useAPICInstTag)

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

func prepareApicCache(parentDn string, obj ApicObject) {
	for _, body := range obj {
		if body.Attributes == nil {
			body.Attributes = make(map[string]interface{})
		}
		dn := obj.BuildDn(parentDn)
		body.Attributes["dn"] = dn

		for _, c := range body.Children {
			prepareApicCache(dn, c)
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
		u, d := conn.diffApicState(current, conn.desiredState[key])
		updates = append(updates, u...)
		deletes = append(deletes, d...)
	}

	for key, desired := range conn.desiredState {
		tag := getTagFromKey(conn.prefix, key)
		if _, ok := conn.cachedState[tag]; !ok {
			// entire key not present in current state
			a, _ := conn.diffApicState(nil, desired)
			updates = append(updates, a...)
		}
	}

	conn.syncEnabled = true
	conn.indexMutex.Unlock()

	conn.applyDiff(updates, deletes, "sync")
	conn.log.WithFields(logrus.Fields{
		"updates": len(updates),
		"deletes": len(deletes),
	}).Info("APIC full sync completed")
}

func (conn *ApicConnection) checkDeletes(oldState map[string]map[string]bool) {
	conn.indexMutex.Lock()
	for dn, ids := range oldState {
		_, found := conn.cacheDnSubIds[dn]
		if !found {
			for id, _ := range ids {
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
		conn.desiredStateDn[obj.GetDn()] = obj
		for _, body := range obj {
			conn.updateDnIndex(body.Children)
		}
	}
}

func (conn *ApicConnection) removeFromDnIndex(dn string) {
	if obj, ok := conn.desiredStateDn[dn]; ok {
		delete(conn.desiredStateDn, dn)

		for _, body := range obj {
			for _, child := range body.Children {
				conn.removeFromDnIndex(child.GetDn())
			}
		}
	}
}

func (conn *ApicConnection) doWriteApicObjects(key string, objects ApicSlice,
	container bool) {
	tag := getTagFromKey(conn.prefix, key)
	prepareApicSliceTag(objects, tag, conn.UseAPICInstTag)

	conn.indexMutex.Lock()
	updates, deletes := conn.diffApicState(conn.desiredState[key], objects)

	conn.updateDnIndex(objects)
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
	conn.doWriteApicObjects(key, objects, true)
}

func (conn *ApicConnection) ClearApicObjects(key string) {
	conn.WriteApicObjects(key, nil)
}

func (conn *ApicConnection) WriteApicObjects(key string, objects ApicSlice) {
	conn.doWriteApicObjects(key, objects, false)
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
					"DN":       dn,
					"expected": eobj,
					"actual":   aci,
				}).Warning("Unexpected ACI object alteration")
			}
		}
	} else {
		tag := aci.GetTag()
		if conn.isSyncTag(tag) {
			conn.log.WithFields(logrus.Fields{"DN": dn}).
				Warning("Deleting unexpected ACI object")
			deletes = append(deletes, dn)
		}
	}

	conn.indexMutex.Unlock()

	conn.applyDiff(updates, deletes, "reconcile "+dn)
}
