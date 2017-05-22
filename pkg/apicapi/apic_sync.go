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
	"sort"

	"github.com/Sirupsen/logrus"
)

func (conn *ApicConnection) apicObjCmp(current ApicObject,
	desired ApicObject) (update bool, deletes []string) {

	for classc, bodyc := range current {
		for classd, bodyd := range desired {
			if classc != classd {
				conn.log.Warning("Invalid comparison ", classc, " != ", classd)
				return
			}

			meta, ok := metadata[classc]
			if !ok {
				conn.log.Warning("No metadata for class ", classc)
				return
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
					update = true
					break
				}
			}

			i := 0
			j := 0
			for i < len(bodyc.Children) && j < len(bodyd.Children) {
				cmp := cmpApicObject(bodyc.Children[i], bodyd.Children[j])
				if cmp < 0 {
					conn.log.Error("1, ", bodyc.Children[i].GetDn())
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
				conn.log.Error("2, ", bodyc.Children[i].GetDn())
				deletes = append(deletes, bodyc.Children[i].GetDn())
				i++
			}
			if j < len(bodyd.Children) {
				update = true
			}
		}
	}
	//if update {
	//	conn.log.Debug(current, desired)
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
			cu, cd := conn.apicObjCmp(currentState[i], desiredState[j])
			if cu {
				updates = append(updates, desiredState[j])
			}
			deletes = append(deletes, cd...)

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

	for _, delete := range deletes {
		conn.log.WithFields(logrus.Fields{"DN": delete, "context": context}).
			Debug("Applying APIC object delete")
		conn.deleteDn(delete)
	}
	for _, update := range updates {
		dn := update.GetDn()
		conn.log.WithFields(logrus.Fields{"DN": dn, "context": context}).
			Debug("Applying APIC object update")
		conn.postDn(dn, update)
	}
}

func (conn *ApicConnection) ClearApicObjects(key string) {
	conn.WriteApicObjects(key, nil)
}

func PrepareApicSlice(objects ApicSlice, key string) ApicSlice {
	sort.Sort(objects)
	for _, obj := range objects {
		for class, body := range obj {
			if class != "tagInst" {
				obj.SetTag(key)
			}
			PrepareApicSlice(body.Children, key)

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
		u, d := conn.diffApicState(current, conn.desiredState[tag])
		updates = append(updates, u...)
		deletes = append(deletes, d...)
	}

	for tag, desired := range conn.desiredState {
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

func (conn *ApicConnection) checkDeletes(oldState map[string][]string) {
	conn.indexMutex.Lock()
	for dn, ids := range oldState {
		_, found := conn.cacheDnSubIds[dn]
		if !found {
			for _, id := range ids {
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

func (conn *ApicConnection) WriteApicObjects(key string, objects ApicSlice) {
	PrepareApicSlice(objects, key)

	conn.indexMutex.Lock()
	updates, deletes := conn.diffApicState(conn.desiredState[key], objects)

	conn.updateDnIndex(objects)
	for _, del := range deletes {
		conn.removeFromDnIndex(del)
	}

	if objects == nil {
		delete(conn.desiredState, key)
	} else {
		conn.desiredState[key] = objects
	}
	for dn := range conn.errorUpdates {
		delete(conn.errorUpdates, dn)
	}

	if conn.syncEnabled {
		conn.indexMutex.Unlock()
		conn.applyDiff(updates, deletes, "write")
	} else {
		conn.indexMutex.Unlock()
	}
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
		update, odels := conn.apicObjCmp(aci, eobj)
		if update {
			updates = ApicSlice{eobj}
		}
		deletes = append(deletes, odels...)

		if update || len(odels) != 0 {
			conn.log.WithFields(logrus.Fields{"DN": dn}).
				Warning("Unexpected ACI object alteration")
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

func (conn *ApicConnection) reconcileApicDelete(dn string) {
	conn.indexMutex.Lock()
	if !conn.syncEnabled {
		conn.indexMutex.Unlock()
		return
	}

	var adds ApicSlice
	if eobj, ok := conn.desiredStateDn[dn]; ok {
		conn.log.WithFields(logrus.Fields{"DN": dn}).
			Warning("Restoring unexpectedly deleted ACI object")
		adds = ApicSlice{eobj}
	}

	conn.indexMutex.Unlock()

	conn.applyDiff(adds, nil, "reconcile "+dn)
}
