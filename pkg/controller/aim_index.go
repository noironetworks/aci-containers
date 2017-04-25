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

// Index to aid in synchronizing AIM resources with the underlying
// objects that generate them.  We keep an index of the expected state
// of the AIM resources that are associated with a given key, then
// ensure that the corresponding ThirdPartyResource objects in the
// kubernetes API are kept in sync

package controller

import (
	"reflect"
	"sort"
	"strings"

	"github.com/Sirupsen/logrus"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
)

type aimKey struct {
	ktype string
	key   string
}

func newAimKey(ktype string, key string) aimKey {
	return aimKey{ktype, key}
}

func (cont *AciController) clearAimObjects(ktype string, key string) {
	cont.writeAimObjects(ktype, key, nil)
}

func addAimLabels(ktype string, key string, aci *Aci) {
	aci.ObjectMeta.Labels[aimKeyTypeLabel] = ktype
	aci.ObjectMeta.Labels[aimKeyLabel] = key
}

func (cont *AciController) aciObjLogger(aci *Aci) *logrus.Entry {
	return cont.log.WithFields(logrus.Fields{
		"KeyType": aci.ObjectMeta.Labels[aimKeyTypeLabel],
		"Key":     aci.ObjectMeta.Labels[aimKeyLabel],
		"Type":    aci.Spec.Type,
		"Name":    aci.ObjectMeta.Name,
	})
}

func (cont *AciController) reconcileAimObject(aci *Aci) {
	cont.indexMutex.Lock()
	if !cont.syncEnabled {
		cont.indexMutex.Unlock()
		return
	}
	ktype, ktok := aci.ObjectMeta.Labels[aimKeyTypeLabel]
	key, kok := aci.ObjectMeta.Labels[aimKeyLabel]

	var updates aciSlice
	var deletes []string

	if ktok && kok {
		akey := newAimKey(ktype, key)

		delete := false
		if expected, ok := cont.aimDesiredState[akey]; ok {
			found := false
			for _, eobj := range expected {
				if eobj.ObjectMeta.Name == aci.ObjectMeta.Name {
					found = true

					if !aciObjEq(eobj, aci) {
						cont.aciObjLogger(aci).
							Warning("Unexpected ACI object alteration")
						updates = aciSlice{eobj}
						break
					}
				}
			}
			if !found {
				delete = true
			}
		} else {
			delete = true
		}
		if delete {
			cont.aciObjLogger(aci).Warning("Deleting unexpected ACI object")
			deletes = []string{aci.ObjectMeta.Name}
		}
	}

	cont.indexMutex.Unlock()

	cont.executeAimDiff(nil, updates, deletes)
}

func (cont *AciController) reconcileAimDelete(aci *Aci) {
	cont.indexMutex.Lock()
	if !cont.syncEnabled {
		cont.indexMutex.Unlock()
		return
	}

	ktype, ktok := aci.ObjectMeta.Labels[aimKeyTypeLabel]
	key, kok := aci.ObjectMeta.Labels[aimKeyLabel]

	var adds aciSlice

	if ktok && kok {
		akey := newAimKey(ktype, key)

		if expected, ok := cont.aimDesiredState[akey]; ok {
			for _, eobj := range expected {
				if eobj.ObjectMeta.Name == aci.ObjectMeta.Name {
					cont.aciObjLogger(aci).
						Warning("Restoring unexpectedly deleted ACI object")
					adds = aciSlice{eobj}
					break
				}
			}
		}
	}

	cont.indexMutex.Unlock()

	cont.executeAimDiff(adds, nil, nil)
}

// note that writing the same object with multiple keys will result in
// undefined behavior.
func (cont *AciController) writeAimObjects(ktype string,
	key string, objects aciSlice) {

	sort.Sort(objects)
	for _, o := range objects {
		addAimLabels(ktype, key, o)
	}
	k := newAimKey(ktype, key)

	cont.indexMutex.Lock()
	adds, updates, deletes :=
		cont.diffAimState(cont.aimDesiredState[k], objects)
	if objects == nil {
		delete(cont.aimDesiredState, k)
	} else {
		cont.aimDesiredState[k] = objects
	}
	cont.indexMutex.Unlock()

	if cont.syncEnabled {
		cont.executeAimDiff(adds, updates, deletes)
	}
}

func (cont *AciController) aimFullSync() {

	currentState := make(map[aimKey]aciSlice)
	var adds aciSlice
	var updates aciSlice
	var deletes []string

	cache.ListAllByNamespace(cont.aimInformer.GetIndexer(),
		aimNamespace, labels.Everything(),
		func(aimobj interface{}) {
			aim := aimobj.(*Aci)
			ktype, ktok := aim.ObjectMeta.Labels[aimKeyTypeLabel]
			key, kok := aim.ObjectMeta.Labels[aimKeyLabel]
			if ktok && kok {
				akey := newAimKey(ktype, key)
				currentState[akey] = append(currentState[akey], aim)
			}
		})

	cont.indexMutex.Lock()
	for akey, cstate := range currentState {
		sort.Sort(cstate)
		a, u, d := cont.diffAimState(cstate, cont.aimDesiredState[akey])
		adds = append(adds, a...)
		updates = append(updates, u...)
		deletes = append(deletes, d...)
	}

	for akey, dstate := range cont.aimDesiredState {
		if _, ok := currentState[akey]; !ok {
			// entire key not present in current state
			a, _, _ := cont.diffAimState(nil, dstate)
			adds = append(adds, a...)
		}
	}
	cont.indexMutex.Unlock()

	if cont.syncEnabled {
		cont.executeAimDiff(adds, updates, deletes)
	}
}

func aciObjEq(a *Aci, b *Aci) bool {
	return reflect.DeepEqual(a.Spec, b.Spec) &&
		reflect.DeepEqual(a.Labels, b.Labels) &&
		reflect.DeepEqual(a.Annotations, b.Annotations)
}

func (cont *AciController) diffAimState(currentState aciSlice,
	desiredState aciSlice) (adds aciSlice, updates aciSlice, deletes []string) {

	i := 0
	j := 0

	for i < len(currentState) && j < len(desiredState) {
		cmp := strings.Compare(currentState[i].Name, desiredState[j].Name)
		if cmp < 0 {
			deletes = append(deletes, currentState[i].Name)
			i++
		} else if cmp > 0 {
			adds = append(adds, desiredState[j])
			j++
		} else {
			if !aciObjEq(currentState[i], desiredState[j]) {
				updates = append(updates, desiredState[j])
			}

			i++
			j++
		}
	}
	// extra old objects
	for i < len(currentState) {
		deletes = append(deletes, currentState[i].Name)
		i++
	}
	// extra new objects
	for j < len(desiredState) {
		adds = append(adds, desiredState[j])
		j++
	}

	return
}

func (cont *AciController) executeAimDiff(adds aciSlice,
	updates aciSlice, deletes []string) {

	for _, delete := range deletes {
		cont.log.WithFields(logrus.Fields{"Name": delete}).
			Debug("Applying ACI object delete")
		err := cont.deleteAim(delete, nil)
		if err != nil {
			cont.log.Error("Could not delete AIM object: ", err)
		}
	}
	for _, update := range updates {
		cont.aciObjLogger(update).Debug("Applying ACI object update")
		_, err := cont.updateAim(update)
		if err != nil {
			cont.log.Error("Could not update AIM object: ", err)
		}
	}
	for _, add := range adds {
		cont.aciObjLogger(add).Debug("Applying ACI object add")
		_, err := cont.addAim(add)
		if err != nil {
			cont.log.Error("Could not add AIM object: ", err)
		}
	}
}
