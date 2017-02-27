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
// objects that generate them

package controller

import (
	"reflect"
	"sort"
	"strings"

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

// note that writing the same object with multiple keys will result in
// undefined behavior.
func (cont *AciController) writeAimObjects(ktype string,
	key string, objects aciSlice) {

	sort.Sort(objects)
	for _, o := range objects {
		addAimLabels(ktype, key, o)
	}

	cont.indexMutex.Lock()
	k := newAimKey(ktype, key)
	adds, updates, deletes :=
		cont.diffAimState(cont.aimDesiredState[k], objects)
	if objects == nil {
		delete(cont.aimDesiredState, k)
	} else {
		cont.aimDesiredState[k] = objects
	}
	cont.indexMutex.Unlock()

	cont.executeAimDiff(adds, updates, deletes)
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

	cont.executeAimDiff(adds, updates, deletes)
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
			if !reflect.DeepEqual(currentState[i].Spec, desiredState[j].Spec) {
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
		err := cont.deleteAim(delete, nil)
		if err != nil {
			cont.log.Error("Could not delete AIM object: ", err)
		}
	}
	for _, update := range updates {
		_, err := cont.updateAim(update)
		if err != nil {
			cont.log.Error("Could not update AIM object: ", err)
		}
	}
	for _, add := range adds {
		_, err := cont.addAim(add)
		if err != nil {
			cont.log.Error("Could not add AIM object: ", err)
		}
	}
}
