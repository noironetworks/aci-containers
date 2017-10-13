// Copyright 2016 Cisco Systems, Inc.
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

package index

import (
	"reflect"
	"sync"

	"github.com/Sirupsen/logrus"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
)

type set map[string]bool

// Represent a selector over a set of pods
type PodSelector struct {
	// If specified, a specific namespace to select
	Namespace *string

	// If specified, a selector over namespace labels for namespaces
	// to include
	NsSelector labels.Selector

	// A selector over pods in the selected namespaces
	PodSelector labels.Selector
}

// Select the pods for the given selector object using a set of pod
// selectors
type GetPodSelectorFunc func(interface{}) []PodSelector

// Create a pod selector slice of length one for the given namespace
// and label selector
func PodSelectorFromNsAndSelector(ns string,
	selector *metav1.LabelSelector) []PodSelector {

	s, err := metav1.LabelSelectorAsSelector(selector)

	if err != nil {
		return nil
	}

	return []PodSelector{
		{
			Namespace:   &ns,
			PodSelector: s,
		},
	}
}

// Return a nil selector
func NilSelectorFunc(interface{}) []PodSelector {
	return nil
}

// Return a unique key for the indexed selector object
type GetKeyFunc func(interface{}) (string, error)

// Callback function for SetPodUpdateCallback or SetObjUpdateCallback
type UpdateFunc func(key string)

// Calculate a hash over pod fields to detect pod changes that should
// trigger an update
type PodHashFunc func(pod *v1.Pod) string

type podIndexState struct {
	objKeys set
	podHash string
}

// Pod selector index type
type PodSelectorIndex struct {
	log *logrus.Logger

	podIndexer       cache.Indexer
	namespaceIndexer cache.Indexer
	objIndexer       cache.Indexer

	getKey         GetKeyFunc
	getPodSelector GetPodSelectorFunc

	updatePod   UpdateFunc
	updateObj   UpdateFunc
	podHashFunc PodHashFunc

	indexMutex sync.Mutex

	// maps pod keys to a set of selector object keys
	podIndex map[string]*podIndexState

	// maps selector object keys to a set of pod keys
	objPodIndex map[string]set

	// maps selector object keys to a set of namespace keys and their
	// associated pod selectors
	objNsIndex map[string]map[string][]labels.Selector
}

// Create a new pod selector index object
func NewPodSelectorIndex(log *logrus.Logger,
	podIndexer cache.Indexer,
	namespaceIndexer cache.Indexer,
	objIndexer cache.Indexer,
	getKey GetKeyFunc,
	getPodSelector GetPodSelectorFunc) *PodSelectorIndex {

	return &PodSelectorIndex{
		log:              log,
		podIndexer:       podIndexer,
		namespaceIndexer: namespaceIndexer,
		objIndexer:       objIndexer,
		getKey:           getKey,
		getPodSelector:   getPodSelector,

		podIndex:    make(map[string]*podIndexState),
		objPodIndex: make(map[string]set),
		objNsIndex:  make(map[string]map[string][]labels.Selector),
	}
}

// Set a callback that will be called whenever the objects that
// select a pod change
func (i *PodSelectorIndex) SetPodUpdateCallback(updatePod UpdateFunc) {
	i.updatePod = updatePod
}

// Set a callback that will be called whenever the pods selected by an
// object change
func (i *PodSelectorIndex) SetObjUpdateCallback(updateObj UpdateFunc) {
	i.updateObj = updateObj
}

// Set a function to compute a hash over pod fields.  When the pod
// hash changes, the object update callback will be called
func (i *PodSelectorIndex) SetPodHashFunc(podHashFunc PodHashFunc) {
	i.podHashFunc = podHashFunc
}

// Get the selector objects that match a given pod
func (i *PodSelectorIndex) GetObjForPod(podkey string) (ret []string) {
	i.indexMutex.Lock()
	if state, ok := i.podIndex[podkey]; ok {
		for objkey := range state.objKeys {
			ret = append(ret, objkey)
		}
	}
	i.indexMutex.Unlock()

	return ret
}

// Get the pods that match a given selector object
func (i *PodSelectorIndex) GetPodForObj(objkey string) (ret []string) {
	i.indexMutex.Lock()
	for podkey := range i.objPodIndex[objkey] {
		ret = append(ret, podkey)
	}
	i.indexMutex.Unlock()

	return ret
}

// Call to update the index when a pod's labels change. Calls the
// callback if the pod's mapping has changed
func (i *PodSelectorIndex) UpdatePod(pod *v1.Pod) {
	if i.UpdatePodNoCallback(pod) && i.updatePod != nil {
		podkey, err := cache.MetaNamespaceKeyFunc(pod)
		if err != nil {
			i.log.Error("Could not create pod key: ", err)
			return
		}
		i.updatePod(podkey)
	}
}

// Call to update the index when a pod's labels change.  Returns true
// if a pod update should be queued
func (i *PodSelectorIndex) UpdatePodNoCallback(pod *v1.Pod) bool {
	var podHash string
	if i.podHashFunc != nil {
		podHash = i.podHashFunc(pod)
		if podHash == "" {
			i.DeletePod(pod)
			return false
		}
	}

	podkey, err := cache.MetaNamespaceKeyFunc(pod)
	if err != nil {
		i.log.Error("Could not create pod key: ", err)
		return false
	}

	podUpdated := false
	matched := make(set)
	updatedObjs := make(set)

	i.indexMutex.Lock()
	// check each selector object that could apply to this pod's
	// namespace for new matches
	for objkey, v := range i.objNsIndex {
		if selectors, ok := v[pod.ObjectMeta.Namespace]; ok {
			for _, podSelector := range selectors {
				if podSelector.Matches(labels.Set(pod.ObjectMeta.Labels)) {
					objm, ok := i.objPodIndex[objkey]
					if !ok {
						objm = make(set)
						i.objPodIndex[objkey] = objm
					}
					if _, ok = objm[podkey]; !ok {
						objm[podkey] = true
						podUpdated = true
						updatedObjs[objkey] = true
					}

					matched[objkey] = true
				}
			}
		}
	}

	// Remove stale matches
	state, ok := i.podIndex[podkey]
	if !ok {
		state = &podIndexState{}
		i.podIndex[podkey] = state
	}

	for objkey := range state.objKeys {
		if _, mok := matched[objkey]; !mok {
			if objm, ok := i.objPodIndex[objkey]; ok {
				delete(objm, podkey)
				if len(objm) == 0 {
					delete(i.objPodIndex, objkey)
				}
			}

			podUpdated = true
			updatedObjs[objkey] = true
		}
	}

	{
		// when pod hash changes call all object callbacks and not
		// just those that result from label changes.
		if podHash != state.podHash {
			for k, v := range matched {
				updatedObjs[k] = v
			}
		}
		state.objKeys = matched
		state.podHash = podHash
	}
	i.indexMutex.Unlock()

	i.updateObjs(updatedObjs)

	return podUpdated
}

// Call to update the index when a pod is deleted
func (i *PodSelectorIndex) DeletePod(pod *v1.Pod) {
	updatedObjs := make(set)

	podkey, err := cache.MetaNamespaceKeyFunc(pod)
	if err != nil {
		i.log.Error("Could not create pod key: ", err)
		return
	}
	i.indexMutex.Lock()
	if state, ok := i.podIndex[podkey]; ok {
		for objkey := range state.objKeys {
			if objm, ok := i.objPodIndex[objkey]; ok {
				delete(objm, podkey)
				if len(objm) == 0 {
					delete(i.objPodIndex, objkey)
				}
				updatedObjs[objkey] = true
			}
		}
		delete(i.podIndex, podkey)
	}
	i.indexMutex.Unlock()

	i.updateObjs(updatedObjs)
}

// Call to update the index when a namespace's labels change
func (i *PodSelectorIndex) UpdateNamespace(ns *v1.Namespace) {
	updatedPods := make(set)
	updatedObjs := make(set)

	i.indexMutex.Lock()

	for _, obj := range i.objIndexer.List() {
		objkey, err := i.getKey(obj)
		if err != nil {
			i.log.Error("Could not create object key: ", err)
			continue
		}

		namespaces := i.getObjNamespaces(obj)
		if !reflect.DeepEqual(namespaces, i.objNsIndex[objkey]) {
			newupdated, objupdated := i.updateSelectorObjForNs(obj, namespaces)
			for u := range newupdated {
				updatedPods[u] = true
			}
			if objupdated {
				updatedObjs[objkey] = true
			}
		}
	}

	i.indexMutex.Unlock()

	i.updatePods(updatedPods)
	i.updateObjs(updatedObjs)
}

// Call to update the index when a namespace is deleted
func (i *PodSelectorIndex) DeleteNamespace(ns *v1.Namespace) {
	i.UpdateNamespace(ns)
}

func (i *PodSelectorIndex) getObjNamespaces(obj interface{}) map[string][]labels.Selector {
	ret := make(map[string][]labels.Selector)
	for _, selector := range i.getPodSelector(obj) {
		if selector.Namespace != nil {
			ret[*selector.Namespace] =
				append(ret[*selector.Namespace], selector.PodSelector)
		}

		if selector.NsSelector != nil {
			cache.ListAll(i.namespaceIndexer, selector.NsSelector,
				func(nsobj interface{}) {
					name := nsobj.(*v1.Namespace).ObjectMeta.Name
					ret[name] = append(ret[name], selector.PodSelector)
				})
		}
	}
	return ret
}

// Must have index lock
func (i *PodSelectorIndex) updateSelectorObjForNs(obj interface{},
	namespaces map[string][]labels.Selector) (set, bool) {

	objkey, err := i.getKey(obj)
	if err != nil {
		i.log.Error("Could not create object key: ", err)
		return nil, false
	}

	matched := make(set)
	updatedPods := make(set)
	objUpdated := false

	i.objNsIndex[objkey] = namespaces
	for ns, selectors := range namespaces {
		for _, selector := range selectors {
			cache.ListAllByNamespace(i.podIndexer,
				ns, selector,
				func(podobj interface{}) {
					pod := podobj.(*v1.Pod)
					podkey, err := cache.MetaNamespaceKeyFunc(pod)
					if err != nil {
						i.log.Error("Could not create pod key: ", err)
						return
					}

					state, ok := i.podIndex[podkey]
					if !ok {
						state = &podIndexState{
							objKeys: make(set),
						}
						i.podIndex[podkey] = state
					}

					matched[podkey] = true
					if _, ok = state.objKeys[objkey]; !ok {
						state.objKeys[objkey] = true
						updatedPods[podkey] = true
					}
				})
		}
	}

	// check for old matches that no longer apply
	for oldkey := range i.objPodIndex[objkey] {
		if _, ok := matched[oldkey]; !ok {
			if state, pok := i.podIndex[oldkey]; pok {
				delete(state.objKeys, objkey)
				if len(state.objKeys) == 0 {
					delete(i.podIndex, oldkey)
				}
			}
			updatedPods[oldkey] = true
		}
	}
	if !reflect.DeepEqual(i.objPodIndex[objkey], matched) {
		i.objPodIndex[objkey] = matched
		objUpdated = true
	}

	return updatedPods, objUpdated
}

// Call to update the index when the selector object's selector(s)
// change. Calls the callback if the selector object's mapping have
// changed
func (i *PodSelectorIndex) UpdateSelectorObj(obj interface{}) {
	if i.UpdateSelectorObjNoCallback(obj) && i.updateObj != nil {
		objkey, err := i.getKey(obj)
		if err != nil {
			i.log.Error("Could not create object key: ", err)
			return
		}
		i.updateObj(objkey)
	}
}

// Call to update the index when the selector object's selector(s)
// change. Returns true if the selector object's mapping have
// changed
func (i *PodSelectorIndex) UpdateSelectorObjNoCallback(obj interface{}) bool {
	namespaces := i.getObjNamespaces(obj)
	i.indexMutex.Lock()
	updatedPods, objUpdated := i.updateSelectorObjForNs(obj, namespaces)
	i.indexMutex.Unlock()

	i.updatePods(updatedPods)

	return objUpdated
}

// Call to update the index when the selector object is deleted
func (i *PodSelectorIndex) DeleteSelectorObj(obj interface{}) {
	updated := make(set)

	objkey, err := i.getKey(obj)
	if err != nil {
		i.log.Error("Could not create object key: ", err)
		return
	}

	i.indexMutex.Lock()
	for oldkey := range i.objPodIndex[objkey] {
		if state, pok := i.podIndex[oldkey]; pok {
			delete(state.objKeys, objkey)
			if len(state.objKeys) == 0 {
				delete(i.podIndex, oldkey)
			}
			updated[oldkey] = true
		}
	}
	delete(i.objPodIndex, objkey)
	delete(i.objNsIndex, objkey)
	i.indexMutex.Unlock()

	i.updatePods(updated)
}

func (i *PodSelectorIndex) updatePods(updated set) {
	if i.updatePod == nil {
		return
	}
	for key := range updated {
		i.updatePod(key)
	}

}

func (i *PodSelectorIndex) updateObjs(updated set) {
	if i.updateObj == nil {
		return
	}
	for key := range updated {
		i.updateObj(key)
	}

}
