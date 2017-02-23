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

	"k8s.io/apimachinery/pkg/labels"
	v1 "k8s.io/client-go/pkg/api/v1"
	"k8s.io/client-go/tools/cache"
)

// If an object selector applies to a particular namespace, then
// return a non-nil string from GetNsFunc
type GetNsFunc func(interface{}) *string

// Return a nil namespace
func NilNamespaceFunc(interface{}) *string {
	return nil
}

// If an object applies to a set of namespaces, return a non-nil
// selector.  If nil, selects no namespaces, if present but empty
// selects all namespaces
type GetNsSelectorFunc func(interface{}) labels.Selector

// Return a nil selector
func NilSelectorFunc(interface{}) labels.Selector {
	return nil
}

// Select the pods within the selected namespaces. If nil, selects no
// pods, if present but empty selects all pods in the namespaces
type GetPodSelectorFunc func(interface{}) labels.Selector

// Return a unique key for the indexed selector object
type GetKeyFunc func(interface{}) string

// Get the current object from its key
type GetObjFunc func(string) interface{}

// Callback when the set of objects that select a pod changes
type UpdatePodFunc func(podkey string)

// Pod selector index type
type PodSelectorIndex struct {
	log *logrus.Logger

	podInformer       cache.SharedIndexInformer
	namespaceInformer cache.SharedIndexInformer
	objInformer       cache.SharedIndexInformer

	getKey         GetKeyFunc
	getObj         GetObjFunc
	getNs          GetNsFunc
	getNsSelector  GetNsSelectorFunc
	getPodSelector GetPodSelectorFunc
	updatePod      UpdatePodFunc

	indexMutex sync.Mutex

	// maps pod keys to a set of selector object keys
	podIndex map[string]map[string]bool

	// maps selector object keys to a set of pod keys
	objPodIndex map[string]map[string]bool

	// maps selector object keys to a set of namespace keys
	objNsIndex map[string]map[string]bool
}

// Create a new pod selector index object
func NewPodSelectorIndex(log *logrus.Logger,
	podInformer cache.SharedIndexInformer,
	namespaceInformer cache.SharedIndexInformer,
	objInformer cache.SharedIndexInformer,
	getKey GetKeyFunc,
	getNs GetNsFunc,
	getNsSelector GetNsSelectorFunc,
	getPodSelector GetPodSelectorFunc,
	updatePod UpdatePodFunc) *PodSelectorIndex {

	return &PodSelectorIndex{
		log:               log,
		podInformer:       podInformer,
		namespaceInformer: namespaceInformer,
		objInformer:       objInformer,
		getKey:            getKey,
		getNs:             getNs,
		getNsSelector:     getNsSelector,
		getPodSelector:    getPodSelector,
		updatePod:         updatePod,

		podIndex:    make(map[string]map[string]bool),
		objPodIndex: make(map[string]map[string]bool),
		objNsIndex:  make(map[string]map[string]bool),
	}
}

// Get the selector objects that match a given pod
func (i *PodSelectorIndex) GetObjForPod(podkey string) (ret []string) {
	i.indexMutex.Lock()
	for objkey, _ := range i.podIndex[podkey] {
		ret = append(ret, objkey)
	}
	i.indexMutex.Unlock()

	return ret
}

// Get the pods that match a given selector object
func (i *PodSelectorIndex) GetPodForObj(objkey string) (ret []string) {
	i.indexMutex.Lock()
	for podkey, _ := range i.objPodIndex[objkey] {
		ret = append(ret, podkey)
	}
	i.indexMutex.Unlock()

	return ret
}

func (i *PodSelectorIndex) removePodObj(podkey string, objkey string) bool {
	updated := false
	if podm, ok := i.podIndex[podkey]; ok {
		if _, pok := podm[objkey]; pok {
			updated = true
			delete(podm, objkey)
		}
	}
	if objm, ok := i.objPodIndex[objkey]; ok {
		delete(objm, podkey)
	}
	return updated
}

// Call to update the index when a pod's labels change
func (i *PodSelectorIndex) UpdatePod(pod *v1.Pod) bool {
	podkey, err := cache.MetaNamespaceKeyFunc(pod)
	if err != nil {
		i.log.Error("Could not create pod key: ", err)
		return false
	}

	updated := false
	matched := make(map[string]bool)

	i.indexMutex.Lock()
	// check each selector object that could apply to this pod's
	// namespace for new matches
	for objkey, v := range i.objNsIndex {
		if _, ok := v[pod.ObjectMeta.Namespace]; ok {
			obj, exists, err := i.objInformer.GetStore().GetByKey(objkey)
			if exists && err == nil {
				if podSelector := i.getPodSelector(obj); podSelector != nil {
					if podSelector.Matches(labels.Set(pod.ObjectMeta.Labels)) {
						objm, ok := i.objPodIndex[objkey]
						if !ok {
							objm = make(map[string]bool)
							i.objPodIndex[objkey] = objm
						}
						if _, ok = objm[podkey]; !ok {
							objm[podkey] = true
							updated = true
						}

						matched[objkey] = true
					}
				}
			}
		}
	}

	// Remove stale matches
	for objkey, _ := range i.podIndex[podkey] {
		if _, mok := matched[objkey]; !mok {
			if objm, ok := i.objPodIndex[objkey]; ok {
				delete(objm, podkey)
				if len(objm) == 0 {
					delete(i.objPodIndex, objkey)
				}
			}

			updated = true
		}
	}
	i.podIndex[podkey] = matched
	i.indexMutex.Unlock()

	if updated {
		i.updatePod(podkey)
	}
	return updated
}

// Call to update the index when a pod is deleted
func (i *PodSelectorIndex) DeletePod(pod *v1.Pod) {
	i.indexMutex.Lock()
	podkey, err := cache.MetaNamespaceKeyFunc(pod)
	if err != nil {
		i.log.Error("Could not create pod key: ", err)
		return
	}
	if podm, ok := i.podIndex[podkey]; ok {
		for objkey, _ := range podm {
			if objm, ok := i.objPodIndex[objkey]; ok {
				delete(objm, podkey)
				if len(objm) == 0 {
					delete(i.objPodIndex, objkey)
				}
			}
		}
		delete(i.podIndex, podkey)
	}
	i.indexMutex.Unlock()
}

// Call to update the index when a namespace's labels change
func (i *PodSelectorIndex) UpdateNamespace(ns *v1.Namespace) {
	updated := make(map[string]bool)

	i.indexMutex.Lock()

	for k, v := range i.objNsIndex {
		obj, exists, err := i.objInformer.GetStore().GetByKey(k)
		if !exists || err != nil {
			continue
		}
		namespaces := i.getObjNamespaces(obj)
		if !reflect.DeepEqual(namespaces, v) {
			newupdated := i.updateSelectorObjForNs(obj, namespaces)
			for u, _ := range newupdated {
				updated[u] = true
			}
		}
	}

	i.indexMutex.Unlock()

	for key, _ := range updated {
		i.updatePod(key)
	}
}

// Call to update the index when a namespace is deleted
func (i *PodSelectorIndex) DeleteNamespace(ns *v1.Namespace) {
	i.UpdateNamespace(ns)
}

func (i *PodSelectorIndex) getObjNamespaces(obj interface{}) map[string]bool {
	ret := make(map[string]bool)
	if ns := i.getNs(obj); ns != nil {
		ret[*ns] = true
	} else if nsSelector := i.getNsSelector(obj); nsSelector != nil {
		cache.ListAll(i.namespaceInformer.GetStore(), nsSelector,
			func(nsobj interface{}) {
				ret[nsobj.(*v1.Namespace).ObjectMeta.Name] = true
			})
	}
	return ret
}

func (i *PodSelectorIndex) updateSelectorObjForNs(obj interface{},
	namespaces map[string]bool) map[string]bool {

	objkey := i.getKey(obj)
	if objkey == "" {
		i.log.Error("Could not create object key")
		return nil
	}

	matched := make(map[string]bool)
	updated := make(map[string]bool)

	i.objNsIndex[objkey] = namespaces
	if podSelector := i.getPodSelector(obj); podSelector != nil {
		for ns, _ := range namespaces {
			cache.ListAllByNamespace(i.podInformer.GetIndexer(), ns, podSelector,
				func(podobj interface{}) {
					pod := podobj.(*v1.Pod)
					podkey, err := cache.MetaNamespaceKeyFunc(pod)
					if err != nil {
						i.log.Error("Could not create pod key: ", err)
						return
					}

					podm, ok := i.podIndex[podkey]
					if !ok {
						podm = make(map[string]bool)
						i.podIndex[podkey] = podm
					}

					matched[podkey] = true
					if _, ok = podm[objkey]; !ok {
						podm[objkey] = true
						updated[podkey] = true
					}
				})
		}
	}

	// check for old matches that no longer apply
	for oldkey, _ := range i.objPodIndex[objkey] {
		if _, ok := matched[oldkey]; !ok {
			if podm, pok := i.podIndex[oldkey]; pok {
				delete(podm, objkey)
				if len(podm) == 0 {
					delete(i.podIndex, oldkey)
				}
			}
			updated[oldkey] = true
		}
	}
	i.objPodIndex[objkey] = matched
	return updated
}

// Call to update the index when the selector object's selector(s)
// change
func (i *PodSelectorIndex) UpdateSelectorObj(obj interface{}) {
	namespaces := i.getObjNamespaces(obj)
	updated := i.updateSelectorObjForNs(obj, namespaces)

	for key, _ := range updated {
		i.updatePod(key)
	}
}

// Call to update the index when the selector object is deleted
func (i *PodSelectorIndex) DeleteSelectorObj(obj interface{}) {
	var updated []string

	objkey := i.getKey(obj)
	if objkey == "" {
		i.log.Error("Could not create object key")
		return
	}

	i.indexMutex.Lock()
	for oldkey, _ := range i.objPodIndex[objkey] {
		if podm, pok := i.podIndex[oldkey]; pok {
			delete(podm, objkey)
			if len(podm) == 0 {
				delete(i.podIndex, oldkey)
			}
			updated = append(updated, oldkey)
		}
	}
	delete(i.objPodIndex, objkey)
	delete(i.objNsIndex, objkey)
	i.indexMutex.Unlock()

	for _, key := range updated {
		i.updatePod(key)
	}
}
