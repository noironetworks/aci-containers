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

// Handlers for namespace updates.  Keeps an index of namespace
// annotations

package main

import (
	"k8s.io/kubernetes/pkg/api"
)

func namespaceUpdated(_ interface{}, obj interface{}) {
	namespaceChanged(obj)
}

func namespaceChanged(obj interface{}) {
	indexMutex.Lock()
	defer indexMutex.Unlock()

	ns := obj.(*api.Namespace)

	pods := podInformer.GetStore().List()
	for _, podobj := range pods {
		pod := podobj.(*api.Pod)
		if !podFilter(pod) {
			continue
		}

		if ns.Name == pod.ObjectMeta.Namespace {
			podChangedLocked(pod)
		}
	}
}
