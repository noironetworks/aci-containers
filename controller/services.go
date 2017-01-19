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

package main

import (
	"github.com/Sirupsen/logrus"

	"k8s.io/kubernetes/pkg/api"
)

func serviceLogger(as *api.Service) *logrus.Entry {
	return log.WithFields(logrus.Fields{
		"namespace": as.ObjectMeta.Namespace,
		"name":      as.ObjectMeta.Name,
		"type":      as.Spec.Type,
	})
}

func endpointsUpdated(_ interface{}, obj interface{}) {
	endpointsChanged(obj)
}

func endpointsChanged(obj interface{}) {
	indexMutex.Lock()
	defer indexMutex.Unlock()

	//	endpoints := obj.(*api.Endpoints)
}

func serviceUpdated(_ interface{}, obj interface{}) {
	serviceAdded(obj)
}

func serviceAdded(obj interface{}) {
	indexMutex.Lock()
	defer indexMutex.Unlock()

	//as := obj.(*api.Service)
}

func serviceDeleted(obj interface{}) {
	indexMutex.Lock()
	defer indexMutex.Unlock()

	//as := obj.(*api.Service)
}
