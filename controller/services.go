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
	"k8s.io/kubernetes/pkg/client/cache"
	"k8s.io/kubernetes/pkg/controller"
	"k8s.io/kubernetes/pkg/runtime"
	"k8s.io/kubernetes/pkg/util/wait"
	"k8s.io/kubernetes/pkg/watch"
)

func initEndpointsInformer() {
	endpointsInformer = cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options api.ListOptions) (runtime.Object, error) {
				return kubeClient.Core().Endpoints(api.NamespaceAll).List(options)
			},
			WatchFunc: func(options api.ListOptions) (watch.Interface, error) {
				return kubeClient.Core().Endpoints(api.NamespaceAll).Watch(options)
			},
		},
		&api.Endpoints{},
		controller.NoResyncPeriodFunc(),
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	endpointsInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    endpointsChanged,
		UpdateFunc: endpointsUpdated,
		DeleteFunc: endpointsChanged,
	})

	go endpointsInformer.GetController().Run(wait.NeverStop)
	go endpointsInformer.Run(wait.NeverStop)
}

func initServiceInformer() {
	serviceInformer = cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options api.ListOptions) (runtime.Object, error) {
				return kubeClient.Core().Services(api.NamespaceAll).List(options)
			},
			WatchFunc: func(options api.ListOptions) (watch.Interface, error) {
				return kubeClient.Core().Services(api.NamespaceAll).Watch(options)
			},
		},
		&api.Service{},
		controller.NoResyncPeriodFunc(),
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	serviceInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    serviceAdded,
		UpdateFunc: serviceUpdated,
		DeleteFunc: serviceDeleted,
	})

	go serviceInformer.GetController().Run(wait.NeverStop)
	go serviceInformer.Run(wait.NeverStop)
}

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
