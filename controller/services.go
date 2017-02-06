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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	v1 "k8s.io/client-go/pkg/api/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/kubernetes/pkg/controller"
)

func (cont *aciController) initEndpointsInformerFromClient(
	kubeClient kubernetes.Interface) {

	cont.initEndpointsInformerBase(&cache.ListWatch{
		ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
			return kubeClient.CoreV1().Endpoints(metav1.NamespaceAll).List(options)
		},
		WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
			return kubeClient.CoreV1().Endpoints(metav1.NamespaceAll).Watch(options)
		},
	})
}

func (cont *aciController) initEndpointsInformerBase(listWatch *cache.ListWatch) {
	cont.endpointsInformer = cache.NewSharedIndexInformer(
		listWatch,
		&v1.Endpoints{},
		controller.NoResyncPeriodFunc(),
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	cont.endpointsInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			cont.endpointsChanged(obj)
		},
		UpdateFunc: func(_ interface{}, obj interface{}) {
			cont.endpointsChanged(obj)
		},
		DeleteFunc: func(obj interface{}) {
			cont.endpointsChanged(obj)
		},
	})

}

func (cont *aciController) initServiceInformerFromClient(
	kubeClient *kubernetes.Clientset) {

	cont.initServiceInformerBase(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				return kubeClient.CoreV1().Services(metav1.NamespaceAll).List(options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				return kubeClient.CoreV1().Services(metav1.NamespaceAll).Watch(options)
			},
		})
}

func (cont *aciController) initServiceInformerBase(listWatch *cache.ListWatch) {
	cont.serviceInformer = cache.NewSharedIndexInformer(
		listWatch,
		&v1.Service{},
		controller.NoResyncPeriodFunc(),
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	cont.serviceInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			cont.serviceChanged(obj)
		},
		UpdateFunc: func(_ interface{}, obj interface{}) {
			cont.serviceChanged(obj)
		},
		DeleteFunc: func(obj interface{}) {
			cont.serviceDeleted(obj)
		},
	})
}

func serviceLogger(as *v1.Service) *logrus.Entry {
	return log.WithFields(logrus.Fields{
		"namespace": as.ObjectMeta.Namespace,
		"name":      as.ObjectMeta.Name,
		"type":      as.Spec.Type,
	})
}

func (cont *aciController) endpointsChanged(obj interface{}) {
	cont.indexMutex.Lock()
	defer cont.indexMutex.Unlock()

	//	endpoints := obj.(*v1.Endpoints)
}

func (cont *aciController) serviceChanged(obj interface{}) {
	cont.indexMutex.Lock()
	defer cont.indexMutex.Unlock()

	//as := obj.(*v1.Service)
}

func (cont *aciController) serviceDeleted(obj interface{}) {
	cont.indexMutex.Lock()
	defer cont.indexMutex.Unlock()

	//as := obj.(*v1.Service)
}
