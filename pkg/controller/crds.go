// Copyright 2020 Cisco Systems, Inc.
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

package controller

import (
	"github.com/noironetworks/metrics-poc/metrics"
	v1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	extv1 "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/typed/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/tools/cache"
)

func (cont *AciController) registerCRDHook(crdName string, h func(*AciController, <-chan struct{})) {
	cont.indexMutex.Lock()
	cont.crdHandlers[crdName] = h
	cont.indexMutex.Unlock()
}

func (cont *AciController) initCRDInformer() {

	restConfig := cont.env.RESTConfig()
	crdClient, _ := extv1.NewForConfig(restConfig)
	cont.initCRDInformerBase(
		cache.NewListWatchFromClient(
			crdClient.RESTClient(), "customresourcedefinitions",
			metav1.NamespaceAll, fields.Everything()))
}

func (cont *AciController) initCRDInformerBase(listWatch *cache.ListWatch) {
	_, cont.crdInformer = cache.NewInformer(
		listWatch, &v1.CustomResourceDefinition{}, 0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				crd, ok := obj.(*v1.CustomResourceDefinition)
				if !ok {
					cont.log.Errorf("Add CRD bad object")
					return
				}
				cont.crdAdded(crd)
				metrics.HandleK8sCRUDEvents(metrics.EventType_EVENT_ADD, obj)
			},
			UpdateFunc: func(oldobj interface{}, newobj interface{}) {
				metrics.HandleK8sCRUDEvents(metrics.EventType_EVENT_UPDATE, newobj)
			},
			DeleteFunc: func(obj interface{}) {
				metrics.HandleK8sCRUDEvents(metrics.EventType_EVENT_DELETE, obj)
			},
		},
	)
}

func (cont *AciController) crdAdded(crd *v1.CustomResourceDefinition) {
	cont.log.Infof("CRD %s added", crd.ObjectMeta.Name)
	cont.indexMutex.Lock()
	h := cont.crdHandlers[crd.ObjectMeta.Name]
	// handle only once
	delete(cont.crdHandlers, crd.ObjectMeta.Name)
	cont.indexMutex.Unlock()

	if h != nil {
		go h(cont, cont.stopCh)
	}
}
