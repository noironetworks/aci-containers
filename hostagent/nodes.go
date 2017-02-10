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

// Handlers for node updates.

package main

import (
	"encoding/json"
	"reflect"

	"github.com/Sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	v1 "k8s.io/client-go/pkg/api/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/kubernetes/pkg/controller"

	"github.com/noironetworks/aci-containers/metadata"
)

func (agent *hostAgent) initNodeInformerFromClient(
	kubeClient *kubernetes.Clientset) {

	agent.initNodeInformerBase(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				options.FieldSelector =
					fields.Set{"metadata.name": agent.config.NodeName}.String()
				return kubeClient.Core().Nodes().List(options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				options.FieldSelector =
					fields.Set{"metadata.name": agent.config.NodeName}.String()
				return kubeClient.Core().Nodes().Watch(options)
			},
		})
}

func (agent *hostAgent) initNodeInformerBase(listWatch *cache.ListWatch) {
	agent.nodeInformer = cache.NewSharedIndexInformer(
		listWatch,
		&v1.Node{},
		controller.NoResyncPeriodFunc(),
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	agent.nodeInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			agent.nodeChanged(obj)
		},
		UpdateFunc: func(_ interface{}, obj interface{}) {
			agent.nodeChanged(obj)
		},
		DeleteFunc: func(obj interface{}) {
			agent.nodeDeleted(obj)
		},
	})
}

func (agent *hostAgent) nodeChanged(obj interface{}) {
	agent.indexMutex.Lock()

	node := obj.(*v1.Node)
	if node.ObjectMeta.Name != agent.config.NodeName {
		log.Error("Got incorrect node update for ", node.ObjectMeta.Name)
		return
	}

	pnet, ok := node.ObjectMeta.Annotations[metadata.PodNetworkRangeAnnotation]
	if ok {
		agent.rebuildIpam(pnet)
	}

	var newServiceEp metadata.ServiceEndpoint
	epval, ok := node.ObjectMeta.Annotations[metadata.ServiceEpAnnotation]
	if ok {
		err := json.Unmarshal([]byte(epval), &newServiceEp)
		if err != nil {
			log.WithFields(logrus.Fields{
				"epval": epval,
			}).Warn("Could not parse node ",
				"service endpoint annotation: ", err)
		}
	}
	if !reflect.DeepEqual(newServiceEp, agent.serviceEp) {
		log.WithFields(logrus.Fields{
			"epval": epval,
		}).Info("Updated service endpoint")
		agent.serviceEp = newServiceEp
		agent.indexMutex.Unlock()
		agent.updateAllServices()
	} else {
		agent.indexMutex.Unlock()
	}
}

func (agent *hostAgent) nodeDeleted(obj interface{}) {
	agent.indexMutex.Lock()
	defer agent.indexMutex.Unlock()

}
