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
	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/client/cache"
	clientset "k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset"
	"k8s.io/kubernetes/pkg/controller"
	"k8s.io/kubernetes/pkg/fields"
	"k8s.io/kubernetes/pkg/runtime"
	"k8s.io/kubernetes/pkg/util/wait"
	"k8s.io/kubernetes/pkg/watch"

	"github.com/noironetworks/aci-containers/metadata"
)

func initNodeInformer(kubeClient *clientset.Clientset) {
	nodeInformer = cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options api.ListOptions) (runtime.Object, error) {
				options.FieldSelector =
					fields.Set{"metadata.name": config.NodeName}.AsSelector()
				return kubeClient.Core().Nodes().List(options)
			},
			WatchFunc: func(options api.ListOptions) (watch.Interface, error) {
				options.FieldSelector =
					fields.Set{"metadata.name": config.NodeName}.AsSelector()
				return kubeClient.Core().Nodes().Watch(options)
			},
		},
		&api.Node{},
		controller.NoResyncPeriodFunc(),
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	nodeInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    nodeChanged,
		UpdateFunc: nodeUpdated,
		DeleteFunc: nodeDeleted,
	})

	go nodeInformer.GetController().Run(wait.NeverStop)
	go nodeInformer.Run(wait.NeverStop)
}

func nodeUpdated(_ interface{}, obj interface{}) {
	nodeChanged(obj)
}

func nodeChanged(obj interface{}) {
	indexMutex.Lock()

	node := obj.(*api.Node)
	if node.ObjectMeta.Name != config.NodeName {
		log.Error("Got incorrect node update for ", node.ObjectMeta.Name)
		return
	}

	pnet, ok := node.ObjectMeta.Annotations[metadata.PodNetworkRangeAnnotation]
	if ok {
		rebuildIpam(pnet)
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
	if !reflect.DeepEqual(newServiceEp, serviceEp) {
		serviceEp = newServiceEp
		indexMutex.Unlock()
		updateAllServices()
	} else {
		indexMutex.Unlock()
	}
}

func nodeDeleted(obj interface{}) {
	indexMutex.Lock()
	defer indexMutex.Unlock()

}
