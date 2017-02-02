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

package main

import (
	"sync"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"github.com/noironetworks/aci-containers/metadata"
)

type aciController struct {
	config *controllerConfig

	defaultEg  string
	defaultSg  string
	indexMutex sync.Mutex
	depPods    map[string]string

	kubeClient         *kubernetes.Clientset
	namespaceInformer  cache.SharedIndexInformer
	podInformer        cache.SharedIndexInformer
	endpointsInformer  cache.SharedIndexInformer
	serviceInformer    cache.SharedIndexInformer
	deploymentInformer cache.SharedIndexInformer
	nodeInformer       cache.SharedIndexInformer

	configuredPodNetworkIps *netIps
	podNetworkIps           *netIps
	serviceIps              *netIps
	staticServiceIps        *netIps
	nodeServiceIps          *netIps

	nodeServiceMetaCache map[string]*nodeServiceMeta
	nodePodNetCache      map[string]*nodePodNetMeta
	nodequeue            chan string
}

type nodeServiceMeta struct {
	serviceEp           metadata.ServiceEndpoint
	serviceEpAnnotation string
}

type nodePodNetMeta struct {
	nodePods            map[string]bool
	podNetIps           metadata.NetIps
	podNetIpsAnnotation string
}

func newNodePodNetMeta() *nodePodNetMeta {
	return &nodePodNetMeta{
		nodePods: make(map[string]bool),
	}
}

func newController() *aciController {
	return &aciController{
		config:    newConfig(),
		defaultEg: "",
		defaultSg: "",
		depPods:   make(map[string]string),

		configuredPodNetworkIps: newNetIps(),
		podNetworkIps:           newNetIps(),
		serviceIps:              newNetIps(),
		staticServiceIps:        newNetIps(),
		nodeServiceIps:          newNetIps(),

		nodeServiceMetaCache: make(map[string]*nodeServiceMeta),
		nodePodNetCache:      make(map[string]*nodePodNetMeta),
		nodequeue:            make(chan string),
	}
}
