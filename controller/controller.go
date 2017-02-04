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
	"encoding/json"
	"sync"

	"k8s.io/apimachinery/pkg/util/wait"
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

func newController(config *controllerConfig) *aciController {
	return &aciController{
		config:    config,
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

func (cont *aciController) init(kubeClient *kubernetes.Clientset) {
	egdata, err := json.Marshal(cont.config.DefaultEg)
	if err != nil {
		log.Error("Could not serialize default endpoint group")
		panic(err.Error())
	}
	cont.defaultEg = string(egdata)

	sgdata, err := json.Marshal(cont.config.DefaultSg)
	if err != nil {
		log.Error("Could not serialize default security groups")
		panic(err.Error())
	}
	cont.defaultSg = string(sgdata)

	log.Debug("Initializing IPAM")
	cont.initIpam()

	log.Debug("Initializing informers")
	cont.kubeClient = kubeClient
	cont.initNodeInformerFromClient(kubeClient)
	cont.initNamespaceInformerFromClient(kubeClient)
	cont.initDeploymentInformerFromClient(kubeClient)
	cont.initPodInformerFromClient(kubeClient)
	cont.initEndpointsInformerFromClient(kubeClient)
	cont.initServiceInformerFromClient(kubeClient)
}

func (cont *aciController) run() {
	log.Debug("Starting informers")
	go cont.namespaceInformer.Run(wait.NeverStop)
	go cont.nodeInformer.Run(wait.NeverStop)
	go cont.deploymentInformer.Run(wait.NeverStop)
	go cont.podInformer.Run(wait.NeverStop)
	go cont.endpointsInformer.Run(wait.NeverStop)
	go cont.serviceInformer.Run(wait.NeverStop)

	go cont.processNodeQueue()
}
