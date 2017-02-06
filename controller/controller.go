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

	"k8s.io/client-go/kubernetes"
	v1 "k8s.io/client-go/pkg/api/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/noironetworks/aci-containers/metadata"
)

type podUpdateFunc func(*v1.Pod) (*v1.Pod, error)
type nodeUpdateFunc func(*v1.Node) (*v1.Node, error)

type aciController struct {
	config *controllerConfig

	defaultEg  string
	defaultSg  string
	indexMutex sync.Mutex
	depPods    map[string]string

	namespaceInformer  cache.SharedIndexInformer
	podInformer        cache.SharedIndexInformer
	endpointsInformer  cache.SharedIndexInformer
	serviceInformer    cache.SharedIndexInformer
	deploymentInformer cache.SharedIndexInformer
	nodeInformer       cache.SharedIndexInformer

	updatePod  podUpdateFunc
	updateNode nodeUpdateFunc

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
	cont.updatePod = func(pod *v1.Pod) (*v1.Pod, error) {
		return kubeClient.CoreV1().Pods(pod.ObjectMeta.Namespace).Update(pod)
	}
	cont.updateNode = func(node *v1.Node) (*v1.Node, error) {
		return kubeClient.CoreV1().Nodes().Update(node)
	}

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
	cont.initNodeInformerFromClient(kubeClient)
	cont.initNamespaceInformerFromClient(kubeClient)
	cont.initDeploymentInformerFromClient(kubeClient)
	cont.initPodInformerFromClient(kubeClient)
	cont.initEndpointsInformerFromClient(kubeClient)
	cont.initServiceInformerFromClient(kubeClient)
}

func (cont *aciController) run(stopCh <-chan struct{}) {
	log.Debug("Starting informers")
	go cont.namespaceInformer.Run(stopCh)
	go cont.nodeInformer.Run(stopCh)
	go cont.deploymentInformer.Run(stopCh)
	go cont.podInformer.Run(stopCh)
	go cont.endpointsInformer.Run(stopCh)
	go cont.serviceInformer.Run(stopCh)

	log.Debug("Starting node queue processor")
	go cont.processNodeQueue(stopCh)
}
