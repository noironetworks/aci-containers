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

	"github.com/noironetworks/aci-containers/ipam"
	md "github.com/noironetworks/aci-containers/metadata"
)

type hostAgent struct {
	config *hostAgentConfig

	indexMutex sync.Mutex

	opflexEps      map[string]*opflexEndpoint
	opflexServices map[string]*opflexService
	epMetadata     map[string]*md.ContainerMetadata
	serviceEp      md.ServiceEndpoint

	podInformer       cache.SharedIndexInformer
	endpointsInformer cache.SharedIndexInformer
	serviceInformer   cache.SharedIndexInformer
	nodeInformer      cache.SharedIndexInformer

	podNetAnnotation string
	podIpsV4         *ipam.IpAlloc
	podIpsV6         *ipam.IpAlloc

	syncEnabled bool
}

func newHostAgent(config *hostAgentConfig) *hostAgent {
	return &hostAgent{
		config:         config,
		opflexEps:      make(map[string]*opflexEndpoint),
		opflexServices: make(map[string]*opflexService),
		epMetadata:     make(map[string]*md.ContainerMetadata),

		podIpsV4: ipam.New(),
		podIpsV6: ipam.New(),
	}
}

func (agent *hostAgent) init(kubeClient *kubernetes.Clientset) {
	log.Debug("Initializing endpoint CNI metadata")
	err := md.LoadMetadata(agent.config.CniMetadataDir,
		agent.config.CniNetwork, &agent.epMetadata)
	if err != nil {
		panic(err.Error())
	}
	log.Info("Loaded cached endpoint CNI metadata: ", len(agent.epMetadata))

	log.Debug("Initializing informers")
	agent.initNodeInformerFromClient(kubeClient)
	agent.initPodInformerFromClient(kubeClient)
	agent.initEndpointsInformerFromClient(kubeClient)
	agent.initServiceInformerFromClient(kubeClient)
}

func (agent *hostAgent) run(stopCh <-chan struct{}) {
	log.Debug("Starting node informer")
	go agent.nodeInformer.Run(stopCh)

	log.Debug("Waiting for node cache sync")
	cache.WaitForCacheSync(stopCh, agent.nodeInformer.HasSynced)
	log.Debug("Node cache sync successful")

	log.Debug("Starting remaining informers")
	go agent.podInformer.Run(stopCh)
	go agent.endpointsInformer.Run(stopCh)
	go agent.serviceInformer.Run(stopCh)

	log.Debug("Waiting for cache sync for remaining objects")
	cache.WaitForCacheSync(stopCh,
		agent.podInformer.HasSynced, agent.endpointsInformer.HasSynced,
		agent.serviceInformer.HasSynced)

	if agent.config.OpFlexEndpointDir == "" ||
		agent.config.OpFlexServiceDir == "" {
		log.Warn("OpFlex endpoint and service directories not set")
	} else {
		log.Info("Enabling OpFlex endpoint and service sync")
		agent.indexMutex.Lock()
		agent.syncEnabled = true
		agent.syncServices()
		agent.syncEps()
		agent.indexMutex.Unlock()
		log.Debug("Initial OpFlex sync complete")
	}

	log.Debug("Starting endpoint RPC")
	err := agent.runEpRPC(stopCh)
	if err != nil {
		panic(err.Error())
	}

	agent.cleanupSetup()
}
