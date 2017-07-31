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

package hostagent

import (
	"sync"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/juju/ratelimit"

	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"github.com/noironetworks/aci-containers/pkg/ipam"
	md "github.com/noironetworks/aci-containers/pkg/metadata"
)

type HostAgent struct {
	log    *logrus.Logger
	config *HostAgentConfig

	indexMutex sync.Mutex

	opflexEps      map[string][]*opflexEndpoint
	opflexServices map[string]*opflexService
	epMetadata     map[string]map[string]*md.ContainerMetadata
	serviceEp      md.ServiceEndpoint

	podInformer       cache.SharedIndexInformer
	endpointsInformer cache.SharedIndexInformer
	serviceInformer   cache.SharedIndexInformer
	nodeInformer      cache.SharedIndexInformer

	podNetAnnotation string
	podIpsV4         []*ipam.IpAlloc
	podIpsV6         []*ipam.IpAlloc

	syncEnabled         bool
	opflexConfigWritten bool
	syncQueue           workqueue.RateLimitingInterface

	netNsFuncChan chan func()
}

func NewHostAgent(config *HostAgentConfig, log *logrus.Logger) *HostAgent {
	return &HostAgent{
		log:            log,
		config:         config,
		opflexEps:      make(map[string][]*opflexEndpoint),
		opflexServices: make(map[string]*opflexService),
		epMetadata:     make(map[string]map[string]*md.ContainerMetadata),

		podIpsV4: []*ipam.IpAlloc{ipam.New(), ipam.New()},
		podIpsV6: []*ipam.IpAlloc{ipam.New(), ipam.New()},

		netNsFuncChan: make(chan func()),
		syncQueue: workqueue.NewNamedRateLimitingQueue(
			&workqueue.BucketRateLimiter{
				Bucket: ratelimit.NewBucketWithRate(float64(10), int64(10)),
			}, "sync"),
	}
}

func (agent *HostAgent) Init(kubeClient *kubernetes.Clientset) {
	agent.log.Debug("Initializing endpoint CNI metadata")
	err := md.LoadMetadata(agent.config.CniMetadataDir,
		agent.config.CniNetwork, &agent.epMetadata)
	if err != nil {
		panic(err.Error())
	}
	agent.log.Info("Loaded cached endpoint CNI metadata: ", len(agent.epMetadata))

	agent.log.Debug("Initializing informers")
	agent.initNodeInformerFromClient(kubeClient)
	agent.initPodInformerFromClient(kubeClient)
	agent.initEndpointsInformerFromClient(kubeClient)
	agent.initServiceInformerFromClient(kubeClient)
}

func (agent *HostAgent) scheduleSyncEps() {
	agent.syncQueue.AddRateLimited("eps")
}

func (agent *HostAgent) scheduleSyncServices() {
	agent.syncQueue.AddRateLimited("services")
}

func (agent *HostAgent) processSyncQueue(queue workqueue.RateLimitingInterface,
	queueStop <-chan struct{}) {

	go wait.Until(func() {
		for {
			syncType, quit := queue.Get()
			if quit {
				break
			}

			var requeue bool
			switch syncType := syncType.(type) {
			case string:
				switch syncType {
				case "eps":
					requeue = agent.syncEps()
				case "services":
					requeue = agent.syncServices()
				}
			}
			if requeue {
				queue.AddRateLimited(syncType)
			} else {
				queue.Forget(syncType)
			}
			queue.Done(syncType)

		}
	}, time.Second, queueStop)
	<-queueStop
	queue.ShutDown()
}

func (agent *HostAgent) Run(stopCh <-chan struct{}) {
	agent.log.Debug("Starting node informer")
	go agent.nodeInformer.Run(stopCh)

	agent.log.Info("Waiting for node cache sync")
	cache.WaitForCacheSync(stopCh, agent.nodeInformer.HasSynced)
	agent.log.Info("Node cache sync successful")

	agent.log.Debug("Starting remaining informers")
	go agent.podInformer.Run(stopCh)
	go agent.endpointsInformer.Run(stopCh)
	go agent.serviceInformer.Run(stopCh)

	agent.log.Info("Waiting for cache sync for remaining objects")
	cache.WaitForCacheSync(stopCh,
		agent.podInformer.HasSynced, agent.endpointsInformer.HasSynced,
		agent.serviceInformer.HasSynced)
	agent.log.Info("Cache sync successful")

	agent.log.Debug("Building IP address management database")
	agent.rebuildIpam()

	if agent.config.OpFlexEndpointDir == "" ||
		agent.config.OpFlexServiceDir == "" {
		agent.log.Warn("OpFlex endpoint and service directories not set")
	} else {
		agent.log.Info("Enabling OpFlex endpoint and service sync")
		agent.indexMutex.Lock()
		agent.syncEnabled = true
		agent.indexMutex.Unlock()

		agent.scheduleSyncServices()
		agent.scheduleSyncEps()
		go agent.processSyncQueue(agent.syncQueue, stopCh)
	}

	agent.log.Info("Starting endpoint RPC")
	err := agent.runEpRPC(stopCh)
	if err != nil {
		panic(err.Error())
	}

	agent.cleanupSetup()
}
