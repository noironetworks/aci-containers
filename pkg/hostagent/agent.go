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
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"github.com/noironetworks/aci-containers/pkg/ipam"
	md "github.com/noironetworks/aci-containers/pkg/metadata"
)

type HostAgent struct {
	log    *logrus.Logger
	config *HostAgentConfig
	env    Environment

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
	podIps           *ipam.IpCache

	syncEnabled         bool
	opflexConfigWritten bool
	syncQueue           workqueue.RateLimitingInterface

	ignoreOvsPorts map[string][]string

	netNsFuncChan chan func()
}

func NewHostAgent(config *HostAgentConfig, env Environment, log *logrus.Logger) *HostAgent {
	return &HostAgent{
		log:            log,
		config:         config,
		env:            env,
		opflexEps:      make(map[string][]*opflexEndpoint),
		opflexServices: make(map[string]*opflexService),
		epMetadata:     make(map[string]map[string]*md.ContainerMetadata),

		podIps: ipam.NewIpCache(),

		ignoreOvsPorts: make(map[string][]string),

		netNsFuncChan: make(chan func()),
		syncQueue: workqueue.NewNamedRateLimitingQueue(
			&workqueue.BucketRateLimiter{
				Bucket: ratelimit.NewBucketWithRate(float64(10), int64(10)),
			}, "sync"),
	}
}

func (agent *HostAgent) Init() {
	agent.log.Debug("Initializing endpoint CNI metadata")
	err := md.LoadMetadata(agent.config.CniMetadataDir,
		agent.config.CniNetwork, &agent.epMetadata)
	if err != nil {
		panic(err.Error())
	}
	agent.log.Info("Loaded cached endpoint CNI metadata: ", len(agent.epMetadata))

	err = agent.env.Init(agent)
	if err != nil {
		panic(err.Error())
	}
}

func (agent *HostAgent) scheduleSyncEps() {
	agent.syncQueue.AddRateLimited("eps")
}

func (agent *HostAgent) scheduleSyncServices() {
	agent.syncQueue.AddRateLimited("services")
}

func (agent *HostAgent) runTickers(stopCh <-chan struct{}) {
	ticker := time.NewTicker(time.Second * 30)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			agent.updateOpflexConfig()
		case <-stopCh:
			return
		}
	}
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
	err := agent.env.PrepareRun(stopCh)
	if err != nil {
		panic(err.Error())
	}

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
	err = agent.runEpRPC(stopCh)
	if err != nil {
		panic(err.Error())
	}

	agent.cleanupSetup()
}
