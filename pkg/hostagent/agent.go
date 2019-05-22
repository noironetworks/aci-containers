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

	"github.com/noironetworks/aci-containers/pkg/index"
	"github.com/noironetworks/aci-containers/pkg/ipam"
	md "github.com/noironetworks/aci-containers/pkg/metadata"
)

type HostAgent struct {
	log    *logrus.Logger
	config *HostAgentConfig
	env    Environment

	indexMutex sync.Mutex
	ipamMutex  sync.Mutex

	opflexEps      map[string][]*opflexEndpoint
	opflexServices map[string]*opflexService
	epMetadata     map[string]map[string]*md.ContainerMetadata
	cniToPodID     map[string]string
	serviceEp      md.ServiceEndpoint

	podInformer        cache.SharedIndexInformer
	endpointsInformer  cache.SharedIndexInformer
	serviceInformer    cache.SharedIndexInformer
	nodeInformer       cache.SharedIndexInformer
	nsInformer         cache.SharedIndexInformer
	netPolInformer     cache.SharedIndexInformer
	depInformer        cache.SharedIndexInformer
	rcInformer         cache.SharedIndexInformer
	snatLocalInformer  cache.SharedIndexInformer
	snatGlobalInformer cache.SharedIndexInformer
	netPolPods         *index.PodSelectorIndex
	depPods            *index.PodSelectorIndex
	rcPods             *index.PodSelectorIndex
	podNetAnnotation   string
	podIps             *ipam.IpCache
	usedIPs            map[string]bool

	syncEnabled         bool
	opflexConfigWritten bool
	syncQueue           workqueue.RateLimitingInterface
	syncProcessors      map[string]func() bool

	ignoreOvsPorts        map[string][]string
	opflexSnatLocalInfos  map[string]*OpflexSnatLocalInfo
	opflexSnatGlobalInfos map[string][]*OpflexSnatGlobalInfo
	netNsFuncChan         chan func()
}

func NewHostAgent(config *HostAgentConfig, env Environment, log *logrus.Logger) *HostAgent {
	ha := &HostAgent{
		log:            log,
		config:         config,
		env:            env,
		opflexEps:      make(map[string][]*opflexEndpoint),
		opflexServices: make(map[string]*opflexService),
		epMetadata:     make(map[string]map[string]*md.ContainerMetadata),
		cniToPodID:     make(map[string]string),

		podIps: ipam.NewIpCache(),

		ignoreOvsPorts: make(map[string][]string),

		netNsFuncChan:         make(chan func()),
		opflexSnatLocalInfos:  make(map[string]*OpflexSnatLocalInfo),
		opflexSnatGlobalInfos: make(map[string][]*OpflexSnatGlobalInfo),
		syncQueue: workqueue.NewNamedRateLimitingQueue(
			&workqueue.BucketRateLimiter{
				Bucket: ratelimit.NewBucketWithRate(float64(10), int64(10)),
			}, "sync"),
	}
	ha.syncProcessors = map[string]func() bool{
		"eps":      ha.syncEps,
		"services": ha.syncServices,
		"snat":     ha.syncSnat}
	return ha
}

func (agent *HostAgent) Init() {
	agent.log.Debug("Initializing endpoint CNI metadata")
	err := md.LoadMetadata(agent.config.CniMetadataDir,
		agent.config.CniNetwork, &agent.epMetadata)
	if err != nil {
		panic(err.Error())
	}
	agent.log.Info("Loaded cached endpoint CNI metadata: ", len(agent.epMetadata))
	agent.buildUsedIPs()

	err = agent.env.Init(agent)
	if err != nil {
		panic(err.Error())
	}
}

func (agent *HostAgent) ScheduleSync(syncType string) {
	agent.syncQueue.AddRateLimited(syncType)
}

func (agent *HostAgent) scheduleSyncEps() {
	agent.ScheduleSync("eps")
}

func (agent *HostAgent) scheduleSyncServices() {
	agent.ScheduleSync("services")
}

func (agent *HostAgent) scheduleSyncSnats() {
	agent.ScheduleSync("snat")
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
				if f, ok := agent.syncProcessors[syncType]; ok {
					requeue = f()
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

func (agent *HostAgent) EnableSync() (changed bool) {
	changed = false
	agent.indexMutex.Lock()
	if agent.syncEnabled == false {
		agent.syncEnabled = true
		changed = true
	}
	agent.indexMutex.Unlock()
	if changed {
		agent.log.Info("Enabling OpFlex endpoint and service sync")
		agent.scheduleSyncServices()
		agent.scheduleSyncEps()
		agent.scheduleSyncSnats()
	}
	return
}

func (agent *HostAgent) Run(stopCh <-chan struct{}) {
	syncEnabled, err := agent.env.PrepareRun(stopCh)
	if err != nil {
		panic(err.Error())
	}

	if agent.config.OpFlexEndpointDir == "" ||
		agent.config.OpFlexServiceDir == "" ||
		agent.config.OpFlexSnatDir == "" {
		agent.log.Warn("OpFlex endpoint and service directories not set")
	} else {
		if syncEnabled {
			agent.EnableSync()
		}
		go agent.processSyncQueue(agent.syncQueue, stopCh)
	}

	agent.log.Info("Starting endpoint RPC")
	err = agent.runEpRPC(stopCh)
	if err != nil {
		panic(err.Error())
	}

	agent.cleanupSetup()
}
