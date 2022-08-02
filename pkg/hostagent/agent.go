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
	"net"
	"sync"
	"time"

	"github.com/containernetworking/cni/pkg/types"
	crdclientset "github.com/noironetworks/aci-containers/pkg/gbpcrd/clientset/versioned"
	aciv1 "github.com/noironetworks/aci-containers/pkg/gbpcrd/clientset/versioned/typed/acipolicy/v1"
	"github.com/noironetworks/aci-containers/pkg/index"
	"github.com/noironetworks/aci-containers/pkg/ipam"
	md "github.com/noironetworks/aci-containers/pkg/metadata"
	nodepodifclset "github.com/noironetworks/aci-containers/pkg/nodepodif/clientset/versioned"
	nodepodifv1 "github.com/noironetworks/aci-containers/pkg/nodepodif/clientset/versioned/typed/acipolicy/v1"
	snatpolicy "github.com/noironetworks/aci-containers/pkg/snatpolicy/apis/aci.snat/v1"
	"github.com/noironetworks/aci-containers/pkg/util"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/time/rate"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

type HostAgent struct {
	log    *logrus.Logger
	config *HostAgentConfig
	env    Environment

	indexMutex           sync.Mutex
	ipamMutex            sync.Mutex
	snatPolicyLabelMutex sync.RWMutex
	snatPolicyCacheMutex sync.RWMutex

	opflexEps             map[string][]*opflexEndpoint
	opflexServices        map[string]*opflexService
	epMetadata            map[string]map[string]*md.ContainerMetadata
	podIpToName           map[string]string
	cniToPodID            map[string]string
	podUidToName          map[string]string
	podToNetAttachDef     map[string][]string
	serviceEp             md.ServiceEndpoint
	crdClient             aciv1.AciV1Interface
	nodePodIFClient       nodepodifv1.AciV1Interface
	podInformer           cache.SharedIndexInformer
	endpointsInformer     cache.SharedIndexInformer
	serviceInformer       cache.SharedIndexInformer
	nodeInformer          cache.SharedIndexInformer
	nsInformer            cache.SharedIndexInformer
	netPolInformer        cache.SharedIndexInformer
	depInformer           cache.SharedIndexInformer
	rcInformer            cache.SharedIndexInformer
	snatGlobalInformer    cache.SharedIndexInformer
	controllerInformer    cache.SharedIndexInformer
	snatPolicyInformer    cache.SharedIndexInformer
	qosPolicyInformer     cache.SharedIndexInformer
	rdConfigInformer      cache.SharedIndexInformer
	qosPolPods            *index.PodSelectorIndex
	endpointSliceInformer cache.SharedIndexInformer
	netPolPods            *index.PodSelectorIndex
	depPods               *index.PodSelectorIndex
	rcPods                *index.PodSelectorIndex
	podNetAnnotation      string
	podIps                *ipam.IpCache
	usedIPs               map[string]string
	netAttDefInformer     cache.SharedIndexInformer

	syncEnabled         bool
	opflexConfigWritten bool
	syncQueue           workqueue.RateLimitingInterface
	syncProcessors      map[string]func() bool

	ignoreOvsPorts        map[string][]string
	netNsFuncChan         chan func()
	vtepIP                string
	gbpServerIP           string
	opflexSnatGlobalInfos map[string][]*opflexSnatGlobalInfo
	opflexSnatLocalInfos  map[string]*opflexSnatLocalInfo
	//snatpods per snat policy
	snatPods map[string]map[string]ResourceType
	//Object Key and list of labels active for snatpolicy
	snatPolicyLabels map[string]map[string]ResourceType
	snatPolicyCache  map[string]*snatpolicy.SnatPolicy
	rdConfig         *opflexRdConfig
	poster           *EventPoster
	ocServices       []opflexOcService // OpenShiftservices
	serviceEndPoints ServiceEndPointType
	// Service to pod uids to track EPfiles aded with clusterIp
	servicetoPodUids map[string]map[string]struct{}
	// reverse map to get ServiceIp's from poduid
	podtoServiceUids map[string]map[string]string
	nodePodIfEPs     map[string]*opflexEndpoint
	// integration test checker
	integ_test *string `json:",omitempty"`
	//network attachment definition map
	netattdefmap map[string]*NetworkAttachmentData
	deviceIdMap  map[string][]string
}

type ServiceEndPointType interface {
	InitClientInformer(kubeClient *kubernetes.Clientset)
	Run(stopCh <-chan struct{})
	SetOpflexService(ofas *opflexService, as *v1.Service,
		external bool, key string, sp v1.ServicePort) bool
}

type serviceEndpoint struct {
	agent *HostAgent
}
type serviceEndpointSlice struct {
	agent *HostAgent
}

func (sep *serviceEndpoint) InitClientInformer(kubeClient *kubernetes.Clientset) {
	sep.agent.initEndpointsInformerFromClient(kubeClient)
}

func (seps *serviceEndpointSlice) InitClientInformer(kubeClient *kubernetes.Clientset) {
	seps.agent.initEndpointSliceInformerFromClient(kubeClient)
}

func (sep *serviceEndpoint) Run(stopCh <-chan struct{}) {
	go sep.agent.endpointsInformer.Run(stopCh)
	cache.WaitForCacheSync(stopCh, sep.agent.endpointsInformer.HasSynced)
}

func (seps *serviceEndpointSlice) Run(stopCh <-chan struct{}) {
	go seps.agent.endpointSliceInformer.Run(stopCh)
	cache.WaitForCacheSync(stopCh, seps.agent.endpointSliceInformer.HasSynced)
}

func NewHostAgent(config *HostAgentConfig, env Environment, log *logrus.Logger) *HostAgent {
	ha := &HostAgent{
		log:            log,
		config:         config,
		env:            env,
		opflexEps:      make(map[string][]*opflexEndpoint),
		opflexServices: make(map[string]*opflexService),
		epMetadata:     make(map[string]map[string]*md.ContainerMetadata),
		podIpToName:    make(map[string]string),
		cniToPodID:     make(map[string]string),
		podUidToName:   make(map[string]string),
		nodePodIfEPs:   make(map[string]*opflexEndpoint),

		podIps: ipam.NewIpCache(),

		ignoreOvsPorts: make(map[string][]string),

		netNsFuncChan:         make(chan func()),
		opflexSnatGlobalInfos: make(map[string][]*opflexSnatGlobalInfo),
		opflexSnatLocalInfos:  make(map[string]*opflexSnatLocalInfo),
		snatPods:              make(map[string]map[string]ResourceType),
		snatPolicyLabels:      make(map[string]map[string]ResourceType),
		snatPolicyCache:       make(map[string]*snatpolicy.SnatPolicy),
		servicetoPodUids:      make(map[string]map[string]struct{}),
		podtoServiceUids:      make(map[string]map[string]string),
		netattdefmap:          make(map[string]*NetworkAttachmentData),
		deviceIdMap:           make(map[string][]string),
		podToNetAttachDef:     make(map[string][]string),
		syncQueue: workqueue.NewNamedRateLimitingQueue(
			&workqueue.BucketRateLimiter{
				Limiter: rate.NewLimiter(rate.Limit(10), int(10)),
			}, "sync"),
		ocServices: []opflexOcService{
			{
				RouterInternalDefault,
				OpenShiftIngressNs,
			},
		},
	}

	ha.syncProcessors = map[string]func() bool{
		"eps":           ha.syncEps,
		"services":      ha.syncServices,
		"opflexServer":  ha.syncOpflexServer,
		"snat":          ha.syncSnat,
		"snatnodeInfo":  ha.syncSnatNodeInfo,
		"rdconfig":      ha.syncRdConfig,
		"snatLocalInfo": ha.UpdateLocalInfoCr,
		"nodepodifs":    ha.syncNodePodIfs}

	if ha.config.EPRegistry == "k8s" {
		cfg, err := rest.InClusterConfig()
		if err != nil {
			log.Errorf("ERROR getting cluster config: %v", err)
			return ha
		}
		aciawClient, err := crdclientset.NewForConfig(cfg)
		if err != nil {
			log.Errorf("ERROR getting crd client for registry: %v", err)
			return ha
		}
		ha.crdClient = aciawClient.AciV1()
	}
	if ha.config.EnableNodePodIF {
		cfg, err := rest.InClusterConfig()
		if err != nil {
			log.Errorf("ERROR getting cluster config: %v", err)
			return ha
		}
		nodepodifClient, err := nodepodifclset.NewForConfig(cfg)
		if err != nil {
			log.Errorf("ERROR getting nodepodif client for enabling NodePodIF: %v", err)
			return ha
		}
		ha.nodePodIFClient = nodepodifClient.AciV1()
	}
	return ha
}

func addPodRoute(ipn types.IPNet, dev string, src string) error {
	link, err := netlink.LinkByName(dev)
	if err != nil {
		return err
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return err
	}
	ipsrc := net.ParseIP(src)
	dst := &net.IPNet{
		IP:   ipn.IP,
		Mask: ipn.Mask,
	}
	route := netlink.Route{LinkIndex: link.Attrs().Index, Dst: dst, Src: ipsrc}
	return netlink.RouteAdd(&route)
}

func (agent *HostAgent) ReadSnatPolicyLabel(key string) (map[string]ResourceType, bool) {
	agent.snatPolicyLabelMutex.RLock()
	defer agent.snatPolicyLabelMutex.RUnlock()
	value, ok := agent.snatPolicyLabels[key]
	return value, ok
}

func (agent *HostAgent) WriteSnatPolicyLabel(key string, policy string, res ResourceType) {
	agent.snatPolicyLabelMutex.Lock()
	defer agent.snatPolicyLabelMutex.Unlock()
	agent.snatPolicyLabels[key][policy] = res
}

func (agent *HostAgent) WriteNewSnatPolicyLabel(key string) {
	agent.snatPolicyLabelMutex.Lock()
	defer agent.snatPolicyLabelMutex.Unlock()
	agent.snatPolicyLabels[key] = make(map[string]ResourceType)
}

func (agent *HostAgent) DeleteSnatPolicyLabelEntry(key string, policy string) {
	agent.snatPolicyLabelMutex.Lock()
	defer agent.snatPolicyLabelMutex.Unlock()
	delete(agent.snatPolicyLabels[key], policy)
}

func (agent *HostAgent) DeleteSnatPolicyLabel(key string) {
	agent.snatPolicyLabelMutex.Lock()
	defer agent.snatPolicyLabelMutex.Unlock()
	delete(agent.snatPolicyLabels, key)
}

func (agent *HostAgent) DeleteMatchingSnatPolicyLabel(policy string) {
	agent.snatPolicyLabelMutex.Lock()
	defer agent.snatPolicyLabelMutex.Unlock()
	for key, v := range agent.snatPolicyLabels {
		if _, ok := v[policy]; ok {
			delete(agent.snatPolicyLabels[key], policy)
		}
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
	agent.buildUsedIPs()
	// check if the cluster supports endpoint slices
	// if cluster doesn't have the support fallback to endpoints
	kubeClient := agent.env.(*K8sEnvironment).kubeClient
	if util.IsEndPointSlicesSupported(kubeClient) {
		agent.serviceEndPoints = &serviceEndpointSlice{}
		agent.serviceEndPoints.(*serviceEndpointSlice).agent = agent
		agent.log.Info("Initializing ServiceEndpointSlices")
	} else {
		agent.serviceEndPoints = &serviceEndpoint{}
		agent.serviceEndPoints.(*serviceEndpoint).agent = agent
		agent.log.Info("Initializing ServiceEndpoints")
	}
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
	agent.scheduleSyncNodePodIfs()
}

func (agent *HostAgent) scheduleSyncServices() {
	agent.ScheduleSync("services")
}

func (agent *HostAgent) scheduleSyncSnats() {
	agent.ScheduleSync("snat")
}

func (agent *HostAgent) scheduleSyncOpflexServer() {
	agent.ScheduleSync("opflexServer")
}
func (agent *HostAgent) scheduleSyncNodeInfo() {
	agent.ScheduleSync("snatnodeInfo")
}
func (agent *HostAgent) scheduleSyncRdConfig() {
	agent.ScheduleSync("rdconfig")
}
func (agent *HostAgent) scheduleSyncLocalInfo() {
	agent.ScheduleSync("snatLocalInfo")
}
func (agent *HostAgent) scheduleSyncNodePodIfs() {
	agent.ScheduleSync("nodepodifs")
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
		agent.scheduleSyncNodeInfo()
		agent.scheduleSyncNodePodIfs()
	}
	return
}

func (agent *HostAgent) Run(stopCh <-chan struct{}) {
	err := agent.populateSnatLocalInfos()
	if err != nil {
		agent.log.Error("Failed to populate opflexSnatLocalInfos ", err.Error())
		panic(err.Error())
	}
	syncEnabled, err := agent.env.PrepareRun(stopCh)
	if err != nil {
		panic(err.Error())
	}
	if agent.config.OpFlexEndpointDir == "" ||
		agent.config.OpFlexServiceDir == "" ||
		agent.config.OpFlexSnatDir == "" {
		agent.log.Warn("OpFlex endpoint,service or snat directories not set")

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
