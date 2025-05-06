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
	"context"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/containernetworking/cni/pkg/types"
	"github.com/fsnotify/fsnotify"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/time/rate"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	fabattclset "github.com/noironetworks/aci-containers/pkg/fabricattachment/clientset/versioned"
	fabattv1 "github.com/noironetworks/aci-containers/pkg/fabricattachment/clientset/versioned/typed/aci.fabricattachment/v1"
	crdclientset "github.com/noironetworks/aci-containers/pkg/gbpcrd/clientset/versioned"
	aciv1 "github.com/noironetworks/aci-containers/pkg/gbpcrd/clientset/versioned/typed/acipolicy/v1"
	"github.com/noironetworks/aci-containers/pkg/index"
	"github.com/noironetworks/aci-containers/pkg/ipam"
	md "github.com/noironetworks/aci-containers/pkg/metadata"
	nodepodifclset "github.com/noironetworks/aci-containers/pkg/nodepodif/clientset/versioned"
	nodepodifv1 "github.com/noironetworks/aci-containers/pkg/nodepodif/clientset/versioned/typed/acipolicy/v1"
	snatpolicy "github.com/noironetworks/aci-containers/pkg/snatpolicy/apis/aci.snat/v1"
	"github.com/noironetworks/aci-containers/pkg/util"
)

// Name of the taint set by Controller
const (
	ACIContainersTaintName string = "aci-containers-host/unavailable"
	ResolvedEpgsFile       string = "/usr/local/var/lib/opflex-agent-ovs/resolved-epgs/resolved-epgs.json"
)

var GbpConfig *GBPConfig

type HostAgent struct {
	log    *logrus.Logger
	config *HostAgentConfig
	env    Environment

	indexMutex           sync.Mutex
	vethMutex            sync.Mutex
	ipamMutex            sync.Mutex
	epfileMutex          sync.Mutex
	pendingEpMutex       sync.Mutex
	snatPolicyLabelMutex sync.RWMutex
	snatPolicyCacheMutex sync.RWMutex
	proactiveConfMutex   sync.Mutex

	opflexEps              map[string][]*opflexEndpoint
	opflexServices         map[string]*opflexService
	epMetadata             map[string]map[string]*md.ContainerMetadata
	podNetworkMetadata     map[string]map[string]map[string]*md.ContainerMetadata
	primaryNetworkName     string
	podIpToName            map[string]string
	cniToPodID             map[string]string
	podUidToName           map[string]string
	podToNetAttachDef      map[string][]string
	serviceEp              md.ServiceEndpoint
	crdClient              aciv1.AciV1Interface
	nodePodIFClient        nodepodifv1.AciV1Interface
	fabAttClient           fabattv1.AciV1Interface
	podInformer            cache.SharedIndexInformer
	endpointsInformer      cache.SharedIndexInformer
	serviceInformer        cache.SharedIndexInformer
	nodeInformer           cache.SharedIndexInformer
	nsInformer             cache.SharedIndexInformer
	netPolInformer         cache.SharedIndexInformer
	depInformer            cache.SharedIndexInformer
	rcInformer             cache.SharedIndexInformer
	snatGlobalInformer     cache.SharedIndexInformer
	controllerInformer     cache.SharedIndexInformer
	snatPolicyInformer     cache.SharedIndexInformer
	qosPolicyInformer      cache.SharedIndexInformer
	rdConfigInformer       cache.SharedIndexInformer
	qosPolPods             *index.PodSelectorIndex
	endpointSliceInformer  cache.SharedIndexInformer
	netPolPods             *index.PodSelectorIndex
	depPods                *index.PodSelectorIndex
	rcPods                 *index.PodSelectorIndex
	podNetAnnotation       string
	aciPodAnnotation       string
	nodeAciPodAnnotation   string
	podIps                 *ipam.IpCache
	usedIPs                map[string]string
	netAttDefInformer      cache.SharedIndexInformer
	nadVlanMapInformer     cache.SharedIndexInformer
	fabricVlanPoolInformer cache.SharedIndexInformer
	hppInformer            cache.SharedIndexInformer
	hppRemoteIpInformer    cache.SharedIndexInformer
	hppMoIndex             map[string][]*gbpBaseMo
	proactiveConfInformer  cache.SharedIndexInformer

	syncEnabled         bool
	opflexConfigWritten bool
	syncQueue           workqueue.RateLimitingInterface
	epSyncQueue         workqueue.RateLimitingInterface
	portSyncQueue       workqueue.RateLimitingInterface
	hppLocalMoSyncQueue workqueue.RateLimitingInterface
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
	podtoServiceUids map[string]map[string][]string
	nodePodIfEPs     map[string]*opflexEndpoint
	// integration test checker
	integ_test *string `json:",omitempty"`
	//network attachment definition map
	netattdefmap            map[string]*NetworkAttachmentData
	netattdefifacemap       map[string]*NetworkAttachmentData
	deviceIdMap             map[string][]string
	nadVlanMap              map[string]*nadVlanMatchData
	fabricDiscoveryRegistry map[int]FabricDiscoveryAgent
	// Namespace and poolname to vlanList
	fabricVlanPoolMap map[string]map[string]string
	orphanNadMap      map[string]*NetworkAttachmentData
	// Pod info
	podNameToTimeStamps map[string]*epTimeStamps
	// Maps epg to poduuid
	pendingEpWriteList map[string]map[string]struct{}
	resolvedEPGCache   []md.OpflexGroup
	completedSyncTypes map[string]struct{}
	taintRemoved       atomic.Value
}

type ServiceEndPointType interface {
	InitClientInformer(kubeClient *kubernetes.Clientset)
	Run(stopCh <-chan struct{})
	SetOpflexService(ofas *opflexService, as *v1.Service,
		external bool, key string, sp *v1.ServicePort) bool
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

		podNameToTimeStamps: make(map[string]*epTimeStamps),
		pendingEpWriteList:  make(map[string]map[string]struct{}),

		podIps: ipam.NewIpCache(),

		ignoreOvsPorts: make(map[string][]string),

		netNsFuncChan:         make(chan func()),
		opflexSnatGlobalInfos: make(map[string][]*opflexSnatGlobalInfo),
		opflexSnatLocalInfos:  make(map[string]*opflexSnatLocalInfo),
		snatPods:              make(map[string]map[string]ResourceType),
		snatPolicyLabels:      make(map[string]map[string]ResourceType),
		snatPolicyCache:       make(map[string]*snatpolicy.SnatPolicy),
		servicetoPodUids:      make(map[string]map[string]struct{}),
		podtoServiceUids:      make(map[string]map[string][]string),
		netattdefmap:          make(map[string]*NetworkAttachmentData),
		netattdefifacemap:     make(map[string]*NetworkAttachmentData),
		deviceIdMap:           make(map[string][]string),
		nadVlanMap:            make(map[string]*nadVlanMatchData),
		fabricVlanPoolMap:     make(map[string]map[string]string),
		orphanNadMap:          make(map[string]*NetworkAttachmentData),
		podToNetAttachDef:     make(map[string][]string),
		podNetworkMetadata:    make(map[string]map[string]map[string]*md.ContainerMetadata),
		completedSyncTypes:    make(map[string]struct{}),
		hppMoIndex:            make(map[string][]*gbpBaseMo),
		syncQueue: workqueue.NewNamedRateLimitingQueue(
			&workqueue.BucketRateLimiter{
				Limiter: rate.NewLimiter(rate.Limit(10), int(10)),
			}, "sync"),
		epSyncQueue: workqueue.NewNamedRateLimitingQueue(
			&workqueue.BucketRateLimiter{
				Limiter: rate.NewLimiter(rate.Limit(10), int(10)),
			}, "epsync"),
		portSyncQueue: workqueue.NewNamedRateLimitingQueue(
			&workqueue.BucketRateLimiter{
				Limiter: rate.NewLimiter(rate.Limit(10), int(10)),
			}, "portsync"),
		hppLocalMoSyncQueue: workqueue.NewNamedRateLimitingQueue(
			&workqueue.BucketRateLimiter{
				Limiter: rate.NewLimiter(rate.Limit(10), int(10)),
			}, "hpplocalmosync"),
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
		"nodepodifs":    ha.syncNodePodIfs,
		"ports":         ha.syncPortsQ,
		"hpp":           ha.syncLocalHppMo}

	if ha.config.EPRegistry == "k8s" {
		cfg, err := rest.InClusterConfig()
		if err != nil {
			log.Errorf("ERROR getting cluster config: %v", err)
			return ha
		}
		if !ha.config.ChainedMode {
			aciawClient, err := crdclientset.NewForConfig(cfg)
			if err != nil {
				log.Errorf("ERROR getting crd client for registry: %v", err)
				return ha
			}
			ha.crdClient = aciawClient.AciV1()
		}
	}
	if !ha.config.ChainedMode {
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
	}
	cfg, err := rest.InClusterConfig()
	if err != nil {
		log.Errorf("ERROR getting cluster config: %v", err)
		return ha
	}
	fabAttClient, err := fabattclset.NewForConfig(cfg)
	if err != nil {
		log.Errorf("ERROR getting fabric attachment client: %v", err)
		return ha
	}
	ha.fabAttClient = fabAttClient.AciV1()

	return ha
}

func addPodRoute(ipn types.IPNet, dev, src string) error {
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

func (agent *HostAgent) WriteSnatPolicyLabel(key, policy string, res ResourceType) {
	agent.snatPolicyLabelMutex.Lock()
	defer agent.snatPolicyLabelMutex.Unlock()
	agent.snatPolicyLabels[key][policy] = res
}

func (agent *HostAgent) WriteNewSnatPolicyLabel(key string) {
	agent.snatPolicyLabelMutex.Lock()
	defer agent.snatPolicyLabelMutex.Unlock()
	agent.snatPolicyLabels[key] = make(map[string]ResourceType)
}

func (agent *HostAgent) DeleteSnatPolicyLabelEntry(key, policy string) {
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
	primaryNetwork := agent.config.CniNetwork
	if agent.config.ChainedMode {
		err := agent.LoadCniNetworks()
		if err != nil {
			agent.log.Infof("%v", err)
		}
		primaryNetwork = agent.primaryNetworkName
		agent.LoadAdditionalNetworkMetadata()
	}

	err := md.LoadMetadata(agent.config.CniMetadataDir,
		primaryNetwork, &agent.epMetadata, agent.config.ChainedMode)
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
	if agent.config.ChainedMode {
		err = agent.FabricDiscoveryRegistryInit()
		if err != nil {
			panic(err.Error())
		}
	}
}

func (agent *HostAgent) removeTaintIfNodeReady(node *v1.Node, taintKey string, clientset *kubernetes.Clientset) error {
	for _, condition := range node.Status.Conditions {
		if condition.Type == v1.NodeReady && condition.Status == v1.ConditionTrue {
			updatedTaints := []v1.Taint{}
			for _, taint := range node.Spec.Taints {
				if taint.Key != taintKey {
					updatedTaints = append(updatedTaints, taint)
				}
			}

			node.Spec.Taints = updatedTaints
			_, err := clientset.CoreV1().Nodes().Update(context.TODO(), node, metav1.UpdateOptions{})
			if err != nil {
				return err
			}
			agent.log.Debugf("Removed taint %s from node %s", taintKey, node.Name)
		}
	}
	return nil
}

func (agent *HostAgent) ScheduleSync(syncType string) {
	if syncType == "eps" {
		agent.epSyncQueue.AddRateLimited(syncType)
	} else if syncType == "ports" {
		agent.portSyncQueue.AddRateLimited(syncType)
	} else if syncType == "hpp" {
		agent.hppLocalMoSyncQueue.AddRateLimited(syncType)
	} else {
		agent.syncQueue.AddRateLimited(syncType)
	}
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
func (agent *HostAgent) scheduleSyncPorts() {
	agent.ScheduleSync("ports")
}
func (agent *HostAgent) scheduleSyncLocalHppMo() {
	agent.ScheduleSync("hpp")
}

func (agent *HostAgent) watchRebootConf(stopCh <-chan struct{}) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		panic(err)
	}
	defer watcher.Close()
	if err := watcher.Add("/usr/local/var/lib/opflex-agent-ovs/reboot-conf.d/reboot.conf"); err != nil {
		panic(err)
	}
	for {
		select {
		// watch for events
		case event := <-watcher.Events:
			agent.log.Info("Reloading aci-containers-host because of an event in /usr/local/var/lib/opflex-agent-ovs/reboot-conf.d/reboot.conf : ", event)
			os.Exit(0)

			// watch for errors
		case err := <-watcher.Errors:
			agent.log.Error("ERROR: ", err)

		case <-stopCh:
			return
		}
	}
}

func (agent *HostAgent) watchResolvedEpgsFile(stopCh <-chan struct{}) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		panic(err)
	}
	defer watcher.Close()
	// akhila : TODO change name of file
	if err := watcher.Add("/usr/local/var/lib/opflex-agent-ovs/resolved-epgs/resolved-epgs.json"); err != nil {
		//panic(err)
		agent.log.Error(err)
		return
	}
	for {
		select {
		// watch for events
		case event := <-watcher.Events:
			// akhila : TODO load json and process list
			agent.log.Info("akhilaaaa......Recievd event ", event)
			agent.processPendingWriteEpFiles()
			agent.log.Info("akhilaaaa......done processing event")

			// watch for errors
		case err := <-watcher.Errors:
			agent.log.Info("akhilaaaa......error event", err)
			agent.log.Error("ERROR: ", err)

		case <-stopCh:
			agent.log.Info("akhilaaaa......stopping event", err)
			return
		}
		agent.log.Info("akhilaaaa......nextt event")
	}
	agent.log.Info("akhilaaaa......exiting event")
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

func (agent *HostAgent) checkSyncProcessorsCompletionStatus(stopCh <-chan struct{}) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	kubeClient := agent.env.(*K8sEnvironment).kubeClient
	for {
		select {
		case <-ticker.C:
			node, err := kubeClient.CoreV1().Nodes().Get(context.TODO(), os.Getenv("KUBERNETES_NODE_NAME"), metav1.GetOptions{})
			if err != nil {
				continue
			}
			for _, taint := range node.Spec.Taints {
				if taint.Key == ACIContainersTaintName && taint.Effect == v1.TaintEffectNoSchedule {
					removeTaint := false
					if agent.taintRemoved.Load().(bool) {
						removeTaint = true
					} else {
						agent.indexMutex.Lock()
						count := len(agent.completedSyncTypes)
						agent.indexMutex.Unlock()
						if count == 5 {
							removeTaint = true
						}
					}

					if removeTaint {
						err := agent.removeTaintIfNodeReady(node, ACIContainersTaintName, kubeClient)
						if err != nil {
							agent.log.Errorf("Failed to remove taint: %v", err)
							continue
						}
						agent.taintRemoved.Store(true)
					}
				}
			}
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
			if sType, ok := syncType.(string); ok {
				if f, ok := agent.syncProcessors[sType]; ok {
					requeue = f()

					switch sType {
					case "services", "eps", "snat", "snatnodeInfo", "nodepodifs":
						if agent.taintRemoved.Load().(bool) {
							break
						}
						agent.indexMutex.Lock()
						agent.completedSyncTypes[sType] = struct{}{}
						agent.indexMutex.Unlock()
					}
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
	if !agent.syncEnabled {
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
	if agent.integ_test == nil {
		err = agent.updateResetConfFile()
		if err != nil {
			agent.log.Error("Failed to create reset.conf ", err.Error())
			panic(err.Error())
		}
	}
	if agent.config.TaintNotReadyNode {
		agent.taintRemoved.Store(false)
		go agent.checkSyncProcessorsCompletionStatus(stopCh)
	} else {
		agent.taintRemoved.Store(true)
	}
	syncEnabled, err := agent.env.PrepareRun(stopCh)
	if err != nil {
		panic(err.Error())
	}
	if agent.config.OpFlexEndpointDir == "" ||
		agent.config.OpFlexServiceDir == "" ||
		agent.config.OpFlexSnatDir == "" {
		if agent.config.EnableHppDirect && agent.config.OpFlexNetPolDir == "" {
			agent.log.Warn("OpFlex endpoint, service, snat or netpol directories not set")
		} else {
			agent.log.Warn("OpFlex endpoint, service, snat directories not set")
		}
	} else {
		if syncEnabled {
			agent.EnableSync()
		}
		go agent.processSyncQueue(agent.syncQueue, stopCh)
		go agent.processSyncQueue(agent.epSyncQueue, stopCh)
		go agent.processSyncQueue(agent.portSyncQueue, stopCh)
		go agent.processSyncQueue(agent.hppLocalMoSyncQueue, stopCh)
	}
	if agent.config.ChainedMode {
		agent.FabricDiscoveryCollectDiscoveryData(stopCh)
	}
	agent.log.Info("Starting endpoint RPC")
	err = agent.runEpRPC(stopCh)
	if err != nil {
		panic(err.Error())
	}

	agent.cleanupSetup()
}
