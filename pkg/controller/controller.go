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

package controller

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/juju/ratelimit"
	"github.com/yl2chen/cidranger"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"github.com/noironetworks/aci-containers/pkg/apicapi"
	"github.com/noironetworks/aci-containers/pkg/index"
	"github.com/noironetworks/aci-containers/pkg/ipam"
	"github.com/noironetworks/aci-containers/pkg/metadata"
	"github.com/noironetworks/aci-containers/pkg/util"
)

type podUpdateFunc func(*v1.Pod) (*v1.Pod, error)
type nodeUpdateFunc func(*v1.Node) (*v1.Node, error)
type serviceUpdateFunc func(*v1.Service) (*v1.Service, error)

type AciController struct {
	log    *logrus.Logger
	config *ControllerConfig
	env    Environment

	defaultEg string
	defaultSg string

	podQueue     workqueue.RateLimitingInterface
	netPolQueue  workqueue.RateLimitingInterface
	serviceQueue workqueue.RateLimitingInterface

	namespaceIndexer      cache.Indexer
	namespaceInformer     cache.Controller
	podIndexer            cache.Indexer
	podInformer           cache.Controller
	endpointsIndexer      cache.Indexer
	endpointsInformer     cache.Controller
	serviceIndexer        cache.Indexer
	serviceInformer       cache.Controller
	replicaSetIndexer     cache.Indexer
	replicaSetInformer    cache.Controller
	deploymentIndexer     cache.Indexer
	deploymentInformer    cache.Controller
	nodeIndexer           cache.Indexer
	nodeInformer          cache.Controller
	networkPolicyIndexer  cache.Indexer
	networkPolicyInformer cache.Controller

	updatePod           podUpdateFunc
	updateNode          nodeUpdateFunc
	updateServiceStatus serviceUpdateFunc

	indexMutex sync.Mutex

	configuredPodNetworkIps *netIps
	podNetworkIps           *netIps
	serviceIps              *ipam.IpCache
	staticServiceIps        *netIps
	nodeServiceIps          *netIps

	// index of pods matched by deployments
	depPods *index.PodSelectorIndex
	// index of pods matched by network policies
	netPolPods *index.PodSelectorIndex
	// index of pods matched by network policy ingress rules
	netPolIngressPods *index.PodSelectorIndex
	// index of pods matched by network policy egress rules
	netPolEgressPods *index.PodSelectorIndex
	// index of IP addresses contained in endpoints objects
	endpointsIpIndex cidranger.Ranger
	// index of service target ports
	targetPortIndex map[string]*portIndexEntry
	// index of ip blocks referenced by network policy egress rules
	netPolSubnetIndex cidranger.Ranger

	apicConn *apicapi.ApicConnection

	nodeServiceMetaCache map[string]*nodeServiceMeta
	nodeOpflexDevice     map[string]apicapi.ApicSlice
	nodePodNetCache      map[string]*nodePodNetMeta
	serviceMetaCache     map[string]*serviceMeta

	nodeSyncEnabled    bool
	serviceSyncEnabled bool
}

type nodeServiceMeta struct {
	serviceEp metadata.ServiceEndpoint
}

type nodePodNetMeta struct {
	nodePods            map[string]bool
	podNetIps           metadata.NetIps
	podNetIpsAnnotation string
}

type serviceMeta struct {
	requestedIp      net.IP
	ingressIps       []net.IP
	staticIngressIps []net.IP
}

type ipIndexEntry struct {
	ipNet net.IPNet
	keys  map[string]bool
}

type targetPort struct {
	proto v1.Protocol
	port  int
}

type portIndexEntry struct {
	port              targetPort
	serviceKeys       map[string]bool
	networkPolicyKeys map[string]bool
}

func (e *ipIndexEntry) Network() net.IPNet {
	return e.ipNet
}

func newNodePodNetMeta() *nodePodNetMeta {
	return &nodePodNetMeta{
		nodePods: make(map[string]bool),
	}
}

func createQueue(name string) workqueue.RateLimitingInterface {
	return workqueue.NewNamedRateLimitingQueue(
		workqueue.NewMaxOfRateLimiter(
			workqueue.NewItemExponentialFailureRateLimiter(5*time.Millisecond,
				10*time.Second),
			&workqueue.BucketRateLimiter{
				Bucket: ratelimit.NewBucketWithRate(float64(10), int64(100)),
			},
		),
		"delta")
}

func NewController(config *ControllerConfig, env Environment, log *logrus.Logger) *AciController {
	return &AciController{
		log:       log,
		config:    config,
		env:       env,
		defaultEg: "",
		defaultSg: "",

		podQueue:     createQueue("pod"),
		netPolQueue:  createQueue("networkPolicy"),
		serviceQueue: createQueue("service"),

		configuredPodNetworkIps: newNetIps(),
		podNetworkIps:           newNetIps(),
		serviceIps:              ipam.NewIpCache(),
		staticServiceIps:        newNetIps(),
		nodeServiceIps:          newNetIps(),

		nodeOpflexDevice: make(map[string]apicapi.ApicSlice),

		nodeServiceMetaCache: make(map[string]*nodeServiceMeta),
		nodePodNetCache:      make(map[string]*nodePodNetMeta),
		serviceMetaCache:     make(map[string]*serviceMeta),
	}
}

func (cont *AciController) Init() {
	egdata, err := json.Marshal(cont.config.DefaultEg)
	if err != nil {
		cont.log.Error("Could not serialize default endpoint group")
		panic(err.Error())
	}
	cont.defaultEg = string(egdata)

	sgdata, err := json.Marshal(cont.config.DefaultSg)
	if err != nil {
		cont.log.Error("Could not serialize default security groups")
		panic(err.Error())
	}
	cont.defaultSg = string(sgdata)

	cont.log.Debug("Initializing IPAM")
	cont.initIpam()

	err = cont.env.Init(cont)
	if err != nil {
		panic(err.Error())
	}
}

func (cont *AciController) processQueue(queue workqueue.RateLimitingInterface,
	store cache.Store, handler func(interface{}) bool,
	stopCh <-chan struct{}) {
	go wait.Until(func() {
		for {
			key, quit := queue.Get()
			if quit {
				break
			}

			var requeue bool
			switch key := key.(type) {
			case chan struct{}:
				close(key)
			case string:
				obj, exists, err := store.GetByKey(key)
				if err == nil && exists {
					requeue = handler(obj)
				}
			}
			if requeue {
				queue.AddRateLimited(key)
			} else {
				queue.Forget(key)
			}
			queue.Done(key)

		}
	}, time.Second, stopCh)
	<-stopCh
	queue.ShutDown()
}

func (cont *AciController) globalStaticObjs() apicapi.ApicSlice {
	return apicapi.ApicSlice{}
}

func (cont *AciController) aciNameForKey(ktype string, key string) string {
	return util.AciNameForKey(cont.config.AciPrefix, ktype, key)
}

func (cont *AciController) initStaticObjs() {
	cont.env.InitStaticAciObjects()
	cont.apicConn.WriteApicObjects(cont.config.AciPrefix+"_static",
		cont.globalStaticObjs())
}

func (cont *AciController) vmmDomainProvider() (vmmProv string) {
	vmmProv = "Kubernetes"
	if strings.ToLower(cont.config.AciVmmDomainType) == "openshift" {
		vmmProv = "OpenShift"
	}
	return
}

func (cont *AciController) Run(stopCh <-chan struct{}) {
	var err error
	var privKey []byte
	var apicCert []byte

	if cont.config.ApicPrivateKeyPath != "" {
		privKey, err = ioutil.ReadFile(cont.config.ApicPrivateKeyPath)
		if err != nil {
			panic(err)
		}
	}
	if cont.config.ApicCertPath != "" {
		apicCert, err = ioutil.ReadFile(cont.config.ApicCertPath)
		if err != nil {
			panic(err)
		}
	}
	// If not defined, default is 900
	if cont.config.ApicRefreshTimer == "" {
		cont.config.ApicRefreshTimer = "900"
	}
	refreshTimeout, err := strconv.Atoi(cont.config.ApicRefreshTimer)
	if err != nil {
		panic(err)
	}
	cont.log.Info("ApicRefreshTimer conf is set to: ", refreshTimeout)

	// If not defined, default to 32
	if cont.config.PodIpPoolChunkSize == 0 {
		cont.config.PodIpPoolChunkSize = 32
	}
	cont.log.Info("PodIpPoolChunkSize conf is set to: ", cont.config.PodIpPoolChunkSize)

	cont.apicConn, err = apicapi.New(cont.log, cont.config.ApicHosts,
		cont.config.ApicUsername, cont.config.ApicPassword,
		privKey, apicCert, cont.config.AciPrefix,
		refreshTimeout)
	if err != nil {
		panic(err)
	}
	cont.apicConn.UseAPICInstTag = cont.config.ApicUseInstTag

	cont.initStaticObjs()

	err = cont.env.PrepareRun(stopCh)
	if err != nil {
		panic(err.Error())
	}

	cont.apicConn.FullSyncHook = func() {
		// put a channel into each work queue and wait on it to
		// checkpoint object syncing in response to new subscription
		// updates
		cont.log.Debug("Starting checkpoint")
		var chans []chan struct{}
		qs := make([]workqueue.RateLimitingInterface, 0)
		_, ok := cont.env.(*K8sEnvironment)
		if ok {
			qs = []workqueue.RateLimitingInterface{
				cont.podQueue, cont.netPolQueue, cont.serviceQueue,
			}
		}
		for _, q := range qs {
			c := make(chan struct{})
			chans = append(chans, c)
			q.Add(c)
		}
		for _, c := range chans {
			<-c
		}
		cont.log.Debug("Checkpoint complete")
	}

	cont.apicConn.AddSubscriptionDn("uni/tn-"+cont.config.AciPolicyTenant,
		[]string{"hostprotPol"})
	cont.apicConn.AddSubscriptionDn("uni/tn-"+cont.config.AciVrfTenant,
		[]string{"fvBD", "vnsLDevVip", "vnsAbsGraph", "vnsLDevCtx",
			"vzFilter", "vzBrCP", "l3extInstP", "vnsSvcRedirectPol",
			"vnsRedirectHealthGroup", "fvIPSLAMonitoringPol"})
	cont.apicConn.AddSubscriptionDn(fmt.Sprintf("uni/tn-%s/out-%s",
		cont.config.AciVrfTenant, cont.config.AciL3Out),
		[]string{"fvRsCons"})
	vmmDn := fmt.Sprintf("comp/prov-%s/ctrlr-[%s]-%s/injcont",
		cont.env.VmmPolicy(), cont.config.AciVmmDomain,
		cont.config.AciVmmController)
	cont.apicConn.AddSubscriptionDn(vmmDn,
		[]string{"vmmInjectedHost", "vmmInjectedNs",
			"vmmInjectedContGrp", "vmmInjectedDepl",
			"vmmInjectedSvc", "vmmInjectedReplSet",
			"vmmInjectedOrg", "vmmInjectedOrgUnit"})

	cont.apicConn.AddSubscriptionClass("opflexODev",
		[]string{"opflexODev"},
		fmt.Sprintf("and(eq(opflexODev.devType,\"%s\"),"+
			"eq(opflexODev.domName,\"%s\"),"+
			"eq(opflexODev.ctrlrName,\"%s\"))",
			cont.env.OpFlexDeviceType(), cont.config.AciVmmDomain,
			cont.config.AciVmmController))

	cont.apicConn.SetSubscriptionHooks("opflexODev",
		func(obj apicapi.ApicObject) bool {
			cont.opflexDeviceChanged(obj)
			return true
		},
		func(dn string) {
			cont.opflexDeviceDeleted(dn)
		})
	go cont.apicConn.Run(stopCh)
}
