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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/juju/ratelimit"

	v1 "k8s.io/api/core/v1"
	v1net "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"github.com/noironetworks/aci-containers/pkg/apicapi"
	"github.com/noironetworks/aci-containers/pkg/index"
	"github.com/noironetworks/aci-containers/pkg/metadata"
	"github.com/noironetworks/aci-containers/pkg/ipam"
)

type podUpdateFunc func(*v1.Pod) (*v1.Pod, error)
type nodeUpdateFunc func(*v1.Node) (*v1.Node, error)
type serviceUpdateFunc func(*v1.Service) (*v1.Service, error)

type AciController struct {
	log    *logrus.Logger
	config *ControllerConfig

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
	serviceIpsV4         []*ipam.IpAlloc
	serviceIpsV6         []*ipam.IpAlloc
	staticServiceIps        *netIps
	nodeServiceIps          *netIps

	depPods           *index.PodSelectorIndex
	netPolPods        *index.PodSelectorIndex
	netPolIngressPods *index.PodSelectorIndex

	apicConn *apicapi.ApicConnection

	nodeServiceMetaCache map[string]*nodeServiceMeta
	nodeOpflexDevice     map[string]apicapi.ApicSlice
	nodePodNetCache      map[string]*nodePodNetMeta
	serviceMetaCache     map[string]*serviceMeta

	nodeSyncEnabled    bool
	serviceSyncEnabled bool
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

type serviceMeta struct {
	requestedIp      net.IP
	ingressIps       []net.IP
	staticIngressIps []net.IP
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

func NewController(config *ControllerConfig, log *logrus.Logger) *AciController {
	return &AciController{
		log:       log,
		config:    config,
		defaultEg: "",
		defaultSg: "",

		podQueue:     createQueue("pod"),
		netPolQueue:  createQueue("networkPolicy"),
		serviceQueue: createQueue("service"),

		configuredPodNetworkIps: newNetIps(),
		podNetworkIps:           newNetIps(),
		serviceIpsV4: []*ipam.IpAlloc{ipam.New(), ipam.New()},
		serviceIpsV6: []*ipam.IpAlloc{ipam.New(), ipam.New()},
		staticServiceIps:        newNetIps(),
		nodeServiceIps:          newNetIps(),

		nodeOpflexDevice: make(map[string]apicapi.ApicSlice),

		nodeServiceMetaCache: make(map[string]*nodeServiceMeta),
		nodePodNetCache:      make(map[string]*nodePodNetMeta),
		serviceMetaCache:     make(map[string]*serviceMeta),
	}
}

func (cont *AciController) Init(kubeClient *kubernetes.Clientset) {
	cont.updatePod = func(pod *v1.Pod) (*v1.Pod, error) {
		return kubeClient.CoreV1().Pods(pod.ObjectMeta.Namespace).Update(pod)
	}
	cont.updateNode = func(node *v1.Node) (*v1.Node, error) {
		return kubeClient.CoreV1().Nodes().Update(node)
	}
	cont.updateServiceStatus = func(service *v1.Service) (*v1.Service, error) {
		return kubeClient.CoreV1().
			Services(service.ObjectMeta.Namespace).UpdateStatus(service)
	}

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

	cont.log.Debug("Initializing informers")
	cont.initNodeInformerFromClient(kubeClient)
	cont.initNamespaceInformerFromClient(kubeClient)
	cont.initReplicaSetInformerFromClient(kubeClient)
	cont.initDeploymentInformerFromClient(kubeClient)
	cont.initPodInformerFromClient(kubeClient)
	cont.initEndpointsInformerFromClient(kubeClient)
	cont.initServiceInformerFromClient(kubeClient)
	cont.initNetworkPolicyInformerFromClient(kubeClient)

	cont.log.Debug("Initializing indexes")
	cont.initDepPodIndex()
	cont.initNetPolPodIndex()
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
	name := cont.config.AciPrefix + "_" + ktype +
		"_" + strings.Replace(key, "/", "_", -1)
	if len(name) < 64 {
		return name
	}

	hash := sha256.New()
	if len(cont.config.AciPrefix)+len(ktype)+1 > 31 {
		if len(cont.config.AciPrefix) > 31 {
			hash.Write([]byte(cont.config.AciPrefix))
			hash.Write([]byte("_"))
		} else {
			name = cont.config.AciPrefix
		}

		hash.Write([]byte(ktype))
		hash.Write([]byte("_"))
	} else {
		name = cont.config.AciPrefix + "_" + ktype
	}
	hash.Write([]byte(key))

	hashstr := hex.EncodeToString(hash.Sum(nil)[:16])
	if len(cont.config.AciPrefix) > 31 {
		return hashstr
	} else {
		return fmt.Sprintf("%s_%s", name, hashstr)
	}
}

func (cont *AciController) initStaticObjs() {
	cont.initStaticNetPolObjs()
	cont.initStaticServiceObjs()
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
	cont.apicConn, err = apicapi.New(cont.log, cont.config.ApicHosts,
		cont.config.ApicUsername, cont.config.ApicPassword,
		privKey, apicCert, cont.config.AciPrefix)
	if err != nil {
		panic(err)
	}

	cont.log.Debug("Starting informers")
	go cont.nodeInformer.Run(stopCh)
	go cont.namespaceInformer.Run(stopCh)
	cont.log.Info("Waiting for node/namespace cache sync")
	cache.WaitForCacheSync(stopCh,
		cont.nodeInformer.HasSynced, cont.namespaceInformer.HasSynced)
	cont.indexMutex.Lock()
	cont.nodeSyncEnabled = true
	cont.indexMutex.Unlock()
	cont.nodeFullSync()
	cont.log.Info("Node/namespace cache sync successful")

	go cont.endpointsInformer.Run(stopCh)
	go cont.serviceInformer.Run(stopCh)
	go cont.processQueue(cont.serviceQueue, cont.serviceIndexer,
		func(obj interface{}) bool {
			return cont.handleServiceUpdate(obj.(*v1.Service))
		}, stopCh)
	cont.log.Debug("Waiting for service cache sync")
	cache.WaitForCacheSync(stopCh,
		cont.endpointsInformer.HasSynced,
		cont.serviceInformer.HasSynced)
	cont.indexMutex.Lock()
	cont.serviceSyncEnabled = true
	cont.indexMutex.Unlock()
	cont.serviceFullSync()
	cont.log.Info("Service cache sync successful")

	go cont.replicaSetInformer.Run(stopCh)
	go cont.deploymentInformer.Run(stopCh)
	go cont.podInformer.Run(stopCh)
	go cont.networkPolicyInformer.Run(stopCh)
	go cont.processQueue(cont.podQueue, cont.podIndexer,
		func(obj interface{}) bool {
			return cont.handlePodUpdate(obj.(*v1.Pod))
		}, stopCh)
	go cont.processQueue(cont.netPolQueue, cont.networkPolicyIndexer,
		func(obj interface{}) bool {
			return cont.handleNetPolUpdate(obj.(*v1net.NetworkPolicy))
		}, stopCh)

	cont.log.Info("Waiting for cache sync for remaining objects")
	cache.WaitForCacheSync(stopCh,
		cont.namespaceInformer.HasSynced,
		cont.replicaSetInformer.HasSynced,
		cont.deploymentInformer.HasSynced,
		cont.podInformer.HasSynced,
		cont.networkPolicyInformer.HasSynced)
	cont.log.Info("Cache sync successful")

	cont.initStaticObjs()

	cont.apicConn.FullSyncHook = func() {
		// put a channel into each work queue and wait on it to
		// checkpoint object syncing in response to new subscription
		// updates
		cont.log.Debug("Starting checkpoint")
		var chans []chan struct{}
		qs := []workqueue.RateLimitingInterface{
			cont.podQueue, cont.netPolQueue, cont.serviceQueue,
		}
		for _, q := range qs {
			c := make(chan struct{})
			chans = append(chans, c)
			q.AddRateLimited(c)
		}
		for _, c := range chans {
			<-c
		}
		cont.log.Debug("Checkpoint complete")
	}

	oDevType := "k8s"
	if strings.ToLower(cont.config.AciVmmDomainType) == "openshift" {
		oDevType = "openshift"
	}

	cont.apicConn.AddSubscriptionDn("uni/tn-"+cont.config.AciPolicyTenant,
		[]string{"hostprotPol"})
	cont.apicConn.AddSubscriptionDn("uni/tn-"+cont.config.AciVrfTenant,
		[]string{"fvBD", "vnsLDevVip", "vnsAbsGraph", "vnsLDevCtx",
			"vzFilter", "vzBrCP", "l3extInstP", "vnsSvcRedirectPol"})
	cont.apicConn.AddSubscriptionDn(fmt.Sprintf("uni/tn-%s/out-%s",
		cont.config.AciVrfTenant, cont.config.AciL3Out),
		[]string{"fvRsCons"})
	vmmDn := fmt.Sprintf("comp/prov-%s/ctrlr-[%s]-%s/injcont",
		cont.vmmDomainProvider(), cont.config.AciVmmDomain,
		cont.config.AciVmmController)
	cont.apicConn.AddSubscriptionDn(vmmDn,
		[]string{"vmmInjectedHost", "vmmInjectedNs",
			"vmmInjectedContGrp", "vmmInjectedDepl",
			"vmmInjectedSvc", "vmmInjectedReplSet"})
	cont.apicConn.AddSubscriptionClass("opflexODev",
		[]string{"opflexODev"},
		fmt.Sprintf("and(eq(opflexODev.devType,\"%s\"),"+
			"eq(opflexODev.domName,\"%s\"),"+
			"eq(opflexODev.ctrlrName,\"%s\"))",
			oDevType, cont.config.AciVmmDomain, cont.config.AciVmmController))

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
