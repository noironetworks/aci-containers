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
	"net"
	"sync"
	"time"

	"github.com/Sirupsen/logrus"

	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	v1 "k8s.io/client-go/pkg/api/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"github.com/noironetworks/aci-containers/pkg/index"
	"github.com/noironetworks/aci-containers/pkg/metadata"
)

type podUpdateFunc func(*v1.Pod) (*v1.Pod, error)
type nodeUpdateFunc func(*v1.Node) (*v1.Node, error)
type serviceUpdateFunc func(*v1.Service) (*v1.Service, error)

type AciController struct {
	log    *logrus.Logger
	config *ControllerConfig

	defaultEg  string
	defaultSg  string
	indexMutex sync.Mutex

	depPods *index.PodSelectorIndex

	podQueue workqueue.RateLimitingInterface

	namespaceInformer  cache.SharedIndexInformer
	podInformer        cache.SharedIndexInformer
	endpointsInformer  cache.SharedIndexInformer
	serviceInformer    cache.SharedIndexInformer
	deploymentInformer cache.SharedIndexInformer
	nodeInformer       cache.SharedIndexInformer
	aimInformer        cache.SharedIndexInformer

	updatePod           podUpdateFunc
	updateNode          nodeUpdateFunc
	updateServiceStatus serviceUpdateFunc

	configuredPodNetworkIps *netIps
	podNetworkIps           *netIps
	serviceIps              *netIps
	staticServiceIps        *netIps
	nodeServiceIps          *netIps

	nodeServiceMetaCache map[string]*nodeServiceMeta
	nodePodNetCache      map[string]*nodePodNetMeta

	serviceMetaCache map[string]*serviceMeta
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

func NewController(config *ControllerConfig, log *logrus.Logger) *AciController {
	return &AciController{
		log:       log,
		config:    config,
		defaultEg: "",
		defaultSg: "",

		podQueue: workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "pod"),

		configuredPodNetworkIps: newNetIps(),
		podNetworkIps:           newNetIps(),
		serviceIps:              newNetIps(),
		staticServiceIps:        newNetIps(),
		nodeServiceIps:          newNetIps(),

		nodeServiceMetaCache: make(map[string]*nodeServiceMeta),
		nodePodNetCache:      make(map[string]*nodePodNetMeta),

		serviceMetaCache: make(map[string]*serviceMeta),
	}
}

func (cont *AciController) Init(kubeClient *kubernetes.Clientset,
	tprClient rest.Interface) {
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
	cont.initDeploymentInformerFromClient(kubeClient)
	cont.initPodInformerFromClient(kubeClient)
	cont.initEndpointsInformerFromClient(kubeClient)
	cont.initServiceInformerFromClient(kubeClient)
	cont.initAimInformerFromRest(tprClient)

	cont.log.Debug("Initializing indexes")
	cont.initDepPodIndex()
}

func (cont *AciController) Run(stopCh <-chan struct{}) {
	cont.log.Debug("Starting informers")
	go cont.namespaceInformer.Run(stopCh)
	go cont.nodeInformer.Run(stopCh)
	go cont.deploymentInformer.Run(stopCh)
	go cont.podInformer.Run(stopCh)
	go cont.endpointsInformer.Run(stopCh)
	go cont.serviceInformer.Run(stopCh)
	go cont.aimInformer.Run(stopCh)
	go func() {
		for i := 0; i < 4; i++ {
			go wait.Until(func() {
				for cont.processNextPodItem() {
				}
			}, time.Second, stopCh)
		}
		<-stopCh
		cont.podQueue.ShutDown()
	}()
}
