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
	"strings"

	istiov1 "github.com/noironetworks/aci-containers/pkg/istiocrd/apis/aci.istio/v1"
	istioclientset "github.com/noironetworks/aci-containers/pkg/istiocrd/clientset/versioned"
	snatnodeinfo "github.com/noironetworks/aci-containers/pkg/nodeinfo/apis/aci.snat/v1"
	nodeinfoclientset "github.com/noironetworks/aci-containers/pkg/nodeinfo/clientset/versioned"
	rdconfigclientset "github.com/noironetworks/aci-containers/pkg/rdconfig/clientset/versioned"
	snatglobalclset "github.com/noironetworks/aci-containers/pkg/snatglobalinfo/clientset/versioned"
	snatpolicy "github.com/noironetworks/aci-containers/pkg/snatpolicy/apis/aci.snat/v1"
	snatclientset "github.com/noironetworks/aci-containers/pkg/snatpolicy/clientset/versioned"
	"github.com/sirupsen/logrus"
	"github.com/yl2chen/cidranger"
	v1 "k8s.io/api/core/v1"
	v1net "k8s.io/api/networking/v1"
	"k8s.io/client-go/kubernetes"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

type Environment interface {
	Init(agent *AciController) error
	PrepareRun(stopCh <-chan struct{}) error
	InitStaticAciObjects()
	NodePodNetworkChanged(nodeName string)
	NodeServiceChanged(nodeName string)
	VmmPolicy() string
	OpFlexDeviceType() string
	ServiceBd() string
}

type K8sEnvironment struct {
	kubeClient       *kubernetes.Clientset
	snatClient       *snatclientset.Clientset
	snatGlobalClient *snatglobalclset.Clientset
	nodeInfoClient   *nodeinfoclientset.Clientset
	rdConfigClient   *rdconfigclientset.Clientset
	istioClient      *istioclientset.Clientset
	cont             *AciController
}

func NewK8sEnvironment(config *ControllerConfig, log *logrus.Logger) (*K8sEnvironment, error) {
	log.WithFields(logrus.Fields{
		"kubeconfig": config.KubeConfig,
	}).Info("Setting up Kubernetes environment")

	log.Debug("Initializing kubernetes client")
	var restconfig *restclient.Config
	var err error
	if config.KubeConfig != "" {
		// use kubeconfig file from command line
		restconfig, err =
			clientcmd.BuildConfigFromFlags("", config.KubeConfig)
		if err != nil {
			return nil, err
		}
	} else {
		// creates the in-cluster config
		restconfig, err = restclient.InClusterConfig()
		if err != nil {
			return nil, err
		}
	}

	// creates the kubernetes API client
	kubeClient, err := kubernetes.NewForConfig(restconfig)
	if err != nil {
		return nil, err
	}
	log.Debug("Initializing snat client")
	snatClient, err := snatclientset.NewForConfig(restconfig)
	if err != nil {
		return nil, err
	}
	snatGlobalClient, err := snatglobalclset.NewForConfig(restconfig)
	if err != nil {
		log.Debug("Failed to intialize snat global info client")
		return nil, err
	}
	nodeInfoClient, err := nodeinfoclientset.NewForConfig(restconfig)
	if err != nil {
		log.Debug("Failed to intialize node info client")
		return nil, err
	}
	rdConfigClient, err := rdconfigclientset.NewForConfig(restconfig)
	if err != nil {
		log.Debug("Failed to intialize rdconfig client")
		return nil, err
	}
	istioClient, err := istioclientset.NewForConfig(restconfig)
	if err != nil {
		log.Debug("Failed to intialize AciIstio client")
		return nil, err
	}
	return &K8sEnvironment{kubeClient: kubeClient, snatClient: snatClient,
		snatGlobalClient: snatGlobalClient, nodeInfoClient: nodeInfoClient,
		rdConfigClient: rdConfigClient, istioClient: istioClient}, nil
}

func (env *K8sEnvironment) VmmPolicy() string {
	return env.cont.vmmDomainProvider()
}

func (env *K8sEnvironment) OpFlexDeviceType() string {
	oDevType := "k8s"
	if strings.ToLower(env.cont.config.AciVmmDomainType) == "openshift" {
		oDevType = "openshift"
	}
	return oDevType
}

func (env *K8sEnvironment) ServiceBd() string {
	return "kubernetes-service"
}

func (env *K8sEnvironment) Init(cont *AciController) error {
	env.cont = cont
	kubeClient := env.kubeClient
	snatClient := env.snatClient

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

	cont.log.Debug("Initializing informers")
	cont.initNodeInformerFromClient(kubeClient)
	cont.initNamespaceInformerFromClient(kubeClient)
	cont.initReplicaSetInformerFromClient(kubeClient)
	cont.initDeploymentInformerFromClient(kubeClient)
	cont.initPodInformerFromClient(kubeClient)
	cont.initEndpointsInformerFromClient(kubeClient)
	cont.initServiceInformerFromClient(kubeClient)
	cont.initNetworkPolicyInformerFromClient(kubeClient)
	cont.initSnatInformerFromClient(snatClient)
	cont.initSnatNodeInformerFromClient(env.nodeInfoClient)
	cont.initSnatCfgFromClient(kubeClient)
	if cont.config.InstallIstio {
		cont.initIstioInformerFromClient(env.istioClient)
	}
	cont.log.Debug("Initializing indexes")
	cont.initDepPodIndex()
	cont.initNetPolPodIndex()
	cont.endpointsIpIndex = cidranger.NewPCTrieRanger()
	cont.targetPortIndex = make(map[string]*portIndexEntry)
	cont.netPolSubnetIndex = cidranger.NewPCTrieRanger()
	return nil
}

func (env *K8sEnvironment) InitStaticAciObjects() {
	env.cont.initStaticNetPolObjs()
	env.cont.initStaticServiceObjs()
}

func (env *K8sEnvironment) NodePodNetworkChanged(nodeName string) {
	env.cont.nodeChangedByName(nodeName)
}

func (env *K8sEnvironment) NodeServiceChanged(nodeName string) {
	env.cont.nodeChangedByName(nodeName)
	env.cont.updateServicesForNode(nodeName)
	env.cont.snatFullSync()
}

func (env *K8sEnvironment) PrepareRun(stopCh <-chan struct{}) error {
	cont := env.cont

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
	go cont.snatInformer.Run(stopCh)
	go cont.processQueue(cont.snatQueue, cont.snatIndexer,
		func(obj interface{}) bool {
			return cont.handleSnatUpdate(obj.(*snatpolicy.SnatPolicy))
		}, stopCh)
	cont.log.Debug("Waiting for snat cache sync")
	cache.WaitForCacheSync(stopCh,
		cont.snatInformer.HasSynced)
	cont.indexMutex.Lock()
	cont.snatSyncEnabled = true
	cont.indexMutex.Unlock()
	cont.snatFullSync()
	cont.log.Info("Snat cache sync successful")
	go cont.networkPolicyInformer.Run(stopCh)
	go cont.processQueue(cont.podQueue, cont.podIndexer,
		func(obj interface{}) bool {
			return cont.handlePodUpdate(obj.(*v1.Pod))
		}, stopCh)
	go cont.processQueue(cont.netPolQueue, cont.networkPolicyIndexer,
		func(obj interface{}) bool {
			return cont.handleNetPolUpdate(obj.(*v1net.NetworkPolicy))
		}, stopCh)
	go cont.snatNodeInformer.Run(stopCh)
	go cont.processQueue(cont.snatNodeInfoQueue, cont.snatNodeInfoIndexer,
		func(obj interface{}) bool {
			return cont.handleSnatNodeInfo(obj.(*snatnodeinfo.NodeInfo))
		}, stopCh)
	go cont.processSyncQueue(cont.syncQueue, stopCh)
	if cont.config.InstallIstio {
		go cont.istioInformer.Run(stopCh)
		go cont.processQueue(cont.istioQueue, cont.istioIndexer,
			func(obj interface{}) bool {
				return cont.handleIstioUpdate(obj.(*istiov1.AciIstioOperator))
			}, stopCh)
		cont.log.Debug("Waiting for AciIstio cache sync")
		cache.WaitForCacheSync(stopCh,
			cont.istioInformer.HasSynced)
		cont.scheduleCreateIstioCR()
	}
	cont.log.Info("Waiting for cache sync for remaining objects")
	go cont.snatCfgInformer.Run(stopCh)
	cache.WaitForCacheSync(stopCh,
		cont.namespaceInformer.HasSynced,
		cont.replicaSetInformer.HasSynced,
		cont.deploymentInformer.HasSynced,
		cont.podInformer.HasSynced,
		cont.networkPolicyInformer.HasSynced,
		cont.snatNodeInformer.HasSynced)
	cont.log.Info("Cache sync successful")
	return nil
}
