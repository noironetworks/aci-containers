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

	"github.com/Sirupsen/logrus"
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
	kubeClient *kubernetes.Clientset
	cont       *AciController
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

	return &K8sEnvironment{kubeClient: kubeClient}, nil
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
	return nil
}
