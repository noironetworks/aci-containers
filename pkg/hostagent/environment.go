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
	"errors"
	"os"

	"github.com/Sirupsen/logrus"

	"k8s.io/client-go/kubernetes"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"

	md "github.com/noironetworks/aci-containers/pkg/metadata"
	nodeinfoclientset "github.com/noironetworks/aci-containers/pkg/nodeinfo/clientset/versioned"
	snatglobalclset "github.com/noironetworks/aci-containers/pkg/snatglobalinfo/clientset/versioned"
	snatlocalclset "github.com/noironetworks/aci-containers/pkg/snatlocalinfo/clientset/versioned"
)

type Environment interface {
	Init(agent *HostAgent) error
	PrepareRun(stopCh <-chan struct{}) (bool, error)

	CniDeviceChanged(metadataKey *string, id *md.ContainerId)
	CniDeviceDeleted(metadataKey *string, id *md.ContainerId)

	CheckPodExists(metadataKey *string) (bool, error)
}

type K8sEnvironment struct {
	kubeClient        *kubernetes.Clientset
	snatLocalClient   *snatlocalclset.Clientset
	snatGlobalClient  *snatglobalclset.Clientset
	nodeInfo          *nodeinfoclientset.Clientset
	agent             *HostAgent
	podInformer       cache.SharedIndexInformer
	endpointsInformer cache.SharedIndexInformer
	serviceInformer   cache.SharedIndexInformer
	nodeInformer      cache.SharedIndexInformer
	snatInformer      cache.SharedIndexInformer
}

func NewK8sEnvironment(config *HostAgentConfig, log *logrus.Logger) (*K8sEnvironment, error) {
	if config.NodeName == "" {
		config.NodeName = os.Getenv("KUBERNETES_NODE_NAME")
	}
	if config.NodeName == "" {
		err := errors.New("Node name not specified and $KUBERNETES_NODE_NAME empty")
		log.Error(err.Error())
		return nil, err
	}

	log.WithFields(logrus.Fields{
		"kubeconfig": config.KubeConfig,
		"node-name":  config.NodeName,
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
	snatLocalClient, err := snatlocalclset.NewForConfig(restconfig)
	if err != nil {
		return nil, err
	}
	snatGlobalClient, err := snatglobalclset.NewForConfig(restconfig)
	if err != nil {
		return nil, err
	}
	nodeInfo, err := nodeinfoclientset.NewForConfig(restconfig)
	log.Debug("Initializing kubernetes client", nodeInfo)
	if err != nil {
		log.Debug("Failed to intialize node info client")
		return nil, err
	}
	return &K8sEnvironment{kubeClient: kubeClient, snatLocalClient: snatLocalClient,
		snatGlobalClient: snatGlobalClient, nodeInfo: nodeInfo}, nil
}

func (env *K8sEnvironment) Init(agent *HostAgent) error {
	env.agent = agent

	env.agent.log.Debug("Initializing informers")
	env.agent.initNodeInformerFromClient(env.kubeClient)
	env.agent.initPodInformerFromClient(env.kubeClient)
	env.agent.initEndpointsInformerFromClient(env.kubeClient)
	env.agent.initServiceInformerFromClient(env.kubeClient)
	env.agent.initNamespaceInformerFromClient(env.kubeClient)
	env.agent.initNetworkPolicyInformerFromClient(env.kubeClient)
	env.agent.initDeploymentInformerFromClient(env.kubeClient)
	env.agent.initRCInformerFromClient(env.kubeClient)
	env.agent.initSnatLocalInformerFromClient(env.snatLocalClient)
	env.agent.initSnatGlobalInformerFromClient(env.snatGlobalClient)
	env.agent.initNetPolPodIndex()
	env.agent.initDepPodIndex()
	env.agent.initRCPodIndex()
	return nil
}

func (env *K8sEnvironment) PrepareRun(stopCh <-chan struct{}) (bool, error) {
	env.agent.log.Debug("Discovering node configuration")
	env.agent.updateOpflexConfig()
	go env.agent.runTickers(stopCh)

	env.agent.log.Debug("Starting node informer")
	go env.agent.nodeInformer.Run(stopCh)
	env.agent.log.Info("Waiting for node cache sync")
	cache.WaitForCacheSync(stopCh, env.agent.nodeInformer.HasSynced)
	env.agent.log.Info("Node cache sync successful")

	env.agent.log.Debug("Starting remaining informers")
	env.agent.log.Debug("exporting NodeInfo: ", env.agent.config.NodeName)
	go env.agent.InformNodeInfo(env.nodeInfo, env.kubeClient)
	go env.agent.podInformer.Run(stopCh)
	go env.agent.endpointsInformer.Run(stopCh)
	go env.agent.serviceInformer.Run(stopCh)
	go env.agent.nsInformer.Run(stopCh)
	go env.agent.netPolInformer.Run(stopCh)
	go env.agent.depInformer.Run(stopCh)
	go env.agent.rcInformer.Run(stopCh)
	go env.agent.snatLocalInformer.Run(stopCh)
	go env.agent.snatGlobalInformer.Run(stopCh)

	env.agent.log.Info("Waiting for cache sync for remaining objects")
	cache.WaitForCacheSync(stopCh,
		env.agent.podInformer.HasSynced, env.agent.endpointsInformer.HasSynced,
		env.agent.serviceInformer.HasSynced, env.agent.snatLocalInformer.HasSynced,
		env.agent.snatGlobalInformer.HasSynced)
	env.agent.log.Info("Cache sync successful")
	return true, nil
}

func (env *K8sEnvironment) CniDeviceChanged(metadataKey *string, id *md.ContainerId) {
	env.agent.podChanged(metadataKey)
}

func (env *K8sEnvironment) CniDeviceDeleted(metadataKey *string, id *md.ContainerId) {
}

func (env *K8sEnvironment) CheckPodExists(metadataKey *string) (bool, error) {
	_, exists, err := env.agent.podInformer.GetStore().GetByKey(*metadataKey)
	return exists, err
}
