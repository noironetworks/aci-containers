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

	netClientSet "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/clientset/versioned"
	"github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"

	fabattclientset "github.com/noironetworks/aci-containers/pkg/fabricattachment/clientset/versioned"
	hppclset "github.com/noironetworks/aci-containers/pkg/hpp/clientset/versioned"
	md "github.com/noironetworks/aci-containers/pkg/metadata"
	nodeinfoclientset "github.com/noironetworks/aci-containers/pkg/nodeinfo/clientset/versioned"
	proactiveconfclientset "github.com/noironetworks/aci-containers/pkg/proactiveconf/clientset/versioned"
	qospolicyclset "github.com/noironetworks/aci-containers/pkg/qospolicy/clientset/versioned"
	rdconfigclset "github.com/noironetworks/aci-containers/pkg/rdconfig/clientset/versioned"
	snatglobalclset "github.com/noironetworks/aci-containers/pkg/snatglobalinfo/clientset/versioned"
	snatlocalinfoclset "github.com/noironetworks/aci-containers/pkg/snatlocalinfo/clientset/versioned"
	snatpolicyclset "github.com/noironetworks/aci-containers/pkg/snatpolicy/clientset/versioned"
)

type Environment interface {
	Init(agent *HostAgent) error
	PrepareRun(stopCh <-chan struct{}) (bool, error)

	CniDeviceChanged(metadataKey *string, id *md.ContainerId)
	CniDeviceDeleted(metadataKey *string, id *md.ContainerId)

	CheckPodExists(metadataKey *string) (bool, error)
	CheckNetAttDefExists(netAttDefKey string) (bool, error)
}

type K8sEnvironment struct {
	kubeClient          *kubernetes.Clientset
	snatGlobalClient    *snatglobalclset.Clientset
	snatPolicyClient    *snatpolicyclset.Clientset
	qosPolicyClient     *qospolicyclset.Clientset
	nodeInfo            *nodeinfoclientset.Clientset
	rdConfig            *rdconfigclset.Clientset
	snatLocalInfoClient *snatlocalinfoclset.Clientset
	agent               *HostAgent
	podInformer         cache.SharedIndexInformer
	endpointsInformer   cache.SharedIndexInformer
	serviceInformer     cache.SharedIndexInformer
	nodeInformer        cache.SharedIndexInformer
	netClient           *netClientSet.Clientset
	fabattClient        *fabattclientset.Clientset
	configmapInformer   cache.SharedIndexInformer
	hppClient           *hppclset.Clientset
	proactiveConfClient *proactiveconfclientset.Clientset
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
		log.Debug("Failed to intialize kube client")
		return nil, err
	}
	snatGlobalClient, err := snatglobalclset.NewForConfig(restconfig)
	if err != nil {
		log.Debug("Failed to intialize snat global info client")
		return nil, err
	}
	nodeInfo, err := nodeinfoclientset.NewForConfig(restconfig)
	log.Debug("Initializing kubernetes client", nodeInfo)
	if err != nil {
		log.Debug("Failed to intialize node info client")
		return nil, err
	}
	snatPolicyClient, err := snatpolicyclset.NewForConfig(restconfig)
	if err != nil {
		log.Debug("Failed to intialize snatpolicy info client")
		return nil, err
	}
	qosPolicyClient, err := qospolicyclset.NewForConfig(restconfig)
	if err != nil {
		log.Debug("Failed to intialize snatpolicy info client")
		return nil, err
	}
	rdConfig, err := rdconfigclset.NewForConfig(restconfig)
	if err != nil {
		log.Debug("Failed to intialize snatpolicy info client")
		return nil, err
	}
	snatLocalInfoClient, err := snatlocalinfoclset.NewForConfig(restconfig)
	if err != nil {
		log.Debug("Failed to intialize snatpolicy info client")
		return nil, err
	}
	netClient, err := netClientSet.NewForConfig(restconfig)
	if err != nil {
		log.Debug("Failed to intialize network attachment definition info client")
		return nil, err
	}
	fabattClient, err := fabattclientset.NewForConfig(restconfig)
	if err != nil {
		log.Debug("Failed to intialize fabric attachment client")
		return nil, err
	}
	hppClient, err := hppclset.NewForConfig(restconfig)
	if err != nil {
		log.Debug("Failed to intialize hpp client")
		return nil, err
	}
	proactiveConfClient, err := proactiveconfclientset.NewForConfig(restconfig)
	if err != nil {
		log.Debug("Failed to intialize ProactiveConf client")
		return nil, err
	}

	return &K8sEnvironment{kubeClient: kubeClient, snatGlobalClient: snatGlobalClient,
		nodeInfo: nodeInfo, snatPolicyClient: snatPolicyClient, qosPolicyClient: qosPolicyClient, rdConfig: rdConfig, snatLocalInfoClient: snatLocalInfoClient, netClient: netClient, fabattClient: fabattClient, hppClient: hppClient, proactiveConfClient: proactiveConfClient}, nil
}

func (env *K8sEnvironment) Init(agent *HostAgent) error {
	env.agent = agent

	env.agent.log.Debug("Initializing informers")
	env.agent.initNodeInformerFromClient(env.kubeClient)
	env.agent.initPodInformerFromClient(env.kubeClient)
	env.agent.serviceEndPoints.InitClientInformer(env.kubeClient)
	env.agent.initServiceInformerFromClient(env.kubeClient)
	env.agent.initNamespaceInformerFromClient(env.kubeClient)
	env.agent.initNetworkPolicyInformerFromClient(env.kubeClient)
	env.agent.initDeploymentInformerFromClient(env.kubeClient)
	env.agent.initRCInformerFromClient(env.kubeClient)
	if !agent.config.ChainedMode {
		env.agent.initSnatGlobalInformerFromClient(env.snatGlobalClient)
		env.agent.initSnatPolicyInformerFromClient(env.snatPolicyClient)
		env.agent.initQoSPolicyInformerFromClient(env.qosPolicyClient)
		env.agent.initRdConfigInformerFromClient(env.rdConfig)
		env.agent.initQoSPolPodIndex()
		if agent.config.ProactiveConf {
			env.agent.initProactiveConfInformerFromClient(env.proactiveConfClient)
		}
	}
	env.agent.initNetPolPodIndex()
	env.agent.initDepPodIndex()
	env.agent.initRCPodIndex()
	env.agent.initEventPoster(env.kubeClient)
	env.agent.initNetworkAttDefInformerFromClient(env.netClient)
	env.agent.initNadVlanInformerFromClient(env.fabattClient)
	env.agent.initFabricVlanPoolsInformerFromClient(env.fabattClient)
	if agent.config.EnableHppDirect {
		env.agent.initHppInformerFromClient(env.hppClient)
		env.agent.initHostprotRemoteIpContainerInformerFromClient(env.hppClient)
	}
	return nil
}

func (env *K8sEnvironment) PrepareRun(stopCh <-chan struct{}) (bool, error) {
	env.agent.log.Debug("Discovering node configuration")
	env.agent.updateOpflexConfig()
	go env.agent.runTickers(stopCh)

	if env.agent.integ_test == nil && !env.agent.config.ChainedMode {
		go env.agent.watchRebootConf(stopCh)
	}

	env.agent.log.Debug("Starting node informer")
	go env.agent.nodeInformer.Run(stopCh)
	env.agent.log.Info("Waiting for node cache sync")
	cache.WaitForCacheSync(stopCh, env.agent.nodeInformer.HasSynced)
	env.agent.log.Info("Node cache sync successful")

	env.agent.log.Debug("Starting service informer")
	go env.agent.serviceInformer.Run(stopCh)
	env.agent.log.Info("Waiting for service cache sync")
	cache.WaitForCacheSync(stopCh, env.agent.serviceInformer.HasSynced)
	env.agent.log.Info("Service cache sync successful")

	if !env.agent.config.ChainedMode {
		env.agent.log.Debug("Starting snat global informer")
		go env.agent.snatGlobalInformer.Run(stopCh)
		env.agent.log.Info("Waiting for snat global cache sync")
		cache.WaitForCacheSync(stopCh, env.agent.snatGlobalInformer.HasSynced)
		env.agent.log.Info("Snat global cache sync successful")

		env.agent.log.Debug("Starting snat policy informer")
		go env.agent.snatPolicyInformer.Run(stopCh)
		env.agent.log.Info("Waiting for snat policy sync")
		cache.WaitForCacheSync(stopCh, env.agent.snatPolicyInformer.HasSynced)
		env.agent.log.Info("Snat policy sync successful")

		env.agent.log.Debug("Starting rdConfig informer")
		go env.agent.rdConfigInformer.Run(stopCh)
		env.agent.log.Info("Waiting for rdConfig cache sync")
		cache.WaitForCacheSync(stopCh, env.agent.rdConfigInformer.HasSynced)
		env.agent.log.Info("RdConfig cache sync successful")

		if env.agent.config.ProactiveConf {
			env.agent.log.Debug("Starting ProactiveConf informers")
			go env.agent.proactiveConfInformer.Run(stopCh)
			env.agent.log.Info("Waiting for ProactiveConf cache sync")
			cache.WaitForCacheSync(stopCh, env.agent.proactiveConfInformer.HasSynced)
			env.agent.log.Info("ProactiveConf cache sync successful")
		}
	}
	env.agent.log.Debug("Starting remaining informers")
	env.agent.log.Debug("Exporting node info: ", env.agent.config.NodeName)
	go env.agent.podInformer.Run(stopCh)
	cache.WaitForCacheSync(stopCh, env.agent.podInformer.HasSynced)
	env.agent.log.Info("Pod cache sync successful")

	env.agent.log.Debug("Starting controller informers")
	go env.agent.controllerInformer.Run(stopCh)
	env.agent.log.Info("Waiting for controller cache sync")
	cache.WaitForCacheSync(stopCh, env.agent.controllerInformer.HasSynced)
	env.agent.log.Info("controller cache sync successful")

	env.agent.serviceEndPoints.Run(stopCh)

	env.agent.log.Debug("Starting namespace informers")
	go env.agent.nsInformer.Run(stopCh)
	env.agent.log.Info("Waiting for namespace cache sync")
	cache.WaitForCacheSync(stopCh, env.agent.nsInformer.HasSynced)
	env.agent.log.Info("namespace cache sync successful")

	env.agent.log.Debug("Starting networkPolicy informers")
	go env.agent.netPolInformer.Run(stopCh)
	env.agent.log.Info("Waiting for networkPolicy cache sync")
	cache.WaitForCacheSync(stopCh, env.agent.netPolInformer.HasSynced)
	env.agent.log.Info("networkPolicy cache sync successful")

	if env.agent.config.EnableHppDirect {
		env.agent.log.Debug("Starting hpp informers")
		go env.agent.hppInformer.Run(stopCh)
		env.agent.log.Info("Waiting for hpp cache sync")
		cache.WaitForCacheSync(stopCh, env.agent.hppInformer.HasSynced)
		env.agent.log.Info("hpp cache sync successful")

		env.agent.log.Debug("Starting hostprotremoteipcontainer informers")
		go env.agent.hppRemoteIpInformer.Run(stopCh)
		env.agent.log.Info("Waiting for hostprotremoteipcontainer cache sync")
		cache.WaitForCacheSync(stopCh, env.agent.hppRemoteIpInformer.HasSynced)
		env.agent.log.Info("hostprotremoteipcontainer cache sync successful")
	}
	env.agent.log.Debug("Starting deployment informers")
	go env.agent.depInformer.Run(stopCh)
	env.agent.log.Info("Waiting for deployment cache sync")
	cache.WaitForCacheSync(stopCh, env.agent.depInformer.HasSynced)
	env.agent.log.Info("deployment cache sync successful")

	env.agent.log.Debug("Starting ReplicationController informers")
	go env.agent.rcInformer.Run(stopCh)
	env.agent.log.Info("Waiting for ReplicationController cache sync")
	cache.WaitForCacheSync(stopCh, env.agent.rcInformer.HasSynced)
	env.agent.log.Info("ReplicationController cache sync successful")

	if !env.agent.config.ChainedMode {
		env.agent.log.Debug("Starting qosPolicy informers")
		go env.agent.qosPolicyInformer.Run(stopCh)
		env.agent.log.Info("Waiting for qosPolicy cache sync")
		cache.WaitForCacheSync(stopCh, env.agent.qosPolicyInformer.HasSynced)
		env.agent.log.Info("qosPolicy cache sync successful")
	}

	if env.agent.config.OvsHardwareOffload || env.agent.config.ChainedMode {
		env.agent.log.Debug("Starting netAttDef informers")
		go env.agent.netAttDefInformer.Run(stopCh)
		env.agent.log.Info("Waiting for netAttDef cache sync")
		cache.WaitForCacheSync(stopCh, env.agent.netAttDefInformer.HasSynced)
		env.agent.log.Info("netAttDef cache sync successful")
		env.agent.log.Debug("Starting nadVlanMap informers")
		go env.agent.nadVlanMapInformer.Run(stopCh)
		cache.WaitForCacheSync(stopCh, env.agent.nadVlanMapInformer.HasSynced)
		env.agent.log.Info("nadvlanMap cache sync successful")
		env.agent.log.Debug("Starting fabricvlanpool informers")
		go env.agent.fabricVlanPoolInformer.Run(stopCh)
		cache.WaitForCacheSync(stopCh, env.agent.fabricVlanPoolInformer.HasSynced)
		env.agent.log.Info("fabricvlanpool cache sync successful")
	}

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

func (env *K8sEnvironment) CheckNetAttDefExists(netAttDefKey string) (bool, error) {
	_, exists, err := env.agent.netAttDefInformer.GetStore().GetByKey(netAttDefKey)
	return exists, err
}
