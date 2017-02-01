// Copyright 2016,2017 Cisco Systems, Inc.
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

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"io/ioutil"
	"os"
	"sync"

	"github.com/Sirupsen/logrus"

	"k8s.io/kubernetes/pkg/client/cache"
	clientset "k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset"
	"k8s.io/kubernetes/pkg/client/restclient"
	"k8s.io/kubernetes/pkg/client/unversioned/clientcmd"
	"k8s.io/kubernetes/pkg/util/wait"

	md "github.com/noironetworks/aci-containers/metadata"
)

var (
	log = logrus.New()

	configPath = flag.String("config-path", "",
		"Absolute path to a host agent configuration file")
	config = &HostAgentConfig{}

	indexMutex     sync.Mutex
	opflexEps      = make(map[string]*opflexEndpoint)
	opflexServices = make(map[string]*opflexService)
	epMetadata     = make(map[string]*md.ContainerMetadata)
	serviceEp      md.ServiceEndpoint

	podInformer       cache.SharedIndexInformer
	endpointsInformer cache.SharedIndexInformer
	serviceInformer   cache.SharedIndexInformer
	nodeInformer      cache.SharedIndexInformer

	syncEnabled = false
)

func main() {
	initFlags()
	flag.Parse()

	if configPath != nil && *configPath != "" {
		log.Info("Loading configuration from ", *configPath)
		raw, err := ioutil.ReadFile(*configPath)
		if err != nil {
			panic(err.Error())
		}
		err = json.Unmarshal(raw, config)
		if err != nil {
			panic(err.Error())
		}
	}

	logLevel, err := logrus.ParseLevel(config.LogLevel)
	if err != nil {
		panic(err.Error())
	}
	log.Level = logLevel

	if config.NodeName == "" {
		config.NodeName = os.Getenv("KUBERNETES_NODE_NAME")
	}
	if config.NodeName == "" {
		err := errors.New("Node name not specified and $KUBERNETES_NODE_NAME empty")
		log.Error(err.Error())
		panic(err.Error())
	}

	log.WithFields(logrus.Fields{
		"kubeconfig":  config.KubeConfig,
		"node-name":   config.NodeName,
		"config-path": *configPath,
		"logLevel":    logLevel,
	}).Info("Starting")

	log.Debug("Initializing kubernetes client")
	var restconfig *restclient.Config
	if config.KubeConfig != "" {
		// use kubeconfig file from command line
		restconfig, err = clientcmd.BuildConfigFromFlags("", config.KubeConfig)
		if err != nil {
			panic(err.Error())
		}
	} else {
		// creates the in-cluster config
		restconfig, err = restclient.InClusterConfig()
		if err != nil {
			panic(err.Error())
		}
	}

	// creates the kubernetes API client
	kubeClient, err := clientset.NewForConfig(restconfig)
	if err != nil {
		panic(err.Error())
	}

	log.Debug("Initializing endpoint CNI Metadata")
	// Initialize metadata cache
	err = md.LoadMetadata(config.CniMetadataDir, config.CniNetwork, &epMetadata)
	if err != nil {
		panic(err.Error())
	}
	log.Info("Loaded cached endpoint CNI metadata: ", len(epMetadata))

	// Initialize RPC service for communicating with CNI plugin
	log.Debug("Initializing endpoint RPC")
	err = initEpRPC()
	if err != nil {
		panic(err.Error())
	}

	var wg sync.WaitGroup
	wg.Add(1)

	log.Debug("Initializing node informer")
	// Initialize informers
	initNodeInformer(kubeClient)
	log.Debug("Waiting for node cache sync")
	cache.WaitForCacheSync(wait.NeverStop, nodeInformer.HasSynced)
	log.Debug("Node cache sync successful")

	log.Debug("Initializing remaining informers")
	initPodInformer(kubeClient)
	initEndpointsInformer(kubeClient)
	initServiceInformer(kubeClient)

	go func() {
		log.Debug("Waiting for cache sync for remaining objects")
		cache.WaitForCacheSync(wait.NeverStop,
			podInformer.HasSynced, endpointsInformer.HasSynced,
			serviceInformer.HasSynced)

		log.Info("Enabling OpFlex endpoint and service sync")
		indexMutex.Lock()
		syncEnabled = true
		syncServices()
		syncEps()
		indexMutex.Unlock()
		log.Debug("Initial OpFlex sync complete")

		cleanupSetup()
	}()

	wg.Wait()
}
