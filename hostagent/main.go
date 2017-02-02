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

	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"

	md "github.com/noironetworks/aci-containers/metadata"
)

var log = logrus.New()

func main() {
	agent := newHostAgent()

	agent.initFlags()
	configPath := flag.String("config-path", "",
		"Absolute path to a host agent configuration file")
	flag.Parse()

	if configPath != nil && *configPath != "" {
		log.Info("Loading configuration from ", *configPath)
		raw, err := ioutil.ReadFile(*configPath)
		if err != nil {
			panic(err.Error())
		}
		err = json.Unmarshal(raw, agent.config)
		if err != nil {
			panic(err.Error())
		}
	}

	logLevel, err := logrus.ParseLevel(agent.config.LogLevel)
	if err != nil {
		panic(err.Error())
	}
	log.Level = logLevel

	if agent.config.NodeName == "" {
		agent.config.NodeName = os.Getenv("KUBERNETES_NODE_NAME")
	}
	if agent.config.NodeName == "" {
		err := errors.New("Node name not specified and $KUBERNETES_NODE_NAME empty")
		log.Error(err.Error())
		panic(err.Error())
	}

	log.WithFields(logrus.Fields{
		"kubeconfig":  agent.config.KubeConfig,
		"node-name":   agent.config.NodeName,
		"config-path": *configPath,
		"logLevel":    logLevel,
	}).Info("Starting")

	log.Debug("Initializing kubernetes client")
	var restconfig *restclient.Config
	if agent.config.KubeConfig != "" {
		// use kubeconfig file from command line
		restconfig, err =
			clientcmd.BuildConfigFromFlags("", agent.config.KubeConfig)
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
	agent.kubeClient, err = kubernetes.NewForConfig(restconfig)
	if err != nil {
		panic(err.Error())
	}

	log.Debug("Initializing endpoint CNI metadata")
	// Initialize metadata cache
	err = md.LoadMetadata(agent.config.CniMetadataDir,
		agent.config.CniNetwork, &agent.epMetadata)
	if err != nil {
		panic(err.Error())
	}
	log.Info("Loaded cached endpoint CNI metadata: ", len(agent.epMetadata))

	// Initialize RPC service for communicating with CNI plugin
	log.Debug("Initializing endpoint RPC")
	err = agent.initEpRPC()
	if err != nil {
		panic(err.Error())
	}

	var wg sync.WaitGroup
	wg.Add(1)

	log.Debug("Initializing node informer")
	// Initialize informers
	agent.initNodeInformer()
	log.Debug("Waiting for node cache sync")
	cache.WaitForCacheSync(wait.NeverStop, agent.nodeInformer.HasSynced)
	log.Debug("Node cache sync successful")

	log.Debug("Initializing remaining informers")
	agent.initPodInformer()
	agent.initEndpointsInformer()
	agent.initServiceInformer()

	go func() {
		log.Debug("Waiting for cache sync for remaining objects")
		cache.WaitForCacheSync(wait.NeverStop,
			agent.podInformer.HasSynced, agent.endpointsInformer.HasSynced,
			agent.serviceInformer.HasSynced)

		log.Info("Enabling OpFlex endpoint and service sync")
		agent.indexMutex.Lock()
		agent.syncEnabled = true
		agent.syncServices()
		agent.syncEps()
		agent.indexMutex.Unlock()
		log.Debug("Initial OpFlex sync complete")

		agent.cleanupSetup()
	}()

	wg.Wait()
}
