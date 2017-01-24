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
	goruntime "runtime"
	"sync"
	"time"

	"github.com/Sirupsen/logrus"

	"k8s.io/kubernetes/pkg/client/cache"
	clientset "k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset"
	"k8s.io/kubernetes/pkg/client/restclient"
	"k8s.io/kubernetes/pkg/client/unversioned/clientcmd"

	md "github.com/noironetworks/aci-containers/cnimetadata"
)

var (
	log = logrus.New()

	configPath = flag.String("config-path", "", "Absolute path to a host agent configuration file")
	config     = &HostAgentConfig{}

	indexMutex     = &sync.Mutex{}
	opflexEps      = make(map[string]*opflexEndpoint)
	opflexServices = make(map[string]*opflexService)
	epMetadata     = make(map[string]*md.ContainerMetadata)

	podInformer       cache.SharedIndexInformer
	endpointsInformer cache.SharedIndexInformer
	serviceInformer   cache.SharedIndexInformer

	syncEnabled = false
)

func init() {
	// this ensures that main runs only on main thread (thread group leader).
	// since namespace ops (unshare, setns) are done for a single thread, we
	// must ensure that the goroutine does not jump from OS thread to thread
	goruntime.LockOSThread()
}

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
	logrus.SetLevel(logLevel)

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
	}).Info("Starting")

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

	// Initialize metadata cache
	err = md.LoadMetadata(config.CniMetadataDir, config.CniNetwork, &epMetadata)
	if err != nil {
		panic(err.Error())
	}
	log.Info("Loaded cached metadata data: ", len(epMetadata))

	// Initialize RPC service for communicating with CNI plugin
	err = initEpRPC()
	if err != nil {
		panic(err.Error())
	}

	var wg sync.WaitGroup
	wg.Add(1)

	// Initialize informers
	initPodInformer(kubeClient)
	initEndpointsInformer(kubeClient)
	initServiceInformer(kubeClient)

	go func() {
		time.Sleep(time.Second * 5)
		syncEnabled = true
		indexMutex.Lock()
		defer indexMutex.Unlock()
		syncServices()
		syncEps()
	}()

	go func() {
		time.Sleep(time.Minute * 5)
		cleanupConfiguration()
	}()

	wg.Wait()
}
