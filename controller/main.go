// Copyright 2016 Cisco Systems, Inc.
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
	"flag"
	"io/ioutil"
	"sync"

	"github.com/Sirupsen/logrus"

	"k8s.io/kubernetes/pkg/client/cache"
	clientset "k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset"
	"k8s.io/kubernetes/pkg/client/restclient"
	"k8s.io/kubernetes/pkg/client/unversioned/clientcmd"
)

var (
	log = logrus.New()

	configPath = flag.String("config-path", "", "Absolute path to a host agent configuration file")
	config     = &ControllerConfig{}

	defaultEg = ""
	defaultSg = ""

	indexMutex = &sync.Mutex{}
	depPods    = make(map[string]string)

	kubeClient         *clientset.Clientset
	namespaceInformer  cache.SharedIndexInformer
	podInformer        cache.SharedIndexInformer
	endpointsInformer  cache.SharedIndexInformer
	serviceInformer    cache.SharedIndexInformer
	deploymentInformer cache.SharedIndexInformer
	nodeInformer       cache.SharedIndexInformer
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
	logrus.SetLevel(logLevel)

	egdata, err := json.Marshal(config.DefaultEg)
	if err != nil {
		log.Error("Could not serialize default endpoint group")
		panic(err.Error())
	}
	defaultEg = string(egdata)

	sgdata, err := json.Marshal(config.DefaultSg)
	if err != nil {
		log.Error("Could not serialize default security groups")
		panic(err.Error())
	}
	defaultSg = string(sgdata)

	log.WithFields(logrus.Fields{
		"kubeconfig": config.KubeConfig,
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

	// creates the client
	kubeClient, err = clientset.NewForConfig(restconfig)
	if err != nil {
		panic(err.Error())
	}

	var wg sync.WaitGroup
	wg.Add(1)

	initNamespaceInformer()
	initDeploymentInformer()
	initPodInformer()

	initEndpointsInformer()
	initServiceInformer()

	//	go func() {
	//		time.Sleep(time.Second * 5)
	//		syncEnabled = true
	//		indexMutex.Lock()
	//		defer indexMutex.Unlock()
	//		syncServices()
	//		syncEps()
	//	}()

	wg.Wait()
}
