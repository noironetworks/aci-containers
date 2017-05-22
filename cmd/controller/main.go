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
	"os"

	"github.com/Sirupsen/logrus"

	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/noironetworks/aci-containers/pkg/controller"
)

func main() {
	log := logrus.New()
	config := controller.NewConfig()

	controller.InitFlags(config)
	configPath := flag.String("config-path", "",
		"Absolute path to a host agent configuration file")
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

	if config.ApicUsername == "" {
		config.ApicUsername = os.Getenv("APIC_USERNAME")
	}
	if config.ApicPassword == "" {
		config.ApicPassword = os.Getenv("APIC_PASSWORD")
	}

	logLevel, err := logrus.ParseLevel(config.LogLevel)
	if err != nil {
		panic(err.Error())
	}
	log.Level = logLevel

	log.WithFields(logrus.Fields{
		"kubeconfig": config.KubeConfig,
		"logLevel":   logLevel,
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

	// creates the client
	kubeClient, err := kubernetes.NewForConfig(restconfig)
	if err != nil {
		panic(err.Error())
	}

	npconfig := *restconfig
	controller.ConfigureNetPolClient(&npconfig)
	netPolClient, err := rest.RESTClientFor(&npconfig)
	if err != nil {
		panic(err)
	}

	cont := controller.NewController(config, log)
	cont.Init(kubeClient, netPolClient)
	cont.Run(wait.NeverStop)
	cont.RunStatus()
}
