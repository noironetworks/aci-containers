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

	"github.com/Sirupsen/logrus"

	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

var log = logrus.New()

// go get github.com/a-h/generate
// go install github.com/a-h/generate/cmd/schema-generate
//go:generate schema-generate -i schema/aim_schema.json  -o aim_schema.go

func main() {
	config := newConfig()

	initFlags(config)
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
	err = initAimThirdPartyResource(kubeClient)
	if err != nil {
		panic(err.Error())
	}

	configureAimClient(restconfig)
	tprClient, err := rest.RESTClientFor(restconfig)
	if err != nil {
		panic(err)
	}

	cont := newController(config)
	cont.init(kubeClient, tprClient)
	cont.run(wait.NeverStop)
	cont.runStatus()
}
