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
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strings"

	"github.com/Sirupsen/logrus"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	restclient "k8s.io/client-go/rest"

	"github.com/noironetworks/aci-containers/pkg/hostagent"
)

func main() {
	log := logrus.New()
	config := &hostagent.HostAgentConfig{}

	config.InitFlags()
	configPath := flag.String("config-path", "",
		"Absolute path to a host agent configuration file")
	version := flag.Bool("version", false, "prints github commit ID and build time")
	getIP := flag.Bool("get-node-ip", false, "prints IP address of this node")
	getVtep := flag.Bool("get-vtep", false, "prints VTEP ip and interface for this node")
	flag.Parse()

	if *version {
		if hostagent.GetVersion().GitCommit != "" {
			buffer := bytes.NewBufferString(hostagent.VersionString())
			fmt.Println(buffer.String())
		} else {
			fmt.Println("Information missing in current build")
		}
		os.Exit(0)
	}

	if *getIP {
		ip, err := getNodeIP()
		if err != nil {
			fmt.Println(err.Error())
			os.Exit(-1)
		}

		fmt.Println(ip)
		os.Exit(0)
	}

	if *getVtep {
		ip, err := getNodeIP()
		if err != nil {
			fmt.Println(err.Error())
			os.Exit(-1)
		}
		ifaces, err := net.Interfaces()
		if err != nil {
			fmt.Println(err.Error())
			os.Exit(-1)
		}
		for _, i := range ifaces {
			addrs, err := i.Addrs()
			if err != nil {
				continue
			}
			for _, a := range addrs {
				if strings.HasPrefix(a.String(), ip) {
					fmt.Println(i.Name, a.String())
					os.Exit(0)
				}
			}
		}
		os.Exit(-1)
	}

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

		logrus.Infof("config: %+v", *config)
	}

	logLevel, err := logrus.ParseLevel(config.LogLevel)
	if err != nil {
		panic(err.Error())
	}
	log.Level = logLevel
	if config.ChildMode {
		hostagent.StartPlugin(log)
		return
	}

	log.WithFields(logrus.Fields{
		"config-path": *configPath,
		"logLevel":    logLevel,
		"domain-type": config.AciVmmDomainType,
	}).Info("Starting")

	var env hostagent.Environment
	domType := strings.ToLower(config.AciVmmDomainType)
	if domType == "kubernetes" || domType == "openshift" {
		env, err = hostagent.NewK8sEnvironment(config, log)
	} else if domType == "cloudfoundry" {
		env, err = hostagent.NewCfEnvironment(config, log)
	} else {
		err = errors.New("Unsupported ACI VMM domain type " + config.AciVmmDomainType)
		log.Error(err)
	}

	if err != nil {
		log.Error("Environment set up failed for domain type ", config.AciVmmDomainType)
		panic(err.Error())
	}

	if hostagent.GetVersion().GitCommit != "" {
		versionInfo := hostagent.GetVersion()
		log.Info("Running hostagent built from git commit ID " +
			versionInfo.GitCommit + " at build time " +
			versionInfo.BuildTime)
	}

	agent := hostagent.NewHostAgent(config, env, log)
	agent.Init()
	agent.Run(wait.NeverStop)
	agent.RunPacketEventListener(wait.NeverStop)
	agent.RunStatus()
}

func getNodeIP() (string, error) {
	var options metav1.ListOptions
	nodeName := os.Getenv("KUBERNETES_NODE_NAME")
	if nodeName == "" {
		return "", fmt.Errorf("KUBERNETES_NODE_NAME must be set")
	}

	restconfig, err := restclient.InClusterConfig()
	if err != nil {
		return "", fmt.Errorf("Error getting config: %v", err)
	}

	kubeClient, err := kubernetes.NewForConfig(restconfig)
	if err != nil {
		return "", fmt.Errorf("Error initializing client: %v", err)
	}

	options.FieldSelector = fields.Set{"metadata.name": nodeName}.String()
	nodeList, err := kubeClient.CoreV1().Nodes().List(options)
	if err != nil {
		return "", fmt.Errorf("Error listing nodes: %v", err)
	}

	for _, node := range nodeList.Items {
		for _, a := range node.Status.Addresses {
			if a.Type == v1.NodeInternalIP {
				return a.Address, nil
			}
		}
	}

	return "", fmt.Errorf("Failed to list node")
}
