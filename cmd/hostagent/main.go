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
	"os"
	"strings"

	"github.com/Sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/noironetworks/aci-containers/pkg/hostagent"
)

func main() {
	log := logrus.New()
	config := &hostagent.HostAgentConfig{}

	config.InitFlags()
	configPath := flag.String("config-path", "",
		"Absolute path to a host agent configuration file")
	version := flag.Bool("version", false, "prints github commit ID and build time")
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
	if config.ChildMode {
		hostagent.StartPlugin(log, config)
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
	agent.RunStatus()
}
