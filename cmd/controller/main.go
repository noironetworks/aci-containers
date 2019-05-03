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

	"github.com/noironetworks/aci-containers/pkg/controller"
)

func main() {
	log := logrus.New()
	config := controller.NewConfig()

	controller.InitFlags(config)
	configPath := flag.String("config-path", "",
		"Absolute path to a host agent configuration file")
	version := flag.Bool("version", false, "prints github commit ID and build time")
	flag.Parse()

	if *version {
		if controller.GetVersion().GitCommit != "" {
			buffer := bytes.NewBufferString(controller.VersionString())
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
		"logLevel":        logLevel,
		"vmm-domain-type": config.AciVmmDomainType,
	}).Info("Starting")

	var env controller.Environment
	domType := strings.ToLower(config.AciVmmDomainType)
	if domType == "kubernetes" || domType == "openshift" {
		env, err = controller.NewK8sEnvironment(config, log)
	} else if domType == "cloudfoundry" {
		env, err = controller.NewCfEnvironment(config, log)
	} else {
		err = errors.New("Unsupported ACI VMM domain type " + config.AciVmmDomainType)
		log.Error(err)
	}

	if err != nil {
		log.Error("Environment set up failed for VMM domain type ", config.AciVmmDomainType)
		panic(err.Error())
	}

	if controller.GetVersion().GitCommit != "" {
		versionInfo := controller.GetVersion()
		log.Info("Running controller built from git commit ID " +
                          versionInfo.GitCommit + " at build time " +
                          versionInfo.BuildTime)
	}

	cont := controller.NewController(config, env, log)
	cont.Init()
	cont.Run(wait.NeverStop)
	cont.RunStatus()
}
