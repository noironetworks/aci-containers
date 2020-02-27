// Copyright 2018 Cisco Systems, Inc.
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
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"time"

	"github.com/coreos/etcd/embed"
	"github.com/sirupsen/logrus"

	"github.com/noironetworks/aci-containers/pkg/gbpserver"
	"github.com/noironetworks/aci-containers/pkg/gbpserver/watchers"
)

type cliOpts struct {
	etcdDir       string
	etcdPort      string
	apiListenPort string
	insecurePort  string
	grpcPort      string
	moDir         string
	cAPICUrl      string
	region        string
}

func main() {
	cfg := &gbpserver.GBPServerConfig{}
	gbpserver.InitConfig(cfg)

	configPath := flag.String("config-path", "",
		"Absolute path to a gbp-server configuration file")
	//	version := flag.Bool("version", false, "prints github commit ID and build time")
	flag.Parse()
	/*	if *version {
		if gbpserver.GetVersion().GitCommit != "" {
			buffer := bytes.NewBufferString(controller.VersionString())
			fmt.Println(buffer.String())
		} else {
			fmt.Println("Information missing in current build")
		}
		os.Exit(0)
	} */

	if configPath != nil && *configPath != "None" {
		logrus.Info("Loading configuration from ", *configPath)
		raw, err := ioutil.ReadFile(*configPath)
		if err != nil {
			panic(err.Error())
		}
		err = json.Unmarshal(raw, cfg)
		if err != nil {
			panic(err.Error())
		}
	}

	// set the global log level
	level, err := logrus.ParseLevel(cfg.LogLevel)
	if err != nil {
		panic(err.Error())
	}
	logrus.SetLevel(level)

	stateDriver := &watchers.K8sStateDriver{}
	err = stateDriver.Init(watchers.FieldClassID)
	if err != nil {
		logrus.Fatalf("State Driver: %v", err)
	}

	etcdURLs := startEtcd(cfg)
	s, err := gbpserver.StartNewServer(cfg, stateDriver, etcdURLs)
	if err != nil {
		logrus.Fatalf("Starting api server: %v", err)
	}

	kw, err := watchers.NewK8sWatcher(s)
	if err != nil {
		logrus.Fatalf("Starting k8s watcher : %v", err)
	}

	stopCh := make(chan struct{})
	if cfg.Apic == nil || cfg.Apic.Hosts == nil {
		logrus.Infof("Listening for intent from k8s")
		kw.InitIntentInformers(stopCh)
	} else {
		logrus.Infof("Listening for intent from apic")
		aw := watchers.NewApicWatcher(s)
		err = aw.Init(cfg.Apic.Hosts, stopCh)
		if err != nil {
			logrus.Fatalf("Starting apic watch: %v", err)
		}
	}
	kw.InitEPInformer(stopCh)

	select {}
}

// panics on error
func startEtcd(c *gbpserver.GBPServerConfig) []string {

	urlMaker := func(portNo int) []url.URL {
		var urlList []url.URL
		var rawList = []string{fmt.Sprintf("http://localhost:%d", portNo)}
		for _, u := range rawList {
			uu, err := url.Parse(u)
			if err != nil {
				logrus.Fatalf("url.Parse: %v", err)
			}

			urlList = append(urlList, *uu)
		}

		return urlList
	}

	err := os.MkdirAll(c.EtcdDir, os.ModePerm)
	if err != nil {
		logrus.Fatalf("os.MkdirAll: %v", err)
	}

	cfg := embed.NewConfig()
	cfg.Dir = c.EtcdDir
	cfg.LCUrls = urlMaker(c.EtcdPort)
	cfg.LPUrls = urlMaker(c.EtcdPort + 1)
	cfg.EnableV2 = true

	e, err := embed.StartEtcd(cfg)
	if err != nil {
		logrus.Fatalf("StartEtcd: %v", err)
	}

	select {
	case <-e.Server.ReadyNotify():
		logrus.Infof("Server is ready!")
	case <-time.After(60 * time.Second):
		e.Server.Stop() // trigger a shutdown
		logrus.Fatalf("Etcd Server took too long to start!")
	}

	return []string{fmt.Sprintf("http://localhost:%d", c.EtcdPort)}
}
