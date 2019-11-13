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

	log "github.com/Sirupsen/logrus"
	"github.com/coreos/etcd/embed"

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
		log.Info("Loading configuration from ", *configPath)
		raw, err := ioutil.ReadFile(*configPath)
		if err != nil {
			panic(err.Error())
		}
		err = json.Unmarshal(raw, cfg)
		if err != nil {
			panic(err.Error())
		}
	}

	/*
		var opts cliOpts
		var flagSet *flag.FlagSet

		flagSet = flag.NewFlagSet("moServer", flag.ExitOnError)
		flagSet.StringVar(&opts.etcdDir, "etcd-dir", "/var/moserver/etcd",
			"Path to etcd data store")
		flagSet.StringVar(&opts.etcdPort, "etcd-port", "12379",
			"Client port for etcd")
		flagSet.StringVar(&opts.apiListenPort, "api-listen-port", "8899",
			"Listen port for moserver")
		flagSet.StringVar(&opts.insecurePort, "insecure-port", "",
			"Listen port for moserver")
		flagSet.StringVar(&opts.grpcPort, "grpc-port", "19999",
			"Listen port for grpc server")
		flagSet.StringVar(&opts.moDir, "mo-dir", "/kube",
			"GBP backup dir")
		flagSet.StringVar(&opts.cAPICUrl, "capic-url", "None",
			"Cloud APIC Url")
		flagSet.StringVar(&opts.region, "aws-region", "None",
			"AWS region")
		err := flagSet.Parse(os.Args[1:])
		if err != nil {
			log.Fatalf("Failed to parse command. Error: %s", err)
		}

		lPort := fmt.Sprintf(":%s", opts.apiListenPort)
		insPort := ""
		if opts.insecurePort != "" {
			insPort = fmt.Sprintf(":%s", opts.insecurePort)
		}

		grpcPort := fmt.Sprintf(":%s", opts.grpcPort)
		//gbpserver.InitDB(opts.moDir, opts.cAPICUrl, opts.region)
		//gbpserver.InitDB(opts.moDir, "None", opts.region)
	*/

	stateDriver := &watchers.K8sStateDriver{}
	err := stateDriver.Init()
	if err != nil {
		log.Fatalf("State Driver: %v", err)
	}

	etcdURLs := startEtcd(cfg)
	s, err := gbpserver.StartNewServer(cfg, stateDriver, etcdURLs)
	if err != nil {
		log.Fatalf("Starting api server: %v", err)
	}

	kw, err := watchers.NewK8sWatcher(s)
	if err != nil {
		log.Fatalf("Starting k8s watcher : %v", err)
	}

	stopCh := make(chan struct{})
	if cfg.Apic == nil || cfg.Apic.Hosts == nil {
		log.Infof("Listening for intent from k8s")
		kw.InitIntentInformers(stopCh)
	} else {
		log.Infof("Listening for intent from apic")
		aw := watchers.NewApicWatcher(s)
		err = aw.Init(cfg.Apic.Hosts, stopCh)
		if err != nil {
			log.Fatalf("Starting apic watch: %v", err)
		}
	}
	kw.InitEPInformer(stopCh)

	select {}
}

// panics on error
func startEtcd(c *gbpserver.GBPServerConfig) []string {
	var etcdClientURLs = []string{fmt.Sprintf("http://localhost:%d", c.EtcdPort)}
	var lcURLs []url.URL

	for _, u := range etcdClientURLs {
		uu, err := url.Parse(u)
		if err != nil {
			log.Fatalf("url.Parse: %v", err)
		}

		lcURLs = append(lcURLs, *uu)
	}

	err := os.MkdirAll(c.EtcdDir, os.ModePerm)
	if err != nil {
		log.Fatalf("os.MkdirAll: %v", err)
	}

	cfg := embed.NewConfig()
	cfg.Dir = c.EtcdDir
	cfg.LCUrls = lcURLs
	cfg.EnableV2 = true

	e, err := embed.StartEtcd(cfg)
	if err != nil {
		log.Fatalf("StartEtcd: %v", err)
	}

	select {
	case <-e.Server.ReadyNotify():
		log.Infof("Server is ready!")
	case <-time.After(60 * time.Second):
		e.Server.Stop() // trigger a shutdown
		log.Fatalf("Etcd Server took too long to start!")
	}

	return etcdClientURLs
}
