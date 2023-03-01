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
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"time"

	"github.com/sirupsen/logrus"
	"go.etcd.io/etcd/server/v3/embed"

	"github.com/noironetworks/aci-containers/pkg/gbpserver"
	"github.com/noironetworks/aci-containers/pkg/gbpserver/stateinit"
	"github.com/noironetworks/aci-containers/pkg/gbpserver/watchers"
)

type cliOpts struct {
	configPath string
	version    bool
	inspect    string
	vtep       string
	epg        string
	init       bool
}

func main() {
	var opts cliOpts

	cfg := &gbpserver.GBPServerConfig{}
	gbpserver.InitConfig(cfg)
	parseCli(&opts)

	if opts.version {
		if gbpserver.GetVersion().GitCommit != "" {
			buffer := bytes.NewBufferString(gbpserver.VersionString())
			fmt.Println(buffer.String())
		} else {
			fmt.Println("Information missing in current build")
		}
		os.Exit(0)
	}

	if opts.configPath != "None" {
		logrus.Info("Loading configuration from ", opts.configPath)
		raw, err := ioutil.ReadFile(opts.configPath)
		if err != nil {
			panic(err.Error())
		}
		err = json.Unmarshal(raw, cfg)
		if err != nil {
			panic(err.Error())
		}
	}

	if opts.inspect != "" {
		handleInspect(&opts, cfg)
		os.Exit(0)
	}

	// set the global log level
	level, err := logrus.ParseLevel(cfg.LogLevel)
	if err != nil {
		panic(err.Error())
	}
	logrus.SetLevel(level)

	if opts.init {
		stateinit.Run(cfg)
		os.Exit(0)
	}

	stateDriver := &watchers.K8sStateDriver{}
	err = stateDriver.Init(watchers.FieldClassID)
	if err != nil {
		logrus.Fatalf("State Driver: %v", err)
	}

	var etcdURLs []string
	if cfg.Apic != nil {
		etcdURLs = startEtcd(cfg)
	}
	s, err := gbpserver.StartNewServer(cfg, stateDriver, etcdURLs)
	if err != nil {
		logrus.Fatalf("Starting api server: %v", err)
	}

	kw, err := watchers.NewK8sWatcher(s)
	if err != nil {
		logrus.Fatalf("Starting k8s watcher : %v", err)
	}
	nfw, err := watchers.NewNetflowWatcher(s)
	if err != nil {
		logrus.Fatalf("Starting netflow watcher : %v", err)
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

	if nfw != nil {
		nfw.InitNetflowInformer(stopCh)
	}

	select {}
}

func parseCli(opts *cliOpts) {
	flag.StringVar(&opts.configPath,
		"config-path", "None", "Path to gbp config")
	flag.BoolVar(&opts.version,
		"version", false, "Print version information")
	flag.StringVar(&opts.inspect,
		"inspect", "", "Print grpc|vtep|kafka information")
	flag.StringVar(&opts.vtep,
		"vtep", "all", "Limit grpc info to the specific VTEP")
	flag.StringVar(&opts.epg,
		"epg", "all", "Limit kafka info to the specific epg")
	flag.BoolVar(&opts.init,
		"init", false, "Initalize state and exit")
	flag.Parse()
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
