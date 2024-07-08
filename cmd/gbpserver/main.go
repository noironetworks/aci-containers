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
	"net/http"
	"os"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/exporters/prometheus"

	"github.com/noironetworks/aci-containers/pkg/gbpserver"
	"github.com/noironetworks/aci-containers/pkg/gbpserver/watchers"
)

type cliOpts struct {
	configPath string
	version    bool
	inspect    string
	vtep       string
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
		raw, err := os.ReadFile(opts.configPath)
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

	s, err := gbpserver.StartNewServer(cfg)
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
	logrus.Infof("Listening for intent from k8s")
	kw.InitIntentInformers(stopCh)
	kw.InitEPInformer(stopCh)

	if nfw != nil {
		nfw.InitNetflowInformer(stopCh)
	}

	if cfg.EnableMetrics {
		_, err = prometheus.New()
		if err != nil {
			// keep going?
			logrus.Error(err)
		}

		go serveMetrics(cfg.MetricsPort)
	}

	select {}
}

func parseCli(opts *cliOpts) {
	flag.StringVar(&opts.configPath,
		"config-path", "None", "Path to gbp config")
	flag.BoolVar(&opts.version,
		"version", false, "Print version information")
	flag.StringVar(&opts.inspect,
		"inspect", "", "Print grpc|vtep information")
	flag.StringVar(&opts.vtep,
		"vtep", "all", "Limit grpc info to the specific VTEP")
	flag.Parse()
}

func serveMetrics(metricsPort int) {
	http.Handle("/metrics", promhttp.Handler())
	err := http.ListenAndServe(fmt.Sprintf(":%d", metricsPort), nil)
	if err != nil {
		logrus.Errorf("error serving http: %v", err)
	}
}
