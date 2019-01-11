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
	"flag"
	"fmt"
	"net/url"
	"os"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/coreos/etcd/embed"

	"github.com/noironetworks/aci-containers/pkg/apiserver"
)

type cliOpts struct {
	etcdDir       string
	etcdPort      string
	apiListenPort string
	insecurePort  string
}

func main() {
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
	err := flagSet.Parse(os.Args[1:])
	if err != nil {
		log.Fatalf("Failed to parse command. Error: %s", err)
	}

	etcdURLs := startEtcd(&opts)
	lPort := fmt.Sprintf(":%s", opts.apiListenPort)
	insPort := ""
	if opts.insecurePort != "" {
		insPort = fmt.Sprintf(":%s", opts.insecurePort)
	}

	_, err = apiserver.StartNewServer(etcdURLs, lPort, insPort)
	if err != nil {
		log.Fatalf("Starting api server: %v", err)
	}

	log.Infof("Api server listening at %s", lPort)

	select {}
}

// panics on error
func startEtcd(opts *cliOpts) []string {
	var etcdClientURLs = []string{fmt.Sprintf("http://localhost:%s", opts.etcdPort)}
	var lcURLs []url.URL

	for _, u := range etcdClientURLs {
		uu, err := url.Parse(u)
		if err != nil {
			log.Fatalf("url.Parse: %v", err)
		}

		lcURLs = append(lcURLs, *uu)
	}

	err := os.MkdirAll(opts.etcdDir, os.ModePerm)
	if err != nil {
		log.Fatalf("os.MkdirAll: %v", err)
	}

	cfg := embed.NewConfig()
	cfg.Dir = opts.etcdDir
	cfg.LCUrls = lcURLs

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
