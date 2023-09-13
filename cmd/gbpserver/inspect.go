// Copyright 2020 Cisco Systems, Inc.
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
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Shopify/sarama"
	"google.golang.org/grpc"

	"github.com/noironetworks/aci-containers/pkg/gbpserver"
	"github.com/noironetworks/aci-containers/pkg/gbpserver/kafkac"
)

func handleInspect(opts *cliOpts, cfg *gbpserver.GBPServerConfig) {
	if opts.configPath == "None" {
		defaultConfig, exists := os.LookupEnv("GBP_SERVER_CONF")
		fmt.Printf("default config path - %s\n", defaultConfig)
		if exists {
			opts.configPath = defaultConfig
		} else {
			fmt.Printf("Please specify config-path ($GBP_SERVER_CONF)\n")
			return
		}
	}

	switch opts.inspect {
	case "grpc":
		inspectGRPC(opts, cfg)

	case "vteps":
		inspectGRPC(opts, cfg)

	case "kafka":
		if cfg.Apic == nil {
			fmt.Printf("Need cfg.Apic for kafka\n")
			return
		}
		inspectKafka(opts, cfg)

	default:
		fmt.Printf("Unknown inspect type (need grpc, vteps or kafka)")
	}
}

func inspectGRPC(opts *cliOpts, cfg *gbpserver.GBPServerConfig) {
	// setup a connection to grpc server

	addr := fmt.Sprintf("localhost:%d", cfg.GRPCPort)
	conn, err := grpc.Dial(addr, grpc.WithInsecure())
	c := gbpserver.NewGBPClient(conn)
	if err != nil {
		fmt.Printf("grpc.Dial returned %v", err)
		return
	}
	defer conn.Close()

	if opts.inspect == "vteps" {
		vl, err := c.ListVTEPs(context.Background(),
			&gbpserver.EmptyMsg{},
			grpc.WaitForReady(true))
		if err != nil {
			fmt.Printf("ListVTEPs returned %v", err)
			return
		}

		fmt.Printf("VTEPS:\n")
		for _, vtep := range vl.Vteps {
			fmt.Printf("  %s\n", vtep)
		}
		return
	}

	snap, err := c.GetSnapShot(context.Background(),
		&gbpserver.VTEP{Vtep: opts.vtep},
		grpc.WaitForReady(true))

	if err != nil {
		fmt.Printf("GetSnapShot returned %v", err)
		return
	}

	policyJson, err := json.MarshalIndent(snap.MoList, "", "    ")
	if err != nil {
		fmt.Printf("ERROR: %v", err)
	}
	fmt.Printf("%s", policyJson)
}

func inspectKafka(opts *cliOpts, cfg *gbpserver.GBPServerConfig) {
	cc, err := kafkac.GetClientConfig(cfg.Apic.Kafka)
	if err != nil {
		fmt.Printf("GetClientConfig returned %v", err)
		return
	}

	cons, err := sarama.NewConsumer(cfg.Apic.Kafka.Brokers, cc)
	if err != nil {
		fmt.Printf("sarama.NewConsumer returned %v", err)
		return
	}

	pc, err := cons.ConsumePartition(cfg.Apic.Kafka.Topic,
		0, sarama.OffsetOldest)
	if err != nil {
		fmt.Printf("sarama.ConsumePartition returned %v", err)
		return
	}

	consChan := pc.Messages()
	epMap := make(map[string]*kafkac.CapicEPMsg)

	func() {
		fmt.Printf("Getting ep's from Kafka...\n")
		for {
			select {
			case <-time.After(10 * time.Second):
				return
			case m, ok := <-consChan:
				if !ok {
					return
				}

				if m.Value == nil {
					delete(epMap, string(m.Key))
					continue
				}

				epMsg := new(kafkac.CapicEPMsg)
				err := json.Unmarshal(m.Value, epMsg)
				if err != nil {
					fmt.Printf("Error %v, %s", err, m.Value)
					continue
				}

				epMap[string(m.Key)] = epMsg
			}
		}
	}()

	fmt.Printf("Received %d total endpoints\n", len(epMap))
	if opts.epg != "all" {
		fmt.Printf("Showing ep's that match epg %s", opts.epg)
	}
	for _, ep := range epMap {
		if opts.epg == "all" || strings.Contains(ep.EpgDN, opts.epg) {
			epJson, _ := json.MarshalIndent(ep, "", "    ")
			fmt.Printf("%s", epJson)
		}
	}
}
