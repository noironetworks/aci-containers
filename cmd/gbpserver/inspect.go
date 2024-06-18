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

	"google.golang.org/grpc"

	"github.com/noironetworks/aci-containers/pkg/gbpserver"
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

	default:
		fmt.Printf("Unknown inspect type (need grpc or vteps)")
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
