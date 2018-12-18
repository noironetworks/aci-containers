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
	"os"

	log "github.com/Sirupsen/logrus"
	"github.com/noironetworks/aci-containers/pkg/apiserver"
)

type cliOpts struct {
	pFile string
	sort  bool
}

func main() {
	var opts cliOpts
	var flagSet *flag.FlagSet

	flagSet = flag.NewFlagSet("verify", flag.ExitOnError)
	flagSet.StringVar(&opts.pFile, "policy", "./gen_policy.json",
		"Path to etcd data store")
	flagSet.BoolVar(&opts.sort, "sort", false,
		"Created a sorted output")
	err := flagSet.Parse(os.Args[1:])
	if err != nil {
		log.Fatalf("Failed to parse command. Error: %s", err)
	}

	apiserver.VerifyFile(opts.pFile, opts.sort)

}
