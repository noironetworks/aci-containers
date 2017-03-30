// Copyright 2014 CNI authors
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
	"fmt"
	"os"
	"time"

	"github.com/noironetworks/aci-containers/pkg/eprpcclient"
)

func resync() error {
	eprpc, err := eprpcclient.NewClient(os.Args[1], time.Millisecond*500)
	if err != nil {
		return err
	}
	_, err = eprpc.Resync()
	if err != nil {
		return err
	}
	return nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Error: no socket specified")
		os.Exit(1)
	}

	i := 0
	for ; i < 20; i++ {
		err := resync()
		if err == nil {
			break
		}
		fmt.Fprintln(os.Stderr, err)
		time.Sleep(time.Second)
	}
	if i >= 10 {
		fmt.Fprintln(os.Stderr, "Timed out waiting for OVS resync")
	}
}
