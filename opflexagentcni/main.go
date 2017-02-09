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
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/containernetworking/cni/pkg/ipam"
	"github.com/containernetworking/cni/pkg/ns"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/tatsushid/go-fastping"

	cnimd "github.com/noironetworks/aci-containers/metadata"
)

var log = logrus.New()

func init() {
	// This ensures that main runs only on main thread (thread group leader).
	// since namespace ops (unshare, setns) are done for a single thread, we
	// must ensure that the goroutine does not jump from OS thread to thread
	runtime.LockOSThread()
}

type K8SArgs struct {
	types.CommonArgs
	K8S_POD_NAME               types.UnmarshallableString
	K8S_POD_NAMESPACE          types.UnmarshallableString
	K8S_POD_INFRA_CONTAINER_ID types.UnmarshallableString
}

type NetConf struct {
	types.NetConf
	LogLevel         string `json:"log-level,omitempty"`
	NoWaitForNetwork bool   `json:"no-wait-for-network"`
}

func loadConf(args *skel.CmdArgs) (*NetConf, *K8SArgs, string, error) {
	n := &NetConf{}
	if err := json.Unmarshal(args.StdinData, n); err != nil {
		return nil, nil, "", fmt.Errorf("failed to load netconf: %v", err)
	}

	log.Out = os.Stderr
	logLevel, err := logrus.ParseLevel(n.LogLevel)
	if err == nil {
		log.Level = logLevel
	}

	k8sArgs := &K8SArgs{}
	err = types.LoadArgs(args.Args, k8sArgs)
	if err != nil {
		return nil, nil, "", err
	}

	id := args.ContainerID
	if k8sArgs.K8S_POD_NAMESPACE != "" && k8sArgs.K8S_POD_NAME != "" {
		id = fmt.Sprintf("%s_%s", k8sArgs.K8S_POD_NAMESPACE, k8sArgs.K8S_POD_NAME)
	}

	return n, k8sArgs, id, nil
}

func waitForNetwork(netns ns.NetNS, result *types.Result,
	id string, timeout time.Duration) {

	logger := log.WithFields(logrus.Fields{
		"id": id,
	})

	end := time.Now().Add(timeout)
	now := time.Now()
	for now.Before(end) {
		if err := netns.Do(func(hostNS ns.NetNS) error {
			pinger := fastping.NewPinger()
			pinger.MaxRTT = time.Millisecond * 100
			expected := 0
			if result.IP4 != nil && result.IP4.Gateway != nil {
				logger.Debug("Pinging gateway ", result.IP4.Gateway)
				pinger.AddIPAddr(&net.IPAddr{IP: result.IP4.Gateway})
				expected += 1
			}
			if result.IP6 != nil && result.IP6.Gateway != nil {
				logger.Debug("Pinging gateway ", result.IP6.Gateway)
				pinger.AddIPAddr(&net.IPAddr{IP: result.IP6.Gateway})
				expected += 1
			}
			if expected == 0 {
				logger.Debug("Network configuration has no gateway")
				return nil
			}

			count := 0
			pinger.OnRecv = func(addr *net.IPAddr, rtt time.Duration) {
				logger.WithFields(logrus.Fields{
					"IP":  addr,
					"rtt": rtt,
				}).Debug("Received")
				count += 1
			}

			err := pinger.Run()
			if err != nil {
				return err
			}
			if count >= expected {
				return nil
			}
			return errors.New("Ping failed")
		}); err == nil {
			return
		}

		now = time.Now()
	}

	logger.Error("Gave up waiting for network")
}

func cmdAdd(args *skel.CmdArgs) error {
	n, k8sArgs, id, err := loadConf(args)
	if err != nil {
		return err
	}

	logger := log.WithFields(logrus.Fields{
		"id": id,
	})

	// run the IPAM plugin and get back the config to apply
	var result *types.Result
	if n.IPAM.Type != "opflex-agent-cni-ipam" {
		logger.Debug("Executing IPAM add")
		result, err = ipam.ExecAdd(n.IPAM.Type, args.StdinData)
		if err != nil {
			return err
		}

		if result.IP4 == nil && result.IP6 == nil {
			return errors.New("IPAM plugin returned missing IP config")
		}
	} else {
		result = &types.Result{}
		result.DNS = n.DNS
	}

	metadata := cnimd.ContainerMetadata{
		Id:            id,
		ContIfaceName: args.IfName,
		NetNS:         args.Netns,
		NetConf:       *result,
		Namespace:     string(k8sArgs.K8S_POD_NAMESPACE),
		Pod:           string(k8sArgs.K8S_POD_NAME),
	}

	logger.Debug("Registering with host agent")

	eprpc, err := NewClient("127.0.0.1:4242", time.Millisecond*500)
	if err != nil {
		return err
	}

	result, err = eprpc.Register(&metadata)
	if err != nil {
		return err
	}

	if !n.NoWaitForNetwork {
		logger.Debug("Waiting for network connectivity")
		netns, err := ns.GetNS(metadata.NetNS)
		if err != nil {
			log.Error("Could not open netns: ", err)
		} else {
			waitForNetwork(netns, result, id, 10*time.Second)
			netns.Close()
		}
	}

	return result.Print()
}

func cmdDel(args *skel.CmdArgs) error {
	n, _, id, err := loadConf(args)
	if err != nil {
		return err
	}

	logger := log.WithFields(logrus.Fields{
		"id": id,
	})

	if n.IPAM.Type != "opflex-agent-cni-ipam" {
		logger.Debug("Executing IPAM delete")
		if err := ipam.ExecDel(n.IPAM.Type, args.StdinData); err != nil {
			return err
		}
	}

	logger.Debug("Unregistering with host agent")

	eprpc, err := NewClient("127.0.0.1:4242", time.Millisecond*500)
	if err != nil {
		return err
	}
	_, err = eprpc.Unregister(id)
	if err != nil {
		return err
	}

	return nil
}

func main() {
	skel.PluginMain(cmdAdd, cmdDel, version.PluginSupports("0.2.0"))
}
