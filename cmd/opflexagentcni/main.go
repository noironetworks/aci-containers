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

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ipam"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/sirupsen/logrus"
	"github.com/tatsushid/go-fastping"

	"github.com/noironetworks/aci-containers/pkg/eprpcclient"
	cnimd "github.com/noironetworks/aci-containers/pkg/metadata"
)

var log = logrus.New()
var logFile string
var logFd *os.File

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
	ChainingMode           bool   `json:"chaining-mode"`
	LogLevel               string `json:"log-level,omitempty"`
	LogFile                string `json:"log-file,omitempty"`
	WaitForNetwork         bool   `json:"wait-for-network"`
	WaitForNetworkDuration uint16 `json:"wait-for-network-duration"`
	EpRpcSock              string `json:"ep-rpc-sock,omitempty"`
	DomainType             string `json:"domain-type,omitempty"`
}

func loadConf(args *skel.CmdArgs) (*NetConf, *K8SArgs, string, error) {
	n := &NetConf{
		EpRpcSock: "/var/run/aci-containers-ep-rpc.sock",
	}
	if err := json.Unmarshal(args.StdinData, n); err != nil {
		return nil, nil, "", fmt.Errorf("failed to load netconf: %w", err)
	}

	log.Out = os.Stderr
	if n.LogFile != "" {
		var err error
		logFd, err = os.OpenFile(n.LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0664)
		if err == nil {
			log.Out = logFd
			logFile = n.LogFile
		} else {
			log.Info(fmt.Sprintf("Failed to open log file %s: %v", logFile, err))
		}
	}

	logLevel, err := logrus.ParseLevel(n.LogLevel)
	if err == nil {
		log.Level = logLevel
	}

	if n.WaitForNetwork && n.WaitForNetworkDuration == 0 {
		n.WaitForNetworkDuration = 210
	}

	log.Debugf("NetConf: %v", n)

	k8sArgs := &K8SArgs{}
	err = types.LoadArgs(args.Args, k8sArgs)
	if err != nil {
		return nil, nil, "", err
	}

	id := args.ContainerID
	log.Debug("Args: ", k8sArgs)

	return n, k8sArgs, id, nil
}

func waitForAllNetwork(result *current.Result, id string,
	timeout time.Duration) error {
	for index, iface := range result.Interfaces {
		netns, err := ns.GetNS(iface.Sandbox)
		if err != nil {
			log.Error("Could not open netns: ", err)
			return err
		} else {
			err := waitForNetwork(netns, result, id, index, timeout)
			netns.Close()
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func waitForNetwork(netns ns.NetNS, result *current.Result,
	id string, index int, timeout time.Duration) error {
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
			for _, ip := range result.IPs {
				if ip.Gateway == nil ||
					(ip.Interface != nil && *ip.Interface != index) {
					continue
				}
				pinger.AddIPAddr(&net.IPAddr{IP: ip.Gateway})
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
			return nil
		}

		now = time.Now()
	}

	logger.Error("Gave up waiting for network")
	return errors.New("Gave up waiting for network")
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
	var result, result2 *current.Result
	if n.ChainingMode {
		if n.NetConf.RawPrevResult == nil {
			logger.Debug("prevResult missing")
			return fmt.Errorf("Required prevResult missing")
		}
		if err := version.ParsePrevResult(&n.NetConf); err != nil {
			logger.Debug("parse prevResult failed")
			return err
		}
		result2, err = current.NewResultFromResult(n.PrevResult)
		if err != nil {
			logger.Debug("parse prevResult failed")
			return err
		}
	} else {
		if n.IPAM.Type != "opflex-agent-cni-ipam" {
			logger.Debug("Executing IPAM add")
			r, err := ipam.ExecAdd(n.IPAM.Type, args.StdinData)
			if err != nil {
				return err
			}
			result, err = current.NewResultFromResult(r)
			if err != nil {
				return err
			}
			if len(result.IPs) == 0 {
				return errors.New("IPAM plugin returned missing IP config")
			}
			zero := 0
			for _, ip := range result.IPs {
				ip.Interface = &zero
			}
		} else {
			result = &current.Result{}
			result.DNS = n.DNS
		}
	}

	metadata := cnimd.ContainerMetadata{
		Id: cnimd.ContainerId{
			ContId:    id,
			Namespace: string(k8sArgs.K8S_POD_NAMESPACE),
			Pod:       string(k8sArgs.K8S_POD_NAME),
		},
		Ifaces: []*cnimd.ContainerIfaceMd{
			{
				Name:    args.IfName,
				Sandbox: args.Netns,
			},
		},
		Network: cnimd.ContainerNetworkMetadata{
			NetworkName: n.NetConf.Name,
			ChainedMode: n.ChainingMode,
		},
	}

	if n.ChainingMode {
		ifaceMds := []*cnimd.ContainerIfaceMd{}
		ifaceFound := false
		ifaceResultIdx := 0
		for idx := range result2.Interfaces {
			if result2.Interfaces[idx].Name == args.IfName && result2.Interfaces[idx].Sandbox == args.Netns {
				ifaceMd := &cnimd.ContainerIfaceMd{
					Name:    result2.Interfaces[idx].Name,
					Sandbox: result2.Interfaces[idx].Sandbox,
				}
				if idx >= 1 {
					ifaceMd.HostVethName = result2.Interfaces[idx-1].Name
				}
				ifaceMds = append(ifaceMds, ifaceMd)
				ifaceFound = true
				ifaceResultIdx = idx
				break
			}
		}
		if ifaceFound {
			for idx := range result2.IPs {
				if *result2.IPs[idx].Interface == ifaceResultIdx {
					ifaceIp := cnimd.ContainerIfaceIP{
						Address: result2.IPs[idx].Address,
						Gateway: result2.IPs[idx].Gateway,
					}
					ifaceMds[0].IPs = append(ifaceMds[0].IPs, ifaceIp)
				}
			}
		}
		metadata.Ifaces = ifaceMds
	}

	logger.Debug("Registering with host agent")

	eprpc, err := eprpcclient.NewClient(n.EpRpcSock, time.Millisecond*500)
	if err != nil {
		return err
	}
	defer eprpc.Close()

	result, err = eprpc.Register(&metadata)
	if err != nil {
		return err
	}

	if n.WaitForNetwork {
		logger.Debug("Waiting for network connectivity")
		err := waitForAllNetwork(result, id, time.Duration(n.WaitForNetworkDuration)*time.Second)
		if err != nil {
			logger.Error("Failed to setup network connectivity, error: ", err)
			logger.Debug("Unregistering with host agent")
			_, unreg_err := eprpc.Unregister(&metadata)
			if unreg_err != nil {
				logger.Error("Failed to Unregisterd, error: ", unreg_err)
			}
			return err
		}
	}

	if n.ChainingMode {
		logger.Debug("ADD result: ", result2)
		return types.PrintResult(result2, n.CNIVersion)
	}

	logger.Debug("ADD result: ", result)
	return types.PrintResult(result, n.CNIVersion)
}

func cmdDel(args *skel.CmdArgs) error {
	n, k8sArgs, id, err := loadConf(args)
	if err != nil {
		return err
	}

	logger := log.WithFields(logrus.Fields{
		"id": id,
	})

	if !n.ChainingMode {
		if n.IPAM.Type != "opflex-agent-cni-ipam" {
			logger.Debug("Executing IPAM delete")
			if err := ipam.ExecDel(n.IPAM.Type, args.StdinData); err != nil {
				return err
			}
		}
	}

	metadata := cnimd.ContainerMetadata{
		Id: cnimd.ContainerId{
			ContId:    id,
			Namespace: string(k8sArgs.K8S_POD_NAMESPACE),
			Pod:       string(k8sArgs.K8S_POD_NAME),
		},
		Network: cnimd.ContainerNetworkMetadata{
			NetworkName: n.NetConf.Name,
			ChainedMode: n.ChainingMode,
		},
	}

	logger.Debug("Unregistering with host agent")

	eprpc, err := eprpcclient.NewClient(n.EpRpcSock, time.Millisecond*500)
	if err != nil {
		return err
	}
	defer eprpc.Close()

	_, err = eprpc.Unregister(&metadata)
	if err != nil {
		logger.Error("unregister failed")
		return err
	}
	if !n.ChainingMode {
		return types.PrintResult(&current.Result{}, n.CNIVersion)
	} else {
		if n.NetConf.RawPrevResult == nil {
			logger.Debug("prevResult missing")
			return types.PrintResult(&current.Result{}, n.CNIVersion)
		}
		if err := version.ParsePrevResult(&n.NetConf); err != nil {
			logger.Debug("parse prevResult failed")
			return err
		}
		result2, err := current.NewResultFromResult(n.PrevResult)
		if err != nil {
			logger.Debug("parse prevResult failed")
			return err
		}
		return types.PrintResult(result2, n.CNIVersion)
	}
}

func cmdCheck(args *skel.CmdArgs) error {
	n, _, id, err := loadConf(args)
	if err != nil {
		return err
	}

	logger := log.WithFields(logrus.Fields{
		"id": id,
	})

	if !n.ChainingMode {
		// run the IPAM plugin and get back the config to apply
		if n.IPAM.Type != "opflex-agent-cni-ipam" {
			logger.Debug("Executing IPAM check")
			err := ipam.ExecCheck(n.IPAM.Type, args.StdinData)
			if err != nil {
				return err
			}
		}
	}
	if n.NetConf.RawPrevResult == nil {
		return fmt.Errorf("Required prevResult missing")
	}
	if err := version.ParsePrevResult(&n.NetConf); err != nil {
		return err
	}
	result, err := current.NewResultFromResult(n.PrevResult)
	if err != nil {
		return err
	}
	if !n.ChainingMode {
		if n.WaitForNetwork {
			logger.Debug("Waiting for network connectivity")
			err := waitForAllNetwork(result, id, time.Duration(n.WaitForNetworkDuration)*time.Second)
			if err != nil {
				return err
			}
		}
	}
	logger.Debug("Check result: ", result)
	return nil
}

func main() {
	skel.PluginMain(cmdAdd, cmdCheck, cmdDel,
		version.PluginSupports("0.3.0", "0.3.1", "0.4.0"), "cni")

	if logFile != "" {
		logFd.Close()
	}
}
