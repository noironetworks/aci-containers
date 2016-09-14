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
	"runtime"

	"github.com/containernetworking/cni/pkg/ip"
	"github.com/containernetworking/cni/pkg/ipam"
	"github.com/containernetworking/cni/pkg/ns"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/vishvananda/netlink"
)

const defaultIntBrName = "br-int"
const defaultAccessBrName = "br-access"
const defaultMTU = 1500
const defaultOvsDbSock = "/var/run/openvswitch/db.sock"
const defaultMetadataDir = "/var/lib/cni/opflex-networks"

type NetConf struct {
	types.NetConf
	OvsDbSock    string `json:"ovsdb-socket"`
	IntBrName    string `json:"int-bridge"`
	AccessBrName string `json:"access-bridge"`
	MTU          int    `json:"mtu"`
	MetadataDir  string `json:"metadata-dir"`
}

func init() {
	// this ensures that main runs only on main thread (thread group leader).
	// since namespace ops (unshare, setns) are done for a single thread, we
	// must ensure that the goroutine does not jump from OS thread to thread
	runtime.LockOSThread()
}

func loadNetConf(bytes []byte) (*NetConf, error) {
	n := &NetConf{
		OvsDbSock:    defaultOvsDbSock,
		IntBrName:    defaultIntBrName,
		AccessBrName: defaultAccessBrName,
		MTU:          defaultMTU,
		MetadataDir:  defaultMetadataDir,
	}
	if err := json.Unmarshal(bytes, n); err != nil {
		return nil, fmt.Errorf("failed to load netconf: %v", err)
	}
	return n, nil
}

func setupVeth(netns ns.NetNS, ifName string, mtu int) (string, mac, error) {
	var hostVethName string
	var mac string

	err := netns.Do(func(hostNS ns.NetNS) error {
		// create the veth pair in the container and move host end into host netns
		hostVeth, _, err := ip.SetupVeth(ifName, mtu, hostNS)
		if err != nil {
			return err
		}

		hostVethName = hostVeth.Attrs().Name
		mac = string(hostVeth.Attrs().HardwareAddr)
		return nil
	})

	return hostVethName, err
}

func cmdAdd(args *skel.CmdArgs) error {
	n, err := loadNetConf(args.StdinData)
	if err != nil {
		return err
	}

	netns, err := ns.GetNS(args.Netns)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %v", args.Netns, err)
	}
	defer netns.Close()

	hostVethName, ifaceMac, err := setupVeth(netns, args.IfName, n.MTU)
	if err != nil {
		return err
	}

	metadata := ContainerMetadata{
		Id:           args.ContainerID,
		HostVethName: hostVethName,
		NetNS:        args.Netns,
		MAC:          ifaceMac,
	}
	err = recordMetadata(n.MetadataDir, n.Name, metadata)
	if err != nil {
		return err
	}

	err = createPorts(n.OvsDbSock, n.IntBrName, n.AccessBrName, hostVethName)
	if err != nil {
		return err
	}

	// run the IPAM plugin and get back the config to apply
	result, err := ipam.ExecAdd(n.IPAM.Type, args.StdinData)
	if err != nil {
		return err
	}

	if result.IP4 == nil && result.IP6 == nil {
		return errors.New("IPAM plugin returned missing IP config")
	}

	if err := netns.Do(func(_ ns.NetNS) error {
		if err := ipam.ConfigureIface(args.IfName, result); err != nil {
			return err
		}

		return nil
	}); err != nil {
		return err
	}

	result.DNS = n.DNS
	return result.Print()
}

func cmdDel(args *skel.CmdArgs) error {
	n, err := loadNetConf(args.StdinData)
	if err != nil {
		return err
	}

	if err := ipam.ExecDel(n.IPAM.Type, args.StdinData); err != nil {
		return err
	}

	if args.Netns == "" {
		return nil
	}

	err = ns.WithNetNSPath(args.Netns, func(_ ns.NetNS) error {
		iface, err := netlink.LinkByName(args.IfName)
		if err != nil {
			return fmt.Errorf("failed to lookup %q: %v", args.IfName, err)
		}

		err = netlink.LinkDel(iface)
		if err != nil {
			return fmt.Errorf("failed to delete %q: %v", args.IfName, err)
		}

		return nil
	})
	if err != nil {
		return err
	}

	metadata, err := getMetadata(n.MetadataDir, n.Name, args.ContainerID)
	if err != nil {
		return err
	}

	err = clearMetadata(n.MetadataDir, n.Name, args.ContainerID)
	if err != nil {
		return err
	}

	if metadata.HostVethName != "" {
		err = delPorts(n.OvsDbSock, n.IntBrName,
			n.AccessBrName, metadata.HostVethName)
		if err != nil {
			return err
		}
	}

	if err := ipam.ExecDel(n.IPAM.Type, args.StdinData); err != nil {
		return err
	}

	return nil
}

func main() {
	skel.PluginMain(cmdAdd, cmdDel)
}
