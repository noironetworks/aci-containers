// Copyright 2016-2017 Cisco Systems, Inc.
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

	"github.com/Sirupsen/logrus"
	"github.com/containernetworking/cni/pkg/ip"
	"github.com/containernetworking/cni/pkg/ipam"
	"github.com/containernetworking/cni/pkg/ns"
	cnitypes "github.com/containernetworking/cni/pkg/types"
	"github.com/vishvananda/netlink"

	md "github.com/noironetworks/aci-containers/metadata"
)

func setupVeth(netns ns.NetNS, ifName string, mtu int) (string, string, error) {
	var hostVethName string
	var mac string

	err := netns.Do(func(hostNS ns.NetNS) error {
		// create the veth pair in the container and move host end into host netns
		hostVeth, _, err := ip.SetupVeth(ifName, mtu, hostNS)
		if err != nil {
			return err
		}

		hostVethName = hostVeth.Attrs().Name

		contVeth, err := netlink.LinkByName(ifName)
		if err != nil {
			return err
		}

		mac = contVeth.Attrs().HardwareAddr.String()
		return nil
	})

	return hostVethName, mac, err
}

func clearVeth(netns ns.NetNS, ifName string) error {
	if err := netns.Do(func(_ ns.NetNS) error {
		iface, err := netlink.LinkByName(ifName)
		if err != nil {
			return fmt.Errorf("failed to lookup %q: %v", ifName, err)
		}

		err = netlink.LinkDel(iface)
		if err != nil {
			return fmt.Errorf("failed to delete %q: %v", ifName, err)
		}

		return nil
	}); err != nil {
		return err
	}

	return nil

}

func setupNetwork(netns ns.NetNS, ifName string, result *cnitypes.Result) error {
	if err := netns.Do(func(_ ns.NetNS) error {
		if err := ipam.ConfigureIface(ifName, result); err != nil {
			return err
		}

		return nil
	}); err != nil {
		return err
	}

	return nil
}

func (agent *hostAgent) configureContainerIface(metadata *md.ContainerMetadata) (*cnitypes.Result, error) {
	logger := log.WithFields(logrus.Fields{
		"id": metadata.Id,
	})

	netns, err := ns.GetNS(metadata.NetNS)
	if err != nil {
		return nil, fmt.Errorf("failed to open netns %q: %v", metadata.NetNS, err)
	}
	defer netns.Close()

	logger.Debug("Setting up veth")

	metadata.HostVethName, metadata.MAC, err =
		setupVeth(netns, metadata.ContIfaceName, agent.config.InterfaceMtu)
	if err != nil {
		return nil, err
	}

	if metadata.NetConf.IP4 == nil && metadata.NetConf.IP6 == nil {
		// We're doing ip address management

		logger.Debug("Allocating IP address(es)")
		err = agent.allocateIps(&metadata.NetConf)
		if err != nil {
			return nil, err
		}
	}

	err = md.RecordMetadata(agent.config.CniMetadataDir,
		agent.config.CniNetwork, *metadata)
	if err != nil {
		return nil, err
	}
	{
		agent.indexMutex.Lock()
		agent.epMetadata[metadata.Id] = metadata
		agent.indexMutex.Unlock()
	}

	logger.Debug("Creating OVS ports")

	err = createPorts(agent.config.OvsDbSock, agent.config.IntBridgeName,
		agent.config.AccessBridgeName, metadata.HostVethName)
	if err != nil {
		return nil, err
	}

	logger.Debug("Configuring network")
	err = setupNetwork(netns, metadata.ContIfaceName, &metadata.NetConf)
	if err != nil {
		return nil, err
	}

	podkey := fmt.Sprintf("%s/%s", metadata.Namespace, metadata.Pod)
	agent.podChanged(&podkey)

	logger.Info("Successfully configured container interface")
	return &metadata.NetConf, nil
}

func (agent *hostAgent) unconfigureContainerIface(id string) error {
	logger := log.WithFields(logrus.Fields{
		"id": id,
	})

	agent.indexMutex.Lock()
	metadata, ok := agent.epMetadata[id]
	if !ok {
		logger.Error("Unconfigure called for container with no metadata")
		// Assume container is already unconfigured
		agent.indexMutex.Unlock()
		return nil
	}
	delete(agent.epMetadata, id)
	agent.indexMutex.Unlock()

	err := md.ClearMetadata(agent.config.CniMetadataDir,
		agent.config.CniNetwork, id)
	if err != nil {
		return err
	}

	logger.Debug("Deallocating IP address(es)")
	agent.deallocateIps(&metadata.NetConf)

	logger.Debug("Clearing OVS ports")
	if metadata.HostVethName != "" {
		err = delPorts(agent.config.OvsDbSock, agent.config.IntBridgeName,
			agent.config.AccessBridgeName, metadata.HostVethName)
		if err != nil {
			logger.Error("Could not clear OVS ports: ", err)
		}
	}

	logger.Debug("Clearing container interface")
	netns, err := ns.GetNS(metadata.NetNS)
	if err != nil {
		logger.Error("Could not unconfigure iface:",
			fmt.Errorf("failed to open netns %q: %v", metadata.NetNS, err))
	} else {
		defer netns.Close()

		err = clearVeth(netns, metadata.ContIfaceName)
		if err != nil {
			logger.Error("Could not clear Veth ports: ", err)
		}
	}

	logger.Info("Successfully unconfigured container interface")
	return nil
}

func (agent *hostAgent) cleanupSetup() {
	log.Info("Checking for stale container setup")

	agent.indexMutex.Lock()
	mdcopy := agent.epMetadata
	agent.indexMutex.Unlock()

	for id, metadata := range mdcopy {
		logger := log.WithFields(logrus.Fields{
			"id": id,
		})

		podkey := fmt.Sprintf("%s/%s", metadata.Namespace, metadata.Pod)
		logger.Debug("Checking")
		_, exists, err := agent.podInformer.GetStore().GetByKey(podkey)
		if err != nil {
			logger.Error("Could not lookup pod: ", err)
			continue
		}
		if !exists {
			logger.Info("Unconfiguring stale container configuration")

			err := agent.unconfigureContainerIface(id)
			if err != nil {
				logger.Error("Could not unconfigure container: ", err)
			}
		}
	}
	log.Debug("Done stale check")
}
