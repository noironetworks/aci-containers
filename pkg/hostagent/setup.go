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

package hostagent

import (
	"errors"
	"fmt"

	"github.com/Sirupsen/logrus"
	"github.com/containernetworking/cni/pkg/ip"
	"github.com/containernetworking/cni/pkg/ipam"
	"github.com/containernetworking/cni/pkg/ns"
	cnitypes "github.com/containernetworking/cni/pkg/types/current"
	"github.com/vishvananda/netlink"

	md "github.com/noironetworks/aci-containers/pkg/metadata"
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

		hostVethName = hostVeth.Name

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

func (agent *HostAgent) addToResult(iface *md.ContainerIfaceMd,
	index int, result *cnitypes.Result) {

	result.Interfaces = append(result.Interfaces,
		&cnitypes.Interface{
			Name:    iface.Name,
			Sandbox: iface.Sandbox,
			Mac:     iface.Mac,
		})
	for _, ip := range iface.IPs {
		var version string
		if ip.Address.IP == nil {
			continue
		}
		if ip.Address.IP.To4() != nil {
			version = "4"
		} else if ip.Address.IP.To16() != nil {
			version = "6"
		} else {
			continue
		}

		result.IPs = append(result.IPs,
			&cnitypes.IPConfig{
				Interface: index,
				Version:   version,
				Address:   ip.Address,
				Gateway:   ip.Gateway,
			})
	}

}

func (agent *HostAgent) configureContainerIfaces(metadata *md.ContainerMetadata) (*cnitypes.Result, error) {
	logger := agent.log.WithFields(logrus.Fields{
		"pod":       metadata.Id.Pod,
		"namespace": metadata.Id.Namespace,
		"container": metadata.Id.ContId,
	})

	logger.Debug("Setting up veth")
	if len(metadata.Ifaces) == 0 {
		return nil, errors.New("No interfaces specified")
	}
	result := &cnitypes.Result{}

	for _, nc := range agent.config.NetConfig {
		result.Routes =
			append(result.Routes, convertRoutes(nc.Routes)...)
	}

	for ifaceind, iface := range metadata.Ifaces {
		netns, err := ns.GetNS(iface.Sandbox)
		if err != nil {
			return nil, fmt.Errorf("failed to open netns %q: %v", iface.Sandbox, err)
		}
		defer netns.Close()

		iface.HostVethName, iface.Mac, err =
			setupVeth(netns, iface.Name, agent.config.InterfaceMtu)
		if err != nil {
			return nil, err
		}

		if len(iface.IPs) == 0 {
			// We're doing ip address management

			logger.Debug("Allocating IP address(es) for ", iface.Name)
			err = agent.allocateIps(iface)
			if err != nil {
				return nil, err
			}
		}

		agent.addToResult(iface, ifaceind, result)

		logger.Debug("Configuring network for ", iface.Name)
		err = setupNetwork(netns, iface.Name, result)
		if err != nil {
			return nil, err
		}
	}

	err := md.RecordMetadata(agent.config.CniMetadataDir,
		agent.config.CniNetwork, *metadata)
	if err != nil {
		return nil, err
	}
	{
		podid := metadata.Id.Namespace + "/" + metadata.Id.Pod
		agent.indexMutex.Lock()
		if _, ok := agent.epMetadata[podid]; !ok {
			agent.epMetadata[podid] =
				make(map[string]*md.ContainerMetadata)
		}
		agent.epMetadata[podid][metadata.Id.ContId] = metadata
		agent.indexMutex.Unlock()
	}

	podkey := fmt.Sprintf("%s/%s", metadata.Id.Namespace, metadata.Id.Pod)
	agent.podChanged(&podkey)

	logger.Info("Successfully configured container interface")
	return result, nil
}

func (agent *HostAgent) unconfigureContainerIfaces(id *md.ContainerId) error {
	logger := agent.log.WithFields(logrus.Fields{
		"ContId":    id.ContId,
		"Pod":       id.Pod,
		"Namespace": id.Namespace,
	})

	podid := id.Namespace + "/" + id.Pod
	agent.indexMutex.Lock()
	mdmap, ok := agent.epMetadata[podid]
	if !ok {
		logger.Error("Unconfigure called for pod with no metadata")
		// Assume container is already unconfigured
		agent.indexMutex.Unlock()
		return nil
	}
	metadata, ok := mdmap[id.ContId]
	if !ok {
		logger.Error("Unconfigure called for container with no metadata")
		// Assume container is already unconfigured
		agent.indexMutex.Unlock()
		return nil
	}
	delete(mdmap, id.ContId)
	if len(mdmap) == 0 {
		delete(agent.epMetadata, podid)
	}
	agent.indexMutex.Unlock()

	err := md.ClearMetadata(agent.config.CniMetadataDir,
		agent.config.CniNetwork, id.ContId)
	if err != nil {
		return err
	}

	logger.Debug("Deallocating IP address(es)")
	agent.deallocateIps(metadata)

	logger.Debug("Clearing container interface")
	for _, iface := range metadata.Ifaces {
		netns, err := ns.GetNS(iface.Sandbox)
		if err != nil {
			logger.Error("Could not unconfigure iface:",
				fmt.Errorf("failed to open netns %q: %v", iface.Sandbox, err))
		} else {
			defer netns.Close()

			err = clearVeth(netns, iface.Name)
			if err != nil {
				logger.Error("Could not clear Veth ports: ", err)
			}
		}
	}

	logger.Info("Successfully unconfigured container interface")
	return nil
}

func (agent *HostAgent) cleanupSetup() {
	agent.log.Info("Checking for stale container setup")

	agent.indexMutex.Lock()
	mdcopy := agent.epMetadata
	agent.indexMutex.Unlock()

	for podkey, mdmap := range mdcopy {
		logger := agent.log.WithFields(logrus.Fields{
			"podkey": podkey,
		})

		logger.Debug("Checking")
		_, exists, err := agent.podInformer.GetStore().GetByKey(podkey)
		if err != nil {
			logger.Error("Could not lookup pod: ", err)
			continue
		}

		if !exists {
			for _, metadata := range mdmap {
				logger := agent.log.WithFields(logrus.Fields{
					"namespace": metadata.Id.Namespace,
					"pod":       metadata.Id.Pod,
					"contid":    metadata.Id.ContId,
				})
				logger.Info("Unconfiguring stale container configuration")

				err := agent.unconfigureContainerIfaces(&metadata.Id)
				if err != nil {
					logger.Error("Could not unconfigure container: ", err)
				}
			}
		}
	}

	err := agent.syncPorts(agent.config.OvsDbSock)
	if err != nil {
		agent.log.Error("Could not sync OVS ports: ", err)
	}

	agent.log.Debug("Done stale check")
}
