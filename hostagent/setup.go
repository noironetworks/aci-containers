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
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/containernetworking/cni/pkg/ip"
	"github.com/containernetworking/cni/pkg/ipam"
	"github.com/containernetworking/cni/pkg/ns"
	cnitypes "github.com/containernetworking/cni/pkg/types"
	"github.com/tatsushid/go-fastping"
	"github.com/vishvananda/netlink"

	md "github.com/noironetworks/aci-containers/cnimetadata"
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

func waitForNetwork(netns ns.NetNS, result *cnitypes.Result, id string) error {
	logger := log.WithFields(logrus.Fields{
		"id": id,
	})
	if err := netns.Do(func(hostNS ns.NetNS) error {
		for i := 1; i <= 100; i++ {
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
		}

		return errors.New("Gave up waiting for network")
	}); err != nil {
		log.Error(err)
	}

	return nil
}

func configureContainerIface(metadata *md.ContainerMetadata) (*cnitypes.Result, error) {
	logger := log.WithFields(logrus.Fields{
		"id": metadata.Id,
	})

	result := &cnitypes.Result{}

	netns, err := ns.GetNS(metadata.NetNS)
	if err != nil {
		return nil, fmt.Errorf("failed to open netns %q: %v", metadata.NetNS, err)
	}
	defer netns.Close()

	logger.Debug("Setting up veth")

	metadata.HostVethName, metadata.MAC, err =
		setupVeth(netns, metadata.ContIfaceName, *mtu)
	if err != nil {
		return nil, err
	}

	err = md.RecordMetadata(*metadataDir, *network, *metadata)
	if err != nil {
		return nil, err
	}
	{
		indexMutex.Lock()
		epMetadata[metadata.Id] = metadata
		indexMutex.Unlock()
	}

	logger.Debug("Creating OVS ports")

	err = createPorts(*ovsDbSock, *intBrName, *accessBrName,
		metadata.HostVethName)
	if err != nil {
		return nil, err
	}

	logger.Debug("Configuring network")
	err = setupNetwork(netns, metadata.ContIfaceName, &metadata.NetConf)
	if err != nil {
		return nil, err
	}

	podkey := fmt.Sprintf("%s/%s", metadata.Namespace, metadata.Pod)
	podChanged(&podkey)

	logger.Debug("Waiting for network connectivity")
	err = waitForNetwork(netns, &metadata.NetConf, metadata.Id)

	logger.Info("Successfully configured container interface")
	return result, nil
}

func unconfigureContainerIface(id string) error {
	logger := log.WithFields(logrus.Fields{
		"id": id,
	})

	indexMutex.Lock()
	metadata, ok := epMetadata[id]
	if !ok {
		logger.Error("Unconfigure called for container with no metadata")
		// Assume container is already unconfigured
		indexMutex.Unlock()
		return nil
	}
	delete(epMetadata, id)
	indexMutex.Unlock()

	err := md.ClearMetadata(*metadataDir, *network, id)
	if err != nil {
		return err
	}

	logger.Debug("Clearing OVS ports")
	if metadata.HostVethName != "" {
		err = delPorts(*ovsDbSock, *intBrName, *accessBrName,
			metadata.HostVethName)
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

func cleanupConfiguration() {
	log.Info("Checking for stale configuration")

	indexMutex.Lock()
	mdcopy := epMetadata
	indexMutex.Unlock()

	for id, metadata := range mdcopy {
		logger := log.WithFields(logrus.Fields{
			"id": id,
		})

		podkey := fmt.Sprintf("%s/%s", metadata.Namespace, metadata.Pod)
		logger.Debug("Checking")
		_, exists, err := podInformer.GetStore().GetByKey(podkey)
		if err != nil {
			logger.Error("Could not lookup pod: ", err)
			continue
		}
		if !exists {
			logger.Info("Unconfiguring stale container configuration")

			err := unconfigureContainerIface(id)
			if err != nil {
				logger.Error("Could not unconfigure container: ", err)
			}
		}
	}
	log.Debug("Done stale check")
}
