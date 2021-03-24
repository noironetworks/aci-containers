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
	"net"
	"os"

	cnicur "github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ipam"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/natefinch/pie"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	md "github.com/noironetworks/aci-containers/pkg/metadata"
)

func StartPlugin(log *logrus.Logger) {
	p := pie.NewProvider()
	if err := p.Register(&ClientRPC{}); err != nil {
		log.Fatalf("failed to register Plugin: %s", err)
		return
	}

	log.Debug("Starting plugin provider")
	p.Serve()
}

// Cloner encapsulate a binary cloner for executing in a different process
// context
type Cloner struct {
	Stub bool
}

var PluginCloner Cloner

// runPluginCmd runs the command from a cloned instance of the
// executable in order to address name space binding needs
//func (c *Cloner) runPluginCmd(method, fsuid string, args interface{},
func (c *Cloner) runPluginCmd(method string, args interface{},
	reply interface{}) error {

	if c.Stub {
		// if we are in stub mode, just return success
		return nil
	}

	exe, err := os.Executable()
	if err != nil {
		return err
	}

	client, err := pie.StartProvider(os.Stderr, exe, "-child-mode")
	if err != nil {
		return err
	}
	defer client.Close()

	return client.Call(method, args, reply)
}

type ClientRPC struct{}

type SetupVethArgs struct {
	Sandbox string
	IfName  string
	Mtu     int
	Ip      net.IP
}

type SetupVethResult struct {
	HostVethName string
	Mac          string
}

func runSetupVeth(sandbox string, ifName string,
	mtu int, ip net.IP) (string, string, error) {
	result := &SetupVethResult{}
	err := PluginCloner.runPluginCmd("ClientRPC.SetupVeth",
		&SetupVethArgs{sandbox, ifName, mtu, ip}, result)
	return result.HostVethName, result.Mac, err
}

func (*ClientRPC) SetupVeth(args *SetupVethArgs, result *SetupVethResult) error {
	netns, err := ns.GetNS(args.Sandbox)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %v", args.Sandbox, err)
	}
	defer netns.Close()

	return netns.Do(func(hostNS ns.NetNS) error {
		// create the veth pair in the container and move host end
		// into host netns
		hostVeth, _, err := ip.SetupVeth(args.IfName, args.Mtu, hostNS)
		if err != nil {
			return err
		}

		result.HostVethName = hostVeth.Name

		// Force a consistent MAC address based on the IPv4 address
		// Currently we dont have a support for V6 based mac allocation. Upstream doesn't support yet :-(
		// This code has to be revisted if upstream drops SetHWAddrByIP in future
		// https://github.com/containernetworking/plugins/blob/e1517e2498fe4774435bc4be6bdd39fa735b469b/pkg/ip/link_linux.go#L228

		if args.Ip.To4() != nil {
			if err := ip.SetHWAddrByIP(args.IfName, args.Ip, nil); err != nil {
				return fmt.Errorf("failed Ip based MAC address allocation for v4: %v", err)
			}
		}

		contVeth, err := netlink.LinkByName(args.IfName)
		if err != nil {
			return err
		}

		result.Mac = contVeth.Attrs().HardwareAddr.String()
		return nil
	})
}

type ClearVethArgs struct {
	Sandbox string
	IfName  string
}

func runClearVeth(sandbox string, ifName string) error {
	ack := false
	err := PluginCloner.runPluginCmd("ClientRPC.ClearVeth",
		&ClearVethArgs{sandbox, ifName}, &ack)
	return err
}

func (c *ClientRPC) ClearVeth(args *ClearVethArgs, ack *bool) error {
	netns, err := ns.GetNS(args.Sandbox)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %v", args.Sandbox, err)
	}
	defer netns.Close()

	*ack = false
	if err := netns.Do(func(_ ns.NetNS) error {
		iface, err := netlink.LinkByName(args.IfName)
		if err != nil {
			return fmt.Errorf("failed to lookup %q: %v", args.IfName, err)
		}

		err = netlink.LinkDel(iface)
		if err != nil {
			return fmt.Errorf("failed to delete %q: %v", args.IfName, err)
		}

		return nil
	}); err != nil {
		return err
	}

	*ack = true
	return nil
}

type SetupNetworkArgs struct {
	Sandbox string
	IfName  string
	Result  *cnicur.Result
}

func runSetupNetwork(sandbox string, ifName string,
	result *cnicur.Result) error {

	ack := false
	err := PluginCloner.runPluginCmd("ClientRPC.SetupNetwork",
		&SetupNetworkArgs{sandbox, ifName, result}, &ack)
	return err
}

func (*ClientRPC) SetupNetwork(args *SetupNetworkArgs, ack *bool) error {
	netns, err := ns.GetNS(args.Sandbox)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %v", args.Sandbox, err)
	}
	defer netns.Close()

	// in gob encoding, pointer to 0 gets turned into a nil pointer.
	// This is a bug in the design of gob that will not be fixed:
	// See https://github.com/golang/go/issues/4609
	// Fix it to workaround I guess.
	index := 0
	for _, ip := range args.Result.IPs {
		if ip.Interface == nil {
			ip.Interface = &index
		}
	}

	*ack = false
	if err := netns.Do(func(_ ns.NetNS) error {
		return ipam.ConfigureIface(args.IfName, args.Result)
	}); err != nil {
		return err
	}

	*ack = true
	return nil
}

func (agent *HostAgent) addToResult(iface *md.ContainerIfaceMd,
	index int, result *cnicur.Result) {

	result.Interfaces = append(result.Interfaces,
		&cnicur.Interface{
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

		ind := index
		result.IPs = append(result.IPs,
			&cnicur.IPConfig{
				Interface: &ind,
				Version:   version,
				Address:   ip.Address,
				Gateway:   ip.Gateway,
			})
	}

}

func (agent *HostAgent) configureContainerIfaces(metadata *md.ContainerMetadata) (*cnicur.Result, error) {
	logger := agent.log.WithFields(logrus.Fields{
		"pod":       metadata.Id.Pod,
		"namespace": metadata.Id.Namespace,
		"container": metadata.Id.ContId,
	})

	podKey := makePodKey(metadata.Id.Namespace, metadata.Id.Pod)
	logger.Debug("Setting up veth")
	if len(metadata.Ifaces) == 0 {
		return nil, errors.New("No interfaces specified")
	}
	result := &cnicur.Result{}

	for _, nc := range agent.config.NetConfig {
		result.Routes =
			append(result.Routes, convertRoutes(nc.Routes)...)
	}

	for ifaceind, iface := range metadata.Ifaces {
		var err error
		var mtu int
		if agent.config.InterfaceMtu == 0 {
			// MTU not explicitly set in config or discovered
			mtu = 1500
		} else {
			mtu = agent.config.InterfaceMtu
		}

		if len(iface.IPs) == 0 {
			// We're doing ip address management

			logger.Debug("Allocating IP address(es) for ", iface.Name)
			err = agent.allocateIps(iface, podKey)
			if err != nil {
				return nil, err
			}
		}

		for _, ip := range iface.IPs {
			//There are 4 cases: IPv4-only, IPv6-only, dual stack with either IPv4 or IPv6 as the first address.
			//We are guaranteed to derive the MAC address from the IPv4 address in the IPv4-only case.

			if ip.Address.IP != nil {
				iface.HostVethName, iface.Mac, err =
					runSetupVeth(iface.Sandbox, iface.Name, mtu, ip.Address.IP)
				if err != nil {
					return nil, err
				} else {
					break
				}
			}
		}

		agent.addToResult(iface, ifaceind, result)

		logger.Debug("Configuring network for ", iface.Name, ": ", *result)
		err = runSetupNetwork(iface.Sandbox, iface.Name, result)
		if err != nil {
			agent.ipamMutex.Lock()
			agent.deallocateIpsLocked(iface)
			agent.ipamMutex.Unlock()
			return nil, err
		}
	}
	var StaleContMetadata []md.ContainerMetadata
	podid := metadata.Id.Namespace + "/" + metadata.Id.Pod
	agent.indexMutex.Lock()
	if len(agent.epMetadata[podid]) > 1 {
		logger.Warnf("There is a Stale metadata present for the pod")
	}
	if val, ok := agent.epMetadata[podid]; ok {
		// check for any stale entry present.
		// this is possible if we miss any register events for unconfiguring the POD
		//  ideally epMetadata[podid] Map should contain only one entry of containerID
		// As every pod contains one network namespace for all the containers with in the pod
		// (i.e pause container ==> metadata.Id.ContId)
		// if there are any stale which doesn't match the ContainerID remove it
		for key, v := range val {
			if metadata.Id.ContId != key {
				logger.Warnf("Stale metadata present clean the entry: %s", key)
				StaleContMetadata = append(StaleContMetadata, *v)
			}
		}
	}
	agent.indexMutex.Unlock()

	for _, v := range StaleContMetadata {
		err := agent.cleanStatleMetadata(v.Id.ContId)
		if err == nil {
			agent.deallocateMdIps(&v)
			agent.ipamMutex.Lock()
			delete(agent.epMetadata[podid], v.Id.ContId)
			agent.ipamMutex.Unlock()
		}
	}

	err := md.RecordMetadata(agent.config.CniMetadataDir,
		agent.config.CniNetwork, *metadata)
	if err != nil {
		logger.Debug("ERROR RecordMetadata")
		return nil, err
	}

	agent.indexMutex.Lock()
	if _, ok := agent.epMetadata[podid]; !ok {
		agent.epMetadata[podid] =
			make(map[string]*md.ContainerMetadata)
	}
	agent.epMetadata[podid][metadata.Id.ContId] = metadata
	agent.indexMutex.Unlock()

	agent.env.CniDeviceChanged(&podid, &metadata.Id)

	logger.Info("Successfully configured container interface")
	return result, nil
}

func (agent *HostAgent) cleanStatleMetadata(id string) error {
	_, err := md.GetMetadata(agent.config.CniMetadataDir,
		agent.config.CniNetwork, id)
	if err == nil {
		err := md.ClearMetadata(agent.config.CniMetadataDir,
			agent.config.CniNetwork, id)
		if err != nil {
			return err
		}
	}
	return err
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

	agent.cniEpDelete(podid)
	logger.Debug("Deallocating IP address(es)")
	agent.deallocateMdIps(metadata)

	logger.Debug("Clearing container interface")
	for _, iface := range metadata.Ifaces {
		err = runClearVeth(iface.Sandbox, iface.Name)
		if err != nil {
			logger.Error("Could not clear Veth ports: ", err)
		}
	}

	agent.env.CniDeviceDeleted(&podid, id)

	logger.Info("Successfully unconfigured container interface")
	return nil
}

func (agent *HostAgent) cleanupSetup() {
	agent.log.Info("Checking for stale container setup")

	agent.indexMutex.Lock()
	if !agent.syncEnabled {
		agent.indexMutex.Unlock()
		agent.log.Info("Sync not enabled, skipping stale container setup")
		return
	}
	mdcopy := agent.epMetadata
	agent.indexMutex.Unlock()

	for podkey, mdmap := range mdcopy {
		logger := agent.log.WithFields(logrus.Fields{
			"podkey": podkey,
		})

		logger.Debug("Checking")
		exists, err := agent.env.CheckPodExists(&podkey)
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
