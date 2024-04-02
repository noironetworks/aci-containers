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
	"strings"

	cnicur "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ipam"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/natefinch/pie"
	fabattv1 "github.com/noironetworks/aci-containers/pkg/fabricattachment/apis/aci.fabricattachment/v1"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/k8snetworkplumbingwg/sriovnet"
	md "github.com/noironetworks/aci-containers/pkg/metadata"
	"github.com/noironetworks/aci-containers/pkg/util"
)

const (
	ipRelevantByteLen      = 4
	PrivateMACPrefixString = "0a:58"
)

var (
	// private mac prefix safe to use
	PrivateMACPrefix = []byte{0x0a, 0x58}
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
// func (c *Cloner) runPluginCmd(method, fsuid string, args interface{},
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

// https://github.com/containernetworking/plugins/blob/v0.9.1/pkg/utils/hwaddr/hwaddr.go#L45
// Reusing code as the fn is removed in v1.0.0
// GenerateHardwareAddr4 generates 48 bit virtual mac addresses based on the IP4 input.
func GenerateHardwareAddr4(ip net.IP, prefix []byte) (net.HardwareAddr, error) {
	switch {
	case ip.To4() == nil:
		return nil, fmt.Errorf("GenerateHardwareAddr4 only supports valid IPv4 address as input")

	case len(prefix) != len(PrivateMACPrefix):
		return nil, fmt.Errorf(
			"Prefix has length %d instead  of %d", len(prefix), len(PrivateMACPrefix))
	}

	ipByteLen := len(ip)
	return net.HardwareAddr(
		append(
			prefix,
			ip[ipByteLen-ipRelevantByteLen:ipByteLen]...),
	), nil
}

// https://github.com/containernetworking/plugins/blob/v0.9.1/pkg/ip/link_linux.go#L228
// Reusing code as the fn is removed in v1.0.0
func SetHWAddrByIP(ifName string, ip4, ip6 net.IP) error {
	iface, err := netlink.LinkByName(ifName)
	if err != nil {
		return fmt.Errorf("failed to lookup %q: %w", ifName, err)
	}

	switch {
	case ip4 == nil && ip6 == nil:
		return fmt.Errorf("neither ip4 or ip6 specified")

	case ip4 != nil:
		hwAddr, err := GenerateHardwareAddr4(ip4, PrivateMACPrefix)
		if err != nil {
			return fmt.Errorf("failed to generate hardware addr: %w", err)
		}
		if err = netlink.LinkSetHardwareAddr(iface, hwAddr); err != nil {
			return fmt.Errorf("failed to add hardware addr to %q: %w", ifName, err)
		}
	case ip6 != nil:
		// TODO: IPv6
	}

	return nil
}

func (*ClientRPC) SetupVeth(args *SetupVethArgs, result *SetupVethResult) error {
	netns, err := ns.GetNS(args.Sandbox)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %w", args.Sandbox, err)
	}
	defer netns.Close()

	return netns.Do(func(hostNS ns.NetNS) error {
		// create the veth pair in the container and move host end
		// into host netns
		hostVeth, _, err := ip.SetupVeth(args.IfName, args.Mtu, "", hostNS)
		if err != nil {
			return err
		}

		result.HostVethName = hostVeth.Name

		// Force a consistent MAC address based on the IPv4 address
		// Currently we dont have a support for V6 based mac allocation. Upstream doesn't support yet :-(

		if args.Ip.To4() != nil {
			if err := SetHWAddrByIP(args.IfName, args.Ip, nil); err != nil {
				return fmt.Errorf("failed Ip based MAC address allocation for v4: %w", err)
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

type SetupVfResult struct {
	HostVfName string
	Mac        string
	VfNetDev   string
}

type SetupVfArgs struct {
	Sandbox       string
	IfName        string
	Mtu           int
	Ip            net.IP
	SriovDeviceId string
	OffloadMode   string
}

func runSetupVf(sandbox, ifName string,
	mtu int, ip net.IP, sriovDeviceId, offloadMode string) (string, string, string, error) {
	result := &SetupVfResult{}
	err := PluginCloner.runPluginCmd("ClientRPC.SetupVf",
		&SetupVfArgs{sandbox, ifName, mtu, ip, sriovDeviceId, offloadMode}, result)
	return result.HostVfName, result.Mac, result.VfNetDev, err
}

func (*ClientRPC) SetupVf(args *SetupVfArgs, result *SetupVfResult) error {
	var uplink string
	logger := logrus.New()

	netns, err := ns.GetNS(args.Sandbox)
	if err != nil {
		logger.Errorf("failed to open netns %q: %v", args.Sandbox, err)
		return err
	}

	if args.OffloadMode != "dpu" {
		uplink, err = sriovnet.GetUplinkRepresentor(args.SriovDeviceId)
		if err != nil {
			logger.Errorf("failed to retrieve uplink interface for pci address %s: %v", args.SriovDeviceId, err)
			return err
		}
	}

	vfIndex, err := sriovnet.GetVfIndexByPciAddress(args.SriovDeviceId)
	if err != nil {
		logger.Errorf("failed to retrieve vfIndex for pci address %s: %v", args.SriovDeviceId, err)
		return err
	}

	if args.OffloadMode != "dpu" {
		vfRep, err := sriovnet.GetVfRepresentor(uplink, vfIndex)
		if err != nil {
			logger.Errorf("failed to retrieve vf representator for pci address %s and vfIndex %d: %v", args.SriovDeviceId, vfIndex, err)
			return err
		}
		hostIface, err := netlink.LinkByName(vfRep)
		if hostIface == nil || err != nil {
			return err
		}
		err = netlink.LinkSetUp(hostIface)
		if err != nil {
			return err
		}
		result.HostVfName = vfRep
	} else if args.OffloadMode == "dpu" {
		result.HostVfName = fmt.Sprintf("pf0vf%d", vfIndex)
	}

	netDevice, err := sriovnet.GetNetDevicesFromPci(args.SriovDeviceId)
	if err != nil {
		logger.Errorf("Failed to retreive netdevice %s:%v", args.SriovDeviceId, err)
		return err
	}
	if len(netDevice) > 1 {
		logger.Errorf("Netdevice allocated should not exceed more than one for PCI address  %s:%v", args.SriovDeviceId, err)
		return err
	}
	// move Vf netdevice to pod's namespace
	result.VfNetDev = netDevice[0]
	netDeviceLink, err := netlink.LinkByName(netDevice[0])
	if err != nil {
		logger.Errorf("Failed to bring up the netlink %s :%v", netDevice[0], err)
		return err
	}
	err = netlink.LinkSetNsFd(netDeviceLink, int(netns.Fd()))
	if err != nil {
		logger.Errorf("Failed to retreive netdevice %s:%v", args.SriovDeviceId, err)
		return err
	}
	defer netns.Close()
	return netns.Do(func(hostNS ns.NetNS) error {
		contLink, err := netlink.LinkByName(netDevice[0])
		if err != nil {
			logger.Errorf("netNS.Do Failed to get link by name %s:%v", netDevice[0], err)
			return err
		}
		err = netlink.LinkSetDown(contLink)
		if err != nil {
			logger.Errorf("netNS.Do Failed to set link down %s:%v", args.IfName, err)
			return err
		}
		err = netlink.LinkSetName(contLink, args.IfName)
		if err != nil {
			logger.Errorf("netNS.Do Failed to set link name %s:%v", args.IfName, err)
			return err
		}
		//Set Mtu
		err = netlink.LinkSetMTU(contLink, args.Mtu)
		if err != nil {
			logger.Errorf("netNS.Do Failed to set MTU %s:%v", args.IfName, err)
			return err
		}
		err = netlink.LinkSetUp(contLink)
		if err != nil {
			logger.Errorf("netNS.Do Failed to set link up %s:%v", args.IfName, err)
			return err
		}
		if args.Ip.To4() != nil {
			if err := SetHWAddrByIP(args.IfName, args.Ip, nil); err != nil {
				return fmt.Errorf("failed Ip based MAC address allocation for v4: %w", err)
			}
		}
		contIface, err := netlink.LinkByName(args.IfName)
		if err != nil {
			logger.Errorf("netNS.Do Failed to get link by name %s:%v", args.IfName, err)
			return err
		}

		result.Mac = contIface.Attrs().HardwareAddr.String()
		if len(result.Mac) == 0 {
			logger.Errorf("netNS.Do got empty MAC for %s", args.IfName)
		}

		return nil
	})
}

type ClearVethArgs struct {
	Sandbox string
	IfName  string
}

func runClearVeth(sandbox, ifName string) error {
	ack := false
	err := PluginCloner.runPluginCmd("ClientRPC.ClearVeth",
		&ClearVethArgs{sandbox, ifName}, &ack)
	return err
}

func (c *ClientRPC) ClearVeth(args *ClearVethArgs, ack *bool) error {
	netns, err := ns.GetNS(args.Sandbox)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %w", args.Sandbox, err)
	}
	defer netns.Close()

	*ack = false
	if err := netns.Do(func(_ ns.NetNS) error {
		iface, err := netlink.LinkByName(args.IfName)
		if err != nil {
			return fmt.Errorf("failed to lookup %q: %w", args.IfName, err)
		}

		err = netlink.LinkDel(iface)
		if err != nil {
			return fmt.Errorf("failed to delete %q: %w", args.IfName, err)
		}

		return nil
	}); err != nil {
		return err
	}

	*ack = true
	return nil
}

type ClearVfArgs struct {
	Sandbox       string
	IfName        string
	SriovDeviceId string
	VfNetDev      string
}

func runClearVf(sandbox, ifName, sriovDeviceid, vfnetdev string) error {
	ack := false
	err := PluginCloner.runPluginCmd("ClientRPC.ClearVf",
		&ClearVfArgs{sandbox, ifName, sriovDeviceid, vfnetdev}, &ack)
	return err
}

func (c *ClientRPC) ClearVf(args *ClearVfArgs, ack *bool) error {
	netns, err := ns.GetNS(args.Sandbox)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %w", args.Sandbox, err)
	}
	defer netns.Close()

	currentNs, err := ns.GetCurrentNS()
	if err != nil {
		return fmt.Errorf("failed to open current netns: %w", err)
	}
	*ack = false

	if err := netns.Do(func(_ ns.NetNS) error {
		vfNetLink, err := netlink.LinkByName(args.IfName)
		if err != nil {
			return fmt.Errorf("failed to lookup %q: %w", args.IfName, err)
		}
		err = netlink.LinkSetDown(vfNetLink)
		if err != nil {
			return fmt.Errorf("failed to bring down Vf Netdevice link: %w", err)
		}
		err = netlink.LinkSetName(vfNetLink, args.VfNetDev)
		if err != nil {
			return err
		}
		err = netlink.LinkSetNsFd(vfNetLink, int(currentNs.Fd()))
		if err != nil {
			return fmt.Errorf("Failed to move Vf netdevice to host's namespace: %w", err)
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

func runSetupNetwork(sandbox, ifName string, result *cnicur.Result) error {
	ack := false
	err := PluginCloner.runPluginCmd("ClientRPC.SetupNetwork",
		&SetupNetworkArgs{sandbox, ifName, result}, &ack)
	return err
}

func (*ClientRPC) SetupNetwork(args *SetupNetworkArgs, ack *bool) error {
	netns, err := ns.GetNS(args.Sandbox)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %w", args.Sandbox, err)
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
		if ip.Address.IP == nil {
			continue
		}
		if !(ip.Address.IP.To4() != nil || ip.Address.IP.To16() != nil) {
			continue
		}

		ind := index
		result.IPs = append(result.IPs,
			&cnicur.IPConfig{
				Interface: &ind,
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

	if metadata.Network.ChainedMode {
		networkName := metadata.Network.NetworkName
		isPrimaryNetwork := false
		result := &cnicur.Result{}
		podid := metadata.Id.Namespace + "/" + metadata.Id.Pod
		agent.indexMutex.Lock()
		if networkName == agent.primaryNetworkName {
			if agent.config.EnableChainedPrimary {
				agent.epMetadata[podid] = make(map[string]*md.ContainerMetadata)
				agent.epMetadata[podid][metadata.Id.ContId] = metadata
			}
			isPrimaryNetwork = true
		} else {
			if agent.config.EnableChainedSecondary {
				if _, ok := agent.podNetworkMetadata[podid]; !ok {
					agent.podNetworkMetadata[podid] =
						make(map[string]map[string]*md.ContainerMetadata)
				}

				netAttDefKey := metadata.Id.Namespace + "/" + metadata.Network.NetworkName
				networkName = metadata.Id.Namespace + "-" + metadata.Network.NetworkName

				if netAttDef, ok := agent.netattdefmap[netAttDefKey]; ok {
					podAtt := &fabattv1.PodAttachment{
						PodRef: fabattv1.ObjRef{Namespace: metadata.Id.Namespace,
							Name: metadata.Id.Pod},
					}
					if netAttDef.PrimaryCNI == "sriov" {
						err := agent.getAlloccatedDeviceId(metadata, "chained")
						if err != nil {
							logger.Error("VF allocation failed ", err)
						}
						if len(metadata.Id.DeviceId) == 0 {
							logger.Error("VF allocation failed: Sriov resource not allocated")
						} else {
							logger.Debug("Sriov resource allocated: ", metadata.Id.DeviceId)
						}
						metadata.Network.PFName = agent.getPFFromVFPCI(metadata.Id.DeviceId)
						metadata.Network.VFName = agent.getNetDevFromVFPCI(metadata.Id.DeviceId, metadata.Network.PFName)
						logger.Infof("Associated PF: %s, VF: %s", metadata.Network.PFName, metadata.Network.VFName)
					} else {
						metadata.Network.VFName = metadata.Ifaces[len(metadata.Ifaces)-1].Name
						metadata.Network.PFName = netAttDef.ResourceName
					}
					podAtt.LocalIface = metadata.Network.VFName
					if _, ok := agent.podNetworkMetadata[podid][metadata.Network.NetworkName]; !ok {
						agent.podNetworkMetadata[podid][metadata.Network.NetworkName] =
							make(map[string]*md.ContainerMetadata)
					}
					agent.podNetworkMetadata[podid][metadata.Network.NetworkName][metadata.Id.ContId] =
						metadata

					err := agent.updateFabricPodNetworkAttachmentLocked(podAtt, metadata.Network.NetworkName, false)
					if err != nil {
						errorMsg := fmt.Sprintf("Could not create Pod Fabric Attachment: %v", err)
						agent.indexMutex.Unlock()
						if errors.Is(err, ErrLLDPAdjacency) {
							logger.Infof("Forcing refresh of LLDP data for iface %s", metadata.Network.PFName)
							for i := 0; i < 3; i++ {
								agent.FabricDiscoveryTriggerCollectionDiscoveryData()
								if fabAttData, err2 := agent.GetFabricDiscoveryNeighborDataLocked(metadata.Network.PFName); err2 == nil {
									for _, nbr := range fabAttData {
										if nbr.StaticPath != "" {
											return result, nil
										}
									}
								}
							}
						}
						return result, errors.New(errorMsg)
					}
					if netAttDef.PrimaryCNI == PrimaryCNIBridge {
						for _, iface := range metadata.Ifaces {
							logger.Debugf("Checking iface %s hostveth %s", iface.Name, iface.HostVethName)
							if iface.Name == netAttDef.ResourceName || iface.HostVethName == "" {
								continue
							}
							vlans, _, _, err := util.ParseVlanList([]string{netAttDef.EncapVlan})
							if err != nil {
								logger.Errorf("Failed to parse vlanList %s: %v", netAttDef.EncapVlan, err)
								return result, nil
							}
							logger.Debugf("Allowing vlans %s on %s", netAttDef.EncapVlan, iface.HostVethName)

							hostVeth, err := netlink.LinkByName(iface.HostVethName)
							if err != nil {
								logger.Errorf("Failed to lookup %s: %v", iface.HostVethName, err)
								return result, nil
							}
							for _, vlan := range vlans {
								err = netlink.BridgeVlanAdd(hostVeth, uint16(vlan), false, false, false, true)
								if err != nil {
									logger.Errorf("failed to setup vlan tag on interface %s: %v", iface.HostVethName, err)
									continue
								}
							}
						}
					}
				} else {
					errorMsg := fmt.Sprintf("Failed to find network-attachment-definition: %s", netAttDefKey)
					agent.indexMutex.Unlock()
					return result, errors.New(errorMsg)
				}
			}
		}
		agent.indexMutex.Unlock()
		if isPrimaryNetwork {
			if agent.config.EnableChainedPrimary {
				for _, iface := range metadata.Ifaces {
					iface.HostVethName = iface.Name
				}
				agent.env.CniDeviceChanged(&podid, &metadata.Id)
			}
		}
		if (isPrimaryNetwork && agent.config.EnableChainedPrimary) || (!isPrimaryNetwork && agent.config.EnableChainedSecondary) {
			err := md.RecordMetadata(agent.config.CniMetadataDir, networkName, metadata)
			if err != nil {
				logger.Debug("ERROR RecordMetadata")
				return result, err
			}
		}
		return result, nil
	}

	if agent.config.OvsHardwareOffload {
		err := agent.getAlloccatedDeviceId(metadata, agent.config.OpflexMode)
		if err != nil {
			logger.Error("VF allocation failed ", err)
		}
		if len(metadata.Id.DeviceId) == 0 {
			logger.Error("VF allocation failed: Sriov resource not allocated")
		} else {
			logger.Debug("Sriov resource allocated: ", metadata.Id.DeviceId)
			logger.Debugf("Num of Sriov resource allocated: %d :", len(metadata.Id.DeviceId))
		}
	}

	podKey := makePodKey(metadata.Id.Namespace, metadata.Id.Pod)
	if len(metadata.Ifaces) == 0 {
		return nil, errors.New("No interfaces specified")
	}
	result := &cnicur.Result{}

	//deallocate IP's incase if container interface creation fails
	deallocIP := func(iface *md.ContainerIfaceMd, err error) {
		logger.Infof("Deallocating IP address(es).")
		logger.Infof("Error: %+v", err)
		agent.ipamMutex.Lock()
		agent.deallocateIpsLocked(iface)
		agent.ipamMutex.Unlock()
	}

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

			logger.Debugf("Allocating IP address(es) for %v", iface.Name)
			err = agent.allocateIps(iface, podKey)
			if err != nil {
				return nil, err
			}
		}
		for _, ip := range iface.IPs {
			//There are 4 cases: IPv4-only, IPv6-only, dual stack with either IPv4 or IPv6 as the first address.
			//We are guaranteed to derive the MAC address from IPv4 if it is assigned
			if ip.Address.IP != nil && ip.Address.IP.To4() != nil {
				if len(metadata.Id.DeviceId) > 0 && agent.config.OvsHardwareOffload {
					if agent.config.OpflexMode == "dpu" {
						logger.Debugf("Setting up VF in dpu mode: deviceId/PCI address %s: ", metadata.Id.DeviceId)
						iface.HostVethName, iface.Mac, iface.VfNetDevice, err =
							runSetupVf(iface.Sandbox, iface.Name, mtu, ip.Address.IP, metadata.Id.DeviceId, agent.config.OpflexMode)
					} else {
						logger.Debugf("Setting up VF in non-dpu mode: deviceId/PCI address %s: ", metadata.Id.DeviceId)
						iface.HostVethName, iface.Mac, iface.VfNetDevice, err =
							runSetupVf(iface.Sandbox, iface.Name, mtu, ip.Address.IP, metadata.Id.DeviceId, agent.config.OpflexMode)
					}
					if err != nil {
						logger.Errorf("VF allocation failed :%v", err)
					} else {
						logger.Debugf("Assigned VF representator is %s and VF netdevice is %s", iface.HostVethName, iface.VfNetDevice)
						break
					}
				} else {
					logger.Debug("Setting up veth")
					iface.HostVethName, iface.Mac, err =
						runSetupVeth(iface.Sandbox, iface.Name, mtu, ip.Address.IP)
					logger.Debug("VethName : ", iface.HostVethName)
					if err != nil {
						return nil, err
					} else {
						break
					}
				}
			}
		}
		// if no mac is assigned, set it to the default Mac.
		if len(iface.Mac) == 0 {
			iface.HostVethName, iface.Mac, err =
				runSetupVeth(iface.Sandbox, iface.Name, agent.config.InterfaceMtu, nil)
			if err != nil {
				deallocIP(iface, err)
				return nil, err
			}
		}
		//Todo: Remove dependency on integ_test flag.
		if agent.integ_test == nil {
			if len(iface.HostVethName) == 0 || len(iface.Mac) == 0 {
				l := fmt.Sprintf("Failed to setup Veth.{ContainerName= %v, HostVethName: { Name=%v, Lenght=%v} ,MAC: {Name=%v, Length=%v}}", metadata.Id.ContId, iface.HostVethName, len(iface.HostVethName), iface.Mac, len(iface.Mac))
				er := fmt.Errorf("Unable to Configure Container Interface, Error: %v", l)
				deallocIP(iface, er)
				return nil, er
			}
		}

		agent.addToResult(iface, ifaceind, result)

		logger.Debug("Configuring network for ", iface.Name, ": ", *result)
		err = runSetupNetwork(iface.Sandbox, iface.Name, result)
		if err != nil {
			deallocIP(iface, err)
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

	for ix := range StaleContMetadata {
		err := agent.cleanStatleMetadata(StaleContMetadata[ix].Id.ContId)
		if err == nil {
			agent.deallocateMdIps(&StaleContMetadata[ix])
			agent.ipamMutex.Lock()
			delete(agent.epMetadata[podid], StaleContMetadata[ix].Id.ContId)
			agent.ipamMutex.Unlock()
		}
	}

	err := md.RecordMetadata(agent.config.CniMetadataDir,
		agent.config.CniNetwork, metadata)
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

func (agent *HostAgent) unconfigureContainerSecondaryIfacesLocked(podId, networkName, contId string) bool {
	podIdParts := strings.Split(podId, "/")
	logger := agent.log.WithFields(logrus.Fields{
		"ContId":    contId,
		"Pod":       podIdParts[1],
		"Namespace": podIdParts[0],
	})
	if nwMetaMap, ok := agent.podNetworkMetadata[podId]; ok {
		if _, ok := nwMetaMap[networkName]; ok {
			podAtt := &fabattv1.PodAttachment{
				PodRef: fabattv1.ObjRef{
					Name:      podIdParts[1],
					Namespace: podIdParts[0],
				},
			}
			if _, ok := agent.podNetworkMetadata[podId]; ok {
				if _, ok := agent.podNetworkMetadata[podId][networkName]; ok {
					podAtt.LocalIface = ""
					if contId != "" {
						if _, ok := agent.podNetworkMetadata[podId][networkName][contId]; ok {
							podAtt.LocalIface = agent.podNetworkMetadata[podId][networkName][contId].Network.VFName
						}
					}
				}
			}

			err := agent.updateFabricPodNetworkAttachmentLocked(podAtt, networkName, true)
			logger.Errorf("Deleting fabricpodnetworkattachment failed: %s", err)
			delete(nwMetaMap, networkName)
			agent.podNetworkMetadata[podId] = nwMetaMap
			return true
		}
	}
	return false
}

func (agent *HostAgent) unconfigureContainerIfaces(metadataArg *md.ContainerMetadata) error {
	logger := agent.log.WithFields(logrus.Fields{
		"ContId":    metadataArg.Id.ContId,
		"Pod":       metadataArg.Id.Pod,
		"Namespace": metadataArg.Id.Namespace,
	})

	podid := metadataArg.Id.Namespace + "/" + metadataArg.Id.Pod
	argNetworkName := metadataArg.Network.NetworkName

	agent.indexMutex.Lock()

	isPrimaryNetwork := false
	if argNetworkName == agent.primaryNetworkName {
		isPrimaryNetwork = true
	}
	isRelevantChainedConfig := false
	if agent.config.ChainedMode && ((isPrimaryNetwork && agent.config.EnableChainedPrimary) || (!isPrimaryNetwork && agent.config.EnableChainedSecondary)) {
		isRelevantChainedConfig = true
	}
	isRelevantConfig := !metadataArg.Network.ChainedMode || isRelevantChainedConfig

	if agent.unconfigureContainerSecondaryIfacesLocked(podid, argNetworkName, metadataArg.Id.ContId) {
		agent.indexMutex.Unlock()
		return nil
	}

	mdmap, ok := agent.epMetadata[podid]
	if !ok {
		if isRelevantConfig {
			logger.Info("Unconfigure called for pod with no metadata")
		}
		// Assume container is already unconfigured
		agent.indexMutex.Unlock()
		return nil
	}
	metadata, ok := mdmap[metadataArg.Id.ContId]
	if !ok {
		if isRelevantConfig {
			logger.Error("Unconfigure called for container with no metadata")
		}
		// Assume container is already unconfigured
		agent.indexMutex.Unlock()
		return nil
	}
	delete(mdmap, metadata.Id.ContId)
	if len(mdmap) == 0 {
		delete(agent.epMetadata, podid)
	}
	agent.indexMutex.Unlock()

	networkName := metadata.Network.NetworkName
	if networkName == "" && !agent.config.ChainedMode {
		networkName = agent.config.CniNetwork
	}
	err := md.ClearMetadata(agent.config.CniMetadataDir,
		networkName, metadataArg.Id.ContId)
	if isRelevantConfig {
		if err != nil {
			logger.Error("Failed to ClearMetadata ")
			return err
		}
	}

	agent.cniEpDelete(podid)
	if metadataArg.Network.ChainedMode {
		logger.Debug("Returning from unconfigure")
		return nil
	}

	logger.Debug("Deallocating IP address(es)")
	agent.deallocateMdIps(metadata)

	logger.Debug("Clearing container interface")

	for _, iface := range metadata.Ifaces {
		if len(metadata.Id.DeviceId) != 0 {
			logger.Debug("Moving the VF back to host's namespace, DeviceId : ", metadata.Id.DeviceId)
			logger.Debug("VF netdevice : ", iface.VfNetDevice)
			logger.Debug("VF rep : ", iface.HostVethName)
			err = runClearVf(iface.Sandbox, iface.Name, metadata.Id.DeviceId, iface.VfNetDevice)
			if err != nil {
				logger.Error("Could not move VF to host's namespace: ", err)
				return err
			}
		} else {
			agent.vethMutex.Lock()
			err = runClearVeth(iface.Sandbox, iface.Name)
			agent.vethMutex.Unlock()
			if err != nil {
				logger.Error("Could not clear Veth ports: ", err)
			}
		}
	}

	agent.env.CniDeviceDeleted(&podid, &metadata.Id)

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
	if agent.config.ChainedMode {
		agent.log.Info("Cleaning up stale additional network metadata")
		for netAttDefKey, netAttData := range agent.netattdefmap {
			exists, err := agent.env.CheckNetAttDefExists(netAttDefKey)
			if err != nil {
				agent.log.Errorf("Could not lookup netattdef %s: %v", netAttDefKey, err)
				continue
			}
			for _, podIfaceMap := range netAttData.Pods {
				for _, podAtt := range podIfaceMap {
					podKey := podAtt.PodRef.Namespace + "/" + podAtt.PodRef.Name
					logger := agent.log.WithFields(logrus.Fields{
						"podkey": podKey,
					})
					if !exists {
						agent.unconfigureContainerSecondaryIfacesLocked(podKey, netAttData.Name, "")
						continue
					}
					podExists, err := agent.env.CheckPodExists(&podKey)
					if err != nil {
						logger.Error("Could not lookup pod: ", err)
						continue
					}
					if !podExists {
						agent.unconfigureContainerSecondaryIfacesLocked(podKey, netAttData.Name, "")
					}
				}
			}
			if !exists {
				agent.networkAttDefDeleteByKeyLocked(netAttDefKey)
			}
		}
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

				err := agent.unconfigureContainerIfaces(metadata)
				if err != nil {
					logger.Error("Could not unconfigure container: ", err)
				}
			}
		}
	}

	agent.scheduleSyncPorts()

	agent.log.Debug("Done stale check")
}
