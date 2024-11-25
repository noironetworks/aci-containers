// Copyright 2017 Cisco Systems, Inc.
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
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"text/template"
	"time"

	uuid "github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

const DHCLIENT_CONF = "/usr/local/etc/dhclient.conf"

type opflexFault struct {
	FaultUUID   string `json:"fault_uuid"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	FaultCode   int    `json:"faultCode"`
}

func writeFault(faultfile string, ep *opflexFault) (bool, error) {
	newdata, err := json.MarshalIndent(ep, "", "  ")
	if err != nil {
		return true, err
	}
	existingdata, err := os.ReadFile(faultfile)
	if err == nil && reflect.DeepEqual(existingdata, newdata) {
		return false, nil
	}
	err = os.WriteFile(faultfile, newdata, 0644)
	return true, err
}

func (agent *HostAgent) createFaultOnAgent(description string, faultCode int) {
	if agent.config.OpFlexFaultDir == "" {
		agent.log.Error("OpFlex Fault directory not set")
		return
	}
	Uuid := uuid.New().String()
	faultFilePath := filepath.Join(agent.config.OpFlexFaultDir, description+".fs")
	faultFileExists := fileExists(faultFilePath)
	if faultFileExists {
		agent.log.Debug("Fault file exist at: ", faultFilePath)
		return
	}
	desc := strings.Replace(description, "_", " ", -1)
	fault := &opflexFault{
		FaultUUID:   Uuid,
		Severity:    "critical",
		Description: desc,
		FaultCode:   faultCode,
	}
	wrote, err := writeFault(faultFilePath, fault)
	if err != nil {
		agent.log.Warn("Unable to write fault file: ", err.Error())
	} else if wrote {
		agent.log.Debug("Created fault files at the location: ", faultFilePath)
	}
}

func (agent *HostAgent) isIpV4Present(iface string) bool {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		agent.log.Error("Could not enumerate interfaces: ", err)
		return false
	}
	if nlLink, ok := link.(*netlink.Vlan); ok {
		addrs, err := netlink.AddrList(nlLink, netlink.FAMILY_V4)
		if err != nil {
			agent.log.Error("Could not enumerate addresses: ", err)
			return false
		}
		if len(addrs) > 0 {
			agent.log.Info("vlan interface ip address: ", addrs)
			return true
		}
	}
	return false
}

func (agent *HostAgent) isIpSameSubnet(iface, subnet string) bool {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		agent.log.Error("Could not enumerate interfaces: ", err)
		return false
	}
	if nlLink, ok := link.(*netlink.Vlan); ok {
		addrs, err := netlink.AddrList(nlLink, netlink.FAMILY_V4)
		if err != nil {
			agent.log.Error("Could not enumerate addresses: ", err)
			return false
		}
		return agent.checkIfAnyIpsInSubnet(subnet, addrs)
	}
	return false
}

func (agent *HostAgent) checkIfAnyIpsInSubnet(subnet string, addrs []netlink.Addr) bool {
	_, ipnet, err := net.ParseCIDR(subnet)
	if err != nil {
		agent.log.Error("Failed to parse subnet: ", subnet, " ", err.Error())
		return false
	}
	for _, addr := range addrs {
		agent.log.Info("vlan interface ip address: ", addr.String())
		ipAddr := addr.IP.To4()
		if ipAddr == nil {
			ipAddr = addr.IP.To16()
		}
		if ipAddr != nil && ipnet.Contains(ipAddr) {
			return true
		}
	}
	return false
}

func (agent *HostAgent) updateResetConfFile() error {
	resetFile := "/usr/local/var/lib/opflex-agent-ovs/reboot-conf.d/reset.conf"
	t := time.Now()
	err := os.WriteFile(resetFile, []byte(t.String()), 0644)
	return err
}

func (agent *HostAgent) releaseVlanIp(name string) bool {
	released := false
	retryCount := agent.config.DhcpRenewMaxRetryCount
	dhcpDelay := time.Duration(agent.config.DhcpDelay)
	for i := 0; i < retryCount; i++ {
		time.Sleep(dhcpDelay * time.Second)
		cmd := exec.Command("dhclient", "-r", name, "--timeout", "30", "-cf", DHCLIENT_CONF)
		agent.log.Info("Executing command:", cmd.String())
		opt, err := cmd.Output()
		if err != nil {
			agent.log.Error("Failed to release ip : ", err.Error(), " ", string(opt))
			continue
		} else {
			agent.log.Info(string(opt))
		}
		if !agent.isIpV4Present(name) {
			agent.log.Info("vlan interface ip released")
			released = true
			break
		}
		agent.log.Info("vlan interface ip not released..retrying ")
	}
	return released
}

func (agent *HostAgent) renewVlanIp(name string) bool {
	renewed := false
	retryCount := agent.config.DhcpRenewMaxRetryCount
	dhcpDelay := time.Duration(agent.config.DhcpDelay)
	for i := 0; i < retryCount; i++ {
		time.Sleep(dhcpDelay * time.Second)
		cmd := exec.Command("dhclient", name, "--timeout", "30", "-cf", DHCLIENT_CONF)
		agent.log.Info("Executing command:", cmd.String())
		opt, err := cmd.Output()
		if err != nil {
			agent.log.Error("Failed to renew ip : ", err.Error(), " ", string(opt))
			continue
		} else {
			agent.log.Info(string(opt))
		}
		if !agent.isIpV4Present(name) {
			agent.log.Info("Ip not renewed..retrying ")
			continue
		}
		renewed = true
		break
	}
	return renewed
}

func (agent *HostAgent) doDhcpRenew(aciPodSubnet string) {
	retryCount := agent.config.DhcpRenewMaxRetryCount

	agent.log.Info("old aci-pod annotiation for multipod ", agent.aciPodAnnotation)
	agent.log.Info("new aci-pod annotiation for multipod ", aciPodSubnet)
	// no dhcp release-renew for none to pod-<id>-subnet case
	// as this is an odev connect case
	if agent.aciPodAnnotation == "none" &&
		aciPodSubnet != "" && aciPodSubnet != "none" {
		return
	}
	links, err := netlink.LinkList()
	if err != nil {
		agent.log.Error("Could not enumerate interfaces: ", err)
		return
	}
	var subnet string
	if aciPodSubnet != "none" {
		subnetSlice := strings.Split(aciPodSubnet, "-")
		if len(subnetSlice) > 2 {
			subnet = subnetSlice[2]
		}
	}
	var oldsubnet string
	if agent.aciPodAnnotation != "none" && agent.aciPodAnnotation != "" {
		subnetSlice := strings.Split(agent.aciPodAnnotation, "-")
		if len(subnetSlice) > 2 {
			oldsubnet = subnetSlice[2]
		}
	}
	for _, link := range links {
		switch link := link.(type) {
		case *netlink.Vlan:
			// find link with matching vlan
			if link.VlanId != int(agent.config.AciInfraVlan) {
				continue
			}
			if aciPodSubnet != "none" {
				if agent.isIpSameSubnet(link.Name, subnet) {
					agent.log.Info("Ip already from same subnet ", subnet)
					break
				}
			}
			success := false
			for i := 0; i < retryCount; i++ {
				if !agent.releaseVlanIp(link.Name) {
					agent.log.Error("FAILURE: Failed to release vlan interface ip, stopped retrying")
					break
				}
				if !agent.renewVlanIp(link.Name) {
					agent.log.Error("FAILURE: Failed to renew vlan interface ip, stopped retrying")
					break
				}
				if aciPodSubnet != "none" {
					if agent.isIpSameSubnet(link.Name, subnet) {
						success = true
						break
					} else {
						agent.log.Info("Interface ip is not from the subnet ", subnet, " retrying...")
					}
				} else if oldsubnet != "" {
					if !agent.isIpSameSubnet(link.Name, oldsubnet) {
						success = true
						agent.log.Info("Interface ip is not from old subnet ", oldsubnet, " retrying...")
						break
					}
					agent.log.Info("Interface ip is of old pod subnet ", oldsubnet)
				} else {
					agent.log.Info("dhcp release and renew done. Iteration : ", i+1)
				}
			}
			if (aciPodSubnet != "none" && !success) || (aciPodSubnet == "none" && oldsubnet != "" && !success) {
				agent.log.Error("FAILURE: Failed to assign an ip from new pod subnet to vlan interface")
			}
		}
	}
}

func (agent *HostAgent) discoverHostConfig() (conf *HostAgentNodeConfig) {
	if agent.config.OpflexMode == "overlay" {
		conf = &HostAgentNodeConfig{}
		conf.OpflexPeerIp = "127.0.0.1"
		agent.log.Debug("\n  == Opflex: Running in overlay mode ==\n")
		return
	} else if agent.config.OpflexMode == "dpu" {
		conf = &HostAgentNodeConfig{}
		conf.VxlanIface = "bond0.4093"
		conf.UplinkIface = "bond0"
		conf.VxlanAnycastIp = "10.0.0.32"
		conf.OpflexPeerIp = "10.0.0.30"
		if agent.config.InterfaceMtu == 0 {
			agent.config.InterfaceMtu = 1500 - agent.config.InterfaceMtuHeadroom
		}
		agent.log.Debug("\n == Opflex: Running on dpu ==\n")
		return
	}

	links, err := netlink.LinkList()
	if err != nil {
		agent.log.Error("Could not enumerate interfaces: ", err)
		description := "Could_not_enumerate_interfaces"
		agent.createFaultOnAgent(description, 3)
		return
	}

	for _, link := range links {
		switch link := link.(type) {
		case *netlink.Vlan:
			// find link with matching vlan
			if link.VlanId != int(agent.config.AciInfraVlan) {
				continue
			}
			// if the interface MTU was not explicitly set by
			// the user, use the link MTU
			if agent.config.InterfaceMtu == 0 {
				agent.config.InterfaceMtu = link.MTU - agent.config.InterfaceMtuHeadroom
			}
			// giving extra headroom of 100 bytes unless specified otherwise
			configMtu := agent.config.InterfaceMtuHeadroom + agent.config.InterfaceMtu
			if link.MTU < configMtu {
				agent.log.WithFields(logrus.Fields{
					"name": link.Name,
					"vlan": agent.config.AciInfraVlan,
					"mtu":  link.MTU,
				}).Error("OpFlex link MTU must be >= ", configMtu)
				description := "User_configured_MTU_exceeds_opflex_MTU"
				agent.createFaultOnAgent(description, 4)
				return
			}

			// find parent link
			var parent netlink.Link
			for _, plink := range links {
				if plink.Attrs().Index != link.ParentIndex {
					continue
				}

				parent = plink
				if parent.Attrs().MTU < configMtu {
					agent.log.WithFields(logrus.Fields{
						"name": parent.Attrs().Name,
						"vlan": agent.config.AciInfraVlan,
						"mtu":  parent.Attrs().MTU,
					}).Error("Uplink MTU must be >= ", configMtu)
					description := "User_configured_MTU_exceed_uplink_MTU"
					agent.createFaultOnAgent(description, 5)
					return
				}
			}
			if parent == nil {
				agent.log.WithFields(logrus.Fields{
					"index": link.ParentIndex,
					"name":  link.Name,
				}).Error("Could not find parent link for OpFlex interface")
				description := "Could_not_find_parent_link_for_OpFlex_interface"
				agent.createFaultOnAgent(description, 6)
				return
			}

			// Find address of link to compute anycast and peer IPs
			addrs, err := netlink.AddrList(link, 2)
			if err != nil {
				agent.log.WithFields(logrus.Fields{
					"name": link.Name,
				}).Error("Could not enumerate link addresses: ", err)
				description := "Could_not_enumerate_link_addresses"
				agent.createFaultOnAgent(description, 7)
				return
			}
			var anycast net.IP
			var peerIp net.IP
			for _, addr := range addrs {
				if addr.IP.To4() == nil || addr.IP.IsLoopback() {
					continue
				}
				anycast = addr.IP.Mask(addr.Mask)
				anycast[len(anycast)-1] = 32
				peerIp = addr.IP.Mask(addr.Mask)
				peerIp[len(peerIp)-1] = 30
			}

			if anycast == nil {
				agent.log.WithFields(logrus.Fields{
					"name": link.Name,
					"vlan": agent.config.AciInfraVlan,
				}).Error("IP address not set for OpFlex link")
				description := "IP_address_not_set_for_OpFlex_link"
				agent.createFaultOnAgent(description, 8)
				return
			}

			conf = &HostAgentNodeConfig{}
			conf.VxlanIface = link.Name
			conf.UplinkIface = parent.Attrs().Name
			conf.VxlanAnycastIp = anycast.String()
			conf.OpflexPeerIp = peerIp.String()
		}
	}

	if conf != nil {
		intf, err := net.InterfaceByName(conf.UplinkIface)
		if err == nil {
			conf.UplinkMacAdress = intf.HardwareAddr.String()
			return
		}
	}

	agent.log.WithFields(logrus.Fields{"vlan": agent.config.AciInfraVlan}).
		Error("Could not find suitable host uplink interface for vlan")
	description := "Could_not_find_suitable_host_uplink_interface_for_vlan"
	agent.createFaultOnAgent(description, 9)
	return
}

var opflexConfigBase = initTempl("opflex-config-base", `{
    "opflex": {
        "name": "{{.NodeName | js}}",
        "domain": "{{print "comp/prov-" .AciVmmDomainType "/ctrlr-[" .AciVmmDomain "]-" .AciVmmController "/sw-InsiemeLSOid" | js}}",
        "peers": [
            {"hostname": "{{.OpflexPeerIp | js}}", "port": "8009"}
        ]
    } ,
    "endpoint-sources": {
        "filesystem": ["{{.OpFlexEndpointDir | js}}"]
    },
    "service-sources": {
        "filesystem": ["{{.OpFlexServiceDir | js}}"]
    },
    "snat-sources": {
        "filesystem": ["{{.OpFlexSnatDir | js}}"]
    },
    "drop-log-config-sources": {
        "filesystem": ["{{.OpFlexDropLogConfigDir | js}}"]
    },
    "packet-event-notif": {
        "socket-name": ["{{.PacketEventNotificationSock | js}}"]
    },
    "host-agent-fault-sources": {
        "filesystem": ["{{.OpFlexFaultDir | js}}"]
    }
}
`)

var opflexConfigVxlan = initTempl("opflex-config-vxlan", `{
    "renderers": {
        "stitched-mode": {
            "int-bridge-name": "{{.IntBridgeName | js}}",
            "access-bridge-name": "{{.AccessBridgeName | js}}",
            "encap": {
                "vxlan" : {
                    "encap-iface": "vxlan0",
                    "uplink-iface": "{{.VxlanIface | js}}",
                    "uplink-vlan": "{{.AciInfraVlan}}",
                    "remote-ip": "{{.VxlanAnycastIp | js}}",
                    "remote-port": 8472
                }
            },
            "flowid-cache-dir": "{{.OpFlexFlowIdCacheDir | js}}",
            "mcast-group-file": "{{.OpFlexMcastFile | js}}",
            "drop-log": {
                "geneve" : {
                    "int-br-iface": "{{.DropLogIntInterface | js}}",
                    "access-br-iface": "{{.DropLogAccessInterface | js}}",
                    "remote-ip": "{{.OpFlexDropLogRemoteIp | js}}"
                }
            },
            "statistics": {
                "service": {
                    "flow-disabled": "true",
                    "enabled": "false"
                }
            }
        }
    }
}
`)

var opflexConfigVlan = initTempl("opflex-config-vlan", `{
    "renderers": {
        "stitched-mode": {
            "int-bridge-name": "{{.IntBridgeName | js}}",
            "access-bridge-name": "{{.AccessBridgeName | js}}",
            "encap": {
                "vlan" : {
                    "encap-iface": "{{.UplinkIface | js}}"
                }
            },
            "flowid-cache-dir": "{{.OpFlexFlowIdCacheDir | js}}",
            "mcast-group-file": "{{.OpFlexMcastFile | js}}",
            "drop-log": {
		"geneve" : {
		    "int-br-iface": "{{.DropLogIntInterface | js}}",
		    "access-br-iface": "{{.DropLogAccessInterface | js}}",
		    "remote-ip": "{{.OpFlexDropLogRemoteIp | js}}"
		}
	    }
        }
    }
}
`)

func initTempl(name, templ string) *template.Template {
	return template.Must(template.New(name).Parse(templ))
}

func (agent *HostAgent) writeConfigFile(name string,
	templ *template.Template) error {
	var buffer bytes.Buffer
	templ.Execute(&buffer, agent.config)

	path := filepath.Join(agent.config.OpFlexConfigPath, name)

	existing, err := os.ReadFile(path)
	if err != nil {
		if bytes.Equal(existing, buffer.Bytes()) {
			agent.log.Info("OpFlex agent configuration file ",
				path, " unchanged")
			return nil
		}
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	// in case there's an error in the write
	defer f.Close()
	_, err = f.Write(buffer.Bytes())
	if err != nil {
		return err
	}
	err = f.Close()
	if err != nil {
		return err
	}

	agent.log.Info("Wrote OpFlex agent configuration file ", path)

	return nil
}

func (agent *HostAgent) updateOpflexConfig() {
	if agent.config.ChainedMode {
		return
	}
	if agent.config.OpFlexConfigPath == "" {
		agent.log.Debug("OpFlex agent configuration path not set")
		return
	}
	if agent.config.OpFlexFaultDir == "" {
		agent.log.Warn("OpFlex Fault directory not set")
	} else {
		err := agent.removeAllFiles(agent.config.OpFlexFaultDir)
		if err != nil {
			agent.log.Error("Not able to clear Fault files on agent: ", err.Error())
		}
	}

	agent.indexMutex.Lock()
	newNodeConfig := agent.discoverHostConfig()
	agent.indexMutex.Unlock()
	if newNodeConfig == nil {
		panic(errors.New("Node configuration autodiscovery failed"))
	}
	var update bool

	agent.indexMutex.Lock()
	if !reflect.DeepEqual(*newNodeConfig, agent.config.HostAgentNodeConfig) ||
		!agent.opflexConfigWritten {
		// reset opflexConfigWritten flag when node-config differs
		agent.opflexConfigWritten = false

		agent.config.HostAgentNodeConfig = *newNodeConfig
		agent.log.WithFields(logrus.Fields{
			"uplink-iface":     newNodeConfig.UplinkIface,
			"vxlan-iface":      newNodeConfig.VxlanIface,
			"vxlan-anycast-ip": newNodeConfig.VxlanAnycastIp,
			"opflex-peer-ip":   newNodeConfig.OpflexPeerIp,
			"opflex-mode":      agent.config.OpflexMode,
		}).Info("Discovered node configuration")
		if err := agent.writeOpflexConfig(); err == nil {
			agent.opflexConfigWritten = true
		} else {
			agent.log.Error("Failed to write OpFlex agent config: ", err)
		}
	}
	agent.indexMutex.Unlock()

	if update {
		agent.updateAllServices()
	}
}

func (agent *HostAgent) writeOpflexConfig() error {
	err := agent.writeConfigFile("01-base.conf", opflexConfigBase)
	if err != nil {
		return err
	}

	var rtempl *template.Template
	if agent.config.EncapType == "vlan" {
		rtempl = opflexConfigVlan
	} else if agent.config.EncapType == "vxlan" {
		rtempl = opflexConfigVxlan
	} else {
		panic("Unsupported encap type: " + agent.config.EncapType)
	}

	err = agent.writeConfigFile("10-renderer.conf", rtempl)
	if err != nil {
		return err
	}
	return nil
}

func (agent *HostAgent) removeAllFiles(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	names, err := d.Readdirnames(-1)
	if err != nil {
		return err
	}
	for _, name := range names {
		err = os.RemoveAll(filepath.Join(dir, name))
		if err != nil {
			agent.log.Error("Not able to clear the Fault Files  ", err)
			return err
		}
	}
	return nil
}
