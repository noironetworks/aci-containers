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
	"errors"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"text/template"

	"encoding/json"
	uuid "github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

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
	existingdata, err := ioutil.ReadFile(faultfile)
	if err == nil && reflect.DeepEqual(existingdata, newdata) {
		return false, nil
	}
	err = ioutil.WriteFile(faultfile, newdata, 0644)
	return true, err
}

func (agent *HostAgent) createFaultOnAgent(description string, faultCode int) {
	Uuid := uuid.New().String()
	faultFilePath := filepath.Join(agent.config.OpFlexFaultDir, description+".fs")
	faultFileExists := fileExists(faultFilePath)
	if faultFileExists {
		agent.log.Debug("fault file exist at: ", faultFilePath)
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
		agent.log.Debug("Created fault file at the location: ", faultFilePath)
	}
	return
}

func (agent *HostAgent) discoverHostConfig() (conf *HostAgentNodeConfig) {
	if agent.config.OpflexMode == "overlay" {
		conf = &HostAgentNodeConfig{}
		conf.OpflexPeerIp = "127.0.0.1"
		agent.log.Debug("\n  == Opflex: Running in overlay mode ==\n")
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
				agent.config.InterfaceMtu = link.MTU - 100
			}
			// giving extra headroom of 100 bytes
			configMtu := 100 + agent.config.InterfaceMtu
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

func initTempl(name string, templ string) *template.Template {
	return template.Must(template.New(name).Parse(templ))
}

func (agent *HostAgent) writeConfigFile(name string,
	templ *template.Template) error {

	var buffer bytes.Buffer
	templ.Execute(&buffer, agent.config)

	path := filepath.Join(agent.config.OpFlexConfigPath, name)

	existing, err := ioutil.ReadFile(path)
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
	if agent.config.OpFlexConfigPath == "" {
		agent.log.Debug("OpFlex agent configuration path not set")
		return
	}
	if agent.config.OpFlexFaultDir == "" {
		agent.log.Warn("OpFlex Faults directories not set")
	} else {
		err := removeAllFiles(agent.config.OpFlexFaultDir)
		if err != nil {
			agent.log.Warn("Not able to clear faults files on agent: ", err.Error())
		}
	}

	newNodeConfig := agent.discoverHostConfig()
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

func removeAllFiles(dir string) error {
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
			return err
		}
	}
	return nil
}
