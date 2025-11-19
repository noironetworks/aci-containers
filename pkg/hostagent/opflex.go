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
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"text/template"
	"time"

	uuid "github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

const (
	DHCLIENT_LEASE_DIR         = "/usr/local/var/lib/dhclient"
	DHCLIENT_CONF              = "/usr/local/etc/dhclient.conf"
	MCAST_ROUTE_DEST           = "224.0.0.0/4"
	PLATFORM_SUBSCRIPTION_FILE = "/usr/local/var/lib/opflex-agent-ovs/events/platformconfig.subscriptions"
	PLATFORM_NOTIFICATION_FILE = "/usr/local/var/lib/opflex-agent-ovs/events/platformconfig.notifications"
	MAX_PLATFORM_EVENT_AGE     = 120 * time.Second
)

type opflexFault struct {
	FaultUUID   string `json:"fault_uuid"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	FaultCode   int    `json:"faultCode"`
}

type OpflexNotification struct {
	Uuid   string                `json:"uuid"`
	Events []PlatformConfigEvent `json:"events"`
}

type PlatformConfigEvent struct {
	Timestamp time.Time `json:"timestamp"`
	Uri       string    `json:"uri"`
	State     string    `json:"state"`
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

func (agent *HostAgent) createPlatformSubscriptionJson() {
	subscription := struct {
		UUID          string `json:"uuid"`
		TimeZone      string `json:"time-zone"`
		TimeFormat    string `json:"time-format"`
		Subscriptions []struct {
			Type    string `json:"type"`
			State   string `json:"state"`
			Subject string `json:"subject"`
		} `json:"subscriptions"`
	}{
		UUID:       uuid.New().String(),
		TimeZone:   "UTC",
		TimeFormat: "ISO8601",
		Subscriptions: []struct {
			Type    string `json:"type"`
			State   string `json:"state"`
			Subject string `json:"subject"`
		}{{
			Type:    "class",
			State:   "deleted",
			Subject: "PlatformConfig",
		}},
	}

	data, err := json.MarshalIndent(subscription, "", "    ")
	if err != nil {
		agent.log.WithError(err).Error("Failed to marshal subscription data")
		return
	}

	if err := os.WriteFile(PLATFORM_SUBSCRIPTION_FILE, data, 0644); err != nil {
		agent.log.WithError(err).Error("Failed to write subscription file")
		return
	}

	agent.log.Debug("Created platform subscription file")
}

func (agent *HostAgent) isPlatformConfigDeleteEventReceivedByOpflex() bool {
	data, err := os.ReadFile(PLATFORM_NOTIFICATION_FILE)
	if err != nil {
		agent.log.WithError(err).Error(
			"Failed to read PlatformConfigDeleteNotification file")
		return false
	}

	var notification OpflexNotification
	if err := json.Unmarshal(data, &notification); err != nil {
		agent.log.WithError(err).Error(
			"Failed to parse PlatformConfigDeleteNotification file")
		return false
	}

	if len(notification.Events) != 1 {
		return false
	}

	event := notification.Events[0]
	diff := time.Since(event.Timestamp)
	agent.log.Debug("Found PlatformConfigDeleteNotification with timestamp: ", event.Timestamp)
	return diff >= 0 && diff <= MAX_PLATFORM_EVENT_AGE
}

func (agent *HostAgent) isMultiCastRoutePresent(link netlink.Link) bool {
	routes, err := netlink.RouteList(link, netlink.FAMILY_V4)
	if err != nil {
		agent.log.Error("Failed to list routes: ", err)
		return false
	}
	for _, route := range routes {
		if route.Dst != nil && route.Dst.String() == MCAST_ROUTE_DEST {
			return true
		}
	}
	return false
}

func (agent *HostAgent) addMultiCastRoute(link netlink.Link, name string) {
	if agent.isMultiCastRoutePresent(link) {
		agent.log.Info("Multicast route already present for interface ", name)
		return
	}
	retryCount := agent.config.DhcpRenewMaxRetryCount
	for i := 0; i < retryCount; i++ {
		cmd := exec.Command("ip", "route", "add", MCAST_ROUTE_DEST, "dev", name, "proto", "static", "scope", "link", "metric", "401")
		agent.log.Info("Executing command:", cmd.String())
		opt, err := cmd.Output()
		if err != nil {
			agent.log.Error("Failed to add multicast route : ", err.Error(), " ", string(opt))
			continue
		} else {
			agent.log.Info(string(opt))
		}
		if agent.isMultiCastRoutePresent(link) {
			agent.log.Info("Added Multicast route successfully ")
			return
		}
		agent.log.Error("Failed to add Multicast route...iteration:", i+1)
	}
}

func (agent *HostAgent) getInterfaceIPv4(iface string) net.IP {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		agent.log.Errorf("failed to find interface %s: %v", iface, err)
		return nil
	}

	addrs, err := ifi.Addrs()
	if err != nil {
		agent.log.Errorf("failed to get addresses for interface %s: %v", iface, err)
		return nil
	}
	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip4 := ip.To4(); ip4 != nil && !ip4.IsLoopback() && !ip4.IsUnspecified() {
			agent.log.Infof("Found IPv4 address %s for interface %s", ip4, iface)
			return ip4
		}
	}
	agent.log.Errorf("failed to get IPV4 address for interface %s", iface)
	return nil
}

func (agent *HostAgent) checkDhclientLease(interfaceName string) string {
	files, err := os.ReadDir(DHCLIENT_LEASE_DIR)
	if err != nil {
		agent.log.Errorf("Error reading directory %s: %v", DHCLIENT_LEASE_DIR, err)
		return ""
	}

	var targetFile string

	reIface := regexp.MustCompile(`interface\s+"([^"]+)"`)
	reIP := regexp.MustCompile(`fixed-address\s+([0-9.]+);`)
	reExpire := regexp.MustCompile(`expire\s+\d+\s+([0-9/:\s]+);`)

	for _, f := range files {
		if f.IsDir() {
			continue
		}
		if !strings.HasSuffix(f.Name(), ".leases") {
			continue
		}
		path := filepath.Join(DHCLIENT_LEASE_DIR, f.Name())
		content, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		matches := reIface.FindAllStringSubmatch(string(content), -1)
		for _, m := range matches {
			if len(m) > 1 && m[1] == interfaceName {
				targetFile = path
				break
			}
		}
	}
	if targetFile == "" {
		agent.log.Infof("No lease file found for interface %s", interfaceName)
		return ""
	}
	file, err := os.Open(targetFile)
	if err != nil {
		agent.log.Errorf("Error opening lease file: %v", err)
		return ""
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	var (
		inLeaseBlock  bool
		currentIface  string
		currentIP     string
		currentExpire time.Time
		maxExpire     time.Time
		selectedIP    string
	)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "lease {") {
			inLeaseBlock = true
			currentIface, currentIP = "", ""
			currentExpire = time.Time{}
			continue
		}
		if strings.HasPrefix(line, "}") && inLeaseBlock {
			inLeaseBlock = false

			if currentIface == interfaceName && !currentExpire.IsZero() {
				if currentExpire.After(maxExpire) {
					maxExpire = currentExpire
					selectedIP = currentIP
				}
			}
			continue
		}
		if !inLeaseBlock {
			continue
		}
		if m := reIface.FindStringSubmatch(line); len(m) == 2 {
			currentIface = m[1]
		}
		if m := reIP.FindStringSubmatch(line); len(m) == 2 {
			currentIP = m[1]
		}
		if m := reExpire.FindStringSubmatch(line); len(m) == 2 {
			t, err := time.Parse("2006/01/02 15:04:05", strings.TrimSpace(m[1]))
			if err == nil {
				currentExpire = t
			}
		}
	}
	if err := scanner.Err(); err != nil {
		agent.log.Errorf("Error scanning lease file: %v", err)
		return ""
	}
	agent.log.Infof("Max expiry for %s: %v", interfaceName, maxExpire)
	return selectedIP
}

func (agent *HostAgent) releaseVlanIp(name string) bool {
	retryCount := agent.config.DhcpRenewMaxRetryCount
	dhcpDelay := time.Duration(agent.config.DhcpDelay) * time.Second
	for i := 0; i < retryCount; i++ {
		if i > 0 {
			time.Sleep(dhcpDelay)
		}
		leaseIP := agent.checkDhclientLease(name)
		interfaceIP := agent.getInterfaceIPv4(name)

		if interfaceIP == nil && leaseIP == "" {
			agent.log.Infof("No IP or lease found for %s, nothing to release", name)
			return true
		}
		// Renew before release if lease info looks inconsistent or lease doesn't exists
		if leaseIP == "" || (interfaceIP != nil && leaseIP != interfaceIP.String()) {
			cmd := exec.Command("dhclient", "-v", name, "--timeout", "30", "-cf", DHCLIENT_CONF)
			agent.log.Info("Executing command:", cmd.String())
			opt, err := cmd.Output()
			leaseIP = agent.checkDhclientLease(name)
			interfaceIP = agent.getInterfaceIPv4(name)
			if err != nil || interfaceIP == nil || leaseIP != interfaceIP.String() {
				agent.log.Errorf("Attempt %d/%d: dhclient renew failed for %s: %v", i+1, retryCount, name, err)
				continue
			} else {
				agent.log.Info(string(opt))
			}
		} else {
			agent.log.Info("Skipping dhclient renew")
		}

		cmd := exec.Command("dhclient", "-v", "-r", name, "--timeout", "30", "-cf", DHCLIENT_CONF)
		agent.log.Info("Executing command:", cmd.String())
		opt, err := cmd.Output()
		interfaceIP = agent.getInterfaceIPv4(name)
		if err != nil || interfaceIP != nil {
			agent.log.Errorf("Attempt %d/%d: failed to release IP on %s: %v", i+1, retryCount, name, err)
			continue
		} else {
			agent.log.Info(string(opt))
			return true
		}
	}
	return false
}

func (agent *HostAgent) renewVlanIp(name string) bool {
	link, err := netlink.LinkByName(name)
	if err != nil {
		fmt.Errorf("failed to find interface %s: %w", name, err)
		return false
	}
	retryCount := agent.config.DhcpRenewMaxRetryCount
	dhcpDelay := time.Duration(agent.config.DhcpDelay) * time.Second
	for i := 0; i < retryCount; i++ {
		if i > 0 {
			time.Sleep(dhcpDelay)
		}
		// Down → short sleep → Up tends to trigger renew across managers.
		if err := netlink.LinkSetDown(link); err != nil {
			agent.log.Errorf("failed to set interface %s down: %v", name, err)
			continue
		}
		time.Sleep(dhcpDelay)
		if err := netlink.LinkSetUp(link); err != nil {
			agent.log.Errorf("failed to set interface %s up: %v", name, err)
			continue
		} else {
			const maxRetries = 5
			for i := 0; i < maxRetries; i++ {
				ip := agent.getInterfaceIPv4(name)
				if ip != nil {
					agent.log.Infof("Successfully renewed VLAN IP for interface %s: %s", name, ip.String())
					return true
				}
				agent.log.Warnf("interface %s has no IPv4 yet (attempt %d/%d)", name, i+1, maxRetries)
				time.Sleep(1 * time.Second)
			}
		}
	}

	return false
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
				const dhcpTurnaroundTime = 15
				for itr := 0; itr < dhcpTurnaroundTime; itr++ {
					if aciPodSubnet != "none" {
						if agent.isIpSameSubnet(link.Name, subnet) {
							success = true
							break
						}
					} else if oldsubnet != "" {
						if !agent.isIpSameSubnet(link.Name, oldsubnet) {
							success = true
							agent.log.Info("Interface ip is not from old subnet ", oldsubnet)
							break
						}
					}
					time.Sleep(1 * time.Second)
				}
				if success {
					break
				} else {
					agent.log.Info("dhcp release and renew done. Iteration : ", i+1)
				}
			}
			if (aciPodSubnet != "none" && !success) || (aciPodSubnet == "none" && oldsubnet != "" && !success) {
				agent.log.Error("FAILURE: Failed to assign an ip from new pod subnet to vlan interface")
			}
			agent.addMultiCastRoute(link, link.Name)
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
			if conf.UplinkMacAdress != agent.config.UplinkMacAdress {
				agent.log.Info("UplinkMacAdress updated from ", agent.config.UplinkMacAdress, " to ", conf.UplinkMacAdress)
				agent.scheduleSyncNodeInfo()
			}
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
        ],
        "notif": {
            "enabled": true
        }
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
	"netpol-sources": {
		"filesystem": ["{{.OpFlexNetPolDir | js}}"]
	},
    "drop-log-config-sources": {
        "filesystem": ["{{.OpFlexDropLogConfigDir | js}}"]
    },
    "packet-event-notif": {
        "socket-name": ["{{.PacketEventNotificationSock | js}}"]
    },
    "host-agent-fault-sources": {
        "filesystem": ["{{.OpFlexFaultDir | js}}"]
    },
    "event-notifications": {
        "filesystem": "/usr/local/var/lib/opflex-agent-ovs/events"
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
