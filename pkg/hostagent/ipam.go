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

// IP address management for host agent

package hostagent

import (
	"encoding/json"
	"fmt"
	"net"

	cnitypes "github.com/containernetworking/cni/pkg/types"
	"github.com/sirupsen/logrus"

	"github.com/noironetworks/aci-containers/pkg/ipam"
	"github.com/noironetworks/aci-containers/pkg/metadata"
)

func makePodKey(ns, name string) string {
	return fmt.Sprintf("%s.%s", ns, name)
}

func combine(ranges []*ipam.IpAlloc) *ipam.IpAlloc {
	result := ipam.New()
	for _, r := range ranges {
		result.AddAll(r)
	}
	return result
}

// builds the used IP info from metadata, at init.
func (agent *HostAgent) buildUsedIPs() {
	agent.usedIPs = make(map[string]string)
	for _, mds := range agent.epMetadata {
		for _, md := range mds {
			podKey := makePodKey(md.Id.Namespace, md.Id.Pod)
			for _, iface := range md.Ifaces {
				for _, ip := range iface.IPs {
					agent.usedIPs[ip.Address.IP.String()] = podKey
				}
			}
		}
	}

	agent.log.Infof("buildIPUsed: %v addresses found", len(agent.usedIPs))
}

// must have index lock
func (agent *HostAgent) rebuildIpam() {
	for ip := range agent.usedIPs {
		ipAddr := net.ParseIP(ip)
		if ipAddr != nil {
			if !agent.podIps.RemoveIp(ipAddr) {
				agent.log.Errorf("Unable to find used IP %s(%s) in range", ip, agent.usedIPs[ip])
			}
		} else {
			agent.log.Warnf("Couldn't parse %v", ip)
		}
	}

	agent.log.WithFields(logrus.Fields{
		"V4": agent.podIps.CombineV4(),
		"V6": agent.podIps.CombineV6(),
	}).Debug("Updated pod network ranges")
}

func (agent *HostAgent) updateIpamAnnotation(newPodNetAnnotation string) {
	if agent.podNetAnnotation == newPodNetAnnotation {
		return
	}
	agent.podNetAnnotation = newPodNetAnnotation

	newRanges := &metadata.NetIps{}
	err := json.Unmarshal([]byte(agent.podNetAnnotation), newRanges)
	if err != nil {
		agent.log.Error("Could not parse pod network annotation", err)
		return
	}

	agent.ipamMutex.Lock()
	defer agent.ipamMutex.Unlock()
	agent.podIps = ipam.NewIpCache()
	if newRanges.V4 != nil {
		agent.podIps.LoadRanges(newRanges.V4)
	}
	if newRanges.V6 != nil {
		agent.podIps.LoadRanges(newRanges.V6)
	}

	agent.rebuildIpam()
}

func convertRoutes(routes []route) (cniroutes []*cnitypes.Route) {
	for _, r := range routes {
		cniroutes = append(cniroutes, &cnitypes.Route{
			Dst: net.IPNet{
				IP:   r.Dst.IP,
				Mask: r.Dst.Mask,
			},
			GW: r.GW,
		})
	}
	return
}

func makeIFaceIp(nc *cniNetConfig, ip net.IP) metadata.ContainerIfaceIP {
	return metadata.ContainerIfaceIP{
		Address: net.IPNet{
			IP:   ip,
			Mask: nc.Subnet.Mask,
		},
		Gateway: nc.Gateway,
	}
}

func deallocateIp(ip net.IP, free []*ipam.IpAlloc) {
	free[len(free)-1].AddIp(ip)
}

func (agent *HostAgent) allocateIps(iface *metadata.ContainerIfaceMd, podKey string) error {
	var result error
	var err error
	agent.ipamMutex.Lock()
	defer agent.ipamMutex.Unlock()

	allocIP := func(isv4 bool, nc *cniNetConfig) {
		var ip net.IP
		ip, err = agent.podIps.AllocateIp(isv4)
		if err != nil {
			result =
				fmt.Errorf("Could not allocate IPv4 address: %v", err)
		} else {
			oldKey, found := agent.usedIPs[ip.String()]
			if found {
				agent.log.Errorf("Duplicate IP %v allocated prev: %s", ip.String(), oldKey)
			}
			iface.IPs =
				append(iface.IPs, makeIFaceIp(nc, ip))
			agent.usedIPs[ip.String()] = podKey
		}
	}

	for _, nc := range agent.config.NetConfig {
		if nc.Subnet.IP != nil {
			if nc.Subnet.IP.To4() != nil {
				allocIP(true, &nc)
			} else if nc.Subnet.IP.To16() != nil {
				allocIP(false, &nc)
			}
		}
	}

	if result != nil {
		agent.deallocateIpsLocked(iface)
	} else {
		agent.log.WithFields(logrus.Fields{
			"IPs": iface.IPs,
		}).Debug("Allocated IP addresses")
	}

	return result
}

func (agent *HostAgent) deallocateIpsLocked(iface *metadata.ContainerIfaceMd) {
	for _, ip := range iface.IPs {
		if ip.Address.IP == nil {
			continue
		}
		if ip.Address.IP.To4() != nil {
			agent.podIps.DeallocateIp(ip.Address.IP)
			delete(agent.usedIPs, ip.Address.IP.String())
		} else if ip.Address.IP.To16() != nil {
			agent.podIps.DeallocateIp(ip.Address.IP)
			delete(agent.usedIPs, ip.Address.IP.String())
		}
	}

	iface.IPs = nil
}

func (agent *HostAgent) deallocateMdIps(md *metadata.ContainerMetadata) {
	if agent.config.NetConfig == nil {
		// using external ipam
		return
	}

	agent.ipamMutex.Lock()
	defer agent.ipamMutex.Unlock()
	for _, iface := range md.Ifaces {
		for _, ip := range iface.IPs {
			if ip.Address.IP == nil {
				continue
			}

			if ip.Address.IP.To4() != nil {
				agent.podIps.DeallocateIp(ip.Address.IP)
				delete(agent.usedIPs, ip.Address.IP.String())
			} else if ip.Address.IP.To16() != nil {
				agent.podIps.DeallocateIp(ip.Address.IP)
				delete(agent.usedIPs, ip.Address.IP.String())
			}
			agent.log.WithFields(logrus.Fields{
				"ip": ip.Address.IP,
			}).Debug("Returned IP to pool")
		}
	}
}
