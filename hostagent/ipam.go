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

package main

import (
	"encoding/json"
	"fmt"
	"net"

	"github.com/Sirupsen/logrus"
	cnitypes "github.com/containernetworking/cni/pkg/types"

	"github.com/noironetworks/aci-containers/ipam"
	"github.com/noironetworks/aci-containers/metadata"
)

// must have index lock
func rebuildIpam(newPodNetAnnotation string) {
	if podNetAnnotation == newPodNetAnnotation {
		return
	}
	podNetAnnotation = newPodNetAnnotation

	ips := &metadata.NetIps{}
	err := json.Unmarshal([]byte(podNetAnnotation), ips)
	if err != nil {
		log.Error("Could not parse pod network annotation", err)
		return
	}

	podIpsV4 = ipam.New()
	if ips.V4 != nil {
		podIpsV4.AddRanges(ips.V4)
	}
	podIpsV6 = ipam.New()
	if ips.V6 != nil {
		podIpsV6.AddRanges(ips.V6)
	}

	for _, ofep := range opflexEps {
		for _, ipStr := range ofep.IpAddress {
			ip := net.ParseIP(ipStr)
			if ip == nil {
				continue
			}
			if ip.To4() != nil {
				podIpsV4.RemoveIp(ip)
			} else if ip.To16() != nil {
				podIpsV6.RemoveIp(ip)
			}
		}
	}

	log.WithFields(logrus.Fields{
		"V4": podIpsV4.FreeList,
		"V6": podIpsV6.FreeList,
	}).Info("Updated pod network ranges")
}

func convertRoutes(routes []Route) []cnitypes.Route {
	cniroutes := make([]cnitypes.Route, 0, len(routes))
	for _, r := range routes {
		cniroutes = append(cniroutes, cnitypes.Route{
			Dst: net.IPNet{
				IP:   r.Dst.IP,
				Mask: r.Dst.Mask,
			},
			GW: r.GW,
		})
	}
	return cniroutes
}

func makeNetconf(nc *CNINetConfig, ip net.IP) *cnitypes.IPConfig {
	return &cnitypes.IPConfig{
		IP: net.IPNet{
			IP:   ip,
			Mask: nc.Subnet.Mask,
		},
		Gateway: nc.Gateway,
		Routes:  convertRoutes(nc.Routes),
	}
}

func allocateIps(netConf *cnitypes.Result) error {
	var v4 net.IP
	var v6 net.IP
	var result error

	for _, nc := range config.NetConfig {
		if nc.Subnet.IP != nil {
			if v4 == nil && nc.Subnet.IP.To4() != nil {
				v4, err := podIpsV4.GetIp()
				if err != nil {
					result = fmt.Errorf("Could not allocate IPv4 address:", err)
				} else {
					netConf.IP4 = makeNetconf(&nc, v4)
				}
			} else if v6 == nil && nc.Subnet.IP.To16() != nil {
				v6, err := podIpsV6.GetIp()
				if err != nil {
					result = fmt.Errorf("Could not allocate IPv6 address:", err)
				} else {
					netConf.IP6 = makeNetconf(&nc, v6)
				}
			}
		}
	}

	if result != nil {
		if v4 != nil {
			podIpsV4.AddIp(v4)
		}
		if v6 != nil {
			podIpsV6.AddIp(v6)
		}
	}

	return result
}
