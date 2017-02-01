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

package main

import (
	"flag"

	"github.com/noironetworks/aci-containers/ipam"
)

type OpflexGroup struct {
	PolicySpace string `json:"policy-space,omitempty"`
	Name        string `json:"name,omitempty"`
}

// Configuration for the controller
type ControllerConfig struct {
	// Log level
	LogLevel string `json:"log-level,omitempty"`

	// Absolute path to a kubeconfig file
	KubeConfig string `json:"kubeconfig,omitempty"`

	// Default endpoint group annotation value
	DefaultEg OpflexGroup `json:"default-endpoint-group,omitempty"`

	// Default security group annotation value
	DefaultSg []OpflexGroup `json:"default-security-group,omitempty"`

	// IP addresses used for pod network
	PodIpPool []ipam.IpRange `json:"pod-ip-pool,omitempty"`

	// IP addresses used for externally exposed load balanced services
	ServiceIpPool []ipam.IpRange `json:"service-ip-pool,omitempty"`

	// IP addresses that can be requested as static service IPs in
	// service spec
	StaticServiceIpPool []ipam.IpRange `json:"static-service-ip-pool,omitempty"`

	// IP addresses to use for node service endpoints
	NodeServiceIpPool []ipam.IpRange `json:"node-service-ip-pool,omitempty"`
}

func NewConfig() *ControllerConfig {
	return &ControllerConfig{
		DefaultSg: make([]OpflexGroup, 0),
	}
}

func initFlags() {
	flag.StringVar(&config.LogLevel, "log-level", "info", "Log level")

	flag.StringVar(&config.KubeConfig, "kubeconfig", "", "Absolute path to a kubeconfig file")
}

func loadIpRanges(v4 *ipam.IpAlloc, v6 *ipam.IpAlloc, ipranges []ipam.IpRange) {

	for _, r := range ipranges {
		if r.Start.To4() != nil && r.End.To4() != nil {
			v4.AddRange(r.Start, r.End)
		} else if r.Start.To16() != nil && r.End.To16() != nil {
			v6.AddRange(r.Start, r.End)
		} else {
			log.Warn("Range invalid: ", r)
		}
	}
}

func initIpam() {
	loadIpRanges(podNetworkIpsV4, podNetworkIpsV6, config.PodIpPool)
	loadIpRanges(serviceIpsV4, serviceIpsV6, config.ServiceIpPool)
	loadIpRanges(staticServiceIpsV4, staticServiceIpsV6,
		config.StaticServiceIpPool)
	loadIpRanges(nodeServiceIpsV4, nodeServiceIpsV6,
		config.NodeServiceIpPool)
}
