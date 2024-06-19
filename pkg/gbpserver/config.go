// Copyright 2019 Cisco Systems, Inc.
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

package gbpserver

import (
	"flag"
)

// Configuration for the gbpserver
type GBPServerConfig struct {
	// General log level
	LogLevel string `json:"log-level,omitempty"`

	// GRPC log level
	GRPCLogLevel string `json:"grpc-log-level,omitempty"`

	// Watch log level
	WatchLogLevel string `json:"watch-log-level,omitempty"`

	// Absolute path to a kubeconfig file
	KubeConfig string `json:"kubeconfig,omitempty"`

	// TCP port to run status server on (or 0 to disable)
	StatusPort int `json:"status-port,omitempty"`

	// TCP port to run grpc server on
	GRPCPort int `json:"grpc-port,omitempty"`

	// TCP port to run apic proxy server on (or 0 to disable)
	ProxyListenPort int `json:"proxy-listen-port,omitempty"`

	// Pod subnet CIDR in the form <gateway-address>/<prefix-length> that
	// cover all pod-ip-pools
	PodSubnet  string `json:"pod-subnet,omitempty"`
	NodeSubnet string `json:"node-subnet,omitempty"`

	// Tenant to use when creating policy objects in APIC
	AciPolicyTenant string `json:"aci-policy-tenant,omitempty"`

	// The name of the ACI VMM domain
	AciVmmDomain string `json:"aci-vmm-domain,omitempty"`

	AciVrfTenant string `json:"aci-vrf-tenant,omitempty"`

	// ACI VRF for this kubernetes instance
	AciVrf     string `json:"aci-vrf,omitempty"`
	VrfEncapID int    `json:"vrf-encap-id,omitempty"`

	// Metrics
	EnableMetrics bool `json:"enable-metrics,omitempty"`
	MetricsPort   int  `json:"metrics-port,omitempty"`
}

func InitConfig(config *GBPServerConfig) {
	flag.StringVar(&config.LogLevel, "log-level", "info", "Log level")
	flag.StringVar(&config.GRPCLogLevel, "grpc-log-level", "info", "Log level")
	flag.StringVar(&config.WatchLogLevel, "watch-log-level", "info", "Log level")
	flag.StringVar(&config.KubeConfig, "kubeconfig", "", "Absolute path to a kubeconfig file")
	flag.IntVar(&config.StatusPort, "status-port", 8092, "TCP port to run status server on (or 0 to disable)")
	flag.IntVar(&config.GRPCPort, "grpc-port", 19999, "TCP port to run grpc server on")
	flag.IntVar(&config.ProxyListenPort, "proxy-listen-port", 8899, "TCP port to run apic proxy listener on(0 to disable)")
	flag.StringVar(&config.AciPolicyTenant, "aci-policy-tenant", "kube", "Tenant")
	flag.StringVar(&config.AciVmmDomain, "aci-vmm-domain", "kubedom", "VmmDomain")
	flag.StringVar(&config.AciVrf, "aci-vrf", "defaultVrf", "Vrf")
	flag.StringVar(&config.PodSubnet, "pod-subnet", "10.2.56.1/21", "pod subnet")
	flag.StringVar(&config.NodeSubnet, "node-subnet", "1.100.201.0/24", "node subnet")
	flag.IntVar(&config.VrfEncapID, "vrf-encap-id", RdEncapID, "encap-id for vrf")
	flag.BoolVar(&config.EnableMetrics, "enable-metrics", false, "Enable metrics")
	flag.IntVar(&config.MetricsPort, "metrics-port", 8192, "Port to expose metrics on")
}
