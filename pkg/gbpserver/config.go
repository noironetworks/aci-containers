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
	"github.com/noironetworks/aci-containers/pkg/gbpserver/kafkac"
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

	// Used by internal kv store
	EtcdDir  string `json:"etcd-dir,omitempty"`
	EtcdPort int    `json:"etcd-port,omitempty"`

	// Tenant to use when creating policy objects in APIC
	AciPolicyTenant string `json:"aci-policy-tenant,omitempty"`

	// The name of the ACI VMM domain
	AciVmmDomain string `json:"aci-vmm-domain,omitempty"`

	// ACI VRF for this kubernetes instance
	AciVrf string `json:"aci-vrf,omitempty"`

	// APIC info
	Apic         *ApicInfo `json:"apic,omitempty"`
	SyncRemEps bool `json:"sync-rem-eps",omitempty"`

	PushJsonFile bool      `json:"push-json-file,omitempty"`
}

type ApicInfo struct {
	// The hostnames or IPs for connecting to apic
	Hosts []string `json:"apic-hosts,omitempty"`

	// The username for connecting to APIC
	Username string `json:"apic-username,omitempty"`

	// The password for connecting to APIC
	Password string `json:"apic-password,omitempty"`

	RefreshTimer string `json:"apic-refreshtime,omitempty"`

	// How early (seconds) the subscriptions to be refreshed than
	// actual subscription refresh-timeout. Will be defaulted to 5Seconds.
	RefreshTickerAdjust string `json:"apic-refreshticker-adjust,omitempty"`
	// A path for a PEM-encoded private key for client certificate
	// authentication for APIC API
	PrivateKeyPath string `json:"apic-private-key-path,omitempty"`

	// A path for a PEM-encoded public certificate for APIC server to
	// enable secure TLS server verifification
	CertPath string `json:"apic-cert-path,omitempty"`

	// Cloud Info
	Cloud *kafkac.CloudInfo `json:"cloud-info,omitempty"`

	// kafka config
	Kafka *kafkac.KafkaCfg `json:"kafka,omitempty"`
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
	flag.StringVar(&config.EtcdDir, "etcd-dir", "/var/gbpserver/etcd", "Etcd dir")
	flag.IntVar(&config.EtcdPort, "etcd-port", 12379, "port for internal kv store")
	flag.StringVar(&config.PodSubnet, "pod-subnet", "10.2.56.1/21", "pod subnet")
	flag.StringVar(&config.NodeSubnet, "node-subnet", "1.100.201.0/24", "pod subnet")
	flag.BoolVar(&config.PushJsonFile, "push-json-file", false, "push file to opflexserver (testing)")
	flag.BoolVar(&config.SyncRemEps, "sync-rem-eps", true, "sync remote eps")
}
