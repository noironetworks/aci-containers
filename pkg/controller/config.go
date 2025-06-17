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

package controller

import (
	"flag"

	"github.com/noironetworks/aci-containers/pkg/ipam"
)

type OpflexGroup struct {
	PolicySpace string `json:"policy-space,omitempty"`
	Name        string `json:"name,omitempty"`
}

type delayService struct {
	Delay     int    `json:"delay,omitempty"`
	Name      string `json:"name,omitempty"`
	Namespace string `json:"namespace,omitempty"`
}

type serviceGraphEpAddDelay struct {
	Delay    int            `json:"delay,omitempty"`
	Services []delayService `json:"services,omitempty"`
}

type NodeSnatRedirectExclude struct {
	Group  string   `json:"group"`
	Labels []string `json:"labels"`
}

// Configuration for the controller
type ControllerConfig struct {
	// Log level
	LogLevel string `json:"log-level,omitempty"`

	// Absolute path to a kubeconfig file
	KubeConfig string `json:"kubeconfig,omitempty"`

	// TCP port to run status server on (or 0 to disable)
	StatusPort int `json:"status-port,omitempty"`

	// Default endpoint group annotation value
	DefaultEg OpflexGroup `json:"default-endpoint-group,omitempty"`

	// Default security group annotation value
	DefaultSg []OpflexGroup `json:"default-security-group,omitempty"`

	// Override default endpoint group assignments for a namespace
	// map ns name -> group
	NamespaceDefaultEg map[string]OpflexGroup `json:"namespace-default-endpoint-group,omitempty"`

	// Override default security group assignments for namespaces
	// map ns name -> slice of groups
	NamespaceDefaultSg map[string][]OpflexGroup `json:"namespace-default-security-group,omitempty"`

	// The hostnames or IPs for connecting to apic
	ApicHosts []string `json:"apic-hosts,omitempty"`

	// The username for connecting to APIC
	ApicUsername string `json:"apic-username,omitempty"`

	// The password for connecting to APIC
	ApicPassword string `json:"apic-password,omitempty"`

	// The number of seconds that APIC should wait before timing
	// out a subscription on a websocket connection. If not
	// explicitly set, then a default of 1800 seconds will
	// be sent in websocket subscriptions. If it is set to 0,
	// then a timeout will not be sent in websocket
	// subscriptions, and APIC will use it's default timeout
	// of 80 seconds. If set to a non-zero value, then the
	// timeout value will be provided when we subscribe to
	// a URL on APIC. NOTE: the subscription timeout is not
	// supported by APIC versions before 3.2(3), so this
	// value must not be set when used with APIC versions
	// older than that release.
	// Also, note that this is a string.
	ApicRefreshTimer string `json:"apic-refreshtime,omitempty"`

	// Delay in milliseconds after each subscription query
	// Will be defaulted to 100ms.
	ApicSubscriptionDelay int `json:"apic-subscription-delay,omitempty"`

	// How early (seconds) the subscriptions to be refreshed than
	// actual subscription refresh-timeout. Will be defaulted to 150Seconds.
	ApicRefreshTickerAdjust string `json:"apic-refreshticker-adjust,omitempty"`

	// A path for a PEM-encoded private key for client certificate
	// authentication for APIC API
	ApicPrivateKeyPath string `json:"apic-private-key-path,omitempty"`

	// A path for a PEM-encoded public certificate for APIC server to
	// enable secure TLS server verifification
	ApicCertPath string `json:"apic-cert-path,omitempty"`

	// The type of the ACI VMM domain: either "kubernetes",
	// "openshift"
	AciVmmDomainType string `json:"aci-vmm-type,omitempty"`

	// The name of the ACI VMM domain
	AciVmmDomain string `json:"aci-vmm-domain,omitempty"`

	// The name of the ACI VMM domain controller instance
	AciVmmController string `json:"aci-vmm-controller,omitempty"`

	// Name prefix to use when creating policy to avoid namespace
	// collisions
	AciPrefix string `json:"aci-prefix,omitempty"`

	// Tenant to use when creating policy objects in APIC
	AciPolicyTenant string `json:"aci-policy-tenant,omitempty"`

	// Physical domain used for service device clusters
	AciServicePhysDom string `json:"aci-service-phys-dom,omitempty"`

	// Encap used for service device clusters
	AciServiceEncap string `json:"aci-service-encap,omitempty"`

	// Time in seconds between service node ICMP probes for more
	// quickly removing failed nodes from service pools
	// 0 (default) means don't monitor
	AciServiceMonitorInterval int `json:"aci-service-monitor-interval,omitempty"`

	// Whether to enable PBR tracking for non-SNAT services
	// when AciServiceMonitorInterval is set to non-zero, PBR tracking
	// is enabled for snat
	AciPbrTrackingNonSnat bool `json:"aci-pbr-tracking-non-snat,omitempty"`

	// By default, the Resilient Hashing Enabled field of vnsSvcRedirectPol is
	// set to "yes". If DisableResilientHashing is true, it will be set to "no"
	DisableResilientHashing bool `json:"disable-resilient-hashing,omitempty"`

	// To ignore the opflexODev which belongs to different vmmDomain
	FilterOpflexDevice bool `json:"filter-opflex-device,omitempty"`

	// The tenants related to AciVrf where BDs/EPGs/Subnets could exist.
	// Usually AciVrfTenant and AciPolicyTenant
	AciVrfRelatedTenants []string `json:"aci-vrf-related-tenants,omitempty"`

	// ACI Pod-BD for this kubernetes instance
	AciPodBdDn string `json:"aci-podbd-dn,omitempty"`

	// ACI Node-BD for this kubernetes instance
	AciNodeBdDn string `json:"aci-nodebd-dn,omitempty"`

	// ACI VRF for this kubernetes instance
	AciVrf string `json:"aci-vrf,omitempty"`

	// ACI VRF for this kubernetes instance
	AciVrfDn string `json:"aci-vrf-dn,omitempty"`

	// Tenant containing the ACI VRF for this kubernetes instance
	AciVrfTenant string `json:"aci-vrf-tenant,omitempty"`

	// L3 out to use for services, service device clusters need to be
	// created in this tenant
	AciL3Out string `json:"aci-l3out,omitempty"`

	// L3 external networks (within the l3out) that will be able to
	// access the service IPs
	AciExtNetworks []string `json:"aci-ext-networks,omitempty"`

	// IP addresses used for pod network
	PodIpPool []ipam.IpRange `json:"pod-ip-pool,omitempty"`

	// The number of IP addresses to allocate when a pod starts to run low
	PodIpPoolChunkSize int `json:"pod-subnet-chunk-size,omitempty"`

	// Pod subnet CIDRs in the form <gateway-address>/<prefix-length> that
	// cover all pod-ip-pools
	PodSubnet []string `json:"pod-subnet,omitempty"`

	// Whether to allocate service IPs or to assume they will be
	// allocated by another controller
	AllocateServiceIps *bool `json:"allocate-service-ips,omitempty"`

	// IP addresses used for externally exposed load balanced services
	ServiceIpPool []ipam.IpRange `json:"service-ip-pool,omitempty"`

	// IP addresses that can be requested as static service IPs in
	// service spec
	StaticServiceIpPool []ipam.IpRange `json:"static-service-ip-pool,omitempty"`

	// IP addresses to use for node service endpoints
	NodeServiceIpPool []ipam.IpRange `json:"node-service-ip-pool,omitempty"`

	// a list of subnet/gateway CIDR addresses that cover the
	// addresses in the node service IP pool
	NodeServiceSubnets []string `json:"node-service-subnets,omitempty"`

	// default port range to use for SNAT svc graph filter
	SnatDefaultPortRangeStart int `json:"snat-default-port-range-start,omitempty"`
	SnatDefaultPortRangeEnd   int `json:"snat-default-port-range-end,omitempty"`

	// Contract scope used for SNAT svc graph
	SnatSvcContractScope string `json:"snat-contract-scope,omitempty"`

	// Maximum number of nodes permitted in a svc graph
	MaxSvcGraphNodes int `json:"max-nodes-svc-graph,omitempty"`

	// Disable routine to sync snatglobalinfo with nodeinfo
	// periodically
	DisablePeriodicSnatGlobalInfoSync bool `json:"disable-periodic-snat-global-info-sync,omitempty"`

	// True when we dont want to wait for service ep to be ready
	// before adding it to service graph
	// Default is false
	NoWaitForServiceEpReadiness bool `json:"no-wait-for-service-ep-readiness,omitempty"`

	ServiceGraphEndpointAddDelay serviceGraphEpAddDelay `json:"service-graph-endpoint-add-delay,omitempty"`
	// True when to add extern_dynamic and extern_static subnets to rdconfig
	// Default is false
	AddExternalSubnetsToRdconfig bool `json:"add-external-subnets-to-rdconfig,omitempty"`

	ExternStatic []string `json:"extern-static,omitempty"`

	ExternDynamic []string `json:"extern-dynamic,omitempty"`

	// Default is false
	HppOptimization bool `json:"hpp-optimization,omitempty"`

	// Default is false
	AciMultipod bool `json:"aci-multipod,omitempty"`

	// If true, enable opflex agent reconnect after vm migration
	// Default is false
	EnableOpflexAgentReconnect bool `json:"enable-opflex-agent-reconnect,omitempty"`

	// Timeout in seconds to wait for reconnect when opflexOdev is diconnected for a node
	// before triggering a dhcp release and renew of vlan interface
	// Applicable only for multipod case
	// default is 5s
	OpflexDeviceReconnectWaitTimeout int `json:"opflex-device-reconnect-wait-timeout,omitempty"`

	// Install Istio ControlPlane components
	InstallIstio bool `json:"install-istio,omitempty"`

	// enable EndpointSlice
	EnabledEndpointSlice bool `json:"enable_endpointslice,omitempty"`

	// Cluster Flavour
	Flavor string `json:"flavor,omitempty"`

	// Enable creation of VmmInjectedLabel, default is false
	EnableVmmInjectedLabels bool `json:"enable-vmm-injected-labels,omitempty"`

	// Timeout to delete old opflex devices
	OpflexDeviceDeleteTimeout float64 `json:"opflex-device-delete-timeout,omitempty"`

	// Configure sleep time for global SNAT sync
	SleepTimeSnatGlobalInfoSync int `json:"sleep-time-snat-global-info-sync,omitempty"`

	// Configure unkMacUcastAct attribute of service BD
	// The forwarding method for unknown layer 2 destinations
	UnknownMacUnicastAction string `json:"unknown-mac-unicast-action,omitempty"`

	// To disable service vlan preprovisioning on OpenShift on OpenStack Clusters
	// By default the feature will be enabled
	DisableServiceVlanPreprovisioning bool `json:"disable-service-vlan-preprovisioning"`

	// PhysDom for additional networks in chained mode
	AciPhysDom string `json:"aci-phys-dom,omitempty"`

	// L3Dom for additional networks in chained mode
	AciL3Dom string `json:"aci-l3-dom,omitempty"`

	// CNI is in chained mode
	ChainedMode bool `json:"chained-mode,omitempty"`

	// AEP for additional networks in chained mode
	AciAdditionalAep string `json:"aci-additional-aep,omitempty"`

	//User can provision Static Objects separately, so have a knob
	ReconcileStaticObjects bool `json:"reconcileStaticObjects,omitempty"`

	//In chained mode, global l2 port policy has been configured, so enable shared vlan pool
	AciUseGlobalScopeVlan bool `json:"aci-use-global-scope-vlan,omitempty"`

	//In chained mode, use system-id for auto-generated names
	AciUseSystemIdForSecondaryNames bool `aci-use-system-id-for-secondary-names,omitempty"`

	// Metrics
	EnableMetrics bool `json:"enable-metrics,omitempty"`
	MetricsPort   int  `json:"metrics-port,omitempty"`

	// Labels to filter nodes from SNAT redirect policy
	NodeSnatRedirectExclude []NodeSnatRedirectExclude `json:"node-snat-redirect-exclude,omitempty"`

	AEP string `json:"aep,omitempty"`
	// Application Profile
	AppProfile string `json:"app-profile,omitempty"`

	// Add external contract to default epg (contract is created for LoadBalancer Service type), default is false
	AddExternalContractToDefaultEPG bool `json:"add-external-contract-to-default-epg,omitempty"`

	// Number of times the connection to APIC should be retried before switching to another APIC
	ApicConnectionRetryLimit int `json:"apic-connection-retry-limit,omitempty"`

	// Timeout in minutes to wait in between retries before sending request to APIC
	ApicRequestRetryDelay int `json:"apic-request-retry-delay,omitempty"`

	// Enable retying request to APIC when a 503 error is encountered
	EnableApicRequestRetry bool `json:"enable-apic-request-retry-delay,omitempty"`

	// Disable hpp rendering if set to true
	DisableHppRendering bool `json:"disable-hpp-rendering,omitempty"`

	// Enable/disable making node unschedulable when it's not ready
	TaintNotReadyNode bool `json:"taint-not-ready-node,omitempty"`

	// Enable/disable local hpp distribution
	EnableHppDirect bool `json:"enable-hpp-direct,omitempty"`

	// Enable/disable proactive conf
	ProactiveConf bool `json:"proactive-conf,omitempty"`
}

type netIps struct {
	V4 *ipam.IpAlloc
	V6 *ipam.IpAlloc
}

func newNetIps() *netIps {
	return &netIps{
		V4: ipam.New(),
		V6: ipam.New(),
	}
}

func NewConfig() *ControllerConfig {
	t := true
	return &ControllerConfig{
		DefaultSg:          make([]OpflexGroup, 0),
		NamespaceDefaultEg: make(map[string]OpflexGroup),
		NamespaceDefaultSg: make(map[string][]OpflexGroup),
		AciVmmDomainType:   "Kubernetes",
		AciPolicyTenant:    "kubernetes",
		AciPrefix:          "kube",
		AllocateServiceIps: &t,
	}
}

func InitFlags(config *ControllerConfig) {
	flag.StringVar(&config.LogLevel, "log-level", "info", "Log level")

	flag.StringVar(&config.KubeConfig, "kube-config", "", "Absolute path to a kubeconfig file")

	flag.IntVar(&config.StatusPort, "status-port", 8091, " TCP port to run status server on (or 0 to disable)")
	flag.BoolVar(&config.EnableVmmInjectedLabels, "enable-vmm-injected-labels", false, "Enable creation of VmmInjectedLabel")
	flag.StringVar(&config.UnknownMacUnicastAction, "unkown-mac-unicast-action", "proxy", "Set the forwarding method for unknown mac for service BD")
	flag.BoolVar(&config.ChainedMode, "chained-mode", false, "CNI is in chained mode")
	flag.BoolVar(&config.ReconcileStaticObjects, "reconcile-static-objects", false, "controller will reconcile implicit static objects")
	flag.BoolVar(&config.AciUseGlobalScopeVlan, "aci-use-global-scope-vlan", false, "Use global vlans for NADs in chained mode")
	flag.BoolVar(&config.AciUseSystemIdForSecondaryNames, "aci-use-system-id-for-secondary-names", false, "Use system id for auto-generated names in chained mode")
	flag.BoolVar(&config.EnableMetrics, "enable-metrics", false, "Enable metrics")
	flag.IntVar(&config.MetricsPort, "metrics-port", 8191, "Port to expose metrics on")
}

func (cont *AciController) loadIpRanges(v4, v6 *ipam.IpAlloc, ipranges []ipam.IpRange) {
	for _, r := range ipranges {
		if r.Start.To4() != nil && r.End.To4() != nil {
			v4.AddRange(r.Start, r.End)
		} else if r.Start.To16() != nil && r.End.To16() != nil {
			v6.AddRange(r.Start, r.End)
		} else {
			cont.log.Warn("Range invalid: ", r)
		}
	}
}

func (cont *AciController) initIpam() {
	cont.loadIpRanges(cont.configuredPodNetworkIps.V4, cont.configuredPodNetworkIps.V6,
		cont.config.PodIpPool)
	cont.podNetworkIps.V4.AddAll(cont.configuredPodNetworkIps.V4)
	cont.podNetworkIps.V6.AddAll(cont.configuredPodNetworkIps.V6)
	cont.serviceIps.LoadRanges(cont.config.ServiceIpPool)
	cont.loadIpRanges(cont.staticServiceIps.V4, cont.staticServiceIps.V6,
		cont.config.StaticServiceIpPool)
	cont.loadIpRanges(cont.nodeServiceIps.V4, cont.nodeServiceIps.V6,
		cont.config.NodeServiceIpPool)
}
