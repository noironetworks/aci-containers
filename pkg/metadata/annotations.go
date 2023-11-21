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

package metadata

import (
	"net"

	"github.com/noironetworks/aci-containers/pkg/ipam"
)

// An opflex security or endpoint group
// Tenant is an alias for policy space and will override policyspace
// If AppProfile is not set the Name is interpreted as AppProfile|Name
type OpflexGroup struct {
	Tenant      string `json:"tenant,omitempty"`
	PolicySpace string `json:"policy-space,omitempty"`
	AppProfile  string `json:"app-profile,omitempty"`
	Name        string `json:"name,omitempty"`
}

// annotation type for service endpoint information
type ServiceEndpoint struct {
	HealthGroupDn string `json:"-"`
	Mac           string `json:"mac,omitempty"`
	Ipv4          net.IP `json:"ipv4,omitempty"`
	Ipv6          net.IP `json:"ipv6,omitempty"`
}

// annotation type for IPs allocation chunks
type NetIps struct {
	V4 []ipam.IpRange `json:"V4,omitempty"`
	V6 []ipam.IpRange `json:"V6,omitempty"`
}

// Custom service graph annotation
const ServiceGraphNameAnnotation = "opflex.cisco.com/service-graph-name"

// Service endpoint annotation
const ServiceEpAnnotation = "opflex.cisco.com/service-endpoint"

// Static lb ip annotations
const LbIpAnnotation = "opflex.cisco.com/lb-ipam-ips"

// Annotation to set service contract scope values. If unset or "", defaults to "context"(VRF). Other valid values: "context", "tenant", and "global"
const ServiceContractScopeAnnotation = "opflex.cisco.com/ext_service_contract_scope"

// List of IP address ranges for use by the pod network
const PodNetworkRangeAnnotation = "opflex.cisco.com/pod-network-ranges"

const AciPodAnnotation = "opflex.cisco.com/aci-pod"
const NodeAciPodAnnotation = "opflex.cisco.com/node-aci-pod"

// Annotation for endpoint group designation for pod, deployment, etc.
const EgAnnotation = "opflex.cisco.com/endpoint-group"

// Annotation for security group designation for pod, deployment, etc.
const SgAnnotation = "opflex.cisco.com/security-group"

// Annotation for qospolicy group designation for pod,deployment, etc.
const QpAnnotation = "opflex.cisco.com/qospolicy"

// Computed endpoint group for pod
const CompEgAnnotation = "opflex.cisco.com/computed-endpoint-group"

// Computed security groups for pod
const CompSgAnnotation = "opflex.cisco.com/computed-security-group"

// Network attachment definition annotation for pod
const NetAttDefAnnotation = "k8s.v1.cni.cncf.io/networks"

// Network attachment definition annotation for pod requesting multus-cni
const MultusNetAnnotation = "v1.multus-cni.io/default-network"
