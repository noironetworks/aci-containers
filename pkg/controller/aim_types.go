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

// Handlers for AIM ThirdPartyResource updates.  Allows creating
// objects in Kubernetes API that will be automatically synced into an
// APIC controller

package controller

import (
	"encoding/json"
	"sort"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// Most AIM scheme types are generated into aim_schema. go.  To
// install the code generator:
//   go get github.com/a-h/generate
//   go install github.com/a-h/generate/cmd/schema-generate
//go:generate schema-generate -i schema/aim_schema.json  -o aim_schema.go -p controller
//go:generate sed -i -e s/\x20bool\x20/\x20*bool\x20/ aim_schema.go

type Aci struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`

	Spec AciObjectSpec `json:"spec"`
}

type aciSlice []*Aci

func (s aciSlice) Len() int {
	return len(s)
}
func (s aciSlice) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}
func (s aciSlice) Less(i, j int) bool {
	r := strings.Compare(s[i].Spec.Type, s[j].Spec.Type)
	if r != 0 {
		return r < 0
	}
	return strings.Compare(s[i].ObjectMeta.Name, s[j].ObjectMeta.Name) < 0
}

type AciList struct {
	metav1.TypeMeta `json:",inline"`
	Metadata        metav1.ListMeta `json:"metadata"`

	Items []Aci `json:"items"`
}

// Required to satisfy Object interface
func (ao *Aci) GetObjectKind() schema.ObjectKind {
	return &ao.TypeMeta
}

// Required to satisfy ObjectMetaAccessor interface
func (ao *Aci) GetObjectMeta() metav1.Object {
	return &ao.ObjectMeta
}

// Required to satisfy Object interface
func (aol *AciList) GetObjectKind() schema.ObjectKind {
	return &aol.TypeMeta
}

// Required to satisfy ListMetaAccessor interface
func (aol *AciList) GetListMeta() metav1.List {
	return &aol.Metadata
}

// The code below is used only to work around a known problem with third-party
// resources and ugorji. If/when these issues are resolved, the code below
// should no longer be required.

type AciListCopy AciList
type AciCopy Aci

func (ao *Aci) UnmarshalJSON(data []byte) error {
	tmp := AciCopy{}
	err := json.Unmarshal(data, &tmp)
	if err != nil {
		return err
	}
	tmp2 := Aci(tmp)
	*ao = tmp2
	return nil
}

func (ao *AciList) UnmarshalJSON(data []byte) error {
	tmp := AciListCopy{}
	err := json.Unmarshal(data, &tmp)
	if err != nil {
		return err
	}
	tmp2 := AciList(tmp)
	*ao = tmp2
	return nil
}

func NewAciObj(aimType string, namingProps map[string]string) *Aci {
	props := make([]string, 0, len(namingProps)+1)
	propValues := make([]string, 0, len(namingProps)+1)
	labels := make(map[string]string)

	for k, v := range namingProps {
		props = append(props, k)
		labels[k] = aimGenerateLabel(v)
	}
	sort.Strings(props)
	for _, k := range props {
		propValues = append(propValues, namingProps[k])
	}

	ret := &Aci{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: aimNamespace,
			Name:      aimGenerateUniqueName(aimType, propValues...),
			Labels:    labels,
		},
		Spec: AciObjectSpec{
			Type: aimType,
		},
	}
	ret.ObjectMeta.Labels["aim_type"] = aimType
	return ret
}

func NewTenant(name string) *Aci {
	ret := NewAciObj("tenant", map[string]string{"name": name})
	ret.Spec.Tenant = &Tenant{
		Name: name,
	}
	return ret
}

func NewPod(name string) *Aci {
	ret := NewAciObj("pod", map[string]string{"name": name})
	ret.Spec.Pod = &Pod{
		Name: name,
	}
	return ret
}

func NewOpflexDevice(podId string, nodeId string,
	bridgeInterface string, devId string) *Aci {

	ret := NewAciObj("opflex_device",
		map[string]string{
			"pod_id":           podId,
			"node_id":          nodeId,
			"bridge_interface": bridgeInterface,
			"dev_id":           devId,
		})
	ret.Spec.OpflexDevice = &OpflexDevice{
		PodId:           podId,
		NodeId:          nodeId,
		BridgeInterface: bridgeInterface,
		DevId:           devId,
	}
	return ret
}

func NewSecurityGroup(tenantName string, name string) *Aci {
	ret := NewAciObj("security_group", map[string]string{
		"tenant_name": tenantName,
		"name":        name})
	ret.Spec.SecurityGroup = &SecurityGroup{
		TenantName: tenantName,
		Name:       name,
	}
	return ret
}

func NewSecurityGroupSubject(tenantName string, secGroup string,
	name string) *Aci {
	ret := NewAciObj("security_group_subject", map[string]string{
		"tenant_name":         tenantName,
		"security_group_name": secGroup,
		"name":                name})

	ret.Spec.SecurityGroupSubject = &SecurityGroupSubject{
		TenantName:        tenantName,
		SecurityGroupName: secGroup,
		Name:              name,
	}
	return ret
}

func NewSecurityGroupRule(tenantName string, secGroup string,
	secGroupSubj string, name string) *Aci {

	ret := NewAciObj("security_group_rule", map[string]string{
		"tenant_name":                 tenantName,
		"security_group_name":         secGroup,
		"security_group_subject_name": secGroupSubj,
		"name": name})

	ret.Spec.SecurityGroupRule = &SecurityGroupRule{
		TenantName:               tenantName,
		SecurityGroupName:        secGroup,
		SecurityGroupSubjectName: secGroupSubj,
		Name: name,
	}
	return ret
}

func NewDeviceCluster(tenantName string, name string) *Aci {
	ret := NewAciObj("device_cluster", map[string]string{
		"tenant_name": tenantName,
		"name":        name})
	ret.Spec.DeviceCluster = &DeviceCluster{
		TenantName: tenantName,
		Name:       name,
	}
	return ret
}

func NewDeviceClusterContext(tenantName string, contractName string,
	serviceGraphName string, nodeName string) *Aci {

	ret := NewAciObj("device_cluster_context", map[string]string{
		"tenant_name":        tenantName,
		"contract_name":      contractName,
		"service_graph_name": serviceGraphName,
		"node_name":          nodeName})
	ret.Spec.DeviceClusterContext = &DeviceClusterContext{
		TenantName:       tenantName,
		ContractName:     contractName,
		ServiceGraphName: serviceGraphName,
		NodeName:         nodeName,
	}
	return ret
}

func NewServiceGraph(tenantName string, name string) *Aci {
	ret := NewAciObj("service_graph", map[string]string{
		"tenant_name": tenantName,
		"name":        name})
	ret.Spec.ServiceGraph = &ServiceGraph{
		TenantName: tenantName,
		Name:       name,
	}
	return ret
}

func NewServiceRedirectPolicy(tenantName string, name string) *Aci {
	ret := NewAciObj("service_redirect_policy", map[string]string{
		"tenant_name": tenantName,
		"name":        name})
	ret.Spec.ServiceRedirectPolicy = &ServiceRedirectPolicy{
		TenantName: tenantName,
		Name:       name,
	}
	return ret
}

func NewContract(tenantName string, name string) *Aci {
	ret := NewAciObj("contract", map[string]string{
		"tenant_name": tenantName,
		"name":        name})
	ret.Spec.Contract = &Contract{
		TenantName: tenantName,
		Name:       name,
	}
	return ret
}

func NewContractSubject(tenantName string, contractName string,
	name string) *Aci {

	ret := NewAciObj("contract_subject", map[string]string{
		"tenant_name":   tenantName,
		"contract_name": contractName,
		"name":          name})
	ret.Spec.ContractSubject = &ContractSubject{
		TenantName:   tenantName,
		ContractName: contractName,
		Name:         name,
	}
	return ret
}

func NewFilter(tenantName string, name string) *Aci {
	ret := NewAciObj("filter", map[string]string{
		"tenant_name": tenantName,
		"name":        name})
	ret.Spec.Filter = &Filter{
		TenantName: tenantName,
		Name:       name,
	}
	return ret
}

func NewFilterEntry(tenantName string, filterName string, name string) *Aci {
	ret := NewAciObj("filter_entry", map[string]string{
		"tenant_name": tenantName,
		"filter_name": filterName,
		"name":        name})
	ret.Spec.FilterEntry = &FilterEntry{
		TenantName: tenantName,
		FilterName: filterName,
		Name:       name,
	}
	return ret
}

func NewExternalNetwork(tenantName string, l3outName string, name string) *Aci {
	ret := NewAciObj("external_network", map[string]string{
		"tenant_name": tenantName,
		"l3out_name":  l3outName,
		"name":        name})
	ret.Spec.ExternalNetwork = &ExternalNetwork{
		TenantName: tenantName,
		L3outName:  l3outName,
		Name:       name,
	}
	return ret
}

func NewExternalSubnet(tenantName string, l3outName string,
	externalNetworkName string, cidr string) *Aci {

	ret := NewAciObj("external_subnet", map[string]string{
		"tenant_name":           tenantName,
		"l3out_name":            l3outName,
		"external_network_name": externalNetworkName,
		"cidr":                  cidr})
	ret.Spec.ExternalSubnet = &ExternalSubnet{
		TenantName:          tenantName,
		L3outName:           l3outName,
		ExternalNetworkName: externalNetworkName,
		Cidr:                cidr,
	}
	return ret
}

func NewBridgeDomain(tenantName string, name string) *Aci {
	ret := NewAciObj("bridge_domain", map[string]string{
		"tenant_name": tenantName,
		"name":        name})
	ret.Spec.BridgeDomain = &BridgeDomain{
		TenantName: tenantName,
		Name:       name,
	}
	return ret
}

func NewSubnet(tenantName string, bdName string, gwIpMask string) *Aci {
	ret := NewAciObj("subnet", map[string]string{
		"tenant_name": tenantName,
		"bd_name":     bdName,
		"gw_ip_mask":  gwIpMask,
	})
	ret.Spec.Subnet = &Subnet{
		TenantName: tenantName,
		BdName:     bdName,
		GwIpMask:   gwIpMask,
	}
	return ret
}
