/***
Copyright 2021 Cisco Systems Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Code generated by applyconfiguration-gen. DO NOT EDIT.

package v1

// FabricTenantConfigurationApplyConfiguration represents an declarative configuration of the FabricTenantConfiguration type for use
// with apply.
type FabricTenantConfigurationApplyConfiguration struct {
	CommonTenant          *bool                                   `json:"commonTenant,omitempty"`
	L3OutInstances        []FabricL3OutApplyConfiguration         `json:"l3OutInstances,omitempty"`
	BGPPeerPrefixPolicies []BGPPeerPrefixPolicyApplyConfiguration `json:"bgpInstances,omitempty"`
}

// FabricTenantConfigurationApplyConfiguration constructs an declarative configuration of the FabricTenantConfiguration type for use with
// apply.
func FabricTenantConfiguration() *FabricTenantConfigurationApplyConfiguration {
	return &FabricTenantConfigurationApplyConfiguration{}
}

// WithCommonTenant sets the CommonTenant field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the CommonTenant field is set to the value of the last call.
func (b *FabricTenantConfigurationApplyConfiguration) WithCommonTenant(value bool) *FabricTenantConfigurationApplyConfiguration {
	b.CommonTenant = &value
	return b
}

// WithL3OutInstances adds the given value to the L3OutInstances field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the L3OutInstances field.
func (b *FabricTenantConfigurationApplyConfiguration) WithL3OutInstances(values ...*FabricL3OutApplyConfiguration) *FabricTenantConfigurationApplyConfiguration {
	for i := range values {
		if values[i] == nil {
			panic("nil value passed to WithL3OutInstances")
		}
		b.L3OutInstances = append(b.L3OutInstances, *values[i])
	}
	return b
}

// WithBGPPeerPrefixPolicies adds the given value to the BGPPeerPrefixPolicies field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the BGPPeerPrefixPolicies field.
func (b *FabricTenantConfigurationApplyConfiguration) WithBGPPeerPrefixPolicies(values ...*BGPPeerPrefixPolicyApplyConfiguration) *FabricTenantConfigurationApplyConfiguration {
	for i := range values {
		if values[i] == nil {
			panic("nil value passed to WithBGPPeerPrefixPolicies")
		}
		b.BGPPeerPrefixPolicies = append(b.BGPPeerPrefixPolicies, *values[i])
	}
	return b
}
