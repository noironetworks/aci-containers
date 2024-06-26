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

// NADFabricL3PeerApplyConfiguration represents an declarative configuration of the NADFabricL3Peer type for use
// with apply.
type NADFabricL3PeerApplyConfiguration struct {
	NAD   *ObjRefApplyConfiguration            `json:"nad,omitempty"`
	Nodes []NodeFabricL3PeerApplyConfiguration `json:"nodes,omitempty"`
}

// NADFabricL3PeerApplyConfiguration constructs an declarative configuration of the NADFabricL3Peer type for use with
// apply.
func NADFabricL3Peer() *NADFabricL3PeerApplyConfiguration {
	return &NADFabricL3PeerApplyConfiguration{}
}

// WithNAD sets the NAD field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the NAD field is set to the value of the last call.
func (b *NADFabricL3PeerApplyConfiguration) WithNAD(value *ObjRefApplyConfiguration) *NADFabricL3PeerApplyConfiguration {
	b.NAD = value
	return b
}

// WithNodes adds the given value to the Nodes field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the Nodes field.
func (b *NADFabricL3PeerApplyConfiguration) WithNodes(values ...*NodeFabricL3PeerApplyConfiguration) *NADFabricL3PeerApplyConfiguration {
	for i := range values {
		if values[i] == nil {
			panic("nil value passed to WithNodes")
		}
		b.Nodes = append(b.Nodes, *values[i])
	}
	return b
}
