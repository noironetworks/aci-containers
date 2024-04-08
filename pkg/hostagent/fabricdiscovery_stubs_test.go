// Copyright 2023 Cisco Systems, Inc.
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

package hostagent

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewFabricDiscoveryAgentLLDPRawSocket(t *testing.T) {
	fda := NewFabricDiscoveryAgentLLDPRawSocket()

	assert.NotNil(t, fda)
	assert.IsType(t, &FabricDiscoveryAgentLLDPRawSocket{}, fda)
}

func TestFabricDiscoveryAgentLLDPRawSocket_Init(t *testing.T) {
	agent := &FabricDiscoveryAgentLLDPRawSocket{}
	ha := &HostAgent{}

	err := agent.Init(ha)

	assert.NoError(t, err)
}

func TestFabricDiscoveryAgentLLDPRawSocket_CollectDiscoveryData(t *testing.T) {
	agent := &FabricDiscoveryAgentLLDPRawSocket{}
	stopChain := make(chan struct{})

	agent.CollectDiscoveryData(stopChain)

	close(stopChain)
}

func TestFabricDiscoveryAgentLLDPRawSocket_TriggerCollectionDiscoveryData(t *testing.T) {
	agent := &FabricDiscoveryAgentLLDPRawSocket{}

	agent.TriggerCollectionDiscoveryData()
}

func TestFabricDiscoveryAgentLLDPRawSocket_GetNeighborData(t *testing.T) {
	agent := &FabricDiscoveryAgentLLDPRawSocket{}
	iface := "eth0"

	data, err := agent.GetNeighborData(iface)

	assert.Nil(t, data)
	assert.EqualError(t, err, fmt.Sprintf("LLDP Neighbor Data is not available yet for %s", iface))
}
func TestFabricDiscoveryAgentLLDPRawSocket_PopulateAdjacencies(t *testing.T) {
	agent := &FabricDiscoveryAgentLLDPRawSocket{}
	adjs := make(map[string][]FabricAttachmentData)

	agent.PopulateAdjacencies(adjs)
}
