// Copyright 2023 Cisco Systems, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package hostagent

import (
	"testing"
	"time"
)

func TestFabricDiscoveryCollectDiscoveryData(t *testing.T) {
	ha := testAgent()
	ha.run()
	defer ha.stop()

	mockCollector := &MockFabricDiscoveryCollector{}
	ha.fabricDiscoveryRegistry = make(map[int]FabricDiscoveryAgent)
	ha.fabricDiscoveryRegistry[0] = mockCollector
	ha.fabricDiscoveryRegistry[1] = mockCollector

	ha.FabricDiscoveryTriggerCollectionDiscoveryData()

	time.Sleep(100 * time.Millisecond)

	if !mockCollector.CollectDiscoveryDataCalled {
		t.Error("Expected CollectDiscoveryData to be called")
	}

}

type MockFabricDiscoveryCollector struct {
	CollectDiscoveryDataCalled bool
}

func (m *MockFabricDiscoveryCollector) GetNeighborData(iface string) ([]*FabricAttachmentData, error) {
	panic("unimplemented")
}

func (m *MockFabricDiscoveryCollector) Init(agent *HostAgent) error {
	panic("unimplemented")
}

func (m *MockFabricDiscoveryCollector) PopulateAdjacencies(adjs map[string][]FabricAttachmentData) {
	panic("unimplemented")
}

func (m *MockFabricDiscoveryCollector) TriggerCollectionDiscoveryData() {
	m.CollectDiscoveryData(make(<-chan struct{}))
}

func (m *MockFabricDiscoveryCollector) CollectDiscoveryData(stopCh <-chan struct{}) {
	m.CollectDiscoveryDataCalled = true
}
