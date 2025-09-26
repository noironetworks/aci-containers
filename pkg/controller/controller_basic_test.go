// Copyright 2025 Cisco Systems, Inc.
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
	"net"
	"testing"
)

func TestCreateQueue(t *testing.T) {
	queue := createQueue("test-queue")

	if queue == nil {
		t.Error("Expected createQueue to return a non-nil queue")
	}

	// Test that we can add items to the queue
	queue.Add("test-item")
	if queue.Len() != 1 {
		t.Errorf("Expected queue length 1, got %d", queue.Len())
	}

	// Test that we can get items from the queue
	item, shutdown := queue.Get()
	if shutdown {
		t.Error("Expected queue not to be shut down")
	}
	if item != "test-item" {
		t.Errorf("Expected item 'test-item', got %v", item)
	}

	queue.Done(item)
	queue.ShutDown()
}

func TestIpIndexEntryNetwork(t *testing.T) {
	tests := []struct {
		name     string
		ipNet    net.IPNet
		expected string
	}{
		{
			name: "IPv4 network",
			ipNet: net.IPNet{
				IP:   net.ParseIP("192.168.1.10"),
				Mask: net.CIDRMask(24, 32),
			},
			expected: "192.168.1.10/24",
		},
		{
			name: "IPv4 network with /16 mask",
			ipNet: net.IPNet{
				IP:   net.ParseIP("10.0.5.100"),
				Mask: net.CIDRMask(16, 32),
			},
			expected: "10.0.5.100/16",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := &ipIndexEntry{
				ipNet: tt.ipNet,
				keys:  make(map[string]bool),
			}

			network := entry.Network()
			if network.String() != tt.expected {
				t.Errorf("Expected network %s, got %s", tt.expected, network.String())
			}
		})
	}
}

func TestNewNodePodNetMeta(t *testing.T) {
	// Test the newNodePodNetMeta function
	meta := newNodePodNetMeta()

	if meta == nil {
		t.Error("Expected newNodePodNetMeta to return a non-nil value")
	}

	if meta.podNetIps.V4 == nil {
		t.Error("Expected V4 IP range to be initialized")
	}

	if meta.podNetIps.V6 == nil {
		t.Error("Expected V6 IP range to be initialized")
	}
}

func TestAciControllerInit(t *testing.T) {
	cont := testController()
	cont.stopCh = make(chan struct{})
	defer cont.stop()

	// Test that basic controller components are initialized
	if cont.podQueue == nil {
		t.Error("Expected podQueue to be initialized")
	}

	if cont.serviceQueue == nil {
		t.Error("Expected serviceQueue to be initialized")
	}

	if cont.netPolQueue == nil {
		t.Error("Expected netPolQueue to be initialized")
	}

	// Test that indexMutex is initialized (it's a value type, so we can't check nil)
	// Instead, we can test that we can use it
	cont.indexMutex.Lock()
	cont.indexMutex.Unlock()
}
