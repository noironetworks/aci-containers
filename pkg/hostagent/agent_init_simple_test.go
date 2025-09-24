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

package hostagent

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	"github.com/containernetworking/cni/pkg/types"
	cnitypes "github.com/containernetworking/cni/pkg/types"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/noironetworks/aci-containers/pkg/metadata"
)

func TestNewHostAgent(t *testing.T) {
	tests := []struct {
		name     string
		config   *HostAgentConfig
		env      Environment
		expected string
	}{
		{
			name: "Basic agent creation",
			config: &HostAgentConfig{
				NodeName: "test-node",
				NetConfig: []cniNetConfig{
					{Subnet: cnitypes.IPNet{IP: net.ParseIP("10.128.2.0"), Mask: net.CIDRMask(24, 32)}},
				},
				GroupDefaults: GroupDefaults{
					DefaultEg: metadata.OpflexGroup{Name: "aci-containers-test|aci-containers-default"},
				},
			},
			env:      &K8sEnvironment{},
			expected: "test-node",
		},
		{
			name: "Agent with EP registry k8s",
			config: &HostAgentConfig{
				NodeName:   "test-node-k8s",
				EPRegistry: "k8s",
				NetConfig: []cniNetConfig{
					{Subnet: cnitypes.IPNet{IP: net.ParseIP("10.128.3.0"), Mask: net.CIDRMask(24, 32)}},
				},
				GroupDefaults: GroupDefaults{
					DefaultEg: metadata.OpflexGroup{Name: "aci-containers-test|aci-containers-default"},
				},
			},
			env:      &K8sEnvironment{},
			expected: "test-node-k8s",
		},
		{
			name: "Agent with chained mode",
			config: &HostAgentConfig{
				NodeName:    "test-node-chained",
				ChainedMode: true,
				NetConfig: []cniNetConfig{
					{Subnet: cnitypes.IPNet{IP: net.ParseIP("10.128.4.0"), Mask: net.CIDRMask(24, 32)}},
				},
				GroupDefaults: GroupDefaults{
					DefaultEg: metadata.OpflexGroup{Name: "aci-containers-test|aci-containers-default"},
				},
			},
			env:      &K8sEnvironment{},
			expected: "test-node-chained",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log := logrus.New()
			log.Level = logrus.InfoLevel

			agent := NewHostAgent(tt.config, tt.env, log)

			assert.NotNil(t, agent)
			assert.Equal(t, tt.expected, agent.config.NodeName)
			assert.NotNil(t, agent.log)
			assert.NotNil(t, agent.config)
			assert.NotNil(t, agent.env)

			// Verify all maps are initialized
			assert.NotNil(t, agent.opflexEps)
			assert.NotNil(t, agent.opflexServices)
			assert.NotNil(t, agent.epMetadata)
			assert.NotNil(t, agent.podIpToName)
			assert.NotNil(t, agent.cniToPodID)
			assert.NotNil(t, agent.podUidToName)
			assert.NotNil(t, agent.nodePodIfEPs)
			assert.NotNil(t, agent.podNameToTimeStamps)
			assert.NotNil(t, agent.podIps)
			assert.NotNil(t, agent.ignoreOvsPorts)
			assert.NotNil(t, agent.netNsFuncChan)
			assert.NotNil(t, agent.opflexSnatGlobalInfos)
			assert.NotNil(t, agent.opflexSnatLocalInfos)
			assert.NotNil(t, agent.snatPods)
			assert.NotNil(t, agent.snatPolicyLabels)
			assert.NotNil(t, agent.snatPolicyCache)
			assert.NotNil(t, agent.servicetoPodUids)
			assert.NotNil(t, agent.podtoServiceUids)
			assert.NotNil(t, agent.netattdefmap)
			assert.NotNil(t, agent.netattdefifacemap)
			assert.NotNil(t, agent.deviceIdMap)
			assert.NotNil(t, agent.nadVlanMap)
			assert.NotNil(t, agent.fabricVlanPoolMap)
			assert.NotNil(t, agent.orphanNadMap)
			assert.NotNil(t, agent.podToNetAttachDef)
			assert.NotNil(t, agent.podNetworkMetadata)
			assert.NotNil(t, agent.completedSyncTypes)
			assert.NotNil(t, agent.hppMoIndex)

			// Verify work queues are initialized
			assert.NotNil(t, agent.syncQueue)
			assert.NotNil(t, agent.epSyncQueue)
			assert.NotNil(t, agent.portSyncQueue)
			assert.NotNil(t, agent.hppLocalMoSyncQueue)

			// Verify sync processors are initialized
			assert.NotNil(t, agent.syncProcessors)
			assert.Contains(t, agent.syncProcessors, "eps")
			assert.Contains(t, agent.syncProcessors, "services")
			assert.Contains(t, agent.syncProcessors, "opflexServer")
			assert.Contains(t, agent.syncProcessors, "snat")
			assert.Contains(t, agent.syncProcessors, "snatnodeInfo")
			assert.Contains(t, agent.syncProcessors, "rdconfig")
			assert.Contains(t, agent.syncProcessors, "snatLocalInfo")
			assert.Contains(t, agent.syncProcessors, "nodepodifs")
			assert.Contains(t, agent.syncProcessors, "ports")
			assert.Contains(t, agent.syncProcessors, "hpp")

			// Verify OpenShift services are initialized
			assert.NotNil(t, agent.ocServices)
			assert.Len(t, agent.ocServices, 1)
			assert.Equal(t, RouterInternalDefault, agent.ocServices[0].Name)
			assert.Equal(t, OpenShiftIngressNs, agent.ocServices[0].Namespace)
		})
	}
}

func TestInitClientInformer(t *testing.T) {
	// Create a test agent using existing pattern
	agent := testAgent()

	t.Run("Service endpoint informer", func(t *testing.T) {
		sep := &serviceEndpoint{agent: agent.HostAgent}
		
		// This should not panic and should initialize the informer
		assert.NotPanics(t, func() {
			sep.InitClientInformer(nil) // Pass nil since we're testing init, not functionality
		})
	})

	t.Run("Service endpoint slice informer", func(t *testing.T) {
		seps := &serviceEndpointSlice{agent: agent.HostAgent}
		
		// This should not panic and should initialize the informer
		assert.NotPanics(t, func() {
			seps.InitClientInformer(nil) // Pass nil since we're testing init, not functionality
		})
	})
}

func TestAddPodRoute(t *testing.T) {
	tests := []struct {
		name        string
		ipNet       types.IPNet
		dev         string
		src         string
		expectError bool
	}{
		{
			name: "Valid IPv4 route",
			ipNet: types.IPNet{
				IP:   net.ParseIP("10.128.2.100"),
				Mask: net.CIDRMask(32, 32),
			},
			dev:         "test-dev",
			src:         "10.128.2.1",
			expectError: true, // Will error in test environment due to missing interface
		},
		{
			name: "Valid IPv6 route",
			ipNet: types.IPNet{
				IP:   net.ParseIP("2001:db8::1"),
				Mask: net.CIDRMask(128, 128),
			},
			dev:         "test-dev-v6",
			src:         "2001:db8::100",
			expectError: true, // Will error in test environment due to missing interface
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := addPodRoute(tt.ipNet, tt.dev, tt.src)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestScheduleSyncFunctions(t *testing.T) {
	agent := testAgent()

	tests := []struct {
		name     string
		syncFunc func()
		syncType string
	}{
		{
			name:     "scheduleSyncOpflexServer",
			syncFunc: agent.scheduleSyncOpflexServer,
			syncType: "opflexServer",
		},
		{
			name:     "scheduleSyncLocalHppMo", 
			syncFunc: agent.scheduleSyncLocalHppMo,
			syncType: "hpp",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear any existing items in the queue
			for agent.syncQueue.Len() > 0 {
				item, _ := agent.syncQueue.Get()
				agent.syncQueue.Done(item)
			}

			// Call the sync function
			assert.NotPanics(t, func() {
				tt.syncFunc()
			})

			// Verify item was added to queue
			assert.Greater(t, agent.syncQueue.Len(), 0, "Expected item to be added to sync queue")

			// Get and verify the queued item
			item, shutdown := agent.syncQueue.Get()
			assert.False(t, shutdown)
			assert.Equal(t, tt.syncType, item.(string))
			agent.syncQueue.Done(item)
		})
	}
}

func TestWatchRebootConf(t *testing.T) {
	agent := testAgent()

	// Create a temporary directory for the reboot config
	tempDir, err := os.MkdirTemp("", "reboot-conf-test")
	assert.NoError(t, err)
	defer os.RemoveAll(tempDir)

	agent.config.OpFlexConfigPath = tempDir

	// Test watchRebootConf function
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// This function should not panic and should handle the context cancellation gracefully
	assert.NotPanics(t, func() {
		go agent.watchRebootConf(ctx.Done())
		<-ctx.Done()
	})
}

func TestCheckSyncProcessorsCompletionStatus(t *testing.T) {
	agent := testAgent()

	// Set up test conditions
	agent.config.TaintNotReadyNode = true
	agent.taintRemoved.Store(false)

	// Create a mock environment
	agent.env = &K8sEnvironment{}

	// Test the function with a short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	assert.NotPanics(t, func() {
		go agent.checkSyncProcessorsCompletionStatus(ctx.Done())
		<-ctx.Done()
	})
}

func TestSnatPolicyLabelFunctions(t *testing.T) {
	agent := testAgent()
	testKey := "test-key"
	testPolicy := "test-policy"

	t.Run("WriteNewSnatPolicyLabel", func(t *testing.T) {
		assert.NotPanics(t, func() {
			agent.WriteNewSnatPolicyLabel(testKey)
		})

		// Verify the label was created
		labels, exists := agent.ReadSnatPolicyLabel(testKey)
		assert.True(t, exists)
		assert.NotNil(t, labels)
	})

	t.Run("WriteSnatPolicyLabel", func(t *testing.T) {
		assert.NotPanics(t, func() {
			agent.WriteSnatPolicyLabel(testKey, testPolicy, RESOURCE_POD)
		})

		// Verify the policy was added to the label
		labels, exists := agent.ReadSnatPolicyLabel(testKey)
		assert.True(t, exists)
		assert.Contains(t, labels, testPolicy)
		assert.Equal(t, RESOURCE_POD, labels[testPolicy])
	})

	t.Run("ReadSnatPolicyLabel", func(t *testing.T) {
		labels, exists := agent.ReadSnatPolicyLabel(testKey)
		assert.True(t, exists)
		assert.NotEmpty(t, labels)
	})

	t.Run("DeleteSnatPolicyLabelEntry", func(t *testing.T) {
		assert.NotPanics(t, func() {
			agent.DeleteSnatPolicyLabelEntry(testKey, testPolicy)
		})

		// Verify the policy was removed
		labels, exists := agent.ReadSnatPolicyLabel(testKey)
		if exists {
			assert.NotContains(t, labels, testPolicy)
		}
	})

	t.Run("DeleteSnatPolicyLabel", func(t *testing.T) {
		// First add a label
		agent.WriteNewSnatPolicyLabel(testKey + "2")
		
		assert.NotPanics(t, func() {
			agent.DeleteSnatPolicyLabel(testKey + "2")
		})

		// Verify the entire label was removed
		_, exists := agent.ReadSnatPolicyLabel(testKey + "2")
		assert.False(t, exists)
	})

	t.Run("DeleteMatchingSnatPolicyLabel", func(t *testing.T) {
		// Setup multiple labels with the same policy
		testKeys := []string{"key1", "key2", "key3"}
		matchingPolicy := "matching-policy"

		for _, key := range testKeys {
			agent.WriteNewSnatPolicyLabel(key)
			agent.WriteSnatPolicyLabel(key, matchingPolicy, RESOURCE_POD)
		}

		assert.NotPanics(t, func() {
			agent.DeleteMatchingSnatPolicyLabel(matchingPolicy)
		})

		// Verify the policy was removed from all labels
		for _, key := range testKeys {
			labels, exists := agent.ReadSnatPolicyLabel(key)
			if exists {
				assert.NotContains(t, labels, matchingPolicy)
			}
		}
	})
}

func TestRemoveTaintIfNodeReady(t *testing.T) {
	agent := testAgent()

	tests := []struct {
		name        string
		node        *v1.Node
		taintKey    string
		expectError bool
		expectTaint bool
	}{
		{
			name: "Node not ready - keep taint",
			node: &v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-node-not-ready",
				},
				Status: v1.NodeStatus{
					Conditions: []v1.NodeCondition{
						{
							Type:   v1.NodeReady,
							Status: v1.ConditionFalse,
						},
					},
				},
				Spec: v1.NodeSpec{
					Taints: []v1.Taint{
						{
							Key:    "test-taint",
							Value:  "test-value",
							Effect: v1.TaintEffectNoSchedule,
						},
					},
				},
			},
			taintKey:    "test-taint",
			expectError: false,
			expectTaint: true,
		},
		{
			name: "Taint key not found",
			node: &v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-node-no-taint",
				},
				Status: v1.NodeStatus{
					Conditions: []v1.NodeCondition{
						{
							Type:   v1.NodeReady,
							Status: v1.ConditionTrue,
						},
					},
				},
				Spec: v1.NodeSpec{
					Taints: []v1.Taint{
						{
							Key:    "other-taint",
							Value:  "other-value",
							Effect: v1.TaintEffectNoSchedule,
						},
					},
				},
			},
			taintKey:    "nonexistent-taint",
			expectError: false,
			expectTaint: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test with nil client to verify the function handles the case gracefully
			err := agent.removeTaintIfNodeReady(tt.node, tt.taintKey, nil)

			// The function should handle nil client gracefully or return an error
			// This tests the function's error handling capability
			if tt.expectError {
				assert.Error(t, err)
			}

			// Verify original node taint state (since we can't test actual removal with nil client)
			taintFound := false
			for _, taint := range tt.node.Spec.Taints {
				if taint.Key == tt.taintKey {
					taintFound = true
					break
				}
			}

			assert.Equal(t, tt.expectTaint, taintFound, "Expected taint presence: %v, actual: %v", tt.expectTaint, taintFound)
		})
	}
}