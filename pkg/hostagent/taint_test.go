// Copyright 2026 Cisco Systems, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRATIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package hostagent

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	framework "k8s.io/client-go/tools/cache/testing"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

// TestScheduleSyncLocalHppMo verifies that scheduleSyncLocalHppMo routes
// through ScheduleSync to the dedicated hppLocalMoSyncQueue (rather than the
// generic syncQueue used by most other sync types).
func TestScheduleSyncLocalHppMo(t *testing.T) {
	agent := testAgent()

	agent.scheduleSyncLocalHppMo()

	item, quit := agent.hppLocalMoSyncQueue.Get()
	assert.False(t, quit)
	assert.Equal(t, "hpp", item)
	agent.hppLocalMoSyncQueue.Done(item)
	agent.hppLocalMoSyncQueue.Forget(item)

	assert.Equal(t, 0, agent.syncQueue.Len())
}

// TestProcessSyncQueueTracksHppCompletion verifies that processSyncQueue
// records "hpp" in completedSyncTypes once the real hpp syncProcessor runs,
// mirroring the same tracking done for "services"/"eps"/etc. This exercises
// the actual inline switch in processSyncQueue rather than duplicating its
// logic, without needing a full envtest/Run() setup.
func TestProcessSyncQueueTracksHppCompletion(t *testing.T) {
	agent := testAgent()
	// testAgentInit() unconditionally forces taintRemoved to true; reset it
	// here so processSyncQueue's tracking branch (gated on
	// !taintRemoved.Load()) actually executes, matching the real
	// TaintNotReadyNode=true runtime scenario.
	agent.taintRemoved.Store(false)

	stopCh := make(chan struct{})
	defer close(stopCh)
	go agent.processSyncQueue(agent.hppLocalMoSyncQueue, stopCh)

	agent.scheduleSyncLocalHppMo()

	assert.Eventually(t, func() bool {
		agent.indexMutex.Lock()
		defer agent.indexMutex.Unlock()
		_, ok := agent.completedSyncTypes["hpp"]
		return ok
	}, 2*time.Second, 20*time.Millisecond, "hpp completion should be tracked in completedSyncTypes")
}

func nodeHasTaint(t *testing.T, kubeClient *kubernetes.Clientset, name string) bool {
	t.Helper()
	node, err := kubeClient.CoreV1().Nodes().Get(context.TODO(), name, metav1.GetOptions{})
	assert.Nil(t, err, "node get")
	for _, taint := range node.Spec.Taints {
		if taint.Key == ACIContainersTaintName {
			return true
		}
	}
	return false
}

// TestCheckSyncProcessorsCompletionStatusTaintRemoval exercises the real
// checkSyncProcessorsCompletionStatus goroutine (started by Run() when
// TaintNotReadyNode is set) end-to-end against an envtest API server: it
// verifies the node's NoSchedule taint is left in place until the
// EnableHppDirect-dependent required sync-type count (5, or 6 when
// EnableHppDirect is set) is reached, and removed once it is.
func TestCheckSyncProcessorsCompletionStatusTaintRemoval(t *testing.T) {
	testenv := &envtest.Environment{}
	cfg, err := testenv.Start()
	assert.Nil(t, err, "testenv start")
	defer func() {
		assert.Nil(t, testenv.Stop(), "testenv stop")
	}()

	kubeClient, err := kubernetes.NewForConfig(cfg)
	assert.Nil(t, err, "clientset create")

	runScenario := func(t *testing.T, nodeName string, enableHppDirect bool,
		belowThresholdSyncTypes []string, finalSyncType string) {
		os.Setenv("KUBERNETES_NODE_NAME", nodeName)
		defer os.Unsetenv("KUBERNETES_NODE_NAME")

		node := &v1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: nodeName},
			Spec: v1.NodeSpec{
				Taints: []v1.Taint{
					{Key: ACIContainersTaintName, Effect: v1.TaintEffectNoSchedule},
				},
			},
		}
		created, err := kubeClient.CoreV1().Nodes().Create(context.TODO(), node, metav1.CreateOptions{})
		assert.Nil(t, err, "node create")
		created.Status.Conditions = []v1.NodeCondition{
			{Type: v1.NodeReady, Status: v1.ConditionTrue},
		}
		_, err = kubeClient.CoreV1().Nodes().UpdateStatus(context.TODO(), created, metav1.UpdateOptions{})
		assert.Nil(t, err, "node status update")

		hcf := &HostAgentConfig{
			NodeName:            nodeName,
			LogLevel:            "debug",
			AciPrefix:           "kube",
			TaintNotReadyNode:   true,
			EnableHppDirect:     enableHppDirect,
			AciHppObjsNamespace: "aci-containers-system",
		}
		agent := testAgentEnvtest(hcf, kubeClient, cfg)
		if enableHppDirect {
			// PrepareRun() requires hppInformer/hppRemoteIpInformer to be
			// non-nil whenever EnableHppDirect is set; wire them with fake
			// sources since we don't need real HPP CRs for this scenario.
			fakeHppSource := framework.NewFakeControllerSource()
			agent.initHppInformerBase(&cache.ListWatch{
				ListFunc:  fakeHppSource.List,
				WatchFunc: fakeHppSource.Watch,
			})
			fakeRicSource := framework.NewFakeControllerSource()
			agent.initHostprotRemoteIpContainerBase(&cache.ListWatch{
				ListFunc:  fakeRicSource.List,
				WatchFunc: fakeRicSource.Watch,
			})
		}
		agent.run()
		defer agent.stop()

		agent.indexMutex.Lock()
		for _, st := range belowThresholdSyncTypes {
			agent.completedSyncTypes[st] = struct{}{}
		}
		agent.indexMutex.Unlock()

		// checkSyncProcessorsCompletionStatus ticks every second; give it a
		// couple of ticks to confirm it does NOT remove the taint yet.
		time.Sleep(2200 * time.Millisecond)
		assert.True(t, nodeHasTaint(t, kubeClient, nodeName),
			"taint should remain while below the required sync-type count")
		assert.False(t, agent.taintRemoved.Load().(bool))

		agent.indexMutex.Lock()
		agent.completedSyncTypes[finalSyncType] = struct{}{}
		agent.indexMutex.Unlock()

		assert.Eventually(t, func() bool {
			return !nodeHasTaint(t, kubeClient, nodeName)
		}, 5*time.Second, 200*time.Millisecond,
			"taint should be removed once the required sync-type count is reached")
		assert.True(t, agent.taintRemoved.Load().(bool))
	}

	t.Run("EnableHppDirect_requires_six_sync_types", func(t *testing.T) {
		runScenario(t, "taint-node-hppdirect", true,
			[]string{"services", "eps", "snat", "snatnodeInfo", "nodepodifs"}, "hpp")
	})

	t.Run("Default_requires_five_sync_types", func(t *testing.T) {
		runScenario(t, "taint-node-default", false,
			[]string{"services", "eps", "snat", "snatnodeInfo"}, "nodepodifs")
	})
}
