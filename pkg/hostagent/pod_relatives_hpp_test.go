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
	"strings"
	"testing"

	hppv1 "github.com/noironetworks/aci-containers/pkg/hpp/apis/aci.hpp/v1"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	v1net "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestEvictStaleHppForNpViaRealPodCallback drives evictStaleHppForNp through
// the *real* SetObjUpdateCallback wiring set up in initNetPolPodIndex (via
// agent.netPolPods.UpdatePod/.DeletePod, not the *NoCallback variants used
// elsewhere), proving the callback registration itself -- not just the
// underlying evictStaleHppForNp function in isolation -- works end-to-end.
func TestEvictStaleHppForNpViaRealPodCallback(t *testing.T) {
	agent := testAgentHppDirect(t)

	np := &v1net.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "np1"},
		Spec: v1net.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
		},
	}
	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "pod1"},
		Spec:       v1.PodSpec{NodeName: nodename},
	}

	// Populate the informer stores that evictStaleHppForNp and the
	// selector index both consult.
	assert.NoError(t, agent.netPolInformer.GetStore().Add(np))
	assert.NoError(t, agent.podInformer.GetStore().Add(pod))
	agent.netPolPods.UpdateSelectorObjNoCallback(np)

	specName, err := agent.getHPPDirLabelKey(np)
	assert.NoError(t, err)
	hpp := &hppv1.HostprotPol{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: agent.config.AciHppObjsNamespace,
			Name:      strings.ReplaceAll(specName, "_", "-"),
		},
		Spec: hppv1.HostprotPolSpec{
			Name:            specName,
			NetworkPolicies: []string{"testns/np1"},
		},
	}
	assert.NoError(t, agent.hppInformer.GetStore().Add(hpp))

	// Pre-populate hppMoIndex as if this NP's HPP had already been
	// rendered locally.
	agent.hppMutex.Lock()
	agent.hppMoIndex[specName] = []*gbpBaseMo{{}}
	agent.hppMutex.Unlock()

	// Real callback path: pod becomes a new match for the NP's selector.
	// The ObjUpdateCallback (evictStaleHppForNp) fires, but since the pod
	// still matches, GetPodForObj returns non-empty and no eviction occurs.
	agent.netPolPods.UpdatePod(pod)

	agent.hppMutex.Lock()
	_, present := agent.hppMoIndex[specName]
	agent.hppMutex.Unlock()
	assert.True(t, present, "hpp entry should remain while the pod still matches the NP")

	// Real callback path: pod deleted -> no longer matches the NP ->
	// ObjUpdateCallback fires -> evictStaleHppForNp sees zero matching
	// pods and evicts the stale hppMoIndex entry.
	agent.netPolPods.DeletePod(pod)

	agent.hppMutex.Lock()
	_, present = agent.hppMoIndex[specName]
	agent.hppMutex.Unlock()
	assert.False(t, present, "hpp entry should be evicted once no pods match the NP")

	item, quit := agent.hppLocalMoSyncQueue.Get()
	assert.False(t, quit)
	assert.Equal(t, "hpp", item)
	agent.hppLocalMoSyncQueue.Done(item)
	agent.hppLocalMoSyncQueue.Forget(item)
}

// TestEvictStaleHppForNpKeepsCanonicalSharedHpp covers the direct-mode
// canonicalization case: two otherwise identical policies in different
// namespaces share one HPP CR.  In particular, an ordinary NetworkPolicy-add
// selector registration for a namespace with no local pod invokes the object
// update callback.  It must not remove the shared HPP while another referenced
// policy is still local.
func TestEvictStaleHppForNpKeepsCanonicalSharedHpp(t *testing.T) {
	agent := testAgentHppDirect(t)

	localNP := &v1net.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "local-ns", Name: "allow-system"},
		Spec:       v1net.NetworkPolicySpec{PodSelector: metav1.LabelSelector{}},
	}
	staleNP := &v1net.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "stale-ns", Name: "allow-system"},
		Spec:       v1net.NetworkPolicySpec{PodSelector: metav1.LabelSelector{}},
	}
	localPod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "local-ns", Name: "pod-local"},
		Spec:       v1.PodSpec{NodeName: nodename},
	}

	specName, err := agent.getHPPDirLabelKey(localNP)
	assert.NoError(t, err)
	staleSpecName, err := agent.getHPPDirLabelKey(staleNP)
	assert.NoError(t, err)
	assert.Equal(t, specName, staleSpecName, "identical policies must share the canonical HPP")

	hpp := &hppv1.HostprotPol{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: agent.config.AciHppObjsNamespace,
			Name:      strings.ReplaceAll(specName, "_", "-"),
		},
		Spec: hppv1.HostprotPolSpec{
			Name: specName,
			NetworkPolicies: []string{
				"local-ns/allow-system",
				"stale-ns/allow-system",
			},
		},
	}
	assert.NoError(t, agent.hppInformer.GetStore().Add(hpp))
	assert.NoError(t, agent.netPolInformer.GetStore().Add(localNP))
	assert.NoError(t, agent.netPolInformer.GetStore().Add(staleNP))
	assert.NoError(t, agent.podInformer.GetStore().Add(localPod))
	// Establish the local member first, as happens while a Bosch profile is
	// applied.  The second policy has no pod selected on this node.
	agent.netPolPods.UpdateSelectorObjNoCallback(localNP)

	agent.hppMutex.Lock()
	agent.hppMoIndex[specName] = []*gbpBaseMo{{}}
	agent.hppMutex.Unlock()

	// This is the production trigger: networkPolicyAdded calls
	// UpdateSelectorObj, whose changed empty mapping invokes the callback.
	// stale-ns has no local selected pod, but local-ns still does.
	agent.networkPolicyAdded(staleNP)
	agent.hppMutex.Lock()
	_, present := agent.hppMoIndex[specName]
	agent.hppMutex.Unlock()
	assert.True(t, present, "shared HPP must stay rendered while any referenced policy is local")

	// Once the remaining referenced local policy has no pod either, eviction
	// is both safe and expected.
	agent.netPolPods.DeletePod(localPod)
	agent.hppMutex.Lock()
	_, present = agent.hppMoIndex[specName]
	agent.hppMutex.Unlock()
	assert.False(t, present, "shared HPP must be evicted after every referenced policy is non-local")
}

// TestEvictStaleHppForNpViaRealPodCallbackNoStaleEntry verifies that when
// there is no existing hppMoIndex entry for the NP's label key,
// evictStaleHppForNp (fired via the real ObjUpdateCallback on pod deletion)
// does not itself schedule a spurious extra sync beyond whatever
// mergeNetPolSg already scheduled while the pod was being rendered.
func TestEvictStaleHppForNpViaRealPodCallbackNoStaleEntry(t *testing.T) {
	agent := testAgentHppDirect(t)

	np := &v1net.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "np2"},
		Spec: v1net.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
		},
	}
	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "pod2"},
		Spec:       v1.PodSpec{NodeName: nodename},
	}

	assert.NoError(t, agent.netPolInformer.GetStore().Add(np))
	assert.NoError(t, agent.podInformer.GetStore().Add(pod))
	agent.netPolPods.UpdateSelectorObjNoCallback(np)

	agent.netPolPods.UpdatePod(pod)
	// mergeNetPolSg unconditionally schedules a sync as part of rendering
	// this pod's groups; drain that expected item before asserting on the
	// eviction path specifically.
	if agent.hppLocalMoSyncQueue.Len() > 0 {
		item, _ := agent.hppLocalMoSyncQueue.Get()
		agent.hppLocalMoSyncQueue.Done(item)
		agent.hppLocalMoSyncQueue.Forget(item)
	}

	agent.netPolPods.DeletePod(pod)

	assert.Equal(t, 0, agent.hppLocalMoSyncQueue.Len(),
		"evictStaleHppForNp should not schedule a sync when there was no rendered hpp entry to evict")
}
