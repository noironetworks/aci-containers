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

// TestEnsureLocalHppsRenderedViaRealPodCallback drives ensureLocalHppsRendered
// through the real mergeNetPolSg/podUpdated callback chain (triggered by the
// pod-selector-index's ObjUpdateCallback wiring in initNetPolPodIndex, not by
// calling ensureLocalHppsRendered directly), proving that when a pod becomes
// selected by a NP whose corresponding HPP CR exists but hasn't yet been
// rendered locally, it gets rendered into hppMoIndex end-to-end.
func TestEnsureLocalHppsRenderedViaRealPodCallback(t *testing.T) {
	agent := testAgentHppDirect(t)

	np := &v1net.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "np-render"},
		Spec: v1net.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
		},
	}
	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "pod-render"},
		Spec:       v1.PodSpec{NodeName: nodename},
	}

	specName, err := agent.getHPPDirLabelKey(np)
	assert.NoError(t, err)

	// The HPP CR corresponding to this NP's derived label key -- not yet
	// rendered into hppMoIndex.
	hppName := strings.ReplaceAll(specName, "_", "-")
	hpp := &hppv1.HostprotPol{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: agent.config.AciHppObjsNamespace,
			Name:      hppName,
		},
		Spec: hppv1.HostprotPolSpec{
			Name:         specName,
			HostprotSubj: []hppv1.HostprotSubj{{Name: "subj1"}},
		},
	}
	assert.NoError(t, agent.hppInformer.GetStore().Add(hpp))

	assert.NoError(t, agent.netPolInformer.GetStore().Add(np))
	assert.NoError(t, agent.podInformer.GetStore().Add(pod))

	agent.hppMutex.Lock()
	_, present := agent.hppMoIndex[specName]
	agent.hppMutex.Unlock()
	assert.False(t, present, "hpp should not be rendered before the pod is selected")

	// Real callback path: registering the NP selector immediately matches
	// the already-indexed pod, firing podUpdated -> mergeNetPolSg ->
	// ensureLocalHppsRendered via the wiring set up in initNetPolPodIndex.
	agent.netPolPods.UpdateSelectorObjNoCallback(np)

	agent.hppMutex.Lock()
	rendered, present := agent.hppMoIndex[specName]
	agent.hppMutex.Unlock()
	assert.True(t, present, "hpp should be rendered into hppMoIndex once the pod is selected")
	assert.NotEmpty(t, rendered, "rendered hpp should produce at least one GBP MO")

	item, quit := agent.hppLocalMoSyncQueue.Get()
	assert.False(t, quit)
	assert.Equal(t, "hpp", item)
	agent.hppLocalMoSyncQueue.Done(item)
	agent.hppLocalMoSyncQueue.Forget(item)
}

// TestEnsureLocalHppsRenderedSkipsAlreadyRendered verifies that
// ensureLocalHppsRendered does not re-render (or otherwise touch) an HPP
// that's already present in hppMoIndex, avoiding redundant work on every
// pod event.
func TestEnsureLocalHppsRenderedSkipsAlreadyRendered(t *testing.T) {
	agent := testAgentHppDirect(t)

	np := &v1net.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "np-skip"},
		Spec: v1net.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
		},
	}
	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "pod-skip"},
		Spec:       v1.PodSpec{NodeName: nodename},
	}

	specName, err := agent.getHPPDirLabelKey(np)
	assert.NoError(t, err)

	// Pre-populate hppMoIndex with a sentinel value distinct from what
	// renderHppToIndex would produce, so we can detect whether
	// ensureLocalHppsRendered overwrote it.
	sentinel := []*gbpBaseMo{{}}
	agent.hppMutex.Lock()
	agent.hppMoIndex[specName] = sentinel
	agent.hppMutex.Unlock()

	assert.NoError(t, agent.netPolInformer.GetStore().Add(np))
	assert.NoError(t, agent.podInformer.GetStore().Add(pod))

	agent.netPolPods.UpdateSelectorObjNoCallback(np)

	agent.hppMutex.Lock()
	got := agent.hppMoIndex[specName]
	agent.hppMutex.Unlock()
	assert.Len(t, got, 1)
	assert.True(t, got[0] == sentinel[0], "already-rendered hpp entries should not be touched")
}
