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
	"os"
	"path/filepath"
	"testing"

	hppv1 "github.com/noironetworks/aci-containers/pkg/hpp/apis/aci.hpp/v1"
	"github.com/noironetworks/aci-containers/pkg/util"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	v1net "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	framework "k8s.io/client-go/tools/cache/testing"
)

// testAgentHppDirect builds a testHostAgent with EnableHppDirect enabled and
// OpFlexNetPolDir pointed at a per-test temp directory.
func testAgentHppDirect(t *testing.T) *testHostAgent {
	hcf := &HostAgentConfig{
		NodeName:            nodename,
		AciPrefix:           "kube",
		EnableHppDirect:     true,
		OpFlexNetPolDir:     t.TempDir(),
		AciHppObjsNamespace: "aci-containers-system",
	}
	agent := testAgentWithConf(hcf)
	fakeRicSource := framework.NewFakeControllerSource()
	agent.initHostprotRemoteIpContainerBase(
		&cache.ListWatch{
			ListFunc:  fakeRicSource.List,
			WatchFunc: fakeRicSource.Watch,
		})
	// In production, EnableHppDirect always implies hppInformer is
	// initialized before the pod/NP informer wiring can fire (see
	// PrepareRun). Wire it here too so code paths reached via the real
	// pod-selector-index callbacks (e.g. mergeNetPolSg ->
	// ensureLocalHppsRendered) behave the same as in production instead of
	// nil-pointer-panicking on an uninitialized informer.
	fakeHppSource := framework.NewFakeControllerSource()
	agent.initHppInformerBase(
		&cache.ListWatch{
			ListFunc:  fakeHppSource.List,
			WatchFunc: fakeHppSource.Watch,
		})
	return agent
}

func staticIngressName(agent *HostAgent) string {
	return util.AciNameForKey(agent.config.AciPrefix, "np", "static-ingress")
}

func staticEgressName(agent *HostAgent) string {
	return util.AciNameForKey(agent.config.AciPrefix, "np", "static-egress")
}

func staticDiscoveryName(agent *HostAgent) string {
	return util.AciNameForKey(agent.config.AciPrefix, "np", "static-discovery")
}

func nodePolicyName(agent *HostAgent) string {
	return util.AciNameForKey(agent.config.AciPrefix, "node", agent.config.NodeName)
}

// drainHppQueue synchronously processes all pending agent.hppQueue items
// (mirrors the production processQueue worker), making async HPP rendering
// deterministic in tests. HPPs must already be in agent.hppInformer's store.
func drainHppQueue(t *testing.T, agent *testHostAgent) {
	t.Helper()
	for agent.hppQueue.Len() > 0 {
		item, _ := agent.hppQueue.Get()
		if key, ok := item.(string); ok {
			if obj, exists, err := agent.hppInformer.GetStore().GetByKey(key); err == nil && exists {
				agent.handleHppQueueItem(obj)
			}
		}
		agent.hppQueue.Done(item)
		agent.hppQueue.Forget(item)
	}
}

func TestIsStaticOrNodeHpp(t *testing.T) {
	agent := testAgentHppDirect(t)

	assert.True(t, agent.isStaticOrNodeHpp(staticIngressName(agent.HostAgent)))
	assert.True(t, agent.isStaticOrNodeHpp(staticEgressName(agent.HostAgent)))
	assert.True(t, agent.isStaticOrNodeHpp(staticDiscoveryName(agent.HostAgent)))
	assert.True(t, agent.isStaticOrNodeHpp(nodePolicyName(agent.HostAgent)))
	assert.False(t, agent.isStaticOrNodeHpp("some-other-policy"))
}

func TestIsHppLocallyRelevantStaticAndNode(t *testing.T) {
	agent := testAgentHppDirect(t)

	staticHpp := &hppv1.HostprotPol{
		Spec: hppv1.HostprotPolSpec{Name: staticIngressName(agent.HostAgent)},
	}
	assert.True(t, agent.isHppLocallyRelevant(staticHpp))

	nodeHpp := &hppv1.HostprotPol{
		Spec: hppv1.HostprotPolSpec{Name: nodePolicyName(agent.HostAgent)},
	}
	assert.True(t, agent.isHppLocallyRelevant(nodeHpp))
}

func TestIsHppLocallyRelevantNpDerived(t *testing.T) {
	agent := testAgentHppDirect(t)

	npHpp := &hppv1.HostprotPol{
		Spec: hppv1.HostprotPolSpec{
			Name:            "np-derived-hpp",
			NetworkPolicies: []string{"testns/np1"},
		},
	}
	// No pods registered yet — not locally relevant.
	assert.False(t, agent.isHppLocallyRelevant(npHpp))

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
	// Register the pod in the pod informer's store so the selector index
	// can find it, then wire up the NP selector and pod membership.
	assert.NoError(t, agent.podInformer.GetStore().Add(pod))
	agent.netPolPods.UpdateSelectorObjNoCallback(np)
	agent.netPolPods.UpdatePodNoCallback(pod)

	assert.True(t, agent.isHppLocallyRelevant(npHpp))
}

func TestRicRefsForHpp(t *testing.T) {
	assert.Empty(t, ricRefsForHpp(nil))

	hpp := &hppv1.HostprotPol{
		Spec: hppv1.HostprotPolSpec{
			HostprotSubj: []hppv1.HostprotSubj{
				{
					Name: "subj1",
					HostprotRule: []hppv1.HostprotRule{
						{Name: "rule1", RsRemoteIpContainer: "ric-1"},
						{Name: "rule2", RsRemoteIpContainer: "ric-2"},
						{Name: "rule3", RsRemoteIpContainer: "ric-1"}, // duplicate
						{Name: "rule4"}, // no RIC ref
					},
				},
			},
		},
	}
	refs := ricRefsForHpp(hpp)
	assert.Equal(t, map[string]bool{"ric-1": true, "ric-2": true}, refs)
}

func hppWithRics(name string, rics ...string) *hppv1.HostprotPol {
	var rules []hppv1.HostprotRule
	for _, ric := range rics {
		rules = append(rules, hppv1.HostprotRule{
			Name:                filepath.Join("rule", ric),
			RsRemoteIpContainer: ric,
		})
	}
	return &hppv1.HostprotPol{
		ObjectMeta: metav1.ObjectMeta{Namespace: "aci-containers-system", Name: name},
		Spec: hppv1.HostprotPolSpec{
			Name:         name,
			HostprotSubj: []hppv1.HostprotSubj{{Name: "subj1", HostprotRule: rules}},
		},
	}
}

func TestRebuildRicMappingForHppAdd(t *testing.T) {
	agent := testAgentHppDirect(t)

	newHpp := hppWithRics("hpp1", "ric-1", "ric-2")
	agent.rebuildRicMappingForHpp(nil, newHpp, "ns/hpp1")

	assert.Equal(t, map[string]bool{"ns/hpp1": true}, agent.ricToHpp["ric-1"])
	assert.Equal(t, map[string]bool{"ns/hpp1": true}, agent.ricToHpp["ric-2"])
}

func TestRebuildRicMappingForHppUpdateDiff(t *testing.T) {
	agent := testAgentHppDirect(t)

	oldHpp := hppWithRics("hpp1", "ric-1", "ric-2")
	agent.rebuildRicMappingForHpp(nil, oldHpp, "ns/hpp1")

	newHpp := hppWithRics("hpp1", "ric-2", "ric-3")
	agent.rebuildRicMappingForHpp(oldHpp, newHpp, "ns/hpp1")

	// ric-1 no longer referenced — entry fully removed.
	_, ricOnePresent := agent.ricToHpp["ric-1"]
	assert.False(t, ricOnePresent)
	// ric-2 still referenced.
	assert.Equal(t, map[string]bool{"ns/hpp1": true}, agent.ricToHpp["ric-2"])
	// ric-3 newly referenced.
	assert.Equal(t, map[string]bool{"ns/hpp1": true}, agent.ricToHpp["ric-3"])
}

func TestRebuildRicMappingForHppUpdatePreservesOtherHppKeys(t *testing.T) {
	agent := testAgentHppDirect(t)

	hppA := hppWithRics("hppA", "ric-shared")
	hppB := hppWithRics("hppB", "ric-shared")
	agent.rebuildRicMappingForHpp(nil, hppA, "ns/hppA")
	agent.rebuildRicMappingForHpp(nil, hppB, "ns/hppB")

	// hppA no longer references ric-shared.
	newHppA := hppWithRics("hppA")
	agent.rebuildRicMappingForHpp(hppA, newHppA, "ns/hppA")

	// ric-shared entry survives because hppB still references it.
	assert.Equal(t, map[string]bool{"ns/hppB": true}, agent.ricToHpp["ric-shared"])
}

func TestHandleHppAddNotLocallyRelevantStillTracksRicMapping(t *testing.T) {
	agent := testAgentHppDirect(t)

	hpp := hppWithRics("np-derived", "ric-1")
	hpp.Spec.NetworkPolicies = []string{"testns/np1"}
	agent.handleHppAdd(hpp)

	// Not locally relevant (no matching pods) — hppMoIndex must not contain it.
	agent.hppMutex.Lock()
	_, present := agent.hppMoIndex[hpp.Spec.Name]
	agent.hppMutex.Unlock()
	assert.False(t, present)

	// RIC reverse mapping is still tracked regardless of local relevance.
	agent.hppMutex.Lock()
	assert.Equal(t, map[string]bool{"aci-containers-system/np-derived": true}, agent.ricToHpp["ric-1"])
	agent.hppMutex.Unlock()
}

func TestHandleHppAddStaticWritesFileEagerly(t *testing.T) {
	agent := testAgentHppDirect(t)

	hpp := hppWithRics(staticIngressName(agent.HostAgent))
	assert.NoError(t, agent.hppInformer.GetStore().Add(hpp))
	agent.handleHppAdd(hpp)
	drainHppQueue(t, agent)

	agent.hppMutex.Lock()
	_, present := agent.hppMoIndex[hpp.Spec.Name]
	agent.hppMutex.Unlock()
	assert.True(t, present)

	filePath := filepath.Join(agent.config.OpFlexNetPolDir, hpp.Spec.Name+".netpol")
	_, err := os.Stat(filePath)
	assert.NoError(t, err, "expected static hpp netpol file to be written eagerly")
}

func TestHandleHppUpdateEvictsWhenNoLongerRelevant(t *testing.T) {
	agent := testAgentHppDirect(t)

	hpp := hppWithRics("np-derived")
	hpp.Spec.NetworkPolicies = []string{"testns/np1"}

	np := &v1net.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "np1"},
		Spec:       v1net.NetworkPolicySpec{PodSelector: metav1.LabelSelector{}},
	}
	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "pod1"},
		Spec:       v1.PodSpec{NodeName: nodename},
	}
	assert.NoError(t, agent.podInformer.GetStore().Add(pod))
	agent.netPolPods.UpdateSelectorObjNoCallback(np)
	agent.netPolPods.UpdatePodNoCallback(pod)

	// Initially relevant — gets rendered.
	assert.NoError(t, agent.hppInformer.GetStore().Add(hpp))
	agent.handleHppAdd(hpp)
	drainHppQueue(t, agent)
	agent.hppMutex.Lock()
	_, present := agent.hppMoIndex[hpp.Spec.Name]
	agent.hppMutex.Unlock()
	assert.True(t, present)

	// Pod removed — NP no longer matches any local pod.
	agent.netPolPods.DeletePod(pod)

	agent.handleHppUpdate(hpp, hpp)
	agent.hppMutex.Lock()
	_, present = agent.hppMoIndex[hpp.Spec.Name]
	agent.hppMutex.Unlock()
	assert.False(t, present)
}

func TestHandleHppDeleteCleansUpIndexes(t *testing.T) {
	agent := testAgentHppDirect(t)

	ric := &hppv1.HostprotRemoteIpContainer{
		ObjectMeta: metav1.ObjectMeta{Namespace: "aci-containers-system", Name: "ric-1"},
		Spec:       hppv1.HostprotRemoteIpContainerSpec{HostprotRemoteIps: []string{"10.0.0.1"}},
	}
	assert.NoError(t, agent.hppRemoteIpInformer.GetStore().Add(ric))

	hpp := hppWithRics(staticEgressName(agent.HostAgent), "ric-1")
	assert.NoError(t, agent.hppInformer.GetStore().Add(hpp))
	agent.handleHppAdd(hpp)
	drainHppQueue(t, agent)

	agent.hppMutex.Lock()
	_, present := agent.hppMoIndex[hpp.Spec.Name]
	agent.hppMutex.Unlock()
	assert.True(t, present)

	agent.handleHppDelete(hpp)

	agent.hppMutex.Lock()
	_, present = agent.hppMoIndex[hpp.Spec.Name]
	_, ricPresent := agent.ricToHpp["ric-1"]
	agent.hppMutex.Unlock()
	assert.False(t, present)
	assert.False(t, ricPresent)
}
