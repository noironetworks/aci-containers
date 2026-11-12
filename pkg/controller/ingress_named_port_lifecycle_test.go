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
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package controller

import (
	"io"
	"net"
	"sort"
	"strings"
	"testing"

	"github.com/noironetworks/aci-containers/pkg/apicapi"
	"github.com/noironetworks/aci-containers/pkg/ipam"
	"github.com/noironetworks/aci-containers/pkg/util"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	v1net "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

type ingressLifecycleFatalT struct{ *testing.T }

func (t ingressLifecycleFatalT) Errorf(format string, args ...interface{}) {
	t.Helper()
	t.Fatalf(format, args...)
}

// Render only queued policies, without Pod workers, so missing notifications
// and named-port cache dependencies cannot be hidden.
func newIngressLifecycleController(t *testing.T, mode string) *testAciController {
	t.Helper()
	return newIngressLifecycleControllerWithPools(t, mode, []ipam.IpRange{{
		Start: net.ParseIP("10.1.0.1"), End: net.ParseIP("10.1.255.254"),
	}})
}

func newIngressLifecycleControllerWithPools(t *testing.T, mode string, pools []ipam.IpRange) *testAciController {
	t.Helper()
	config := NewConfig()
	config.AciPrefix = "kube"
	config.AciPolicyTenant = "test-tenant"
	config.HppOptimization = mode == "optimized"
	config.EnableHppDirect = mode == "direct"
	config.PodIpPool = pools
	cont := testControllerWithConfig(config)
	cont.log.SetOutput(io.Discard)
	cont.initIpam()
	var err error
	cont.apicConn, err = apicapi.New(cont.log, nil, "", "", nil, nil,
		config.AciPrefix, 1800, 210, 60, 5, "common", nil, false)
	assert.NoError(ingressLifecycleFatalT{t}, err)
	for _, ns := range []string{"testns", "otherns"} {
		assert.NoError(ingressLifecycleFatalT{t}, cont.namespaceIndexer.Add(namespaceLabel(ns, nil)))
	}
	t.Cleanup(func() {
		cont.netPolQueue.ShutDown()
		cont.podQueue.ShutDown()
		cont.hppQueue.ShutDown()
		cont.remIpContQueue.ShutDown()
	})
	return cont
}

func ingressLifecyclePod(ns, name, app string, number int32) *v1.Pod {
	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns, Name: name, UID: types.UID(name + "-original"),
			Labels: map[string]string{"app": app},
		},
		Spec: v1.PodSpec{Containers: []v1.Container{{
			Name: "app", Ports: []v1.ContainerPort{{
				Name: "http", ContainerPort: number, Protocol: v1.ProtocolTCP,
			}},
		}}},
		Status: v1.PodStatus{PodIP: "10.1.0.10"},
	}
}

func ingressLifecyclePolicy(name string, selector metav1.LabelSelector, portName string) *v1net.NetworkPolicy {
	protocol := v1.ProtocolTCP
	port := intstr.FromString(portName)
	return netpol("testns", name, &selector,
		[]v1net.NetworkPolicyIngressRule{{
			Ports: []v1net.NetworkPolicyPort{{Protocol: &protocol, Port: &port}},
		}}, nil, []v1net.PolicyType{v1net.PolicyTypeIngress})
}

func addIngressLifecyclePod(t *testing.T, cont *testAciController, pod *v1.Pod) {
	t.Helper()
	assert.NoError(ingressLifecycleFatalT{t}, cont.podIndexer.Add(pod))
	cont.podAdded(pod)
}

func updateIngressLifecyclePod(t *testing.T, cont *testAciController, oldPod, newPod *v1.Pod) {
	t.Helper()
	assert.NoError(ingressLifecycleFatalT{t}, cont.podIndexer.Update(newPod))
	cont.podUpdated(oldPod, newPod)
}

func addIngressLifecyclePolicy(t *testing.T, cont *testAciController, np *v1net.NetworkPolicy) {
	t.Helper()
	assert.NoError(ingressLifecycleFatalT{t}, cont.networkPolicyIndexer.Add(np))
	cont.networkPolicyAdded(np)
}

func renderIngressLifecycleQueue(t *testing.T, cont *testAciController, wantKeys ...string) {
	t.Helper()
	var queued []string
	for cont.netPolQueue.Len() != 0 {
		item, shutdown := cont.netPolQueue.Get()
		assert.False(ingressLifecycleFatalT{t}, shutdown)
		key, ok := item.(string)
		assert.True(ingressLifecycleFatalT{t}, ok, "unexpected NetworkPolicy queue item: %T", item)
		queued = append(queued, key)
		cont.netPolQueue.Done(item)
		cont.netPolQueue.Forget(item)
	}
	sort.Strings(queued)
	sort.Strings(wantKeys)
	assert.Equal(ingressLifecycleFatalT{t}, strings.Join(wantKeys, ","), strings.Join(queued, ","),
		"only relevant policies should be queued by the event")
	for _, key := range queued {
		obj, exists, err := cont.networkPolicyIndexer.GetByKey(key)
		assert.NoError(ingressLifecycleFatalT{t}, err)
		assert.True(ingressLifecycleFatalT{t}, exists)
		assert.False(ingressLifecycleFatalT{t}, cont.handleNetPolUpdate(obj.(*v1net.NetworkPolicy)))
	}
}

func assertIngressLifecyclePorts(t *testing.T, cont *testAciController, np *v1net.NetworkPolicy, want ...string) {
	t.Helper()
	key, err := cache.MetaNamespaceKeyFunc(np)
	assert.NoError(ingressLifecycleFatalT{t}, err)
	var ports []string
	if cont.config.EnableHppDirect {
		hash, err := util.CreateCanonicalHashFromNetPol(np)
		assert.NoError(ingressLifecycleFatalT{t}, err)
		hppName := strings.ReplaceAll(cont.aciNameForKey("np", hash), "_", "-")
		ref, exists := cont.hppDirRef[hppName]
		assert.True(ingressLifecycleFatalT{t}, exists, "direct policy was not rendered")
		for _, subject := range ref.HppCr.Spec.HostprotSubj {
			if subject.Name != "networkpolicy-ingress" {
				continue
			}
			for _, rule := range subject.HostprotRule {
				ports = append(ports, rule.FromPort)
			}
		}
	} else {
		if cont.config.HppOptimization {
			key, err = util.CreateHashFromNetPol(np)
			assert.NoError(ingressLifecycleFatalT{t}, err)
		}
		desired := cont.apicConn.GetDesiredState(cont.aciNameForKey("np", key))
		assert.NotEmpty(ingressLifecycleFatalT{t}, desired, "APIC policy was not rendered")
		for _, obj := range desired {
			hpp := obj["hostprotPol"]
			assert.NotNil(ingressLifecycleFatalT{t}, hpp)
			for _, child := range hpp.Children {
				subject := child["hostprotSubj"]
				if subject == nil || subject.Attributes["name"] != "networkpolicy-ingress" {
					continue
				}
				for _, child := range subject.Children {
					if rule := child["hostprotRule"]; rule != nil {
						value, ok := rule.Attributes["fromPort"].(string)
						assert.True(ingressLifecycleFatalT{t}, ok)
						ports = append(ports, value)
					}
				}
			}
		}
	}
	sort.Strings(ports)
	sort.Strings(want)
	assert.Equal(t, strings.Join(want, ","), strings.Join(ports, ","),
		"rendered ingress ports must follow the current subject Pods")
}

// Run a worker step at the first enqueue to expose partially updated indexes.
type ingressLifecyclePublicationQueue struct {
	workqueue.RateLimitingInterface
	onFirstAdd func()
}

func (q *ingressLifecyclePublicationQueue) Add(item interface{}) {
	q.RateLimitingInterface.Add(item)
	if q.onFirstAdd != nil {
		callback := q.onFirstAdd
		q.onFirstAdd = nil
		callback()
	}
}

func TestIngressNamedPortLifecycleQueuePublicationAfterPeerIndex(t *testing.T) {
	for _, mode := range []string{"legacy", "optimized", "direct"} {
		for _, event := range []string{"add", "label-join"} {
			t.Run(mode+"/"+event, func(t *testing.T) {
				cont := newIngressLifecycleController(t, mode)
				selector := metav1.LabelSelector{MatchLabels: map[string]string{"app": "selected"}}
				np := ingressLifecyclePolicy("ingress", selector, "http")
				np.Spec.Ingress[0].From = []v1net.NetworkPolicyPeer{{PodSelector: &selector}}
				pod := ingressLifecyclePod("testns", "router", "selected", 8080)
				if event == "label-join" {
					pod.Labels["app"] = "other"
					addIngressLifecyclePod(t, cont, pod)
				}
				addIngressLifecyclePolicy(t, cont, np)
				renderIngressLifecycleQueue(t, cont, "testns/ingress")
				assertIngressLifecyclePorts(t, cont, np)

				firstRender := false
				cont.netPolQueue = &ingressLifecyclePublicationQueue{
					RateLimitingInterface: cont.netPolQueue,
					onFirstAdd: func() {
						firstRender = true
						item, shutdown := cont.netPolQueue.Get()
						assert.False(ingressLifecycleFatalT{t}, shutdown)
						defer cont.netPolQueue.Done(item)
						defer cont.netPolQueue.Forget(item)
						key, ok := item.(string)
						assert.True(ingressLifecycleFatalT{t}, ok)
						assert.Equal(ingressLifecycleFatalT{t}, "testns/ingress", key)
						obj, exists, err := cont.networkPolicyIndexer.GetByKey(key)
						assert.NoError(ingressLifecycleFatalT{t}, err)
						assert.True(ingressLifecycleFatalT{t}, exists)
						assert.Equal(t, []string{"testns/router"}, cont.netPolPods.GetPodForObj(key))
						assert.Equal(t, []string{"testns/router"}, cont.netPolIngressPods.GetPodForObj(key),
							"the first policy notification must not expose a stale ingress-peer index")
						assert.False(ingressLifecycleFatalT{t}, cont.handleNetPolUpdate(obj.(*v1net.NetworkPolicy)))
						// Direct rules use separate remote-IP state; check the peer index too.
						assertIngressLifecyclePorts(t, cont, np, "8080")
					},
				}
				if event == "add" {
					addIngressLifecyclePod(t, cont, pod)
				} else {
					updated := pod.DeepCopy()
					updated.Labels["app"] = "selected"
					updateIngressLifecyclePod(t, cont, pod, updated)
				}
				assert.True(t, firstRender, "the Pod event must notify the policy worker")
				// A later notification must not be needed to repair the first render.
				renderIngressLifecycleQueue(t, cont, "testns/ingress")
				assertIngressLifecyclePorts(t, cont, np, "8080")
			})
		}
	}
}

func TestIngressNamedPortLifecycleCNOPathsDoNotUsePolicyIndexes(t *testing.T) {
	for _, mode := range []string{"chained", "vmm-lite"} {
		t.Run(mode, func(t *testing.T) {
			cont := newIngressLifecycleController(t, "legacy")
			cont.config.ChainedMode = mode == "chained"
			cont.config.VmmLite = mode == "vmm-lite"
			// Production skips initializing these indexes in CNO mode.
			cont.netPolPods = nil
			cont.netPolIngressPods = nil
			cont.netPolEgressPods = nil
			cont.erspanPolPods = nil
			pod := ingressLifecyclePod("testns", "router", "other", 8080)
			pod.Spec.Containers[0].Ports = nil
			addIngressLifecyclePod(t, cont, pod)
			updated := pod.DeepCopy()
			updated.Labels["app"] = "selected"
			updated.Status.PodIP = "10.1.0.11"
			updated.Spec.Containers[0].Ports = []v1.ContainerPort{{
				Name: "http", ContainerPort: 9090, Protocol: v1.ProtocolTCP,
			}}
			updateIngressLifecyclePod(t, cont, pod, updated)
			// Empty cache state keeps asynchronous legacy cleanup out of this test.
			assert.Empty(ingressLifecycleFatalT{t}, cont.ctrPortNameCache)
			assert.NoError(ingressLifecycleFatalT{t}, cont.podIndexer.Delete(updated))
			cont.podDeleted(updated)
			renderIngressLifecycleQueue(t, cont)
		})
	}
}

func TestIngressNamedPortLifecycleLabelChanges(t *testing.T) {
	for _, mode := range []string{"legacy", "optimized", "direct"} {
		for _, joining := range []bool{true, false} {
			name := "leave"
			if joining {
				name = "join"
			}
			t.Run(mode+"/"+name, func(t *testing.T) {
				cont := newIngressLifecycleController(t, mode)
				stable := ingressLifecyclePod("testns", "stable", "selected", 8081)
				changing := ingressLifecyclePod("testns", "changing", "selected", 8080)
				if joining {
					changing.Labels["app"] = "other"
				}
				addIngressLifecyclePod(t, cont, stable)
				addIngressLifecyclePod(t, cont, changing)
				np := ingressLifecyclePolicy("ingress", metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "selected"},
				}, "http")
				addIngressLifecyclePolicy(t, cont, np)
				renderIngressLifecycleQueue(t, cont, "testns/ingress")
				if joining {
					assertIngressLifecyclePorts(t, cont, np, "8081")
				} else {
					assertIngressLifecyclePorts(t, cont, np, "8080", "8081")
				}
				updated := changing.DeepCopy()
				updated.Labels["app"] = "other"
				if joining {
					updated.Labels["app"] = "selected"
				}
				updateIngressLifecyclePod(t, cont, changing, updated)
				renderIngressLifecycleQueue(t, cont, "testns/ingress")
				if joining {
					assertIngressLifecyclePorts(t, cont, np, "8080", "8081")
				} else {
					assertIngressLifecyclePorts(t, cont, np, "8081")
				}
			})
		}
	}
}

func TestIngressNamedPortLifecycleDeleteBeforeCachePublication(t *testing.T) {
	for _, mode := range []string{"legacy", "optimized", "direct"} {
		for _, emptySelector := range []bool{true, false} {
			name := "selected"
			selector := metav1.LabelSelector{MatchLabels: map[string]string{"app": "selected"}}
			if emptySelector {
				name, selector = "all", metav1.LabelSelector{}
			}
			t.Run(mode+"/"+name, func(t *testing.T) {
				cont := newIngressLifecycleController(t, mode)
				np := ingressLifecyclePolicy("ingress", selector, "http")
				addIngressLifecyclePolicy(t, cont, np)
				renderIngressLifecycleQueue(t, cont, "testns/ingress")
				assertIngressLifecyclePorts(t, cont, np)
				pod := ingressLifecyclePod("testns", "router", "selected", 8080)
				addIngressLifecyclePod(t, cont, pod)
				renderIngressLifecycleQueue(t, cont, "testns/ingress")
				assertIngressLifecyclePorts(t, cont, np, "8080")
				assert.Empty(ingressLifecycleFatalT{t}, cont.ctrPortNameCache)
				assert.NoError(ingressLifecycleFatalT{t}, cont.podIndexer.Delete(pod))
				cont.podDeleted(pod)
				renderIngressLifecycleQueue(t, cont, "testns/ingress")
				assertIngressLifecyclePorts(t, cont, np)
			})
		}
	}
}

func TestIngressNamedPortLifecycleRelistReplacement(t *testing.T) {
	for _, mode := range []string{"legacy", "optimized", "direct"} {
		for _, removeName := range []bool{false, true} {
			name := "changed-number"
			if removeName {
				name = "removed-name"
			}
			t.Run(mode+"/"+name, func(t *testing.T) {
				cont := newIngressLifecycleController(t, mode)
				oldPod := ingressLifecyclePod("testns", "router", "selected", 8080)
				addIngressLifecyclePod(t, cont, oldPod)
				np := ingressLifecyclePolicy("ingress", metav1.LabelSelector{}, "http")
				addIngressLifecyclePolicy(t, cont, np)
				renderIngressLifecycleQueue(t, cont, "testns/ingress")
				assertIngressLifecyclePorts(t, cont, np, "8080")
				// A relist can deliver a same-key replacement as Update, without Delete/Add.
				newPod := oldPod.DeepCopy()
				newPod.UID = "router-replacement"
				newPod.Spec.Containers[0].Ports[0].ContainerPort = 9090
				if removeName {
					newPod.Spec.Containers[0].Ports[0].Name = "metrics"
				}
				updateIngressLifecyclePod(t, cont, oldPod, newPod)
				renderIngressLifecycleQueue(t, cont, "testns/ingress")
				if removeName {
					assertIngressLifecyclePorts(t, cont, np)
				} else {
					assertIngressLifecyclePorts(t, cont, np, "9090")
				}
			})
		}
	}
}

func TestIngressNamedPortLifecycleDelayedOldCacheCleanup(t *testing.T) {
	for _, mode := range []string{"legacy", "optimized", "direct"} {
		t.Run(mode, func(t *testing.T) {
			cont := newIngressLifecycleController(t, mode)
			oldPod := ingressLifecyclePod("testns", "router", "selected", 8080)
			addIngressLifecyclePod(t, cont, oldPod)
			key := "testns/router"
			cont.updateCtrNmPortForPod(oldPod, key)
			np := ingressLifecyclePolicy("ingress", metav1.LabelSelector{}, "http")
			addIngressLifecyclePolicy(t, cont, np)
			renderIngressLifecycleQueue(t, cont, "testns/ingress")
			assertIngressLifecyclePorts(t, cont, np, "8080")

			// Reproduce old cleanup running after replacement publication,
			// without relying on goroutine timing.
			assert.NoError(ingressLifecycleFatalT{t}, cont.podIndexer.Delete(oldPod))
			cont.netPolPods.DeletePod(oldPod)
			newPod := oldPod.DeepCopy()
			newPod.UID = "router-replacement"
			addIngressLifecyclePod(t, cont, newPod)
			cont.updateCtrNmPortForPod(newPod, key)
			cont.deleteCtrNmPortForPod(oldPod, key)
			assert.Empty(ingressLifecycleFatalT{t}, cont.ctrPortNameCache,
				"the legacy cache can lose the replacement, but ingress must not use it")
			renderIngressLifecycleQueue(t, cont, "testns/ingress")
			assertIngressLifecyclePorts(t, cont, np, "8080")
			obj, exists, err := cont.podIndexer.GetByKey(key)
			assert.NoError(ingressLifecycleFatalT{t}, err)
			assert.True(ingressLifecycleFatalT{t}, exists)
			assert.Equal(t, newPod.UID, obj.(*v1.Pod).UID)
		})
	}
}

func TestIngressNamedPortLifecyclePolicySelectorOnlyChange(t *testing.T) {
	for _, mode := range []string{"legacy", "optimized", "direct"} {
		t.Run(mode, func(t *testing.T) {
			cont := newIngressLifecycleController(t, mode)
			addIngressLifecyclePod(t, cont, ingressLifecyclePod("testns", "blue", "blue", 8080))
			addIngressLifecyclePod(t, cont, ingressLifecyclePod("testns", "green", "green", 9090))
			np := ingressLifecyclePolicy("ingress", metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "blue"},
			}, "http")
			addIngressLifecyclePolicy(t, cont, np)
			renderIngressLifecycleQueue(t, cont, "testns/ingress")
			assertIngressLifecyclePorts(t, cont, np, "8080")
			updated := np.DeepCopy()
			updated.Spec.PodSelector.MatchLabels["app"] = "green"
			assert.NoError(ingressLifecycleFatalT{t}, cont.networkPolicyIndexer.Update(updated))
			cont.networkPolicyChanged(np, updated)
			renderIngressLifecycleQueue(t, cont, "testns/ingress")
			assertIngressLifecyclePorts(t, cont, updated, "9090")
		})
	}
}

func TestIngressNamedPortLifecycleUniformResolution(t *testing.T) {
	selectors := []struct {
		name     string
		selector metav1.LabelSelector
	}{
		{name: "empty"},
		{name: "empty-map", selector: metav1.LabelSelector{MatchLabels: map[string]string{}}},
		{name: "selected", selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "selected"}}},
	}
	for _, mode := range []string{"legacy", "optimized", "direct"} {
		for _, selector := range selectors {
			t.Run(mode+"/"+selector.name, func(t *testing.T) {
				cont := newIngressLifecycleController(t, mode)
				regular := ingressLifecyclePod("testns", "regular", "selected", 8080)
				init := ingressLifecyclePod("testns", "init", "selected", 8082)
				init.Spec.InitContainers = init.Spec.Containers
				init.Spec.Containers = []v1.Container{{Name: "app"}}
				host := ingressLifecyclePod("testns", "host", "selected", 8083)
				host.Spec.HostNetwork = true
				foreign := ingressLifecyclePod("otherns", "foreign", "selected", 8084)
				pending := ingressLifecyclePod("testns", "pending", "selected", 8085)
				pending.Status = v1.PodStatus{}
				for _, pod := range []*v1.Pod{regular, init, host, foreign, pending} {
					addIngressLifecyclePod(t, cont, pod)
				}
				np := ingressLifecyclePolicy("ingress", selector.selector, "http")
				addIngressLifecyclePolicy(t, cont, np)
				renderIngressLifecycleQueue(t, cont, "testns/ingress")
				assertIngressLifecyclePorts(t, cont, np, "8080", "8082")
				assert.Empty(ingressLifecycleFatalT{t}, cont.ctrPortNameCache)
			})
		}
	}
}

func TestIngressNamedPortLifecycleRelevantNotificationsOnly(t *testing.T) {
	for _, mode := range []string{"legacy", "optimized", "direct"} {
		t.Run(mode, func(t *testing.T) {
			cont := newIngressLifecycleController(t, mode)
			selector := metav1.LabelSelector{MatchLabels: map[string]string{"app": "selected"}}
			http := ingressLifecyclePolicy("http", selector, "http")
			metrics := ingressLifecyclePolicy("metrics", selector, "metrics")
			numeric := ingressLifecyclePolicy("numeric", selector, "http")
			value := intstr.FromInt(8080)
			numeric.Spec.Ingress[0].Ports[0].Port = &value
			foreign := ingressLifecyclePolicy("foreign", selector, "http")
			foreign.Namespace = "otherns"
			for _, np := range []*v1net.NetworkPolicy{http, metrics, numeric, foreign} {
				addIngressLifecyclePolicy(t, cont, np)
			}
			renderIngressLifecycleQueue(t, cont, "otherns/foreign", "testns/http", "testns/metrics", "testns/numeric")
			pod := ingressLifecyclePod("testns", "router", "selected", 8080)
			addIngressLifecyclePod(t, cont, pod)
			renderIngressLifecycleQueue(t, cont, "testns/http")
			assertIngressLifecyclePorts(t, cont, http, "8080")
			for _, change := range []struct {
				name        string
				update      func(*v1.Pod)
				queuePolicy bool
			}{
				{name: "annotation", update: func(p *v1.Pod) { p.Annotations = map[string]string{"note": "changed"} }},
				{name: "phase", update: func(p *v1.Pod) { p.Status.Phase = v1.PodRunning }},
				{name: "primary-address", update: func(p *v1.Pod) { p.Status.PodIP = "10.1.0.11" }, queuePolicy: true},
				{name: "secondary-address", update: func(p *v1.Pod) {
					p.Status.PodIPs = []v1.PodIP{{IP: p.Status.PodIP}, {IP: "2001:db8::11"}}
				}},
			} {
				t.Run(change.name, func(t *testing.T) {
					updated := pod.DeepCopy()
					change.update(updated)
					updateIngressLifecyclePod(t, cont, pod, updated)
					if change.queuePolicy {
						renderIngressLifecycleQueue(t, cont, "testns/http")
					} else {
						renderIngressLifecycleQueue(t, cont)
					}
					assertIngressLifecyclePorts(t, cont, http, "8080")
					pod = updated
				})
			}
		})
	}
}

func TestIngressNamedPortLifecycleNoIPChangesDeferredUntilAssignment(t *testing.T) {
	for _, mode := range []string{"legacy", "optimized", "direct"} {
		t.Run(mode, func(t *testing.T) {
			cont := newIngressLifecycleController(t, mode)
			np := ingressLifecyclePolicy("ingress", metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "selected"},
			}, "http")
			addIngressLifecyclePolicy(t, cont, np)
			renderIngressLifecycleQueue(t, cont, "testns/ingress")
			pod := ingressLifecyclePod("testns", "router", "selected", 8080)
			pod.Status = v1.PodStatus{}
			pod.Spec.Containers[0].Ports = nil
			addIngressLifecyclePod(t, cont, pod)
			renderIngressLifecycleQueue(t, cont)
			assert.Empty(t, cont.netPolPods.GetPodForObj("testns/ingress"),
				"unaddressed Pods do not contribute ingress named-port resolutions")
			outside := pod.DeepCopy()
			outside.Labels["app"] = "other"
			updateIngressLifecyclePod(t, cont, pod, outside)
			renderIngressLifecycleQueue(t, cont)
			assert.Empty(t, cont.netPolPods.GetPodForObj("testns/ingress"))
			inside := outside.DeepCopy()
			inside.Labels["app"] = "selected"
			updateIngressLifecyclePod(t, cont, outside, inside)
			renderIngressLifecycleQueue(t, cont)
			assert.Empty(t, cont.netPolPods.GetPodForObj("testns/ingress"))
			replacement := inside.DeepCopy()
			replacement.UID = "router-replacement"
			replacement.Spec.Containers[0].Ports = []v1.ContainerPort{{
				Name: "http", ContainerPort: 8080, Protocol: v1.ProtocolTCP,
			}}
			updateIngressLifecyclePod(t, cont, inside, replacement)
			renderIngressLifecycleQueue(t, cont)
			assertIngressLifecyclePorts(t, cont, np)
			addressed := replacement.DeepCopy()
			addressed.Status.PodIP = "10.1.0.10"
			updateIngressLifecyclePod(t, cont, replacement, addressed)
			renderIngressLifecycleQueue(t, cont, "testns/ingress")
			assertIngressLifecyclePorts(t, cont, np, "8080")
			unaddressed := addressed.DeepCopy()
			unaddressed.Status = v1.PodStatus{}
			updateIngressLifecyclePod(t, cont, addressed, unaddressed)
			renderIngressLifecycleQueue(t, cont, "testns/ingress")
			assertIngressLifecyclePorts(t, cont, np)
			assert.Empty(t, cont.netPolPods.GetPodForObj("testns/ingress"))
		})
	}
}

func TestIngressNamedPortLifecycleHostNetworkReplacement(t *testing.T) {
	for _, mode := range []string{"legacy", "optimized", "direct"} {
		t.Run(mode, func(t *testing.T) {
			cont := newIngressLifecycleController(t, mode)
			pod := ingressLifecyclePod("testns", "router", "selected", 8080)
			addIngressLifecyclePod(t, cont, pod)
			np := ingressLifecyclePolicy("ingress", metav1.LabelSelector{}, "http")
			addIngressLifecyclePolicy(t, cont, np)
			renderIngressLifecycleQueue(t, cont, "testns/ingress")
			assertIngressLifecyclePorts(t, cont, np, "8080")
			host := pod.DeepCopy()
			host.UID = "router-hostnetwork-replacement"
			host.Spec.HostNetwork = true
			updateIngressLifecyclePod(t, cont, pod, host)
			renderIngressLifecycleQueue(t, cont, "testns/ingress")
			assertIngressLifecyclePorts(t, cont, np)
			assert.Empty(t, cont.netPolPods.GetPodForObj("testns/ingress"))
			ordinary := host.DeepCopy()
			ordinary.UID = "router-ordinary-replacement"
			ordinary.Spec.HostNetwork = false
			updateIngressLifecyclePod(t, cont, host, ordinary)
			renderIngressLifecycleQueue(t, cont, "testns/ingress")
			assertIngressLifecyclePorts(t, cont, np, "8080")
		})
	}
}

func TestIngressNamedPortLifecycleRenameNotifiesOldAndNewNames(t *testing.T) {
	for _, mode := range []string{"legacy", "optimized", "direct"} {
		t.Run(mode, func(t *testing.T) {
			cont := newIngressLifecycleController(t, mode)
			pod := ingressLifecyclePod("testns", "router", "selected", 8080)
			addIngressLifecyclePod(t, cont, pod)
			http := ingressLifecyclePolicy("http", metav1.LabelSelector{}, "http")
			metrics := ingressLifecyclePolicy("metrics", metav1.LabelSelector{}, "metrics")
			addIngressLifecyclePolicy(t, cont, http)
			addIngressLifecyclePolicy(t, cont, metrics)
			renderIngressLifecycleQueue(t, cont, "testns/http", "testns/metrics")
			assertIngressLifecyclePorts(t, cont, http, "8080")
			assertIngressLifecyclePorts(t, cont, metrics)
			replacement := pod.DeepCopy()
			replacement.UID = "router-replacement"
			replacement.Spec.Containers[0].Ports[0].Name = "metrics"
			replacement.Spec.Containers[0].Ports[0].ContainerPort = 9090
			updateIngressLifecyclePod(t, cont, pod, replacement)
			renderIngressLifecycleQueue(t, cont, "testns/http", "testns/metrics")
			assertIngressLifecyclePorts(t, cont, http)
			assertIngressLifecyclePorts(t, cont, metrics, "9090")
		})
	}
}

func TestIngressNamedPortLifecycleNoIPStartupOrdering(t *testing.T) {
	for _, mode := range []string{"legacy", "optimized", "direct"} {
		for _, policyFirst := range []bool{true, false} {
			order := "pod-first"
			if policyFirst {
				order = "policy-first"
			}
			t.Run(mode+"/"+order, func(t *testing.T) {
				cont := newIngressLifecycleController(t, mode)
				np := ingressLifecyclePolicy("ingress", metav1.LabelSelector{}, "http")
				pod := ingressLifecyclePod("testns", "router", "selected", 8080)
				pod.Status = v1.PodStatus{}
				if policyFirst {
					addIngressLifecyclePolicy(t, cont, np)
					renderIngressLifecycleQueue(t, cont, "testns/ingress")
					addIngressLifecyclePod(t, cont, pod)
					renderIngressLifecycleQueue(t, cont)
				} else {
					addIngressLifecyclePod(t, cont, pod)
					renderIngressLifecycleQueue(t, cont)
					addIngressLifecyclePolicy(t, cont, np)
					renderIngressLifecycleQueue(t, cont, "testns/ingress")
				}
				// A policy-first Pod event removes the key; a Pod-first selector scan
				// may retain it. Neither path may render a permit before IP assignment.
				assertIngressLifecyclePorts(t, cont, np)
				assert.Empty(ingressLifecycleFatalT{t}, cont.ctrPortNameCache)
				addressed := pod.DeepCopy()
				addressed.Status.PodIP = "10.1.0.10"
				updateIngressLifecyclePod(t, cont, pod, addressed)
				renderIngressLifecycleQueue(t, cont, "testns/ingress")
				assertIngressLifecyclePorts(t, cont, np, "8080")
				unaddressed := addressed.DeepCopy()
				unaddressed.Status = v1.PodStatus{}
				updateIngressLifecyclePod(t, cont, addressed, unaddressed)
				renderIngressLifecycleQueue(t, cont, "testns/ingress")
				assertIngressLifecyclePorts(t, cont, np)
			})
		}
	}
}

func TestIngressNamedPortLifecycleSelectorChangeToNoIPPod(t *testing.T) {
	for _, mode := range []string{"legacy", "optimized", "direct"} {
		t.Run(mode, func(t *testing.T) {
			cont := newIngressLifecycleController(t, mode)
			blue := ingressLifecyclePod("testns", "blue", "blue", 8080)
			green := ingressLifecyclePod("testns", "green", "green", 9090)
			green.Status = v1.PodStatus{}
			addIngressLifecyclePod(t, cont, blue)
			addIngressLifecyclePod(t, cont, green)
			np := ingressLifecyclePolicy("ingress", metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "blue"},
			}, "http")
			addIngressLifecyclePolicy(t, cont, np)
			renderIngressLifecycleQueue(t, cont, "testns/ingress")
			assertIngressLifecyclePorts(t, cont, np, "8080")
			updated := np.DeepCopy()
			updated.Spec.PodSelector.MatchLabels["app"] = "green"
			assert.NoError(ingressLifecycleFatalT{t}, cont.networkPolicyIndexer.Update(updated))
			cont.networkPolicyChanged(np, updated)
			renderIngressLifecycleQueue(t, cont, "testns/ingress")
			assert.Equal(t, []string{"testns/green"}, cont.netPolPods.GetPodForObj("testns/ingress"),
				"exercise a selector scan that includes an unaddressed Pod")
			assertIngressLifecyclePorts(t, cont, updated)
			addressed := green.DeepCopy()
			addressed.Status.PodIP = "10.1.0.11"
			updateIngressLifecyclePod(t, cont, green, addressed)
			renderIngressLifecycleQueue(t, cont, "testns/ingress")
			assertIngressLifecyclePorts(t, cont, updated, "9090")
		})
	}
}

func TestIngressNamedPortLifecycleIPFamilies(t *testing.T) {
	for _, mode := range []string{"legacy", "optimized", "direct"} {
		for _, family := range []string{"ipv4", "ipv6", "dual-stack"} {
			t.Run(mode+"/"+family, func(t *testing.T) {
				v4 := ipam.IpRange{Start: net.ParseIP("10.1.0.1"), End: net.ParseIP("10.1.255.254")}
				v6 := ipam.IpRange{Start: net.ParseIP("2001:db8::1"), End: net.ParseIP("2001:db8::ffff")}
				pools := []ipam.IpRange{v4}
				if family == "ipv6" {
					pools = []ipam.IpRange{v6}
				} else if family == "dual-stack" {
					pools = []ipam.IpRange{v4, v6}
				}
				cont := newIngressLifecycleControllerWithPools(t, mode, pools)
				np := ingressLifecyclePolicy("ingress", metav1.LabelSelector{}, "http")
				addIngressLifecyclePolicy(t, cont, np)
				renderIngressLifecycleQueue(t, cont, "testns/ingress")
				pod := ingressLifecyclePod("testns", "router", "selected", 8080)
				if family == "ipv6" {
					pod.Status.PodIP = "2001:db8::10"
				}
				pod.Status.PodIPs = []v1.PodIP{{IP: pod.Status.PodIP}}
				if family == "dual-stack" {
					pod.Status.PodIPs = append(pod.Status.PodIPs, v1.PodIP{IP: "2001:db8::10"})
				}
				addIngressLifecyclePod(t, cont, pod)
				renderIngressLifecycleQueue(t, cont, "testns/ingress")
				want := []string{"8080"}
				if family == "dual-stack" {
					want = append(want, "8080")
				}
				assertIngressLifecyclePorts(t, cont, np, want...)
				updated := pod.DeepCopy()
				updated.UID = "router-replacement"
				updated.Spec.Containers[0].Ports[0].ContainerPort = 9090
				updateIngressLifecyclePod(t, cont, pod, updated)
				renderIngressLifecycleQueue(t, cont, "testns/ingress")
				for i := range want {
					want[i] = "9090"
				}
				assertIngressLifecyclePorts(t, cont, np, want...)
			})
		}
	}
}

func TestIngressNamedPortStateInputs(t *testing.T) {
	empty := getIngressNamedPortState(&v1.Pod{})
	assert.Equal(t, ingressNamedPortState{}, empty)
	assert.Equal(t, empty, getIngressNamedPortState(nil))
	pod := ingressLifecyclePod("testns", "router", "selected", 8080)
	initial := getIngressNamedPortState(pod)
	assert.Equal(t, map[string]bool{"http": true}, initial.names)
	assert.Equal(t, "10.1.0.10|http:tcp:8080|", initial.fingerprint)
	unaddressed := pod.DeepCopy()
	unaddressed.Status = v1.PodStatus{}
	assert.Equal(t, empty, getIngressNamedPortState(unaddressed),
		"unaddressed Pods must not contribute declarations before IP assignment")
	secondary := pod.DeepCopy()
	secondary.Status.PodIPs = []v1.PodIP{{IP: pod.Status.PodIP}, {IP: "2001:db8::10"}}
	assert.Equal(t, initial, getIngressNamedPortState(secondary),
		"a secondary-address-only change does not change the primary-IP fingerprint")
	ipv6 := pod.DeepCopy()
	ipv6.Status.PodIP = "2001:db8::10"
	ipv6.Status.PodIPs = []v1.PodIP{{IP: "2001:db8::10"}, {IP: "10.1.0.10"}}
	assert.Equal(t, "2001:db8::10|http:tcp:8080|", getIngressNamedPortState(ipv6).fingerprint,
		"PodIP is the primary address and may be IPv6")
	defaultTCP := pod.DeepCopy()
	defaultTCP.Spec.Containers[0].Ports[0].Protocol = ""
	assert.Equal(t, initial, getIngressNamedPortState(defaultTCP))
	udp := pod.DeepCopy()
	udp.Spec.Containers[0].Ports[0].Protocol = v1.ProtocolUDP
	assert.NotEqual(t, initial.fingerprint, getIngressNamedPortState(udp).fingerprint)
	sctp := pod.DeepCopy()
	sctp.Spec.Containers[0].Ports[0].Protocol = v1.ProtocolSCTP
	assert.NotEqual(t, initial.fingerprint, getIngressNamedPortState(sctp).fingerprint)
	assert.NotEqual(t, getIngressNamedPortState(udp).fingerprint, getIngressNamedPortState(sctp).fingerprint)
	init := pod.DeepCopy()
	init.Spec.InitContainers = []v1.Container{{Name: "init", Ports: []v1.ContainerPort{{
		Name: "metrics", ContainerPort: 9090,
	}}}}
	assert.Equal(t, map[string]bool{"http": true, "metrics": true}, getIngressNamedPortState(init).names)
	host := init.DeepCopy()
	host.Spec.HostNetwork = true
	assert.Equal(t, empty, getIngressNamedPortState(host))
	unnamed := pod.DeepCopy()
	unnamed.Spec.Containers[0].Ports = append(unnamed.Spec.Containers[0].Ports,
		v1.ContainerPort{ContainerPort: 9000, Protocol: v1.ProtocolTCP})
	assert.Equal(t, initial, getIngressNamedPortState(unnamed))
	unnamed.Spec.Containers[0].Ports[0].Name = ""
	assert.Equal(t, ingressNamedPortState{fingerprint: unnamed.Status.PodIP}, getIngressNamedPortState(unnamed),
		"addressed Pods without named ports use PodIP directly")
}

func TestIngressNamedPortStateAllocationFreeFastPaths(t *testing.T) {
	named := ingressLifecyclePod("testns", "router", "selected", 8080)
	unaddressed := named.DeepCopy()
	unaddressed.Status = v1.PodStatus{}
	host := named.DeepCopy()
	host.Spec.HostNetwork = true
	unnamed := named.DeepCopy()
	unnamed.Spec.Containers[0].Ports[0].Name = ""
	unnamed.Spec.InitContainers = []v1.Container{{Name: "init", Ports: []v1.ContainerPort{{ContainerPort: 9090}}}}
	for _, tc := range []struct {
		name string
		pod  *v1.Pod
		want ingressNamedPortState
	}{
		{name: "nil"},
		{name: "no-IP", pod: unaddressed},
		{name: "HostNetwork", pod: host},
		{name: "no-named-ports", pod: unnamed, want: ingressNamedPortState{fingerprint: unnamed.Status.PodIP}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var state ingressNamedPortState
			allocs := testing.AllocsPerRun(100, func() {
				state = getIngressNamedPortState(tc.pod)
			})
			assert.Zero(t, allocs, "the common fast path should not allocate maps or a builder buffer")
			assert.Equal(t, tc.want, state)
		})
	}
}
