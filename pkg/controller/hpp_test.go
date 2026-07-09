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

package controller

import (
	"testing"
	"time"

	hppv1 "github.com/noironetworks/aci-containers/pkg/hpp/apis/aci.hpp/v1"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	framework "k8s.io/client-go/tools/cache/testing"
)

// newTestHppController builds a minimal AciController with only the queues
// initialized (via NewController), matching the pattern used by
// TestProcessRemIpContQueue. No informers/InitController is needed since
// hppChanged/hppDeleted only touch cont.hppQueue, and
// hppRemoteIpChanged/hppRemoteIpDeleted only touch cont.remIpContQueue.
func newTestHppController() *AciController {
	return NewController(&ControllerConfig{}, nil, nil, false)
}

// getQueueItem does a non-blocking-in-practice Get() on the queue (the item
// is expected to already be present) and marks it Done so it doesn't leak
// into subsequent assertions.
func getQueueItem(t *testing.T, queue interface {
	Get() (interface{}, bool)
	Done(interface{})
}) interface{} {
	t.Helper()
	type result struct {
		item interface{}
		shut bool
	}
	ch := make(chan result, 1)
	go func() {
		item, shutdown := queue.Get()
		ch <- result{item, shutdown}
	}()
	select {
	case r := <-ch:
		if r.shut {
			t.Fatalf("queue was shut down unexpectedly")
		}
		queue.Done(r.item)
		return r.item
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for item to be added to queue")
		return nil
	}
}

func TestHppChanged(t *testing.T) {
	cont := newTestHppController()
	hpp := &hppv1.HostprotPol{
		ObjectMeta: metav1.ObjectMeta{Name: "test-hpp-1"},
	}

	cont.hppChanged(hpp)

	// hppChanged routes through queueHppUpdateByKey, which adds to
	// hppQueue -- distinct from hppRemoteIpChanged, which targets
	// remIpContQueue.
	item := getQueueItem(t, cont.hppQueue)
	assert.Equal(t, "test-hpp-1", item)
	assert.Equal(t, 0, cont.remIpContQueue.Len())
}

func TestHppDeleted(t *testing.T) {
	cont := newTestHppController()
	hpp := &hppv1.HostprotPol{
		ObjectMeta: metav1.ObjectMeta{Name: "test-hpp-2"},
	}

	cont.hppDeleted(hpp)

	item := getQueueItem(t, cont.hppQueue)
	assert.Equal(t, "test-hpp-2", item)
}

func TestHppDeletedTombstone(t *testing.T) {
	cont := newTestHppController()
	hpp := &hppv1.HostprotPol{
		ObjectMeta: metav1.ObjectMeta{Name: "test-hpp-tombstone"},
	}
	tombstone := cache.DeletedFinalStateUnknown{
		Key: "test-hpp-tombstone",
		Obj: hpp,
	}

	cont.hppDeleted(tombstone)

	item := getQueueItem(t, cont.hppQueue)
	assert.Equal(t, "test-hpp-tombstone", item)
}

func TestHppRemoteIpChanged(t *testing.T) {
	cont := newTestHppController()
	ric := &hppv1.HostprotRemoteIpContainer{
		ObjectMeta: metav1.ObjectMeta{Name: "test-ric-1"},
	}

	cont.hppRemoteIpChanged(ric)

	// hppRemoteIpChanged routes through queueRemoteIpConUpdateByKey to
	// remIpContQueue -- distinct from hppChanged, which targets hppQueue.
	item := getQueueItem(t, cont.remIpContQueue)
	assert.Equal(t, "test-ric-1", item)
}

func TestHppRemoteIpDeleted(t *testing.T) {
	cont := newTestHppController()
	ric := &hppv1.HostprotRemoteIpContainer{
		ObjectMeta: metav1.ObjectMeta{Name: "test-ric-2"},
	}

	cont.hppRemoteIpDeleted(ric)

	item := getQueueItem(t, cont.remIpContQueue)
	assert.Equal(t, "test-ric-2", item)
}

func TestHppRemoteIpDeletedTombstone(t *testing.T) {
	cont := newTestHppController()
	ric := &hppv1.HostprotRemoteIpContainer{
		ObjectMeta: metav1.ObjectMeta{Name: "test-ric-tombstone"},
	}
	tombstone := cache.DeletedFinalStateUnknown{
		Key: "test-ric-tombstone",
		Obj: ric,
	}

	cont.hppRemoteIpDeleted(tombstone)

	item := getQueueItem(t, cont.remIpContQueue)
	assert.Equal(t, "test-ric-tombstone", item)
}

// TestHppInformerWiringSmoke verifies the informer plumbing itself (not just
// the handler functions in isolation): Add/Update/Delete events delivered
// through a real SharedIndexInformer sourced from a FakeControllerSource
// actually reach hppChanged/hppDeleted via initHppInformerBase's
// AddEventHandler wiring, ending up on hppQueue.
func TestHppInformerWiringSmoke(t *testing.T) {
	cont := newTestHppController()

	fakeHppSource := framework.NewFakeControllerSource()
	cont.initHppInformerBase(&cache.ListWatch{
		ListFunc:  fakeHppSource.List,
		WatchFunc: fakeHppSource.Watch,
	})

	stopCh := make(chan struct{})
	defer close(stopCh)
	go cont.hppInformer.Run(stopCh)
	assert.True(t, cache.WaitForCacheSync(stopCh, cont.hppInformer.HasSynced))

	hpp := &hppv1.HostprotPol{
		ObjectMeta: metav1.ObjectMeta{Name: "smoke-hpp-1"},
	}
	fakeHppSource.Add(hpp)

	item := getQueueItem(t, cont.hppQueue)
	assert.Equal(t, "smoke-hpp-1", item)

	fakeHppSource.Delete(hpp)

	item = getQueueItem(t, cont.hppQueue)
	assert.Equal(t, "smoke-hpp-1", item)
}

// TestHppRemoteIpInformerWiringSmoke mirrors TestHppInformerWiringSmoke for
// the hostprotremoteipcontainer informer, verifying
// initHppRemoteIpInformerBase's AddEventHandler wiring reaches
// hppRemoteIpChanged/hppRemoteIpDeleted end-to-end.
func TestHppRemoteIpInformerWiringSmoke(t *testing.T) {
	cont := newTestHppController()

	fakeRicSource := framework.NewFakeControllerSource()
	cont.initHppRemoteIpInformerBase(&cache.ListWatch{
		ListFunc:  fakeRicSource.List,
		WatchFunc: fakeRicSource.Watch,
	})

	stopCh := make(chan struct{})
	defer close(stopCh)
	go cont.hppRemoteIpInformer.Run(stopCh)
	assert.True(t, cache.WaitForCacheSync(stopCh, cont.hppRemoteIpInformer.HasSynced))

	ric := &hppv1.HostprotRemoteIpContainer{
		ObjectMeta: metav1.ObjectMeta{Name: "smoke-ric-1"},
	}
	fakeRicSource.Add(ric)

	item := getQueueItem(t, cont.remIpContQueue)
	assert.Equal(t, "smoke-ric-1", item)

	fakeRicSource.Delete(ric)

	item = getQueueItem(t, cont.remIpContQueue)
	assert.Equal(t, "smoke-ric-1", item)
}
