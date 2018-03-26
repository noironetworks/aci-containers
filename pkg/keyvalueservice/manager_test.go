// Copyright 2018 Cisco Systems, Inc.
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

package keyvalueservice

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	tu "github.com/noironetworks/aci-containers/pkg/testutil"
)

func lesser(lhs, rhs uint64) assert.Comparison {
	f := func() bool {
		return lhs < rhs
	}
	return f
}

func TestKvManagerGetSet(t *testing.T) {
	mgr := NewKvManager()

	oldver, items := mgr.List("ns1")
	assert.Nil(t, items)
	assert.Equal(t, uint64(0), oldver)

	_, err := mgr.Get("ns1", "key1")
	assert.Equal(t, KvErrorNotFound, err)

	mgr.Set("ns1", "key1", "value1")
	newver, items := mgr.List("ns1")
	assert.Condition(t, lesser(oldver, newver))
	assert.ElementsMatch(t, []KvItem{{Key: "key1", Value: "value1"}}, items)
	oldver = newver

	item, err := mgr.Get("ns1", "key1")
	assert.Nil(t, err)
	assert.Equal(t, KvItem{Key: "key1", Value: "value1"}, item)

	_, err = mgr.Get("ns1", "key2")
	assert.Equal(t, KvErrorNotFound, err)

	mgr.Set("ns1", "key2", "value2")
	newver, items = mgr.List("ns1")
	assert.Condition(t, lesser(oldver, newver))
	assert.ElementsMatch(t,
		[]KvItem{{Key: "key1", Value: "value1"},
			{Key: "key2", Value: "value2"}},
		items)
	oldver = newver

	mgr.Delete("ns1", "key2")
	newver, items = mgr.List("ns1")
	assert.Condition(t, lesser(oldver, newver))
	assert.ElementsMatch(t, []KvItem{{Key: "key1", Value: "value1"}}, items)
	oldver = newver

	// delete non-existing key
	mgr.Delete("ns1", "key2")
	newver1, items1 := mgr.List("ns1")
	assert.Equal(t, newver, newver1)
	assert.ElementsMatch(t, items, items1)

	mgr.Set("ns1", "key1", "value3")
	newver, items = mgr.List("ns1")
	assert.Condition(t, lesser(oldver, newver))
	assert.ElementsMatch(t, []KvItem{{Key: "key1", Value: "value3"}}, items)
}

func TestKvManagerWatchNotRunning(t *testing.T) {
	mgr := NewKvManager()

	// not serving watches
	_, _, err := mgr.Watch("ns1", 0)
	assert.Equal(t, KvErrorInternal, err)
}

func initWatching(t *testing.T, mgr *KvManager, stopCh <-chan struct{}) {
	go mgr.ServeWatch(stopCh)
	tu.WaitFor(t, "Waiting for watching enabled", 500*time.Millisecond,
		func(bool) (bool, error) { return mgr.servingWatch, nil })
}

func TestKvManagerWatchImmediate(t *testing.T) {
	mgr := NewKvManager()
	initWatching(t, mgr, nil)

	// setup few items
	mgr.Set("ns1", "key1", "value1")
	mgr.Set("ns1", "key10", "value10")
	veryoldver, _ := mgr.List("ns1")

	mgr.Set("ns1", "key2", "value2")
	newver, items := mgr.List("ns1")
	assert.Equal(t, 3, len(items))
	oldver := newver

	// do some updates before watch
	mgr.Set("ns1", "key1", "value1_1")
	mgr.Delete("ns1", "key2")
	mgr.Set("ns1", "key3", "value3")

	newver, acts, err := mgr.Watch("ns1", oldver)
	assert.Nil(t, err)
	assert.Condition(t, lesser(oldver, newver))
	assert.ElementsMatch(t,
		[]KvAction{
			{Action: OP_SET, Item: KvItem{Key: "key1", Value: "value1_1"}},
			{Action: OP_SET, Item: KvItem{Key: "key3", Value: "value3"}},
			{Action: OP_DELETE, Item: KvItem{Key: "key2", Value: "value2"}}},
		acts)
	oldver = newver

	// get updates from much older version
	newver1, acts1, err1 := mgr.Watch("ns1", veryoldver)
	assert.Nil(t, err1)
	assert.Equal(t, newver, newver1)
	assert.ElementsMatch(t, acts, acts1)
}

func TestKvManagerWatchCoalesce(t *testing.T) {
	mgr := NewKvManager()
	initWatching(t, mgr, nil)

	// setup few items
	mgr.Set("ns1", "key1", "value1")
	oldver, _ := mgr.List("ns1")

	mgr.Set("ns1", "key2", "value2")
	oldver, _, _ = mgr.Watch("ns1", oldver)

	// delete followed by set -> set only
	mgr.Delete("ns1", "key2")
	mgr.Set("ns1", "key2", "value2_1")

	newver, acts1, err := mgr.Watch("ns1", oldver)
	assert.Nil(t, err)
	assert.Condition(t, lesser(oldver, newver))
	assert.ElementsMatch(t,
		[]KvAction{
			{Action: OP_SET, Item: KvItem{Key: "key2", Value: "value2_1"}}},
		acts1)
	oldver = newver

	// add followed by delete -> delete only
	mgr.Set("ns1", "key3", "value3")
	mgr.Delete("ns1", "key3")
	newver, acts2, err := mgr.Watch("ns1", oldver)
	assert.Nil(t, err)
	assert.Condition(t, lesser(oldver, newver))
	assert.ElementsMatch(t,
		[]KvAction{
			{Action: OP_DELETE, Item: KvItem{Key: "key3", Value: "value3"}}},
		acts2)
}

func TestKvManagerWatchWait(t *testing.T) {
	mgr := NewKvManager()
	initWatching(t, mgr, nil)

	// setup few items
	mgr.Set("ns1", "key1", "value1")
	mgr.Set("ns1", "key2", "value2")
	newver, items := mgr.List("ns1")
	assert.Equal(t, 2, len(items))

	var allacts []KvAction
	go func() {
		oldver := newver
		for {
			ver, acts, err := mgr.Watch("ns1", oldver)
			assert.Nil(t, err)
			if err == nil {
				assert.Condition(t, lesser(oldver, ver))
				allacts = append(allacts, acts...)
				oldver = ver
			}
		}
	}()
	tu.WaitFor(t, "Waiting for pending watches", 500*time.Millisecond,
		func(bool) (bool, error) { return len(mgr.pending["ns1"]) > 0, nil })

	// do some updates after watch
	mgr.Delete("ns1", "key1")
	mgr.Set("ns1", "key3", "value3_1")
	mgr.Set("ns1", "key2", "value2_1")

	tu.WaitFor(t, "Waiting for watch results", 500*time.Millisecond,
		func(bool) (bool, error) { return len(allacts) == 3, nil })

	assert.ElementsMatch(t,
		[]KvAction{
			{Action: OP_DELETE, Item: KvItem{Key: "key1", Value: "value1"}},
			{Action: OP_SET, Item: KvItem{Key: "key3", Value: "value3_1"}},
			{Action: OP_SET, Item: KvItem{Key: "key2", Value: "value2_1"}}},
		allacts)
}

func TestKvManagerWatchMultiple(t *testing.T) {
	mgr := NewKvManager()
	initWatching(t, mgr, nil)
	allns := []string{"ns0", "ns1", "ns2"}

	foreachns := func(f func(ns string)) {
		for _, n := range allns {
			f(n)
		}
	}
	vers := make(map[string]uint64)

	// setup few items
	foreachns(func(ns string) {
		mgr.Set(ns, "key1", "value1")
		newver, _ := mgr.List(ns)
		vers[ns] = newver
		mgr.Set(ns, "key2", "value2")
	})

	// watch each namespace - should return immediately
	foreachns(func(ns string) {
		newver, acts, err := mgr.Watch(ns, vers[ns])
		assert.Nil(t, err)
		assert.Condition(t, lesser(vers[ns], newver))
		assert.Equal(t,
			[]KvAction{
				{Action: OP_SET, Item: KvItem{Key: "key2", Value: "value2"}}},
			acts)
		vers[ns] = newver
	})

	// setup multiple watches in each namespace
	var wg sync.WaitGroup
	foreachns(func(ns string) {
		for w := 0; w < 5; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				acts := make([]KvAction, 0)
				startver := vers[ns]
				for len(acts) < 2 {
					newver, a, err := mgr.Watch(ns, startver)
					assert.Nil(t, err)
					assert.Condition(t, lesser(startver, newver))
					acts = append(acts, a...)
					startver = newver
				}
				assert.ElementsMatch(t,
					[]KvAction{
						{Action: OP_DELETE, Item: KvItem{Key: "key1", Value: "value1"}},
						{Action: OP_SET, Item: KvItem{Key: "key2", Value: "value2_1"}}},
					acts)
			}()
		}
	})
	foreachns(func(ns string) {
		tu.WaitFor(t, "Waiting for pending watches", 500*time.Millisecond,
			func(bool) (bool, error) { return len(mgr.pending[ns]) >= 5, nil })
	})
	// unblock the watches
	foreachns(func(ns string) {
		mgr.Delete(ns, "key1")
		mgr.Set(ns, "key2", "value2_1")
	})
	watchesUnblocked := false
	go func() {
		wg.Wait()
		watchesUnblocked = true
	}()
	tu.WaitFor(t, "Waiting for watches to unblock", 500*time.Millisecond,
		func(bool) (bool, error) { return watchesUnblocked, nil })
}

func TestKvManagerWatchCancel(t *testing.T) {
	mgr := NewKvManager()
	ch := make(chan struct{})
	serveEnded := false
	go func() {
		mgr.ServeWatch(ch)
		serveEnded = true
	}()
	tu.WaitFor(t, "Waiting for watching enabled", 500*time.Millisecond,
		func(bool) (bool, error) { return mgr.servingWatch, nil })

	var wg sync.WaitGroup
	for n := 0; n < 2; n++ {
		nsname := fmt.Sprintf("ns%d", n)
		for i := 0; i < 5; i++ {
			wg.Add(1)
			oldver := uint64(i + 1)
			go func() {
				defer wg.Done()
				ver, acts, err := mgr.Watch(nsname, oldver)
				assert.Nil(t, err)
				assert.Equal(t, oldver, ver)
				assert.Empty(t, acts)
			}()
		}
	}
	tu.WaitFor(t, "Waiting for pending watches", 500*time.Millisecond,
		func(bool) (bool, error) {
			len_ns0 := len(mgr.pending["ns0"])
			len_ns1 := len(mgr.pending["ns1"])
			return len_ns0 >= 5 && len_ns1 >= 5, nil
		})

	watchStopped := false
	go func() {
		wg.Wait()
		watchStopped = true
	}()

	close(ch)
	tu.WaitFor(t, "Waiting for serve watch to end", 500*time.Millisecond,
		func(bool) (bool, error) { return serveEnded, nil })
	assert.False(t, mgr.servingWatch)
	assert.Empty(t, mgr.pending)
	tu.WaitFor(t, "Waiting for watch to return", 500*time.Millisecond,
		func(bool) (bool, error) { return watchStopped, nil })
}

func TestKvManagerWatchTooOld(t *testing.T) {
	mgr := NewKvManager()
	mgr.maxRetained = 2
	initWatching(t, mgr, nil)

	mgr.Set("ns1", "init", "0")
	ver, _ := mgr.List("ns1")

	for i := 0; i <= 2*mgr.maxRetained; i++ {
		k := fmt.Sprintf("key%d", i)
		mgr.Set("ns1", k, "value")
		mgr.Delete("ns1", k)
	}
	_, _, err := mgr.Watch("ns1", ver)
	assert.Equal(t, KvErrorVersionTooOld, err)

	newver, items := mgr.List("ns1")
	assert.Condition(t, lesser(ver, newver))
	assert.ElementsMatch(t, []KvItem{{Key: "init", Value: "0"}}, items)
}
