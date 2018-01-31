// Copyright 2017 Cisco Systems, Inc.
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

package cf_etcd

import (
	"testing"
	"time"

	"github.com/Sirupsen/logrus"
	etcdclient "github.com/coreos/etcd/client"
	"github.com/stretchr/testify/assert"
	"golang.org/x/net/context"

	etcd_f "github.com/noironetworks/aci-containers/pkg/cf_etcd_fakes"
	tu "github.com/noironetworks/aci-containers/pkg/testutil"
)

func TestCfEtcdWatcher(t *testing.T) {
	updates := make(map[string]bool)
	handler := func(action *string, node *etcdclient.Node) error {
		updates[*action+"|"+node.Key] = true
		return nil
	}

	log := logrus.New()
	log.Level = logrus.DebugLevel

	kapi := etcd_f.NewFakeEtcdKeysApi(log)
	ctx := context.Background()
	kapi.Set(ctx, "/a", "", nil)
	kapi.Set(ctx, "/a/b", "", nil)
	kapi.Set(ctx, "/a/b/c", "c", nil)
	kapi.Set(ctx, "/a/b/d", "d", nil)

	watcher := NewEtcdWatcher(kapi, "/a", handler, log)
	ch := make(chan struct{})

	go func() {
		watcher.Run(ch)
	}()
	tu.WaitFor(t, "Waiting to sync", 500*time.Millisecond,
		func(bool) (bool, error) { return watcher.Synced(), nil })
	assert.Nil(t, watcher.Error())
	assert.Contains(t, updates, "set|/a")
	assert.Contains(t, updates, "set|/a/b")
	assert.Contains(t, updates, "set|/a/b/c")
	assert.Contains(t, updates, "set|/a/b/d")

	updates = make(map[string]bool)
	kapi.FakeWatcher.Enqueue(&etcdclient.Response{
		Node:   &etcdclient.Node{Key: "/a/b/e", Value: "e"},
		Action: "set"})
	tu.WaitFor(t, "Waiting for update - set new", 500*time.Millisecond,
		func(bool) (bool, error) { return updates["set|/a/b/e"], nil })

	kapi.FakeWatcher.Enqueue(&etcdclient.Response{
		Node:   &etcdclient.Node{Key: "/a/b/c", Value: "c1"},
		Action: "set"})
	tu.WaitFor(t, "Waiting for update - set existing", 500*time.Millisecond,
		func(bool) (bool, error) { return updates["set|/a/b/c"], nil })

	kapi.FakeWatcher.Enqueue(&etcdclient.Response{
		Node:   &etcdclient.Node{Key: "/a/b/d", Value: ""},
		Action: "delete"})
	tu.WaitFor(t, "Waiting for update - delete", 500*time.Millisecond,
		func(bool) (bool, error) { return updates["delete|/a/b/d"], nil })

	close(ch)
}

func TestCfEtcdWatcherCancel(t *testing.T) {
	log := logrus.New()
	log.Level = logrus.DebugLevel

	handler := func(action *string, node *etcdclient.Node) error { return nil }
	kapi := etcd_f.NewFakeEtcdKeysApi(log)

	watcher := NewEtcdWatcher(kapi, "/a", handler, log)
	ch := make(chan struct{})
	runEnded := false
	go func() {
		watcher.Run(ch)
		runEnded = true
	}()
	tu.WaitFor(t, "Waiting to sync", 500*time.Millisecond,
		func(bool) (bool, error) { return watcher.Synced(), nil })
	close(ch)
	tu.WaitFor(t, "Waiting for Run() to end", 1000*time.Millisecond,
		func(bool) (bool, error) { return runEnded, nil })
}

func TestCfEtcdEpName(t *testing.T) {
	ep := &EpInfo{AppName: "app", InstanceIndex: 1}
	assert.Equal(t, "app (1)", ep.EpName("c"))

	ep.InstanceIndex = INST_IDX_STAGING
	assert.Equal(t, "app (staging)", ep.EpName("c"))

	ep.InstanceIndex = INST_IDX_TASK
	assert.Equal(t, "app (task)", ep.EpName("c"))

	ep.TaskName = "errand"
	assert.Equal(t, "app (task errand)", ep.EpName("c"))

	ep.AppName = ""
	assert.Equal(t, "c", ep.EpName("c"))
}
