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
	"io"
	"net"
	"net/rpc"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	tu "github.com/noironetworks/aci-containers/pkg/testutil"
)

func newLogger() (log *logrus.Logger) {
	log = logrus.New()
	log.Level = logrus.DebugLevel
	return
}

type MockListener struct {
	conn    net.Conn
	conns   chan net.Conn
	stopped bool
}

func NewMockListener(c net.Conn) *MockListener {
	l := &MockListener{conn: c, conns: make(chan net.Conn, 1)}
	if c != nil {
		l.conns <- c
	}
	return l
}

func (l *MockListener) Addr() net.Addr {
	return l.conn.LocalAddr()
}

func (l *MockListener) Accept() (net.Conn, error) {
	c := <-l.conns
	l.conn = c
	return c, nil
}

func (l *MockListener) Close() error {
	if !l.stopped {
		close(l.conns)
		l.stopped = true
	}
	return nil
}

type WatcherWrapper struct {
	allItems   []KvItem
	allActions []KvAction
	W          *KvWatcher
}

func NewWatchWrapper(ns string) *WatcherWrapper {
	r := &WatcherWrapper{allItems: make([]KvItem, 0),
		allActions: make([]KvAction, 0)}
	allfunc := func(n string, items []KvItem) {
		if n == ns {
			r.allItems = items
		}
	}
	updatefunc := func(n string, acts []KvAction) {
		if n == ns {
			r.allActions = append(r.allActions, acts...)
		}
	}
	r.W = NewKvWatcher([]string{ns}, newLogger(), allfunc, updatefunc)
	return r
}

func NewTestKvManager(t *testing.T, ns_prefix string) *KvManager {
	mgr := NewKvManager()
	initWatching(t, mgr, nil)
	ns1 := ns_prefix + "ns1"
	ns2 := ns_prefix + "ns2"
	mgr.Set(ns1, "key1", "value1")
	mgr.Set(ns1, "key2", "value2")
	mgr.Set(ns2, "key2_1", "value1")
	mgr.Set(ns2, "key2_2", "value2")
	return mgr
}

func doTestServerClientRun(t *testing.T,
	setupLocal func(c_local net.Conn) *WatcherWrapper) {
	c_local, c_remote := net.Pipe()
	cdc_remote := NewMultiplexCodec(c_remote)

	remote_mgr := NewTestKvManager(t, "remote-")
	remote_rpc_server, _, _ := NewKvRpcServer(remote_mgr)
	remote_rpc_client := rpc.NewClientWithCodec(cdc_remote)
	go remote_rpc_server.ServeCodec(cdc_remote)

	local_wr := setupLocal(c_local)
	// Verify we can receive remote items
	tu.WaitFor(t, "Waiting for all remote items", 500*time.Millisecond,
		func(bool) (bool, error) { return len(local_wr.allItems) == 2, nil })
	assert.ElementsMatch(t,
		[]KvItem{{Key: "key1", Value: "value1"},
			{Key: "key2", Value: "value2"}},
		local_wr.allItems)

	// Verify we can serve local items
	reply := RpcListReply{}
	err := remote_rpc_client.Call("KvService.List",
		&RpcListArgs{Namespace: "local-ns1"},
		&reply)
	assert.Nil(t, err)
	assert.ElementsMatch(t,
		[]KvItem{{Key: "key1", Value: "value1"},
			{Key: "key2", Value: "value2"}},
		reply.Items)

	// Install a watch from remote side before closing connection
	replyWatch := RpcWatchReply{}
	remote_rpc_client.Go("KvService.Watch",
		&RpcWatchArgs{Namespace: "local-ns1", Version: reply.Version},
		&replyWatch, nil)

	// Close remote side of connection -> verify local is also closed
	c_remote.Close()
	err = nil
	tu.WaitFor(t, "Waiting for local conn close", 500*time.Millisecond,
		func(bool) (bool, error) {
			_, err = c_local.Write([]byte("a"))
			return err != nil, nil
		})
	assert.Equal(t, io.ErrClosedPipe, err)
}

func TestKvServerRun(t *testing.T) {
	setupLocalServer := func(c_local net.Conn) *WatcherWrapper {
		local_wr := NewWatchWrapper("remote-ns1")
		local_mgr := NewTestKvManager(t, "local-")
		listnr := NewMockListener(c_local)
		kvserver := NewKvServer(
			func() (net.Listener, error) { return listnr, nil },
			local_mgr, local_wr.W, newLogger())
		go kvserver.Watcher().Watch(nil)
		go kvserver.Run(nil)
		return local_wr
	}
	doTestServerClientRun(t, setupLocalServer)
}

func TestKvServerReconnectClient(t *testing.T) {
	local_mgr := NewTestKvManager(t, "local-")
	local_wr := NewWatchWrapper("remote-something")
	listnr := NewMockListener(nil)
	kvserver := NewKvServer(
		func() (net.Listener, error) { return listnr, nil },
		local_mgr, local_wr.W, newLogger())
	go kvserver.Watcher().Watch(nil)
	go kvserver.Run(nil)

	expected_all_count := 2
	for iter := 1; iter <= 5; iter++ {
		iter_s := fmt.Sprintf("%d", iter)
		c_local, c_remote := net.Pipe()

		remote_watcher := NewWatchWrapper("local-ns1")
		remote_mgr := NewTestKvManager(t, "remote-"+iter_s+"-")
		kvclient := NewKvClient(
			func() (net.Conn, error) { return c_remote, nil },
			remote_mgr, remote_watcher.W, newLogger())
		go kvclient.Watcher().Watch(nil)
		listnr.conns <- c_local
		remote_stopCh := make(chan struct{})
		go kvclient.Run(remote_stopCh)

		// remote should get all data and updated
		tu.WaitFor(t, "Remote "+iter_s+" - Waiting for all items",
			500*time.Millisecond,
			func(bool) (bool, error) {
				return len(remote_watcher.allItems) == expected_all_count, nil
			})
		local_mgr.Set("local-ns1", "key4-"+iter_s, "value4")
		local_mgr.Set("local-ns1", "key5-"+iter_s, "value5")
		tu.WaitFor(t, "Remote "+iter_s+" - Waiting for actions",
			500*time.Millisecond,
			func(bool) (bool, error) {
				return len(remote_watcher.allActions) == 2, nil
			})

		// remote disconnects
		close(remote_stopCh)
		c_remote.Close()
		c_local.Close()

		// some intermediate changes
		local_mgr.Set("local-ns1", "key6-"+iter_s, "value6")
		local_mgr.Set("local-ns1", "key7-"+iter_s, "value7")
		expected_all_count += 4
	}
}

func TestKvClientRun(t *testing.T) {
	setupLocalClient := func(c_local net.Conn) *WatcherWrapper {
		local_wr := NewWatchWrapper("remote-ns1")
		local_mgr := NewTestKvManager(t, "local-")
		kvclient := NewKvClient(
			func() (net.Conn, error) { return c_local, nil },
			local_mgr, local_wr.W, newLogger())
		go kvclient.Watcher().Watch(nil)
		go kvclient.Run(nil)
		return local_wr
	}
	doTestServerClientRun(t, setupLocalClient)
}

func TestKvServerCancel(t *testing.T) {
	c_local, _ := net.Pipe()
	local_mgr := NewTestKvManager(t, "local-")
	listnr := NewMockListener(c_local)
	kvserver := NewKvServer(
		func() (net.Listener, error) { return listnr, nil },
		local_mgr, nil, newLogger())
	runEnded := false
	stopCh := make(chan struct{})
	go func() {
		kvserver.Run(stopCh)
		runEnded = true
	}()
	tu.WaitFor(t, "Waiting for server to accept", 500*time.Millisecond,
		func(bool) (bool, error) { return len(listnr.conns) == 0, nil })
	close(stopCh)
	tu.WaitFor(t, "Waiting for server run to end", 500*time.Millisecond,
		func(bool) (bool, error) { return runEnded == true, nil })
	_, err := c_local.Write([]byte("a"))
	assert.Equal(t, io.ErrClosedPipe, err)
}

func TestKvClientCancel(t *testing.T) {
	c_local, _ := net.Pipe()
	local_mgr := NewTestKvManager(t, "local-")
	connected := false
	kvclient := NewKvClient(
		func() (net.Conn, error) {
			connected = true
			return c_local, nil
		},
		local_mgr, nil, newLogger())
	runEnded := false
	stopCh := make(chan struct{})
	go func() {
		kvclient.Run(stopCh)
		runEnded = true
	}()
	tu.WaitFor(t, "Waiting for client to connect", 500*time.Millisecond,
		func(bool) (bool, error) { return connected, nil })
	close(stopCh)
	tu.WaitFor(t, "Waiting for client run to end", 500*time.Millisecond,
		func(bool) (bool, error) { return runEnded == true, nil })
	_, err := c_local.Write([]byte("a"))
	assert.Equal(t, io.ErrClosedPipe, err)
}

func TestKvServerListenLoop(t *testing.T) {
	local_mgr := NewTestKvManager(t, "local-")
	listenCount := 0
	kvserver := NewKvServer(
		func() (net.Listener, error) {
			listenCount++
			return nil, io.EOF
		},
		local_mgr, nil, newLogger())
	kvserver.errDelay = 10 * time.Millisecond
	go kvserver.Run(nil)
	tu.WaitFor(t, "Waiting for multiple listens", 500*time.Millisecond,
		func(bool) (bool, error) { return listenCount > 1, nil })
}

func TestKvClientConnectLoop(t *testing.T) {
	local_mgr := NewTestKvManager(t, "local-")
	connectCount := 0
	kvclient := NewKvClient(
		func() (net.Conn, error) {
			connectCount++
			return nil, io.EOF
		},
		local_mgr, nil, newLogger())
	kvclient.errDelay = 10 * time.Millisecond
	go kvclient.Run(nil)
	tu.WaitFor(t, "Waiting for multiple connects", 500*time.Millisecond,
		func(bool) (bool, error) { return connectCount > 1, nil })
}
