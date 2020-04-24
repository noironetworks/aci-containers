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
	"io"
	"net"
	"net/rpc"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	tu "github.com/noironetworks/aci-containers/pkg/testutil"
)

func setupRemote(t *testing.T) (mgr *KvManager, clientConn net.Conn) {
	mgr = NewKvManager()
	initWatching(t, mgr, nil)
	mgr.Set("ns1", "key1", "value1")
	mgr.Set("ns1", "key2", "value2")
	mgr.Set("ns2", "key2_1", "value1")
	mgr.Set("ns2", "key2_2", "value2")
	mgr.Set("ns3", "key3_1", "value1")
	mgr.Set("ns3", "key3_2", "value2")

	serverConn, clientConn := net.Pipe()

	server, _, err := NewKvRpcServer(mgr)
	assert.Nil(t, err)
	go server.ServeCodec(NewMultiplexCodec(serverConn))
	return
}

func TestKvWatcherOps(t *testing.T) {
	remoteMgr, clientConn := setupRemote(t)

	allItems := make(map[string][]KvItem)
	allActions := make(map[string][]KvAction)
	allItems["ns1"] = make([]KvItem, 0)
	allItems["ns3"] = make([]KvItem, 0)
	allActions["ns1"] = make([]KvAction, 0)
	allActions["ns3"] = make([]KvAction, 0)

	allfunc := func(ns string, items []KvItem) {
		allItems[ns] = items
	}

	updatefunc := func(ns string, acts []KvAction) {
		allActions[ns] = append(allActions[ns], acts...)
	}

	log := logrus.New()
	log.Level = logrus.DebugLevel
	w := NewKvWatcher([]string{"ns1", "ns3"}, log, allfunc, updatefunc)
	go w.Watch(nil)
	w.ServeConn(NewMultiplexCodec(clientConn))

	tu.WaitFor(t, "Waiting for all ns1 items", 500*time.Millisecond,
		func(bool) (bool, error) { return len(allItems["ns1"]) == 2, nil })
	assert.ElementsMatch(t,
		[]KvItem{{Key: "key1", Value: "value1"},
			{Key: "key2", Value: "value2"}},
		allItems["ns1"])

	tu.WaitFor(t, "Waiting for all ns3 items", 500*time.Millisecond,
		func(bool) (bool, error) { return len(allItems["ns3"]) == 2, nil })
	assert.ElementsMatch(t,
		[]KvItem{{Key: "key3_1", Value: "value1"},
			{Key: "key3_2", Value: "value2"}},
		allItems["ns3"])

	remoteMgr.Set("ns1", "key2", "value2_1")
	remoteMgr.Delete("ns1", "key1")
	remoteMgr.Set("ns1", "key3", "value3")
	remoteMgr.Set("ns2", "key2_1", "value1_1")
	remoteMgr.Set("ns3", "key3_2", "value2_1")
	remoteMgr.Delete("ns3", "key3_1")
	remoteMgr.Set("ns3", "key3_3", "value3")

	tu.WaitFor(t, "Waiting for updated ns1 items", 500*time.Millisecond,
		func(bool) (bool, error) { return len(allActions["ns1"]) == 3, nil })
	assert.ElementsMatch(t,
		[]KvAction{
			{Action: OP_SET, Item: KvItem{Key: "key2", Value: "value2_1"}},
			{Action: OP_SET, Item: KvItem{Key: "key3", Value: "value3"}},
			{Action: OP_DELETE, Item: KvItem{Key: "key1", Value: "value1"}}},
		allActions["ns1"])

	tu.WaitFor(t, "Waiting for updated ns3 items", 500*time.Millisecond,
		func(bool) (bool, error) { return len(allActions["ns3"]) == 3, nil })
	assert.ElementsMatch(t,
		[]KvAction{
			{Action: OP_SET, Item: KvItem{Key: "key3_2", Value: "value2_1"}},
			{Action: OP_SET, Item: KvItem{Key: "key3_3", Value: "value3"}},
			{Action: OP_DELETE, Item: KvItem{Key: "key3_1", Value: "value1"}}},
		allActions["ns3"])
}

func TestKvWatcherConnError(t *testing.T) {
	serverConn, clientConn := net.Pipe()

	log := logrus.New()
	log.Level = logrus.DebugLevel
	w := NewKvWatcher([]string{"ns1"}, log, nil, nil)
	go w.Watch(nil)
	w.ServeConn(NewMultiplexCodec(clientConn))

	tu.WaitFor(t, "Waiting for conn setup", 500*time.Millisecond,
		func(bool) (bool, error) { return len(w.conns) > 0, nil })

	serverConn.Close()
	tu.WaitFor(t, "Waiting for conn close", 500*time.Millisecond,
		func(bool) (bool, error) { return len(w.conns) == 0, nil })
}

type fakeKvService struct {
}

func (s *fakeKvService) List(args *RpcListArgs, reply *RpcListReply) error {
	reply.Items = []KvItem{{Key: "key1", Value: "value1"},
		{Key: "key2", Value: "value2"}}
	reply.Version = 1
	return nil
}

func (s *fakeKvService) Watch(args *RpcWatchArgs, reply *RpcWatchReply) error {
	time.Sleep(100 * time.Millisecond)
	return KvErrorVersionTooOld
}

func TestKvWatcherReinit(t *testing.T) {
	rpcServer := rpc.NewServer()
	err := rpcServer.RegisterName("KvService", &fakeKvService{})
	assert.Nil(t, err)

	serverConn, clientConn := net.Pipe()
	go rpcServer.ServeCodec(NewMultiplexCodec(serverConn))

	allcount := 0
	allfunc := func(ns string, items []KvItem) {
		allcount = allcount + 1
	}
	log := logrus.New()
	log.Level = logrus.DebugLevel
	w := NewKvWatcher([]string{"ns1"}, log, allfunc, nil)
	go w.Watch(nil)
	w.ServeConn(NewMultiplexCodec(clientConn))

	tu.WaitFor(t, "Waiting for all items", 500*time.Millisecond,
		func(bool) (bool, error) { return allcount > 1, nil })
}

func TestKvWatcherCancel(t *testing.T) {
	_, clientConn := setupRemote(t)

	log := logrus.New()
	log.Level = logrus.DebugLevel
	w := NewKvWatcher([]string{"ns1"}, log, nil, nil)

	stopCh := make(chan struct{})
	watchEnded := false
	go func() {
		w.Watch(stopCh)
		watchEnded = true
	}()
	w.ServeConn(NewMultiplexCodec(clientConn))
	tu.WaitFor(t, "Waiting for watch start", 500*time.Millisecond,
		func(bool) (bool, error) { return len(w.conns) > 0, nil })

	close(stopCh)
	tu.WaitFor(t, "Waiting for watch end", 1000*time.Millisecond,
		func(bool) (bool, error) { return watchEnded, nil })
	// connection should be closed
	_, err := clientConn.Write([]byte{})
	assert.Equal(t, io.ErrClosedPipe, err)
}
