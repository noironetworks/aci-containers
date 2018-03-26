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
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/rpc"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	tu "github.com/noironetworks/aci-containers/pkg/testutil"
)

func setup(t *testing.T, mgr *KvManager) (net.Conn, net.Conn) {
	server, _, err := NewKvRpcServer(mgr)
	assert.Nil(t, err)
	serverConn, clientConn := net.Pipe()
	go server.ServeConn(serverConn)
	return serverConn, clientConn
}

func TestKvServiceList(t *testing.T) {
	mgr := NewKvManager()
	initWatching(t, mgr, nil)

	serverConn, clientConn := setup(t, mgr)
	client := rpc.NewClient(clientConn)
	reply := RpcListReply{}
	err := client.Call("KvService.List",
		&RpcListArgs{Namespace: "ns1"},
		&reply)
	assert.Nil(t, err)
	assert.Empty(t, reply.Items)
	assert.Equal(t, uint64(0), reply.Version)

	mgr.Set("ns1", "key1", "value1")
	mgr.Set("ns1", "key2", "value2")

	err = client.Call("KvService.List",
		&RpcListArgs{Namespace: "ns1"},
		&reply)
	assert.Nil(t, err)
	assert.ElementsMatch(t,
		[]KvItem{{Key: "key1", Value: "value1"},
			{Key: "key2", Value: "value2"}},
		reply.Items)
	assert.Condition(t, lesser(0, reply.Version))

	serverConn.Close()
	clientConn.Close()
}

func callUnblocked(c *rpc.Call) bool {
	select {
	case <-c.Done:
		return true
	default:
		return false
	}
}

func TestKvServiceWatch(t *testing.T) {
	mgr := NewKvManager()
	initWatching(t, mgr, nil)
	mgr.Set("ns1", "key1", "value1")

	serverConn, clientConn := setup(t, mgr)
	client := rpc.NewClient(clientConn)

	list_reply := RpcListReply{}
	err := client.Call("KvService.List",
		&RpcListArgs{Namespace: "ns1"},
		&list_reply)
	assert.Nil(t, err)
	assert.Equal(t, 1, len(list_reply.Items))

	mgr.Set("ns1", "key2", "value2")
	mgr.Delete("ns1", "key1")

	// watch returns immediately with results
	watch_reply := RpcWatchReply{}
	err = client.Call("KvService.Watch",
		&RpcWatchArgs{Namespace: "ns1", Version: list_reply.Version},
		&watch_reply)
	assert.Nil(t, err)
	assert.ElementsMatch(t,
		[]KvAction{
			{Action: OP_SET, Item: KvItem{Key: "key2", Value: "value2"}},
			{Action: OP_DELETE, Item: KvItem{Key: "key1", Value: "value1"}}},
		watch_reply.Actions)
	assert.Condition(t, lesser(list_reply.Version, watch_reply.Version))

	// asynchronous watch
	watch_reply1 := RpcWatchReply{}
	call := client.Go("KvService.Watch",
		&RpcWatchArgs{Namespace: "ns1", Version: watch_reply.Version},
		&watch_reply1, nil)
	tu.WaitFor(t, "Waiting for pending watches", 500*time.Millisecond,
		func(bool) (bool, error) { return len(mgr.pending["ns1"]) > 0, nil })
	mgr.Set("ns1", "key3", "value3")

	tu.WaitFor(t, "Waiting for async watch reply", 500*time.Millisecond,
		func(bool) (bool, error) { return callUnblocked(call), nil })
	assert.Nil(t, call.Error)
	assert.ElementsMatch(t,
		[]KvAction{
			{Action: OP_SET, Item: KvItem{Key: "key3", Value: "value3"}}},
		watch_reply1.Actions)
	assert.Condition(t, lesser(watch_reply.Version, watch_reply1.Version))

	serverConn.Close()
	clientConn.Close()
}

func TestKvServiceAbortWatch(t *testing.T) {
	mgr := NewKvManager()
	initWatching(t, mgr, nil)

	server, svc, err := NewKvRpcServer(mgr)
	assert.Nil(t, err)
	serverConn, clientConn := net.Pipe()
	client := rpc.NewClient(clientConn)
	go server.ServeConn(serverConn)

	watch_reply := RpcWatchReply{}
	call := client.Go("KvService.Watch",
		&RpcWatchArgs{Namespace: "ns1", Version: uint64(0)},
		&watch_reply, nil)
	tu.WaitFor(t, "Waiting for pending watches", 500*time.Millisecond,
		func(bool) (bool, error) { return len(mgr.pending["ns1"]) > 0, nil })

	svc.abortWatch()

	tu.WaitFor(t, "Waiting for watch abort", 500*time.Millisecond,
		func(bool) (bool, error) { return callUnblocked(call), nil })
	assert.Nil(t, call.Error)
	assert.Equal(t, uint64(0), watch_reply.Version)
	assert.Empty(t, watch_reply.Actions)

	serverConn.Close()
	clientConn.Close()
}

func TestKvServiceListBadConnection(t *testing.T) {
	mgr := NewKvManager()
	initWatching(t, mgr, nil)

	serverConn, clientConn := setup(t, mgr)
	client := rpc.NewClient(clientConn)

	serverConn.Close()
	list_reply := RpcListReply{}
	err := client.Call("KvService.List",
		&RpcListArgs{Namespace: "ns1"},
		&list_reply)
	assert.NotNil(t, err)
	assert.NotContains(t, "KvError:", err)
}

func TestKvServiceWatchBadConnection(t *testing.T) {
	mgr := NewKvManager()
	initWatching(t, mgr, nil)

	serverConn, clientConn := setup(t, mgr)
	client := rpc.NewClient(clientConn)

	watch_reply := RpcWatchReply{}
	call := client.Go("KvService.Watch",
		&RpcWatchArgs{Namespace: "ns1", Version: uint64(0)},
		&watch_reply, nil)
	tu.WaitFor(t, "Waiting for pending watches", 500*time.Millisecond,
		func(bool) (bool, error) { return len(mgr.pending["ns1"]) > 0, nil })

	serverConn.Close()
	tu.WaitFor(t, "Waiting for async watch reply", 500*time.Millisecond,
		func(bool) (bool, error) { return callUnblocked(call), nil })

	assert.NotNil(t, call.Error)
	assert.NotContains(t, "KvError:", call.Error)
}

func TestMultiplexCodecInterleavedRead(t *testing.T) {
	c1, c2 := net.Pipe()
	c := NewMultiplexCodec(c2)
	enc := json.NewEncoder(c1)

	type bodyType struct {
		F1, F2 uint64
	}
	type requestBody struct {
		rpc.Request
		body bodyType
	}
	type responseBody struct {
		rpc.Response
		body bodyType
	}
	var c1_messages []codecMessage
	var expected_requests []requestBody
	var expected_responses []responseBody
	for i := 1; i <= 3; i++ {
		for j := 0; j < i; j++ {
			id := uint64(i*10 + j)
			param := json.RawMessage(
				fmt.Sprintf(`{"F1": %d, "F2": %d}`, id, -id))
			c1_messages = append(c1_messages,
				codecMessage{IsRequest: true,
					Id: id, Method: "L", Params: &param})
			expected_requests = append(expected_requests,
				requestBody{
					Request: rpc.Request{Seq: id, ServiceMethod: "L"},
					body:    bodyType{F1: id, F2: -id}})
		}
		for j := 0; j < i; j++ {
			id := uint64(i*10 + j)
			res := json.RawMessage(
				fmt.Sprintf(`{"F1": %d, "F2": %d}`, -id, id))
			c1_messages = append(c1_messages,
				codecMessage{IsRequest: false,
					Id: id, Method: "W", Result: &res})
			expected_responses = append(expected_responses,
				responseBody{
					Response: rpc.Response{Seq: id, ServiceMethod: "W"},
					body:     bodyType{F1: -id, F2: id}})
		}
	}

	var c2_requests []requestBody
	var c2_responses []responseBody
	go func() {
		for {
			req := requestBody{}
			err := c.ReadRequestHeader(&req.Request)
			assert.Nil(t, err)
			err = c.ReadRequestBody(&req.body)
			assert.Nil(t, err)
			c2_requests = append(c2_requests, req)
		}
	}()

	go func() {
		for {
			resp := responseBody{}
			err := c.ReadResponseHeader(&resp.Response)
			assert.Nil(t, err)
			err = c.ReadResponseBody(&resp.body)
			assert.Nil(t, err)
			c2_responses = append(c2_responses, resp)
		}
	}()
	for _, m := range c1_messages {
		err := enc.Encode(m)
		assert.Nil(t, err)
	}
	tu.WaitFor(t, "Waiting for all request", 500*time.Millisecond,
		func(bool) (bool, error) {
			return len(c2_requests) == len(expected_requests), nil
		})
	assert.ElementsMatch(t, expected_requests, c2_requests)
	tu.WaitFor(t, "Waiting for all responses", 500*time.Millisecond,
		func(bool) (bool, error) {
			return len(c2_responses) == len(expected_responses), nil
		})
	assert.ElementsMatch(t, expected_responses, c2_responses)
}

func TestMultiplexCodecConcurrentWrite(t *testing.T) {
	c1, c2 := net.Pipe()
	c := NewMultiplexCodec(c1)
	dec := json.NewDecoder(c2)

	expected_reqIds := make(map[uint64]struct{})
	expected_respIds := make(map[uint64]struct{})
	count := 10
	go func() {
		for id := 1; id <= count; id++ {
			req := &rpc.Request{Seq: uint64(id), ServiceMethod: "L"}
			expected_reqIds[uint64(id)] = struct{}{}
			err := c.WriteRequest(req, "abc")
			assert.Nil(t, err)
			time.Sleep(5 * time.Millisecond)
		}
	}()
	go func() {
		for id := 1; id <= count; id++ {
			resp := &rpc.Response{Seq: uint64(id), ServiceMethod: "W"}
			expected_respIds[uint64(id)] = struct{}{}
			err := c.WriteResponse(resp, "xyz")
			assert.Nil(t, err)
			time.Sleep(5 * time.Millisecond)
		}
	}()
	reqIds := make(map[uint64]struct{})
	respIds := make(map[uint64]struct{})
	for len(reqIds) < count || len(respIds) < count {
		var m codecMessage
		err := dec.Decode(&m)
		assert.Nil(t, err)
		if m.IsRequest {
			reqIds[m.Id] = struct{}{}
		} else {
			respIds[m.Id] = struct{}{}
		}
	}
	assert.Equal(t, expected_reqIds, reqIds)
	assert.Equal(t, expected_respIds, respIds)
}

func TestMultiplexCodecReadConnError(t *testing.T) {
	c1, c2 := net.Pipe()
	c := NewMultiplexCodec(c2)
	enc := json.NewEncoder(c1)

	var reqErr, respErr error
	reqRead, respRead := false, false
	go func() {
		for reqErr == nil {
			reqErr = c.ReadRequestHeader(&rpc.Request{})
			if reqErr == nil {
				reqRead = true
			}
		}
	}()
	go func() {
		for respErr == nil {
			respErr = c.ReadResponseHeader(&rpc.Response{})
			if respErr == nil {
				respRead = true
			}
		}
	}()
	// send sentinel messages
	param := json.RawMessage(`{"A": 1}`)
	result := json.RawMessage(`{"Z": 1}`)
	err := enc.Encode(&codecMessage{IsRequest: true, Id: uint64(1),
		Method: "L", Params: &param})
	assert.Nil(t, err)
	err = enc.Encode(&codecMessage{IsRequest: false, Id: uint64(1),
		Method: "W", Result: &result})
	assert.Nil(t, err)
	tu.WaitFor(t, "Waiting for sentinel reads",
		500*time.Millisecond,
		func(bool) (bool, error) { return reqRead && respRead, nil })
	c1.Close()
	tu.WaitFor(t, "Waiting for request read error",
		500*time.Millisecond,
		func(bool) (bool, error) { return reqErr != nil, nil })
	tu.WaitFor(t, "Waiting for response read error",
		500*time.Millisecond,
		func(bool) (bool, error) { return respErr != nil, nil })
	assert.Equal(t, io.EOF, reqErr)
	assert.Equal(t, io.EOF, respErr)
}

func TestMultiplexCodecWriteConnError(t *testing.T) {
	c1, c2 := net.Pipe()
	c := NewMultiplexCodec(c1)

	c2.Close()
	err := c.WriteRequest(
		&rpc.Request{Seq: uint64(1), ServiceMethod: "L"}, "abc")
	assert.Equal(t, io.ErrClosedPipe, err)

	err = c.WriteResponse(
		&rpc.Response{Seq: uint64(1), ServiceMethod: "W"}, "abc")
	assert.Equal(t, io.ErrClosedPipe, err)
}

func TestMultiplexCodecClose(t *testing.T) {
	c1, _ := net.Pipe()
	c := NewMultiplexCodec(c1)
	assert.Equal(t, c1, c.Conn())
	c.Close()
	assert.Equal(t, io.ErrClosedPipe, c.WriteRequest(&rpc.Request{}, ""))
}

func TestMultiplexCodecReadDrain(t *testing.T) {
	c1, _ := net.Pipe()
	c := NewMultiplexCodec(c1)
	assert.Nil(t, c.ReadRequestBody(nil))
	assert.Nil(t, c.ReadResponseBody(nil))
}

func TestMultiplexCodecBadResponseError(t *testing.T) {
	c1, c2 := net.Pipe()
	c := NewMultiplexCodec(c2)
	enc := json.NewEncoder(c1)
	count := 0
	go func() {
		for {
			resp := rpc.Response{}
			err := c.ReadResponseHeader(&resp)
			if err == nil {
				assert.Contains(t, resp.Error, "No error specified")
			} else {
				assert.Contains(t, err.Error(), "Invalid error")
			}
			count++
		}
	}()
	err := enc.Encode(&codecMessage{IsRequest: false, Id: uint64(1),
		Method: "W", Error: 42})
	assert.Nil(t, err)
	err = enc.Encode(&codecMessage{IsRequest: false, Id: uint64(1),
		Method: "W", Error: ""})
	assert.Nil(t, err)
	tu.WaitFor(t, "Waiting for all errors",
		500*time.Millisecond,
		func(bool) (bool, error) { return count >= 2, nil })
}

func TestMultiplexCodecServerClient(t *testing.T) {
	type numPair struct {
		First, Second int
	}
	conn1, conn2 := net.Pipe()
	c1 := NewMultiplexCodec(conn1)
	c2 := NewMultiplexCodec(conn2)
	count := 10
	wg := sync.WaitGroup{}
	serverFunc := func(c rpc.ServerCodec, other string) {
		for i := 1; i <= count; i++ {
			req, pair, resp := rpc.Request{}, numPair{}, rpc.Response{}
			assert.Nil(t, c.ReadRequestHeader(&req))
			assert.Contains(t, req.ServiceMethod, other+"-add-sub")
			assert.Nil(t, c.ReadRequestBody(&pair))
			time.Sleep(2 * time.Millisecond)
			pair = numPair{First: pair.First + pair.Second,
				Second: pair.First - pair.Second}
			resp.Seq = req.Seq
			resp.ServiceMethod = req.ServiceMethod
			assert.Nil(t, c.WriteResponse(&resp, &pair))
		}
		wg.Done()
	}
	clientFunc := func(c rpc.ClientCodec, name string) {
		for i := 1; i <= count; i++ {
			req := rpc.Request{Seq: uint64(1),
				ServiceMethod: fmt.Sprintf("%s-add-sub-%d", name, i)}
			pair, resp := numPair{3 * i, 2 * i}, rpc.Response{}
			assert.Nil(t, c.WriteRequest(&req, &pair))

			assert.Nil(t, c.ReadResponseHeader(&resp))
			assert.Equal(t, req.Seq, resp.Seq)
			assert.Equal(t, resp.ServiceMethod, resp.ServiceMethod)
			assert.Nil(t, c.ReadResponseBody(&pair))
			assert.Equal(t, numPair{5 * i, i}, pair)
			time.Sleep(3 * time.Millisecond)
		}
		wg.Done()
	}
	wg.Add(4)
	go serverFunc(c1, "peer2")
	go clientFunc(c1, "peer1")
	go serverFunc(c2, "peer1")
	go clientFunc(c2, "peer2")
	wg.Wait()
}

func TestMapToStruct(t *testing.T) {
	type A struct {
		F1 int
		F2 []string
	}
	m := make(map[string]interface{})
	m["F1"] = 10
	m["F2"] = []string{"1", "2", "3"}
	a := &A{}
	assert.Nil(t, MapToStruct(m, a))
	assert.Equal(t, A{F1: 10, F2: []string{"1", "2", "3"}}, *a)
}

func TestStructToMap(t *testing.T) {
	type A struct {
		F1 int
		F2 []string
	}
	m := make(map[string]interface{})
	m["F1"] = float64(10)
	m["F2"] = []interface{}{"1", "2", "3"}
	a := &A{F1: 10, F2: []string{"1", "2", "3"}}
	assert.Equal(t, m, StructToMap(a))
}
