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
	"net"
	"net/rpc"
	"sync"
)

type RpcListArgs struct {
	Namespace string
}

type RpcListReply struct {
	Items   []KvItem
	Version uint64
}

type RpcWatchArgs struct {
	Namespace string
	Version   uint64
}

type RpcWatchReply struct {
	Actions []KvAction
	Version uint64
}

type KvService struct {
	manager      *KvManager
	abortWatchCh chan struct{}
	abortOnce    sync.Once
}

func NewKvService(mgr *KvManager) *KvService {
	return &KvService{manager: mgr, abortWatchCh: make(chan struct{})}
}

func (s *KvService) List(args *RpcListArgs, reply *RpcListReply) error {
	last, items := s.manager.List(args.Namespace)
	reply.Version = last
	reply.Items = items
	return nil
}

func (s *KvService) Watch(args *RpcWatchArgs, reply *RpcWatchReply) error {
	ch, err := s.manager.watchAsync(args.Namespace, args.Version)
	if err != nil {
		return err
	}
	select {
	case res, ok := <-ch:
		if ok {
			reply.Version = res.Version
			reply.Actions = res.Actions
			return res.Error
		}
	case <-s.abortWatchCh:
	}
	// watch aborted
	reply.Version = args.Version
	return nil
}

func (s *KvService) abortWatch() {
	s.abortOnce.Do(func() { close(s.abortWatchCh) })
}

func NewKvRpcServer(mgr *KvManager) (*rpc.Server, *KvService, error) {
	svc := NewKvService(mgr)
	rpcServer := rpc.NewServer()
	err := rpcServer.Register(svc)
	if err != nil {
		return nil, nil, err
	}
	return rpcServer, svc, nil
}

type MultiplexCodec struct {
	conn net.Conn
	dec  *json.Decoder
	enc  *json.Encoder

	writeLock sync.Locker

	readCond     *sync.Cond
	reading      bool
	readErr      error
	responses    []*codecMessage
	lastResponse *codecMessage
	requests     []*codecMessage
	lastRequest  *codecMessage
}

func NewMultiplexCodec(c net.Conn) *MultiplexCodec {
	m := &MultiplexCodec{conn: c,
		dec:       json.NewDecoder(c),
		enc:       json.NewEncoder(c),
		readCond:  sync.NewCond(new(sync.Mutex)),
		writeLock: new(sync.Mutex),
		reading:   false}

	// TODO use bounded queues
	m.responses = make([]*codecMessage, 0)
	m.requests = make([]*codecMessage, 0)
	return m
}

type codecMessageClientRequest struct {
	IsRequest bool        `json:"req"`
	Id        uint64      `json:"id"`
	Method    string      `json:"method"`
	Params    interface{} `json:"params"`
}

type codecMessageServerResponse struct {
	IsRequest bool        `json:"req"`
	Id        uint64      `json:"id"`
	Method    string      `json:"method"`
	Result    interface{} `json:"result"`
	Error     interface{} `json:"error"`
}

type codecMessage struct {
	IsRequest bool             `json:"req"`
	Id        uint64           `json:"id"`
	Method    string           `json:"method"`
	Params    *json.RawMessage `json:"params"`
	Result    *json.RawMessage `json:"result"`
	Error     interface{}      `json:"error"`
}

// Client codec methods
func (c *MultiplexCodec) WriteRequest(req *rpc.Request, b interface{}) error {
	c.writeLock.Lock()
	defer c.writeLock.Unlock()
	m := codecMessageClientRequest{
		IsRequest: true, Id: req.Seq, Method: req.ServiceMethod, Params: b}
	err := c.enc.Encode(m)
	return err
}

func (c *MultiplexCodec) ReadResponseHeader(resp *rpc.Response) (err error) {
	var msg *codecMessage
	// log.Println("Waiting to read RESPONSE header")
	if msg, err = c.read(false); err == nil {
		resp.ServiceMethod = msg.Method
		resp.Seq = msg.Id
		if msg.Error != nil || msg.Result == nil {
			e, ok := msg.Error.(string)
			if !ok {
				err = fmt.Errorf("Invalid error %v", msg.Error)
				return
			}
			if e == "" {
				e = "No error specified"
			}
			resp.Error = e
		}
		c.lastResponse = msg
	}
	return
}

func (c *MultiplexCodec) ReadResponseBody(body interface{}) error {
	if body == nil {
		return nil
	}
	return json.Unmarshal(*c.lastResponse.Result, body)
}

// Server codec methods
func (c *MultiplexCodec) ReadRequestHeader(req *rpc.Request) (err error) {
	var msg *codecMessage
	// log.Println("Waiting to read REQUEST header")
	if msg, err = c.read(true); err == nil {
		req.ServiceMethod = msg.Method
		req.Seq = msg.Id
		c.lastRequest = msg
	}
	return
}

func (c *MultiplexCodec) ReadRequestBody(body interface{}) error {
	if body == nil {
		return nil
	}
	return json.Unmarshal(*c.lastRequest.Params, body)
}

func (c *MultiplexCodec) WriteResponse(resp *rpc.Response,
	body interface{}) error {
	c.writeLock.Lock()
	defer c.writeLock.Unlock()
	m := codecMessageServerResponse{
		IsRequest: false, Id: resp.Seq, Method: resp.ServiceMethod}
	if resp.Error != "" {
		m.Error = resp.Error
	} else {
		m.Result = body
	}
	err := c.enc.Encode(m)
	return err
}

// Common codec methods
func (c *MultiplexCodec) Close() error {
	return c.conn.Close()
}

// Other methods
func (c *MultiplexCodec) Conn() net.Conn {
	return c.conn
}

func (c *MultiplexCodec) read(req bool) (msg *codecMessage, readErr error) {
	c.readCond.L.Lock()
	defer c.readCond.L.Unlock()
	found := false
	for !found && readErr == nil {
		if req && len(c.requests) > 0 {
			found = true
			msg, c.requests = c.requests[0], c.requests[1:]
			// log.Println("Found rpc REQUEST ", *msg)
		} else if !req && len(c.responses) > 0 {
			found = true
			msg, c.responses = c.responses[0], c.responses[1:]
			// log.Println("Found rpc RESPONSE ", *msg)
		} else {
			if c.reading {
				// we need to wait till concurrent read finishes
				c.readCond.Wait()
				readErr = c.readErr
			} else {
				c.reading = true
				c.readErr = nil
				c.readCond.L.Unlock()

				// Now read from conn without holding lock
				var newmsg codecMessage
				readErr = c.dec.Decode(&newmsg)

				c.readCond.L.Lock()
				if readErr == nil {
					// populate c.requests or c.responses
					if newmsg.IsRequest {
						c.requests = append(c.requests, &newmsg)
					} else {
						c.responses = append(c.responses, &newmsg)
					}
				}
				c.reading = false
				c.readErr = readErr
				c.readCond.Signal()
			}
		}
	}
	return
}

func MapToStruct(in map[string]interface{}, out interface{}) error {
	// TODO use reflect to avoid encode-map-to-JSON then decode-JSON-to-struct
	if enc, err := json.Marshal(in); err != nil {
		return err
	} else {
		return json.Unmarshal(enc, out)
	}
}

// This method is provided for help with unit-testing
func StructToMap(in interface{}) (out map[string]interface{}) {
	// TODO use reflect to avoid encode-map-to-JSON then decode-JSON-to-struct
	out = nil
	if enc, err := json.Marshal(in); err == nil {
		out = make(map[string]interface{})
		err1 := json.Unmarshal(enc, &out)
		if err1 != nil {
			panic(err1)
		}
	} else {
		panic(err)
	}
	return
}
