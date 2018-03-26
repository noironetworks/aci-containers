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
	"net"
	"net/rpc"

	"github.com/Sirupsen/logrus"
)

type HandleAllFunc func(string, []KvItem)
type HandleUpdateFunc func(string, []KvAction)

type clientCodecWrapper interface {
	rpc.ClientCodec
	Conn() net.Conn
}

type KvWatcher struct {
	watchNamespaces []string
	log             *logrus.Entry

	allHandler    HandleAllFunc
	updateHandler HandleUpdateFunc

	connChan chan clientCodecWrapper
	callChan chan *rpc.Call
	conns    map[*rpc.Client]clientCodecWrapper
}

func NewKvWatcher(ns []string, l *logrus.Logger, ah HandleAllFunc,
	uh HandleUpdateFunc) *KvWatcher {

	return &KvWatcher{
		watchNamespaces: ns,
		log:             l.WithField("ctx", "KvWatcher"),
		allHandler:      ah,
		updateHandler:   uh,
		connChan:        make(chan clientCodecWrapper),
		callChan:        make(chan *rpc.Call, 16),
		conns:           make(map[*rpc.Client]clientCodecWrapper)}
}

func (w *KvWatcher) AllHandler() HandleAllFunc {
	return w.allHandler
}

func (w *KvWatcher) UpdateHandler() HandleUpdateFunc {
	return w.updateHandler
}

func (w *KvWatcher) ServeConn(conn clientCodecWrapper) {
	w.connChan <- conn
}

func (w *KvWatcher) Watch(stopCh <-chan struct{}) {
	called := make(map[*rpc.Call]*rpc.Client)

	for {
		select {
		case conn := <-w.connChan:
			client := rpc.NewClientWithCodec(conn)
			w.conns[client] = conn
			log := w.connLogger(client)

			for _, ns := range w.watchNamespaces {
				if ns == "" {
					continue
				}
				log.WithField("ns", ns).Debug("Initializing watch")
				call := client.Go("KvService.List",
					&RpcListArgs{Namespace: ns},
					&RpcListReply{},
					w.callChan)
				called[call] = client
			}

		case call := <-w.callChan:
			client, ok := called[call]
			delete(called, call)
			var nc *rpc.Call
			var err error
			if ok {
				switch call.ServiceMethod {
				case "KvService.List":
					nc, err = w.handleListReply(call, client)
				case "KvService.Watch":
					nc, err = w.handleWatchReply(call, client)
				default:
					w.connLogger(client).Debug("Reply to unknown call ",
						call.ServiceMethod)
				}
				if err != nil {
					w.closeClientOnError(err, call, client)
				} else if nc != nil {
					newCall := client.Go(nc.ServiceMethod,
						nc.Args, nc.Reply, w.callChan)
					called[newCall] = client
				}
			}

		case <-stopCh:
			w.log.Debug("Exiting watch loop")
			for _, client := range called {
				client.Close()
			}
			return
		}
	}
}

func (w *KvWatcher) connLogger(client *rpc.Client) *logrus.Entry {
	conn := w.conns[client]
	remote := "<unknown>"
	if conn != nil {
		remote = conn.Conn().RemoteAddr().String()
	}
	return w.log.WithField("remote", remote)
}

func (w *KvWatcher) closeClientOnError(err error, call *rpc.Call,
	client *rpc.Client) {

	if err != nil {
		w.connLogger(client).Error(
			fmt.Sprintf("Closing connection on failure of call %s: %v",
				call.ServiceMethod, err))
		delete(w.conns, client)
		client.Close()
	}
}

func (w *KvWatcher) handleListReply(call *rpc.Call,
	client *rpc.Client) (*rpc.Call, error) {

	if call.Error != nil {
		// all errors are fatal to the connection
		return nil, call.Error
	}
	args := call.Args.(*RpcListArgs)
	log := w.connLogger(client).WithFields(logrus.Fields{
		"call": call.ServiceMethod,
		"ns":   args.Namespace})
	reply := call.Reply.(*RpcListReply)
	log.WithFields(logrus.Fields{
		"count":       len(reply.Items),
		"new-version": reply.Version}).Debug("Got items")
	if w.allHandler != nil {
		w.allHandler(args.Namespace, reply.Items)
	}

	nc := &rpc.Call{
		ServiceMethod: "KvService.Watch",
		Args: &RpcWatchArgs{Namespace: args.Namespace,
			Version: reply.Version},
		Reply: &RpcWatchReply{}}
	return nc, nil
}

func (w *KvWatcher) handleWatchReply(call *rpc.Call,
	client *rpc.Client) (*rpc.Call, error) {

	args := call.Args.(*RpcWatchArgs)
	log := w.connLogger(client).WithFields(logrus.Fields{
		"call":    call.ServiceMethod,
		"ns":      args.Namespace,
		"version": args.Version})

	reinit := false
	if call.Error != nil {
		if call.Error.Error() == KvErrorVersionTooOld.Error() {
			log.Info("Watch returned VERSION_TOO_OLD")
			reinit = true
		} else {
			return nil, call.Error
		}
	}
	var nc *rpc.Call
	if reinit {
		log.Debug("Reinitializing watch")
		nc = &rpc.Call{
			ServiceMethod: "KvService.List",
			Args:          &RpcListArgs{Namespace: args.Namespace},
			Reply:         &RpcListReply{}}
	} else {
		reply := call.Reply.(*RpcWatchReply)
		log.WithFields(logrus.Fields{
			"count":       len(reply.Actions),
			"new-version": reply.Version}).Debug("Got actions")
		if w.updateHandler != nil {
			w.updateHandler(args.Namespace, reply.Actions)
		}

		nc = &rpc.Call{
			ServiceMethod: "KvService.Watch",
			Args: &RpcWatchArgs{Namespace: args.Namespace,
				Version: reply.Version},
			Reply: &RpcWatchReply{}}
	}
	return nc, nil
}
