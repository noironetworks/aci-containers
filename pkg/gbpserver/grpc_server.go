/***
Copyright 2019 Cisco Systems Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package gbpserver

import (
	"fmt"
	"net"
	"strings"

	log "github.com/Sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/peer"
)

const (
	inboxSize = 256
)

// gbpWatch implements the GBPServer interface
type gbpWatch struct {
	gs      *Server
	l       net.Listener
	stopped bool
}

func StartGRPC(port string, gs *Server) (*gbpWatch, error) {
	lis, err := net.Listen("tcp", port)
	if err != nil {
		return nil, err
	}

	s := grpc.NewServer()
	gw := &gbpWatch{gs: gs, l: lis}
	RegisterGBPServer(s, gw)
	go func() {
		if err := s.Serve(lis); err != nil {
			if !gw.stopped {
				log.Fatalf("Failed to serve - %v", err)
			}
		}
		if !gw.stopped {
			log.Fatalf("grpc server exited")
		}
	}()

	return gw, nil
}

func (gw *gbpWatch) Stop() {
	gw.stopped = true
	gw.l.Close()
}

// ListObjects is the list-watch streaming method invoked by the client.
// It blocks after each send, until a new operation is avaialable to send
func (gw *gbpWatch) ListObjects(v *Version, ss GBP_ListObjectsServer) error {

	// extract peer ip from context
	peer, ok := peer.FromContext(ss.Context())
	if !ok {
		log.Errorf("Peer information unavailable")
		return fmt.Errorf("Peer information unavailable")
	}

	log.Infof("peerAddr %s", peer.Addr.String())
	peerVtep := strings.Split(peer.Addr.String(), ":")[0]
	log.Infof("ListObjects from %s", peerVtep)
	inbox := make(chan *GBPOperation, inboxSize)

	updateFn := func(op GBPOperation_OpCode, url string) {
		var moList []*GBPObject
		if strings.Contains(url, "InvRemoteInventoryEp") {
			moList = getInvSubTree(url, peerVtep)
		} else {
			moList = getMoSubTree(url)
		}

		gbpOp := &GBPOperation{
			Opcode:     op,
			ObjectList: moList,
		}

		inbox <- gbpOp
	}

	// get a snapshot of current MoDB, and register a callback for changes
	gMutex.Lock()
	objList := getSnapShot(peerVtep)
	gw.gs.RegisterCallBack(peer.Addr.String(), updateFn)
	gMutex.Unlock()

	// send the snapshot
	gbpOp := &GBPOperation{
		Opcode:     GBPOperation_REPLACE,
		ObjectList: objList,
	}
	ss.Send(gbpOp)

	// pick up updates from inbox and send
	for {
		select {
		case gbpOp = <-inbox:
			ss.Send(gbpOp)

		case <-ss.Context().Done():
			gw.gs.RemoveCallBack(peer.Addr.String())
			return ss.Context().Err()
		}
	}
}
