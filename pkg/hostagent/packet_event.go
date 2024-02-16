// Copyright 2020 Cisco Systems, Inc.
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

package hostagent

import (
	"encoding/json"
	"io"
	"net"
	"os"
	"time"
)

type PacketEvent struct {
	TimeStamp       string
	DropReason      string
	SourceMac       string
	DestinationMac  string
	EtherType       string
	SourceIP        string
	DestinationIP   string
	IPProto         string
	SourcePort      string
	DestinationPort string
}

func (agent *HostAgent) RunPacketEventListener(stopCh <-chan struct{}) {
	os.Remove(agent.config.PacketEventNotificationSock)
	if agent.config.PacketEventNotificationSock == "" {
		agent.log.Info("Packet event recording is disabled")
		return
	}
	pc, err := net.Listen("unix", agent.config.PacketEventNotificationSock)
	if err != nil {
		agent.log.Errorf("Failed to listen on unix socket %s: %s ",
			agent.config.PacketEventNotificationSock, err)
		return
	} else {
		agent.log.Info("Listening for packet events on unix socket ",
			agent.config.PacketEventNotificationSock)
	}

	go func() {
		for {
			fd, err := pc.Accept()
			if err != nil {
				agent.log.Warnf("Failed to accept %s", err)
				return
			}
			go func(newFd net.Conn) {
				defer newFd.Close()
				dec := json.NewDecoder(newFd)
				for {
					var m []PacketEvent
					if err1 := dec.Decode(&m); err1 != nil {
						if err1 == io.EOF {
							break
						}
						agent.log.Debug("Unmarshaling error ", err1)
						continue
					}
					for ix := range m {
						err2 := agent.processPacketEvent(&m[ix], time.Now())
						if err2 != nil {
							agent.log.Debugf("Failed to post event %d", err2)
						}
					}
				}
			}(fd)
		}
	}()

	go func() {
		<-stopCh
		pc.Close()
	}()
}
