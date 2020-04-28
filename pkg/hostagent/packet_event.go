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
				for {
					buffer := make([]byte, 4096)
					n, err := newFd.Read(buffer)
					if err != nil {
						if err != io.EOF {
							agent.log.Errorf("packet event socket read error %s", err)
						}
						break
					}
					var m []PacketEvent
					err1 := json.Unmarshal(buffer[:n], &m)
					if err1 != nil {
						agent.log.Error("Unmarshaling error ", err1)
					}
					for _, event := range m {
						err2 := agent.processPacketEvent(event, time.Now())
						if err2 != nil {
							agent.log.Errorf("Failed to post event %d", err2)
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
