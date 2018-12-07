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

package hostagent

import (
	"errors"
	"net"
	"net/rpc"
	"os"
	"strconv"

	"github.com/Sirupsen/logrus"
	cnitypes "github.com/containernetworking/cni/pkg/types/current"
	md "github.com/noironetworks/aci-containers/pkg/metadata"
)

type EpRPC struct {
	agent  *HostAgent
	server *rpc.Server // our pvt instance of the server
}

func (agent *HostAgent) runEpRPC(stopCh <-chan struct{}) error {
	if agent.config.EpRpcSock == "" {
		return nil
	}

	epRPC := NewEpRPC(agent)
	err := epRPC.server.Register(epRPC)
	if err != nil {
		agent.log.Fatalf("epRPC.server.Register - %v", err)
	}

	os.Remove(agent.config.EpRpcSock)
	l, err := net.Listen("unix", agent.config.EpRpcSock)
	if err != nil {
		agent.log.Error("Could not listen to rpc socket: ", err)
		return err
	}

	// Set socket file permissions
	if agent.config.EpRpcSockPerms != "" {
		perms, err := strconv.ParseUint(agent.config.EpRpcSockPerms, 8, 32)
		if err != nil {
			agent.log.Warning("Could not parse socket file permissions: ", err)
		} else {
			err = os.Chmod(agent.config.EpRpcSock, os.FileMode(perms))
			if err != nil {
				agent.log.Warning("Could not set socket file permissions: ", err)
			}
		}
	}

	go epRPC.server.Accept(l)
	go func() {
		<-stopCh
		l.Close()
	}()
	return nil
}

func NewEpRPC(agent *HostAgent) *EpRPC {
	return &EpRPC{
		agent:  agent,
		server: rpc.NewServer(),
	}
}

func (r *EpRPC) Register(metadata *md.ContainerMetadata, result *cnitypes.Result) error {
	if metadata.Id.Namespace == "" || metadata.Id.Pod == "" {
		return errors.New("Metadata has empty pod key fields")
	}

	r.agent.log.Debug("Registering ", metadata.Id)

	regresult, err := r.agent.configureContainerIfaces(metadata)
	if err != nil {
		r.agent.log.Error("Failed to configure container interface: ", err)
		return err
	}

	err = r.agent.syncPorts(r.agent.config.OvsDbSock)
	if err != nil {
		r.agent.log.Error("Could not sync OVS ports: ", err)
	}

	*result = *regresult
	return nil
}

func (r *EpRPC) Unregister(id *md.ContainerId, ack *bool) error {
	if id.Namespace == "" || id.Pod == "" || id.ContId == "" {
		return errors.New("Metadata has empty key fields")
	}

	r.agent.log.Debug("Unregistering ", id)

	err := r.agent.unconfigureContainerIfaces(id)
	if err != nil {
		r.agent.log.WithFields(logrus.Fields{
			"id": id,
		}).Error("Failed to unconfigure container interface: ", err)
		return err
	}

	err = r.agent.syncPorts(r.agent.config.OvsDbSock)
	if err != nil {
		r.agent.log.Error("Could not sync OVS ports: ", err)
	}

	*ack = true
	return nil
}

type ResyncArgs struct{}

func (r *EpRPC) Resync(args ResyncArgs, ack *bool) error {
	r.agent.log.Debug("EpRPC resync invoked")
	r.agent.syncPorts(r.agent.config.OvsDbSock)
	*ack = true
	return nil
}
