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

	"github.com/Sirupsen/logrus"
	cnitypes "github.com/containernetworking/cni/pkg/types"
	md "github.com/noironetworks/aci-containers/pkg/metadata"
)

type EpRPC struct {
	agent *HostAgent
}

func (agent *HostAgent) runEpRPC(stopCh <-chan struct{}) error {
	if agent.config.EpRpcSock == "" {
		return nil
	}

	rpc.Register(NewEpRPC(agent))

	os.Remove(agent.config.EpRpcSock)
	l, err := net.Listen("unix", agent.config.EpRpcSock)
	if err != nil {
		agent.log.Error("Could not listen to rpc socket: ", err)
		return err
	}

	go rpc.Accept(l)
	go func() {
		<-stopCh
		l.Close()
	}()
	return nil
}

func NewEpRPC(agent *HostAgent) *EpRPC {
	return &EpRPC{agent: agent}
}

func (r *EpRPC) Register(metadata *md.ContainerMetadata, result *cnitypes.Result) error {
	if metadata.Namespace == "" || metadata.Pod == "" {
		return errors.New("Metadata has empty pod key fields")
	}

	regresult, err := r.agent.configureContainerIface(metadata)
	if err != nil {
		r.agent.log.Error("Failed to configure container interface: ", err)
		return err
	}

	*result = *regresult
	return nil
}

func (r *EpRPC) Unregister(id string, ack *bool) error {
	if id == "" {
		return errors.New("ID is empty")
	}

	err := r.agent.unconfigureContainerIface(id)
	if err != nil {
		r.agent.log.WithFields(logrus.Fields{
			"id": id,
		}).Error("Failed to unconfigure container interface: ", err)
		return err
	}

	*ack = true
	return nil
}
