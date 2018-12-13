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
	"github.com/Sirupsen/logrus"
	cnitypes "github.com/containernetworking/cni/pkg/types"
	"k8s.io/client-go/tools/cache"
	framework "k8s.io/client-go/tools/cache/testing"
	"net"
)

const nodename = "test-node"

type testHostAgent struct {
	*HostAgent
	stopCh chan struct{}

	fakeNodeSource      *framework.FakeControllerSource
	fakePodSource       *framework.FakeControllerSource
	fakeEndpointsSource *framework.FakeControllerSource
	fakeServiceSource   *framework.FakeControllerSource
}

func testAgent() *testHostAgent {
	log := logrus.New()
	log.Level = logrus.DebugLevel

	ncf := cniNetConfig{Subnet: cnitypes.IPNet{IP: net.ParseIP("10.128.2.0"), Mask: net.CIDRMask(24, 32)}}
	agent := &testHostAgent{
		HostAgent: NewHostAgent(&HostAgentConfig{
			NodeName:       nodename,
			EpRpcSock:      "/tmp/aci-containers-ep-rpc.sock",
			CniMetadataDir: "/tmp/cnimeta",
			NetConfig:      []cniNetConfig{ncf},
		}, &K8sEnvironment{}, log),
	}
	agent.env.(*K8sEnvironment).agent = agent.HostAgent

	agent.fakeNodeSource = framework.NewFakeControllerSource()
	agent.initNodeInformerBase(
		&cache.ListWatch{
			ListFunc:  agent.fakeNodeSource.List,
			WatchFunc: agent.fakeNodeSource.Watch,
		})

	agent.fakePodSource = framework.NewFakeControllerSource()
	agent.initPodInformerBase(
		&cache.ListWatch{
			ListFunc:  agent.fakePodSource.List,
			WatchFunc: agent.fakePodSource.Watch,
		})

	agent.fakeEndpointsSource = framework.NewFakeControllerSource()
	agent.initEndpointsInformerBase(
		&cache.ListWatch{
			ListFunc:  agent.fakeEndpointsSource.List,
			WatchFunc: agent.fakeEndpointsSource.Watch,
		})

	agent.fakeServiceSource = framework.NewFakeControllerSource()
	agent.initServiceInformerBase(
		&cache.ListWatch{
			ListFunc:  agent.fakeServiceSource.List,
			WatchFunc: agent.fakeServiceSource.Watch,
		})
	agent.usedIPs = make(map[string]bool)

	return agent
}

func (agent *testHostAgent) run() {
	agent.stopCh = make(chan struct{})
	agent.HostAgent.Run(agent.stopCh)
}

func (agent *testHostAgent) stop() {
	close(agent.stopCh)
}
