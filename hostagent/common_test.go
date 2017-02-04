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

package main

import (
	"k8s.io/client-go/tools/cache"
	framework "k8s.io/client-go/tools/cache/testing"
)

const nodename = "test-node"

type testHostAgent struct {
	hostAgent
	stopCh chan struct{}

	fakeNodeSource      *framework.FakeControllerSource
	fakePodSource       *framework.FakeControllerSource
	fakeEndpointsSource *framework.FakeControllerSource
	fakeServiceSource   *framework.FakeControllerSource
}

func testAgent() *testHostAgent {
	agent := &testHostAgent{
		hostAgent: *newHostAgent(&hostAgentConfig{
			NodeName: nodename,
		}),
	}

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

	return agent
}

func (agent *testHostAgent) run() {
	agent.stopCh = make(chan struct{})

	nodeStop := make(chan struct{})
	podStop := make(chan struct{})
	endpointsStop := make(chan struct{})
	serviceStop := make(chan struct{})

	go agent.nodeInformer.Run(nodeStop)
	go agent.podInformer.Run(podStop)
	go agent.endpointsInformer.Run(endpointsStop)
	go agent.serviceInformer.Run(serviceStop)

	go func() {
		<-agent.stopCh
		var s struct{}
		nodeStop <- s
		podStop <- s
		endpointsStop <- s
		serviceStop <- s
	}()
}

func (agent *testHostAgent) stop() {
	var s struct{}
	agent.stopCh <- s
}
