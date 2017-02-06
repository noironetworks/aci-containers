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
	"github.com/Sirupsen/logrus"
	v1 "k8s.io/client-go/pkg/api/v1"
	"k8s.io/client-go/tools/cache"
	framework "k8s.io/client-go/tools/cache/testing"
)

type testAciController struct {
	aciController
	stopCh chan struct{}

	fakeNamespaceSource  *framework.FakeControllerSource
	fakePodSource        *framework.FakeControllerSource
	fakeEndpointsSource  *framework.FakeControllerSource
	fakeServiceSource    *framework.FakeControllerSource
	fakeNodeSource       *framework.FakeControllerSource
	fakeDeploymentSource *framework.FakeControllerSource

	podUpdates []*v1.Pod
}

func testController() *testAciController {
	log.Level = logrus.DebugLevel
	log.Formatter = &logrus.TextFormatter{
		DisableColors: true,
	}

	cont := &testAciController{
		aciController: *newController(newConfig()),
	}

	cont.fakeNamespaceSource = framework.NewFakeControllerSource()
	cont.initNamespaceInformerBase(
		&cache.ListWatch{
			ListFunc:  cont.fakeNamespaceSource.List,
			WatchFunc: cont.fakeNamespaceSource.Watch,
		})

	cont.fakePodSource = framework.NewFakeControllerSource()
	cont.initPodInformerBase(
		&cache.ListWatch{
			ListFunc:  cont.fakePodSource.List,
			WatchFunc: cont.fakePodSource.Watch,
		})

	cont.fakeEndpointsSource = framework.NewFakeControllerSource()
	cont.initEndpointsInformerBase(
		&cache.ListWatch{
			ListFunc:  cont.fakeEndpointsSource.List,
			WatchFunc: cont.fakeEndpointsSource.Watch,
		})

	cont.fakeServiceSource = framework.NewFakeControllerSource()
	cont.initServiceInformerBase(
		&cache.ListWatch{
			ListFunc:  cont.fakeServiceSource.List,
			WatchFunc: cont.fakeServiceSource.Watch,
		})

	cont.fakeNodeSource = framework.NewFakeControllerSource()
	cont.initNodeInformerBase(
		&cache.ListWatch{
			ListFunc:  cont.fakeNodeSource.List,
			WatchFunc: cont.fakeNodeSource.Watch,
		})

	cont.fakeDeploymentSource = framework.NewFakeControllerSource()
	cont.initDeploymentInformerBase(
		&cache.ListWatch{
			ListFunc:  cont.fakeDeploymentSource.List,
			WatchFunc: cont.fakeDeploymentSource.Watch,
		})

	cont.updatePod = func(pod *v1.Pod) (*v1.Pod, error) {
		cont.podUpdates = append(cont.podUpdates, pod)
		return pod, nil
	}

	return cont
}

func (cont *testAciController) run() {
	cont.stopCh = make(chan struct{})
	cont.aciController.run(cont.stopCh)
}

func (cont *testAciController) stop() {
	close(cont.stopCh)
}
