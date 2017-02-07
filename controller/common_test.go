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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "k8s.io/client-go/pkg/api/v1"
	v1beta1 "k8s.io/client-go/pkg/apis/extensions/v1beta1"
	"k8s.io/client-go/tools/cache"
	framework "k8s.io/client-go/tools/cache/testing"

	"github.com/Sirupsen/logrus"

	"github.com/noironetworks/aci-containers/metadata"
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

	podUpdates  []*v1.Pod
	nodeUpdates []*v1.Node
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
	cont.updateNode = func(node *v1.Node) (*v1.Node, error) {
		cont.nodeUpdates = append(cont.nodeUpdates, node)
		return node, nil
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

func node(name string) *v1.Node {
	return &v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Annotations: map[string]string{},
		},
	}
}

func namespace(name string, egAnnot string, sgAnnot string) *v1.Namespace {
	return &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Annotations: map[string]string{
				metadata.EgAnnotation: egAnnot,
				metadata.SgAnnotation: sgAnnot,
			},
		},
	}
}

func pod(namespace string, name string, egAnnot string, sgAnnot string) *v1.Pod {
	return &v1.Pod{
		Spec: v1.PodSpec{
			NodeName: "test-node",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
			Labels: map[string]string{
				"app":  "sample-app",
				"tier": "sample-tier",
			},
			Annotations: map[string]string{
				"kubernetes.io/created-by": "something",
				metadata.EgAnnotation:      egAnnot,
				metadata.SgAnnotation:      sgAnnot,
			},
		},
	}
}

func deployment(namespace string, name string, egAnnot string, sgAnnot string) *v1beta1.Deployment {
	return &v1beta1.Deployment{
		Spec: v1beta1.DeploymentSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app":  "sample-app",
					"tier": "sample-tier",
				},
			},
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
			Annotations: map[string]string{
				metadata.EgAnnotation: egAnnot,
				metadata.SgAnnotation: sgAnnot,
			},
		},
	}
}
