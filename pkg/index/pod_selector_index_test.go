// Copyright 2016 Cisco Systems, Inc.
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

package index

import (
	"sync"
	"testing"
	"time"

	"github.com/Sirupsen/logrus"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	v1 "k8s.io/client-go/pkg/api/v1"
	v1beta1 "k8s.io/client-go/pkg/apis/extensions/v1beta1"
	"k8s.io/client-go/tools/cache"
	framework "k8s.io/client-go/tools/cache/testing"
	"k8s.io/kubernetes/pkg/controller"

	tu "github.com/noironetworks/aci-containers/pkg/testutil"
)

type testDepIndex struct {
	stopCh chan struct{}

	fakeNamespaceSource  *framework.FakeControllerSource
	fakePodSource        *framework.FakeControllerSource
	fakeDeploymentSource *framework.FakeControllerSource

	si *PodSelectorIndex

	mutex      sync.Mutex
	podUpdates map[string]bool
}

func newTestIndex(log *logrus.Logger) *testDepIndex {
	log.Level = logrus.DebugLevel

	testIndex := &testDepIndex{
		stopCh:               make(chan struct{}),
		fakeNamespaceSource:  framework.NewFakeControllerSource(),
		fakePodSource:        framework.NewFakeControllerSource(),
		fakeDeploymentSource: framework.NewFakeControllerSource(),
	}
	namespaceInformer := cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc:  testIndex.fakeNamespaceSource.List,
			WatchFunc: testIndex.fakeNamespaceSource.Watch,
		},
		&v1.Namespace{},
		controller.NoResyncPeriodFunc(),
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	namespaceInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			testIndex.si.UpdateNamespace(obj.(*v1.Namespace))
		},
		UpdateFunc: func(_ interface{}, obj interface{}) {
			testIndex.si.UpdateNamespace(obj.(*v1.Namespace))
		},
		DeleteFunc: func(obj interface{}) {
			testIndex.si.DeleteNamespace(obj.(*v1.Namespace))
		},
	})
	podInformer := cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc:  testIndex.fakePodSource.List,
			WatchFunc: testIndex.fakePodSource.Watch,
		},
		&v1.Pod{},
		controller.NoResyncPeriodFunc(),
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			testIndex.si.UpdatePod(obj.(*v1.Pod))
		},
		UpdateFunc: func(_ interface{}, obj interface{}) {
			testIndex.si.UpdatePod(obj.(*v1.Pod))
		},
		DeleteFunc: func(obj interface{}) {
			testIndex.si.DeletePod(obj.(*v1.Pod))
		},
	})
	deploymentInformer := cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc:  testIndex.fakeDeploymentSource.List,
			WatchFunc: testIndex.fakeDeploymentSource.Watch,
		},
		&v1beta1.Deployment{},
		controller.NoResyncPeriodFunc(),
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	deploymentInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			testIndex.si.UpdateSelectorObj(obj)
		},
		UpdateFunc: func(_ interface{}, obj interface{}) {
			testIndex.si.UpdateSelectorObj(obj)
		},
		DeleteFunc: func(obj interface{}) {
			testIndex.si.DeleteSelectorObj(obj)
		},
	})

	testIndex.si = NewPodSelectorIndex(log, podInformer,
		namespaceInformer, deploymentInformer,
		func(obj interface{}) string {
			return obj.(*v1beta1.Deployment).ObjectMeta.Namespace + "/" +
				obj.(*v1beta1.Deployment).ObjectMeta.Name
		},
		func(obj interface{}) *string {
			return &obj.(*v1beta1.Deployment).ObjectMeta.Namespace
		},
		NilSelectorFunc,
		func(obj interface{}) labels.Selector {
			selector, _ := metav1.
				LabelSelectorAsSelector(obj.(*v1beta1.Deployment).Spec.Selector)
			return selector
		},
		func(podkey string) {
			testIndex.mutex.Lock()
			testIndex.podUpdates[podkey] = true
			testIndex.mutex.Unlock()
		})

	go podInformer.Run(testIndex.stopCh)
	go namespaceInformer.Run(testIndex.stopCh)
	go deploymentInformer.Run(testIndex.stopCh)

	return testIndex
}

func (i *testDepIndex) stop() {
	close(i.stopCh)
}

func pod(namespace string, name string, labels map[string]string) *v1.Pod {
	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
			Labels:    labels,
		},
	}
}

func namespace(namespace string, labels map[string]string) *v1.Namespace {
	return &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   namespace,
			Labels: labels,
		},
	}
}

func deployment(namespace string, name string,
	matchLabels map[string]string) *v1beta1.Deployment {

	return &v1beta1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
		},
		Spec: v1beta1.DeploymentSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: matchLabels,
			},
		},
	}
}

type depUpdateTest struct {
	op      string
	thing   interface{}
	updates []string
	keys    map[string][]string
	desc    string
}

var depUpdateTests = []depUpdateTest{
	{
		"add",
		deployment("testns1", "testdep1", map[string]string{
			"label1": "value1",
			"label2": "value2"}),
		[]string{"testns1/testpod1"},
		map[string][]string{
			"testns1/testpod1": []string{"testns1/testdep1"},
			"testns1/testpod2": nil,
		},
		"simple",
	},
	{
		"add",
		deployment("testns1", "testdep1", map[string]string{
			"label1": "value3",
			"label2": "value4"}),
		[]string{"testns1/testpod2", "testns1/testpod1"},
		map[string][]string{
			"testns1/testpod1": nil,
			"testns1/testpod2": []string{"testns1/testdep1"},
		},
		"change",
	},
	{
		"add",
		deployment("testns2", "testdep2", map[string]string{
			"label1": "value1",
			"label2": "value2"}),
		[]string{"testns2/testpod3"},
		map[string][]string{
			"testns1/testpod1": nil,
			"testns1/testpod2": []string{"testns1/testdep1"},
			"testns2/testpod3": []string{"testns2/testdep2"},
		},
		"diffns",
	},
	{
		"add",
		deployment("testns1", "testdep3", map[string]string{}),
		[]string{"testns1/testpod1", "testns1/testpod2"},
		map[string][]string{
			"testns1/testpod1": []string{"testns1/testdep3"},
			"testns1/testpod2": []string{"testns1/testdep1", "testns1/testdep3"},
		},
		"multimatch",
	},
	{
		"remove",
		deployment("testns1", "testdep3", map[string]string{}),
		[]string{"testns1/testpod1", "testns1/testpod2"},
		map[string][]string{
			"testns1/testpod1": nil,
			"testns1/testpod2": []string{"testns1/testdep1"},
		},
		"remove",
	},
	{
		"add",
		pod("testns1", "testpod2", map[string]string{
			"label1": "value1",
			"label2": "value3"}),
		[]string{"testns1/testpod2"},
		map[string][]string{
			"testns1/testpod2": nil,
		},
		"changepod",
	},
	{
		"add",
		pod("testns1", "testpod4", map[string]string{
			"label1": "value3",
			"label2": "value4"}),
		[]string{"testns1/testpod4"},
		map[string][]string{
			"testns1/testpod4": []string{"testns1/testdep1"},
		},
		"addpodafterdep",
	},
}

func TestPodIndex(t *testing.T) {
	log := logrus.New()
	testIndex := newTestIndex(log)

	ns1 := namespace("testns1", nil)
	ns2 := namespace("testns2", nil)
	pod1 := pod("testns1", "testpod1", map[string]string{
		"label1": "value1",
		"label2": "value2"})
	pod2 := pod("testns1", "testpod2", map[string]string{
		"label1": "value3",
		"label2": "value4"})
	pod3 := pod("testns2", "testpod3", map[string]string{
		"label1": "value1",
		"label2": "value2"})

	testIndex.fakeNamespaceSource.Add(ns1)
	testIndex.fakeNamespaceSource.Add(ns2)

	testIndex.fakePodSource.Add(pod1)
	testIndex.fakePodSource.Add(pod2)
	testIndex.fakePodSource.Add(pod3)

	testIndex.podUpdates = make(map[string]bool)
	for _, dt := range depUpdateTests {
		log.Info("Starting ", dt.desc)

		switch dt.op {
		case "add":
			switch o := dt.thing.(type) {
			case *v1beta1.Deployment:
				testIndex.fakeDeploymentSource.Add(o)
			case *v1.Namespace:
				testIndex.fakeNamespaceSource.Add(o)
			case *v1.Pod:
				testIndex.fakePodSource.Add(o)
			}
		case "remove":
			switch o := dt.thing.(type) {
			case *v1beta1.Deployment:
				testIndex.fakeDeploymentSource.Delete(o)
			case *v1.Namespace:
				testIndex.fakeNamespaceSource.Delete(o)
			case *v1.Pod:
				testIndex.fakePodSource.Delete(o)
			}

		}

		tu.WaitFor(t, dt.desc, 500*time.Millisecond,
			func(last bool) (bool, error) {
				tupd := make(map[string]bool)
				for _, k := range dt.updates {
					tupd[k] = true
				}
				testIndex.mutex.Lock()
				if !tu.WaitEqual(t, last, tupd,
					testIndex.podUpdates, dt.desc, "updates") {
					testIndex.mutex.Unlock()
					return false, nil
				}
				testIndex.mutex.Unlock()
				for k, v := range dt.keys {
					if !tu.WaitEqual(t, last, v, testIndex.si.GetObjForPod(k),
						dt.desc, "objForPod", k) {
						return false, nil
					}
				}
				return true, nil
			})

		testIndex.podUpdates = make(map[string]bool)
	}

	testIndex.stop()
}
