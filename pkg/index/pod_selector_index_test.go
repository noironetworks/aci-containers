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
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"

	v1 "k8s.io/api/core/v1"
	v1beta1 "k8s.io/api/extensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/cache"
	framework "k8s.io/client-go/tools/cache/testing"

	tu "github.com/noironetworks/aci-containers/pkg/testutil"
)

type testIndex struct {
	stopCh chan struct{}

	fakeNamespaceSource *framework.FakeControllerSource
	fakePodSource       *framework.FakeControllerSource
	fakeObjSource       *framework.FakeControllerSource

	si *PodSelectorIndex

	mutex   sync.Mutex
	updates map[string]bool
}

type TestKubeObj struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	selector []PodSelector
}

func (in *TestKubeObj) DeepCopyInto(out *TestKubeObj) {
	*out = *in
	return
}

func (in *TestKubeObj) DeepCopy() *TestKubeObj {
	if in == nil {
		return nil
	}
	out := new(TestKubeObj)
	in.DeepCopyInto(out)
	return out
}

func (in *TestKubeObj) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	} else {
		return nil
	}
}

func newTestIndex(log *logrus.Logger, dep bool) *testIndex {
	log.Level = logrus.DebugLevel

	testIndex := &testIndex{
		stopCh:              make(chan struct{}),
		fakeNamespaceSource: framework.NewFakeControllerSource(),
		fakePodSource:       framework.NewFakeControllerSource(),
		fakeObjSource:       framework.NewFakeControllerSource(),
	}
	namespaceIndexer, namespaceInformer := cache.NewIndexerInformer(
		&cache.ListWatch{
			ListFunc:  testIndex.fakeNamespaceSource.List,
			WatchFunc: testIndex.fakeNamespaceSource.Watch,
		},
		&v1.Namespace{}, 0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				testIndex.si.UpdateNamespace(obj.(*v1.Namespace))
			},
			UpdateFunc: func(_ interface{}, obj interface{}) {
				testIndex.si.UpdateNamespace(obj.(*v1.Namespace))
			},
			DeleteFunc: func(obj interface{}) {
				testIndex.si.DeleteNamespace(obj.(*v1.Namespace))
			},
		},
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	podIndexer, podInformer := cache.NewIndexerInformer(
		&cache.ListWatch{
			ListFunc:  testIndex.fakePodSource.List,
			WatchFunc: testIndex.fakePodSource.Watch,
		},
		&v1.Pod{}, 0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				testIndex.si.UpdatePod(obj.(*v1.Pod))
			},
			UpdateFunc: func(_ interface{}, obj interface{}) {
				testIndex.si.UpdatePod(obj.(*v1.Pod))
			},
			DeleteFunc: func(obj interface{}) {
				testIndex.si.DeletePod(obj.(*v1.Pod))
			},
		},
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	var objtype runtime.Object
	if dep {
		objtype = &v1beta1.Deployment{}
	} else {
		objtype = &TestKubeObj{}
	}
	objIndexer, objInformer := cache.NewIndexerInformer(
		&cache.ListWatch{
			ListFunc:  testIndex.fakeObjSource.List,
			WatchFunc: testIndex.fakeObjSource.Watch,
		},
		objtype, 0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				testIndex.si.UpdateSelectorObj(obj)
			},
			UpdateFunc: func(_ interface{}, obj interface{}) {
				testIndex.si.UpdateSelectorObj(obj)
			},
			DeleteFunc: func(obj interface{}) {
				testIndex.si.DeleteSelectorObj(obj)
			},
		},
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)

	updateCb := func(key string) {
		testIndex.mutex.Lock()
		testIndex.updates[key] = true
		testIndex.mutex.Unlock()
	}

	if dep {
		testIndex.si = NewPodSelectorIndex(
			log, podIndexer, namespaceIndexer, objIndexer,
			cache.MetaNamespaceKeyFunc,
			func(obj interface{}) []PodSelector {
				dep := obj.(*v1beta1.Deployment)
				return PodSelectorFromNsAndSelector(dep.ObjectMeta.Namespace,
					dep.Spec.Selector)
			})
		testIndex.si.SetPodUpdateCallback(updateCb)
	} else {
		testIndex.si = NewPodSelectorIndex(
			log, podIndexer, namespaceIndexer, objIndexer,
			cache.MetaNamespaceKeyFunc,
			func(obj interface{}) []PodSelector {
				to := obj.(*TestKubeObj)
				return to.selector
			})
		testIndex.si.SetObjUpdateCallback(updateCb)
	}

	go podInformer.Run(testIndex.stopCh)
	go namespaceInformer.Run(testIndex.stopCh)
	go objInformer.Run(testIndex.stopCh)

	return testIndex
}

func (i *testIndex) stop() {
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

type updateTest struct {
	op      string
	thing   interface{}
	updates []string
	keys    map[string][]string
	desc    string
}

var depUpdateTests = []updateTest{
	{
		"add",
		deployment("testns1", "testdep1", map[string]string{
			"label1": "value1",
			"label2": "value2"}),
		[]string{"testns1/testpod1"},
		map[string][]string{
			"testns1/testpod1": {"testns1/testdep1"},
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
			"testns1/testpod2": {"testns1/testdep1"},
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
			"testns1/testpod2": {"testns1/testdep1"},
			"testns2/testpod3": {"testns2/testdep2"},
		},
		"diffns",
	},
	{
		"add",
		deployment("testns1", "testdep3", map[string]string{}),
		[]string{"testns1/testpod1", "testns1/testpod2"},
		map[string][]string{
			"testns1/testpod1": {"testns1/testdep3"},
			"testns1/testpod2": {"testns1/testdep1", "testns1/testdep3"},
		},
		"multimatch",
	},
	{
		"remove",
		deployment("testns1", "testdep3", map[string]string{}),
		[]string{"testns1/testpod1", "testns1/testpod2"},
		map[string][]string{
			"testns1/testpod1": nil,
			"testns1/testpod2": {"testns1/testdep1"},
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
			"testns1/testpod4": {"testns1/testdep1"},
		},
		"addpodafterdep",
	},
}

func TestPodIndexDeployment(t *testing.T) {
	log := logrus.New()
	testIndex := newTestIndex(log, true)

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

	testIndex.updates = make(map[string]bool)
	for _, dt := range depUpdateTests {
		log.Info("Starting ", dt.desc)

		switch dt.op {
		case "add":
			switch o := dt.thing.(type) {
			case *v1beta1.Deployment:
				testIndex.fakeObjSource.Add(o)
			case *v1.Namespace:
				testIndex.fakeNamespaceSource.Add(o)
			case *v1.Pod:
				testIndex.fakePodSource.Add(o)
			}
		case "remove":
			switch o := dt.thing.(type) {
			case *v1beta1.Deployment:
				testIndex.fakeObjSource.Delete(o)
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
					testIndex.updates, dt.desc, "updates") {
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

		testIndex.updates = make(map[string]bool)
	}

	testIndex.stop()
}

func testObj(namespace string, name string, s []PodSelector) *TestKubeObj {
	return &TestKubeObj{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
		},
		selector: s,
	}
}

var ns1 = "testns1"

var nsMatchTests = []updateTest{
	{
		"add",
		testObj("testns1", "testobj1", []PodSelector{
			{
				NsSelector: labels.SelectorFromSet(labels.Set{
					"nslabel1": "value1",
					"nslabel2": "value2"}),
				PodSelector: labels.Everything(),
			},
		}),
		[]string{"testns1/testobj1"},
		map[string][]string{
			"testns1/testobj1": {
				"testns1/testpod1",
				"testns1/testpod2"},
		},
		"nsselector",
	},
	{
		"remove",
		namespace("testns1", map[string]string{}),
		[]string{"testns1/testobj1"},
		map[string][]string{
			"testns1/testobj1": nil,
		},
		"removens",
	},
	{
		"add",
		namespace("testns1", map[string]string{
			"nslabel1": "value1",
			"nslabel2": "value2"}),
		[]string{"testns1/testobj1"},
		map[string][]string{
			"testns1/testobj1": {
				"testns1/testpod1",
				"testns1/testpod2"},
		},
		"addns",
	},
	{
		"add",
		testObj("testns1", "testobj1", []PodSelector{
			{
				Namespace: &ns1,
				PodSelector: labels.SelectorFromSet(labels.Set{
					"label1": "value1",
					"label2": "value2"}),
			},
		}),
		[]string{"testns1/testobj1"},
		map[string][]string{
			"testns1/testobj1": {
				"testns1/testpod1"},
		},
		"podselector",
	},
	{
		"remove",
		pod("testns1", "testpod1", map[string]string{}),
		[]string{"testns1/testobj1"},
		map[string][]string{
			"testns1/testobj1": nil,
		},
		"removepod",
	},
}

func TestPodIndexNSMatch(t *testing.T) {
	log := logrus.New()
	testIndex := newTestIndex(log, false)

	ns1 := namespace("testns1", map[string]string{
		"nslabel1": "value1",
		"nslabel2": "value2"})
	ns2 := namespace("testns2", map[string]string{
		"nslabel1": "value3",
		"nslabel2": "value4"})
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

	testIndex.updates = make(map[string]bool)
	for _, dt := range nsMatchTests {
		log.Info("Starting ", dt.desc)

		switch dt.op {
		case "add":
			switch o := dt.thing.(type) {
			case *TestKubeObj:
				testIndex.fakeObjSource.Add(o)
			case *v1.Namespace:
				testIndex.fakeNamespaceSource.Add(o)
			case *v1.Pod:
				testIndex.fakePodSource.Add(o)
			}
		case "remove":
			switch o := dt.thing.(type) {
			case *TestKubeObj:
				testIndex.fakeObjSource.Delete(o)
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
					testIndex.updates, dt.desc, "updates") {
					testIndex.mutex.Unlock()
					return false, nil
				}
				testIndex.mutex.Unlock()
				for k, v := range dt.keys {
					sort.Strings(v)
					act := testIndex.si.GetPodForObj(k)
					sort.Strings(act)

					if !tu.WaitEqual(t, last, v, act,
						dt.desc, "podForObj", k) {
						return false, nil
					}
				}
				return true, nil
			})

		testIndex.updates = make(map[string]bool)
	}

	testIndex.stop()
}
