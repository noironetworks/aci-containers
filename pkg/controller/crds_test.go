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
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package controller

import (
	"net"
	"testing"
	"time"

	v1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/noironetworks/aci-containers/pkg/ipam"
	"github.com/stretchr/testify/assert"
)

const (
	testCRDName1 = "testCRD1.tgroup.com"
	testCRDName2 = "testCRD2.tgroup.com"
	testCRDName3 = "testCRD3.tgroup.com"
)

type crdTst struct {
	h   func(cont *AciController, stopCh <-chan struct{})
	obj *v1.CustomResourceDefinition
}

func TestCRDs(t *testing.T) {
	initCont := func() *testAciController {
		cont := testController()
		cont.config.AciPolicyTenant = "test-tenant_crd"
		cont.config.NodeServiceIpPool = []ipam.IpRange{
			{Start: net.ParseIP("10.1.1.2"), End: net.ParseIP("10.1.1.3")},
		}
		cont.config.PodIpPool = []ipam.IpRange{
			{Start: net.ParseIP("10.1.1.2"), End: net.ParseIP("10.1.255.254")},
		}
		cont.AciController.initIpam()

		cont.fakeNamespaceSource.Add(namespaceLabel("testns_qos",
			map[string]string{"test": "testv"}))
		cont.fakeNamespaceSource.Add(namespaceLabel("ns1_qos",
			map[string]string{"nl_qos": "nv_qos"}))
		cont.fakeNamespaceSource.Add(namespaceLabel("ns2_qos",
			map[string]string{"nl_qos": "nv_qos"}))

		return cont
	}

	outChan := make(chan string)
	crdHandler1 := func(cont *AciController, stopCh <-chan struct{}) {
		outChan <- testCRDName1
	}
	crdHandler2 := func(cont *AciController, stopCh <-chan struct{}) {
		outChan <- testCRDName2
	}

	crdList := []crdTst{
		{
			h: crdHandler1,
			obj: &v1.CustomResourceDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: testCRDName1,
				},
			},
		},
		{
			h: crdHandler2,
			obj: &v1.CustomResourceDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: testCRDName2,
				},
			},
		},
	}

	cont := initCont()
	cont.run()
	for _, crd := range crdList {
		cont.registerCRDHook(crd.obj.ObjectMeta.Name, crd.h)
	}

	for _, crd := range crdList {
		cont.fakeCRDSource.Add(crd.obj)
	}
	for _, crd := range crdList {
		cont.fakeCRDSource.Modify(crd.obj)
	}
	handled := make(map[string]bool)
waitHandler:
	for {
		select {
		case n := <-outChan:
			handled[n] = true
			if len(handled) == len(crdList) {
				break waitHandler
			}
		case <-time.After(5 * time.Second):
			assert.True(t, false, "Timeout waiting for handler")
		}
	}

	for _, crd := range crdList {
		assert.True(t, handled[crd.obj.ObjectMeta.Name], crd.obj.ObjectMeta.Name)
	}
}

func TestCRDsDelete(t *testing.T) {
	initCont := func() *testAciController {
		cont := testController()
		return cont
	}

	outChan := make(chan string)
	crdHandler1 := func(cont *AciController, stopCh <-chan struct{}) {
		outChan <- testCRDName1
	}
	crdHandler2 := func(cont *AciController, stopCh <-chan struct{}) {
		outChan <- testCRDName2
	}

	crdList := []crdTst{
		{
			h: crdHandler1,
			obj: &v1.CustomResourceDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: testCRDName1,
				},
			},
		},
		{
			h: crdHandler2,
			obj: &v1.CustomResourceDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: testCRDName2,
				},
			},
		},
	}

	cont := initCont()
	cont.run()
	for _, crd := range crdList {
		cont.registerCRDHook(crd.obj.ObjectMeta.Name, crd.h)
	}

	for _, crd := range crdList {
		cont.fakeCRDSource.Delete(crd.obj)
	}
	handled := make(map[string]bool)
waitHandler:
	for {
		select {
		case n := <-outChan:
			handled[n] = true
		case <-time.After(5 * time.Second):
			if len(handled) == 0 {
				assert.True(t, true, "No handlers called")
			} else {
				assert.True(t, false, "No handlers should be called")
			}
			break waitHandler
		}
	}
}
