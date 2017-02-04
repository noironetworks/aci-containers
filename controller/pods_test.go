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
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "k8s.io/client-go/pkg/api/v1"

	"github.com/noironetworks/aci-containers/metadata"
	tu "github.com/noironetworks/aci-containers/testutil"
)

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

func TestNSAnnotation(t *testing.T) {
	cont := testController()
	cont.run()

	//cont.fakeNamespaceSource.Add(namespace("testns", "{\"policy-space\": \"demo\", \"name\": \"demo|redis\"}", ""))
	//cont.fakePodSource.Add(pod("testns", "testpod", "", ""))

	// TODO add framework for intercepting object writes
	tu.WaitFor(t, "test", 100*time.Millisecond,
		func(last bool) (bool, error) {
			return true, nil
		})

	cont.stop()
}
