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
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package controller

import (
	snatpolicy "github.com/noironetworks/aci-containers/pkg/snatpolicy/apis/aci.snat/v1"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"testing"
	"time"
)

func TestWebhookMulLabels(t *testing.T) {
	rawJSON := `{
		"kind": "AdmissionReview",
		"apiVersion": "admission.k8s.io/v1beta1",
		"request": {
			"uid": "7f0b2891-916f-4ed6-b7cd-27bff1815a8c",
			"kind": {
				"group": "",
				"version": "v1",
				"kind": "SnatPolicy"
			},
			"resource": {
				"group": "",
				"version": "v1",
				"resource": "snatpolcies"
			},
			"requestKind": {
				"group": "",
				"version": "v1",
				"kind": "SnatPolicy"
			},
			"requestResource": {
				"group": "",
				"version": "v1",
				"resource": "snatpolcies"
			},
			"operation": "CREATE",
			"userInfo": {
				"username": "kubernetes-admin",
				"groups": [
					"system:masters",
					"system:authenticated"
				]
			},
		"object": {
			"kind": "SnatPolicy",
			"apiVersion": "aci.snat/v1",
    			"metadata": {
        			"annotations": {
            			"kubectl.kubernetes.io/last-applied-configuration": "{\"apiVersion\":\"aci.snat/v1\",\"kind\":\"SnatPolicy\",\"metadata\":{\"annotations\":{},\"name\":\"it-ns-ns-snatpolicy\"},\"spec\":{\"destIp\":[\"100.100.100.0/24\"],\"selector\":{\"namespace\":\"default\"},\"snatIp\":[\"10.2.30.50/31\"]}}\n"
        			},
        			"creationTimestamp": null,
        			"name": "it-ns-ns-snatpolicy"
    			},
    			"spec": {
        			"destIp": [
            			"100.100.100.0/24"
        			],
        			"selector": {
					"Labels": {
                				"key": "value",
						"key2": "value2"
            				},
            				"namespace": "default"
        			},
        			"snatIp": [
            			"10.2.30.50/31"
        			]
    			}
    		}
	}
	}`
	cont := testController()
	cont.run()
	response, err := cont.serveRequestBody([]byte(rawJSON))
	if err != nil {
		t.Errorf("failed to mutate AdmissionRequest")
	}

	rr := response.Response
	assert.Equal(t, rr.Allowed, false)
	cont.stop()
}

func TestWebhookMatchingSnatIp(t *testing.T) {
	policy := &snatpolicy.SnatPolicy{
		Spec: snatpolicy.SnatPolicySpec{
			SnatIp: []string{"10.2.30.50/31"},
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "plcy1",
		},
	}
	var podSelector snatpolicy.PodSelector
	podSelector.Namespace = "testns"
	podSelector.Labels = map[string]string{"key2": "value2"}
	policy.Spec.Selector = podSelector
	cont := testController()
	cont.run()
	cont.fakeSnatPolicySource.Add(policy)
	time.Sleep(time.Second)
	rawJSON := `{
		"kind": "AdmissionReview",
		"apiVersion": "admission.k8s.io/v1beta1",
		"request": {
			"uid": "7f0b2891-916f-4ed6-b7cd-27bff1815a8c",
			"kind": {
				"group": "",
				"version": "v1",
				"kind": "SnatPolicy"
			},
			"resource": {
				"group": "",
				"version": "v1",
				"resource": "snatpolcies"
			},
			"requestKind": {
				"group": "",
				"version": "v1",
				"kind": "SnatPolicy"
			},
			"requestResource": {
				"group": "",
				"version": "v1",
				"resource": "snatpolcies"
			},
			"operation": "CREATE",
			"userInfo": {
				"username": "kubernetes-admin",
				"groups": [
					"system:masters",
					"system:authenticated"
				]
			},
		"object": {
			"kind": "SnatPolicy",
			"apiVersion": "aci.snat/v1",
    			"metadata": {
        			"annotations": {
            			"kubectl.kubernetes.io/last-applied-configuration": "{\"apiVersion\":\"aci.snat/v1\",\"kind\":\"SnatPolicy\",\"metadata\":{\"annotations\":{},\"name\":\"it-ns-ns-snatpolicy\"},\"spec\":{\"destIp\":[\"100.100.100.0/24\"],\"selector\":{\"namespace\":\"default\"},\"snatIp\":[\"10.2.30.50/31\"]}}\n"
        			},
        			"creationTimestamp": null,
        			"name": "it-ns-ns-snatpolicy"
    			},
    			"spec": {
        			"destIp": [
            			"100.100.100.0/24"
        			],
        			"selector": {
					"Labels": {
                				"key": "value"
            				},
            				"namespace": "default"
        			},
        			"snatIp": [
            			"10.2.30.50/30"
        			]
    			}
    		}
	}
	}`
	response, err := cont.serveRequestBody([]byte(rawJSON))
	if err != nil {
		t.Errorf("failed to mutate AdmissionRequest")
	}

	rr := response.Response
	assert.Equal(t, false, rr.Allowed)
	cont.stop()
}
func TestWebhookMatchingLabels(t *testing.T) {
	policy := &snatpolicy.SnatPolicy{
		Spec: snatpolicy.SnatPolicySpec{
			SnatIp: []string{"10.2.30.50/31"},
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "plcy1",
		},
	}
	var podSelector snatpolicy.PodSelector
	podSelector.Namespace = "testns"
	podSelector.Labels = map[string]string{"key": "value"}
	policy.Spec.Selector = podSelector
	cont := testController()
	cont.run()
	cont.fakeSnatPolicySource.Add(policy)
	time.Sleep(time.Second)
	rawJSON := `{
		"kind": "AdmissionReview",
		"apiVersion": "admission.k8s.io/v1beta1",
		"request": {
			"uid": "7f0b2891-916f-4ed6-b7cd-27bff1815a8c",
			"kind": {
				"group": "",
				"version": "v1",
				"kind": "SnatPolicy"
			},
			"resource": {
				"group": "",
				"version": "v1",
				"resource": "snatpolcies"
			},
			"requestKind": {
				"group": "",
				"version": "v1",
				"kind": "SnatPolicy"
			},
			"requestResource": {
				"group": "",
				"version": "v1",
				"resource": "snatpolcies"
			},
			"operation": "CREATE",
			"userInfo": {
				"username": "kubernetes-admin",
				"groups": [
					"system:masters",
					"system:authenticated"
				]
			},
		"object": {
			"kind": "SnatPolicy",
			"apiVersion": "aci.snat/v1",
    			"metadata": {
        			"annotations": {
            			"kubectl.kubernetes.io/last-applied-configuration": "{\"apiVersion\":\"aci.snat/v1\",\"kind\":\"SnatPolicy\",\"metadata\":{\"annotations\":{},\"name\":\"it-ns-ns-snatpolicy\"},\"spec\":{\"destIp\":[\"100.100.100.0/24\"],\"selector\":{\"namespace\":\"default\"},\"snatIp\":[\"10.2.30.50/31\"]}}\n"
        			},
        			"creationTimestamp": null,
        			"name": "it-ns-ns-snatpolicy"
    			},
    			"spec": {
        			"destIp": [
            			"100.100.100.0/24"
        			],
        			"selector": {
					"Labels": {
                				"key": "value"
            				},
            				"namespace": "default"
        			},
        			"snatIp": [
            			"10.2.30.90/30"
        			]
    			}
    		}
	}
	}`
	response, err := cont.serveRequestBody([]byte(rawJSON))
	if err != nil {
		t.Errorf("failed to mutate AdmissionRequest")
	}

	rr := response.Response
	assert.Equal(t, false, rr.Allowed)
	cont.stop()
}
