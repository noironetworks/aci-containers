// Copyright 2023 Cisco Systems, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package hostagent

import (
	"testing"

	fabattv1 "github.com/noironetworks/aci-containers/pkg/fabricattachment/apis/aci.fabricattachment/v1"
	fabattclientset "github.com/noironetworks/aci-containers/pkg/fabricattachment/clientset/versioned"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestGetGlobalFabricVlanPool(t *testing.T) {
	agent := &HostAgent{
		fabricVlanPoolMap: map[string]map[string]string{
			"aci-containers-system": {
				"default": "[3023,3700-3701,3801,3804-3805,3826-3827,3829-3830,3840,3850-3852,3877-3879]",
			},
		},
	}

	expected := "3023,3700-3701,3801,3804-3805,3826-3827,3829-3830,3840,3850-3852,3877-3879"
	result := agent.getGlobalFabricVlanPool()

	assert.Equal(t, expected, result, "global fabric vlan pool")
}

func TestFabricVlanPoolDeleted(t *testing.T) {
	agent := testAgent()
	fabricVlanPoolMap := map[string]map[string]string{
		"aci-containers-system": {
			"default":    "[3023,3700-3701,3801,3804-3805,3826-3827,3829-3830,3840,3850-3852,3877-3879]",
			"additional": "[100]",
		},
	}

	agent.fabricVlanPoolMap = fabricVlanPoolMap

	obj := &fabattv1.FabricVlanPool{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "default",
			Namespace: "aci-containers-system",
		},
		Spec: fabattv1.FabricVlanPoolSpec{
			Vlans: []string{"102", "105"},
		},
	}

	agent.fabricVlanPoolDeleted(obj)

	expectedMap := map[string]map[string]string{
		"aci-containers-system": {"additional": "[100]"},
	}
	assert.Equal(t, expectedMap, agent.fabricVlanPoolMap, "fabricVlanPoolMap")

	expectedGlobalPool := "100"
	result := agent.getGlobalFabricVlanPool()
	assert.Equal(t, expectedGlobalPool, result, "global fabric vlan pool")
}
func TestGetFabricVlanPool(t *testing.T) {
	agent := &HostAgent{
		fabricVlanPoolMap: map[string]map[string]string{
			"aci-containers-system": {
				"default": "[3023]",
			},
		},
	}

	expected1 := "3023"
	result1 := agent.getFabricVlanPool("aci-containers-system", false)
	assert.Equal(t, expected1, result1, "fabric vlan pool for existing namespace")

	expected2 := "3023"
	result2 := agent.getFabricVlanPool("non-existent-namespace", false)
	assert.Equal(t, expected2, result2, "fabric vlan pool for non-existent namespace")

	expected3 := "3023"
	result3 := agent.getFabricVlanPool("aci-containers-system", true)
	assert.Equal(t, expected3, result3, "fabric vlan pool for existing namespace with locked indexMutex")
}
func TestInitFabricVlanPoolsInformerFromClient(t *testing.T) {
	client := &fabattclientset.Clientset{}

	agent := testAgent()
	agent.initFabricVlanPoolsInformerFromClient(client)

	assert.NotNil(t, agent.fabricVlanPoolInformer, "fabricVlanPoolInformer")
}
