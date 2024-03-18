package hostagent

import (
	"fmt"
	"testing"
	"time"

	fabattv1 "github.com/noironetworks/aci-containers/pkg/fabricattachment/apis/aci.fabricattachment/v1"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestGetGlobalFabricVlanPool(t *testing.T) {
	agent := &HostAgent{
		fabricVlanPoolMap: map[string]map[string]string{
			"aci-containers-system": {
				"default":    "[3023,3700-3701,3801,3804-3805,3826-3827,3829-3830,3840,3850-3852,3877-3879]",
				"additional": "[100]",
			},
			"default": {
				"test":       "[610]",
				"additional": "[3000]",
			},
		},
	}

	expected := "3023,3700-3701,3801,3804-3805,3826-3827,3829-3830,3840,3850-3852,3877-3879,100,610,3000"
	result := agent.getGlobalFabricVlanPool()

	assert.Equal(t, expected, result, "global fabric vlan pool")
}
func TestFabricVlanPoolDeleted(t *testing.T) {

	agent := testAgent()
	agent.run()
	defer agent.stop()

	obj := &fabattv1.FabricVlanPool{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "default",
			Namespace: "aci-containers-system",
		},
		Spec: fabattv1.FabricVlanPoolSpec{
			Vlans: []string{"102", "105"},
		},
	}

	agent.fakeFabricVlanPoolSource.Add(obj)
	time.Sleep(200 * time.Millisecond)
	fmt.Println(agent.fabricVlanPoolMap)
	agent.fabricVlanPoolDeleted(obj)
	assert.Equal(t, "", agent.getGlobalFabricVlanPool(), "global fabric vlan pool")
}
func TestFabricVlanPoolDeleted2(t *testing.T) {
	agent := testAgent()
	agent.run()
	defer agent.stop()

	fabricVlanPoolMap := map[string]map[string]string{
		"aci-containers-system": {
			"default":    "[3023,3700-3701,3801,3804-3805,3826-3827,3829-3830,3840,3850-3852,3877-3879]",
			"additional": "[100]",
		},
		"default": {
			"test":       "[610]",
			"additional": "[3000]",
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
		"aci-containers-system": {"additional": "[100]"}, "default": {"additional": "[3000]", "test": "[610]"},
	}
	assert.Equal(t, expectedMap, agent.fabricVlanPoolMap, "fabricVlanPoolMap")

	expectedGlobalPool := "610,3000,100"
	result := agent.getGlobalFabricVlanPool()
	assert.Equal(t, expectedGlobalPool, result, "global fabric vlan pool")
}
