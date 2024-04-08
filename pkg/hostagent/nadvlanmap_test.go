package hostagent

import (
	"testing"

	"k8s.io/client-go/tools/cache"
)

func TestInitNadVlanInformerBase(t *testing.T) {
	agent := testAgent()
	listWatch := &cache.ListWatch{}

	agent.initNadVlanInformerBase(listWatch)

	if agent.nadVlanMapInformer == nil {
		t.Error("Expected nadVlanMapInformer to be created, but it is nil")
	}
}
func TestNormalizeVlanList(t *testing.T) {
	agent := testAgent()

	// Test case 1: Single VLAN
	vlanList := []string{"100"}
	expectedResult := "[100]"
	normalizedVlan, err := agent.normalizeVlanList(vlanList)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if normalizedVlan != expectedResult {
		t.Errorf("Expected normalizedVlan to be %s, but got %s", expectedResult, normalizedVlan)
	}

	// Test case 2: VLAN range
	vlanList = []string{"10-20"}
	expectedResult = "[10-20]"
	normalizedVlan, err = agent.normalizeVlanList(vlanList)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if normalizedVlan != expectedResult {
		t.Errorf("Expected normalizedVlan to be %s, but got %s", expectedResult, normalizedVlan)
	}

	// Test case 3: Multiple VLANs
	vlanList = []string{"100,200,300"}
	expectedResult = "[100,200,300]"
	normalizedVlan, err = agent.normalizeVlanList(vlanList)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if normalizedVlan != expectedResult {
		t.Errorf("Expected normalizedVlan to be %s, but got %s", expectedResult, normalizedVlan)
	}

	// Test case 4: Mixed VLANs and VLAN ranges
	vlanList = []string{"100,200-205,300"}
	expectedResult = "[100,200-205,300]"
	normalizedVlan, err = agent.normalizeVlanList(vlanList)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if normalizedVlan != expectedResult {
		t.Errorf("Expected normalizedVlan to be %s, but got %s", expectedResult, normalizedVlan)
	}
}
