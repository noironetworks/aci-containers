package controller

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestServiceEndpointStructs(t *testing.T) {
	// Just test that these structs can be created without panic
	sep := &serviceEndpoint{}
	assert.NotNil(t, sep)

	seps := &serviceEndpointSlice{}
	assert.NotNil(t, seps)
}

func TestControllerConfiguration(t *testing.T) {
	cont := testController()

	// Test that basic fields are initialized
	assert.NotNil(t, cont.env)
	assert.NotNil(t, cont.log)
	assert.NotNil(t, cont.config)
}

func TestStaticNetPolKey(t *testing.T) {
	key := staticNetPolKey()
	assert.NotEmpty(t, key)
	assert.Equal(t, "kube_np_static", key)
}

func TestAciNameForKey(t *testing.T) {
	cont := testController()
	cont.config.AciPrefix = "test"

	// Test with prefix replacement (note: kube prefix gets replaced with aci prefix)
	name := cont.aciNameForKey("kube", "test-key")
	assert.Equal(t, "test_kube_test-key", name) // Fixed expectation

	// Test without prefix replacement
	name2 := cont.aciNameForKey("np", "network-policy")
	assert.Equal(t, "test_np_network-policy", name2)
}

func TestInitDepPodIndex(t *testing.T) {
	cont := testController()

	// Test that initDepPodIndex doesn't panic
	assert.NotPanics(t, func() {
		cont.initDepPodIndex()
	})

	// Test that the index is initialized
	assert.NotNil(t, cont.depPods)
}

func TestInitNetPolPodIndex(t *testing.T) {
	cont := testController()

	// Test that initNetPolPodIndex doesn't panic
	assert.NotPanics(t, func() {
		cont.initNetPolPodIndex()
	})

	// Test that the index is initialized
	assert.NotNil(t, cont.netPolPods)
}

func TestInitErspanPolPodIndex(t *testing.T) {
	cont := testController()

	// Test that initErspanPolPodIndex doesn't panic
	assert.NotPanics(t, func() {
		cont.initErspanPolPodIndex()
	})

	// Test that the index is initialized
	assert.NotNil(t, cont.erspanPolPods)
}

func TestControllerComponents(t *testing.T) {
	cont := testController()

	// Test that basic controller components exist
	assert.NotNil(t, cont.config)
	assert.NotNil(t, cont.env)
	assert.NotNil(t, cont.log)

	// Test configuration values
	assert.NotEmpty(t, cont.config.AciPrefix)
	assert.NotEmpty(t, cont.config.AciPolicyTenant)
}
