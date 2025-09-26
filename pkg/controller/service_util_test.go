package controller

import (
	"testing"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
)

func TestStringInSlice(t *testing.T) {
	list := []string{"apple", "banana", "cherry"}

	// Test existing item
	assert.True(t, stringInSlice("banana", list))

	// Test non-existing item
	assert.False(t, stringInSlice("grape", list))

	// Test empty string
	assert.False(t, stringInSlice("", list))

	// Test empty list
	assert.False(t, stringInSlice("apple", []string{}))
}

func TestValidScope(t *testing.T) {
	// Test valid scopes
	assert.True(t, validScope(""))
	assert.True(t, validScope("context"))
	assert.True(t, validScope("tenant"))
	assert.True(t, validScope("global"))

	// Test invalid scope
	assert.False(t, validScope("invalid"))
	assert.False(t, validScope("application-profile"))
}

func TestApicExtNetCreate(t *testing.T) {
	// Test IPv4 subnet creation
	ipv4Net := apicExtNetCreate("uni/tn-test/out-l3out/instP-test", "192.168.1.0/24", true, true, false)
	assert.NotNil(t, ipv4Net)
	assert.Equal(t, "192.168.1.0/24", ipv4Net.GetAttr("ip"))
	assert.Equal(t, "import-security", ipv4Net.GetAttr("scope"))

	// Test IPv6 subnet creation
	ipv6Net := apicExtNetCreate("uni/tn-test/out-l3out/instP-test", "2001:db8::/32", false, true, false)
	assert.NotNil(t, ipv6Net)
	assert.Equal(t, "2001:db8::/32", ipv6Net.GetAttr("ip"))
	assert.Equal(t, "import-security", ipv6Net.GetAttr("scope"))

	// Test with shared security
	sharedNet := apicExtNetCreate("uni/tn-test/out-l3out/instP-test", "10.0.0.0/8", true, true, true)
	assert.NotNil(t, sharedNet)
	assert.Equal(t, "import-security,shared-security", sharedNet.GetAttr("scope"))
}

func TestApicExtNetCons(t *testing.T) {
	cons := apicExtNetCons("test-contract", "common", "l3out", "ext1")
	assert.NotNil(t, cons)
	assert.Equal(t, "test-contract", cons.GetAttr("tnVzBrCPName"))
}

func TestApicExtNetProv(t *testing.T) {
	prov := apicExtNetProv("test-contract", "common", "l3out", "ext1")
	assert.NotNil(t, prov)
	assert.Equal(t, "test-contract", prov.GetAttr("tnVzBrCPName"))
}

func TestApicContract(t *testing.T) {
	// Test basic contract
	contract := apicContract("test-contract", "common", "test-graph", "context", false, false)
	assert.NotNil(t, contract)
	assert.Equal(t, "test-contract", contract.GetAttr("name"))

	// Test contract with custom scope
	contractGlobal := apicContract("test-contract", "common", "test-graph", "global", false, false)
	assert.NotNil(t, contractGlobal)
	assert.Equal(t, "global", contractGlobal.GetAttr("scope"))

	// Test SNAT PBR filter chain contract
	snatContract := apicContract("test-contract", "common", "test-graph", "global", true, false)
	assert.NotNil(t, snatContract)
	// Check that it was created successfully
	assert.Equal(t, "test-contract", snatContract.GetAttr("name"))
}

func TestApicExtNet(t *testing.T) {
	ingresses := []string{
		"192.168.1.0/24",
		"10.0.0.1/32",
		"2001:db8::/64",
	}

	// Test with SNAT
	extNetSnat := apicExtNet("test-snat", "common", "l3out", ingresses, true, true)
	assert.NotNil(t, extNetSnat)
	assert.Equal(t, "test-snat", extNetSnat.GetAttr("name"))

	// Test without SNAT (provider)
	extNetProv := apicExtNet("test-prov", "common", "l3out", ingresses, false, false)
	assert.NotNil(t, extNetProv)
	assert.Equal(t, "test-prov", extNetProv.GetAttr("name"))

	// Check that the external network was created successfully
	assert.Equal(t, "test-snat", extNetSnat.GetAttr("name"))
}

// Test getProtocolStr function - Protocol string conversion utility
func TestGetProtocolStrExpanded(t *testing.T) {
	tests := []struct {
		name     string
		proto    v1.Protocol
		expected string
	}{
		{
			name:     "TCP protocol",
			proto:    v1.ProtocolTCP,
			expected: "tcp",
		},
		{
			name:     "UDP protocol",
			proto:    v1.ProtocolUDP,
			expected: "udp",
		},
		{
			name:     "SCTP protocol",
			proto:    v1.ProtocolSCTP,
			expected: "sctp",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getProtocolStr(tt.proto)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Test transformMac function - MAC address transformation utility
func TestTransformMac(t *testing.T) {
	tests := []struct {
		name     string
		mac      string
		expected string
	}{
		{
			name:     "Standard MAC with colons",
			mac:      "aa:bb:cc:dd:ee:ff",
			expected: "aa-bb-cc-dd-ee-ff",
		},
		{
			name:     "Uppercase MAC with colons",
			mac:      "AA:BB:CC:DD:EE:FF",
			expected: "AA-BB-CC-DD-EE-FF",
		},
		{
			name:     "MAC already with dashes",
			mac:      "aa-bb-cc-dd-ee-ff",
			expected: "aa-bb-cc-dd-ee-ff",
		},
		{
			name:     "Empty string",
			mac:      "",
			expected: "",
		},
		{
			name:     "Single colon",
			mac:      "aa:bb",
			expected: "aa-bb",
		},
		{
			name:     "No separator",
			mac:      "aabbccddeeff",
			expected: "aabbccddeeff",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := transformMac(tt.mac)
			assert.Equal(t, tt.expected, result)
		})
	}
}
