// Copyright 2026 Cisco Systems, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRATIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package hostagent

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestProtocolNameToNumber(t *testing.T) {
	tests := []struct {
		name     string
		protocol string
		expected int
	}{
		{"tcp lowercase", "tcp", 6},
		{"udp lowercase", "udp", 17},
		{"icmp lowercase", "icmp", 1},
		{"icmpv6 lowercase", "icmpv6", 58},
		{"sctp lowercase", "sctp", 132},
		{"tcp uppercase", "TCP", 6},
		{"udp uppercase", "UDP", 17},
		{"icmp mixed case", "IcMp", 1},
		{"icmpv6 mixed case", "ICMPv6", 58},
		{"sctp uppercase", "SCTP", 132},
		{"unknown protocol", "foo", 0},
		{"empty string", "", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, protocolNameToNumber(tt.protocol))
		})
	}
}

func TestNormalizeRemoteAddr(t *testing.T) {
	tests := []struct {
		name     string
		addr     string
		expected string
	}{
		{"bare IPv4", "10.0.0.1", "10.0.0.1/32"},
		{"IPv4 with CIDR unchanged", "10.0.0.0/24", "10.0.0.0/24"},
		{"bare IPv6", "2001:db8::1", "2001:db8::1/128"},
		{"IPv6 with CIDR unchanged", "2001:db8::/64", "2001:db8::/64"},
		{"invalid address unchanged", "not-an-ip", "not-an-ip"},
		{"empty string unchanged", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, normalizeRemoteAddr(tt.addr))
		})
	}
}
