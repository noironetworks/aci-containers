package hostagent

import "testing"

func TestNormalizeRemoteAddr(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "ipv4 bare", in: "10.1.2.3", want: "10.1.2.3/32"},
		{name: "ipv6 bare", in: "2001:db8::10", want: "2001:db8::10/128"},
		{name: "ipv4 cidr unchanged", in: "10.1.2.0/24", want: "10.1.2.0/24"},
		{name: "ipv6 cidr unchanged", in: "2001:db8::/64", want: "2001:db8::/64"},
		{name: "invalid unchanged", in: "not-an-ip", want: "not-an-ip"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeRemoteAddr(tt.in)
			if got != tt.want {
				t.Fatalf("normalizeRemoteAddr(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestProtocolNameToNumber(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want int
	}{
		{name: "udp", in: "udp", want: 17},
		{name: "icmp", in: "icmp", want: 1},
		{name: "tcp", in: "tcp", want: 6},
		{name: "icmpv6", in: "icmpv6", want: 58},
		{name: "case insensitive", in: "ICMPV6", want: 58},
		{name: "unknown", in: "sctp", want: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := protocolNameToNumber(tt.in)
			if got != tt.want {
				t.Fatalf("protocolNameToNumber(%q) = %d, want %d", tt.in, got, tt.want)
			}
		})
	}
}
