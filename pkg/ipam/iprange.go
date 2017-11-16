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

// Provides tools for handling IP address ranges
package ipam

import (
	"bytes"
	"net"
)

func Range2Cidr(start, end net.IP) (r []*net.IPNet) {
	maxLen := 8 * len(start)
	endOfRange := make([]byte, len(start))
	for i := 0; i < len(start); i++ {
		endOfRange[i] = 0xFF
	}
	for bytes.Compare(start, end) <= 0 {
		l := maxLen
		for l > 0 {
			m := net.CIDRMask(l-1, maxLen)
			firstAddr := start.Mask(m)
			lastAddr := last(start, m)
			if bytes.Compare(start, firstAddr) != 0 ||
				bytes.Compare(lastAddr, end) > 0 {
				break
			}
			l--
		}
		r = append(r, &net.IPNet{IP: start, Mask: net.CIDRMask(l, maxLen)})
		lastAddr := last(start, net.CIDRMask(l, maxLen))
		if bytes.Compare(lastAddr, endOfRange) == 0 {
			break
		}
		start = next(lastAddr)
	}
	return
}

func subnetRange(subnet *net.IPNet) (start net.IP, end net.IP) {
	start = subnet.IP.Mask(subnet.Mask)
	end = last(start, subnet.Mask)
	return
}

func next(ip net.IP) net.IP {
	n := len(ip)
	out := make(net.IP, n)
	copy := false
	for n > 0 {
		n--
		if copy {
			out[n] = ip[n]
			continue
		}
		if ip[n] < 255 {
			out[n] = ip[n] + 1
			copy = true
			continue
		}
		out[n] = 0
	}
	return out
}

func last(ip net.IP, mask net.IPMask) net.IP {
	n := len(ip)
	out := make(net.IP, n)
	for i := 0; i < n; i++ {
		out[i] = ip[i] | ^mask[i]
	}
	return out
}
