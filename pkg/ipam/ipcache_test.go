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

package ipam

import (
	"github.com/stretchr/testify/assert"
	"net"
	"testing"
)

var testIpPool = []IpRange{
	{Start: net.ParseIP("10.0.0.1"), End: net.ParseIP("10.0.0.9")},
	{Start: net.ParseIP("2:2::1"), End: net.ParseIP("2:2::9")},
}

type fakeHostagent struct {
	fakepodIps *IpCache
}

var verifyAllocIpv4 = []net.IP{
	net.ParseIP("10.0.0.1"),
	net.ParseIP("10.0.0.2"),
	net.ParseIP("10.0.0.3"),
	net.ParseIP("10.0.0.4"),
	net.ParseIP("10.0.0.5"),
	net.ParseIP("10.0.0.6"),
	net.ParseIP("10.0.0.7"),
	net.ParseIP("10.0.0.8"),
	net.ParseIP("10.0.0.9"),
}

var verifyCombv4 = []IpRange{
	{
		Start: net.ParseIP("10.0.0.1"),
		End:   net.ParseIP("10.0.0.9"),
	},
}

var verifyAllocIpv6 = []net.IP{
	net.ParseIP("2:2::1"),
	net.ParseIP("2:2::2"),
	net.ParseIP("2:2::3"),
	net.ParseIP("2:2::4"),
	net.ParseIP("2:2::5"),
	net.ParseIP("2:2::6"),
	net.ParseIP("2:2::7"),
	net.ParseIP("2:2::8"),
	net.ParseIP("2:2::9"),
}

var verifyCombv6 = []IpRange{
	{
		Start: net.ParseIP("2:2::1"),
		End:   net.ParseIP("2:2::9"),
	},
}

var emptyIpPool = []IpRange{}

var invalidIpPool = []IpRange{
	{
		Start: net.ParseIP("333.1.1.1"),
		End:   net.ParseIP("443.1.1.1"),
	},
}

func TestInvalidIpPool(t *testing.T) {
	var fakeagent fakeHostagent
	ipv4 := true
	ipv6 := false

	fakeagent.fakepodIps = NewIpCache()
	fakeagent.fakepodIps.LoadRanges(invalidIpPool)

	for _, ipr := range verifyAllocIpv4 {
		if ipr.To4() == nil {
			continue
		}
		ipr, err := fakeagent.fakepodIps.AllocateIp(ipv4)
		assert.Error(t, err, "Invalid ip pool")
		assert.Nil(t, ipr, "Invalid ip pool")
	}
	for _, ipr := range verifyAllocIpv6 {
		if ipr.To16() == nil {
			continue
		}
		ipr, err := fakeagent.fakepodIps.AllocateIp(ipv6)
		assert.Error(t, err, "Invalid ip pool")
		assert.Nil(t, ipr, "Invalid ip pool")
	}

}

func TestEmptyIpPool(t *testing.T) {
	var fakeagent fakeHostagent
	ipv4 := true
	ipv6 := false
	fakeagent.fakepodIps = NewIpCache()
	fakeagent.fakepodIps.LoadRanges(emptyIpPool)

	for _, ipr := range verifyAllocIpv4 {
		if ipr.To4() == nil {
			continue
		}
		ipr, err := fakeagent.fakepodIps.AllocateIp(ipv4)
		assert.Error(t, err, "Invalid ip pool")
		assert.Nil(t, ipr, "Invalid ip pool")
	}
	for _, ipr := range verifyAllocIpv6 {
		if ipr.To16() == nil {
			continue
		}
		ipr, err := fakeagent.fakepodIps.AllocateIp(ipv6)
		assert.Error(t, err, "Empty ip pool")
		assert.Nil(t, ipr, "Empty ip pool")
	}
}

func TestHasIp(t *testing.T) {
	var fakeagent fakeHostagent

	fakeagent.fakepodIps = NewIpCache()
	fakeagent.fakepodIps.LoadRanges(testIpPool)
	ipt := net.ParseIP("10.0.0.3")
	assert.True(t, HasIp(fakeagent.fakepodIps.GetV4IpCache()[0],
		ipt), "verify v4 present")
	ipt = net.ParseIP("10.0.0.31")
	assert.False(t, HasIp(fakeagent.fakepodIps.GetV4IpCache()[0],
		ipt), "verify v4 not present")
	ipt = net.ParseIP("10.0.0.0")
	assert.False(t, HasIp(fakeagent.fakepodIps.GetV4IpCache()[0],
		ipt), "verify v4 not present")
}

func TestIpCache(t *testing.T) {

	var fakeagent fakeHostagent
	ipv4 := true
	ipv6 := false
	var v4out []net.IP
	var v6out []net.IP

	fakeagent.fakepodIps = NewIpCache()
	fakeagent.fakepodIps.LoadRanges(testIpPool)

	for _, ipr := range verifyAllocIpv4 {
		if ipr.To4() == nil {
			continue
		}
		ipr, err := fakeagent.fakepodIps.AllocateIp(ipv4)
		if err != nil {
			t.Error("\n Failed to Allocate IPv4")
		} else {
			v4out = append(v4out, ipr)
		}
	}
	assert.Equal(t, verifyAllocIpv4, v4out, "verify v4 Alloc")
	assert.Equal(t, 0, len(fakeagent.fakepodIps.GetV4IpCache()[0].FreeList),
		"verify v4 alloc")

	for _, ipr := range verifyAllocIpv4 {
		fakeagent.fakepodIps.DeallocateIp(ipr)
		assert.False(t, HasIp(fakeagent.fakepodIps.GetV4IpCache()[0],
			ipr), "verify v4 dealloc")
		assert.True(t, HasIp(fakeagent.fakepodIps.GetV4IpCache()[1],
			ipr), "verify v4 dealloc")
		ipr, v4out = v4out[0], v4out[1:]
	}
	for _, ipr := range verifyAllocIpv4 {
		if ipr.To4() == nil {
			continue
		}
		ipr, err := fakeagent.fakepodIps.AllocateIp(ipv4)
		if err != nil {
			t.Error("\n Failed to Allocate IPv4")
		} else {
			v4out = append(v4out, ipr)
		}
	}
	assert.Equal(t, verifyAllocIpv4, v4out, "verify v4 Alloc")
	assert.Equal(t, 0, len(fakeagent.fakepodIps.GetV4IpCache()[0].FreeList),
		"verify v4 alloc")

	for _, ipr := range verifyAllocIpv6 {
		if ipr.To16() == nil {
			continue
		}
		ipr, err := fakeagent.fakepodIps.AllocateIp(ipv6)
		if err != nil {
			t.Error("\n Failed to Allocate IPv6")
		} else {
			v6out = append(v6out, ipr)
		}
	}
	assert.Equal(t, verifyAllocIpv6, v6out, "verify v6 Alloc")
	assert.Equal(t, 0, len(fakeagent.fakepodIps.GetV6IpCache()[0].FreeList),
		"verify v6 alloc")

	for _, ipr := range verifyAllocIpv6 {
		fakeagent.fakepodIps.DeallocateIp(ipr)
		assert.False(t, HasIp(fakeagent.fakepodIps.GetV6IpCache()[0],
			ipr), "verify v6 dealloc")
		assert.True(t, HasIp(fakeagent.fakepodIps.GetV6IpCache()[1],
			ipr), "verify v6 dealloc")
		ipr, v6out = v6out[0], v6out[1:]
	}

	for _, ipr := range verifyAllocIpv6 {
		if ipr.To16() == nil {
			continue
		}
		ipr, err := fakeagent.fakepodIps.AllocateIp(ipv6)
		if err != nil {
			t.Error("\n Failed to Allocate IPv6")
		} else {
			v6out = append(v6out, ipr)
		}
	}
	assert.Equal(t, verifyAllocIpv6, v6out, "verify v6 Alloc")
	assert.Equal(t, 0, len(fakeagent.fakepodIps.GetV6IpCache()[0].FreeList),
		"verify v6 alloc")

	iptest := net.ParseIP("10.0.0.3")
	fakeagent.fakepodIps.DeallocateIp(iptest)
	assert.False(t, HasIp(fakeagent.fakepodIps.GetV4IpCache()[0],
		iptest), "verify v4 dealloc")
	assert.True(t, HasIp(fakeagent.fakepodIps.GetV4IpCache()[1],
		iptest), "verify v4 dealloc")
}

func TestRemoveIp(t *testing.T) {
	var fakeagent fakeHostagent

	fakeagent.fakepodIps = NewIpCache()
	fakeagent.fakepodIps.LoadRanges(testIpPool)

	fakeagent.fakepodIps.RemoveIp(net.ParseIP("10.0.0.3"))
	assert.False(t, HasIp(fakeagent.fakepodIps.GetV4IpCache()[1],
		net.ParseIP("10.0.0.3")), "verify v4 removeIP")
	fakeagent.fakepodIps.RemoveIp(net.ParseIP("2:2::1"))
	assert.False(t, HasIp(fakeagent.fakepodIps.GetV6IpCache()[1],
		net.ParseIP("2:2::1")), "verify v6 removeIp")
}

func TestCombine(t *testing.T) {

	var fakeagent fakeHostagent
	var combv4, combv6 []IpRange

	fakeagent.fakepodIps = NewIpCache()
	fakeagent.fakepodIps.LoadRanges(testIpPool)

	combv4 = fakeagent.fakepodIps.CombineV4()
	combv6 = fakeagent.fakepodIps.CombineV6()
	assert.Equal(t, verifyCombv4, combv4, "verify the combine")
	assert.Equal(t, verifyCombv6, combv6, "verify the combine")
}
