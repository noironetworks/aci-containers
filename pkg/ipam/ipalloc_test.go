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
	"fmt"
	"math"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

type carryIncrementTest struct {
	input       []byte
	output      []byte
	outputCarry bool
	desc        string
}

var carryIncrementTests = []carryIncrementTest{
	{[]byte{1, 255, 254}, []byte{1, 255, 255}, false, "no carry"},
	{[]byte{1, 255, 255}, []byte{2, 0, 0}, false, "carry partial"},
	{[]byte{255, 255, 255}, []byte{0, 0, 0}, true, "carry total"},
}

func TestCarryIncrement(t *testing.T) {
	for _, ct := range carryIncrementTests {
		out, outCarry := carryIncrement(ct.input)
		assert.Equal(t, ct.output, out, ct.desc)
		assert.Equal(t, ct.outputCarry, outCarry, ct.desc)
	}
}

type carryDecrementTest struct {
	input       []byte
	output      []byte
	outputCarry bool
	desc        string
}

var carryDecrementTests = []carryDecrementTest{
	{[]byte{1, 255, 254}, []byte{1, 255, 253}, false, "no carry"},
	{[]byte{1, 0, 0}, []byte{0, 255, 255}, false, "carry partial"},
	{[]byte{0, 0, 0}, []byte{255, 255, 255}, true, "carry total"},
}

func TestCarryDecrement(t *testing.T) {
	for _, ct := range carryDecrementTests {
		out, outCarry := carryDecrement(ct.input)
		assert.Equal(t, ct.output, out, ct.desc)
		assert.Equal(t, ct.outputCarry, outCarry, ct.desc)
	}
}

type addRangeTest struct {
	input    []IpRange
	freeList []IpRange
	desc     string
}

var addRangeTests = []addRangeTest{
	{[]IpRange{}, []IpRange{}, "empty"},
	{
		[]IpRange{
			{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.1.254")},
		},
		[]IpRange{
			{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.1.254")},
		},
		"simple",
	},
	{
		[]IpRange{
			{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.1.254")},
			{net.ParseIP("10.0.2.1"), net.ParseIP("10.0.2.254")},
		},
		[]IpRange{
			{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.1.254")},
			{net.ParseIP("10.0.2.1"), net.ParseIP("10.0.2.254")},
		},
		"Separate",
	},
	{
		[]IpRange{
			{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.2.1")},
			{net.ParseIP("10.0.2.1"), net.ParseIP("10.0.2.254")},
		},
		[]IpRange{
			{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.2.254")},
		},
		"Overlapping by one",
	},
	{
		[]IpRange{
			{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.2.3")},
			{net.ParseIP("10.0.2.1"), net.ParseIP("10.0.2.254")},
		},
		[]IpRange{
			{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.2.254")},
		},
		"Overlapping by more",
	},
	{
		[]IpRange{
			{net.ParseIP("10.0.2.1"), net.ParseIP("10.0.2.254")},
			{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.2.3")},
		},
		[]IpRange{
			{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.2.254")},
		},
		"Out of order",
	},
	{
		[]IpRange{
			{net.ParseIP("10.0.2.1"), net.ParseIP("10.0.2.254")},
			{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.2.3")},
			{net.ParseIP("192.168.0.1"), net.ParseIP("192.168.0.1")},
		},
		[]IpRange{
			{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.2.254")},
			{net.ParseIP("192.168.0.1"), net.ParseIP("192.168.0.1")},
		},
		"Multiple separate",
	},
	{
		[]IpRange{
			{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.2.3")},
			{net.ParseIP("10.0.2.4"), net.ParseIP("10.0.2.254")},
		},
		[]IpRange{
			{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.2.254")},
		},
		"Adjacent",
	},
	{
		[]IpRange{
			{net.ParseIP("10.0.0.1"), net.ParseIP("10.255.255.255")},
			{net.ParseIP("11.0.0.0"), net.ParseIP("11.255.255.255")},
		},
		[]IpRange{
			{net.ParseIP("10.0.0.1"), net.ParseIP("11.255.255.255")},
		},
		"Adjacent carry",
	},
	{
		[]IpRange{
			{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.2.2")},
			{net.ParseIP("10.0.2.4"), net.ParseIP("10.0.2.254")},
		},
		[]IpRange{
			{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.2.2")},
			{net.ParseIP("10.0.2.4"), net.ParseIP("10.0.2.254")},
		},
		"Separate by one",
	},
	{
		[]IpRange{
			{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.2.3")},
			{net.ParseIP("10.0.2.4"), net.ParseIP("10.0.2.254")},
			{net.ParseIP("10.0.2.3"), net.ParseIP("10.0.2.4")},
		},
		[]IpRange{
			{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.2.254")},
		},
		"merge",
	},
	{
		[]IpRange{
			{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.2.3")},
			{net.ParseIP("10.0.2.10"), net.ParseIP("10.0.2.254")},
			{net.ParseIP("10.0.2.5"), net.ParseIP("10.0.2.6")},
		},
		[]IpRange{
			{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.2.3")},
			{net.ParseIP("10.0.2.5"), net.ParseIP("10.0.2.6")},
			{net.ParseIP("10.0.2.10"), net.ParseIP("10.0.2.254")},
		},
		"can't merge",
	},
	{
		[]IpRange{
			{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.2.3")},
			{net.ParseIP("10.0.2.10"), net.ParseIP("10.0.2.254")},
			{net.ParseIP("10.0.2.5"), net.ParseIP("10.0.2.6")},
			{net.ParseIP("10.0.2.3"), net.ParseIP("10.0.2.5")},
			{net.ParseIP("10.0.2.6"), net.ParseIP("10.0.2.10")},
		},
		[]IpRange{
			{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.2.254")},
		},
		"complex merge",
	},
	{
		[]IpRange{
			{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.2.3")},
			{net.ParseIP("10.0.2.10"), net.ParseIP("10.0.2.254")},
			{net.ParseIP("10.0.2.5"), net.ParseIP("10.0.2.6")},
			{net.ParseIP("10.0.2.4"), net.ParseIP("10.0.2.4")},
			{net.ParseIP("10.0.2.7"), net.ParseIP("10.0.2.10")},
		},
		[]IpRange{
			{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.2.254")},
		},
		"complex merge adjacent",
	},
}

func TestAddRange(t *testing.T) {
	for i, rt := range addRangeTests {
		ipa := New()
		ipa.AddRanges(rt.input)
		assert.Equal(t, rt.freeList, ipa.FreeList,
			fmt.Sprintf("AddRange %d: %s", i, rt.desc))
	}
}

type addSubnetTest struct {
	input    []string
	freeList []IpRange
	desc     string
}

var addSubnetTests = []addSubnetTest{
	{[]string{}, []IpRange{}, "empty"},
	{
		[]string{"192.168.0.0/16"},
		[]IpRange{
			{net.IP{192, 168, 0, 0}, net.IP{192, 168, 255, 255}},
		},
		"simple",
	},
	{
		[]string{"192.168.0.0/17"},
		[]IpRange{
			{net.IP{192, 168, 0, 0}, net.IP{192, 168, 127, 255}},
		},
		"nonbyte",
	},
}

func TestAddSubnet(t *testing.T) {
	for i, st := range addSubnetTests {
		ipa := New()
		for _, sub := range st.input {
			_, net, _ := net.ParseCIDR(sub)
			ipa.AddSubnet(net)
		}
		assert.Equal(t, st.freeList, ipa.FreeList,
			fmt.Sprintf("AddSubnet %d: %s", i, st.desc))
	}
}

type removeRangeTest struct {
	add      []IpRange
	remove   []IpRange
	freeList []IpRange
	changed  bool
	desc     string
}

var removeRangeTests = []removeRangeTest{
	{
		[]IpRange{},
		[]IpRange{
			{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.1.254")},
		},
		[]IpRange{},
		false,
		"empty",
	},
	{
		[]IpRange{
			{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.1.254")},
		},
		[]IpRange{
			{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.1.254")},
		},
		[]IpRange{},
		true,
		"whole",
	},
	{
		[]IpRange{
			{net.ParseIP("10.0.1.0"), net.ParseIP("10.0.1.254")},
		},
		[]IpRange{
			{net.ParseIP("10.0.0.100"), net.ParseIP("10.0.0.255")},
		},
		[]IpRange{
			{net.ParseIP("10.0.1.0"), net.ParseIP("10.0.1.254")},
		},
		false,
		"miss left",
	},
	{
		[]IpRange{
			{net.ParseIP("10.0.1.0"), net.ParseIP("10.0.1.254")},
		},
		[]IpRange{
			{net.ParseIP("10.0.2.128"), net.ParseIP("10.0.2.255")},
		},
		[]IpRange{
			{net.ParseIP("10.0.1.0"), net.ParseIP("10.0.1.254")},
		},
		false,
		"miss right",
	},
	{
		[]IpRange{
			{net.ParseIP("10.0.1.0"), net.ParseIP("10.0.1.254")},
		},
		[]IpRange{
			{net.ParseIP("10.0.0.100"), net.ParseIP("10.0.1.127")},
		},
		[]IpRange{
			{net.ParseIP("10.0.1.128"), net.ParseIP("10.0.1.254")},
		},
		true,
		"left overlap",
	},
	{
		[]IpRange{
			{net.ParseIP("10.0.1.0"), net.ParseIP("10.0.1.254")},
		},
		[]IpRange{
			{net.ParseIP("10.0.0.100"), net.ParseIP("10.0.1.0")},
		},
		[]IpRange{
			{net.ParseIP("10.0.1.1"), net.ParseIP("10.0.1.254")},
		},
		true,
		"left touch",
	},
	{
		[]IpRange{
			{net.ParseIP("10.0.1.0"), net.ParseIP("10.0.1.254")},
		},
		[]IpRange{
			{net.ParseIP("10.0.1.0"), net.ParseIP("10.0.1.127")},
		},
		[]IpRange{
			{net.ParseIP("10.0.1.128"), net.ParseIP("10.0.1.254")},
		},
		true,
		"left touch 2",
	},
	{
		[]IpRange{
			{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.254")},
			{net.ParseIP("10.0.1.128"), net.ParseIP("10.0.1.254")},
			{net.ParseIP("10.10.0.0"), net.ParseIP("10.10.1.254")},
		},
		[]IpRange{
			{net.ParseIP("10.0.1.100"), net.ParseIP("10.0.1.212")},
		},
		[]IpRange{
			{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.254")},
			{net.ParseIP("10.0.1.213"), net.ParseIP("10.0.1.254")},
			{net.ParseIP("10.10.0.0"), net.ParseIP("10.10.1.254")},
		},
		true,
		"left overlap search",
	},
	{
		[]IpRange{
			{net.ParseIP("10.0.1.0"), net.ParseIP("10.0.1.254")},
		},
		[]IpRange{
			{net.ParseIP("10.0.1.128"), net.ParseIP("10.0.2.128")},
		},
		[]IpRange{
			{net.ParseIP("10.0.1.0"), net.ParseIP("10.0.1.127")},
		},
		true,
		"right overlap",
	},
	{
		[]IpRange{
			{net.ParseIP("10.0.1.0"), net.ParseIP("10.0.1.254")},
		},
		[]IpRange{
			{net.ParseIP("10.0.1.254"), net.ParseIP("10.0.2.128")},
		},
		[]IpRange{
			{net.ParseIP("10.0.1.0"), net.ParseIP("10.0.1.253")},
		},
		true,
		"right touch",
	},
	{
		[]IpRange{
			{net.ParseIP("10.0.1.0"), net.ParseIP("10.0.1.254")},
		},
		[]IpRange{
			{net.ParseIP("10.0.1.128"), net.ParseIP("10.0.1.254")},
		},
		[]IpRange{
			{net.ParseIP("10.0.1.0"), net.ParseIP("10.0.1.127")},
		},
		true,
		"right touch 2",
	},
	{
		[]IpRange{
			{net.ParseIP("10.0.1.0"), net.ParseIP("10.0.1.254")},
			{net.ParseIP("10.10.0.0"), net.ParseIP("10.10.1.254")},
		},
		[]IpRange{
			{net.ParseIP("10.0.1.128"), net.ParseIP("10.0.2.128")},
		},
		[]IpRange{
			{net.ParseIP("10.0.1.0"), net.ParseIP("10.0.1.127")},
			{net.ParseIP("10.10.0.0"), net.ParseIP("10.10.1.254")},
		},
		true,
		"right overlap search",
	},
	{
		[]IpRange{
			{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.254")},
			{net.ParseIP("10.0.1.0"), net.ParseIP("10.0.1.254")},
			{net.ParseIP("10.10.0.0"), net.ParseIP("10.10.1.254")},
		},
		[]IpRange{
			{net.ParseIP("10.0.1.128"), net.ParseIP("10.0.2.128")},
		},
		[]IpRange{
			{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.254")},
			{net.ParseIP("10.0.1.0"), net.ParseIP("10.0.1.127")},
			{net.ParseIP("10.10.0.0"), net.ParseIP("10.10.1.254")},
		},
		true,
		"right overlap search 2",
	},
	{
		[]IpRange{
			{net.ParseIP("10.0.1.0"), net.ParseIP("10.0.1.254")},
		},
		[]IpRange{
			{net.ParseIP("10.0.1.100"), net.ParseIP("10.0.1.127")},
		},
		[]IpRange{
			{net.ParseIP("10.0.1.0"), net.ParseIP("10.0.1.99")},
			{net.ParseIP("10.0.1.128"), net.ParseIP("10.0.1.254")},
		},
		true,
		"center overlap",
	},
	{
		[]IpRange{
			{net.ParseIP("10.0.1.1"), net.ParseIP("10.0.1.1")},
		},
		[]IpRange{
			{net.ParseIP("10.0.1.1"), net.ParseIP("10.0.1.1")},
		},
		[]IpRange{},
		true,
		"one",
	},
	{
		[]IpRange{
			{net.ParseIP("10.0.1.1"), net.ParseIP("10.0.1.255")},
		},
		[]IpRange{
			{net.ParseIP("10.0.1.127"), net.ParseIP("10.0.1.127")},
		},
		[]IpRange{
			{net.ParseIP("10.0.1.1"), net.ParseIP("10.0.1.126")},
			{net.ParseIP("10.0.1.128"), net.ParseIP("10.0.1.255")},
		},
		true,
		"one from middle",
	},
}

func TestRemoveRange(t *testing.T) {
	for i, rt := range removeRangeTests {
		ipa := NewFromRanges(rt.add)
		changed := false
		for _, r := range rt.remove {
			changed = ipa.RemoveRange(r.Start, r.End) || changed
		}
		assert.Equal(t, rt.freeList, ipa.FreeList,
			fmt.Sprintf("RemoveRange %d: %s", i, rt.desc))
		assert.Equal(t, rt.changed, changed,
			fmt.Sprintf("RemoveRange %d changed: %s", i, rt.desc))
	}
}

type removeSubnetTest struct {
	add      []string
	remove   []string
	freeList []IpRange
	changed  bool
	desc     string
}

var removeSubnetTests = []removeSubnetTest{
	{
		[]string{"192.168.0.0/16"},
		[]string{"192.168.5.0/24", "192.168.10.0/25"},
		[]IpRange{
			{net.IP{192, 168, 0, 0}, net.IP{192, 168, 4, 255}},
			{net.IP{192, 168, 6, 0}, net.IP{192, 168, 9, 255}},
			{net.IP{192, 168, 10, 128}, net.IP{192, 168, 255, 255}},
		},
		true,
		"remove",
	},
	{
		[]string{"192.168.0.0/16"},
		[]string{"192.0.0.0/8"},
		[]IpRange{},
		true,
		"overlap",
	},
}

func TestRemoveSubnet(t *testing.T) {
	for i, st := range removeSubnetTests {
		ipa := New()
		for _, sub := range st.add {
			_, net, _ := net.ParseCIDR(sub)
			ipa.AddSubnet(net)
		}
		changed := false
		for _, sub := range st.remove {
			_, net, _ := net.ParseCIDR(sub)
			changed = ipa.RemoveSubnet(net) || changed
		}

		assert.Equal(t, st.freeList, ipa.FreeList,
			fmt.Sprintf("RemoveSubnet %d: %s", i, st.desc))
		assert.Equal(t, st.changed, changed,
			fmt.Sprintf("RemoveSubnet %d changed: %s", i, st.desc))
	}
}

type getIpTest struct {
	add      []IpRange
	freeList []IpRange
	ip       net.IP
	err      bool
	desc     string
}

var getIpTests = []getIpTest{
	{
		[]IpRange{},
		[]IpRange{},
		nil,
		true,
		"empty",
	},
	{
		[]IpRange{
			{net.ParseIP("10.0.1.127"), net.ParseIP("10.0.1.127")},
		},
		[]IpRange{},
		net.ParseIP("10.0.1.127"),
		false,
		"one",
	},
	{
		[]IpRange{
			{net.ParseIP("10.0.1.127"), net.ParseIP("10.0.1.127")},
			{net.ParseIP("10.0.2.127"), net.ParseIP("10.0.2.255")},
		},
		[]IpRange{
			{net.ParseIP("10.0.2.127"), net.ParseIP("10.0.2.255")},
		},
		net.ParseIP("10.0.1.127"),
		false,
		"one with remaining",
	},
	{
		[]IpRange{
			{net.ParseIP("10.0.1.127"), net.ParseIP("10.0.1.255")},
			{net.ParseIP("10.0.2.127"), net.ParseIP("10.0.2.255")},
		},
		[]IpRange{
			{net.ParseIP("10.0.1.128"), net.ParseIP("10.0.1.255")},
			{net.ParseIP("10.0.2.127"), net.ParseIP("10.0.2.255")},
		},
		net.ParseIP("10.0.1.127"),
		false,
		"range",
	},
}

func TestGetIp(t *testing.T) {
	for i, rt := range getIpTests {
		ipa := NewFromRanges(rt.add)
		ip, err := ipa.GetIp()
		if rt.err {
			assert.NotNil(t, err, fmt.Sprintf("err %d: %s", i, rt.desc))
		}
		assert.Equal(t, rt.freeList, ipa.FreeList,
			fmt.Sprintf("freeList %d: %s", i, rt.desc))
		assert.Equal(t, rt.ip, ip,
			fmt.Sprintf("ip %d: %s", i, rt.desc))
	}
}

type getIpChunkTest struct {
	add       []IpRange
	chunkSize int64
	result    []IpRange
	freeList  []IpRange
	err       bool
	desc      string
}

var getIpChunkTests = []getIpChunkTest{
	{
		[]IpRange{},
		256,
		nil,
		[]IpRange{},
		true,
		"empty",
	},
	{
		[]IpRange{
			{net.ParseIP("10.0.1.127"), net.ParseIP("10.0.1.127")},
		},
		256,
		nil,
		[]IpRange{
			{net.ParseIP("10.0.1.127"), net.ParseIP("10.0.1.127")},
		},
		true,
		"notenough",
	},
	{
		[]IpRange{
			{net.ParseIP("10.0.1.0"), net.ParseIP("10.0.1.255")},
		},
		256,
		[]IpRange{
			{net.ParseIP("10.0.1.0"), net.ParseIP("10.0.1.255")},
		},
		[]IpRange{},
		false,
		"onechunk",
	},
	{
		[]IpRange{
			{net.ParseIP("10.0.1.127"), net.ParseIP("10.0.2.128")},
		},
		258,
		[]IpRange{
			{net.ParseIP("10.0.1.127"), net.ParseIP("10.0.2.128")},
		},
		[]IpRange{},
		false,
		"onechunk split",
	},
	{
		[]IpRange{
			{net.ParseIP("10.0.1.127"), net.ParseIP("10.0.2.10")},
			{net.ParseIP("10.0.3.9"), net.ParseIP("10.0.4.128")},
		},
		129 + 11 + 247,
		[]IpRange{
			{net.ParseIP("10.0.1.127"), net.ParseIP("10.0.2.10")},
			{net.ParseIP("10.0.3.9"), net.ParseIP("10.0.3.255")},
		},
		[]IpRange{
			{net.ParseIP("10.0.4.0"), net.ParseIP("10.0.4.128")},
		},
		false,
		"multichunk",
	},
	{
		[]IpRange{
			{net.ParseIP("fd43:85d7:bcf2:9ad2::"),
				net.ParseIP("fd43:85d7:bcf2:9ad2:ffff:ffff:ffff:ffff")},
		},
		256,
		[]IpRange{
			{net.ParseIP("fd43:85d7:bcf2:9ad2::"),
				net.ParseIP("fd43:85d7:bcf2:9ad2::ff")},
		},
		[]IpRange{
			{net.ParseIP("fd43:85d7:bcf2:9ad2::100"),
				net.ParseIP("fd43:85d7:bcf2:9ad2:ffff:ffff:ffff:ffff")},
		},
		false,
		"v6",
	},
}

func TestGetIpChunk(t *testing.T) {
	for i, rt := range getIpChunkTests {
		ipa := NewFromRanges(rt.add)
		ipchunk, err := ipa.GetIpChunk(rt.chunkSize)
		if rt.err {
			assert.NotNil(t, err, fmt.Sprintf("err %d: %s", i, rt.desc))
		}
		assert.Equal(t, rt.result, ipchunk,
			fmt.Sprintf("ipChunk %d: %s", i, rt.desc))
		assert.Equal(t, rt.freeList, ipa.FreeList,
			fmt.Sprintf("freeList %d: %s", i, rt.desc))
	}
}

type getSizeTest struct {
	add  []IpRange
	size int64
	desc string
}

var getSizeTests = []getSizeTest{
	{
		[]IpRange{},
		0,
		"empty",
	},
	{
		[]IpRange{
			{net.ParseIP("10.0.1.1"), net.ParseIP("10.0.1.255")},
			{net.ParseIP("10.0.3.9"), net.ParseIP("10.0.4.128")},
		},
		255 + 376,
		"simple",
	},
	{
		[]IpRange{
			{net.ParseIP("fd43:85d7:bcf2:9ad2::"),
				net.ParseIP("fd43:85d7:bcf2:9ad2::ffff:ffff")},
		},
		4294967296,
		"v6",
	},
	{
		[]IpRange{
			{net.ParseIP("fd43:85d7:bcf2:9ad2::"),
				net.ParseIP("fd43:85d7:bcf2:9ad2::ffff:ffff:ffff")},
		},
		0x1000000000000,
		"v6 48 bits",
	},
	{
		[]IpRange{
			{net.ParseIP("fd43:85d7:bcf2:9ad2::"),
				net.ParseIP("fd43:85d7:bcf2:9ad2:ffff:ffff:ffff:ffff")},
		},
		math.MaxInt64,
		"too big",
	},
}

func TestGetSize(t *testing.T) {
	for i, rt := range getSizeTests {
		ipa := NewFromRanges(rt.add)
		size := ipa.GetSize()
		assert.Equal(t, rt.size, size, fmt.Sprintf("size %d: %s", i, rt.desc))
	}
}

func TestEmpty(t *testing.T) {
	for i, rt := range getSizeTests {
		ipa := NewFromRanges(rt.add)
		empty := ipa.Empty()
		assert.Equal(t, rt.size == 0, empty, fmt.Sprintf("empty %d: %s", i, rt.desc))
	}
}

type intersectTest struct {
	a      []IpRange
	b      []IpRange
	result []IpRange
	desc   string
}

var intersectTests = []intersectTest{
	{
		[]IpRange{},
		[]IpRange{},
		[]IpRange{},
		"empty",
	},
	{
		[]IpRange{
			{net.ParseIP("10.0.1.1"), net.ParseIP("10.0.1.255")},
		},
		[]IpRange{
			{net.ParseIP("10.0.1.4"), net.ParseIP("10.0.1.250")},
		},
		[]IpRange{
			{net.ParseIP("10.0.1.4"), net.ParseIP("10.0.1.250")},
		},
		"middle 1",
	},
	{
		[]IpRange{
			{net.ParseIP("10.0.1.4"), net.ParseIP("10.0.1.250")},
		},
		[]IpRange{
			{net.ParseIP("10.0.1.1"), net.ParseIP("10.0.1.255")},
		},
		[]IpRange{
			{net.ParseIP("10.0.1.4"), net.ParseIP("10.0.1.250")},
		},
		"middle 2",
	},
	{
		[]IpRange{
			{net.ParseIP("10.0.1.1"), net.ParseIP("10.0.1.250")},
		},
		[]IpRange{
			{net.ParseIP("10.0.1.128"), net.ParseIP("10.0.1.255")},
		},
		[]IpRange{
			{net.ParseIP("10.0.1.128"), net.ParseIP("10.0.1.250")},
		},
		"left",
	},
	{
		[]IpRange{
			{net.ParseIP("10.0.1.1"), net.ParseIP("10.0.1.250")},
		},
		[]IpRange{
			{net.ParseIP("10.0.1.1"), net.ParseIP("10.0.1.255")},
		},
		[]IpRange{
			{net.ParseIP("10.0.1.1"), net.ParseIP("10.0.1.250")},
		},
		"left touch",
	},
	{
		[]IpRange{
			{net.ParseIP("10.0.1.1"), net.ParseIP("10.0.1.250")},
		},
		[]IpRange{
			{net.ParseIP("10.0.1.5"), net.ParseIP("10.0.1.250")},
		},
		[]IpRange{
			{net.ParseIP("10.0.1.5"), net.ParseIP("10.0.1.250")},
		},
		"right touch",
	},
	{
		[]IpRange{
			{net.ParseIP("10.0.1.1"), net.ParseIP("10.0.1.250")},
		},
		[]IpRange{
			{net.ParseIP("10.0.1.251"), net.ParseIP("10.0.1.255")},
		},
		[]IpRange{},
		"left empty",
	},
	{
		[]IpRange{
			{net.ParseIP("10.0.1.1"), net.ParseIP("10.0.1.250")},
		},
		[]IpRange{
			{net.ParseIP("10.0.1.5"), net.ParseIP("10.0.1.10")},
			{net.ParseIP("10.0.1.20"), net.ParseIP("10.0.1.25")},
		},
		[]IpRange{
			{net.ParseIP("10.0.1.5"), net.ParseIP("10.0.1.10")},
			{net.ParseIP("10.0.1.20"), net.ParseIP("10.0.1.25")},
		},
		"multiple",
	},
	{
		[]IpRange{
			{net.ParseIP("10.0.1.1"), net.ParseIP("10.0.1.250")},
		},
		[]IpRange{
			{net.ParseIP("10.0.1.5"), net.ParseIP("10.0.1.10")},
			{net.ParseIP("10.0.1.20"), net.ParseIP("10.0.1.255")},
		},
		[]IpRange{
			{net.ParseIP("10.0.1.5"), net.ParseIP("10.0.1.10")},
			{net.ParseIP("10.0.1.20"), net.ParseIP("10.0.1.250")},
		},
		"multiple",
	},
	{
		[]IpRange{
			{net.ParseIP("10.0.1.1"), net.ParseIP("10.0.1.250")},
			{net.ParseIP("10.0.2.1"), net.ParseIP("10.0.3.250")},
		},
		[]IpRange{
			{net.ParseIP("10.0.1.5"), net.ParseIP("10.0.1.10")},
			{net.ParseIP("10.0.1.20"), net.ParseIP("10.0.1.255")},
			{net.ParseIP("10.0.1.254"), net.ParseIP("10.0.2.255")},
			{net.ParseIP("10.0.4.1"), net.ParseIP("10.0.4.4")},
		},
		[]IpRange{
			{net.ParseIP("10.0.1.5"), net.ParseIP("10.0.1.10")},
			{net.ParseIP("10.0.1.20"), net.ParseIP("10.0.1.250")},
			{net.ParseIP("10.0.2.1"), net.ParseIP("10.0.2.255")},
		},
		"multiple 2",
	},
}

func TestIntersect(t *testing.T) {
	for i, rt := range intersectTests {
		a := NewFromRanges(rt.a)
		b := NewFromRanges(rt.b)
		result := NewFromRanges(rt.result)
		assert.Equal(t, result, a.Intersect(b),
			fmt.Sprintf("intersect %d: %s", i, rt.desc))
	}
}
