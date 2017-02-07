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
			IpRange{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.1.254")},
		},
		[]IpRange{
			IpRange{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.1.254")},
		},
		"simple",
	},
	{
		[]IpRange{
			IpRange{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.1.254")},
			IpRange{net.ParseIP("10.0.2.1"), net.ParseIP("10.0.2.254")},
		},
		[]IpRange{
			IpRange{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.1.254")},
			IpRange{net.ParseIP("10.0.2.1"), net.ParseIP("10.0.2.254")},
		},
		"Separate",
	},
	{
		[]IpRange{
			IpRange{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.2.1")},
			IpRange{net.ParseIP("10.0.2.1"), net.ParseIP("10.0.2.254")},
		},
		[]IpRange{
			IpRange{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.2.254")},
		},
		"Overlapping by one",
	},
	{
		[]IpRange{
			IpRange{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.2.3")},
			IpRange{net.ParseIP("10.0.2.1"), net.ParseIP("10.0.2.254")},
		},
		[]IpRange{
			IpRange{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.2.254")},
		},
		"Overlapping by more",
	},
	{
		[]IpRange{
			IpRange{net.ParseIP("10.0.2.1"), net.ParseIP("10.0.2.254")},
			IpRange{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.2.3")},
		},
		[]IpRange{
			IpRange{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.2.254")},
		},
		"Out of order",
	},
	{
		[]IpRange{
			IpRange{net.ParseIP("10.0.2.1"), net.ParseIP("10.0.2.254")},
			IpRange{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.2.3")},
			IpRange{net.ParseIP("192.168.0.1"), net.ParseIP("192.168.0.1")},
		},
		[]IpRange{
			IpRange{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.2.254")},
			IpRange{net.ParseIP("192.168.0.1"), net.ParseIP("192.168.0.1")},
		},
		"Multiple separate",
	},
	{
		[]IpRange{
			IpRange{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.2.3")},
			IpRange{net.ParseIP("10.0.2.4"), net.ParseIP("10.0.2.254")},
		},
		[]IpRange{
			IpRange{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.2.254")},
		},
		"Adjacent",
	},
	{
		[]IpRange{
			IpRange{net.ParseIP("10.0.0.1"), net.ParseIP("10.255.255.255")},
			IpRange{net.ParseIP("11.0.0.0"), net.ParseIP("11.255.255.255")},
		},
		[]IpRange{
			IpRange{net.ParseIP("10.0.0.1"), net.ParseIP("11.255.255.255")},
		},
		"Adjacent carry",
	},
	{
		[]IpRange{
			IpRange{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.2.2")},
			IpRange{net.ParseIP("10.0.2.4"), net.ParseIP("10.0.2.254")},
		},
		[]IpRange{
			IpRange{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.2.2")},
			IpRange{net.ParseIP("10.0.2.4"), net.ParseIP("10.0.2.254")},
		},
		"Separate by one",
	},
	{
		[]IpRange{
			IpRange{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.2.3")},
			IpRange{net.ParseIP("10.0.2.4"), net.ParseIP("10.0.2.254")},
			IpRange{net.ParseIP("10.0.2.3"), net.ParseIP("10.0.2.4")},
		},
		[]IpRange{
			IpRange{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.2.254")},
		},
		"merge",
	},
	{
		[]IpRange{
			IpRange{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.2.3")},
			IpRange{net.ParseIP("10.0.2.10"), net.ParseIP("10.0.2.254")},
			IpRange{net.ParseIP("10.0.2.5"), net.ParseIP("10.0.2.6")},
		},
		[]IpRange{
			IpRange{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.2.3")},
			IpRange{net.ParseIP("10.0.2.5"), net.ParseIP("10.0.2.6")},
			IpRange{net.ParseIP("10.0.2.10"), net.ParseIP("10.0.2.254")},
		},
		"can't merge",
	},
	{
		[]IpRange{
			IpRange{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.2.3")},
			IpRange{net.ParseIP("10.0.2.10"), net.ParseIP("10.0.2.254")},
			IpRange{net.ParseIP("10.0.2.5"), net.ParseIP("10.0.2.6")},
			IpRange{net.ParseIP("10.0.2.3"), net.ParseIP("10.0.2.5")},
			IpRange{net.ParseIP("10.0.2.6"), net.ParseIP("10.0.2.10")},
		},
		[]IpRange{
			IpRange{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.2.254")},
		},
		"complex merge",
	},
	{
		[]IpRange{
			IpRange{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.2.3")},
			IpRange{net.ParseIP("10.0.2.10"), net.ParseIP("10.0.2.254")},
			IpRange{net.ParseIP("10.0.2.5"), net.ParseIP("10.0.2.6")},
			IpRange{net.ParseIP("10.0.2.4"), net.ParseIP("10.0.2.4")},
			IpRange{net.ParseIP("10.0.2.7"), net.ParseIP("10.0.2.10")},
		},
		[]IpRange{
			IpRange{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.2.254")},
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
			IpRange{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.1.254")},
		},
		[]IpRange{},
		false,
		"empty",
	},
	{
		[]IpRange{
			IpRange{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.1.254")},
		},
		[]IpRange{
			IpRange{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.1.254")},
		},
		[]IpRange{},
		true,
		"whole",
	},
	{
		[]IpRange{
			IpRange{net.ParseIP("10.0.1.0"), net.ParseIP("10.0.1.254")},
		},
		[]IpRange{
			IpRange{net.ParseIP("10.0.0.100"), net.ParseIP("10.0.0.255")},
		},
		[]IpRange{
			IpRange{net.ParseIP("10.0.1.0"), net.ParseIP("10.0.1.254")},
		},
		false,
		"miss left",
	},
	{
		[]IpRange{
			IpRange{net.ParseIP("10.0.1.0"), net.ParseIP("10.0.1.254")},
		},
		[]IpRange{
			IpRange{net.ParseIP("10.0.2.128"), net.ParseIP("10.0.2.255")},
		},
		[]IpRange{
			IpRange{net.ParseIP("10.0.1.0"), net.ParseIP("10.0.1.254")},
		},
		false,
		"miss right",
	},
	{
		[]IpRange{
			IpRange{net.ParseIP("10.0.1.0"), net.ParseIP("10.0.1.254")},
		},
		[]IpRange{
			IpRange{net.ParseIP("10.0.0.100"), net.ParseIP("10.0.1.127")},
		},
		[]IpRange{
			IpRange{net.ParseIP("10.0.1.128"), net.ParseIP("10.0.1.254")},
		},
		true,
		"left overlap",
	},
	{
		[]IpRange{
			IpRange{net.ParseIP("10.0.1.0"), net.ParseIP("10.0.1.254")},
		},
		[]IpRange{
			IpRange{net.ParseIP("10.0.0.100"), net.ParseIP("10.0.1.0")},
		},
		[]IpRange{
			IpRange{net.ParseIP("10.0.1.1"), net.ParseIP("10.0.1.254")},
		},
		true,
		"left touch",
	},
	{
		[]IpRange{
			IpRange{net.ParseIP("10.0.1.0"), net.ParseIP("10.0.1.254")},
		},
		[]IpRange{
			IpRange{net.ParseIP("10.0.1.0"), net.ParseIP("10.0.1.127")},
		},
		[]IpRange{
			IpRange{net.ParseIP("10.0.1.128"), net.ParseIP("10.0.1.254")},
		},
		true,
		"left touch 2",
	},
	{
		[]IpRange{
			IpRange{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.254")},
			IpRange{net.ParseIP("10.0.1.128"), net.ParseIP("10.0.1.254")},
			IpRange{net.ParseIP("10.10.0.0"), net.ParseIP("10.10.1.254")},
		},
		[]IpRange{
			IpRange{net.ParseIP("10.0.1.100"), net.ParseIP("10.0.1.212")},
		},
		[]IpRange{
			IpRange{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.254")},
			IpRange{net.ParseIP("10.0.1.213"), net.ParseIP("10.0.1.254")},
			IpRange{net.ParseIP("10.10.0.0"), net.ParseIP("10.10.1.254")},
		},
		true,
		"left overlap search",
	},
	{
		[]IpRange{
			IpRange{net.ParseIP("10.0.1.0"), net.ParseIP("10.0.1.254")},
		},
		[]IpRange{
			IpRange{net.ParseIP("10.0.1.128"), net.ParseIP("10.0.2.128")},
		},
		[]IpRange{
			IpRange{net.ParseIP("10.0.1.0"), net.ParseIP("10.0.1.127")},
		},
		true,
		"right overlap",
	},
	{
		[]IpRange{
			IpRange{net.ParseIP("10.0.1.0"), net.ParseIP("10.0.1.254")},
		},
		[]IpRange{
			IpRange{net.ParseIP("10.0.1.254"), net.ParseIP("10.0.2.128")},
		},
		[]IpRange{
			IpRange{net.ParseIP("10.0.1.0"), net.ParseIP("10.0.1.253")},
		},
		true,
		"right touch",
	},
	{
		[]IpRange{
			IpRange{net.ParseIP("10.0.1.0"), net.ParseIP("10.0.1.254")},
		},
		[]IpRange{
			IpRange{net.ParseIP("10.0.1.128"), net.ParseIP("10.0.1.254")},
		},
		[]IpRange{
			IpRange{net.ParseIP("10.0.1.0"), net.ParseIP("10.0.1.127")},
		},
		true,
		"right touch 2",
	},
	{
		[]IpRange{
			IpRange{net.ParseIP("10.0.1.0"), net.ParseIP("10.0.1.254")},
			IpRange{net.ParseIP("10.10.0.0"), net.ParseIP("10.10.1.254")},
		},
		[]IpRange{
			IpRange{net.ParseIP("10.0.1.128"), net.ParseIP("10.0.2.128")},
		},
		[]IpRange{
			IpRange{net.ParseIP("10.0.1.0"), net.ParseIP("10.0.1.127")},
			IpRange{net.ParseIP("10.10.0.0"), net.ParseIP("10.10.1.254")},
		},
		true,
		"right overlap search",
	},
	{
		[]IpRange{
			IpRange{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.254")},
			IpRange{net.ParseIP("10.0.1.0"), net.ParseIP("10.0.1.254")},
			IpRange{net.ParseIP("10.10.0.0"), net.ParseIP("10.10.1.254")},
		},
		[]IpRange{
			IpRange{net.ParseIP("10.0.1.128"), net.ParseIP("10.0.2.128")},
		},
		[]IpRange{
			IpRange{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.254")},
			IpRange{net.ParseIP("10.0.1.0"), net.ParseIP("10.0.1.127")},
			IpRange{net.ParseIP("10.10.0.0"), net.ParseIP("10.10.1.254")},
		},
		true,
		"right overlap search 2",
	},
	{
		[]IpRange{
			IpRange{net.ParseIP("10.0.1.0"), net.ParseIP("10.0.1.254")},
		},
		[]IpRange{
			IpRange{net.ParseIP("10.0.1.100"), net.ParseIP("10.0.1.127")},
		},
		[]IpRange{
			IpRange{net.ParseIP("10.0.1.0"), net.ParseIP("10.0.1.99")},
			IpRange{net.ParseIP("10.0.1.128"), net.ParseIP("10.0.1.254")},
		},
		true,
		"center overlap",
	},
	{
		[]IpRange{
			IpRange{net.ParseIP("10.0.1.1"), net.ParseIP("10.0.1.1")},
		},
		[]IpRange{
			IpRange{net.ParseIP("10.0.1.1"), net.ParseIP("10.0.1.1")},
		},
		[]IpRange{},
		true,
		"one",
	},
	{
		[]IpRange{
			IpRange{net.ParseIP("10.0.1.1"), net.ParseIP("10.0.1.255")},
		},
		[]IpRange{
			IpRange{net.ParseIP("10.0.1.127"), net.ParseIP("10.0.1.127")},
		},
		[]IpRange{
			IpRange{net.ParseIP("10.0.1.1"), net.ParseIP("10.0.1.126")},
			IpRange{net.ParseIP("10.0.1.128"), net.ParseIP("10.0.1.255")},
		},
		true,
		"one from middle",
	},
}

func TestRemoveRange(t *testing.T) {
	for i, rt := range removeRangeTests {
		ipa := NewFromRanges(rt.add)
		for _, r := range rt.remove {
			ipa.RemoveRange(r.Start, r.End)
		}
		assert.Equal(t, rt.freeList, ipa.FreeList,
			fmt.Sprintf("RemoveRange %d: %s", i, rt.desc))
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
			IpRange{net.ParseIP("10.0.1.127"), net.ParseIP("10.0.1.127")},
		},
		[]IpRange{},
		net.ParseIP("10.0.1.127"),
		false,
		"one",
	},
	{
		[]IpRange{
			IpRange{net.ParseIP("10.0.1.127"), net.ParseIP("10.0.1.127")},
			IpRange{net.ParseIP("10.0.2.127"), net.ParseIP("10.0.2.255")},
		},
		[]IpRange{
			IpRange{net.ParseIP("10.0.2.127"), net.ParseIP("10.0.2.255")},
		},
		net.ParseIP("10.0.1.127"),
		false,
		"one with remaining",
	},
	{
		[]IpRange{
			IpRange{net.ParseIP("10.0.1.127"), net.ParseIP("10.0.1.255")},
			IpRange{net.ParseIP("10.0.2.127"), net.ParseIP("10.0.2.255")},
		},
		[]IpRange{
			IpRange{net.ParseIP("10.0.1.128"), net.ParseIP("10.0.1.255")},
			IpRange{net.ParseIP("10.0.2.127"), net.ParseIP("10.0.2.255")},
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
			IpRange{net.ParseIP("10.0.1.127"), net.ParseIP("10.0.1.127")},
		},
		256,
		nil,
		[]IpRange{
			IpRange{net.ParseIP("10.0.1.127"), net.ParseIP("10.0.1.127")},
		},
		true,
		"notenough",
	},
	{
		[]IpRange{
			IpRange{net.ParseIP("10.0.1.0"), net.ParseIP("10.0.1.255")},
		},
		256,
		[]IpRange{
			IpRange{net.ParseIP("10.0.1.0"), net.ParseIP("10.0.1.255")},
		},
		[]IpRange{},
		false,
		"onechunk",
	},
	{
		[]IpRange{
			IpRange{net.ParseIP("10.0.1.127"), net.ParseIP("10.0.2.128")},
		},
		258,
		[]IpRange{
			IpRange{net.ParseIP("10.0.1.127"), net.ParseIP("10.0.2.128")},
		},
		[]IpRange{},
		false,
		"onechunk split",
	},
	{
		[]IpRange{
			IpRange{net.ParseIP("10.0.1.127"), net.ParseIP("10.0.2.10")},
			IpRange{net.ParseIP("10.0.3.9"), net.ParseIP("10.0.4.128")},
		},
		129 + 11 + 247,
		[]IpRange{
			IpRange{net.ParseIP("10.0.1.127"), net.ParseIP("10.0.2.10")},
			IpRange{net.ParseIP("10.0.3.9"), net.ParseIP("10.0.3.255")},
		},
		[]IpRange{
			IpRange{net.ParseIP("10.0.4.0"), net.ParseIP("10.0.4.128")},
		},
		false,
		"multichunk",
	},
	{
		[]IpRange{
			IpRange{net.ParseIP("fd43:85d7:bcf2:9ad2::"),
				net.ParseIP("fd43:85d7:bcf2:9ad2:ffff:ffff:ffff:ffff")},
		},
		256,
		[]IpRange{
			IpRange{net.ParseIP("fd43:85d7:bcf2:9ad2::"),
				net.ParseIP("fd43:85d7:bcf2:9ad2::ff")},
		},
		[]IpRange{
			IpRange{net.ParseIP("fd43:85d7:bcf2:9ad2::100"),
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
			IpRange{net.ParseIP("10.0.1.1"), net.ParseIP("10.0.1.255")},
			IpRange{net.ParseIP("10.0.3.9"), net.ParseIP("10.0.4.128")},
		},
		255 + 376,
		"simple",
	},
	{
		[]IpRange{
			IpRange{net.ParseIP("fd43:85d7:bcf2:9ad2::"),
				net.ParseIP("fd43:85d7:bcf2:9ad2::ffff:ffff")},
		},
		4294967296,
		"v6",
	},
	{
		[]IpRange{
			IpRange{net.ParseIP("fd43:85d7:bcf2:9ad2::"),
				net.ParseIP("fd43:85d7:bcf2:9ad2::ffff:ffff:ffff")},
		},
		0x1000000000000,
		"v6 48 bits",
	},
	{
		[]IpRange{
			IpRange{net.ParseIP("fd43:85d7:bcf2:9ad2::"),
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

type intersectTest struct {
	a      []IpRange
	b      []IpRange
	result []IpRange
	desc   string
}

var intersectTests = []intersectTest{
	intersectTest{
		[]IpRange{},
		[]IpRange{},
		[]IpRange{},
		"empty",
	},
	intersectTest{
		[]IpRange{
			IpRange{net.ParseIP("10.0.1.1"), net.ParseIP("10.0.1.255")},
		},
		[]IpRange{
			IpRange{net.ParseIP("10.0.1.4"), net.ParseIP("10.0.1.250")},
		},
		[]IpRange{
			IpRange{net.ParseIP("10.0.1.4"), net.ParseIP("10.0.1.250")},
		},
		"middle 1",
	},
	intersectTest{
		[]IpRange{
			IpRange{net.ParseIP("10.0.1.4"), net.ParseIP("10.0.1.250")},
		},
		[]IpRange{
			IpRange{net.ParseIP("10.0.1.1"), net.ParseIP("10.0.1.255")},
		},
		[]IpRange{
			IpRange{net.ParseIP("10.0.1.4"), net.ParseIP("10.0.1.250")},
		},
		"middle 2",
	},
	intersectTest{
		[]IpRange{
			IpRange{net.ParseIP("10.0.1.1"), net.ParseIP("10.0.1.250")},
		},
		[]IpRange{
			IpRange{net.ParseIP("10.0.1.128"), net.ParseIP("10.0.1.255")},
		},
		[]IpRange{
			IpRange{net.ParseIP("10.0.1.128"), net.ParseIP("10.0.1.250")},
		},
		"left",
	},
	intersectTest{
		[]IpRange{
			IpRange{net.ParseIP("10.0.1.1"), net.ParseIP("10.0.1.250")},
		},
		[]IpRange{
			IpRange{net.ParseIP("10.0.1.1"), net.ParseIP("10.0.1.255")},
		},
		[]IpRange{
			IpRange{net.ParseIP("10.0.1.1"), net.ParseIP("10.0.1.250")},
		},
		"left touch",
	},
	intersectTest{
		[]IpRange{
			IpRange{net.ParseIP("10.0.1.1"), net.ParseIP("10.0.1.250")},
		},
		[]IpRange{
			IpRange{net.ParseIP("10.0.1.5"), net.ParseIP("10.0.1.250")},
		},
		[]IpRange{
			IpRange{net.ParseIP("10.0.1.5"), net.ParseIP("10.0.1.250")},
		},
		"right touch",
	},
	intersectTest{
		[]IpRange{
			IpRange{net.ParseIP("10.0.1.1"), net.ParseIP("10.0.1.250")},
		},
		[]IpRange{
			IpRange{net.ParseIP("10.0.1.251"), net.ParseIP("10.0.1.255")},
		},
		[]IpRange{},
		"left empty",
	},
	intersectTest{
		[]IpRange{
			IpRange{net.ParseIP("10.0.1.1"), net.ParseIP("10.0.1.250")},
		},
		[]IpRange{
			IpRange{net.ParseIP("10.0.1.5"), net.ParseIP("10.0.1.10")},
			IpRange{net.ParseIP("10.0.1.20"), net.ParseIP("10.0.1.25")},
		},
		[]IpRange{
			IpRange{net.ParseIP("10.0.1.5"), net.ParseIP("10.0.1.10")},
			IpRange{net.ParseIP("10.0.1.20"), net.ParseIP("10.0.1.25")},
		},
		"multiple",
	},
	intersectTest{
		[]IpRange{
			IpRange{net.ParseIP("10.0.1.1"), net.ParseIP("10.0.1.250")},
		},
		[]IpRange{
			IpRange{net.ParseIP("10.0.1.5"), net.ParseIP("10.0.1.10")},
			IpRange{net.ParseIP("10.0.1.20"), net.ParseIP("10.0.1.255")},
		},
		[]IpRange{
			IpRange{net.ParseIP("10.0.1.5"), net.ParseIP("10.0.1.10")},
			IpRange{net.ParseIP("10.0.1.20"), net.ParseIP("10.0.1.250")},
		},
		"multiple",
	},
	intersectTest{
		[]IpRange{
			IpRange{net.ParseIP("10.0.1.1"), net.ParseIP("10.0.1.250")},
			IpRange{net.ParseIP("10.0.2.1"), net.ParseIP("10.0.3.250")},
		},
		[]IpRange{
			IpRange{net.ParseIP("10.0.1.5"), net.ParseIP("10.0.1.10")},
			IpRange{net.ParseIP("10.0.1.20"), net.ParseIP("10.0.1.255")},
			IpRange{net.ParseIP("10.0.1.254"), net.ParseIP("10.0.2.255")},
			IpRange{net.ParseIP("10.0.4.1"), net.ParseIP("10.0.4.4")},
		},
		[]IpRange{
			IpRange{net.ParseIP("10.0.1.5"), net.ParseIP("10.0.1.10")},
			IpRange{net.ParseIP("10.0.1.20"), net.ParseIP("10.0.1.250")},
			IpRange{net.ParseIP("10.0.2.1"), net.ParseIP("10.0.2.255")},
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
