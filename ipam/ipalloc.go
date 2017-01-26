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
	"bytes"
	"errors"
	"fmt"
	"net"
	"sort"
)

type IpRange struct {
	start net.IP
	end   net.IP
}

type IpAlloc struct {
	freeList []IpRange
}

// Create a new IpAlloc
func New() *IpAlloc {
	return &IpAlloc{
		freeList: make([]IpRange, 0),
	}
}

func carryIncrement(input []byte) ([]byte, bool) {
	result := make([]byte, len(input))
	copy(result, input)
	carry := true
	i := len(input) - 1

	for carry && i >= 0 {
		if input[i] < 255 {
			result[i] = input[i] + 1
			carry = false
		} else {
			result[i] = 0
			i -= 1
		}
	}

	return result, carry
}

func carryDecrement(input []byte) ([]byte, bool) {
	result := make([]byte, len(input))
	copy(result, input)
	carry := true
	i := len(input) - 1

	for carry && i >= 0 {
		if input[i] > 0 {
			result[i] = input[i] - 1
			carry = false
		} else {
			result[i] = 255
			i -= 1
		}
	}

	return result, carry
}

func isAdjOrGreater(a []byte, b []byte) bool {
	ainc, carry := carryIncrement(a)
	if carry {
		return true
	}
	return bytes.Compare(ainc, b) >= 0
}

func (ipa *IpAlloc) fixRange(index int) {
	i := index - 1
	if i < 0 {
		i = 0
	}
	for i+1 < len(ipa.freeList) &&
		isAdjOrGreater(ipa.freeList[i].end, ipa.freeList[i+1].start) {

		if bytes.Compare(ipa.freeList[i].end, ipa.freeList[i+1].end) < 0 {
			ipa.freeList[i].end = ipa.freeList[i+1].end
		}
		ipa.freeList = append(ipa.freeList[:i+1], ipa.freeList[i+2:]...)
	}
}

// Add the range of IP addresses provides to the free list
func (ipa *IpAlloc) AddRange(start net.IP, end net.IP) {
	if bytes.Compare(start, end) > 0 {
		return
	}
	i := sort.Search(len(ipa.freeList), func(i int) bool {
		return bytes.Compare(ipa.freeList[i].start, start) >= 0
	})
	ipa.freeList = append(ipa.freeList, IpRange{})
	copy(ipa.freeList[i+1:], ipa.freeList[i:])
	ipa.freeList[i].start = start
	ipa.freeList[i].end = end

	ipa.fixRange(i)
}

func cutRange(target IpRange, start net.IP, end net.IP) []IpRange {
	result := make([]IpRange, 0)

	if bytes.Compare(target.start, start) < 0 {
		if bytes.Compare(target.end, start) >= 0 {
			startdec, _ := carryDecrement(start)
			result = append(result, IpRange{target.start, startdec})
		} else {
			result = append(result, target)
		}
	}
	if bytes.Compare(target.end, end) > 0 {
		if bytes.Compare(target.start, end) <= 0 {
			endinc, _ := carryIncrement(end)
			result = append(result, IpRange{endinc, target.end})
		} else {
			result = append(result, target)
		}
	}
	return result
}

// Remove all the IP addresses in the range from the free list
func (ipa *IpAlloc) RemoveRange(start net.IP, end net.IP) {
	if bytes.Compare(start, end) > 0 {
		return
	}

	startind := sort.Search(len(ipa.freeList), func(i int) bool {
		return bytes.Compare(ipa.freeList[i].start, start) >= 0
	})
	endind := sort.Search(len(ipa.freeList), func(i int) bool {
		return bytes.Compare(ipa.freeList[i].end, end) >= 0
	})

	i := startind

	for i > 0 &&
		(i >= len(ipa.freeList) ||
			bytes.Compare(ipa.freeList[i].end, start) >= 0) {
		i--
	}

	for i < len(ipa.freeList) && i <= endind {
		r := cutRange(ipa.freeList[i], start, end)
		ipa.freeList = append(ipa.freeList[:i], append(r, ipa.freeList[i+1:]...)...)
		i += len(r)
	}
}

// Remove the given IP address from the free list
func (ipa *IpAlloc) RemoveIp(ip net.IP) {
	ipa.RemoveRange(ip, ip)
}

// Return a free IP address and remove it from the free list
func (ipa *IpAlloc) GetIp() (net.IP, error) {
	if len(ipa.freeList) == 0 {
		return nil, errors.New("No IP addresses are available")
	}

	result := ipa.freeList[0].start
	if bytes.Compare(ipa.freeList[0].start, ipa.freeList[0].end) == 0 {
		ipa.freeList = ipa.freeList[1:]
	} else {
		news, _ := carryIncrement(ipa.freeList[0].start)
		ipa.freeList[0].start = news
	}
	return result, nil
}

// Return a set of ranges containing at least 256 IP addresses and
// remove them from the free list.
func (ipa *IpAlloc) GetIpChunk() ([]IpRange, error) {
	size := 0
	result := New()

	for size < 256 {
		if len(ipa.freeList) == 0 {
			// can't get enough IP addresses; return anything we
			// already allocated and return an error
			for _, r := range result.freeList {
				ipa.AddRange(r.start, r.end)
			}
			return nil, errors.New("Insufficient IP addresses are available")
		}

		first := ipa.freeList[0]
		slast := first.start[len(first.start)-1]
		elast := first.end[len(first.end)-1]
		srest := first.start[:len(first.start)-1]
		erest := first.end[:len(first.end)-1]

		if bytes.Compare(srest, erest) != 0 {
			// first and last differ in last byte; take the rest of
			// the byte
			end := make([]byte, len(first.start))
			copy(end, first.start)
			end[len(end)-1] = 255
			r := IpRange{first.start, end}
			ipa.RemoveRange(r.start, r.end)
			result.AddRange(r.start, r.end)
			size += 255 - int(slast) + 1
			fmt.Println("1", 255-int(slast)+1, size, r.start, r.end)
		} else {
			// chunk starts and ends in the same byte; take the whole
			// chunk
			result.AddRange(first.start, first.end)
			ipa.RemoveRange(first.start, first.end)
			size += int(elast) - int(slast) + 1
			fmt.Println("2", int(elast)-int(slast)+1, size, first.start, first.end)
		}
	}
	return result.freeList, nil
}
