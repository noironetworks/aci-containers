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

// Provides tools and data structures for managing IP address pools
package ipam

import (
	"bytes"

	"errors"
	"math"
	"math/big"
	"net"
	"sort"
)

// A range of IP addresses starting at Start and ending at End
// (inclusive)
type IpRange struct {
	Start net.IP `json:"start,omitempty"`
	End   net.IP `json:"end,omitempty"`
}

// A IP pool containing a list of free IP address ranges.  IP
// addresses can be either v4 or v6, but not both
type IpAlloc struct {
	FreeList []IpRange
}

// Create a new IpAlloc
func New() *IpAlloc {
	return &IpAlloc{
		FreeList: make([]IpRange, 0),
	}
}

// Create a new IpAlloc from an existing freelist
func NewFromRanges(ranges []IpRange) *IpAlloc {
	ipa := &IpAlloc{
		FreeList: make([]IpRange, len(ranges)),
	}
	copy(ipa.FreeList, ranges)
	return ipa
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

	// iterate until we hit a disjoint range or the freelist compresses
	// to a single item at the current index.
	for i+1 < len(ipa.FreeList) &&
		isAdjOrGreater(ipa.FreeList[i].End, ipa.FreeList[i+1].Start) {

		if bytes.Compare(ipa.FreeList[i].End, ipa.FreeList[i+1].End) < 0 {
			ipa.FreeList[i].End = ipa.FreeList[i+1].End
		}
		if len(ipa.FreeList) > i+1 {
			ipa.FreeList = append(ipa.FreeList[:i+1], ipa.FreeList[i+2:]...)
		} else {
			ipa.FreeList = ipa.FreeList[:i+1]
		}
	}
}

// Add the range of IP addresses provides to the free list
//example: start:10.2.1.1 and end 10.2.1.1
//example: ipa.FreeList = [{10.2.1.2 10.2.1.129}]
//After the following function the ipa.Freelist = [{10.2.1.1 10.2.1.129}]
func (ipa *IpAlloc) AddRange(start net.IP, end net.IP) {
	if bytes.Compare(start, end) > 0 {
		return
	}
	i := sort.Search(len(ipa.FreeList), func(i int) bool {
		if i >= len(ipa.FreeList) || i < 0 {
			return true
		}

		return bytes.Compare(ipa.FreeList[i].Start, start) >= 0
	})

	// add at the right spot and merge if necessary.
	item := IpRange{Start: start, End: end}
	i = ipa.addToFree(item, i)
	ipa.fixRange(i)
}

func (ipa *IpAlloc) addToFree(item IpRange, pos int) int {
	// it is surprisingly easy to mess this up as we could end up checking
	// boundary after we change the slice length!
	if pos >= len(ipa.FreeList) {
		pos = len(ipa.FreeList)
		ipa.FreeList = append(ipa.FreeList, item)
	} else {
		// create room and insert
		ipa.FreeList = append(ipa.FreeList, item)
		copy(ipa.FreeList[pos+1:], ipa.FreeList[pos:])
		ipa.FreeList[pos] = item
	}

	return pos
}

// Add the ip address to the free list
func (ipa *IpAlloc) AddIp(ip net.IP) {
	ipa.AddRange(ip, ip)
}

// Add the given subnet to the free list.  Note that this will include
// the network address ip|mask in the range.
func (ipa *IpAlloc) AddSubnet(subnet *net.IPNet) {
	ipa.AddRange(subnetRange(subnet))
}

func cutRange(target IpRange, start net.IP, end net.IP) ([]IpRange, bool) {
	result := make([]IpRange, 0)
	changed := true

	if bytes.Compare(target.Start, start) < 0 {
		if bytes.Compare(target.End, start) >= 0 {
			startdec, _ := carryDecrement(start)
			result = append(result, IpRange{target.Start, startdec})
		} else {
			result = append(result, target)
			changed = false
		}
	}
	if bytes.Compare(target.End, end) > 0 {
		if bytes.Compare(target.Start, end) <= 0 {
			endinc, _ := carryIncrement(end)
			result = append(result, IpRange{endinc, target.End})
		} else {
			result = append(result, target)
			changed = false
		}
	}
	return result, changed
}

// Remove all the IP addresses in the range from the free list
func (ipa *IpAlloc) RemoveRange(start net.IP, end net.IP) bool {
	changed := false
	if bytes.Compare(start, end) > 0 {
		return changed
	}

	startind := sort.Search(len(ipa.FreeList), func(i int) bool {
		return bytes.Compare(ipa.FreeList[i].Start, start) >= 0
	})
	endind := sort.Search(len(ipa.FreeList), func(i int) bool {
		return bytes.Compare(ipa.FreeList[i].End, end) >= 0
	})

	i := startind

	for i > 0 &&
		(i >= len(ipa.FreeList) ||
			bytes.Compare(ipa.FreeList[i].End, start) >= 0) {
		i--
	}

	for i < len(ipa.FreeList) && i <= endind {
		r, rchanged := cutRange(ipa.FreeList[i], start, end)
		changed = changed || rchanged
		ipa.FreeList = append(ipa.FreeList[:i], append(r, ipa.FreeList[i+1:]...)...)
		i += len(r)
	}
	return changed
}

// Remove the given subnet from the free list
func (ipa *IpAlloc) RemoveSubnet(subnet *net.IPNet) bool {
	return ipa.RemoveRange(subnetRange(subnet))
}

// Remove the given IP address from the free list
func (ipa *IpAlloc) RemoveIp(ip net.IP) bool {
	return ipa.RemoveRange(ip, ip)
}

// Return a free IP address and remove it from the free list
func (ipa *IpAlloc) GetIp() (net.IP, error) {
	if len(ipa.FreeList) == 0 {
		return nil, errors.New("No IP addresses are available")
	}

	result := ipa.FreeList[0].Start
	if bytes.Compare(ipa.FreeList[0].Start, ipa.FreeList[0].End) == 0 {
		ipa.FreeList = ipa.FreeList[1:]
	} else {
		news, _ := carryIncrement(ipa.FreeList[0].Start)
		ipa.FreeList[0].Start = news
	}
	return result, nil
}

var one = big.NewInt(1)

// Return a set of ranges containing at chunkSize IP addresses and
// remove them from the free list.
func (ipa *IpAlloc) GetIpChunk(chunkSize int64) ([]IpRange, error) {
	currentSize := int64(0)
	result := New()

	for currentSize < chunkSize {
		if len(ipa.FreeList) == 0 {
			// can't get enough IP addresses; return anything we
			// already allocated and return an error
			for _, r := range result.FreeList {
				ipa.AddRange(r.Start, r.End)
			}
			return nil, errors.New("Insufficient IP addresses are available")
		}

		r := ipa.FreeList[0]
		start := new(big.Int).SetBytes(r.Start)
		end := new(big.Int).SetBytes(r.End)
		rangeSize := new(big.Int).Add(one, new(big.Int).Sub(end, start))
		needed := big.NewInt(chunkSize - currentSize)

		if needed.Cmp(rangeSize) >= 0 {
			// take whole range
			result.AddRange(r.Start, r.End)
			ipa.RemoveRange(r.Start, r.End)

			currentSize += rangeSize.Int64()
		} else {
			// take as much as we need
			newend :=
				new(big.Int).Sub(new(big.Int).Add(start, needed), one).Bytes()
			if len(newend) < len(r.End) {
				newend = append(make([]byte, len(r.End)-len(newend)), newend...)
			}

			result.AddRange(r.Start, newend)
			ipa.RemoveRange(r.Start, newend)

			currentSize += needed.Int64()
		}
	}
	return result.FreeList, nil
}

// Add all IP ranges from another IpAlloc object
func (ipa *IpAlloc) AddAll(other *IpAlloc) error {
	return ipa.AddRanges(other.FreeList)
}

// Add all IP ranges from a slice of ranges
func (ipa *IpAlloc) AddRanges(ranges []IpRange) error {
	for _, r := range ranges {
		ipa.AddRange(r.Start, r.End)
	}
	return nil
}

// Remove all IP ranges from another IpAlloc object
func (ipa *IpAlloc) RemoveAll(other *IpAlloc) error {
	return ipa.RemoveRanges(other.FreeList)
}

// Remove all IP ranges from a slice of ranges
func (ipa *IpAlloc) RemoveRanges(ranges []IpRange) error {
	for _, r := range ranges {
		ipa.RemoveRange(r.Start, r.End)
	}
	return nil
}

// Get the number of IPs available in the free list
func (ipa *IpAlloc) GetSize() int64 {
	size := big.NewInt(0)
	for _, r := range ipa.FreeList {
		start := new(big.Int).SetBytes(r.Start)
		end := new(big.Int).SetBytes(r.End)

		size.Add(size, new(big.Int).Sub(end, start))
		size.Add(size, one)
	}

	if big.NewInt(math.MaxInt64).Cmp(size) <= 0 {
		return math.MaxInt64
	} else {
		return size.Int64()
	}
}

// Check whether there are no IPs available
func (ipa *IpAlloc) Empty() bool {
	return len(ipa.FreeList) == 0
}

func intersectLeft(result *IpAlloc, a *IpRange, b *IpRange, i *int, j *int) {
	if bytes.Compare(a.End, b.Start) < 0 {
		*i += 1
	} else {
		cmp := bytes.Compare(a.End, b.End)
		if cmp < 0 {
			*i += 1
			result.AddRange(b.Start, a.End)
		} else if cmp == 0 {
			*i += 1
			*j += 1
			result.AddRange(b.Start, a.End)
		} else {
			*j += 1
			result.AddRange(b.Start, b.End)
		}
	}
}

// Create a new IpAlloc that is the intersection of the ranges in the
// ipa and other
func (ipa *IpAlloc) Intersect(other *IpAlloc) *IpAlloc {
	result := New()
	i, j := 0, 0

	for i < len(ipa.FreeList) && j < len(other.FreeList) {
		a := &ipa.FreeList[i]
		b := &other.FreeList[j]

		if bytes.Compare(a.Start, b.Start) < 0 {
			intersectLeft(result, a, b, &i, &j)
		} else {
			intersectLeft(result, b, a, &j, &i)
		}
	}

	return result
}
