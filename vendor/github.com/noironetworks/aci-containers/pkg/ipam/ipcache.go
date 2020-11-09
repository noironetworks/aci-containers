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

// Provides tools and data structures for caching IP address pools and
// managing them
package ipam

import (
	"bytes"
	"errors"
	"net"
	"sort"
)

//The data structure to cache the IpV4 and IpV6 lists
type IpCache struct {
	cacheIpsV4 []*IpAlloc
	cacheIpsV6 []*IpAlloc
}

//Create a new IpCache which will have 2 lists,
//the  List-0 is for the available IPs and List-1 is for the used Ips.
func NewIpCache() *IpCache {
	return &IpCache{
		cacheIpsV4: []*IpAlloc{New(), New()},
		cacheIpsV6: []*IpAlloc{New(), New()},
	}
}

//allocates Ip from the pool and updates the Lists
// also removes the Ip from the available Ips list
func (iplists *IpCache) AllocateIp(ipv4 bool) (net.IP, error) {
	if ipv4 {
		if iplists.cacheIpsV4[0].Empty() &&
			iplists.cacheIpsV4[1].Empty() {
			return nil, errors.New("No IP addresses are available")
		}
		if iplists.cacheIpsV4[0].Empty() {
			iplists.cacheIpsV4 = append(iplists.cacheIpsV4[1:], New())
		}
		ip, err := iplists.cacheIpsV4[0].GetIp()
		if err != nil {
			return nil, err
		}
		return ip, nil
	} else {
		if iplists.cacheIpsV6[0].Empty() &&
			iplists.cacheIpsV6[1].Empty() {
			return nil, errors.New("No IP addresses are available")
		}
		if iplists.cacheIpsV6[0].Empty() {
			iplists.cacheIpsV6 = append(iplists.cacheIpsV6[1:], New())
		}
		ip, err := iplists.cacheIpsV6[0].GetIp()
		if err != nil {
			return nil, err
		}
		return ip, nil
	}
}

//Adds the Ip to the used list of Ips
func (iplists *IpCache) DeallocateIp(ip net.IP) {
	if ip.To4() != nil {
		iplists.cacheIpsV4[len(iplists.cacheIpsV4)-1].AddIp(ip)
	} else if ip.To16() != nil {
		iplists.cacheIpsV6[len(iplists.cacheIpsV6)-1].AddIp(ip)
	}
}

//loads the Iplists from the
//given IpRange, this function is invoked at the init or the update
func (iplists *IpCache) LoadRanges(ipranges []IpRange) {
	for _, r := range ipranges {
		if r.Start.To4() != nil && r.End.To4() != nil {
			iplists.cacheIpsV4[0].AddRange(r.Start, r.End)
		} else if r.Start.To16() != nil && r.End.To16() != nil {
			iplists.cacheIpsV6[0].AddRange(r.Start, r.End)
		} else {
			errors.New("Range invalid: ")
		}
	}
}

// Removes the IP from the respective IpCache
// Returns true if successful
func (iplists *IpCache) RemoveIp(ip net.IP) bool {
	if ip.To4() != nil {
		for _, ipa := range iplists.cacheIpsV4 {
			if ipa.RemoveIp(ip) {
				return true
			}
		}
	} else if ip.To16() != nil {
		for _, ipa := range iplists.cacheIpsV6 {
			if ipa.RemoveIp(ip) {
				return true
			}
		}
	}

	return false
}

//Combines the 2 V4 lists into 1 list
func (iplists *IpCache) CombineV4() []IpRange {
	v4ranges := iplists.cacheIpsV4
	v4result := New()
	for _, r := range v4ranges {
		v4result.AddAll(r)
	}
	return v4result.FreeList
}

//Combines the 2 V6 lists into 1 list
func (iplists *IpCache) CombineV6() []IpRange {
	v6ranges := iplists.cacheIpsV6
	v6result := New()
	for _, r := range v6ranges {
		v6result.AddAll(r)
	}
	return v6result.FreeList
}

func (iplists *IpCache) GetV4IpCache() []*IpAlloc {
	return iplists.cacheIpsV4
}

func (iplists *IpCache) GetV6IpCache() []*IpAlloc {
	return iplists.cacheIpsV6
}

//Checks if the List has the given IP
func HasIp(list *IpAlloc, ip net.IP) bool {
	if len(list.FreeList) == 0 {
		return false
	}
	i := sort.Search(len(list.FreeList), func(i int) bool {
		return ((bytes.Compare(list.FreeList[i].Start, ip) >= 0) || (bytes.Compare(list.FreeList[i].End, ip) == 0))
	})
	if (i < len(list.FreeList)) &&
		((bytes.Compare(list.FreeList[i].Start, ip) == 0) ||
			(bytes.Compare(list.FreeList[i].End, ip) == 0)) {
		return true
	} else {
		for j := 0; j <= (len(list.FreeList) - 1); j++ {
			if (bytes.Compare(list.FreeList[j].Start, ip) <= 0) &&
				(bytes.Compare(list.FreeList[j].End, ip) >= 0) {
				return true
			} else {
				continue
			}
		}
		return false
	}
}
