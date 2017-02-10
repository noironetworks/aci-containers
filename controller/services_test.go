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

package main

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/client-go/pkg/api/v1"

	"github.com/noironetworks/aci-containers/ipam"
	tu "github.com/noironetworks/aci-containers/testutil"
)

func waitForSStatus(t *testing.T, cont *testAciController,
	ips []string, desc string) {

	tu.WaitFor(t, desc, 500*time.Millisecond,
		func(last bool) (bool, error) {
			if !tu.WaitCondition(t, last, func() bool {
				return len(cont.serviceUpdates) >= 1
			}, desc, "update") {
				return false, nil
			}
			ingress :=
				cont.serviceUpdates[len(cont.serviceUpdates)-1].
					Status.LoadBalancer.Ingress
			expected := make(map[string]bool)
			for _, i := range ips {
				expected[i] = true
			}
			seen := make(map[string]bool)
			for _, i := range ingress {
				seen[i.IP] = true
			}
			return tu.WaitEqual(t, last, expected, seen, "lb ingress ips"), nil
		})
}

func hasIpCond(pool *ipam.IpAlloc, ipStr string) func() bool {
	return func() bool {
		ip := net.ParseIP(ipStr)
		r := pool.RemoveIp(ip)
		if r {
			pool.AddIp(ip)
		}
		return r
	}
}
func notHasIpCond(pool *ipam.IpAlloc, ipStr string) func() bool {
	return func() bool {
		return !hasIpCond(pool, ipStr)()
	}
}

func TestServiceIp(t *testing.T) {
	cont := testController()
	cont.config.ServiceIpPool = []ipam.IpRange{
		ipam.IpRange{Start: net.ParseIP("10.4.1.1"), End: net.ParseIP("10.4.1.255")},
	}
	cont.config.StaticServiceIpPool = []ipam.IpRange{
		ipam.IpRange{Start: net.ParseIP("10.4.2.1"), End: net.ParseIP("10.4.2.255")},
	}
	cont.aciController.initIpam()
	cont.run()

	{
		cont.serviceUpdates = nil
		cont.fakeServiceSource.Add(service("testns", "service1", ""))
		waitForSStatus(t, cont, []string{"10.4.1.1"}, "pool")
	}
	{
		cont.serviceUpdates = nil
		cont.fakeServiceSource.Add(service("testns", "service2", "10.4.2.1"))
		waitForSStatus(t, cont, []string{"10.4.2.1"}, "static")
	}
	{
		cont.serviceUpdates = nil
		cont.fakeServiceSource.Add(service("testns", "service3", "10.4.3.1"))
		waitForSStatus(t, cont, []string{"10.4.1.2"}, "static invalid")
	}
	{
		cont.serviceUpdates = nil
		cont.fakeServiceSource.Add(service("testns", "service1", "10.4.2.2"))
		waitForSStatus(t, cont, []string{"10.4.2.2"}, "add request")
	}
	{
		cont.serviceUpdates = nil
		cont.fakeServiceSource.Add(service("testns", "service4", ""))
		waitForSStatus(t, cont, []string{"10.4.1.1"}, "pool return")
	}
	{
		cont.serviceUpdates = nil
		s := service("testns", "service5", "")
		s.Status.LoadBalancer.Ingress =
			[]v1.LoadBalancerIngress{v1.LoadBalancerIngress{IP: "10.4.1.32"}}
		cont.serviceChanged(s)
		assert.Nil(t, cont.serviceUpdates, "existing")
		assert.Condition(t, notHasIpCond(cont.serviceIps.V4, "10.4.1.32"),
			"existing pool check")
	}
	{
		cont.serviceUpdates = nil
		s := service("testns", "service6", "10.4.2.3")
		s.Status.LoadBalancer.Ingress =
			[]v1.LoadBalancerIngress{v1.LoadBalancerIngress{IP: "10.4.2.3"}}
		cont.serviceChanged(s)
		assert.Nil(t, cont.serviceUpdates, "static existing")
	}
	{
		cont.serviceUpdates = nil
		cont.serviceDeleted(service("testns", "service1", "10.4.2.2"))
		assert.Condition(t, hasIpCond(cont.staticServiceIps.V4, "10.4.2.2"),
			"delete static return")
	}
	{
		cont.serviceUpdates = nil
		cont.serviceDeleted(service("testns", "service5", ""))
		assert.Condition(t, hasIpCond(cont.serviceIps.V4, "10.4.1.32"),
			"delete pool return")
	}

	cont.stop()
}
