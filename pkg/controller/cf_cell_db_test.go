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

package controller

import (
	"database/sql"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/noironetworks/aci-containers/pkg/ipam"
	m "github.com/noironetworks/aci-containers/pkg/metadata"
)

func TestCfCellServiceEpDbOps(t *testing.T) {
	env := testCfEnvironment(t)
	epdb := CellServiceEpDb{}

	// get with no record
	txn(env.db, func(txn *sql.Tx) {
		ep, err := epdb.Get(txn, "cell1")
		assert.Nil(t, err)
		assert.Nil(t, ep)
	})

	// set with mac, v4, v6
	svcep := &m.ServiceEndpoint{
		Mac:  "aa:bb:cc:dd:ee:ff",
		Ipv4: net.ParseIP("1.2.3.4"),
		Ipv6: net.ParseIP("::fe80")}

	txn(env.db, func(txn *sql.Tx) {
		err := epdb.Set(txn, "cell1", svcep)
		assert.Nil(t, err)
		ep, err := epdb.Get(txn, "cell1")
		assert.Nil(t, err)
		assert.Equal(t, *svcep, *ep)
	})

	// set with v4 only
	svcep.Ipv6 = nil
	txn(env.db, func(txn *sql.Tx) {
		err := epdb.Set(txn, "cell1", svcep)
		assert.Nil(t, err)
		ep, err := epdb.Get(txn, "cell1")
		assert.Nil(t, err)
		assert.Equal(t, *svcep, *ep)
	})

	// set again
	txn(env.db, func(txn *sql.Tx) {
		err := epdb.Set(txn, "cell1", svcep)
		assert.Nil(t, err)
		ep, err := epdb.Get(txn, "cell1")
		assert.Nil(t, err)
		assert.Equal(t, *svcep, *ep)
	})

	// reset
	svcep.Ipv4 = nil
	txn(env.db, func(txn *sql.Tx) {
		err := epdb.Set(txn, "cell1", svcep)
		assert.Nil(t, err)
		ep, err := epdb.Get(txn, "cell1")
		assert.Nil(t, err)
		assert.Equal(t, *svcep, *ep)
	})

	// delete
	txn(env.db, func(txn *sql.Tx) {
		err := epdb.Delete(txn, "cell1")
		assert.Nil(t, err)
		ep, err := epdb.Get(txn, "cell1")
		assert.Nil(t, err)
		assert.Nil(t, ep)
	})

	// delete again
	txn(env.db, func(txn *sql.Tx) {
		err := epdb.Delete(txn, "cell1")
		assert.Nil(t, err)
	})
}

func TestCfCellPodNetDbOps(t *testing.T) {
	env := testCfEnvironment(t)
	netdb := CellPodNetDb{}

	// get with no record
	txn(env.db, func(txn *sql.Tx) {
		podnet, err := netdb.Get(txn, "cell1")
		assert.Nil(t, err)
		assert.Nil(t, podnet)
	})

	// set v4 and v6
	podnet := &m.NetIps{
		V4: []ipam.IpRange{
			{Start: net.ParseIP("1.2.3.4"), End: net.ParseIP("1.2.3.8")},
			{Start: net.ParseIP("5.6.6.2"), End: net.ParseIP("5.8.8.7")}},
		V6: []ipam.IpRange{
			{Start: net.ParseIP("::1:2"), End: net.ParseIP("::1:8")},
			{Start: net.ParseIP("::5:6"), End: net.ParseIP("::5:9")}}}

	txn(env.db, func(txn *sql.Tx) {
		err := netdb.Set(txn, "cell1", podnet)
		assert.Nil(t, err)
		n, err := netdb.Get(txn, "cell1")
		assert.Nil(t, err)
		assert.Equal(t, *podnet, *n)
	})

	// append more ranges
	podnet.V4 = append(podnet.V4,
		ipam.IpRange{Start: net.ParseIP("9.8.7.2"),
			End: net.ParseIP("9.8.8.9")})
	podnet.V6 = append(podnet.V6,
		ipam.IpRange{Start: net.ParseIP("::9:4"),
			End: net.ParseIP("::9:8")})
	txn(env.db, func(txn *sql.Tx) {
		err := netdb.Set(txn, "cell1", podnet)
		assert.Nil(t, err)
		n, err := netdb.Get(txn, "cell1")
		assert.Nil(t, err)
		assert.Equal(t, *podnet, *n)
	})

	// set with v4 only
	podnet1 := &m.NetIps{V4: podnet.V4}
	txn(env.db, func(txn *sql.Tx) {
		err := netdb.Set(txn, "cell1", podnet1)
		assert.Nil(t, err)
		n, err := netdb.Get(txn, "cell1")
		assert.Nil(t, err)
		assert.Equal(t, *podnet1, *n)
	})

	// set with v6 only
	podnet2 := &m.NetIps{V6: podnet.V6}
	txn(env.db, func(txn *sql.Tx) {
		err := netdb.Set(txn, "cell1", podnet2)
		assert.Nil(t, err)
		n, err := netdb.Get(txn, "cell1")
		assert.Nil(t, err)
		assert.Equal(t, *podnet2, *n)
	})

	// delete
	txn(env.db, func(txn *sql.Tx) {
		err := netdb.Delete(txn, "cell1")
		assert.Nil(t, err)
		n, err := netdb.Get(txn, "cell1")
		assert.Nil(t, err)
		assert.Nil(t, n)
	})

	// delete again
	txn(env.db, func(txn *sql.Tx) {
		err := netdb.Delete(txn, "cell1")
		assert.Nil(t, err)
	})
}
