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
	"fmt"
	"net"

	"github.com/noironetworks/aci-containers/pkg/ipam"
	m "github.com/noironetworks/aci-containers/pkg/metadata"
)

type CellPodNetDb struct {
}

func (db *CellPodNetDb) Get(txn *sql.Tx, cell string) (
	result *m.NetIps, err error) {

	rows, err := txn.Query("SELECT start, end FROM "+
		"aci_cell_pod_networks WHERE guid=? ORDER BY start ASC", cell)
	if err != nil {
		return
	}
	ips := &m.NetIps{}
	defer rows.Close()
	nr := 0
	for rows.Next() {
		nr++
		var start, end string
		if err := rows.Scan(&start, &end); err == nil {
			start_ip, end_ip := net.ParseIP(start), net.ParseIP(end)
			if start_ip == nil || end_ip == nil {
				continue
			}
			if start_ip.To4() != nil && end_ip.To4() != nil {
				ips.V4 = append(ips.V4, ipam.IpRange{start_ip, end_ip})
			} else if start_ip.To16() != nil && end_ip.To16() != nil {
				ips.V6 = append(ips.V6, ipam.IpRange{start_ip, end_ip})
			}
		}
	}
	if err = rows.Err(); err != nil {
		return
	}
	if len(ips.V4) > 0 || len(ips.V6) > 0 {
		result = ips
	}
	return
}

func (db *CellPodNetDb) Set(txn *sql.Tx, cell string, ips *m.NetIps) (
	err error) {

	err = db.Delete(txn, cell)
	if err != nil {
		err = fmt.Errorf("Error deleting old rows - %s", err.Error())
		return
	}
	for _, ipl := range [][]ipam.IpRange{ips.V4, ips.V6} {
		for _, ip := range ipl {
			if len(ip.Start) == 0 || len(ip.End) == 0 {
				continue
			}
			_, err = txn.Exec("INSERT INTO aci_cell_pod_networks(guid, start, "+
				"end) VALUES(?, ?, ?)",
				cell, ip.Start.String(), ip.End.String())
			if err != nil {
				return
			}
		}
	}
	return
}

func (db *CellPodNetDb) Delete(txn *sql.Tx, cell string) (err error) {
	q := "DELETE FROM aci_cell_pod_networks WHERE guid=?"
	_, err = txn.Exec(q, cell)
	return
}

type CellServiceEpDb struct {
}

func (db *CellServiceEpDb) Get(txn *sql.Tx, cell string) (
	result *m.ServiceEndpoint, err error) {

	ep := &m.ServiceEndpoint{}
	var ipv4_s, ipv6_s string
	err = txn.QueryRow("SELECT mac, ip_v4, ip_v6 FROM "+
		"aci_cell_service_ep WHERE guid=?",
		cell).Scan(&ep.Mac, &ipv4_s, &ipv6_s)
	if err == nil {
		ipv4, ipv6 := net.ParseIP(ipv4_s), net.ParseIP(ipv6_s)
		if ipv4 != nil && ipv4.To4() != nil {
			ep.Ipv4 = ipv4
		}
		if ipv6 != nil && ipv6.To16() != nil {
			ep.Ipv6 = ipv6
		}
		result = ep
	} else if err == sql.ErrNoRows {
		err = nil
		return
	}
	return
}

func (db *CellServiceEpDb) Set(txn *sql.Tx, cell string,
	svcep *m.ServiceEndpoint) (err error) {

	var v4_s, v6_s string
	if len(svcep.Ipv4) > 0 {
		v4_s = svcep.Ipv4.String()
	}
	if len(svcep.Ipv6) > 0 {
		v6_s = svcep.Ipv6.String()
	}
	res, err := txn.Exec("UPDATE aci_cell_service_ep SET "+
		"mac=?, ip_v4=?, ip_v6=? WHERE guid=?",
		svcep.Mac, v4_s, v6_s, cell)
	if err != nil {
		return
	}
	nrows, _ := res.RowsAffected()
	if nrows == 0 {
		_, err = txn.Exec("INSERT INTO aci_cell_service_ep("+
			"guid, mac, ip_v4, ip_v6) VALUES(?, ?, ?, ?)",
			cell, svcep.Mac, v4_s, v6_s)
	}
	return
}

func (db *CellServiceEpDb) Delete(txn *sql.Tx, cell string) (err error) {
	q := "DELETE FROM aci_cell_service_ep WHERE guid=?"
	_, err = txn.Exec(q, cell)
	return
}
