// Copyright 2016 Cisco Systems, Inc.
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
	"encoding/json"
	"errors"
	"fmt"
	"github.com/socketplane/libovsdb"

	"github.com/noironetworks/aci-containers/metadata"
)

type ovsBridge struct {
	uuid  string
	ports map[string]string
}

func uuidSetToMap(set interface{}) map[string]bool {
	ports := map[string]bool{}

	switch t := set.(type) {
	case libovsdb.OvsSet:
		for _, p := range t.GoSet {
			switch pt := p.(type) {
			case libovsdb.UUID:
				ports[pt.GoUUID] = true
			}
		}
	case libovsdb.UUID:
		ports[t.GoUUID] = true
	}

	return ports
}

func loadBridges(ovs *libovsdb.OvsdbClient,
	brNames []string) (map[string]ovsBridge, error) {

	bridges := map[string]ovsBridge{}

	requests := make(map[string]libovsdb.MonitorRequest)
	requests["Bridge"] = libovsdb.MonitorRequest{
		Columns: []string{"name", "ports"},
		Select:  libovsdb.MonitorSelect{Initial: true},
	}
	requests["Port"] = libovsdb.MonitorRequest{
		Columns: []string{"interfaces", "name"},
		Select:  libovsdb.MonitorSelect{Initial: true},
	}

	initial, _ := ovs.Monitor("Open_vSwitch", "", requests)

	var pcache = map[string]libovsdb.Row{}
	tableUpdate, ok := initial.Updates["Port"]
	if !ok {
		return nil, fmt.Errorf("Port table not found")
	}
	for uuid, row := range tableUpdate.Rows {
		pcache[uuid] = row.New
	}

	tableUpdate, ok = initial.Updates["Bridge"]
	if !ok {
		return nil, fmt.Errorf("Bridges table not found")
	}
	for uuid, row := range tableUpdate.Rows {
		switch n := row.New.Fields["name"].(type) {
		case string:
			for _, brName := range brNames {
				if brName == n {
					br := ovsBridge{
						uuid:  uuid,
						ports: map[string]string{},
					}
					for uuid, _ := range uuidSetToMap(row.New.Fields["ports"]) {
						switch pn := pcache[uuid].Fields["name"].(type) {
						case string:
							br.ports[pn] = uuid
						}
					}
					bridges[brName] = br
				}
			}
		}
	}

	return bridges, nil
}

func createPorts(socket string, intBrName string,
	accessBrName string, hostVethName string) error {

	ovs, err := libovsdb.ConnectWithUnixSocket(socket)
	if err != nil {
		return err
	}
	defer ovs.Disconnect()

	bridges, err := loadBridges(ovs, []string{intBrName, accessBrName})
	if err != nil {
		return err
	}

	for _, brName := range []string{intBrName, accessBrName} {
		if _, ok := bridges[brName]; !ok {
			return fmt.Errorf("Bridge %s not found", brName)
		}
	}

	patchIntName, patchAccessName := metadata.GetIfaceNames(hostVethName)
	const EXISTS = "Port %s already exists"
	if _, ok := bridges[intBrName].ports[patchIntName]; ok {
		return fmt.Errorf(EXISTS, patchIntName)
	}
	if _, ok := bridges[accessBrName].ports[patchAccessName]; ok {
		return fmt.Errorf(EXISTS, patchAccessName)
	}
	if _, ok := bridges[accessBrName].ports[hostVethName]; ok {
		return fmt.Errorf(EXISTS, hostVethName)
	}

	const uuidHostP = "host_veth_uuid_port"
	const uuidHostI = "host_veth_uuid_interface"
	const uuidPatchIntP = "patch_int_uuid_port"
	const uuidPatchIntI = "patch_int_uuid_interface"
	const uuidPatchAccP = "patch_acc_uuid_port"
	const uuidPatchAccI = "patch_acc_uuid_interface"

	patchopti, err := libovsdb.NewOvsMap(map[string]interface{}{
		"peer": patchAccessName,
	})
	if err != nil {
		return err
	}
	patchopta, err := libovsdb.NewOvsMap(map[string]interface{}{
		"peer": patchIntName,
	})
	if err != nil {
		return err
	}

	aports, err := libovsdb.NewOvsSet([]libovsdb.UUID{
		{GoUUID: uuidHostP},
		{GoUUID: uuidPatchAccP},
	})
	if err != nil {
		return err
	}
	mabridge := []interface{}{libovsdb.NewMutation("ports", "insert", aports)}
	cabridge := []interface{}{libovsdb.NewCondition("_uuid", "==",
		libovsdb.UUID{GoUUID: bridges[accessBrName].uuid})}

	iports, err := libovsdb.NewOvsSet([]libovsdb.UUID{
		{GoUUID: uuidPatchIntP},
	})
	if err != nil {
		return err
	}
	mibridge := []interface{}{libovsdb.NewMutation("ports", "insert", iports)}
	cibridge := []interface{}{libovsdb.NewCondition("_uuid", "==",
		libovsdb.UUID{GoUUID: bridges[intBrName].uuid})}

	ops := []libovsdb.Operation{
		libovsdb.Operation{
			Op:    "insert",
			Table: "Interface",
			Row: map[string]interface{}{
				"name": hostVethName,
			},
			UUIDName: uuidHostI,
		},
		libovsdb.Operation{
			Op:    "insert",
			Table: "Interface",
			Row: map[string]interface{}{
				"name":    patchIntName,
				"type":    "patch",
				"options": patchopti,
			},
			UUIDName: uuidPatchIntI,
		},
		libovsdb.Operation{
			Op:    "insert",
			Table: "Interface",
			Row: map[string]interface{}{
				"name":    patchAccessName,
				"type":    "patch",
				"options": patchopta,
			},
			UUIDName: uuidPatchAccI,
		},
		libovsdb.Operation{
			Op:    "insert",
			Table: "Port",
			Row: map[string]interface{}{
				"name":       hostVethName,
				"interfaces": libovsdb.UUID{GoUUID: uuidHostI},
			},
			UUIDName: uuidHostP,
		},
		libovsdb.Operation{
			Op:    "insert",
			Table: "Port",
			Row: map[string]interface{}{
				"name":       patchIntName,
				"interfaces": libovsdb.UUID{GoUUID: uuidPatchIntI},
			},
			UUIDName: uuidPatchIntP,
		},
		libovsdb.Operation{
			Op:    "insert",
			Table: "Port",
			Row: map[string]interface{}{
				"name":       patchAccessName,
				"interfaces": libovsdb.UUID{GoUUID: uuidPatchAccI},
			},
			UUIDName: uuidPatchAccP,
		},
		libovsdb.Operation{
			Op:        "mutate",
			Table:     "Bridge",
			Mutations: mabridge,
			Where:     cabridge,
		},
		libovsdb.Operation{
			Op:        "mutate",
			Table:     "Bridge",
			Mutations: mibridge,
			Where:     cibridge,
		},
	}

	return execTransaction(ovs, ops)
}

func delBrPortOp(brUuid string, pUuid []libovsdb.UUID) libovsdb.Operation {
	p, _ := libovsdb.NewOvsSet(pUuid)
	m := []interface{}{libovsdb.NewMutation("ports", "delete", p)}
	c := []interface{}{libovsdb.NewCondition("_uuid", "==",
		libovsdb.UUID{GoUUID: brUuid})}
	return libovsdb.Operation{
		Op:        "mutate",
		Table:     "Bridge",
		Mutations: m,
		Where:     c,
	}
}

func delPorts(socket string, intBrName string,
	accessBrName string, hostVethName string) error {
	ovs, err := libovsdb.ConnectWithUnixSocket(socket)
	if err != nil {
		return err
	}
	defer ovs.Disconnect()

	bridges, err := loadBridges(ovs, []string{intBrName, accessBrName})
	if err != nil {
		return err
	}

	patchIntName, patchAccessName := metadata.GetIfaceNames(hostVethName)

	ops := []libovsdb.Operation{}

	for brName, portNames := range map[string][]string{
		accessBrName: []string{patchAccessName, hostVethName},
		intBrName:    []string{patchIntName},
	} {
		if br, ok := bridges[brName]; ok {
			var delports []libovsdb.UUID
			for _, n := range portNames {
				if uuid, ok := br.ports[n]; ok {
					delports = append(delports, libovsdb.UUID{GoUUID: uuid})
				}
			}
			if len(delports) > 0 {
				ops = append(ops, delBrPortOp(br.uuid, delports))
			}
		}
	}

	if len(ops) > 0 {
		return execTransaction(ovs, ops)
	}
	return nil
}

func execTransaction(ovs *libovsdb.OvsdbClient, ops []libovsdb.Operation) error {
	reply, _ := ovs.Transact("Open_vSwitch", ops...)
	if len(reply) < len(ops) {
		return errors.New("Number of replies less than number of operations")
	}

	for i, o := range reply {
		if o.Error != "" {
			r, _ := json.Marshal(o)
			return fmt.Errorf("Transaction %d failed due to an error: %s", i,
				string(r))
		}
	}
	return nil
}
