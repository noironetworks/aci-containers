// Copyright 2016,2017 Cisco Systems, Inc.
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

package hostagent

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/noironetworks/aci-containers/pkg/metadata"
	"github.com/socketplane/libovsdb"
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
					for uuid := range uuidSetToMap(row.New.Fields["ports"]) {
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

	for _, name := range brNames {
		if _, ok := bridges[name]; !ok {
			return nil, fmt.Errorf("Bridge %s not found", name)
		}
	}

	return bridges, nil
}

func (agent *HostAgent) syncPorts(socket string) error {
	agent.log.Debug("Syncing OVS ports")

	ovs, err := libovsdb.ConnectWithUnixSocket(socket)
	if err != nil {
		return err
	}
	defer ovs.Disconnect()

	brNames :=
		[]string{agent.config.AccessBridgeName, agent.config.IntBridgeName}

	bridges, err := loadBridges(ovs, brNames)
	if err != nil {
		return err
	}

	for _, brName := range brNames {
		if _, ok := bridges[brName]; !ok {
			return fmt.Errorf("Bridge %s not found", brName)
		}
	}

	ops := agent.diffPorts(bridges)
	return execTransaction(ovs, ops)
}

func (agent *HostAgent) diffPorts(bridges map[string]ovsBridge) []libovsdb.Operation {

	var ops []libovsdb.Operation

	found := make(map[string]map[string]bool)

	brNames :=
		[]string{agent.config.AccessBridgeName, agent.config.IntBridgeName}
	for _, brName := range brNames {
		found[brName] = map[string]bool{
			brName: true,
		}
	}

	agent.indexMutex.Lock()
	opid := 0
	for id, metas := range agent.epMetadata {
		for _, meta := range metas {
			for _, iface := range meta.Ifaces {
				if iface.HostVethName == "" {
					continue
				}

				patchIntName, patchAccessName :=
					metadata.GetIfaceNames(iface.HostVethName)

				var delops []libovsdb.Operation
				portmissing := false
				portMap := map[string][]string{
					agent.config.AccessBridgeName: {patchAccessName,
						iface.HostVethName},
					agent.config.IntBridgeName: {patchIntName},
				}
				for _, brName := range brNames {
					portNames := portMap[brName]
					if br, ok := bridges[brName]; ok {
						var delports []libovsdb.UUID
						for _, n := range portNames {
							if uuid, ok := br.ports[n]; ok {
								delports = append(delports,
									libovsdb.UUID{GoUUID: uuid})
								found[brName][n] = true
							} else {
								portmissing = true
							}
						}
						if len(delports) > 0 {
							delops = append(delops,
								delBrPortOp(br.uuid, delports))
						}
					}
				}

				if portmissing {
					// if we have only some of the ports, delete the ones that
					// are already there
					if len(delops) > 0 {
						agent.log.Warning("Deleting stale partial state for ",
							id)
						ops = append(ops, delops...)
					}

					agent.log.Debug("Adding ports for ", id)
					adds, err :=
						addIfaceOps(iface.HostVethName, patchIntName,
							patchAccessName,
							bridges[agent.config.AccessBridgeName].uuid,
							bridges[agent.config.IntBridgeName].uuid,
							strconv.Itoa(opid))
					opid++
					if err != nil {
						agent.log.Error(err)
					}
					ops = append(ops, adds...)
				}
			}
		}
	}

	intbr, ok := bridges[agent.config.IntBridgeName]
	if ok {
		var uplinkList []string
		uplinks := make(map[string]addUplinkIfaceFunc)
		if agent.config.UplinkIface != "" {
			uplinkList = append(uplinkList, agent.config.UplinkIface)
			uplinks[agent.config.UplinkIface] = addUplinkIfaceOps
		}
		if agent.config.EncapType == "vxlan" {
			uplinkList = append(uplinkList, "vxlan0")
			uplinks["vxlan0"] = addVxlanIfaceOps
		}
		for _, iface := range uplinkList {
			if _, pok := intbr.ports[iface]; pok {
				found[agent.config.IntBridgeName][iface] = true
			} else {
				agent.log.Debug("Adding uplink port ", iface)
				adds, err := uplinks[iface](agent.config,
					bridges[agent.config.IntBridgeName].uuid)
				if err != nil {
					agent.log.Error(err)
				}
				ops = append(ops, adds...)
			}
		}
	}

	agent.indexMutex.Unlock()

	for _, brName := range brNames {
		br, ok := bridges[brName]
		if !ok {
			agent.log.Warning("Bridge ", brName, " missing")
			continue
		}

		var delports []libovsdb.UUID
		for name, uuid := range br.ports {
			if found[brName][name] {
				continue
			}
			skip_ok := false
			for _, skip := range agent.ignoreOvsPorts[brName] {
				if skip == name {
					skip_ok = true
					break
				}
			}
			if skip_ok {
				continue
			}
			agent.log.Debug("Deleting stale port for ", brName, ": ", name)
			delports = append(delports, libovsdb.UUID{GoUUID: uuid})
		}
		if len(delports) > 0 {
			ops = append(ops, delBrPortOp(br.uuid, delports))
		}
	}

	return ops
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

type addUplinkIfaceFunc func(config *HostAgentConfig,
	intBrUuid string) ([]libovsdb.Operation, error)

func addVxlanIfaceOps(config *HostAgentConfig,
	intBrUuid string) ([]libovsdb.Operation, error) {
	uuidVxlanP := "vxlan_uuid_port"
	uuidVxlanI := "vxlan_uuid_interface"

	opti, err := libovsdb.NewOvsMap(map[string]interface{}{
		"dst_port":  "8472",
		"key":       "flow",
		"remote_ip": "flow",
	})
	if err != nil {
		return nil, err
	}

	iports, err := libovsdb.NewOvsSet([]libovsdb.UUID{
		{GoUUID: uuidVxlanP},
	})
	if err != nil {
		return nil, err
	}
	mibridge := []interface{}{libovsdb.NewMutation("ports", "insert", iports)}
	cibridge := []interface{}{libovsdb.NewCondition("_uuid", "==",
		libovsdb.UUID{GoUUID: intBrUuid})}

	ops := []libovsdb.Operation{
		{
			Op:    "insert",
			Table: "Interface",
			Row: map[string]interface{}{
				"name":    "vxlan0",
				"type":    "vxlan",
				"options": opti,
			},
			UUIDName: uuidVxlanI,
		},
		{
			Op:    "insert",
			Table: "Port",
			Row: map[string]interface{}{
				"name":       "vxlan0",
				"interfaces": libovsdb.UUID{GoUUID: uuidVxlanI},
			},
			UUIDName: uuidVxlanP,
		},
		{
			Op:        "mutate",
			Table:     "Bridge",
			Mutations: mibridge,
			Where:     cibridge,
		},
	}
	return ops, nil
}

func addUplinkIfaceOps(config *HostAgentConfig,
	intBrUuid string) ([]libovsdb.Operation, error) {

	uuidUplinkP := "uplink_uuid_port"
	uuidUplinkI := "uplink_uuid_interface"

	iports, err := libovsdb.NewOvsSet([]libovsdb.UUID{
		{GoUUID: uuidUplinkP},
	})
	if err != nil {
		return nil, err
	}
	mibridge := []interface{}{libovsdb.NewMutation("ports", "insert", iports)}
	cibridge := []interface{}{libovsdb.NewCondition("_uuid", "==",
		libovsdb.UUID{GoUUID: intBrUuid})}

	ops := []libovsdb.Operation{
		{
			Op:    "insert",
			Table: "Interface",
			Row: map[string]interface{}{
				"name": config.UplinkIface,
			},
			UUIDName: uuidUplinkI,
		},
		{
			Op:    "insert",
			Table: "Port",
			Row: map[string]interface{}{
				"name":       config.UplinkIface,
				"interfaces": libovsdb.UUID{GoUUID: uuidUplinkI},
			},
			UUIDName: uuidUplinkP,
		},
		{
			Op:        "mutate",
			Table:     "Bridge",
			Mutations: mibridge,
			Where:     cibridge,
		},
	}
	return ops, nil
}

func addIfaceOps(hostVethName string, patchIntName string,
	patchAccessName string, accessBrUuid string,
	intBrUuid string, opid string) ([]libovsdb.Operation, error) {

	uuidHostP := "host_veth_uuid_port_" + opid
	uuidHostI := "host_veth_uuid_interface" + opid
	uuidPatchIntP := "patch_int_uuid_port" + opid
	uuidPatchIntI := "patch_int_uuid_interface" + opid
	uuidPatchAccP := "patch_acc_uuid_port" + opid
	uuidPatchAccI := "patch_acc_uuid_interface" + opid

	patchopti, err := libovsdb.NewOvsMap(map[string]interface{}{
		"peer": patchAccessName,
	})
	if err != nil {
		return nil, err
	}
	patchopta, err := libovsdb.NewOvsMap(map[string]interface{}{
		"peer": patchIntName,
	})
	if err != nil {
		return nil, err
	}

	aports, err := libovsdb.NewOvsSet([]libovsdb.UUID{
		{GoUUID: uuidHostP},
		{GoUUID: uuidPatchAccP},
	})
	if err != nil {
		return nil, err
	}
	mabridge := []interface{}{libovsdb.NewMutation("ports", "insert", aports)}
	cabridge := []interface{}{libovsdb.NewCondition("_uuid", "==",
		libovsdb.UUID{GoUUID: accessBrUuid})}

	iports, err := libovsdb.NewOvsSet([]libovsdb.UUID{
		{GoUUID: uuidPatchIntP},
	})
	if err != nil {
		return nil, err
	}
	mibridge := []interface{}{libovsdb.NewMutation("ports", "insert", iports)}
	cibridge := []interface{}{libovsdb.NewCondition("_uuid", "==",
		libovsdb.UUID{GoUUID: intBrUuid})}

	return []libovsdb.Operation{
		{
			Op:    "insert",
			Table: "Interface",
			Row: map[string]interface{}{
				"name": hostVethName,
			},
			UUIDName: uuidHostI,
		},
		{
			Op:    "insert",
			Table: "Interface",
			Row: map[string]interface{}{
				"name":    patchIntName,
				"type":    "patch",
				"options": patchopti,
			},
			UUIDName: uuidPatchIntI,
		},
		{
			Op:    "insert",
			Table: "Interface",
			Row: map[string]interface{}{
				"name":    patchAccessName,
				"type":    "patch",
				"options": patchopta,
			},
			UUIDName: uuidPatchAccI,
		},
		{
			Op:    "insert",
			Table: "Port",
			Row: map[string]interface{}{
				"name":       hostVethName,
				"interfaces": libovsdb.UUID{GoUUID: uuidHostI},
			},
			UUIDName: uuidHostP,
		},
		{
			Op:    "insert",
			Table: "Port",
			Row: map[string]interface{}{
				"name":       patchIntName,
				"interfaces": libovsdb.UUID{GoUUID: uuidPatchIntI},
			},
			UUIDName: uuidPatchIntP,
		},
		{
			Op:    "insert",
			Table: "Port",
			Row: map[string]interface{}{
				"name":       patchAccessName,
				"interfaces": libovsdb.UUID{GoUUID: uuidPatchAccI},
			},
			UUIDName: uuidPatchAccP,
		},
		{
			Op:        "mutate",
			Table:     "Bridge",
			Mutations: mabridge,
			Where:     cabridge,
		},
		{
			Op:        "mutate",
			Table:     "Bridge",
			Mutations: mibridge,
			Where:     cibridge,
		},
	}, nil
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
