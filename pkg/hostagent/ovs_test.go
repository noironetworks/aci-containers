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

package hostagent

import (
	"testing"

	"github.com/ovn-org/libovsdb"
	"github.com/stretchr/testify/assert"

	md "github.com/noironetworks/aci-containers/pkg/metadata"
)

type diffPortTest struct {
	bridges  map[string]ovsBridge
	metadata map[string]map[string]*md.ContainerMetadata
	expected []libovsdb.Operation
	desc     string
}

func TestDiffPorts(t *testing.T) {
	agent := testAgent()
	agent.config.AccessBridgeName = "br-access"
	agent.config.IntBridgeName = "br-int"
	agent.config.OpflexMode = "overlay"

	partialBr := map[string]ovsBridge{
		"br-access": {
			uuid: "86d9e696-00d0-43dd-9fd2-d43f7f6a883d",
			ports: map[string]string{
				"vethf3323b92": "640a7740-d51e-4579-86e2-609d38b38e11",
			},
		},
		"br-int": {
			uuid: "aba85930-00f9-4665-9917-40beff731d87",
			ports: map[string]string{
				"pi-vethf3323b92": "baa976d4-3b8b-4cfb-976e-08477ffcf72c",
			},
		},
	}
	emptyBr := map[string]ovsBridge{
		"br-access": {
			uuid:  "86d9e696-00d0-43dd-9fd2-d43f7f6a883d",
			ports: map[string]string{},
		},
		"br-int": {
			uuid:  "aba85930-00f9-4665-9917-40beff731d87",
			ports: map[string]string{},
		},
	}
	emptyBrWhostac := map[string]ovsBridge{
		"br-access": {
			uuid:  "86d9e696-00d0-43dd-9fd2-d43f7f6a883d",
			ports: map[string]string{},
		},
		"br-int": {
			uuid:  "aba85930-00f9-4665-9917-40beff731d87",
			ports: map[string]string{},
		},
	}
	onepodMeta := map[string]map[string]*md.ContainerMetadata{
		"ns/pod1": {
			"pod1": &md.ContainerMetadata{
				Id: md.ContainerId{
					ContId:    "cont1",
					Pod:       "pod1",
					Namespace: "ns",
				},
				Ifaces: []*md.ContainerIfaceMd{
					{
						HostVethName: "vethf3323b92",
					},
				},
			},
		},
	}

	addOnePod, _ := addIfaceOps("vethf3323b92", "pi-vethf3323b92",
		"pa-vethf3323b92", "86d9e696-00d0-43dd-9fd2-d43f7f6a883d",
		"aba85930-00f9-4665-9917-40beff731d87", "0")
	delPartial := []libovsdb.Operation{
		delBrPortOp("86d9e696-00d0-43dd-9fd2-d43f7f6a883d",
			[]libovsdb.UUID{
				{GoUUID: "640a7740-d51e-4579-86e2-609d38b38e11"},
			}),
		delBrPortOp("aba85930-00f9-4665-9917-40beff731d87",
			[]libovsdb.UUID{
				{GoUUID: "baa976d4-3b8b-4cfb-976e-08477ffcf72c"},
			}),
	}

	updatePartial := make([]libovsdb.Operation, len(delPartial))
	copy(updatePartial, delPartial)
	updatePartial = append(updatePartial, addOnePod...)

	emptyMeta := map[string]map[string]*md.ContainerMetadata{}

	diffPortTests := []diffPortTest{
		{
			bridges:  emptyBr,
			metadata: onepodMeta,
			expected: addOnePod,
			desc:     "simple add",
		},
		{
			bridges:  partialBr,
			metadata: onepodMeta,
			expected: updatePartial,
			desc:     "partial",
		},
		{
			bridges:  partialBr,
			metadata: emptyMeta,
			expected: delPartial,
			desc:     "stale",
		},
	}

	for _, pt := range diffPortTests {
		agent.epMetadata = pt.metadata
		assert.Equal(t, pt.expected, agent.diffPorts(pt.bridges), pt.desc)
	}

	agent.config.UplinkIface = "eth2"
	agent.config.EncapType = "vxlan"
	addUplinks, _ :=
		addUplinkIfaceOps(agent.config, "aba85930-00f9-4665-9917-40beff731d87")
	addVxlan, _ :=
		addVxlanIfaceOps(agent.config, "aba85930-00f9-4665-9917-40beff731d87")
	addUplinks = append(addUplinks, addVxlan...)

	agent.epMetadata = emptyMeta
	assert.Equal(t, addUplinks, agent.diffPorts(emptyBrWhostac), "uplinks")
}

func TestUuidSetToMap(t *testing.T) {
	portUuid := libovsdb.UUID{GoUUID: "aba85930-00f9-4665-9917-40beff731d87"}
	portMap := uuidSetToMap(portUuid)
	assert.EqualValues(t, 1, len(portMap))

	ports, err := libovsdb.NewOvsSet([]libovsdb.UUID{
		{GoUUID: "aba85930-00f9-4665-9917-40beff731d87"},
		{GoUUID: "aba85930-00f9-4665-9917-40beff731d88"},
		{GoUUID: "aba85930-00f9-4665-9917-40beff731d89"},
	})
	assert.Nil(t, err)
	portMap2 := uuidSetToMap(*ports)
	assert.EqualValues(t, 3, len(ports.GoSet))
	assert.EqualValues(t, 3, len(portMap2))
}
