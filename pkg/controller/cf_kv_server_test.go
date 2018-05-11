// Copyright 2018 Cisco Systems, Inc.
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
	"net"
	"testing"

	"github.com/stretchr/testify/assert"

	rkv "github.com/noironetworks/aci-containers/pkg/keyvalueservice"
	md "github.com/noironetworks/aci-containers/pkg/metadata"
)

func TestCfHandleKvContainer(t *testing.T) {
	env := testCfEnvironment(t)
	w := NewCfKvServer(env).Watcher()
	allf := w.AllHandler()
	updf := w.UpdateHandler()

	env.contIdx["c-5"] = &ContainerInfo{ContainerId: "c-5", CellId: "cell-1", InstanceIndex: -1,
		AppId: "app-1"}
	env.contIdx["c-6"] = &ContainerInfo{ContainerId: "c-6", CellId: "cell-1", InstanceIndex: -2,
		AppId: "app-1"}
	env.contIdx["c-7"] = &ContainerInfo{ContainerId: "c-7", CellId: "cell-1", InstanceIndex: -2,
		AppId: "app-2"}

	ifaces_c5 := []interface{}{
		rkv.StructToMap(&md.ContainerIfaceMd{
			HostVethName: "veth1",
			Mac:          "1:2:3:4:5:6",
			IPs: []md.ContainerIfaceIP{
				{Address: net.IPNet{IP: net.ParseIP("10.255.0.45")}}}})}
	ifaces_c6 := []interface{}{
		rkv.StructToMap(&md.ContainerIfaceMd{
			HostVethName: "veth1", Mac: "1:2:3:4:5:8"})}
	ifaces_c7 := []interface{}{
		rkv.StructToMap(&md.ContainerIfaceMd{
			HostVethName: "veth1",
			Mac:          "1:2:3:4:5:7",
			IPs: []md.ContainerIfaceIP{
				{Address: net.IPNet{IP: net.ParseIP("10.255.0.46")}}}})}

	item_c5 := rkv.KvItem{Key: "c-5", Value: ifaces_c5}
	item_c6 := rkv.KvItem{Key: "c-6", Value: ifaces_c6}
	action_c7 := rkv.KvAction{Action: rkv.OP_SET,
		Item: rkv.KvItem{Key: "c-7", Value: ifaces_c7}}
	action_c5 := rkv.KvAction{Action: rkv.OP_DELETE,
		Item: rkv.KvItem{Key: "c-5", Value: ifaces_c5}}

	allf("container", []rkv.KvItem{item_c5, item_c6})
	assert.Equal(t, "10.255.0.45", env.contIdx["c-5"].IpAddress)
	assert.Equal(t, "10.255.0.45", env.appIdx["app-1"].ContainerIps["c-5"])

	assert.Equal(t, "", env.contIdx["c-6"].IpAddress)
	assert.Equal(t, "", env.appIdx["app-1"].ContainerIps["c-6"])

	updf("container", []rkv.KvAction{action_c7, action_c5})
	assert.Equal(t, "10.255.0.46", env.contIdx["c-7"].IpAddress)
	assert.Equal(t, "10.255.0.46", env.appIdx["app-2"].ContainerIps["c-7"])

	assert.Equal(t, "10.255.0.45", env.contIdx["c-5"].IpAddress)
	assert.Equal(t, "10.255.0.45", env.appIdx["app-1"].ContainerIps["c-5"])
}
