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
	"encoding/json"
	"net"
	"testing"
	"time"

	etcdclient "github.com/coreos/etcd/client"
	"github.com/stretchr/testify/assert"

	md "github.com/noironetworks/aci-containers/pkg/metadata"
	tu "github.com/noironetworks/aci-containers/pkg/testutil"
)

func TestCfHandleEtcdContainerNode(t *testing.T) {
	env := testCfEnvironment(t)
	handler := NewCfEtcdContainersWatcher(env).NodeHandler()
	op := "set"

	env.contIdx["c-5"] = &ContainerInfo{ContainerId: "c-5", CellId: "cell-1", InstanceIndex: -1,
		AppId: "app-1"}
	env.contIdx["c-6"] = &ContainerInfo{ContainerId: "c-6", CellId: "cell-1", InstanceIndex: -2,
		AppId: "app-1"}
	env.contIdx["c-7"] = &ContainerInfo{ContainerId: "c-7", CellId: "cell-1", InstanceIndex: -2,
		AppId: "app-2"}

	ifaces_c5 := []*md.ContainerIfaceMd{
		{
			HostVethName: "veth1",
			Mac:          "1:2:3:4:5:6",
			IPs: []md.ContainerIfaceIP{
				{
					Address: net.IPNet{
						IP: net.ParseIP("10.255.0.45")}}}}}
	ifaces_c6 := []*md.ContainerIfaceMd{
		{HostVethName: "veth1", Mac: "1:2:3:4:5:8"}}
	ifaces_c7 := []*md.ContainerIfaceMd{
		{
			HostVethName: "veth1",
			Mac:          "1:2:3:4:5:7",
			IPs: []md.ContainerIfaceIP{
				{
					Address: net.IPNet{
						IP: net.ParseIP("10.255.0.46")}}}}}

	ifaces_c5_str, _ := json.Marshal(ifaces_c5)
	ifaces_c6_str, _ := json.Marshal(ifaces_c6)
	ifaces_c7_str, _ := json.Marshal(ifaces_c7)

	node_c5 := &etcdclient.Node{
		Key: "/aci/controller/containers/c-5/metadata", Value: string(ifaces_c5_str)}
	node_c6 := &etcdclient.Node{
		Key: "/aci/controller/containers/c-6/metadata", Value: string(ifaces_c6_str)}
	node_c7 := &etcdclient.Node{
		Key: "/aci/controller/containers/c-7/metadata", Value: string(ifaces_c7_str)}

	handler(&op, node_c5)
	assert.Equal(t, "10.255.0.45", env.contIdx["c-5"].IpAddress)
	assert.Equal(t, "10.255.0.45", env.appIdx["app-1"].ContainerIps["c-5"])

	handler(&op, node_c6)
	assert.Equal(t, "", env.contIdx["c-6"].IpAddress)
	assert.Equal(t, "", env.appIdx["app-1"].ContainerIps["c-6"])

	handler(&op, node_c7)
	assert.Equal(t, "10.255.0.46", env.contIdx["c-7"].IpAddress)
	assert.Equal(t, "10.255.0.46", env.appIdx["app-2"].ContainerIps["c-7"])

	op = "delete"
	node_c5.Key = "/aci/controller/containers/c-5"
	handler(&op, node_c5)
	assert.Equal(t, "10.255.0.45", env.contIdx["c-5"].IpAddress)
	assert.Equal(t, "10.255.0.45", env.appIdx["app-1"].ContainerIps["c-5"])
}

func TestCfEtcdWatcherCancel(t *testing.T) {
	env := testCfEnvironment(t)
	cw := NewCfEtcdContainersWatcher(env)
	ch := make(chan struct{})
	runEnded := false
	go func() {
		cw.Run(ch)
		runEnded = true
	}()
	tu.WaitFor(t, "Waiting to sync", 500*time.Millisecond,
		func(bool) (bool, error) { return cw.Synced(), nil })
	close(ch)
	tu.WaitFor(t, "Waiting for Run() to end", 1000*time.Millisecond,
		func(bool) (bool, error) { return runEnded, nil })
}
