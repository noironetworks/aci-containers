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
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/noironetworks/aci-containers/pkg/ipam"
	rkv "github.com/noironetworks/aci-containers/pkg/keyvalueservice"
	md "github.com/noironetworks/aci-containers/pkg/metadata"
	tu "github.com/noironetworks/aci-containers/pkg/testutil"
)

func TestCfHandleKvContainer(t *testing.T) {
	env := testCfEnvironment(t)
	w := NewCfKvClient(env).Watcher()
	allf := w.AllHandler()
	updf := w.UpdateHandler()

	env.agent.epMetadata["_cf_/one"] = getTestEpMetadata("one")
	env.agent.epMetadata["_cf_/two"] = getTestEpMetadata("two")
	ep_one := getTestEpInfo()
	ep_two := getTestEpInfo()

	allf("cell/cell1", []rkv.KvItem{
		{Key: "ct/one", Value: rkv.StructToMap(ep_one)},
		{Key: "ct/two", Value: rkv.StructToMap(ep_two)}})
	assert.Equal(t, ep_one, env.epIdx["one"])
	assert.NotNil(t, env.agent.opflexEps["one"])
	assert.Equal(t, ep_two, env.epIdx["two"])
	assert.NotNil(t, env.agent.opflexEps["two"])

	ep_two.AppName = "a2-name"
	updf("cell/cell1", []rkv.KvAction{
		{Action: rkv.OP_DELETE,
			Item: rkv.KvItem{Key: "ct/one",
				Value: rkv.StructToMap(ep_one)}},
		{Action: rkv.OP_SET,
			Item: rkv.KvItem{Key: "ct/two",
				Value: rkv.StructToMap(ep_two)}},
		{Action: rkv.OP_SET,
			Item: rkv.KvItem{Key: "ct/three",
				Value: rkv.StructToMap(ep_one)}}})
	assert.Nil(t, env.epIdx["one"])
	assert.Nil(t, env.agent.opflexEps["one"])
	assert.Equal(t, ep_two, env.epIdx["two"])
	assert.Equal(t, ep_one, env.epIdx["three"])

	// full sync
	allf("cell/cell1", []rkv.KvItem{
		{Key: "ct/four", Value: rkv.StructToMap(ep_one)}})
	assert.Nil(t, env.epIdx["two"])
	assert.Nil(t, env.agent.opflexEps["two"])
	assert.Nil(t, env.epIdx["three"])
	assert.Nil(t, env.agent.opflexEps["three"])
	assert.Equal(t, ep_one, env.epIdx["four"])
}

func TestCfHandleKvApp(t *testing.T) {
	env := testCfEnvironment(t)
	w := NewCfKvClient(env).Watcher()
	allf := w.AllHandler()
	updf := w.UpdateHandler()

	env.epIdx["one"] = getTestEpInfo()
	env.epIdx["two"] = getTestEpInfo()
	env.epIdx["two"].AppId = "a2"
	app_one := getTestAppInfo()
	app_two := getTestAppInfo()

	allf("apps", []rkv.KvItem{
		{Key: "a1", Value: rkv.StructToMap(app_one)},
		{Key: "a2", Value: rkv.StructToMap(app_two)}})
	assert.Equal(t, app_one, env.appIdx["a1"])
	assert.NotNil(t, env.agent.opflexServices["a1"])
	assert.NotNil(t, env.agent.opflexServices["a1-external"])
	assert.Equal(t, app_two, env.appIdx["a2"])
	assert.NotNil(t, env.agent.opflexServices["a2"])
	assert.NotNil(t, env.agent.opflexServices["a2-external"])

	app_two.ContainerIps = append(app_two.ContainerIps, "10.255.0.101")
	updf("apps", []rkv.KvAction{
		{Action: rkv.OP_DELETE,
			Item: rkv.KvItem{Key: "a1",
				Value: rkv.StructToMap(app_one)}},
		{Action: rkv.OP_SET,
			Item: rkv.KvItem{Key: "a2",
				Value: rkv.StructToMap(app_two)}},
		{Action: rkv.OP_SET,
			Item: rkv.KvItem{Key: "a3",
				Value: rkv.StructToMap(app_one)}}})
	assert.Nil(t, env.appIdx["a1"])
	assert.Nil(t, env.agent.opflexServices["a1"])
	assert.Nil(t, env.agent.opflexServices["a1-external"])
	assert.Equal(t, app_two, env.appIdx["a2"])
	assert.Equal(t, app_one, env.appIdx["a3"])

	// full sync
	allf("apps", []rkv.KvItem{
		{Key: "a4", Value: rkv.StructToMap(app_one)}})
	assert.Nil(t, env.appIdx["a2"])
	assert.Nil(t, env.appIdx["a3"])
	assert.Equal(t, app_one, env.appIdx["a4"])
}

func TestCfHandleKvCellNetwork(t *testing.T) {
	env := testCfEnvironment(t)
	w := NewCfKvClient(env).Watcher()
	allf := w.AllHandler()
	updf := w.UpdateHandler()

	pod_ip := md.NetIps{}
	pod_ip.V4 = append(pod_ip.V4,
		ipam.IpRange{Start: net.ParseIP("10.255.0.2"),
			End: net.ParseIP("10.255.0.127")},
		ipam.IpRange{Start: net.ParseIP("10.255.1.2"),
			End: net.ParseIP("10.255.1.127")})
	pod_ip.V6 = append(pod_ip.V6,
		ipam.IpRange{Start: net.ParseIP("::ff02"),
			End: net.ParseIP("::ffef")},
		ipam.IpRange{Start: net.ParseIP("::fe02"),
			End: net.ParseIP("::feef")})
	pod_ann, _ := json.Marshal(pod_ip)

	allf("cell/cell1", []rkv.KvItem{{Key: "network", Value: string(pod_ann)}})
	assert.Equal(t, string(pod_ann), env.agent.podNetAnnotation)

	// full sync
	allf("cell/cell1", []rkv.KvItem{})
	assert.Equal(t, "{}", env.agent.podNetAnnotation)

	pod_ip.V4 = pod_ip.V4[1:]
	pod_ip.V6 = pod_ip.V6[1:]
	pod_ann, _ = json.Marshal(pod_ip)

	updf("cell/cell1", []rkv.KvAction{
		{Action: rkv.OP_SET,
			Item: rkv.KvItem{Key: "network", Value: string(pod_ann)}}})
	assert.Equal(t, string(pod_ann), env.agent.podNetAnnotation)

	updf("cell/cell1", []rkv.KvAction{
		{Action: rkv.OP_DELETE,
			Item: rkv.KvItem{Key: "network", Value: string(pod_ann)}}})
	assert.Equal(t, "{}", env.agent.podNetAnnotation)
}

func TestCfHandleKvCellService(t *testing.T) {
	env := testCfEnvironment(t)
	w := NewCfKvClient(env).Watcher()
	allf := w.AllHandler()
	updf := w.UpdateHandler()

	env.epIdx["one"] = getTestEpInfo()
	env.appIdx["a1"] = getTestAppInfo()
	ep_one := getTestEpInfo()

	svc_ep := md.ServiceEndpoint{Mac: "de:ad:be:ef:00:01",
		Ipv4: net.ParseIP("10.150.0.10")}
	allf("cell/cell1",
		[]rkv.KvItem{
			{Key: "service", Value: rkv.StructToMap(&svc_ep)},
			{Key: "ct/one", Value: rkv.StructToMap(ep_one)}})
	assert.Equal(t, svc_ep, env.agent.serviceEp)
	tu.WaitFor(t, "Ext-IP service ep created", 500*time.Millisecond,
		func(last bool) (bool, error) {
			return env.agent.opflexServices["a1-external"] != nil, nil
		})

	updf("cell/cell1", []rkv.KvAction{
		{Action: rkv.OP_DELETE,
			Item: rkv.KvItem{Key: "service",
				Value: rkv.StructToMap(&svc_ep)}}})
	assert.Equal(t, "", env.agent.serviceEp.Mac)
	assert.Nil(t, env.agent.serviceEp.Ipv4)
	tu.WaitFor(t, "Ext-IP service ep removed", 500*time.Millisecond,
		func(last bool) (bool, error) {
			svc := env.agent.opflexServices["a1-external"]
			return (svc != nil && svc.ServiceMac == "" &&
				svc.InterfaceIp == ""), nil
		})

	updf("cell/cell1", []rkv.KvAction{
		{Action: rkv.OP_SET,
			Item: rkv.KvItem{Key: "service",
				Value: rkv.StructToMap(&svc_ep)}}})
	assert.Equal(t, svc_ep, env.agent.serviceEp)
	// full sync
	allf("cell/cell1", []rkv.KvItem{
		{Key: "ct/one", Value: rkv.StructToMap(ep_one)}})
	assert.Equal(t, "", env.agent.serviceEp.Mac)
	assert.Nil(t, env.agent.serviceEp.Ipv4)
}

func TestCfStaleContCleanup(t *testing.T) {
	env := testCfEnvironment(t)
	w := NewCfKvClient(env).Watcher()
	allf := w.AllHandler()

	env.agent.epMetadata["_cf_/one"] = getTestEpMetadata("one")
	env.agent.epMetadata["_cf_/two"] = getTestEpMetadata("two")
	env.agent.epMetadata["_cf_/three"] = getTestEpMetadata("three")

	allf("cell/cell1", []rkv.KvItem{})
	allf("apps", []rkv.KvItem{})
	assert.True(t, env.agent.syncEnabled)
	assert.Empty(t, env.agent.epMetadata)
}
