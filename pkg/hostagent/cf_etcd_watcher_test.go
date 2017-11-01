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

	etcdclient "github.com/coreos/etcd/client"
	"github.com/stretchr/testify/assert"

	"github.com/noironetworks/aci-containers/pkg/ipam"
	md "github.com/noironetworks/aci-containers/pkg/metadata"
	tu "github.com/noironetworks/aci-containers/pkg/testutil"
)

func TestCfHandleEtcdContainerNode(t *testing.T) {
	env := testCfEnvironment(t)
	handler := NewCfEtcdCellWatcher(env).NodeHandler()
	op := "create"

	env.agent.epMetadata["_cf_/one"] = getTestEpMetadata()
	ep := getTestEpInfo()
	ep_str, _ := json.Marshal(ep)
	node := &etcdclient.Node{Key: "/aci/cells/cell1/containers/one/ep", Value: string(ep_str)}

	handler(&op, node)
	assert.Equal(t, ep, env.epIdx["one"])
	assert.NotNil(t, env.agent.opflexEps["one"])

	op = "delete"
	node.Key = "/aci/cells/cell1/containers/one"
	handler(&op, node)
	assert.Nil(t, env.epIdx["one"])
	assert.Nil(t, env.agent.opflexEps["one"])
}

func TestCfHandleEtcdAppNode(t *testing.T) {
	env := testCfEnvironment(t)
	handler := NewCfEtcdAppWatcher(env).NodeHandler()
	op := "create"

	env.epIdx["one"] = getTestEpInfo()
	app := getTestAppInfo()
	app_str, _ := json.Marshal(app)
	node := &etcdclient.Node{Key: "/aci/apps/a1", Value: string(app_str)}

	handler(&op, node)
	assert.Equal(t, app, env.appIdx["a1"])
	assert.NotNil(t, env.agent.opflexServices["a1"])
	assert.NotNil(t, env.agent.opflexServices["a1-external"])

	op = "delete"
	handler(&op, node)
	assert.Nil(t, env.appIdx["a1"])
	assert.Nil(t, env.agent.opflexServices["a1"])
	assert.Nil(t, env.agent.opflexServices["a1-external"])
}

func TestCfHandleEtcdCellNetworkNode(t *testing.T) {
	env := testCfEnvironment(t)
	handler := NewCfEtcdCellWatcher(env).NodeHandler()
	op := "create"

	pod_ip := md.NetIps{}
	pod_ip.V4 = append(pod_ip.V4,
		ipam.IpRange{Start: net.ParseIP("10.255.0.2"), End: net.ParseIP("10.255.0.127")},
		ipam.IpRange{Start: net.ParseIP("10.255.1.2"), End: net.ParseIP("10.255.1.127")})
	pod_ip.V6 = append(pod_ip.V6,
		ipam.IpRange{Start: net.ParseIP("::ff02"), End: net.ParseIP("::ffef")},
		ipam.IpRange{Start: net.ParseIP("::fe02"), End: net.ParseIP("::feef")})
	pod_ann, _ := json.Marshal(pod_ip)

	node := &etcdclient.Node{Key: "/aci/cells/cell1/network", Value: string(pod_ann)}
	handler(&op, node)
	assert.Equal(t, string(pod_ann), env.agent.podNetAnnotation)

	op = "delete"
	node.Key = "/aci/cells/cell1"
	handler(&op, node)
	assert.Equal(t, "[]", env.agent.podNetAnnotation)
}

func TestCfHandleEtcdCellServiceNode(t *testing.T) {
	env := testCfEnvironment(t)
	handler := NewCfEtcdCellWatcher(env).NodeHandler()
	op := "create"

	env.epIdx["one"] = getTestEpInfo()
	env.appIdx["a1"] = getTestAppInfo()

	svc_ep := md.ServiceEndpoint{Mac: "de:ad:be:ef:00:01", Ipv4: net.ParseIP("10.150.0.10")}
	svc_ep_str, _ := json.Marshal(svc_ep)
	node := &etcdclient.Node{Key: "/aci/cells/cell1/service", Value: string(svc_ep_str)}

	handler(&op, node)
	assert.Equal(t, svc_ep, env.agent.serviceEp)
	tu.WaitFor(t, "Ext-IP service ep created", 500*time.Millisecond,
		func(last bool) (bool, error) {
			return env.agent.opflexServices["a1-external"] != nil, nil
	})

	op = "delete"
	node.Key = "/aci/cells/cell1"
	handler(&op, node)
	assert.Equal(t, "", env.agent.serviceEp.Mac)
	assert.Nil(t, env.agent.serviceEp.Ipv4)
	tu.WaitFor(t, "Ext-IP service ep removed", 500*time.Millisecond,
		func(last bool) (bool, error) {
			svc := env.agent.opflexServices["a1-external"]
			return (svc != nil && svc.ServiceMac == "" && svc.InterfaceIp == ""), nil
	})
}
