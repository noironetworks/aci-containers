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

	"github.com/stretchr/testify/assert"

	etcd "github.com/noironetworks/aci-containers/pkg/cf_etcd"
	md "github.com/noironetworks/aci-containers/pkg/metadata"
)

func TestCfContainerUpdate(t *testing.T) {
	env := testCfEnvironment(t)
	exists := false

	id := "one"
	ep := getTestEpInfo()
	env.epIdx[id] = ep
	env.agent.epMetadata["_cf_/one"] = getTestEpMetadata("one")
	expected_ep := getExpectedOpflexEp()
	expected_svc := getExpectedOpflexServiceForLegacyNet(env)

	// create
	env.cfAppContainerChanged(&id, ep)
	// check opflex-EP
	assert.Equal(t, expected_ep, env.agent.opflexEps["one"][0])
	// check iptables rules for legacy networking
	exists, _ = env.iptbl.Exists("nat", NAT_PRE_CHAIN,
		"-d 10.10.0.5 -p tcp --dport 60010 -j DNAT --to-destination 10.255.0.45:8080")
	assert.True(t, exists)
	exists, _ = env.iptbl.Exists("nat", NAT_PRE_CHAIN,
		"-d 10.10.0.5 -p tcp --dport 60011 -j DNAT --to-destination 10.255.0.45:2222")
	assert.True(t, exists)
	exists, _ = env.iptbl.Exists("nat", NAT_POST_CHAIN,
		"-o cf-net-legacy -p tcp -m tcp --dport 8080 -j SNAT --to-source 169.254.169.254")
	assert.True(t, exists)
	exists, _ = env.iptbl.Exists("nat", NAT_POST_CHAIN,
		"-o cf-net-legacy -p tcp -m tcp --dport 2222 -j SNAT --to-source 169.254.169.254")
	assert.True(t, exists)
	// check opflex service for legacy networking
	checkOpflexService(t, expected_svc, env.agent.opflexServices["cf-net-cell1"])

	// update
	ep.Epg = "epg2"
	ep.SecurityGroups = append(ep.SecurityGroups, etcd.GroupInfo{Tenant: "e", Group: "sg3"})
	ep.PortMapping = []etcd.PortMap{
		{ContainerPort: 8080, HostPort: 60010},
		{ContainerPort: 9443, HostPort: 60012}}
	expected_ep.EndpointGroup = "epg2"
	expected_ep.SecurityGroup = append(expected_ep.SecurityGroup,
		md.OpflexGroup{PolicySpace: "e", Name: "sg3"})
	expected_svc.ServiceMappings = append(expected_svc.ServiceMappings,
		opflexServiceMapping{
			ServiceIp:   "169.254.169.254",
			ServicePort: 9443,
			NextHopIps:  make([]string, 0)})
	env.cfAppContainerChanged(&id, ep)
	assert.Equal(t, expected_ep, env.agent.opflexEps["one"][0])
	exists, _ = env.iptbl.Exists("nat", NAT_PRE_CHAIN,
		"-d 10.10.0.5 -p tcp --dport 60010 -j DNAT --to-destination 10.255.0.45:8080")
	assert.True(t, exists)
	exists, _ = env.iptbl.Exists("nat", NAT_PRE_CHAIN,
		"-d 10.10.0.5 -p tcp --dport 60012 -j DNAT --to-destination 10.255.0.45:9443")
	assert.True(t, exists)
	exists, _ = env.iptbl.Exists("nat", NAT_POST_CHAIN,
		"-o cf-net-legacy -p tcp -m tcp --dport 8080 -j SNAT --to-source 169.254.169.254")
	assert.True(t, exists)
	exists, _ = env.iptbl.Exists("nat", NAT_POST_CHAIN,
		"-o cf-net-legacy -p tcp -m tcp --dport 9443 -j SNAT --to-source 169.254.169.254")
	assert.True(t, exists)
	exists, _ = env.iptbl.Exists("nat", NAT_PRE_CHAIN,
		"-d 10.10.0.5 -p tcp --dport 60011 -j DNAT --to-destination 10.255.0.45:2222")
	assert.False(t, exists)
	checkOpflexService(t, expected_svc, env.agent.opflexServices["cf-net-cell1"])

	// delete
	delete(env.epIdx, id)
	delete(env.agent.epMetadata, "_cf_/one")
	env.cfAppContainerDeleted(&id, ep)
	_, ok := env.agent.opflexEps["one"]
	assert.False(t, ok)
	exists, _ = env.iptbl.Exists("nat", NAT_PRE_CHAIN,
		"-d 10.10.0.5 -p tcp --dport 60010 -j DNAT --to-destination 10.255.0.45:8080")
	assert.False(t, exists)
	exists, _ = env.iptbl.Exists("nat", NAT_PRE_CHAIN,
		"-d 10.10.0.5 -p tcp --dport 60012 -j DNAT --to-destination 10.255.0.45:9443")
	assert.False(t, exists)
	checkOpflexService(t, expected_svc, env.agent.opflexServices["cf-net-cell1"])
}

func TestCfStagingContainerUpdate(t *testing.T) {
	env := testCfEnvironment(t)

	id := "one"
	ep := getTestEpInfo()
	ep.InstanceIndex = etcd.INST_IDX_STAGING
	env.epIdx[id] = ep
	env.agent.epMetadata["_cf_/one"] = getTestEpMetadata("one")
	expected_ep := getExpectedOpflexEp()
	expected_ep.Attributes["vm-name"] = "a1-name (staging)"

	// create
	env.cfAppContainerChanged(&id, ep)
	assert.Equal(t, expected_ep, env.agent.opflexEps["one"][0])

	// delete
	delete(env.epIdx, id)
	delete(env.agent.epMetadata, "_cf_/one")
	env.cfAppContainerDeleted(&id, ep)
	_, ok := env.agent.opflexEps["one"]
	assert.False(t, ok)
}

func TestCfTaskContainerUpdate(t *testing.T) {
	env := testCfEnvironment(t)

	id := "one"
	ep := getTestEpInfo()
	ep.InstanceIndex = etcd.INST_IDX_TASK
	ep.TaskName = "errand"
	env.epIdx[id] = ep
	env.agent.epMetadata["_cf_/one"] = getTestEpMetadata("one")
	expected_ep := getExpectedOpflexEp()
	expected_ep.Attributes["vm-name"] = "a1-name (task errand)"

	// create
	env.cfAppContainerChanged(&id, ep)
	assert.Equal(t, expected_ep, env.agent.opflexEps["one"][0])

	// delete
	delete(env.epIdx, id)
	delete(env.agent.epMetadata, "_cf_/one")
	env.cfAppContainerDeleted(&id, ep)
	_, ok := env.agent.opflexEps["one"]
	assert.False(t, ok)
}

func TestCfAppUpdate(t *testing.T) {
	env := testCfEnvironment(t)

	id := "a1"
	ep := getTestEpInfo()
	app := getTestAppInfo()
	env.epIdx["one"] = ep
	env.appIdx[id] = app

	exp_vip_svc := getExpectedOpflexServiceForApp(id, false, app.VirtualIp, app.ContainerIps)
	exp_ext_svc := getExpectedOpflexServiceForApp(id, true, app.ExternalIp, []string{"10.255.0.45"})

	// create
	env.cfAppChanged(&id, app)
	checkOpflexService(t, exp_vip_svc, env.agent.opflexServices[id])
	checkOpflexService(t, exp_ext_svc, env.agent.opflexServices[id+"-external"])

	// remove vip & ext-ip
	app.VirtualIp = nil
	app.ExternalIp = nil
	env.cfAppIdChanged(&id)
	_, vip_ok := env.agent.opflexServices[id]
	_, ext_ok := env.agent.opflexServices[id+"-external"]
	assert.False(t, vip_ok)
	assert.False(t, ext_ok)

	// update vip & ext-ip
	app.ContainerIps = []string{"10.255.0.10", "10.255.0.11", "10.255.0.46"}
	app.VirtualIp = []string{"10.254.0.6"}
	app.ExternalIp = []string{"150.150.0.3"}
	ep.IpAddress = "10.255.0.46"
	exp_vip_svc = getExpectedOpflexServiceForApp(id, false, app.VirtualIp, app.ContainerIps)
	exp_ext_svc = getExpectedOpflexServiceForApp(id, true, app.ExternalIp, []string{"10.255.0.46"})
	env.cfAppChanged(&id, app)
	checkOpflexService(t, exp_vip_svc, env.agent.opflexServices[id])
	checkOpflexService(t, exp_ext_svc, env.agent.opflexServices[id+"-external"])

	// delete app
	env.cfAppDeleted(&id, app)
	_, vip_ok = env.agent.opflexServices[id]
	_, ext_ok = env.agent.opflexServices[id+"-external"]
	assert.False(t, vip_ok)
	assert.False(t, ext_ok)
}
