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
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/noironetworks/aci-containers/pkg/cf_common"
	md "github.com/noironetworks/aci-containers/pkg/metadata"
	tu "github.com/noironetworks/aci-containers/pkg/testutil"
)

func TestCfCniDeviceOps(t *testing.T) {
	env := testCfEnvironment(t)

	id := md.ContainerId{Namespace: "_cf_", Pod: "one", ContId: "one"}
	mdKey := "_cf_/one"
	ep := getTestEpInfo()
	env.epIdx["one"] = ep
	meta := getTestEpMetadata("one")
	env.agent.epMetadata[mdKey] = meta

	env.CniDeviceChanged(&mdKey, &id)

	assert.Equal(t, meta, env.GetKvContainerMetadata("one"))
	_, ok := env.agent.opflexEps["one"]
	assert.True(t, ok)

	delete(env.agent.epMetadata, mdKey)
	delete(env.epIdx, "one")
	env.CniDeviceDeleted(&mdKey, &id)

	assert.Nil(t, env.GetKvContainerMetadata("one"))
	_, ok = env.agent.opflexEps["one"]
	assert.False(t, ok)

}

func TestCfPublishCniMetadata(t *testing.T) {
	env := testCfEnvironment(t)

	md_one := getTestEpMetadata("one")
	md_two := getTestEpMetadata("two")
	md_three := getTestEpMetadata("three")

	env.agent.epMetadata["_cf_/one"] = md_one
	env.agent.epMetadata["_cf_/two"] = md_two
	env.agent.epMetadata["_cf_/three"] = md_three

	assert.Empty(t, env.GetKvContainerMetadata("one"))
	assert.Empty(t, env.GetKvContainerMetadata("two"))
	assert.Empty(t, env.GetKvContainerMetadata("three"))

	env.publishCniMetadata()
	assert.Equal(t, md_one, env.GetKvContainerMetadata("one"))
	assert.Equal(t, md_two, env.GetKvContainerMetadata("two"))
	assert.Equal(t, md_three, env.GetKvContainerMetadata("three"))
}

func TestCfSyncLegacyCfNet(t *testing.T) {
	env := testCfEnvironment(t)
	env.agent.syncEnabled = true
	delete(env.agent.syncProcessors, "services")
	expected_svc := getExpectedOpflexServiceForLegacyNet(env)
	expected_svc_mapping := expected_svc.ServiceMappings
	exp_pre_rules := []string{"-N " + NAT_PRE_CHAIN}
	exp_post_rules := []string{"-N " + NAT_POST_CHAIN}

	syncAndWait := func() {
		env.agent.ScheduleSync("iptables")
		tu.WaitFor(t, "syncQ drained", 500*time.Millisecond,
			func(last bool) (bool, error) {
				return env.agent.syncQueue.Len() == 0, nil
			})
	}
	go env.agent.processSyncQueue(env.agent.syncQueue, nil)

	// test - clean setup
	expected_svc.ServiceMappings = nil
	syncAndWait()
	rules, _ := env.iptbl.List("nat", NAT_PRE_CHAIN)
	assert.ElementsMatch(t, exp_pre_rules, rules)
	rules, _ = env.iptbl.List("nat", NAT_POST_CHAIN)
	assert.ElementsMatch(t, exp_post_rules, rules)
	exist, _ := env.iptbl.Exists("nat", "PREROUTING", "-j", NAT_PRE_CHAIN)
	assert.True(t, exist)
	exist, _ = env.iptbl.Exists("nat", "POSTROUTING", "-j", NAT_POST_CHAIN)
	assert.True(t, exist)
	checkOpflexService(t, expected_svc,
		env.agent.opflexServices["cf-net-cell1"])

	// test - add an EP
	ep := getTestEpInfo()
	env.epIdx["one"] = ep
	expected_svc.ServiceMappings = expected_svc_mapping
	exp_pre_rules = append(exp_pre_rules,
		"-A "+NAT_PRE_CHAIN+" -d 10.10.0.5/32 -p tcp -m tcp --dport "+
			"60010 -j DNAT --to-destination 10.255.0.45:8080",
		"-A "+NAT_PRE_CHAIN+" -d 10.10.0.5/32 -p tcp -m tcp --dport "+
			"60011 -j DNAT --to-destination 10.255.0.45:2222")
	exp_post_rules = append(exp_post_rules,
		"-A "+NAT_POST_CHAIN+" -o cf-net-legacy -p tcp -m tcp --dport "+
			"8080 -j SNAT --to-source 169.254.169.254",
		"-A "+NAT_POST_CHAIN+" -o cf-net-legacy -p tcp -m tcp --dport "+
			"2222 -j SNAT --to-source 169.254.169.254")
	syncAndWait()
	rules, _ = env.iptbl.List("nat", NAT_PRE_CHAIN)
	assert.ElementsMatch(t, exp_pre_rules, rules)
	rules, _ = env.iptbl.List("nat", NAT_POST_CHAIN)
	assert.ElementsMatch(t, exp_post_rules, rules)
	checkOpflexService(t, expected_svc,
		env.agent.opflexServices["cf-net-cell1"])

	// test - update EP portmapping
	ep.PortMapping = []cf_common.PortMap{
		{ContainerPort: 8080, HostPort: 60010},
		{ContainerPort: 9443, HostPort: 60012}}
	expected_svc.ServiceMappings[1] = opflexServiceMapping{
		ServiceIp:   "169.254.169.254",
		ServicePort: 9443,
		NextHopIps:  make([]string, 0)}
	exp_pre_rules[2] = "-A " + NAT_PRE_CHAIN + " -d 10.10.0.5/32 -p tcp " +
		"-m tcp --dport 60012 -j DNAT --to-destination 10.255.0.45:9443"
	exp_post_rules[2] = "-A " + NAT_POST_CHAIN + " -o cf-net-legacy -p tcp " +
		"-m tcp --dport 9443 -j SNAT --to-source 169.254.169.254"
	syncAndWait()
	rules, _ = env.iptbl.List("nat", NAT_PRE_CHAIN)
	assert.ElementsMatch(t, exp_pre_rules, rules)
	rules, _ = env.iptbl.List("nat", NAT_POST_CHAIN)
	assert.ElementsMatch(t, exp_post_rules, rules)
	checkOpflexService(t, expected_svc,
		env.agent.opflexServices["cf-net-cell1"])

	// test - delete EP
	delete(env.epIdx, "one")
	exp_pre_rules = exp_pre_rules[:1]
	exp_post_rules = exp_post_rules[:1]
	expected_svc.ServiceMappings = nil
	syncAndWait()
	rules, _ = env.iptbl.List("nat", NAT_PRE_CHAIN)
	assert.ElementsMatch(t, exp_pre_rules, rules)
	rules, _ = env.iptbl.List("nat", NAT_POST_CHAIN)
	assert.ElementsMatch(t, exp_post_rules, rules)
	checkOpflexService(t, expected_svc,
		env.agent.opflexServices["cf-net-cell1"])
}
