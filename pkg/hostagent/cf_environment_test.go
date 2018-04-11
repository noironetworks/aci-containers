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

	md "github.com/noironetworks/aci-containers/pkg/metadata"
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

	assert.Equal(t, meta, env.GetContainerMetadata("one"))
	assert.Equal(t, meta, env.GetKvContainerMetadata("one"))
	_, ok := env.agent.opflexEps["one"]
	assert.True(t, ok)

	delete(env.agent.epMetadata, mdKey)
	delete(env.epIdx, "one")
	env.CniDeviceDeleted(&mdKey, &id)

	assert.Nil(t, env.GetContainerMetadata("one"))
	assert.Nil(t, env.GetKvContainerMetadata("one"))
	_, ok = env.agent.opflexEps["one"]
	assert.False(t, ok)

}

func TestCfSetupIpTables(t *testing.T) {
	env := testCfEnvironment(t)
	env.iptbl.AppendUnique("nat", NAT_PRE_CHAIN, "foo bar")
	env.iptbl.AppendUnique("nat", NAT_PRE_CHAIN, "foo1 bar1")
	env.iptbl.AppendUnique("nat", NAT_POST_CHAIN, "foo2 bar2")
	env.iptbl.AppendUnique("nat", NAT_POST_CHAIN, "foo3 bar2")

	env.setupIpTablesForLegacyCfNet()
	exist := false

	exist, _ = env.iptbl.Exists("nat", "PREROUTING", "-j", NAT_PRE_CHAIN)
	assert.True(t, exist)
	exist, _ = env.iptbl.Exists("nat", "POSTROUTING", "-j", NAT_POST_CHAIN)
	assert.True(t, exist)
	exist, _ = env.iptbl.Exists("nat", NAT_PRE_CHAIN, "foo bar")
	assert.False(t, exist)
	exist, _ = env.iptbl.Exists("nat", NAT_PRE_CHAIN, "foo1 bar1")
	assert.False(t, exist)
	exist, _ = env.iptbl.Exists("nat", NAT_POST_CHAIN, "foo2 bar2")
	assert.False(t, exist)
	exist, _ = env.iptbl.Exists("nat", NAT_POST_CHAIN, "foo3 bar3")
	assert.False(t, exist)
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

