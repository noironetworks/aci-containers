// Copyright 2019 Cisco Systems, Inc.
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
	rdconfig "github.com/noironetworks/aci-containers/pkg/rdconfig/apis/aci.snat/v1"
	tu "github.com/noironetworks/aci-containers/pkg/testutil"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"os"
	"testing"
	"time"
)

func rdConfigdata(usersubnets, discoveredsubnets []string) *rdconfig.RdConfig {
	rdcon := &rdconfig.RdConfig{
		Spec: rdconfig.RdConfigSpec{
			UserSubnets:       usersubnets,
			DiscoveredSubnets: discoveredsubnets,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "rdconfig",
		},
	}
	return rdcon
}

func (agent *testHostAgent) doTestRdConfig(t *testing.T, name string, internalsubnets []string, desc string) {
	var raw []byte
	rdcon := &opflexRdConfig{}

	tu.WaitFor(t, name, 1000*time.Millisecond,
		func(last bool) (bool, error) {
			var err error
			rdfile := agent.FormRdFilePath()
			raw, err = os.ReadFile(rdfile)
			agent.log.Info("rdfile added ", err)
			if err != nil {
				return false, nil
			}
			err = json.Unmarshal(raw, rdcon)
			agent.log.Info("rdfile added ", rdfile)
			return tu.WaitNil(t, last, err, desc, name, "unmarshal rdfile"), nil
		})
	assert.Equal(t, internalsubnets, rdcon.InternalSubnets, desc)
}

func TestRdConfig(t *testing.T) {
	tempdir, err := os.MkdirTemp("", "hostagent_test_")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tempdir)
	agent := testAgent()
	agent.config.OpFlexSnatDir = tempdir
	agent.config.OpFlexEndpointDir = tempdir
	agent.config.OpFlexServiceDir = tempdir
	agent.config.UplinkIface = "eth10"
	agent.config.NodeName = "test-node"
	agent.config.ServiceVlan = 4003
	agent.config.AciVrf = "vrf"
	agent.run()
	rdconfig := rdConfigdata([]string{"10.10.10.0/24"}, []string{"20.20.20.0/24"})
	os.WriteFile(agent.FormRdFilePath(), []byte("random gibberish"), 0644)
	agent.fakeRdConfigSource.Add(rdconfig)
	agent.doTestRdConfig(t, "rdconfig", []string{"10.10.10.0/24", "20.20.20.0/24"}, "create")
	agent.stop()
}
