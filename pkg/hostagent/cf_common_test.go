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
	"net"
	"os/exec"
	"strings"
	"sync"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/coreos/go-iptables/iptables"
	"github.com/stretchr/testify/assert"
	"github.com/vishvananda/netlink"

	"github.com/noironetworks/aci-containers/pkg/cf_common"
	rkv "github.com/noironetworks/aci-containers/pkg/keyvalueservice"
	md "github.com/noironetworks/aci-containers/pkg/metadata"
)

var exitErr1 *exec.ExitError

func init() {
	c := exec.Command("sh", "-c", "exit 1")
	e := c.Run()
	switch e := e.(type) {
	case *exec.ExitError:
		exitErr1 = e
	}
}

func testCfEnvironment(t *testing.T) *CfEnvironment {
	env := CfEnvironment{indexLock: &sync.Mutex{}}
	env.epIdx = make(map[string]*cf_common.EpInfo)
	env.appIdx = make(map[string]*cf_common.AppInfo)
	log := logrus.New()
	log.Level = logrus.DebugLevel
	log.Formatter = &logrus.TextFormatter{
		DisableColors: true,
	}
	node := "cell1"
	agent := NewHostAgent(
		&HostAgentConfig{
			HostAgentNodeConfig: HostAgentNodeConfig{UplinkIface: "eth1"},
			AciVrfTenant:        "common",
			AciVrf:              "cf",
			ServiceVlan:         4001},
		&env,
		log)
	agent.serviceEp.Mac = "de:ad:be:ef:00:00"
	agent.serviceEp.Ipv4 = net.ParseIP("10.150.0.2")
	env.agent = agent
	env.log = log

	env.cfconfig = &CfConfig{CellID: node, CellAddress: "10.10.0.5",
		CfNetOvsPort: "cf-net-legacy", CfNetIntfAddress: "169.254.169.254"}
	env.iptbl = newFakeIpTables()
	env.cfNetLink = &fakeNetlinkLink{fakeMac: "cc:ff:00:55:ee:dd"}
	env.kvmgr = rkv.NewKvManager()
	env.agent.syncProcessors["iptables"] = env.syncLegacyCfNet
	return &env
}

func (e *CfEnvironment) GetKvContainerMetadata(ctId string) map[string]*md.ContainerMetadata {
	if v, err := e.kvmgr.Get("container", ctId); err == nil {
		ifs := v.Value.([]*md.ContainerIfaceMd)
		return map[string]*md.ContainerMetadata{ctId: {
			Id:     md.ContainerId{Namespace: "_cf_", Pod: ctId, ContId: ctId},
			Ifaces: ifs}}
	}
	return nil
}

type fakeIpTables struct {
	rules  map[string]struct{}
	chains map[string]map[string]struct{}
}

func newFakeIpTables() *fakeIpTables {
	t := &fakeIpTables{
		rules:  make(map[string]struct{}),
		chains: make(map[string]map[string]struct{})}
	t.chains["nat"] = map[string]struct{}{
		"PREROUTING":  {},
		"POSTROUTING": {}}
	return t
}

func (ipt *fakeIpTables) key(table, chain string, rulespec ...string) string {
	return table + "|" + chain + "|" + strings.Join(rulespec, " ")
}

func (ipt *fakeIpTables) chainExists(table, chain string) error {
	if c, ok := ipt.chains[table]; ok {
		if _, ok := c[chain]; ok {
			return nil
		}
	}
	return &iptables.Error{ExitError: *exitErr1}
}

func (ipt *fakeIpTables) List(table, chain string) ([]string, error) {
	if err := ipt.chainExists(table, chain); err != nil {
		return nil, err
	}
	out := []string{"-N " + chain}
	for k := range ipt.rules {
		if strings.HasPrefix(k, table+"|"+chain+"|") {
			r := "-A " + chain + " " + k[len(table)+len(chain)+2:]
			out = append(out, r)
		}
	}
	return out, nil
}

func (ipt *fakeIpTables) Append(table, chain string, spec ...string) error {
	if err := ipt.chainExists(table, chain); err != nil {
		return err
	}
	k := ipt.key(table, chain, spec...)
	if _, ok := ipt.rules[k]; ok {
		return &iptables.Error{ExitError: *exitErr1}
	}
	ipt.rules[k] = struct{}{}
	return nil
}

func (ipt *fakeIpTables) Exists(table, chain string, rulespec ...string) (bool, error) {
	if err := ipt.chainExists(table, chain); err != nil {
		return false, err
	}
	_, ok := ipt.rules[ipt.key(table, chain, rulespec...)]
	return ok, nil
}

func (ipt *fakeIpTables) AppendUnique(table, chain string, rulespec ...string) error {
	if err := ipt.chainExists(table, chain); err != nil {
		return err
	}
	k := ipt.key(table, chain, rulespec...)
	_, ok := ipt.rules[k]
	if !ok {
		ipt.rules[k] = struct{}{}
	}
	return nil
}

func (ipt *fakeIpTables) Delete(table, chain string, rulespec ...string) error {
	if err := ipt.chainExists(table, chain); err != nil {
		return err
	}
	delete(ipt.rules, ipt.key(table, chain, rulespec...))
	return nil
}

func (ipt *fakeIpTables) NewChain(table, chain string) error {
	if err := ipt.chainExists(table, chain); err == nil {
		return &iptables.Error{ExitError: *exitErr1}
	}
	ipt.chains[table][chain] = struct{}{}
	return nil
}

func (ipt *fakeIpTables) ClearChain(table, chain string) error {
	ipt.chains[table][chain] = struct{}{}
	for k := range ipt.rules {
		if strings.HasPrefix(k, table+"|"+chain+"|") {
			delete(ipt.rules, k)
		}
	}
	return nil
}

type fakeNetlinkLink struct {
	fakeMac string
}

func (l *fakeNetlinkLink) Attrs() *netlink.LinkAttrs {
	a := netlink.NewLinkAttrs()
	a.HardwareAddr, _ = net.ParseMAC(l.fakeMac)
	return &a
}

func (l *fakeNetlinkLink) Type() string {
	return "fake"
}

func getTestEpInfo() *cf_common.EpInfo {
	ep := &cf_common.EpInfo{
		AppId:         "a1",
		AppName:       "a1-name",
		SpaceId:       "sp1",
		OrgId:         "org1",
		IpAddress:     "10.255.0.45",
		InstanceIndex: 1,
		PortMapping: []cf_common.PortMap{
			{ContainerPort: 8080, HostPort: 60010},
			{ContainerPort: 2222, HostPort: 60011}},
		EpgTenant: "cf",
		Epg:       "epg1",
		SecurityGroups: []cf_common.GroupInfo{
			{Tenant: "c", Group: "sg1"},
			{Tenant: "d", Group: "sg2"}},
	}
	return ep
}

func getTestEpMetadata(ctId string) map[string]*md.ContainerMetadata {
	meta := make(map[string]*md.ContainerMetadata)
	meta[ctId] = &md.ContainerMetadata{
		Id: md.ContainerId{Namespace: "_cf_", Pod: ctId, ContId: ctId},
		Ifaces: []*md.ContainerIfaceMd{
			{
				HostVethName: "veth1",
				Mac:          "1:2:3:4:5:6",
				IPs: []md.ContainerIfaceIP{
					{
						Address: net.IPNet{
							IP: net.ParseIP("10.255.0.45")}}}}}}
	return meta
}

func getExpectedOpflexEp() *opflexEndpoint {
	expected_ep := &opflexEndpoint{
		Uuid:              "one_one_veth1",
		MacAddress:        "1:2:3:4:5:6",
		IpAddress:         []string{"10.255.0.45"},
		AccessIface:       "veth1",
		AccessUplinkIface: "pa-veth1",
		IfaceName:         "pi-veth1",
		SecurityGroup: []md.OpflexGroup{
			{PolicySpace: "c", Name: "sg1"},
			{PolicySpace: "d", Name: "sg2"}},
		EgPolicySpace: "cf",
		EndpointGroup: "epg1",
	}
	attrs := make(map[string]string)
	attrs["app-id"] = "a1"
	attrs["container-id"] = "one"
	attrs["interface-name"] = "veth1"
	attrs["org-id"] = "org1"
	attrs["space-id"] = "sp1"
	attrs["vm-name"] = "a1-name (1)"
	expected_ep.Attributes = attrs
	return expected_ep
}

func getExpectedOpflexServiceForLegacyNet(env *CfEnvironment) *opflexService {
	expected_svc := &opflexService{
		Uuid:              "cf-net-cell1",
		DomainPolicySpace: "common",
		DomainName:        "cf",
		ServiceMac:        env.cfNetLink.(*fakeNetlinkLink).fakeMac,
		InterfaceName:     "cf-net-legacy"}
	svc_map1 := opflexServiceMapping{
		ServiceIp:   "169.254.169.254",
		ServicePort: 8080,
		NextHopIps:  make([]string, 0)}
	svc_map2 := opflexServiceMapping{
		ServiceIp:   "169.254.169.254",
		ServicePort: 2222,
		NextHopIps:  make([]string, 0)}
	expected_svc.ServiceMappings = []opflexServiceMapping{svc_map1, svc_map2}
	return expected_svc
}

func checkOpflexService(t *testing.T, exp, actual *opflexService) {
	exp_map := exp.ServiceMappings
	exp.ServiceMappings = nil
	actual_map := actual.ServiceMappings
	actual.ServiceMappings = nil

	assert.Equal(t, exp, actual)
	assert.Equal(t, len(exp_map), len(actual_map))
	for _, em := range exp_map {
		assert.Contains(t, actual_map, em)
	}

	exp.ServiceMappings = exp_map
	actual.ServiceMappings = actual_map
}

func getTestAppInfo() *cf_common.AppInfo {
	app := &cf_common.AppInfo{
		ContainerIps: []string{"10.255.0.10", "10.255.0.45"},
		VirtualIp:    []string{"10.254.0.5"},
		ExternalIp:   []string{"150.150.0.3"},
	}
	return app
}

func getExpectedOpflexServiceForApp(appId string, external bool, vips, ips []string) *opflexService {
	uuid := appId
	if external {
		uuid += "-external"
	}
	expected_svc := &opflexService{
		Uuid:              uuid,
		DomainPolicySpace: "common",
		DomainName:        "cf",
		ServiceMode:       "loadbalancer",
		ServiceMappings:   make([]opflexServiceMapping, 0),
	}
	if external {
		expected_svc.InterfaceName = "eth1"
		expected_svc.InterfaceVlan = 4001
		expected_svc.ServiceMac = "de:ad:be:ef:00:00"
		expected_svc.InterfaceIp = "10.150.0.2"
	}
	for _, vip := range vips {
		sm := opflexServiceMapping{
			ServiceIp:  vip,
			NextHopIps: ips,
			Conntrack:  true,
		}
		expected_svc.ServiceMappings = append(expected_svc.ServiceMappings, sm)
	}
	return expected_svc
}
