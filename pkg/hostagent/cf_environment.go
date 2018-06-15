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
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"strings"
	"sync"
	"syscall"

	"github.com/Sirupsen/logrus"
	"github.com/coreos/go-iptables/iptables"
	"github.com/vishvananda/netlink"

	"github.com/noironetworks/aci-containers/pkg/cf_common"
	"github.com/noironetworks/aci-containers/pkg/ipam"
	rkv "github.com/noironetworks/aci-containers/pkg/keyvalueservice"
	md "github.com/noironetworks/aci-containers/pkg/metadata"
)

const (
	NAT_PRE_CHAIN  = "aci-nat-pre"
	NAT_POST_CHAIN = "aci-nat-post"
)

// wrapper over thirdparty implementation that can be overridden for unit-tests
type IPTables interface {
	Exists(table, chain string, rulespec ...string) (bool, error)
	List(table, chain string) ([]string, error)
	Append(table, chain string, rulespec ...string) error
	AppendUnique(table, chain string, rulespec ...string) error
	Delete(table, chain string, rulespec ...string) error
	NewChain(table, chain string) error
	ClearChain(table, chain string) error
}

type CfEnvironment struct {
	agent    *HostAgent
	cfconfig *CfConfig
	kvmgr    *rkv.KvManager

	indexLock sync.Locker
	epIdx     map[string]*cf_common.EpInfo
	appIdx    map[string]*cf_common.AppInfo

	iptbl     IPTables
	cfNetv4   bool
	cfNetLink netlink.Link

	appsSynced, cellSynced bool
	log                    *logrus.Logger
}

type CfConfig struct {
	CellID      string `json:"cell_id,omitempty"`
	CellAddress string `json:"cell_address,omitempty"`

	ControllerAddress string `json:"controller_address,omitempty"`

	ControllerCACertFile     string `json:"controller_ca_cert_file"`
	ControllerClientCertFile string `json:"controller_client_cert_file"`
	ControllerClientKeyFile  string `json:"controller_client_key_file"`

	CfNetOvsPort     string `json:"cf_net_ovs_port"`
	CfNetIntfAddress string `json:"cf_net_interface_address"`
}

func NewCfEnvironment(config *HostAgentConfig, log *logrus.Logger) (*CfEnvironment, error) {
	if config.CfConfig == "" {
		err := errors.New("Path to CloudFoundry config file is empty")
		log.Error(err.Error())
		return nil, err
	}

	cfconfig := &CfConfig{}
	log.Info("Loading CF configuration from ", config.CfConfig)
	raw, err := ioutil.ReadFile(config.CfConfig)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(raw, cfconfig)
	if err != nil {
		return nil, err
	}

	log.WithFields(logrus.Fields{
		"cfconfig": config.CfConfig,
		"cell-id":  cfconfig.CellID,
	}).Info("Setting up CloudFoundry environment")

	return &CfEnvironment{log: log, cfconfig: cfconfig,
		indexLock: &sync.Mutex{}}, nil
}

func (env *CfEnvironment) Init(agent *HostAgent) error {
	env.agent = agent
	env.epIdx = make(map[string]*cf_common.EpInfo)
	env.appIdx = make(map[string]*cf_common.AppInfo)
	if env.cfconfig.CfNetOvsPort != "" {
		env.agent.ignoreOvsPorts[env.agent.config.IntBridgeName] = []string{env.cfconfig.CfNetOvsPort}
	}
	cellIp := net.ParseIP(env.cfconfig.CellAddress)
	if cellIp == nil {
		err := fmt.Errorf("Invalid cell IP address")
		return err
	}
	env.cfNetv4 = cellIp.To4() != nil
	var err error
	if env.cfNetv4 {
		env.iptbl, err = iptables.NewWithProtocol(iptables.ProtocolIPv4)
	} else {
		env.iptbl, err = iptables.NewWithProtocol(iptables.ProtocolIPv6)
	}
	env.kvmgr = rkv.NewKvManager()
	env.agent.syncProcessors["iptables"] = env.syncLegacyCfNet
	return err
}

func (env *CfEnvironment) PrepareRun(stopCh <-chan struct{}) (
	syncEnabled bool, err error) {
	env.agent.log.Debug("Discovering node configuration")
	env.agent.updateOpflexConfig()
	go env.agent.runTickers(stopCh)

	err = env.setupInterfaceForLegacyCfNet()
	if err != nil {
		env.log.Error("Error setting up interface for legacy CF networking: ", err)
		return
	}

	go env.kvmgr.ServeWatch(stopCh)
	kv_client := NewCfKvClient(env)
	go kv_client.Watcher().Watch(stopCh)
	go kv_client.Run(stopCh)
	env.publishCniMetadata()

	if env.agent.podNetAnnotation == "" {
		env.log.Info("Cell network info node not found, using default pool")
		defIpPool := env.getDefaultIpPool()
		env.agent.updateIpamAnnotation(defIpPool)
	}
	return
}

func (env *CfEnvironment) CniDeviceChanged(metadataKey *string, id *md.ContainerId) {
	// TODO Find a better way to identify containers that we want to hide
	if strings.Contains(*metadataKey, "executor-healthcheck-") {
		return
	}
	env.updateContainerMetadata(metadataKey)

	ctId := id.Pod
	env.indexLock.Lock()
	ep := env.epIdx[ctId]
	env.indexLock.Unlock()

	if ep == nil {
		env.log.Debug("No EP info for container ", ctId)
		return
	}
	env.cfAppContainerChanged(&ctId, ep)
}

func (env *CfEnvironment) CniDeviceDeleted(metadataKey *string, id *md.ContainerId) {
	env.updateContainerMetadata(metadataKey)
	env.cfAppContainerDeleted(&id.Pod, nil)
}

func (env *CfEnvironment) publishCniMetadata() {
	env.agent.indexMutex.Lock()
	for _, md := range env.agent.epMetadata {
		for ctId, meta := range md {
			if meta != nil {
				env.kvmgr.Set("container", ctId, meta.Ifaces)
			}
		}
	}
	env.agent.indexMutex.Unlock()
}

func extractContainerIdFromMetadataKey(metadataKey *string) string {
	parts := strings.SplitN(*metadataKey, "/", 2)
	if len(parts) < 2 || parts[0] != "_cf_" {
		return ""
	}
	return parts[1]
}

func (env *CfEnvironment) CheckPodExists(metadataKey *string) (bool, error) {
	ctId := extractContainerIdFromMetadataKey(metadataKey)
	if ctId == "" {
		return false, nil
	}
	env.indexLock.Lock()
	defer env.indexLock.Unlock()
	ep := env.epIdx[ctId]
	return (ep != nil), nil
}

func (env *CfEnvironment) getDefaultIpPool() string {
	ipa4 := ipam.New()
	ipa6 := ipam.New()

	for _, nc := range env.agent.config.NetConfig {
		ip := nc.Subnet.IP.To4()
		num_ones, _ := nc.Subnet.Mask.Size()
		mask := net.CIDRMask(num_ones, 32)
		gw := nc.Gateway.To4()
		ipa := ipa4
		if ip == nil {
			ip = nc.Subnet.IP.To16()
			mask = net.CIDRMask(num_ones, 128)
			gw = nc.Gateway.To16()
			ipa = ipa6
			if ip == nil {
				continue
			}
		}
		last := make(net.IP, len(ip))
		for i := 0; i < len(ip); i++ {
			last[i] = ip[i] | ^mask[i]
		}
		// TODO add a random offset to start address
		ipa.AddRange(ip, last)
		// remove the start address and gateway address
		ipa.RemoveIp(ip)
		ipa.RemoveIp(gw)
	}

	netips := md.NetIps{V4: ipa4.FreeList, V6: ipa6.FreeList}
	raw, err := json.Marshal(&netips)
	if err != nil {
		env.log.Error("Could not create default ip-pool", err)
		return ""
	}
	env.log.Debug("Setting default IP pool to ", string(raw))
	return string(raw)
}

func (env *CfEnvironment) setupInterfaceForLegacyCfNet() error {
	// Assign ip to interface that receives legacy CF networking traffic
	intfIp := net.ParseIP(env.cfconfig.CfNetIntfAddress)
	if intfIp == nil || (env.cfNetv4 && intfIp.To4() == nil) {
		err := fmt.Errorf("CF legacy network interface IP is not a valid IP address")
		return err
	}
	link, err := netlink.LinkByName(env.cfconfig.CfNetOvsPort)
	if err != nil {
		return err
	}
	linkAddr := netlink.Addr{IPNet: netlink.NewIPNet(intfIp)}
	linkAddr.Scope = syscall.IFA_LOCAL
	fam := netlink.FAMILY_V4
	if !env.cfNetv4 {
		fam = netlink.FAMILY_V6
	}
	allAddr, err := netlink.AddrList(link, fam)
	if err != nil {
		return err
	}
	addrFound := false
	for _, a := range allAddr {
		if a.Equal(linkAddr) {
			addrFound = true
			break
		}
	}
	if !addrFound {
		if err := netlink.AddrAdd(link, &linkAddr); err != nil {
			return err
		}
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return err
	}

	// set routing rules to redirect traffic to the interface
	for _, n := range env.agent.config.NetConfig {
		dst := net.IPNet{IP: n.Subnet.IP, Mask: n.Subnet.Mask}
		route := netlink.Route{Dst: &dst, Gw: intfIp}
		if err := netlink.RouteReplace(&route); err != nil {
			return err
		}
	}
	env.cfNetLink = link
	return nil
}

func (env *CfEnvironment) syncLegacyCfNet() bool {
	if !env.agent.syncEnabled {
		return false
	}
	env.log.Debug("Syncing stuff for legacy CF networking ...")

	const TABLE = "nat"
	expRules := make(map[string]map[string]bool)
	expRules[NAT_PRE_CHAIN] = make(map[string]bool)
	expRules[NAT_POST_CHAIN] = make(map[string]bool)

	// build expected rules
	env.indexLock.Lock()
	contPorts := make(map[uint32]struct{})
	for _, ep := range env.epIdx {
		for i, _ := range ep.PortMapping {
			r := fmt.Sprintf(
				"-d %s/32 -p tcp -m tcp --dport %d -j DNAT "+
					"--to-destination %s:%d",
				env.cfconfig.CellAddress, ep.PortMapping[i].HostPort,
				ep.IpAddress, ep.PortMapping[i].ContainerPort)
			contPorts[ep.PortMapping[i].ContainerPort] = struct{}{}
			expRules[NAT_PRE_CHAIN][r] = false
		}
	}
	env.indexLock.Unlock()
	for cp, _ := range contPorts {
		r := fmt.Sprintf("-o %s -p tcp -m tcp --dport %d -j SNAT "+
			"--to-source %s",
			env.cfconfig.CfNetOvsPort, cp, env.cfconfig.CfNetIntfAddress)
		expRules[NAT_POST_CHAIN][r] = false
	}
	env.updateLegacyCfNetService(contPorts)

	// get current rules
	foundRules := make(map[string][]string)
	chains := map[string]string{
		NAT_PRE_CHAIN:  "PREROUTING",
		NAT_POST_CHAIN: "POSTROUTING"}
	for chain, parent := range chains {
		rules, err := env.iptbl.List(TABLE, chain)
		if err == nil {
			foundRules[chain] = rules
			continue
		}
		l := env.log.WithField("chain", chain)
		if ipte, eok := err.(*iptables.Error); !eok || ipte.ExitStatus() != 1 {
			l.Error("Failed to list nat ACI iptables rules: ", err)
			return true
		}
		// chain doesn't exist, setup it up
		l.Debug("Create nat ACI iptables chain")
		if e := env.iptbl.NewChain(TABLE, chain); e != nil {
			l.Error("Failed to create nat ACI iptables chain: ", e)
			return true
		}
		if e := env.iptbl.AppendUnique(TABLE, parent, "-j", chain); e != nil {
			l.Error("Failed to set jump rule for nat ACI iptables chain: ", e)
			return true
		}
	}

	retry := false
	for chain, rules := range foundRules {
		expChain, _ := expRules[chain]
		prefix := fmt.Sprintf("-A %s ", chain)
		for _, r := range rules {
			if !strings.HasPrefix(r, prefix) {
				continue
			}
			r = r[len(prefix):]
			if _, ok := expChain[r]; !ok {
				l := env.log.WithField("chain", chain).WithField("rule", r)
				l.Debug("Deleting nat ACI iptables rule")
				rspec := strings.Split(r, " ")
				if e := env.iptbl.Delete(TABLE, chain, rspec...); e != nil {
					l.Error("Delete iptables rule failed: ", e)
					retry = true
				}
			} else {
				expChain[r] = true
			}
		}
	}
	for chain, rules := range expRules {
		for r, found := range rules {
			if !found {
				l := env.log.WithField("chain", chain).WithField("rule", r)
				l.Debug("Appending nat ACI iptables rule")
				rspec := strings.Split(r, " ")
				if e := env.iptbl.Append(TABLE, chain, rspec...); e != nil {
					l.Error("Append iptables rule failed: ", e)
					retry = true
				}
			}
		}
	}
	env.log.Debug("Sync complete for legacy CF networking")
	return retry
}
