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
	"fmt"
	"errors"
	"io/ioutil"
	"net"
	"strings"
	"sync"
	"syscall"

	etcdclient "github.com/coreos/etcd/client"
	"github.com/coreos/go-iptables/iptables"
	"github.com/Sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"k8s.io/client-go/tools/cache"

	etcd "github.com/noironetworks/aci-containers/pkg/cf_etcd"
	"github.com/noironetworks/aci-containers/pkg/ipam"
	md "github.com/noironetworks/aci-containers/pkg/metadata"
)

const (
	NAT_PRE_CHAIN = "aci-nat-pre"
	NAT_POST_CHAIN = "aci-nat-post"
)

// wrapper over thirdparty implementation that can be overridden for unit-tests
type IPTables interface {
	Exists(table, chain string, rulespec ...string) (bool, error)
	AppendUnique(table, chain string, rulespec ...string) error
	Delete(table, chain string, rulespec ...string) error
	ClearChain(table, chain string) error
}

type CfEnvironment struct {
	agent        *HostAgent
	cfconfig     *CfConfig
	etcdKeysApi  etcdclient.KeysAPI

	indexLock    sync.Locker
	epIdx        map[string]*etcd.EpInfo
	appIdx       map[string]*etcd.AppInfo

	iptbl        IPTables
	ctPortMap    map[string]map[uint32]uint32
	cfNetv4      bool
	cfNetLink    netlink.Link
	cfNetContainerPorts    map[uint32]struct{}

	log          *logrus.Logger
}

type CfConfig struct {
	CellID                             string                `json:"cell_id,omitempty"`
	CellAddress                        string                `json:"cell_address,omitempty"`

	EtcdUrl                            string                `json:"etcd_url,omitempty"`
	EtcdCACertFile                     string                `json:"etcd_ca_cert_file"`
	EtcdClientCertFile                 string                `json:"etcd_client_cert_file"`
	EtcdClientKeyFile                  string                `json:"etcd_client_key_file"`

	CfNetOvsPort                       string                `json:"cf_net_ovs_port"`
	CfNetIntfAddress                   string                `json:"cf_net_interface_address"`
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
		"cfconfig":  config.CfConfig,
		"cell-id":   cfconfig.CellID,
	}).Info("Setting up CloudFoundry environment")

	etcdClient, err := etcd.NewEtcdClient(cfconfig.EtcdUrl, cfconfig.EtcdCACertFile,
		cfconfig.EtcdClientCertFile, cfconfig.EtcdClientKeyFile)
	if err != nil {
		log.Error("Failed to create Etcd client: ", err)
		return nil, err
	}
	etcdKeysApi := etcdclient.NewKeysAPI(etcdClient)

	return &CfEnvironment{etcdKeysApi: etcdKeysApi, log: log,
		cfconfig: cfconfig, indexLock: &sync.Mutex{}}, nil
}

func (env *CfEnvironment) Init(agent *HostAgent) error {
	env.agent = agent
	env.epIdx = make(map[string]*etcd.EpInfo)
	env.appIdx = make(map[string]*etcd.AppInfo)
	env.ctPortMap = make(map[string]map[uint32]uint32)
	env.cfNetContainerPorts = make(map[uint32]struct{})
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
	return err
}

func (env *CfEnvironment) PrepareRun(stopCh <-chan struct{}) error {
	err := env.setupInterfaceForLegacyCfNet()
	if err != nil {
		env.log.Error("Error setting up interface for legacy CF networking: ", err)
		return err
	}
	err = env.setupIpTablesForLegacyCfNet()
	if err != nil {
		env.log.Error("Error setting up IPTables for legacy CF networking: ", err)
		return err
	}
	etcd_cell_w := NewCfEtcdCellWatcher(env)
	etcd_app_w := NewCfEtcdAppWatcher(env)
	go etcd_cell_w.Run(stopCh)
	go etcd_app_w.Run(stopCh)
	cache.WaitForCacheSync(stopCh, etcd_cell_w.Synced, etcd_app_w.Synced)

	if env.agent.podNetAnnotation == "" {
		env.log.Info("Cell network info node not found in etcd, using default pool")
		defIpPool := env.getDefaultIpPool()
		env.agent.updateIpamAnnotation(defIpPool)
	}
	return nil
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

func (env *CfEnvironment) getDefaultIpPool() (string) {
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

func (env *CfEnvironment) setupIpTablesForLegacyCfNet() error {
	// clear or create our iptables rule chains
	if err := env.iptbl.ClearChain("nat", NAT_PRE_CHAIN); err != nil {
		return err
	}
	if err := env.iptbl.ClearChain("nat", NAT_POST_CHAIN); err != nil {
		return err
	}
	// Link our chains from the pre/post-routing chains
	if err := env.iptbl.AppendUnique("nat", "PREROUTING", "-j", NAT_PRE_CHAIN); err != nil {
		return err
	}
	if err := env.iptbl.AppendUnique("nat", "POSTROUTING", "-j", NAT_POST_CHAIN); err != nil {
		return err
	}

	return nil
}
