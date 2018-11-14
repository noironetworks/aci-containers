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
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"

	"os"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"code.cloudfoundry.org/bbs"
	"code.cloudfoundry.org/clock"
	"code.cloudfoundry.org/lager"
	"code.cloudfoundry.org/locket"
	"code.cloudfoundry.org/locket/lock"
	locketmodels "code.cloudfoundry.org/locket/models"

	"github.com/Sirupsen/logrus"
	cfclient "github.com/cloudfoundry-community/go-cfclient"
	"golang.org/x/net/context"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"github.com/noironetworks/aci-containers/pkg/apicapi"
	"github.com/noironetworks/aci-containers/pkg/cfapi"
	"github.com/noironetworks/aci-containers/pkg/ipam"
	rkv "github.com/noironetworks/aci-containers/pkg/keyvalueservice"
	"github.com/noironetworks/aci-containers/pkg/metadata"
)

type CfEnvironment struct {
	cont     *AciController
	cfconfig *CfConfig

	bbsClient    bbs.Client
	ccClient     cfapi.CcClient
	netpolClient cfapi.PolicyClient
	cfAuthClient cfapi.CfAuthClient
	cfLogger     lager.Logger
	db           *sql.DB
	locketClient locketmodels.LocketClient
	kvmgr        *rkv.KvManager

	indexLock sync.Locker
	contIdx   map[string]*ContainerInfo
	appIdx    map[string]*AppInfo
	spaceIdx  map[string]*SpaceInfo
	orgIdx    map[string]*OrgInfo
	asgIdx    map[string]*cfclient.SecGroup
	netpolIdx map[string]map[string][]cfapi.Destination
	isoSegIdx map[string]*IsoSegInfo

	spaceFetchQ      workqueue.RateLimitingInterface
	spaceChangesQ    workqueue.RateLimitingInterface
	appUpdateQ       workqueue.RateLimitingInterface
	appDeleteQ       workqueue.RateLimitingInterface
	containerUpdateQ workqueue.RateLimitingInterface
	containerDeleteQ workqueue.RateLimitingInterface
	orgChangesQ      workqueue.RateLimitingInterface
	asgUpdateQ       workqueue.RateLimitingInterface
	asgDeleteQ       workqueue.RateLimitingInterface

	appVips *netIps

	goRouterIps  []string
	tcpRouterIps []string

	log *logrus.Logger
}

type CfConfig struct {
	VmmPolicy                 string `json:"vmm_policy"`
	BBSAddress                string `json:"bbs_address"`
	BBSCACertFile             string `json:"bbs_ca_cert_file"`
	BBSClientCertFile         string `json:"bbs_client_cert_file"`
	BBSClientKeyFile          string `json:"bbs_client_key_file"`
	BBSClientSessionCacheSize int    `json:"bbs_client_session_cache_size,omitempty"`
	BBSMaxIdleConnsPerHost    int    `json:"bbs_max_idle_conns_per_host,omitempty"`

	CCApiUrl      string `json:"cc_api_url,omitempty"`
	CCApiUsername string `json:"cc_api_username,omitempty"`
	CCApiPassword string `json:"cc_api_password,omitempty"`

	UaaUrl          string `json:"uaa_url,omitempty"`
	UaaCACertFile   string `json:"uaa_ca_cert_file"`
	UaaClientName   string `json:"uaa_client_name"`
	UaaClientSecret string `json:"uaa_client_secret"`

	NetPolApiUrl          string `json:"network_policy_api_url"`
	NetPolCACertFile      string `json:"network_policy_ca_cert_file"`
	NetPolClientCertFile  string `json:"network_policy_client_cert_file"`
	NetPolClientKeyFile   string `json:"network_policy_client_key_file"`
	NetPolPollingInterval int    `json:"network_policy_polling_interval_sec"`

	DbType string `json:"db_type"`
	DbDsn  string `json:"db_dsn"`

	LocketAddress        string `json:"locket_address"`
	LocketCACertFile     string `json:"locket_ca_cert_file"`
	LocketClientCertFile string `json:"locket_client_cert_file"`
	LocketClientKeyFile  string `json:"locket_client_key_file"`

	KeyValuePort uint32 `json:"key_value_port"`

	ControllerCACertFile     string `json:"controller_ca_cert_file"`
	ControllerServerCertFile string `json:"controller_server_cert_file"`
	ControllerServerKeyFile  string `json:"controller_server_key_file"`

	Uuid          string `json:"uuid"`
	ApiPathPrefix string `json:"api_path_prefix"`

	GoRouterAddress  string
	TcpRouterAddress string
	AppPort          uint32 `json:"app_port"`
	SshPort          uint32 `json:"ssh_port"`

	DefaultAppProfile string `json:"default_app_profile"`

	// Virtual IP address pool for apps
	AppVipPool   []ipam.IpRange `json:"app_vip_pool,omitempty"`
	AppVipSubnet []string       `json:"app_vip_subnet,omitempty"`

	// Source address used on cells for legacy CF networking
	CfNetIntfAddress string `json:"cf_net_interface_address"`

	CleanupPollingInterval int `json:"cleanup_polling_interval_sec"`
}

func NewCfEnvironment(config *ControllerConfig, log *logrus.Logger) (*CfEnvironment, error) {
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
	cfconfig.GoRouterAddress = "gorouter.service.cf.internal"
	cfconfig.TcpRouterAddress = "tcp-router.service.cf.internal"
	if cfconfig.VmmPolicy == "" {
		cfconfig.VmmPolicy = "CloudFoundry"
	}
	if cfconfig.AppPort == 0 {
		cfconfig.AppPort = 8080
	}
	if cfconfig.SshPort == 0 {
		cfconfig.SshPort = 2222
	}
	if cfconfig.NetPolPollingInterval <= 0 {
		cfconfig.NetPolPollingInterval = 1
	}
	if cfconfig.ApiPathPrefix == "" {
		cfconfig.ApiPathPrefix = "/networking-aci"
	}
	if cfconfig.CleanupPollingInterval <= 0 {
		cfconfig.CleanupPollingInterval = 10
	}

	return &CfEnvironment{cfconfig: cfconfig, indexLock: &sync.Mutex{}, appVips: newNetIps(), log: log},
		nil
}

func (env *CfEnvironment) VmmPolicy() string {
	return env.cfconfig.VmmPolicy
}

func (env *CfEnvironment) OpFlexDeviceType() string {
	return "cf"
}

func (env *CfEnvironment) ServiceBd() string {
	return "app-ext-ip"
}

func (env *CfEnvironment) Init(cont *AciController) error {
	env.cont = cont

	env.cfLogger = lager.NewLogger("CfEnv")
	lagerLevel := lager.INFO
	switch env.log.Level {
	case logrus.DebugLevel:
		lagerLevel = lager.INFO // Some CF clients can be very chatty
	case logrus.InfoLevel:
		lagerLevel = lager.INFO
	case logrus.WarnLevel:
		lagerLevel = lager.INFO
	case logrus.ErrorLevel:
		lagerLevel = lager.ERROR
	case logrus.FatalLevel:
		lagerLevel = lager.FATAL
	case logrus.PanicLevel:
		lagerLevel = lager.FATAL
	default:
	}
	env.cfLogger.RegisterSink(lager.NewWriterSink(env.log.Out, lagerLevel))

	env.initIndexes()
	cont.loadIpRanges(env.appVips.V4, env.appVips.V6, env.cfconfig.AppVipPool)

	var err error
	env.db, err = sql.Open(env.cfconfig.DbType, env.cfconfig.DbDsn)
	if err != nil {
		env.log.Error("Unable to open SQL DB: ", err)
		return err
	}

	env.log.WithFields(logrus.Fields{
		"cfconfig": cont.config.CfConfig,
	}).Info("Setting up CloudFoundry environment")

	env.bbsClient, err = bbs.NewClient(
		env.cfconfig.BBSAddress,
		env.cfconfig.BBSCACertFile,
		env.cfconfig.BBSClientCertFile,
		env.cfconfig.BBSClientKeyFile,
		env.cfconfig.BBSClientSessionCacheSize,
		env.cfconfig.BBSMaxIdleConnsPerHost,
	)
	if err != nil {
		env.log.Error("Failed to configure secure BBS client: ", err)
		return err
	}

	env.kvmgr = rkv.NewKvManager()

	env.netpolClient, err = cfapi.NewNetPolClient(env.cfconfig.NetPolApiUrl,
		env.cfconfig.NetPolCACertFile,
		env.cfconfig.NetPolClientCertFile,
		env.cfconfig.NetPolClientKeyFile)
	if err != nil {
		env.log.Error("Failed to create network policy client: ", err)
		return err
	}

	env.cfAuthClient, err = cfapi.NewCfAuthClient(env.cfconfig.UaaUrl, env.cfconfig.UaaCACertFile,
		env.cfconfig.UaaClientName, env.cfconfig.UaaClientSecret)
	if err != nil {
		env.log.Error("Failed to create UAA client: ", err)
		return err
	}

	return nil
}

func (env *CfEnvironment) initIndexes() {
	env.contIdx = make(map[string]*ContainerInfo)
	env.appIdx = make(map[string]*AppInfo)
	env.spaceIdx = make(map[string]*SpaceInfo)
	env.orgIdx = make(map[string]*OrgInfo)
	env.asgIdx = make(map[string]*cfclient.SecGroup)
	env.netpolIdx = make(map[string]map[string][]cfapi.Destination)
	env.isoSegIdx = make(map[string]*IsoSegInfo)

	env.spaceFetchQ = createQueue("fetch-space")
	env.spaceChangesQ = createQueue("delete-space")
	env.appUpdateQ = createQueue("update-app")
	env.appDeleteQ = createQueue("delete-app")
	env.containerUpdateQ = createQueue("update-container")
	env.containerDeleteQ = createQueue("delete-container")
	env.orgChangesQ = createQueue("delete-org")
	env.asgUpdateQ = createQueue("update-asg")
	env.asgDeleteQ = createQueue("delete-asg")
}

func (env *CfEnvironment) PrepareRun(stopCh <-chan struct{}) error {
	var err error

	err = env.waitToBecomeMaster(stopCh,
		0,
		func() {
			env.log.Error("No longer controller master, exiting ...")
			os.Exit(1)
		})
	if err != nil {
		env.log.Error("Error while waiting to become controller master: ", err)
		return err
	}

	// test DB connectivity
	if err = env.db.Ping(); err != nil {
		env.log.Error("Unable to connect to SQL DB: ", err)
		return err
	}
	if err = env.RunDbMigration(); err != nil {
		env.log.Error("Failed to run DB migration: ", err)
		return err
	}

	epg_anno_handler := EpgAnnotationHttpHandler{env: env}
	app_vip_handler := AppVipHttpHandler{env: env}
	app_ext_ip_handler := AppExtIpHttpHandler{env: env}
	http.Handle(epg_anno_handler.Path(), &epg_anno_handler)
	http.Handle(app_vip_handler.Path(), &app_vip_handler)
	http.Handle(app_ext_ip_handler.Path(), &app_ext_ip_handler)

	maxattempts := 240 // TODO move the connect loop to app-index builder
	for env.ccClient == nil && maxattempts > 0 {
		maxattempts--
		ccClient, err := cfapi.NewCcClient(env.cfconfig.CCApiUrl, env.cfconfig.CCApiUsername,
			env.cfconfig.CCApiPassword)
		if err != nil {
			env.log.Error("Failed to create CC API client: ", err)
			time.Sleep(5 * time.Second)
			continue
		}
		env.log.Debug("CC API client created")
		env.ccClient = ccClient
	}
	if env.ccClient == nil {
		env.log.Error("Couldn't create CC API client, aborting: ", err)
		return err
	}

	env.LoadAppExtIps()
	env.LoadAppVips()
	env.LoadEpgAnnotations()

	go env.kvmgr.ServeWatch(stopCh)
	kvserver := NewCfKvServer(env)
	go kvserver.Watcher().Watch(stopCh)
	go kvserver.Run(stopCh)

	bbsLrp := NewCfBbsLrpListener(env)
	bbsTasks := NewCfBbsTaskListener(env)
	go bbsLrp.Run(stopCh)
	go bbsTasks.Run(stopCh)

	go env.processQueue(env.spaceFetchQ, env.spaceFetchQueueHandler, stopCh)
	go env.processQueue(env.spaceChangesQ, env.processSpaceChanges, stopCh)
	go env.processQueue(env.appUpdateQ,
		func(id interface{}) bool { return env.handleAppUpdate(id.(string)) },
		stopCh)
	go env.processQueue(env.appDeleteQ,
		func(id interface{}) bool { return env.handleAppDelete(id.(*AppInfo)) },
		stopCh)
	go env.processQueue(env.containerUpdateQ,
		func(id interface{}) bool { return env.handleContainerUpdate(id.(string)) },
		stopCh)
	go env.processQueue(env.containerDeleteQ,
		func(id interface{}) bool {
			return env.handleContainerDelete(id.(*ContainerInfo))
		},
		stopCh)
	go env.processQueue(env.orgChangesQ, env.processOrgChanges, stopCh)
	go env.processQueue(env.asgUpdateQ,
		func(id interface{}) bool { return env.handleAsgUpdate(id.(string)) },
		stopCh)
	go env.processQueue(env.asgDeleteQ,
		func(id interface{}) bool { return env.handleAsgDelete(id.(*cfclient.SecGroup)) },
		stopCh)

	go wait.Until(env.UpdateHppForCfComponents, 30*time.Second, stopCh)

	cache.WaitForCacheSync(stopCh, bbsLrp.Synced, bbsTasks.Synced)
	env.log.Info("BBS sync complete")

	netPolPoller := NewNetworkPolicyPoller(env)
	go netPolPoller.Run(true, stopCh)
	cellPoller := NewCfBbsCellPoller(env)
	go cellPoller.Run(true, stopCh)
	cache.WaitForCacheSync(stopCh, netPolPoller.Synced, cellPoller.Synced)

	// start cleanup pollers
	app_poller := NewAppCloudControllerPoller(env)
	space_poller := NewSpaceCloudControllerPoller(env)
	org_poller := NewOrgCloudControllerPoller(env)
	go app_poller.Run(true, stopCh)
	go space_poller.Run(true, stopCh)
	go org_poller.Run(true, stopCh)
	cache.WaitForCacheSync(stopCh, app_poller.Synced, space_poller.Synced,
		org_poller.Synced)
	go NewAsgCleanupPoller(env).Run(false, stopCh)

	return nil
}

func (env *CfEnvironment) InitStaticAciObjects() {
	env.initStaticHpp()
	env.cont.initStaticServiceObjs()
}

func (env *CfEnvironment) initStaticHpp() {
	cont := env.cont

	staticName := cont.aciNameForKey("hpp", "static")
	hpp := apicapi.NewHostprotPol(cont.config.AciPolicyTenant, staticName)

	{
		// ARP ingress/egress and ICMP ingress (+ reply)
		discSubj := apicapi.NewHostprotSubj(hpp.GetDn(), "discovery")
		discDn := discSubj.GetDn()
		{
			arpin := apicapi.NewHostprotRule(discDn, "arp-ingress")
			arpin.SetAttr("direction", "ingress")
			arpin.SetAttr("ethertype", "arp")
			arpin.SetAttr("connTrack", "normal")
			discSubj.AddChild(arpin)
		}
		{
			arpout := apicapi.NewHostprotRule(discDn, "arp-egress")
			arpout.SetAttr("direction", "egress")
			arpout.SetAttr("ethertype", "arp")
			arpout.SetAttr("connTrack", "normal")
			discSubj.AddChild(arpout)
		}
		{
			icmpin := apicapi.NewHostprotRule(discDn, "icmp-ingress")
			icmpin.SetAttr("direction", "ingress")
			icmpin.SetAttr("ethertype", "ipv4")
			icmpin.SetAttr("protocol", "icmp")
			discSubj.AddChild(icmpin)
		}
		hpp.AddChild(discSubj)
	}

	{
		// Allow TCP/UDP egress (+ reply) to CNI network and app-VIP network
		subnets := make([]string, 0)
		for _, s := range env.cont.config.PodSubnets {
			subnets = append(subnets, s)
		}
		if len(subnets) == 0 {
			env.log.Warning("Pod subnets not defined")
		}
		for _, vip_sn := range env.cfconfig.AppVipSubnet {
			subnets = append(subnets, vip_sn)
		}
		for idx, subnet_str := range subnets {
			_, subnet, err := net.ParseCIDR(subnet_str)
			if err != nil {
				env.log.Warning(fmt.Sprintf("Invalid subnet %s: ", subnet_str), err)
			} else {
				af := "ipv4"
				if subnet.IP.To4() == nil && subnet.IP.To16() != nil {
					af = "ipv6"
				}
				c2cSubj := apicapi.NewHostprotSubj(hpp.GetDn(), fmt.Sprintf("c2c-%d", idx))
				c2cDn := c2cSubj.GetDn()
				tcp := apicapi.NewHostprotRule(c2cDn, "c2c-tcp")
				tcp.SetAttr("direction", "egress")
				tcp.SetAttr("ethertype", af)
				tcp.SetAttr("protocol", "tcp")
				tcp_remote := apicapi.NewHostprotRemoteIp(tcp.GetDn(), subnet.String())
				tcp.AddChild(tcp_remote)
				c2cSubj.AddChild(tcp)

				udp := apicapi.NewHostprotRule(c2cDn, "c2c-udp")
				udp.SetAttr("direction", "egress")
				udp.SetAttr("ethertype", af)
				udp.SetAttr("protocol", "udp")
				udp_remote := apicapi.NewHostprotRemoteIp(udp.GetDn(), subnet.String())
				udp.AddChild(udp_remote)
				c2cSubj.AddChild(udp)

				hpp.AddChild(c2cSubj)
			}
		}
	}

	hppExtName := cont.aciNameForKey("hpp", "app-ext-ip")
	hppExt := apicapi.NewHostprotPol(cont.config.AciPolicyTenant, hppExtName)
	{
		// Allow all incoming traffic to app port. To be used if app has external-IP
		appSubj := apicapi.NewHostprotSubj(hppExt.GetDn(), "app-ext-ingress")
		appDn := appSubj.GetDn()
		appPortv4 := apicapi.NewHostprotRule(appDn, "app-port-v4")
		appPortv4.SetAttr("direction", "ingress")
		appPortv4.SetAttr("ethertype", "ipv4")
		appPortv4.SetAttr("toPort", fmt.Sprintf("%d", env.cfconfig.AppPort))
		appPortv4.SetAttr("protocol", "tcp")
		appSubj.AddChild(appPortv4)

		appPortv6 := apicapi.NewHostprotRule(appDn, "app-port-v6")
		appPortv6.SetAttr("direction", "ingress")
		appPortv6.SetAttr("ethertype", "ipv6")
		appPortv6.SetAttr("toPort", fmt.Sprintf("%d", env.cfconfig.AppPort))
		appPortv6.SetAttr("protocol", "tcp")
		appSubj.AddChild(appPortv6)

		hppExt.AddChild(appSubj)
	}
	cont.apicConn.WriteApicObjects(cont.config.AciPrefix+"_asg_static", apicapi.ApicSlice{hpp, hppExt})
}

func (env *CfEnvironment) CheckCfComponentsIps() bool {
	// fetch go-router IPs
	gorouter := env.cfconfig.GoRouterAddress
	tcprouter := env.cfconfig.TcpRouterAddress
	resolv := net.Resolver{PreferGo: true}
	rtrIps, err_rtr := resolv.LookupHost(context.Background(), gorouter)
	if err_rtr != nil {
		env.log.Warn(
			"Failed to resolve gorouter DNS name "+gorouter+": ", err_rtr)
	} else {
		sort.Strings(rtrIps)
	}
	tcpRtrIps, err_tcp_rtr := resolv.LookupHost(context.Background(),
		tcprouter)
	if err_tcp_rtr != nil {
		env.log.Warn(
			"Failed to resolve TCP router DNS name "+tcprouter+": ",
			err_tcp_rtr)
	} else {
		sort.Strings(tcpRtrIps)
	}
	updated := false
	env.indexLock.Lock()
	defer env.indexLock.Unlock()
	if err_rtr == nil && !reflect.DeepEqual(env.goRouterIps, rtrIps) {
		env.goRouterIps = rtrIps
		updated = true
		env.log.Info("Updated gorouters: ", env.goRouterIps)
	}
	if err_tcp_rtr == nil && !reflect.DeepEqual(env.tcpRouterIps, tcpRtrIps) {
		env.tcpRouterIps = tcpRtrIps
		updated = true
		env.log.Info("Updated TCP routers: ", env.tcpRouterIps)
	}
	return updated
}

func (env *CfEnvironment) UpdateHppForCfComponents() {
	if !env.CheckCfComponentsIps() {
		return
	}

	cont := env.cont
	cfcompName := cont.aciNameForKey("hpp", "cf-components")
	hpp := apicapi.NewHostprotPol(cont.config.AciPolicyTenant, cfcompName)

	// Default app port and SSH port - ingress (+reply) allowed from
	// GoRouter, TCP-router & SSH-proxy
	appSubj := apicapi.NewHostprotSubj(hpp.GetDn(), "app-ingress")
	appDn := appSubj.GetDn()
	env.indexLock.Lock()
	defer env.indexLock.Unlock()

	if len(env.goRouterIps) > 0 || len(env.tcpRouterIps) > 0 {
		appPort := apicapi.NewHostprotRule(appDn, "app-port")
		appPort.SetAttr("direction", "ingress")
		appPort.SetAttr("ethertype", "ipv4") // TODO separate out v6
		appPort.SetAttr("toPort", fmt.Sprintf("%d", env.cfconfig.AppPort))
		appPort.SetAttr("protocol", "tcp")
		for _, ip := range env.goRouterIps {
			remote := apicapi.NewHostprotRemoteIp(appPort.GetDn(), ip)
			appPort.AddChild(remote)
		}
		for _, ip := range env.tcpRouterIps {
			remote := apicapi.NewHostprotRemoteIp(appPort.GetDn(), ip)
			appPort.AddChild(remote)
		}
		appSubj.AddChild(appPort)
	}
	if env.cfconfig.CfNetIntfAddress != "" {
		appSsh := apicapi.NewHostprotRule(appDn, "app-legacy-net")
		appSsh.SetAttr("direction", "ingress")
		appSsh.SetAttr("ethertype", "ipv4") // TODO separate out v6
		appSsh.SetAttr("protocol", "tcp")
		remote := apicapi.NewHostprotRemoteIp(appSsh.GetDn(), env.cfconfig.CfNetIntfAddress)
		appSsh.AddChild(remote)
		appSubj.AddChild(appSsh)
	}
	// update apps that support multiple ports
	apps := make(map[string]struct{})
	for _, cinfo := range env.contIdx {
		if cinfo != nil && cinfo.AppId != "" && len(env.GetAdditionalPorts(cinfo)) > 0 {
			apps[cinfo.AppId] = struct{}{}
		}
	}

	for a := range apps {
		env.appUpdateQ.Add(a)
	}
	hpp.AddChild(appSubj)
	cont.apicConn.WriteApicObjects(cont.config.AciPrefix+"_hpp_cf_comp", apicapi.ApicSlice{hpp})
}

// must be called with cont.indexMutex locked
func (env *CfEnvironment) LoadCellNetworkInfo(cellId string) {
	if _, ok := env.cont.nodePodNetCache[cellId]; ok {
		return
	}
	nodePodNet := newNodePodNetMeta()

	txn, _ := env.db.Begin()
	podnetdb := CellPodNetDb{}
	netips, err := podnetdb.Get(txn, cellId)
	if err != nil {
		env.log.WithField("cellId", cellId).Error(
			"Unable to fetch cell pod network info from DB: ", err)
		return
	}
	txn.Commit()
	if netips == nil {
		return
	}
	nodePodNet.podNetIps = *netips
	env.cont.recomputePodNetAnnotation(nodePodNet)
	env.log.WithField("cellId", cellId).Info(
		"Read pod net from DB: ", nodePodNet.podNetIpsAnnotation)
	env.cont.nodePodNetCache[cellId] = nodePodNet

	env.kvmgr.Set("cell/"+cellId, "network", nodePodNet.podNetIpsAnnotation)
}

// must be called with cont.indexMutex locked
func (env *CfEnvironment) SetCellServiceInfo(nodeName, cellId string) {

	// check if cell has opflex device mac
	env.cont.indexMutex.Lock()
	defer env.cont.indexMutex.Unlock()
	deviceMac, hasDevice := env.cont.deviceMacForNode(nodeName)
	if !hasDevice {
		env.log.Debug("Opflex Device MAC not available for cell ", nodeName)
		return
	}
	currMeta := env.cont.nodeServiceMetaCache[nodeName]
	if currMeta != nil && currMeta.serviceEp.Mac == deviceMac {
		// MAC unchanged, skip updates
		return
	}

	nodeMeta := &nodeServiceMeta{}
	existing := &metadata.ServiceEndpoint{}
	svcepdb := CellServiceEpDb{}
	if currMeta == nil {
		txn, _ := env.db.Begin()
		svcep, err := svcepdb.Get(txn, cellId)
		txn.Commit()
		if err != nil {
			env.log.WithField("cellId", cellId).Error(
				"Unable to fetch cell service EP from DB: ", err)
			return
		}
		if svcep != nil {
			existing = svcep
			env.log.WithField("cellId", cellId).Info(
				"Read service EP from DB: ", *existing)
		}
	} else {
		existing = &currMeta.serviceEp
	}
	err := env.cont.createServiceEndpoint(existing, &nodeMeta.serviceEp,
		deviceMac)
	if err != nil {
		env.log.Error("Couldn't create service EP info for cell: ", err)
		return
	}
	updated := !reflect.DeepEqual(existing, &nodeMeta.serviceEp)
	if updated {
		txn, _ := env.db.Begin()
		if err := svcepdb.Set(txn, cellId, &nodeMeta.serviceEp); err != nil {
			env.log.WithField("cellId", cellId).Error(
				"Failed to write cell service EP to DB: ", err)
		} else {
			env.log.WithField("cellId", cellId).Info(
				"Updated service EP in DB to: ", nodeMeta.serviceEp)
		}
		txn.Commit()
	}
	env.cont.nodeServiceMetaCache[nodeName] = nodeMeta
	env.kvmgr.Set("cell/"+cellId, "service", &nodeMeta.serviceEp)

	return
}

// must be called with cont.indexMutex locked
func (env *CfEnvironment) NodePodNetworkChanged(nodename string) {
	env.cont.indexMutex.Lock()
	podnet, ok := env.cont.nodePodNetCache[nodename]
	env.cont.indexMutex.Unlock()
	if ok {
		txn, _ := env.db.Begin()
		podnetdb := CellPodNetDb{}
		if err := podnetdb.Set(txn, nodename, &podnet.podNetIps); err != nil {
			env.log.WithField("cellId", nodename).Error(
				"Failed to write cell pod network info to DB: ", err)
		} else {
			env.log.WithField("cellId", nodename).Info(
				"Wrote pod net to DB: ", podnet.podNetIpsAnnotation)
		}
		txn.Commit()

		env.kvmgr.Set("cell/"+nodename, "network", podnet.podNetIpsAnnotation)
	}
}

func (env *CfEnvironment) NodeServiceChanged(nodeName string) {
	cellId := strings.TrimPrefix(nodeName, "diego-cell-")
	env.SetCellServiceInfo(nodeName, cellId)
	env.indexLock.Lock()
	defer env.indexLock.Unlock()
	apps := make(map[string]struct{})
	for _, cinfo := range env.contIdx {
		if cinfo != nil && cinfo.CellId == cellId {
			apps[cinfo.AppId] = struct{}{}
		}
	}

	for id := range apps {
		env.appUpdateQ.Add(id)
	}
}

func (env *CfEnvironment) processQueue(queue workqueue.RateLimitingInterface,
	handler func(interface{}) bool, stopCh <-chan struct{}) {
	go wait.Until(func() {
		for {
			key, quit := queue.Get()
			if quit {
				break
			}

			requeue := handler(key)
			if requeue {
				queue.AddRateLimited(key)
			} else {
				queue.Forget(key)
			}
			queue.Done(key)
		}
	}, time.Second, stopCh)
	<-stopCh
	queue.ShutDown()
}

func (env *CfEnvironment) waitToBecomeMaster(stopCh <-chan struct{}, retryInterval time.Duration,
	onDemote func()) error {
	if retryInterval == 0 {
		retryInterval = locket.SQLRetryInterval
	}
	for env.locketClient == nil {
		cfg := locket.ClientLocketConfig{
			LocketAddress:        env.cfconfig.LocketAddress,
			LocketCACertFile:     env.cfconfig.LocketCACertFile,
			LocketClientCertFile: env.cfconfig.LocketClientCertFile,
			LocketClientKeyFile:  env.cfconfig.LocketClientKeyFile,
		}
		c, err := locket.NewClient(env.cfLogger, cfg)
		if err != nil {
			env.log.Info("Failed to create locket client: ", err)
			time.Sleep(10 * time.Second)
		} else {
			env.locketClient = c
		}
	}

	lockRes := &locketmodels.Resource{
		Key:      "/aci/controller/master",
		Owner:    env.cfconfig.Uuid,
		TypeCode: locketmodels.LOCK,
	}
	runner := lock.NewLockRunner(
		env.cfLogger,
		env.locketClient,
		lockRes,
		locket.DefaultSessionTTLInSeconds,
		clock.NewClock(),
		retryInterval)

	readyChan := make(chan struct{})
	isReady := false
	sigChan := make(chan os.Signal)

	// start locket runner
	var ret error = nil
	go func() {
		ret = runner.Run(sigChan, readyChan)
		if !isReady {
			// unblock waitToBecomeMaster if it is still waiting
			close(readyChan)
		}
		if ret != nil {
			env.log.Info("Locket runner exited with error: ", ret)
			onDemote()
		}
	}()

	// monitor stop channel
	stopping := false
	go func() {
		<-stopCh
		stopping = true
		env.log.Info("Received stop, signaling locket runner")
		sigChan <- os.Interrupt
	}()

	<-readyChan
	isReady = true
	if ret == nil && !stopping {
		env.log.Info("Master lock acquired")
	}

	return ret
}
