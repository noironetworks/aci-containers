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

package controller

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInitFlags(t *testing.T) {
	config := &ControllerConfig{}
	expConfig := &ControllerConfig{
		LogLevel:                          "info",
		KubeConfig:                        "",
		StatusPort:                        8091,
		DefaultEg:                         OpflexGroup{},
		DefaultSg:                         nil,
		NamespaceDefaultEg:                nil,
		NamespaceDefaultSg:                nil,
		ApicHosts:                         nil,
		ApicUsername:                      "",
		ApicPassword:                      "",
		ApicRefreshTimer:                  "",
		ApicSubscriptionDelay:             0,
		ApicRefreshTickerAdjust:           "",
		ApicPrivateKeyPath:                "",
		ApicCertPath:                      "",
		AciVmmDomainType:                  "",
		AciVmmDomain:                      "",
		AciVmmController:                  "",
		AciPrefix:                         "",
		AciPolicyTenant:                   "",
		LBType:                            "aci-nlb",
		AciServicePhysDom:                 "",
		AciServiceEncap:                   "",
		AciServiceMonitorInterval:         0,
		AciPbrTrackingNonSnat:             false,
		AciVrfRelatedTenants:              nil,
		AciPodBdDn:                        "",
		AciNodeBdDn:                       "",
		AciVrf:                            "",
		AciVrfDn:                          "",
		AciVrfTenant:                      "",
		AciL3Out:                          "",
		AciExtNetworks:                    nil,
		PodIpPool:                         nil,
		PodIpPoolChunkSize:                0,
		PodSubnet:                         nil,
		AllocateServiceIps:                nil,
		ServiceIpPool:                     nil,
		StaticServiceIpPool:               nil,
		NodeServiceIpPool:                 nil,
		NodeServiceSubnets:                nil,
		SnatDefaultPortRangeStart:         0,
		SnatDefaultPortRangeEnd:           0,
		SnatSvcContractScope:              "",
		MaxSvcGraphNodes:                  0,
		DisablePeriodicSnatGlobalInfoSync: false,
		NoWaitForServiceEpReadiness:       false,
		ServiceGraphEndpointAddDelay:      serviceGraphEpAddDelay{},
		AddExternalSubnetsToRdconfig:      false,
		ExternStatic:                      nil,
		ExternDynamic:                     nil,
		HppOptimization:                   false,
		AciMultipod:                       false,
		EnableOpflexAgentReconnect:        false,
		OpflexDeviceReconnectWaitTimeout:  0,
		InstallIstio:                      false,
		MaxCSRTunnels:                     16,
		CSRTunnelIDBase:                   4001,
		EnabledEndpointSlice:              false,
		Flavor:                            "",
		EnableVmmInjectedLabels:           false,
		OpflexDeviceDeleteTimeout:         0,
		SleepTimeSnatGlobalInfoSync:       0,
		UnknownMacUnicastAction:           "proxy",
		AciPhysDom:                        "",
		ChainedMode:                       false,
		AciAdditionalAep:                  "",
		ReconcileStaticObjects:            false,
		AciUseGlobalScopeVlan:             false,
		EnableMetrics:                     false,
		MetricsPort:                       8191,
		NodeSnatRedirectExclude:           nil,
		AppProfile:                        "",
		AddExternalContractToDefaultEPG:   false,
	}
	InitFlags(config)
	assert.Equal(t, expConfig, config)
	fmt.Println(expConfig)
	fmt.Println(config)
}
