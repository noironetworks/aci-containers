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
	"crypto/tls"
	"fmt"
	"net"

	"code.cloudfoundry.org/cfhttp"

	rkv "github.com/noironetworks/aci-containers/pkg/keyvalueservice"
	md "github.com/noironetworks/aci-containers/pkg/metadata"
)

func NewCfKvServer(env *CfEnvironment) *rkv.KvServer {
	lf := func() (net.Listener, error) {
		tlscfg, err := cfhttp.NewTLSConfig(
			env.cfconfig.ControllerServerCertFile,
			env.cfconfig.ControllerServerKeyFile,
			env.cfconfig.ControllerCACertFile)
		if err != nil {
			env.log.Warning("CfKvServer: Failed to create server-side "+
				"TLS config: ", err)
			return nil, err
		}
		return tls.Listen("tcp",
			fmt.Sprintf(":%d", env.cfconfig.KeyValuePort), tlscfg)
	}
	w := rkv.NewKvWatcher([]string{"container"}, env.log, env.handleKvItems,
		env.handleKvActions)
	return rkv.NewKvServer(lf, env.kvmgr, w, env.log)
}

func (env *CfEnvironment) handleKvItems(ns string, items []rkv.KvItem) {
	switch ns {
	case "container":
		env.handleContainerKvItems(items)
	}
}

func (env *CfEnvironment) handleKvActions(ns string, acts []rkv.KvAction) {
	switch ns {
	case "container":
		env.handleContainerKvActions(acts)
	}
}

func (env *CfEnvironment) handleContainerKvItems(items []rkv.KvItem) {
	if len(items) == 0 {
		return
	}

	env.indexLock.Lock()
	defer env.indexLock.Unlock()
	for i, _ := range items {
		env.handleContainerIpUpdate(&items[i])
	}
}

func (env *CfEnvironment) handleContainerKvActions(acts []rkv.KvAction) {
	if len(acts) == 0 {
		return
	}
	env.indexLock.Lock()
	defer env.indexLock.Unlock()

	for i, _ := range acts {
		if acts[i].Action != rkv.OP_DELETE {
			env.handleContainerIpUpdate(&acts[i].Item)
		}
	}
}

// expect env.indexLock to be held
func (env *CfEnvironment) handleContainerIpUpdate(item *rkv.KvItem) {
	ctId := item.Key
	ifs, ok := item.Value.([]interface{})
	l := env.log.WithField("ctx", "KvItem:Container")
	if !ok {
		l.Error("Unexpected value type: ", item.Value)
		return
	}
	if len(ifs) == 0 {
		return
	}
	if0_m, ok := ifs[0].(map[string]interface{})
	if !ok {
		l.Error("Unexpected item #0 value type: ", ifs[0])
		return
	}
	if0 := &md.ContainerIfaceMd{}
	if err := rkv.MapToStruct(if0_m, if0); err != nil {
		l.WithField("value", item.Value).Error("Decode error: ", err)
		return
	}
	if len(if0.IPs) == 0 {
		return
	}
	ct := env.contIdx[ctId]
	if ct == nil || ct.IsApp() {
		return
	}
	ct.IpAddress = if0.IPs[0].Address.IP.String()
	env.contIdx[ctId] = ct
	l.WithField("ctId", ctId).Debug("KV IP update: ", ct.IpAddress)
	var app *AppInfo
	if ct.AppId != "" {
		if app = env.appIdx[ct.AppId]; app != nil {
			app.ContainerIps[ctId] = ct.IpAddress
			env.appIdx[ct.AppId] = app
		}
	}

	if app != nil {
		env.appUpdateQ.Add(app.AppId)
	}
	env.containerUpdateQ.Add(ctId)
}
