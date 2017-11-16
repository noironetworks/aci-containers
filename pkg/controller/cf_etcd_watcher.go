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
	"encoding/json"
	"fmt"
	"strings"

	etcdclient "github.com/coreos/etcd/client"

	etcd "github.com/noironetworks/aci-containers/pkg/cf_etcd"
	md "github.com/noironetworks/aci-containers/pkg/metadata"
)

func NewCfEtcdContainersWatcher(env *CfEnvironment) *etcd.CfEtcdWatcher {
	key := etcd.CONTROLLER_KEY_BASE + "/containers"
	handleEtcdNode := func(action *string, node *etcdclient.Node) error {
		if strings.HasPrefix(node.Key, key) {
			return env.handleEtcdContainerNode(action, node)
		}
		return nil
	}

	return etcd.NewEtcdWatcher(env.etcdKeysApi, key, handleEtcdNode, env.log)
}

func (env *CfEnvironment) handleEtcdContainerNode(action *string, node *etcdclient.Node) error {
	if etcd.IsDeleteAction(action) {
		return nil
	}
	isMdNode := strings.HasSuffix(node.Key, "/metadata")
	if !isMdNode {
		return nil
	}
	key_parts := strings.Split(node.Key, "/")
	ctId := key_parts[len(key_parts)-2]

	md := md.ContainerMetadata{Id: md.ContainerId{ContId: ctId}}
	err := json.Unmarshal([]byte(node.Value), &md.Ifaces)
	if err != nil {
		env.log.Error("Error deserializing container metadata: ", err)
		return nil
	}
	if len(md.Ifaces) == 0 || len(md.Ifaces[0].IPs) == 0 {
		return nil
	}

	env.indexLock.Lock()
	defer env.indexLock.Unlock()
	ct := env.contIdx[ctId]
	if ct == nil || ct.IsApp() {
		return nil
	}
	ct.IpAddress = md.Ifaces[0].IPs[0].Address.IP.String()
	env.contIdx[ctId] = ct
	env.log.Debug(fmt.Sprintf("Container updated due to metadata event: %+v", ct))
	var app *AppInfo
	if ct.AppId != "" {
		app = env.appIdx[ct.AppId]
		if app != nil {
			app.ContainerIps[ctId] = ct.IpAddress
			env.appIdx[ct.AppId] = app
		}
	}

	if app != nil {
		env.appUpdateQ.Add(app.AppId)
	}
	env.containerUpdateQ.Add(ctId)
	return nil
}
