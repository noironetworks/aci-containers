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
	"reflect"
	"strings"

	etcdclient "github.com/coreos/etcd/client"

	"github.com/noironetworks/aci-containers/pkg/cf_common"
	etcd "github.com/noironetworks/aci-containers/pkg/cf_etcd"
	"github.com/noironetworks/aci-containers/pkg/metadata"
)

func NewCfEtcdCellWatcher(env *CfEnvironment) *etcd.CfEtcdWatcher {
	cellKey := etcd.CELL_KEY_BASE + "/" + env.cfconfig.CellID
	cellNetKey := cellKey + "/network"
	cellSvcKey := cellKey + "/service"
	ctBaseKey := cellKey + "/containers/"

	handleEtcdNode := func(action *string, node *etcdclient.Node) error {
		if node.Key == cellKey {
			return env.handleEtcdCellNode(action, node)
		} else if node.Key == cellNetKey {
			return env.handleEtcdCellNetworkNode(action, node)
		} else if node.Key == cellSvcKey {
			return env.handleEtcdCellServiceNode(action, node)
		} else if strings.HasPrefix(node.Key, ctBaseKey) {
			return env.handleEtcdContainerNode(action, node)
		}
		return nil
	}

	return etcd.NewEtcdWatcher(env.etcdKeysApi, cellKey, handleEtcdNode, env.log)
}

func NewCfEtcdAppWatcher(env *CfEnvironment) *etcd.CfEtcdWatcher {
	key := etcd.APP_KEY_BASE

	handleEtcdNode := func(action *string, node *etcdclient.Node) error {
		if strings.HasPrefix(node.Key, etcd.APP_KEY_BASE+"/") {
			return env.handleEtcdAppNode(action, node)
		}
		return nil
	}

	return etcd.NewEtcdWatcher(env.etcdKeysApi, key, handleEtcdNode, env.log)
}

func (env *CfEnvironment) handleEtcdCellNode(action *string, node *etcdclient.Node) error {
	if etcd.IsDeleteAction(action) {
		env.handleEtcdCellNetworkNode(action, nil)
		env.handleEtcdCellServiceNode(action, nil)
	}
	return nil
}

func (env *CfEnvironment) handleEtcdCellNetworkNode(action *string, node *etcdclient.Node) error {
	if etcd.IsDeleteAction(action) {
		env.agent.updateIpamAnnotation("[]")
	} else {
		env.agent.updateIpamAnnotation(node.Value)
	}
	return nil
}

func (env *CfEnvironment) handleEtcdCellServiceNode(action *string, node *etcdclient.Node) error {
	var newServiceEp metadata.ServiceEndpoint
	updated := false
	agent := env.agent
	if etcd.IsDeleteAction(action) {
		agent.indexMutex.Lock()
		agent.serviceEp = newServiceEp
		agent.indexMutex.Unlock()
		updated = true
	} else {
		err := json.Unmarshal([]byte(node.Value), &newServiceEp)
		if err != nil {
			env.log.Error("Error deserializing cell service node value: ", err)
			return err
		} else {
			agent.indexMutex.Lock()
			if !reflect.DeepEqual(newServiceEp, agent.serviceEp) {
				env.log.Info("Cell service EP updated: ", node.Value)
				agent.serviceEp = newServiceEp
				updated = true
			}
			agent.indexMutex.Unlock()
		}
	}
	if updated {
		// update service files for all apps that have a container
		apps := make(map[string]struct{})
		env.indexLock.Lock()
		for _, ep := range env.epIdx {
			if ep != nil {
				apps[ep.AppId] = struct{}{}
			}
		}
		env.indexLock.Unlock()
		// TODO Use a queue for updating all apps
		go func() {
			for id := range apps {
				env.cfAppIdChanged(&id)
			}
		}()
	}
	return nil
}

func (env *CfEnvironment) handleEtcdContainerNode(action *string, node *etcdclient.Node) error {
	epNode := strings.HasSuffix(node.Key, "/ep")
	key_parts := strings.Split(node.Key, "/")
	ctId := key_parts[len(key_parts)-2]
	if !epNode {
		ctId = key_parts[len(key_parts)-1]
	}
	deleted := etcd.IsDeleteAction(action)
	if epNode && !deleted {
		var ep cf_common.EpInfo
		err := json.Unmarshal([]byte(node.Value), &ep)
		if err != nil {
			env.log.Error("Error deserializing container node value: ", err)
			return err
		}

		env.log.Info(fmt.Sprintf("Etcd udpate event for Container %s - %+v", ctId, ep))

		env.indexLock.Lock()
		env.epIdx[ctId] = &ep
		env.indexLock.Unlock()

		env.cfAppContainerChanged(&ctId, &ep)
	}
	if deleted {
		env.log.Info("Etcd delete event for Container ", ctId)
		env.indexLock.Lock()
		ep := env.epIdx[ctId]
		delete(env.epIdx, ctId)
		env.indexLock.Unlock()

		env.cfAppContainerDeleted(&ctId, ep)
	}
	return nil
}

func (env *CfEnvironment) handleEtcdAppNode(action *string, node *etcdclient.Node) error {
	key_parts := strings.Split(node.Key, "/")
	appId := key_parts[len(key_parts)-1]
	deleted := etcd.IsDeleteAction(action)
	if !deleted {
		var app cf_common.AppInfo
		err := json.Unmarshal([]byte(node.Value), &app)
		if err != nil {
			env.log.Error("Error deserializing app node value: ", err)
			return err
		}

		env.log.Info(fmt.Sprintf("Etcd udpate event for App %s - %+v", appId, app))
		env.indexLock.Lock()
		env.appIdx[appId] = &app
		env.indexLock.Unlock()

		env.cfAppChanged(&appId, &app)
	} else {
		env.log.Info("Etcd delete event for App ", appId)
		env.indexLock.Lock()
		app := env.appIdx[appId]
		delete(env.appIdx, appId)
		env.indexLock.Unlock()

		env.cfAppDeleted(&appId, app)
	}
	return nil
}
