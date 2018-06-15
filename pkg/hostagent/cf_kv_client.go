// Copyright 2018 Cisco Systems, Inc.
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
	"crypto/tls"
	"fmt"
	"net"
	"reflect"
	"strings"

	"code.cloudfoundry.org/cfhttp"
	"github.com/Sirupsen/logrus"

	"github.com/noironetworks/aci-containers/pkg/cf_common"
	rkv "github.com/noironetworks/aci-containers/pkg/keyvalueservice"
	"github.com/noironetworks/aci-containers/pkg/metadata"
)

func NewCfKvClient(env *CfEnvironment) *rkv.KvClient {
	cf := func() (net.Conn, error) {
		tlscfg, err := cfhttp.NewTLSConfig(
			env.cfconfig.ControllerClientCertFile,
			env.cfconfig.ControllerClientKeyFile,
			env.cfconfig.ControllerCACertFile)
		if err != nil {
			env.log.Warning("CfKvClient: Failed to create "+
				"client-side TLS config: ", err)
			return nil, err
		}
		return tls.Dial("tcp", env.cfconfig.ControllerAddress, tlscfg)
	}
	w := rkv.NewKvWatcher([]string{"apps", "cell/" + env.cfconfig.CellID},
		env.log, env.handleKvItems, env.handleKvActions)
	return rkv.NewKvClient(cf, env.kvmgr, w, env.log)
}

type appKvHandler struct {
	env *CfEnvironment
}

type cellKvHandler struct {
	env *CfEnvironment
}

func (env *CfEnvironment) handleKvItems(ns string, items []rkv.KvItem) {
	env.log.WithFields(
		logrus.Fields{"ctx": "handleKvItems", "ns": ns, "#items": len(items)},
	).Info("Got all items")
	switch ns {
	case "apps":
		(&appKvHandler{env}).All(items)
		env.appsSynced = true
	case "cell/" + env.cfconfig.CellID:
		env.cellSynced = true
		(&cellKvHandler{env}).All(items)
	}
	if env.appsSynced && env.cellSynced {
		env.agent.EnableSync()
		env.agent.cleanupSetup()
		env.agent.ScheduleSync("iptables")
	}
}

func (env *CfEnvironment) handleKvActions(ns string, acts []rkv.KvAction) {
	switch ns {
	case "apps":
		(&appKvHandler{env}).Update(acts)
	case "cell/" + env.cfconfig.CellID:
		(&cellKvHandler{env}).Update(acts)
	}
}

type idSet map[string]struct{}

func (h *appKvHandler) All(items []rkv.KvItem) {
	ids := make(idSet)
	for i, _ := range items {
		h.do(&items[i], ids, false)
	}

	h.env.indexLock.Lock()
	tonotify := make(map[string]*cf_common.AppInfo)
	for app, info := range h.env.appIdx {
		if _, ok := ids[app]; !ok {
			tonotify[app] = info
			delete(h.env.appIdx, app)
		}
	}
	h.env.indexLock.Unlock()
	for app, info := range tonotify {
		h.env.cfAppDeleted(&app, info)
	}
}

func (h *appKvHandler) Update(acts []rkv.KvAction) {
	for i, _ := range acts {
		h.do(&acts[i].Item, nil, acts[i].Action == rkv.OP_DELETE)
	}
}

func (h *appKvHandler) do(item *rkv.KvItem, ids idSet, del bool) {
	appId := item.Key
	l := h.env.log.WithFields(
		logrus.Fields{"ctx": "KvItem:App", "appId": appId})
	if !del {
		if m, ok := item.Value.(map[string]interface{}); !ok {
			l.Error("Unexpected value type: ", item.Value)
		} else {
			app := &cf_common.AppInfo{}
			if err := rkv.MapToStruct(m, app); err != nil {
				l.WithField("value", item.Value).Error("Decode error: ", err)
			} else {
				l.Info("KV update, new value: ", fmt.Sprintf("%+v", app))
				h.env.indexLock.Lock()
				h.env.appIdx[appId] = app
				h.env.indexLock.Unlock()
				if ids != nil {
					ids[appId] = struct{}{}
				}
				h.env.cfAppChanged(&appId, app)
			}
		}
	} else {
		l.Info("KV delete")
		h.env.indexLock.Lock()
		app := h.env.appIdx[appId]
		delete(h.env.appIdx, appId)
		h.env.indexLock.Unlock()

		h.env.cfAppDeleted(&appId, app)
	}
}

func (h *cellKvHandler) All(items []rkv.KvItem) {
	ids := make(idSet)
	hasNet, hasSvc := false, false
	for i, _ := range items {
		n, s := h.do(&items[i], ids, false)
		hasNet = hasNet || n
		hasSvc = hasSvc || s
	}

	if !hasNet {
		h.doNetwork(nil, true)
	}
	if !hasSvc {
		h.doService(nil, true)
	}

	h.env.indexLock.Lock()
	tonotify := make(map[string]*cf_common.EpInfo)
	for ctId, info := range h.env.epIdx {
		if _, ok := ids[ctId]; !ok {
			tonotify[ctId] = info
			delete(h.env.epIdx, ctId)
		}
	}
	h.env.indexLock.Unlock()
	for ctId, ep := range tonotify {
		l := h.env.log.WithFields(
			logrus.Fields{"ctx": "KvItem:Container", "ctId": ctId})
		l.Info("KV delete on full sync")
		h.env.cfAppContainerDeleted(&ctId, ep)
	}
}

func (h *cellKvHandler) Update(acts []rkv.KvAction) {
	for i, _ := range acts {
		h.do(&acts[i].Item, nil, acts[i].Action == rkv.OP_DELETE)
	}
}

func (h *cellKvHandler) do(item *rkv.KvItem, ids idSet, del bool) (
	netChanged, svcChanged bool) {
	if item.Key == "network" {
		netChanged = h.doNetwork(item, del)
	} else if item.Key == "service" {
		svcChanged = h.doService(item, del)
	} else if strings.HasPrefix(item.Key, "ct/") {
		h.doContainer(item, ids, del)
	}
	return
}

func (h *cellKvHandler) doNetwork(item *rkv.KvItem, del bool) (updated bool) {
	l := h.env.log.WithField("ctx", "KvItem:CellNetwork")
	if del {
		l.Info("Resetting network pool to default")
		h.env.agent.updateIpamAnnotation(h.env.getDefaultIpPool())
	} else {
		if ann, ok := item.Value.(string); !ok {
			l.Error("Unexpected value type: ", item.Value)
		} else {
			h.env.agent.updateIpamAnnotation(ann)
			updated = true
		}
	}
	return
}

func (h *cellKvHandler) doService(item *rkv.KvItem, del bool) (updated bool) {
	env := h.env
	agent := env.agent
	l := env.log.WithField("ctx", "KvItem:CellService")
	if del {
		l.Info("Clearing service EP info")
		agent.indexMutex.Lock()
		agent.serviceEp = metadata.ServiceEndpoint{}
		agent.indexMutex.Unlock()
	} else {
		if m, ok := item.Value.(map[string]interface{}); !ok {
			l.Error("Unexpected value type: ", item.Value)
		} else {
			sep := &metadata.ServiceEndpoint{}
			if err := rkv.MapToStruct(m, sep); err != nil {
				l.WithField("value", item.Value).Error("Decode error: ", err)
			} else {
				agent.indexMutex.Lock()
				if !reflect.DeepEqual(sep, &agent.serviceEp) {
					l.Info("Cell service EP updated: ",
						fmt.Sprintf("%+v", sep))
					agent.serviceEp = *sep
					updated = true
				}
				agent.indexMutex.Unlock()
			}
		}
	}
	if updated || del {
		// update service files for all apps that have a container
		apps := make(idSet)
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
	return
}

func (h *cellKvHandler) doContainer(item *rkv.KvItem, ids idSet, del bool) {
	env := h.env
	ctId := strings.Split(item.Key, "/")[1]
	l := env.log.WithFields(
		logrus.Fields{"ctx": "KvItem:Container", "ctId": ctId})
	if del {
		l.Info("KV delete")

		env.indexLock.Lock()
		ep := env.epIdx[ctId]
		delete(env.epIdx, ctId)
		env.indexLock.Unlock()

		env.cfAppContainerDeleted(&ctId, ep)
	} else {
		if m, ok := item.Value.(map[string]interface{}); !ok {
			l.Error("Unexpected value type: ", item.Value)
		} else {
			ep := &cf_common.EpInfo{}
			if err := rkv.MapToStruct(m, ep); err != nil {
				l.WithField("value", item.Value).Error("Decode error: ", err)
			} else {
				l.Info("KV update, new value: ", fmt.Sprintf("%+v", ep))
				env.indexLock.Lock()
				env.epIdx[ctId] = ep
				env.indexLock.Unlock()
				if ids != nil {
					ids[ctId] = struct{}{}
				}
				env.cfAppContainerChanged(&ctId, ep)
			}
		}
	}
}
