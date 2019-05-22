// Copyright 2016 Cisco Systems, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRATIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Handlers for snat updates.

package hostagent

import (
	"encoding/json"
	"fmt"
	"github.com/Sirupsen/logrus"
	snatglobal "github.com/noironetworks/aci-containers/pkg/snatglobalinfo/apis/aci.snat/v1"
	snatglobalclset "github.com/noironetworks/aci-containers/pkg/snatglobalinfo/clientset/versioned"
	snatlocal "github.com/noironetworks/aci-containers/pkg/snatlocalinfo/apis/aci.snat/v1"
	snatlocalclset "github.com/noironetworks/aci-containers/pkg/snatlocalinfo/clientset/versioned"
	"io/ioutil"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
	"k8s.io/kubernetes/pkg/controller"
	"os"
	"path/filepath"
	"reflect"
	"strings"
)

type OpflexPortRange struct {
	Start int `json:"start,omitempty"`
	End   int `json:"end,omitempty"`
}

type OpflexSnatIp struct {
	Uuid          string                   `json:"uuid"`
	InterfaceName string                   `json:"interface-name,omitempty"`
	SnatIp        string                   `json:"snat-ip,omitempty"`
	InterfaceMac  string                   `json:"interface-mac,omitempty"`
	Local         bool                     `json:"local,omitempty"`
	DestIpAddress string                   `json:"destip-dddress,omitempty"`
	DestPrefix    uint16                   `json:"dest-prefix,omitempty"`
	PortRange     []OpflexPortRange        `json:"port-range,omitempty"`
	InterfaceVlan uint                     `json:"interface-vlan,omitempty"`
	Remote        []OpflexSnatIpRemoteInfo `json:"remote,omitempty"`
}
type OpflexSnatIpRemoteInfo struct {
	NodeIp     string            `json:"snat_ip,omitempty"`
	MacAddress string            `json:"mac,omitempty"`
	PortRange  []OpflexPortRange `json:"port-range,omitempty"`
	Refcount   int               `json:"ref,omitempty"`
}
type OpflexSnatGlobalInfo struct {
	SnatIp     string
	MacAddress string
	PortRange  []OpflexPortRange
	SnatIpUid  string
	Protocols  []string
}

type OpflexSnatLocalInfo struct {
	SnatIp     string
	MarkDelete bool
}

func (agent *HostAgent) initSnatLocalInformerFromClient(
	snatClient *snatlocalclset.Clientset) {
	agent.initSnatLocalInformerBase(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				options.FieldSelector =
					fields.Set{"metadata.name": agent.config.NodeName}.String()
				return snatClient.AciV1().SnatLocalInfos(metav1.NamespaceAll).List(options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				options.FieldSelector =
					fields.Set{"metadata.name": agent.config.NodeName}.String()
				return snatClient.AciV1().SnatLocalInfos(metav1.NamespaceAll).Watch(options)
			},
		})
}
func (agent *HostAgent) initSnatGlobalInformerFromClient(
	snatClient *snatglobalclset.Clientset) {
	agent.initSnatGlobalInformerBase(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				return snatClient.AciV1().SnatGlobalInfos(metav1.NamespaceAll).List(options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				return snatClient.AciV1().SnatGlobalInfos(metav1.NamespaceAll).Watch(options)
			},
		})
}

func getsnat(snatfile string) (string, error) {
	raw, err := ioutil.ReadFile(snatfile)
	if err != nil {
		return "", err
	}
	return string(raw), err
}

func writeSnat(snatfile string, snat *OpflexSnatIp) (bool, error) {
	newdata, err := json.MarshalIndent(snat, "", "  ")
	if err != nil {
		return true, err
	}
	existingdata, err := ioutil.ReadFile(snatfile)
	if err == nil && reflect.DeepEqual(existingdata, newdata) {
		return false, nil
	}

	err = ioutil.WriteFile(snatfile, newdata, 0644)
	return true, err
}

func (agent *HostAgent) FormSnatFilePath(uuid string) string {
	return filepath.Join(agent.config.OpFlexSnatDir, uuid+".snat")
}

func SnatLocalInfoLogger(log *logrus.Logger, snat *snatlocal.SnatLocalInfo) *logrus.Entry {
	return log.WithFields(logrus.Fields{
		"namespace": snat.ObjectMeta.Namespace,
		"name":      snat.ObjectMeta.Name,
		"spec":      snat.Spec,
	})
}

func SnatGlobalInfoLogger(log *logrus.Logger, snat *snatglobal.SnatGlobalInfo) *logrus.Entry {
	return log.WithFields(logrus.Fields{
		"namespace": snat.ObjectMeta.Namespace,
		"name":      snat.ObjectMeta.Name,
		"spec":      snat.Spec,
	})
}

func opflexSnatIpLogger(log *logrus.Logger, snatip *OpflexSnatIp) *logrus.Entry {
	return log.WithFields(logrus.Fields{
		"uuid":           snatip.Uuid,
		"snat_ip":        snatip.SnatIp,
		"mac_address":    snatip.InterfaceMac,
		"port_range":     snatip.PortRange,
		"local":          snatip.Local,
		"interface-name": snatip.InterfaceName,
		"interfcae-vlan": snatip.InterfaceVlan,
		"remote":         snatip.Remote,
	})
}

func (agent *HostAgent) initSnatLocalInformerBase(listWatch *cache.ListWatch) {
	agent.snatLocalInformer = cache.NewSharedIndexInformer(
		listWatch,
		&snatlocal.SnatLocalInfo{},
		controller.NoResyncPeriodFunc(),
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	agent.snatLocalInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			agent.snatLocalInfoUpdate(obj)
		},
		UpdateFunc: func(_ interface{}, obj interface{}) {
			agent.snatLocalInfoUpdate(obj)
		},
		DeleteFunc: func(obj interface{}) {
			agent.snatLocalInfoDelete(obj)
		},
	})
	agent.log.Debug("Initializing Snat Local info Informers")
}

func (agent *HostAgent) initSnatGlobalInformerBase(listWatch *cache.ListWatch) {
	agent.snatGlobalInformer = cache.NewSharedIndexInformer(
		listWatch,
		&snatglobal.SnatGlobalInfo{},
		controller.NoResyncPeriodFunc(),
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	agent.snatGlobalInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			agent.snatGlobalInfoUpdate(obj)
		},
		UpdateFunc: func(_ interface{}, obj interface{}) {
			agent.snatGlobalInfoUpdate(obj)
		},
		DeleteFunc: func(obj interface{}) {
			agent.snatGlobalInfoDelete(obj)
		},
	})
	agent.log.Debug("Initializing SnatGlobal Info Informers")
}

func (agent *HostAgent) snatLocalInfoUpdate(obj interface{}) {
	agent.indexMutex.Lock()
	defer agent.indexMutex.Unlock()
	snat := obj.(*snatlocal.SnatLocalInfo)
	key, err := cache.MetaNamespaceKeyFunc(snat)
	if err != nil {
		SnatLocalInfoLogger(agent.log, snat).
			Error("Could not create key:" + err.Error())
		return
	}
	agent.log.Info("Snat Local Object added/Updated ", snat)
	agent.doUpdateSnatLocalInfo(key)
}

func (agent *HostAgent) snatGlobalInfoUpdate(obj interface{}) {
	agent.indexMutex.Lock()
	defer agent.indexMutex.Unlock()
	snat := obj.(*snatglobal.SnatGlobalInfo)
	key, err := cache.MetaNamespaceKeyFunc(snat)
	if err != nil {
		SnatGlobalInfoLogger(agent.log, snat).
			Error("Could not create key:" + err.Error())
		return
	}
	agent.log.Info("Snat Local Object added/Updated ", snat)
	agent.doUpdateSnatGlobalInfo(key)
}

func (agent *HostAgent) doUpdateSnatLocalInfo(key string) {
	snatobj, exists, err :=
		agent.snatLocalInformer.GetStore().GetByKey(key)
	if err != nil {
		agent.log.Error("Could not lookup snat for " +
			key + ": " + err.Error())
		return
	}
	if !exists || snatobj == nil {
		return
	}
	snat := snatobj.(*snatlocal.SnatLocalInfo)
	logger := SnatLocalInfoLogger(agent.log, snat)
	agent.snatLocalInfoChanged(snatobj, logger)
}

func (agent *HostAgent) snatLocalInfoChanged(snatobj interface{}, logger *logrus.Entry) {
	snat := snatobj.(*snatlocal.SnatLocalInfo)
	if logger == nil {
		logger = agent.log.WithFields(logrus.Fields{})
	}
	logger.Debug("Snat local info Changed...")
	localInfo := snat.Spec.LocalInfos
	syncep := false
	// This case is true when scope moves from namespace to deployment
	if len(localInfo) < len(agent.opflexSnatLocalInfos) {
		for poduid, v := range agent.opflexSnatLocalInfos {
			if _, ok := localInfo[poduid]; !ok {
				// if pod present mark it snat ip deleted for local info
				if _, ok := agent.opflexEps[poduid]; ok {
					v.MarkDelete = true
					syncep = true
				} else {
					delete(agent.opflexSnatLocalInfos, poduid)
				}
			}
		}
	}
	for poduid, v := range localInfo {
		localInfo := &OpflexSnatLocalInfo{
			SnatIp:     v.SnatIp,
			MarkDelete: false,
		}
		if _, ok := agent.opflexSnatLocalInfos[poduid]; !ok {
			agent.opflexSnatLocalInfos[poduid] = localInfo
			syncep = true
		} else if agent.opflexSnatLocalInfos[poduid] != localInfo {
			agent.opflexSnatLocalInfos[poduid] = localInfo
			syncep = true
		}
	}
	if syncep {
		agent.scheduleSyncEps()
	}
}

func (agent *HostAgent) doUpdateSnatGlobalInfo(key string) {
	snatobj, exists, err :=
		agent.snatGlobalInformer.GetStore().GetByKey(key)
	if err != nil {
		agent.log.Error("Could not lookup snat for " +
			key + ": " + err.Error())
		return
	}
	if !exists || snatobj == nil {
		return
	}
	snat := snatobj.(*snatglobal.SnatGlobalInfo)
	logger := SnatGlobalInfoLogger(agent.log, snat)
	agent.snaGlobalInfoChanged(snatobj, logger)
}

func (agent *HostAgent) snaGlobalInfoChanged(snatobj interface{}, logger *logrus.Entry) {
	snat := snatobj.(*snatglobal.SnatGlobalInfo)
	syncSnat := false
	if logger == nil {
		logger = agent.log.WithFields(logrus.Fields{})
	}
	logger.Debug("Snat Global info Changed...")
	globalInfo := snat.Spec.GlobalInfos
	// This case is possible when all the pods will be deleted from that node
	if len(globalInfo) < len(agent.opflexSnatGlobalInfos) {
		for nodename, _ := range agent.opflexSnatGlobalInfos {
			if _, ok := globalInfo[nodename]; !ok {
				delete(agent.opflexSnatGlobalInfos, nodename)
				syncSnat = true
			}
		}
	}
	agent.log.Debug("Snat Gobal Obj Map: ", globalInfo)
	for nodename, val := range globalInfo {
		var newglobalinfos []*OpflexSnatGlobalInfo
		for _, v := range val {
			portrange := make([]OpflexPortRange, 1)
			portrange[0].Start = v.PortRanges[0].Start
			portrange[0].End = v.PortRanges[0].End
			nodeInfo := &OpflexSnatGlobalInfo{
				SnatIp:     v.SnatIp,
				MacAddress: v.MacAddress,
				PortRange:  portrange,
				SnatIpUid:  v.SnatIpUid,
				Protocols:  v.Protocols,
			}
			newglobalinfos = append(newglobalinfos, nodeInfo)
		}
		existing, ok := agent.opflexSnatGlobalInfos[nodename]
		if (ok && !reflect.DeepEqual(existing, newglobalinfos)) || !ok {
			agent.opflexSnatGlobalInfos[nodename] = newglobalinfos
			syncSnat = true
		}
	}
	agent.log.Debug("Snat Gobal Obj Map: ", agent.opflexSnatGlobalInfos)
	if syncSnat {
		agent.scheduleSyncSnats()
	}
}
func (agent *HostAgent) snatLocalInfoDelete(obj interface{}) {
	agent.log.Debug("Snat Delete Obj")
	snat := obj.(*snatlocal.SnatLocalInfo)
	localInfo := snat.Spec.LocalInfos
	syncep := false
	for poduid, _ := range localInfo {
		if _, ok := agent.opflexSnatLocalInfos[poduid]; ok {
			if _, ok := agent.opflexEps[poduid]; ok {
				// if pod present mark it snat ip deleted for local info
				agent.opflexSnatLocalInfos[poduid].MarkDelete = true
				syncep = true
			} else {
				delete(agent.opflexSnatLocalInfos, poduid)
			}
		}
	}
	if syncep {
		agent.scheduleSyncEps()
	}
}

func (agent *HostAgent) snatGlobalInfoDelete(obj interface{}) {
	agent.log.Debug("Snat Delete Obj")
	snat := obj.(*snatglobal.SnatGlobalInfo)
	globalInfo := snat.Spec.GlobalInfos
	for nodename, _ := range globalInfo {
		if _, ok := agent.opflexSnatGlobalInfos[nodename]; ok {
			delete(agent.opflexSnatGlobalInfos, nodename)
		}
	}
	agent.scheduleSyncSnats()
}

func (agent *HostAgent) syncSnat() bool {
	if !agent.syncEnabled {
		return false
	}
	agent.log.Debug("Syncing snats")
	agent.indexMutex.Lock()
	opflexSnatIps := make(map[string]*OpflexSnatIp)
	remoteinfo := make([]OpflexSnatIpRemoteInfo, 0)
	local := make(map[string]bool)
	//set all the local SnatIp's
	for _, v := range agent.opflexSnatLocalInfos {
		local[v.SnatIp] = true
	}
	// get the latest remote info
	for nodename, v := range agent.opflexSnatGlobalInfos {
		for _, ginfo := range v {
			if nodename != agent.config.NodeName {
				var remote OpflexSnatIpRemoteInfo
				remote.MacAddress = ginfo.MacAddress
				remote.PortRange = ginfo.PortRange
				remoteinfo = append(remoteinfo, remote)
			}
		}
	}
	agent.log.Debug("Remte Info: ", remoteinfo)
	// set the Opflex Snat IP information
	var localportrange []OpflexPortRange
	for nodename, v := range agent.opflexSnatGlobalInfos {
		for _, ginfo := range v {
			var snatinfo OpflexSnatIp
			// set the local portrange
			if nodename == agent.config.NodeName && local[ginfo.SnatIp] {
				localportrange = ginfo.PortRange
			}
			snatinfo.InterfaceName = agent.config.UplinkIface
			snatinfo.InterfaceVlan = agent.config.ServiceVlan
			if local[ginfo.SnatIp] {
				snatinfo.PortRange = localportrange
			}
			snatinfo.Local = local[ginfo.SnatIp]
			snatinfo.SnatIp = ginfo.SnatIp
			snatinfo.Uuid = ginfo.SnatIpUid
			snatinfo.Remote = remoteinfo
			opflexSnatIps[ginfo.SnatIp] = &snatinfo
			agent.log.Debug("Opflex Snat data IP: ", opflexSnatIps[ginfo.SnatIp])
		}
	}
	agent.indexMutex.Unlock()
	files, err := ioutil.ReadDir(agent.config.OpFlexSnatDir)
	if err != nil {
		agent.log.WithFields(
			logrus.Fields{"SnatDir": agent.config.OpFlexSnatDir},
		).Error("Could not read directory " + err.Error())
		return true
	}
	seen := make(map[string]bool)
	for _, f := range files {
		uuid := f.Name()
		if strings.HasSuffix(uuid, ".snat") {
			uuid = uuid[:len(uuid)-5]
		} else {
			continue
		}

		snatfile := filepath.Join(agent.config.OpFlexSnatDir, f.Name())
		logger := agent.log.WithFields(
			logrus.Fields{"Uuid": uuid})
		existing, ok := opflexSnatIps[uuid]
		if ok {
			fmt.Printf("snatfile:%s\n", snatfile)
			wrote, err := writeSnat(snatfile, existing)
			if err != nil {
				opflexSnatIpLogger(agent.log, existing).Error("Error writing snat file: ", err)
			} else if wrote {
				opflexSnatIpLogger(agent.log, existing).Info("Updated snat")
			}
			seen[uuid] = true
		} else {
			logger.Info("Removing snat")
			os.Remove(snatfile)
		}
	}
	for _, snat := range opflexSnatIps {
		if seen[snat.Uuid] {
			continue
		}
		opflexSnatIpLogger(agent.log, snat).Info("Adding Snat")
		snatfile :=
			agent.FormSnatFilePath(snat.Uuid)
		_, err = writeSnat(snatfile, snat)
		if err != nil {
			opflexSnatIpLogger(agent.log, snat).
				Error("Error writing snat file: ", err)
		}
	}
	agent.log.Debug("Finished snat sync")
	return false
}
