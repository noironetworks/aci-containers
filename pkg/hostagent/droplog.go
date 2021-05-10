// Copyright 2021 Cisco Systems, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Handlers for Droplog updates.

package hostagent

import (
	"encoding/json"
	droplog "github.com/noironetworks/aci-containers/pkg/droplog/apis/aci.droplog/v1alpha1"
	droplogclientset "github.com/noironetworks/aci-containers/pkg/droplog/clientset/versioned"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/tools/cache"
	"k8s.io/kubernetes/pkg/controller"
	//"path/filepath"
	"reflect"
)

const DropLogCfgFile = "a.droplogcfg"

// This structure is to write to a.droplogcfg file under opflexagent droplog directory
type dropLogData struct {
	DisableDropLog bool             `json:"drop-log-disable,omitempty"`
	DropLogMode    string           `json:"drop-log-mode,omitempty"`
	DropLogPrune   []dropLogPruning `json:"drop-log-pruning,omitempty"`
}

type dropLogPruning struct {
	Name    string `json:"name"`
	SrcIP   string `json:"src-ip,omitempty"`
	DstIP   string `json:"dest-ip,omitempty"`
	SrcMac  string `json:"src-mac,omitempty"`
	DstMac  string `json:"dest-mac,omitempty"`
	SrcPort uint16 `json:"src-port,omitempty"`
	DstPort uint16 `json:"dest-port,omitempty"`
	IpProto uint8  `json:"ip-proto,omitempty"`
}

func writeDropLogCfg(droplogcfg string, drplog *dropLogData) (bool, error) {
	newdata, err := json.MarshalIndent(drplog, "", "  ")
	if err != nil {
		return true, err
	}
	existingdata, err := ioutil.ReadFile(droplogcfg)
	if err == nil && reflect.DeepEqual(existingdata, newdata) {
		return false, nil
	}
	err = ioutil.WriteFile(droplogcfg, newdata, 0644)
	return true, err
}

func EnableDropLogLogger(log *logrus.Logger, endroplog *droplog.EnableDropLog) *logrus.Entry {
	return log.WithFields(logrus.Fields{
		"namespace": endroplog.ObjectMeta.Namespace,
		"name":      endroplog.ObjectMeta.Name,
		"spec":      endroplog.Spec,
	})
}

func PruneDropLogLogger(log *logrus.Logger, prdroplog *droplog.PruneDropLog) *logrus.Entry {
	return log.WithFields(logrus.Fields{
		"namespace": prdroplog.ObjectMeta.Namespace,
		"name":      prdroplog.ObjectMeta.Name,
		"spec":      prdroplog.Spec,
	})
}

func (agent *HostAgent) initEnableDropLogInformerFromClient(
	dropLogClient *droplogclientset.Clientset) {
	agent.initEnableDropLogInformerBase(
		cache.NewListWatchFromClient(
			dropLogClient.AciV1alpha1().RESTClient(), "enabledroplogs",
			metav1.NamespaceAll, fields.Everything()))
}

func (agent *HostAgent) initPruneDropLogInformerFromClient(
	dropLogClient *droplogclientset.Clientset) {
	agent.initPruneDropLogInformerBase(
		cache.NewListWatchFromClient(
			dropLogClient.AciV1alpha1().RESTClient(), "prunedroplogs",
			metav1.NamespaceAll, fields.Everything()))
}

func (agent *HostAgent) initEnableDropLogInformerBase(listWatch *cache.ListWatch) {
	agent.enableDropLogInformer = cache.NewSharedIndexInformer(
		listWatch, &droplog.EnableDropLog{}, controller.NoResyncPeriodFunc(),
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)

	agent.enableDropLogInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			agent.enableDropLogUpdated(obj)
		},
		UpdateFunc: func(_ interface{}, obj interface{}) {
			agent.enableDropLogUpdated(obj)
		},
		DeleteFunc: func(obj interface{}) {
			agent.enableDropLogDeleted(obj)
		},
	})
	agent.log.Info("Initializing enable droplog informers")
}

func (agent *HostAgent) initPruneDropLogInformerBase(listWatch *cache.ListWatch) {
	agent.pruneDropLogInformer = cache.NewSharedIndexInformer(
		listWatch, &droplog.PruneDropLog{}, controller.NoResyncPeriodFunc(),
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)

	agent.pruneDropLogInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			agent.pruneDropLogUpdated(obj)
		},
		UpdateFunc: func(_ interface{}, obj interface{}) {
			agent.pruneDropLogUpdated(obj)
		},
		DeleteFunc: func(obj interface{}) {
			agent.pruneDropLogDeleted(obj)
		},
	})
	agent.log.Info("Initializing prune droplog informers")
}

func (agent *HostAgent) enableDropLogUpdated(obj interface{}) {
	dropLog, ok := obj.(*droplog.EnableDropLog)
	if !ok {
		agent.log.Error("enableDropLogUpdated: Bad object type")
		return
	}
	// key, err := cache.MetaNamespaceKeyFunc(dropLog)
	// if err != nil {
	// EnableDropLogLogger(agent.log, dropLog).
	// Error("Could not create droplog key:" + err.Error())
	// return
	// }
	//agent.queueDropLogUpdateByKey(key)
	agent.log.Info("enable droplog updated: ", dropLog.ObjectMeta.Name)
}

func (agent *HostAgent) pruneDropLogUpdated(obj interface{}) {
	dropLog, ok := obj.(*droplog.PruneDropLog)
	if !ok {
		agent.log.Error("pruneDropLogUpdated: Bad object type")
		return
	}
	// key, err := cache.MetaNamespaceKeyFunc(dropLog)
	// if err != nil {
	// PruneDropLogLogger(agent.log, dropLog).
	// Error("Could not create droplog key:" + err.Error())
	// return
	// }
	//agent.queueDropLogUpdateByKey(key)
	agent.log.Info("prune droplog updated: ", dropLog.ObjectMeta.Name)
}

func (agent *HostAgent) enableDropLogDeleted(obj interface{}) {
	agent.indexMutex.Lock()
	defer agent.indexMutex.Unlock()
	dropLog := obj.(*droplog.EnableDropLog)
	agent.log.Info("enable droplog deleted: ", dropLog.ObjectMeta.Name)
}

func (agent *HostAgent) pruneDropLogDeleted(obj interface{}) {
	agent.indexMutex.Lock()
	defer agent.indexMutex.Unlock()
	dropLog := obj.(*droplog.PruneDropLog)
	agent.log.Info("prune droplog deleted: ", dropLog.ObjectMeta.Name)
}

// func (agent *HostAgent) queueDropLogUpdateByKey(key string) {
// droplogobj, exists, err := agent.dropLogInformer.GetStore().GetByKey(key)
// if err != nil {
// agent.log.Error("Could not lookup droplog for " +
// key + ": " + err.Error())
// return
// }
// if !exists || droplogobj == nil {
// return
// }
// dp := droplogobj.(*droplog.DropLog)
// dpdata := droplogobj.(*dropLogData)
// dpprune := droplogobj.(*droplog.DropLogPruning)
// agent.populateDropLogCfg(dp, dpdata, dpprune)
// agent.log.Debug("Queuing droplog update by key")
// }

// func (agent *HostAgent) populateDropLogCfg(dp *droplog.DropLog, dpdata *dropLogData,
// dpprune *droplog.DropLogPruning) {
// if agent.config.OpFlexDropLogConfigDir == "" {
// agent.log.Error("OpFlex DropLog directory not set")
// return
// }
// dropLogFilePath := filepath.Join(agent.config.OpFlexDropLogConfigDir, DropLogCfgFile)
// dropLogFileExists := fileExists(dropLogFilePath)
// if !dropLogFileExists {
// agent.log.Debug("Drop log config file does not exist at: ", dropLogFilePath)
// return
// }

// droplog := &dropLogData{
// DisableDropLog: dp.Spec.DisableDroplog,
// DropLogMode:    dp.Spec.DropLogMode,
// DropLogPrune:   make([]dropLogPruning, 0),
// }

// for _, val := range dp.Spec.DropLogPrune {
// agent.log.Debug("Iterating: ", val)
// filter := &dropLogPruning{
// Name:    dp.ObjectMeta.Name,
// SrcIP:   dpprune.SrcIP,
// DstIP:   dpprune.DstIP,
// SrcMac:  dpprune.SrcMac,
// DstMac:  dpprune.DstMac,
// SrcPort: uint16(dpprune.SrcPort),
// DstPort: uint16(dpprune.DstPort),
// IpProto: uint8(dpprune.IpProto),
// }
// droplog.DropLogPrune = append(droplog.DropLogPrune, *filter)
// }

// wrote, err := writeDropLogCfg(dropLogFilePath, droplog)
// if err != nil {
// agent.log.Warn("Unable to write to drop log config file: ", err.Error())
// } else if wrote {
// agent.log.Debug("Updated drop log info at: ", dropLogFilePath)
// }
// return
// }
