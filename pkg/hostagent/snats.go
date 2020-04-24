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
// WITHOUT WARRATIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Handlers for snat updates.

package hostagent

import (
	"encoding/json"
	"fmt"
	"github.com/sirupsen/logrus"
	snatglobal "github.com/noironetworks/aci-containers/pkg/snatglobalinfo/apis/aci.snat/v1"
	snatglobalclset "github.com/noironetworks/aci-containers/pkg/snatglobalinfo/clientset/versioned"
	snatlocal "github.com/noironetworks/aci-containers/pkg/snatlocalinfo/apis/aci.snat/v1"
	snatpolicy "github.com/noironetworks/aci-containers/pkg/snatpolicy/apis/aci.snat/v1"
	snatpolicyclset "github.com/noironetworks/aci-containers/pkg/snatpolicy/clientset/versioned"
	"github.com/noironetworks/aci-containers/pkg/util"
	"io/ioutil"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
	"k8s.io/kubernetes/pkg/controller"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
)

// Filename used to create external service file on host
// example snat-external.service
const SnatService = "snat-external"

type ResourceType int

const (
	POD ResourceType = 1 << iota
	SERVICE
	DEPLOYMENT
	NAMESPACE
	CLUSTER
	INVALID
)

type OpflexPortRange struct {
	Start int `json:"start,omitempty"`
	End   int `json:"end,omitempty"`
}

// This structure is to write the  SnatFile
type OpflexSnatIp struct {
	Uuid          string                   `json:"uuid"`
	InterfaceName string                   `json:"interface-name,omitempty"`
	SnatIp        string                   `json:"snat-ip,omitempty"`
	InterfaceMac  string                   `json:"interface-mac,omitempty"`
	Local         bool                     `json:"local,omitempty"`
	DestIpAddress []string                 `json:"dest,omitempty"`
	PortRange     []OpflexPortRange        `json:"port-range,omitempty"`
	InterfaceVlan uint                     `json:"interface-vlan,omitempty"`
	Zone          uint                     `json:"zone,omitempty"`
	Remote        []OpflexSnatIpRemoteInfo `json:"remote,omitempty"`
}

// This Structure is to calculate remote Info
type OpflexSnatIpRemoteInfo struct {
	NodeIp     string            `json:"snat_ip,omitempty"`
	MacAddress string            `json:"mac,omitempty"`
	PortRange  []OpflexPortRange `json:"port-range,omitempty"`
	Refcount   int               `json:"ref,omitempty"`
}

type opflexSnatGlobalInfo struct {
	SnatIp         string
	MacAddress     string
	PortRange      []OpflexPortRange
	SnatIpUid      string
	SnatPolicyName string
}

type opflexSnatLocalInfo struct {
	Snatpolicies map[ResourceType][]string //Each resource can represent multiple entries
	PlcyUuids    []string                  //sorted policy uuids
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

func (agent *HostAgent) initSnatPolicyInformerFromClient(
	snatClient *snatpolicyclset.Clientset) {
	agent.initSnatPolicyInformerBase(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				return snatClient.AciV1().SnatPolicies().List(options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				return snatClient.AciV1().SnatPolicies().Watch(options)
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
	agent.log.Info("Initializing SnatGlobal Info Informers")
}

func (agent *HostAgent) initSnatPolicyInformerBase(listWatch *cache.ListWatch) {
	agent.snatPolicyInformer = cache.NewSharedIndexInformer(
		listWatch,
		&snatpolicy.SnatPolicy{}, controller.NoResyncPeriodFunc(),
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	agent.snatPolicyInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			agent.snatPolicyAdded(obj)
		},
		UpdateFunc: func(oldobj interface{}, newobj interface{}) {
			agent.snatPolicyUpdated(oldobj, newobj)
		},
		DeleteFunc: func(obj interface{}) {
			agent.snatPolicyDeleted(obj)
		},
	})
	agent.log.Infof("Initializing Snat Policy Informers")
}

func (agent *HostAgent) snatPolicyAdded(obj interface{}) {
	agent.indexMutex.Lock()
	defer agent.indexMutex.Unlock()
	agent.log.Info("Policy Info Added: ")
	policyinfo := obj.(*snatpolicy.SnatPolicy)
	agent.log.Info("Policy Info Added: ", policyinfo.ObjectMeta.Name)
	if policyinfo.Status.State != snatpolicy.Ready {
		return
	}
	agent.snatPolicyCache[policyinfo.ObjectMeta.Name] = policyinfo
	setDestIp(agent.snatPolicyCache[policyinfo.ObjectMeta.Name].Spec.DestIp)
	agent.handleSnatUpdate(policyinfo)
}

func (agent *HostAgent) snatPolicyUpdated(oldobj interface{}, newobj interface{}) {
	agent.indexMutex.Lock()
	defer agent.indexMutex.Unlock()
	oldpolicyinfo := oldobj.(*snatpolicy.SnatPolicy)
	newpolicyinfo := newobj.(*snatpolicy.SnatPolicy)
	agent.log.Info("Policy Info Updated: ", newpolicyinfo.ObjectMeta.Name)
	agent.log.Info("Policy Status: ", newpolicyinfo.Status.State)
	if reflect.DeepEqual(oldpolicyinfo, newpolicyinfo) {
		return
	}
	//1. check if the local nodename is  present in globalinfo
	// 2. if it is not present then delete the policy from localInfo as the portinfo is not allocated  for node
	if newpolicyinfo.Status.State == snatpolicy.IpPortsExhausted {
		agent.log.Info("Ports exhausted: ", newpolicyinfo.ObjectMeta.Name)
		ginfo, ok := agent.opflexSnatGlobalInfos[agent.config.NodeName]
		present := false
		if ok {
			for _, v := range ginfo {
				if v.SnatPolicyName == newpolicyinfo.ObjectMeta.Name {
					present = true
				}
			}
		}
		if !ok || !present {
			agent.log.Info("Delete Policy: ", newpolicyinfo.ObjectMeta.Name)
			agent.deletePolicy(newpolicyinfo, false)
		}
		return
	}
	if newpolicyinfo.Status.State != snatpolicy.Ready {
		return
	}
	agent.snatPolicyCache[newpolicyinfo.ObjectMeta.Name] = newpolicyinfo
	setDestIp(agent.snatPolicyCache[newpolicyinfo.ObjectMeta.Name].Spec.DestIp)
	// After Validation of SnatPolicy State will be set to Ready
	if newpolicyinfo.Status.State != oldpolicyinfo.Status.State {
		agent.handleSnatUpdate(newpolicyinfo)
		return
	}
	update := true
	// updateEpFile
	//TODO need to revisit the code is it  good to update first and then delete
	if !reflect.DeepEqual(oldpolicyinfo.Spec.Selector,
		newpolicyinfo.Spec.Selector) {
		// remove poduids matching the policy
		var poduids []string
		for uuid, res := range agent.snatPods[newpolicyinfo.ObjectMeta.Name] {
			agent.deleteSnatLocalInfo(uuid, res, newpolicyinfo.ObjectMeta.Name)
			poduids = append(poduids, uuid)
		}
		agent.updateEpFiles(poduids)
		agent.handleSnatUpdate(newpolicyinfo)
		// this trigger handles if handle snatUpdate don't match any pod
		if len(poduids) > 0 {
			agent.scheduleSyncNodeInfo()
		}
		update = false
	}
	// destination update can be ignored  if labels also changed
	if !reflect.DeepEqual(oldpolicyinfo.Spec.DestIp,
		newpolicyinfo.Spec.DestIp) && update {
		// updateEpFile
		// SyncSnatFile
		var poduids []string
		for uid := range agent.snatPods[newpolicyinfo.ObjectMeta.Name] {
			poduids = append(poduids, uid)
		}
		agent.updateEpFiles(poduids)
		agent.scheduleSyncSnats()
	}

}

func (agent *HostAgent) snatPolicyDeleted(obj interface{}) {
	agent.indexMutex.Lock()
	defer agent.indexMutex.Unlock()
	policyinfo := obj.(*snatpolicy.SnatPolicy)
	agent.deletePolicy(policyinfo, true)
	delete(agent.snatPolicyCache, policyinfo.ObjectMeta.Name)
}

func (agent *HostAgent) handleSnatUpdate(policy *snatpolicy.SnatPolicy) {
	// First Parse the policy and check for applicability
	// list all the Pods based on labels and namespace
	agent.log.Debug("Handle snatUpdate: ", policy)
	_, err := cache.MetaNamespaceKeyFunc(policy)
	if err != nil {
		return
	}
	// 1.List the targets matching the policy based on policy config
	uids := make(map[ResourceType][]string)
	switch {
	case len(policy.Spec.SnatIp) == 0:
		//handle policy for service pods
		var services []*v1.Service
		var poduids []string
		selector := labels.SelectorFromSet(labels.Set(policy.Spec.Selector.Labels))
		cache.ListAll(agent.serviceInformer.GetIndexer(), selector,
			func(servobj interface{}) {
				services = append(services, servobj.(*v1.Service))
			})
		// list the pods and apply the policy at service target
		for _, service := range services {
			uids, _ := agent.getPodsMatchingObjet(service, policy.ObjectMeta.Name)
			poduids = append(poduids, uids...)
		}
		uids[SERVICE] = poduids
	case reflect.DeepEqual(policy.Spec.Selector, snatpolicy.PodSelector{}):
		// This Policy will be applied at cluster level
		var poduids []string
		// handle policy for cluster
		for k, _ := range agent.opflexEps {
			poduids = append(poduids, k)
		}
		uids[CLUSTER] = poduids
	case len(policy.Spec.Selector.Labels) == 0:
		// This is namespace based policy
		var poduids []string
		cache.ListAllByNamespace(agent.podInformer.GetIndexer(), policy.Spec.Selector.Namespace, labels.Everything(),
			func(podobj interface{}) {
				pod := podobj.(*v1.Pod)
				if pod.Spec.NodeName == agent.config.NodeName {
					poduids = append(poduids, string(pod.ObjectMeta.UID))
				}
			})
		uids[NAMESPACE] = poduids
	default:
		poduids, deppoduids, nspoduids :=
			agent.getPodUidsMatchingLabel(policy.Spec.Selector.Namespace, policy.Spec.Selector.Labels, policy.ObjectMeta.Name)
		uids[POD] = poduids
		uids[DEPLOYMENT] = deppoduids
		uids[NAMESPACE] = nspoduids
	}
	for res, poduids := range uids {
		agent.applyPolicy(poduids, res, policy.GetName())
	}
}

// Get all the pods matching the Policy Selector
func (agent *HostAgent) getPodUidsMatchingLabel(namespace string, label map[string]string, policyname string) (poduids []string,
	deppoduids []string, nspoduids []string) {
	selector := labels.SelectorFromSet(labels.Set(label))
	cache.ListAll(agent.podInformer.GetIndexer(), selector,
		func(podobj interface{}) {
			pod := podobj.(*v1.Pod)
			if pod.Spec.NodeName == agent.config.NodeName {
				key, _ := cache.MetaNamespaceKeyFunc(podobj)
				poduids = append(poduids, string(pod.ObjectMeta.UID))
				if _, ok := agent.snatPolicyLabels[key]; ok {
					agent.snatPolicyLabels[key][policyname] = POD
				}
			}
		})
	cache.ListAll(agent.depInformer.GetIndexer(), selector,
		func(depobj interface{}) {
			key, _ := cache.MetaNamespaceKeyFunc(depobj)
			dep := depobj.(*appsv1.Deployment)
			uids, _ := agent.getPodsMatchingObjet(dep, policyname)
			deppoduids = append(deppoduids, uids...)
			if len(deppoduids) > 0 {
				if _, ok := agent.snatPolicyLabels[key]; ok {
					agent.snatPolicyLabels[key][policyname] = DEPLOYMENT
				}
			}
		})
	cache.ListAll(agent.nsInformer.GetIndexer(), selector,
		func(nsobj interface{}) {
			ns := nsobj.(*v1.Namespace)
			key, _ := cache.MetaNamespaceKeyFunc(nsobj)
			uids, _ := agent.getPodsMatchingObjet(ns, policyname)
			nspoduids = append(nspoduids, uids...)
			if len(nspoduids) > 0 {
				if _, ok := agent.snatPolicyLabels[key]; ok {
					agent.snatPolicyLabels[key][policyname] = NAMESPACE
				}
			}
		})
	return
}

// Apply the Policy at Resource level
func (agent *HostAgent) applyPolicy(poduids []string, res ResourceType, snatPolicyName string) {
	nodeUpdate := false
	if len(poduids) == 0 {
		return
	}
	if _, ok := agent.snatPods[snatPolicyName]; !ok {
		agent.snatPods[snatPolicyName] = make(map[string]ResourceType)
		nodeUpdate = true
	}
	for _, uid := range poduids {
		_, ok := agent.opflexSnatLocalInfos[uid]
		if !ok {
			var localinfo opflexSnatLocalInfo
			localinfo.Snatpolicies = make(map[ResourceType][]string)
			localinfo.Snatpolicies[res] = append(localinfo.Snatpolicies[res], snatPolicyName)
			agent.opflexSnatLocalInfos[uid] = &localinfo
			agent.snatPods[snatPolicyName][uid] |= res
			agent.log.Debug("applypolicy Res: ", agent.snatPods[snatPolicyName][uid])

		} else {
			present := false
			for _, name := range agent.opflexSnatLocalInfos[uid].Snatpolicies[res] {
				if name == snatPolicyName {
					present = true
				}
			}
			if present == false {
				agent.opflexSnatLocalInfos[uid].Snatpolicies[res] =
					append(agent.opflexSnatLocalInfos[uid].Snatpolicies[res], snatPolicyName)
				agent.snatPods[snatPolicyName][uid] |= res
				agent.log.Debug("applypolicy Res: ", agent.snatPods[snatPolicyName][uid])
			}
		}
	}
	if nodeUpdate == true {
		agent.log.Debug("Schedule the node Sync:")
		agent.scheduleSyncNodeInfo()
	} else {
		// trigger update  the epfile
		agent.updateEpFiles(poduids)
	}
	return
}

// Sync the NodeInfo
func (agent *HostAgent) syncSnatNodeInfo() bool {
	if !agent.syncEnabled {
		return false
	}
	snatPolicyNames := make(map[string]struct{})
	agent.indexMutex.Lock()
	var dummy struct{}
	for key, val := range agent.snatPods {
		if len(val) > 0 {
			snatPolicyNames[key] = dummy
		}
	}
	agent.indexMutex.Unlock()
	env := agent.env.(*K8sEnvironment)
	if env == nil {
		return false
	}
	// send nodeupdate for the policy names
	if agent.InformNodeInfo(env.nodeInfo, snatPolicyNames) == false {
		agent.log.Debug("Failed to update retry: ", snatPolicyNames)
		return true
	}
	agent.log.Debug("Updated Node Info: ", snatPolicyNames)
	return false
}

func (agent *HostAgent) deletePolicy(policy *snatpolicy.SnatPolicy, sync bool) {
	pods, ok := agent.snatPods[policy.GetName()]
	var poduids []string
	if !ok {
		return
	}
	for uuid, res := range pods {
		agent.deleteSnatLocalInfo(uuid, res, policy.GetName())
		poduids = append(poduids, uuid)
	}
	agent.updateEpFiles(poduids)
	delete(agent.snatPods, policy.GetName())
	agent.log.Info("SnatPolicy deleted update Nodeinfo: ", policy.GetName())
	if sync {
		agent.scheduleSyncNodeInfo()
	}
	return
}

func (agent *HostAgent) deleteSnatLocalInfo(poduid string, res ResourceType, plcyname string) {
	localinfo, ok := agent.opflexSnatLocalInfos[poduid]
	if ok {
		i := uint(0)
		j := uint(0)
		// loop through all the resources matching the policy
		for i < uint(res) {
			i = 1 << j
			j = j + 1
			if i&uint(res) == i {
				length := len(localinfo.Snatpolicies[ResourceType(i)])
				deletedcount := 0
				for k := 0; k < length; k++ {
					l := k - deletedcount
					// delete the matching policy from  policy stack
					if plcyname == localinfo.Snatpolicies[ResourceType(i)][l] {
						agent.log.Info("Delete the Policy name: ", plcyname)
						localinfo.Snatpolicies[ResourceType(i)] =
							append(localinfo.Snatpolicies[ResourceType(i)][:l],
								localinfo.Snatpolicies[ResourceType(i)][l+1:]...)
						deletedcount++
					}
				}
				agent.log.Debug("Opflex agent and localinfo ", agent.opflexSnatLocalInfos[poduid], localinfo)
				if len(localinfo.Snatpolicies[res]) == 0 {
					delete(localinfo.Snatpolicies, res)
				}
				if v, ok := agent.snatPods[plcyname]; ok {
					if _, ok := v[poduid]; ok {
						agent.snatPods[plcyname][poduid] &= ^(res) // clear the bit
						agent.log.Debug("Res:  ", agent.snatPods[plcyname][poduid])
						if agent.snatPods[plcyname][poduid] == 0 { // delete the pod if no resource is pointing for the policy
							delete(agent.snatPods[plcyname], poduid)
							if len(agent.snatPods[plcyname]) == 0 {
								delete(agent.snatPods, plcyname)
							}
						}
					}
				}
			}
		}
	}
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
	agent.log.Info("Snat Global Object added/Updated ", snat)
	agent.doUpdateSnatGlobalInfo(key)
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

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func (agent *HostAgent) snaGlobalInfoChanged(snatobj interface{}, logger *logrus.Entry) {
	snat := snatobj.(*snatglobal.SnatGlobalInfo)
	syncSnat := false
	updateLocalInfo := false
	if logger == nil {
		logger = agent.log.WithFields(logrus.Fields{})
	}
	logger.Debug("Snat Global info Changed...")
	globalInfo := snat.Spec.GlobalInfos
	// This case is possible when all the pods will be deleted from that node
	if len(globalInfo) < len(agent.opflexSnatGlobalInfos) {
		for nodename := range agent.opflexSnatGlobalInfos {
			if _, ok := globalInfo[nodename]; !ok {
				delete(agent.opflexSnatGlobalInfos, nodename)
				syncSnat = true
			}
		}
	}
	for nodename, val := range globalInfo {
		var newglobalinfos []*opflexSnatGlobalInfo
		for _, v := range val {
			portrange := make([]OpflexPortRange, 1)
			portrange[0].Start = v.PortRanges[0].Start
			portrange[0].End = v.PortRanges[0].End
			nodeInfo := &opflexSnatGlobalInfo{
				SnatIp:         v.SnatIp,
				MacAddress:     v.MacAddress,
				PortRange:      portrange,
				SnatIpUid:      v.SnatIpUid,
				SnatPolicyName: v.SnatPolicyName,
			}
			newglobalinfos = append(newglobalinfos, nodeInfo)
		}
		existing, ok := agent.opflexSnatGlobalInfos[nodename]
		if (ok && !reflect.DeepEqual(existing, newglobalinfos)) || !ok {
			agent.opflexSnatGlobalInfos[nodename] = newglobalinfos
			if nodename == agent.config.NodeName {
				updateLocalInfo = true
			}
			syncSnat = true
		}
	}

	snatFileName := SnatService + ".service"
	filePath := filepath.Join(agent.config.OpFlexServiceDir, snatFileName)
	file_exists := fileExists(filePath)
	if len(agent.opflexSnatGlobalInfos) > 0 {
		// if more than one global infos, create snat ext file
		as := &opflexService{
			Uuid:              SnatService,
			DomainPolicySpace: agent.config.AciVrfTenant,
			DomainName:        agent.config.AciVrf,
			ServiceMode:       "loadbalancer",
			ServiceMappings:   make([]opflexServiceMapping, 0),
			InterfaceName:     agent.config.UplinkIface,
			InterfaceVlan:     uint16(agent.config.ServiceVlan),
			ServiceMac:        agent.config.UplinkMacAdress,
			InterfaceIp:       agent.serviceEp.Ipv4.String(),
		}
		sm := &opflexServiceMapping{
			Conntrack: true,
		}
		as.ServiceMappings = append(as.ServiceMappings, *sm)
		agent.opflexServices[SnatService] = as
		if !file_exists {
			wrote, err := writeAs(filePath, as)
			if err != nil {
				agent.log.Debug("Unable to write snat ext service file:")
			} else if wrote {
				agent.log.Debug("Created snat ext service file")
			}

		}
	} else {
		delete(agent.opflexServices, SnatService)
		// delete snat service file if no global infos exist
		if file_exists {
			err := os.Remove(filePath)
			if err != nil {
				agent.log.Debug("Unable to delete snat ext service file")
			} else {
				agent.log.Debug("Deleted snat ext service file")
			}
		}
	}
	if syncSnat {
		agent.scheduleSyncSnats()
	}
	if updateLocalInfo {
		var poduids []string
		for _, v := range agent.opflexSnatGlobalInfos[agent.config.NodeName] {
			for uuid, _ := range agent.snatPods[v.SnatPolicyName] {
				poduids = append(poduids, uuid)
			}
		}
		agent.log.Info("Updating EpFile GlobalInfo Context: ", poduids)
		agent.updateEpFiles(poduids)
	}
}

func (agent *HostAgent) snatGlobalInfoDelete(obj interface{}) {
	agent.log.Debug("Snat Global Info Obj Delete")
	snat := obj.(*snatglobal.SnatGlobalInfo)
	globalInfo := snat.Spec.GlobalInfos
	for nodename := range globalInfo {
		if _, ok := agent.opflexSnatGlobalInfos[nodename]; ok {
			delete(agent.opflexSnatGlobalInfos, nodename)
		}
	}
}

func (agent *HostAgent) syncSnat() bool {
	if !agent.syncEnabled {
		return false
	}
	agent.log.Debug("Syncing snats")
	agent.indexMutex.Lock()
	opflexSnatIps := make(map[string]*OpflexSnatIp)
	remoteinfo := make(map[string][]OpflexSnatIpRemoteInfo)
	// set the remote info for every snatIp
	for nodename, v := range agent.opflexSnatGlobalInfos {
		for _, ginfo := range v {
			if nodename != agent.config.NodeName {
				var remote OpflexSnatIpRemoteInfo
				remote.MacAddress = ginfo.MacAddress
				remote.PortRange = ginfo.PortRange
				remoteinfo[ginfo.SnatIp] = append(remoteinfo[ginfo.SnatIp], remote)
			}
		}
	}
	agent.log.Debug("RemoteInfo: ", remoteinfo)
	// set the Opflex Snat IP information
	localportrange := make(map[string][]OpflexPortRange)
	ginfos, ok := agent.opflexSnatGlobalInfos[agent.config.NodeName]

	if ok {
		for _, ginfo := range ginfos {
			localportrange[ginfo.SnatIp] = ginfo.PortRange
		}
	}

	for _, v := range agent.opflexSnatGlobalInfos {
		for _, ginfo := range v {
			var snatinfo OpflexSnatIp
			// set the local portrange
			snatinfo.InterfaceName = agent.config.UplinkIface
			snatinfo.InterfaceVlan = agent.config.ServiceVlan
			snatinfo.InterfaceMac = agent.config.UplinkMacAdress
			snatinfo.Local = false
			if _, ok := localportrange[ginfo.SnatIp]; ok {
				snatinfo.PortRange = localportrange[ginfo.SnatIp]
				// need to sort the order
				if _, ok := agent.snatPolicyCache[ginfo.SnatPolicyName]; ok {
					if len(agent.snatPolicyCache[ginfo.SnatPolicyName].Spec.DestIp) == 0 {
						snatinfo.DestIpAddress = []string{"0.0.0.0/0"}
					} else {
						snatinfo.DestIpAddress =
							agent.snatPolicyCache[ginfo.SnatPolicyName].Spec.DestIp
					}
				}
				snatinfo.Local = true

			}
			snatinfo.SnatIp = ginfo.SnatIp
			snatinfo.Uuid = ginfo.SnatIpUid
			snatinfo.Zone = agent.config.Zone
			snatinfo.Remote = remoteinfo[ginfo.SnatIp]
			opflexSnatIps[ginfo.SnatIp] = &snatinfo
			agent.log.Debug("Opflex Snat data IP: ", opflexSnatIps[ginfo.SnatIp])
		}
	}
	agent.indexMutex.Unlock()
	files, err := ioutil.ReadDir(agent.config.OpFlexSnatDir)
	if err != nil {
		agent.log.WithFields(
			logrus.Fields{"SnatDir: ": agent.config.OpFlexSnatDir},
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

// Get the Pods matching the Object selector
func (agent *HostAgent) getPodsMatchingObjet(obj interface{}, policyname string) (poduids []string, res ResourceType) {
	metadata, err := meta.Accessor(obj)
	if err != nil {
		return
	}
	if agent.isPolicyNameSpaceMatches(policyname, metadata.GetNamespace()) == false {
		return
	}
	switch obj.(type) {
	case *v1.Pod:
		pod, _ := obj.(*v1.Pod)
		poduids = append(poduids, string(pod.ObjectMeta.UID))
		agent.log.Info("Pod uid: ", poduids)
	case *appsv1.Deployment:
		deployment, _ := obj.(*appsv1.Deployment)
		depkey, _ :=
			cache.MetaNamespaceKeyFunc(deployment)
		for _, podkey := range agent.depPods.GetPodForObj(depkey) {
			podobj, exists, err := agent.podInformer.GetStore().GetByKey(podkey)
			if err != nil {
				agent.log.Error("Could not lookup pod: ", err)
				continue
			}
			if !exists || podobj == nil {
				agent.log.Error("Object doesn't exist yet ", podkey)
				continue
			}
			poduids = append(poduids, string(podobj.(*v1.Pod).ObjectMeta.UID))
		}
		agent.log.Info("Deployment Pod uid: ", poduids)
		res = DEPLOYMENT
	case *v1.Service:
		service, _ := obj.(*v1.Service)
		selector := labels.SelectorFromSet(labels.Set(service.Spec.Selector))
		cache.ListAllByNamespace(agent.podInformer.GetIndexer(),
			service.ObjectMeta.Namespace, selector,
			func(podobj interface{}) {
				pod := podobj.(*v1.Pod)
				if pod.Spec.NodeName == agent.config.NodeName {
					poduids = append(poduids, string(pod.ObjectMeta.UID))
				}
			})
		agent.log.Info("Service Pod uid: ", poduids)
		res = SERVICE
	case *v1.Namespace:
		ns, _ := obj.(*v1.Namespace)
		cache.ListAllByNamespace(agent.podInformer.GetIndexer(),
			ns.ObjectMeta.Name, labels.Everything(),
			func(podobj interface{}) {
				pod := podobj.(*v1.Pod)
				if pod.Spec.NodeName == agent.config.NodeName {
					poduids = append(poduids, string(pod.ObjectMeta.UID))
				}
			})
		agent.log.Info("NameSpace: ", poduids)
		res = NAMESPACE
	default:
	}
	return
}

// Updates the EPFile with Snatuuid's
func (agent *HostAgent) updateEpFiles(poduids []string) {
	syncEp := false
	for _, uid := range poduids {
		localinfo, ok := agent.opflexSnatLocalInfos[uid]
		if !ok {
			continue
		}
		agent.log.Debug("Local info: ", localinfo)
		var i uint = 1
		var pos uint = 0
		var policystack []string
		// 1. loop through all the resource hierarchy
		// 2. Compute the Policy Stack
		for ; i <= uint(CLUSTER); i = 1 << pos {
			pos = pos + 1
			seen := make(map[string]bool)
			policies, ok := localinfo.Snatpolicies[ResourceType(i)]
			var sortedpolicies []string
			if ok {
				for _, name := range policies {
					if _, ok := seen[name]; !ok {
						seen[name] = true
						sortedpolicies = append(sortedpolicies, name)
					} else {
						continue
					}
				}
				sort.Slice(sortedpolicies,
					func(i, j int) bool {
						return agent.compare(sortedpolicies[i], sortedpolicies[j])
					})
			}
			policystack = append(policystack, sortedpolicies...)
		}
		var uids []string
		for _, name := range policystack {
			for _, val := range agent.opflexSnatGlobalInfos[agent.config.NodeName] {
				if val.SnatPolicyName == name {
					uids = append(uids, val.SnatIpUid)
				}
			}
			if len(agent.snatPolicyCache[name].Spec.DestIp) == 0 {
				break
			}
		}
		if !reflect.DeepEqual(agent.opflexSnatLocalInfos[uid].PlcyUuids, uids) {
			agent.log.Debug("Update EpFile: ", uids)
			agent.opflexSnatLocalInfos[uid].PlcyUuids = uids
			if len(uids) == 0 {
				delete(agent.opflexSnatLocalInfos, uid)
			}
			syncEp = true
		}
	}
	if syncEp {
		agent.scheduleSyncEps()
	}
}

func (agent *HostAgent) compare(plcy1, plcy2 string) bool {
	sort := false
	for _, a := range agent.snatPolicyCache[plcy1].Spec.DestIp {
		ip_temp := net.ParseIP(a)
		if ip_temp != nil && ip_temp.To4() != nil {
			a = a + "/32"
		}
		for _, b := range agent.snatPolicyCache[plcy2].Spec.DestIp {
			ip_temp := net.ParseIP(b)
			if ip_temp != nil && ip_temp.To4() != nil {
				b = b + "/32"
			}
			ipB, _, _ := net.ParseCIDR(b)
			_, ipnetA, _ := net.ParseCIDR(a)
			ipA, _, _ := net.ParseCIDR(a)
			_, ipnetB, _ := net.ParseCIDR(b)
			switch {
			case ipnetA.Contains(ipB):
				sort = false
			case ipnetB.Contains(ipA):
				sort = true
			default:
				sort = true
			}
		}
	}
	return sort
}

func (agent *HostAgent) getMatchingSnatPolicy(obj interface{}) (snatPolicyNames map[string][]ResourceType) {
	snatPolicyNames = make(map[string][]ResourceType)
	_, err := cache.MetaNamespaceKeyFunc(obj)
	if err != nil {
		return
	}
	metadata, err := meta.Accessor(obj)
	if err != nil {
		return
	}
	namespace := metadata.GetNamespace()
	label := metadata.GetLabels()
	res := getResourceType(obj)
	for _, item := range agent.snatPolicyCache {
		// check for empty policy selctor
		if reflect.DeepEqual(item.Spec.Selector, snatpolicy.PodSelector{}) {
			snatPolicyNames[item.ObjectMeta.Name] =
				append(snatPolicyNames[item.ObjectMeta.Name], CLUSTER)
		} else if len(item.Spec.Selector.Labels) == 0 &&
			item.Spec.Selector.Namespace == namespace { // check policy matches namespace
			if res == SERVICE {
				if len(item.Spec.SnatIp) == 0 {
					snatPolicyNames[item.ObjectMeta.Name] =
						append(snatPolicyNames[item.ObjectMeta.Name], SERVICE)
				}
			} else {
				if len(item.Spec.SnatIp) > 0 {
					snatPolicyNames[item.ObjectMeta.Name] =
						append(snatPolicyNames[item.ObjectMeta.Name], NAMESPACE)
				}
			}
		} else { //Check Policy matches the labels on the Object
			if (item.Spec.Selector.Namespace != "" &&
				item.Spec.Selector.Namespace == namespace) ||
				(item.Spec.Selector.Namespace == "") {
				if util.MatchLabels(item.Spec.Selector.Labels, label) {
					snatPolicyNames[item.ObjectMeta.Name] =
						append(snatPolicyNames[item.ObjectMeta.Name], res)
				}
				if res == POD {
					if len(item.Spec.SnatIp) == 0 {
						var services []*v1.Service
						cache.ListAllByNamespace(agent.serviceInformer.GetIndexer(), namespace, labels.Everything(),
							func(servobj interface{}) {
								services = append(services, servobj.(*v1.Service))
							})
						// list the pods and apply the policy at service target
						for _, service := range services {
							if util.MatchLabels(item.Spec.Selector.Labels,
								service.ObjectMeta.Labels) {
								snatPolicyNames[item.ObjectMeta.Name] =
									append(snatPolicyNames[item.ObjectMeta.Name], SERVICE)
								break
							}

						}
					} else {
						podKey, _ := cache.MetaNamespaceKeyFunc(obj)
						for _, dpkey := range agent.depPods.GetObjForPod(podKey) {
							depobj, exists, err :=
								agent.depInformer.GetStore().GetByKey(dpkey)
							if err != nil {
								agent.log.Error("Could not lookup snat for " +
									dpkey + ": " + err.Error())
								continue
							}
							if !exists || depobj == nil {
								continue
							}
							if util.MatchLabels(item.Spec.Selector.Labels,
								depobj.(*appsv1.Deployment).ObjectMeta.Labels) {
								snatPolicyNames[item.ObjectMeta.Name] =
									append(snatPolicyNames[item.ObjectMeta.Name], DEPLOYMENT)

							}
						}
						nsobj, exists, err := agent.nsInformer.GetStore().GetByKey(namespace)
						if err != nil {
							agent.log.Error("Could not lookup snat for " +
								namespace + ": " + err.Error())
							continue
						}
						if !exists || nsobj == nil {
							continue
						}
						if util.MatchLabels(item.Spec.Selector.Labels,
							nsobj.(*v1.Namespace).ObjectMeta.Labels) {
							snatPolicyNames[item.ObjectMeta.Name] =
								append(snatPolicyNames[item.ObjectMeta.Name], NAMESPACE)
						}
						// check for namespace match
					}
				}
			}
		}
	}
	return
}

func (agent *HostAgent) handleObjectUpdateForSnat(obj interface{}) {
	objKey, err := cache.MetaNamespaceKeyFunc(obj)
	if err != nil {
		return
	}
	agent.log.Info("handleObjectUpdateForSnat: ", objKey)
	plcynames, ok := agent.snatPolicyLabels[objKey]
	if !ok {
		agent.snatPolicyLabels[objKey] = make(map[string]ResourceType)
	}
	sync := false
	if len(plcynames) == 0 {
		polcies := agent.getMatchingSnatPolicy(obj)
		agent.log.Info("HandleObject matching policies: ", polcies)
		for name, resources := range polcies {
			for _, res := range resources {
				poduids, _ := agent.getPodsMatchingObjet(obj, name)
				agent.log.Info("HandleObject Update/Matching Pod Uid's: ", poduids)
				if len(agent.snatPolicyCache[name].Spec.Selector.Labels) == 0 {
					agent.applyPolicy(poduids, res, name)
				} else {
					agent.applyPolicy(poduids, res, name)
					agent.snatPolicyLabels[objKey][name] = res
				}
				sync = true
			}
		}

	} else {
		var delpodlist []string
		matchnames := agent.getMatchingSnatPolicy(obj)
		agent.log.Info("HandleObject matching policies: ", matchnames)
		seen := make(map[string]bool)
		for name, res := range plcynames {
			if _, ok := matchnames[name]; !ok {
				poduids, _ := agent.getPodsMatchingObjet(obj, name)
				for _, uid := range poduids {
					agent.deleteSnatLocalInfo(uid, res, name)
				}
				delpodlist = append(delpodlist, poduids...)
				delete(agent.snatPolicyLabels[objKey], name)
			}
			sync = true
			seen[name] = true
		}
		if len(delpodlist) > 0 {
			agent.updateEpFiles(delpodlist)
		}
		for name, resources := range matchnames {
			if seen[name] == true {
				continue
			}
			for _, res := range resources {
				poduids, _ := agent.getPodsMatchingObjet(obj, name)
				agent.applyPolicy(poduids, res, name)
				agent.snatPolicyLabels[objKey][name] = res
				sync = true
			}
		}
	}
	if sync == true {
		agent.scheduleSyncNodeInfo()
	}
}

func (agent *HostAgent) handleObjectDeleteForSnat(obj interface{}) {
	objKey, err := cache.MetaNamespaceKeyFunc(obj)
	if err != nil {
		return
	}
	metadata, err := meta.Accessor(obj)
	if err != nil {
		return
	}
	agent.log.Debug("HandleObject Delete: ", objKey)
	plcynames := agent.getMatchingSnatPolicy(obj)
	var podidlist []string
	sync := false
	for name, resources := range plcynames {
		poduids, _ := agent.getPodsMatchingObjet(obj, name)
		agent.log.Debug("Object deleted: ", poduids, metadata.GetNamespace(), name)
		for _, uid := range poduids {
			if getResourceType(obj) == SERVICE {
				agent.log.Debug("Service deleted update the localInfo: ", name)
				for _, res := range resources {
					agent.deleteSnatLocalInfo(uid, res, name)
				}
			} else {
				delete(agent.opflexSnatLocalInfos, uid)
				delete(agent.snatPods[name], uid)
			}
		}
		podidlist = append(podidlist, poduids...)
		sync = true
	}
	delete(agent.snatPolicyLabels, objKey)
	// Delete any Policy entries present for POD
	if getResourceType(obj) == POD {
		uid := string(obj.(*v1.Pod).ObjectMeta.UID)
		localinfo, ok := agent.opflexSnatLocalInfos[uid]
		if ok {
			for _, policynames := range localinfo.Snatpolicies {
				for _, name := range policynames {
					delete(agent.snatPods[name], uid)
				}
			}
			delete(agent.opflexSnatLocalInfos, uid)
			sync = true
		}
	}

	if sync {
		agent.scheduleSyncNodeInfo()
		if getResourceType(obj) == SERVICE {
			agent.updateEpFiles(podidlist)
		} else {
			agent.scheduleSyncEps()
		}
	}
}

func (agent *HostAgent) isPolicyNameSpaceMatches(policyName string, namespace string) bool {
	policy, ok := agent.snatPolicyCache[policyName]
	if ok {
		if len(policy.Spec.Selector.Namespace) == 0 || (len(policy.Spec.Selector.Namespace) > 0 &&
			policy.Spec.Selector.Namespace == namespace) {
			return true
		}
	}
	return false
}

func (agent *HostAgent) getSnatUuids(poduuid string) []string {
	agent.indexMutex.Lock()
	val, check := agent.opflexSnatLocalInfos[poduuid]
	agent.indexMutex.Unlock()
	if check {
		agent.log.Debug("Syncing snat Uuids: ", val.PlcyUuids)
		return val.PlcyUuids

	} else {
		return []string{}
	}
}

func setDestIp(destIp []string) {
	if len(destIp) > 0 {
		sort.Slice(destIp, func(i, j int) bool {
			a := destIp[i]
			b := destIp[j]
			ip_temp := net.ParseIP(a)
			if ip_temp != nil && ip_temp.To4() != nil {
				a = a + "/32"
			}
			ip_temp = net.ParseIP(b)
			if ip_temp != nil && ip_temp.To4() != nil {
				b = b + "/32"
			}
			ipB, _, _ := net.ParseCIDR(b)
			_, ipnetA, _ := net.ParseCIDR(a)
			if ipnetA.Contains(ipB) {
				return false
			}
			return true
		})
	}
}

func getResourceType(obj interface{}) ResourceType {
	var res ResourceType
	switch obj.(type) {
	case *v1.Pod:
		res = POD
	case *appsv1.Deployment:
		res = DEPLOYMENT
	case *v1.Service:
		res = SERVICE
	case *v1.Namespace:
		res = NAMESPACE
	default:
	}
	return res
}
