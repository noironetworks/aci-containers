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
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package controller

import (
	"context"
	"net"
	"os"
	"reflect"
	"strconv"

	"github.com/google/uuid"
	nodeinfo "github.com/noironetworks/aci-containers/pkg/nodeinfo/apis/aci.snat/v1"
	nodeinfoclset "github.com/noironetworks/aci-containers/pkg/nodeinfo/clientset/versioned"
	snatglobalinfo "github.com/noironetworks/aci-containers/pkg/snatglobalinfo/apis/aci.snat/v1"
	snatlocalinfo "github.com/noironetworks/aci-containers/pkg/snatlocalinfo/apis/aci.snat/v1"
	snatlocalinfoclset "github.com/noironetworks/aci-containers/pkg/snatlocalinfo/clientset/versioned"
	snatv1 "github.com/noironetworks/aci-containers/pkg/snatpolicy/apis/aci.snat/v1"
	"github.com/noironetworks/aci-containers/pkg/util"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

func (cont *AciController) initSnatLocalInfoInformerFromClient(
	snatClient *snatlocalinfoclset.Clientset) {
	cont.initSnatLocalInfoInformerBase(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				obj, err := snatClient.AciV1().SnatLocalInfos(metav1.NamespaceAll).List(context.TODO(), options)
				if err != nil {
					cont.log.Fatal("Failed to list SnatLocalInfos during initialization of SnatLocalInfoInformer ", err)
				}
				return obj, err
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				obj, err := snatClient.AciV1().SnatLocalInfos(metav1.NamespaceAll).Watch(context.TODO(), options)
				if err != nil {
					cont.log.Fatal("Failed to watch SnatLocalInfos during initialization SnatLocalInfoInformer ", err)
				}
				return obj, err
			},
		})
}

func (cont *AciController) initSnatLocalInfoInformerBase(listWatch *cache.ListWatch) {
	_, cont.snatLocalInfoInformer = cache.NewIndexerInformer(
		listWatch,
		&snatlocalinfo.SnatLocalInfo{}, 0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				cont.snatLocalInfoAdded(obj)
			},
		},
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	cont.log.Debug("Initializing SnatLocalInfo Informers: ")
}

func (cont *AciController) initSnatNodeInformerFromClient(
	snatClient *nodeinfoclset.Clientset) {
	cont.initSnatNodeInformerBase(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				obj, err := snatClient.AciV1().NodeInfos(metav1.NamespaceAll).List(context.TODO(), options)
				if err != nil {
					cont.log.Fatal("Failed to list NodeInfos during initialization of SnatNodeInformer")
				}
				return obj, err
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				obj, err := snatClient.AciV1().NodeInfos(metav1.NamespaceAll).Watch(context.TODO(), options)
				if err != nil {
					cont.log.Fatal("Failed to watch NodeInfos during initialization SnatNodeInformer")
				}
				return obj, err
			},
		})
}

func (cont *AciController) initSnatNodeInformerBase(listWatch *cache.ListWatch) {
	cont.snatNodeInfoIndexer, cont.snatNodeInformer = cache.NewIndexerInformer(
		listWatch,
		&nodeinfo.NodeInfo{}, 0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				cont.snatNodeInfoAdded(obj)
			},
			UpdateFunc: func(oldiobj interface{}, newobj interface{}) {
				cont.snatNodeInfoUpdated(oldiobj, newobj)
			},
			DeleteFunc: func(obj interface{}) {
				cont.snatNodeInfoDeleted(obj)
			},
		},
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	cont.log.Debug("Initializing Node Informers: ")
}

func (cont *AciController) initSnatCfgFromClient(
	kubeClient kubernetes.Interface) {
	cont.initSnatCfgInformerBase(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				options.FieldSelector =
					fields.Set{"metadata.name": "snat-operator-config"}.String()
				obj, err := kubeClient.CoreV1().ConfigMaps("aci-containers-system").List(context.TODO(), options)
				if err != nil {
					cont.log.Fatal("Failed to list ConfigMap during initialization of SnatCfg")
				}
				return obj, err
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				options.FieldSelector =
					fields.Set{"metadata.name": "snat-operator-config"}.String()
				obj, err := kubeClient.CoreV1().ConfigMaps("aci-containers-system").Watch(context.TODO(), options)
				if err != nil {
					cont.log.Fatal("Failed to watch NodeInfos during initialization SnatNodeInformer")
				}
				return obj, err
			},
		})
}

func (cont *AciController) initSnatCfgInformerBase(listWatch *cache.ListWatch) {
	_, cont.snatCfgInformer = cache.NewIndexerInformer(
		listWatch,
		&v1.ConfigMap{}, 0,
		cache.ResourceEventHandlerFuncs{
			UpdateFunc: func(oldObj interface{}, newObj interface{}) {
				cont.snatCfgUpdate(oldObj, newObj)
			},
		},
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	cont.log.Info("Initializing SnatCfg Informers: ")
}

// Handle any changes to snatOperator Config
func (cont *AciController) snatCfgUpdate(oldObj, newObj interface{}) {
	oldSnatcfg := oldObj.(*v1.ConfigMap)
	newSnatcfg := newObj.(*v1.ConfigMap)
	oldData := oldSnatcfg.Data
	newData := newSnatcfg.Data
	if reflect.DeepEqual(oldData, newData) {
		cont.log.Info("ConfigMap is unchanged for: ", oldSnatcfg.Name)
		return
	}
	cont.log.Infof("snatCfgUpdated from %+v to %+v: ", oldSnatcfg, newSnatcfg)
	start, err1 := strconv.Atoi(newData["start"])
	end, err2 := strconv.Atoi(newData["end"])
	portsPerNode, err3 := strconv.Atoi(newData["ports-per-node"])
	if err1 != nil || err2 != nil || err3 != nil ||
		start < 5000 || end > 65000 || start > end || portsPerNode > end-start+1 {
		cont.log.Error("Invalid values provided for ConfigMap: ", newSnatcfg.Name)
		return
	}
	var portRange snatglobalinfo.PortRange
	portRange.Start = start
	portRange.End = end
	var currPortRange []snatglobalinfo.PortRange
	currPortRange = append(currPortRange, portRange)
	cont.indexMutex.Lock()
	nodeInfoKeys := make(map[string]bool)
	for name, info := range cont.snatPolicyCache {
		cont.clearSnatGlobalCache(name, "")
		info.ExpandedSnatPorts = util.ExpandPortRanges(currPortRange, portsPerNode)
		cont.getNodeInfoKeys(name, nodeInfoKeys)
	}
	cont.indexMutex.Unlock()
	for key := range nodeInfoKeys {
		cont.queueNodeInfoUpdateByKey(key)
	}
}

func (cont *AciController) snatLocalInfoAdded(obj interface{}) {
	localinfo := obj.(*snatlocalinfo.SnatLocalInfo)
	if !cont.isNodeExists(localinfo.ObjectMeta.Name) {
		cont.log.Info("Deleting stale SnatLocalInfo : ", localinfo.ObjectMeta.Name)
		cont.deleteStaleSnatResources(localinfo.ObjectMeta.Name, false, true)
	}
}

func (cont *AciController) snatNodeInfoAdded(obj interface{}) {
	nodeinfo := obj.(*nodeinfo.NodeInfo)
	nodeinfokey, err := cache.MetaNamespaceKeyFunc(nodeinfo)
	if err != nil {
		cont.log.Error("Could not create key, err: ", err)
		return
	}
	cont.log.Info("Node Info Added: ", nodeinfokey)
	cont.indexMutex.Lock()
	cont.snatNodeInfoCache[nodeinfo.ObjectMeta.Name] = nodeinfo
	cont.indexMutex.Unlock()
	cont.queueNodeInfoUpdateByKey(nodeinfokey)
}

func (cont *AciController) queueNodeInfoUpdateByKey(key string) {
	cont.log.Debug("Node key Queued: ", key)
	cont.snatNodeInfoQueue.Add(key)
}

func (cont *AciController) snatNodeInfoUpdated(oldobj, newobj interface{}) {
	oldnodeinfo := oldobj.(*nodeinfo.NodeInfo)
	newnodeinfo := newobj.(*nodeinfo.NodeInfo)
	nodeinfokey, err := cache.MetaNamespaceKeyFunc(newnodeinfo)
	if err != nil {
		cont.log.Debug("Could not create key, err: ", err)
		return
	}
	if reflect.DeepEqual(oldnodeinfo.Spec, newnodeinfo.Spec) {
		return
	}
	cont.indexMutex.Lock()
	cont.log.Info("Updating nodeinfo to: ", newnodeinfo)
	cont.updateSnatIpandPorts(oldnodeinfo.Spec.SnatPolicyNames,
		newnodeinfo.Spec.SnatPolicyNames, newnodeinfo.ObjectMeta.Name)
	cont.snatNodeInfoCache[newnodeinfo.ObjectMeta.Name] = newnodeinfo
	cont.indexMutex.Unlock()
	cont.queueNodeInfoUpdateByKey(nodeinfokey)
}

func (cont *AciController) snatNodeInfoDeleted(obj interface{}) {
	nodeInfo, isNodeInfo := obj.(*nodeinfo.NodeInfo)
	if !isNodeInfo {
		deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			cont.log.Error("Received unexpected object: ", obj)
			return
		}
		nodeInfo, ok = deletedState.Obj.(*nodeinfo.NodeInfo)
		if !ok {
			cont.log.Error("DeletedFinalStateUnknown contained non-NodeInfo object: ", deletedState.Obj)
			return
		}
	}
	cont.indexMutex.Lock()
	cont.log.Info("Deleting nodeinfo object with name: ", nodeInfo.ObjectMeta.Name)
	delete(cont.snatNodeInfoCache, nodeInfo.ObjectMeta.Name)
	cont.indexMutex.Unlock()
	cont.handleSnatNodeInfo(nodeInfo)
}

func (cont *AciController) setSnatPolicyStatus(snatPolicyName string, status snatv1.PolicyState) bool {
	obj, exists, err := cont.snatIndexer.GetByKey(snatPolicyName)
	if err == nil && exists && obj != nil {
		snatpolicy := obj.(*snatv1.SnatPolicy)
		if snatpolicy.Status.State != status {
			snatpolicy.Status.State = status
			env := cont.env.(*K8sEnvironment)
			policycl := env.snatClient
			if policycl != nil {
				err = util.UpdateSnatPolicyCR(*policycl, snatpolicy)
				if err != nil {
					cont.log.Info("Policy status update failed queue the request again: ", err)
					return true
				}
			}
		}
	}
	return false
}

func (cont *AciController) isSnatNodeInfoPresent(nodeName string) bool {
	cont.indexMutex.Lock()
	_, ok := cont.snatNodeInfoCache[nodeName]
	cont.indexMutex.Unlock()
	return ok
}

func (cont *AciController) checksnatPolicyPortExhausted(name string) bool {
	snatobj, exists, err := cont.snatIndexer.GetByKey(name)
	if err == nil && exists && snatobj != nil {
		snatpolicy := snatobj.(*snatv1.SnatPolicy)
		if snatpolicy.Status.State == snatv1.IpPortsExhausted {
			return true
		}
	}
	return false
}

func (cont *AciController) deleteStaleSnatResources(nodename string,
	nodeinfodel, localinfodel bool) error {

	ns := os.Getenv("SYSTEM_NAMESPACE")
	env := cont.env.(*K8sEnvironment)
	if nodeinfodel {
		_, nodeinfoExists, err := cont.snatNodeInfoIndexer.GetByKey(ns + "/" + nodename)
		if err != nil {
			cont.log.Info("Could not lookup NodeInfoCR: ", err, "NodeInfo Name: ", nodename)
			return err
		}
		if nodeinfoExists {
			nodeinfocl := env.nodeInfoClient
			if nodeinfocl != nil {
				err = util.DeleteNodeInfoCR(*nodeinfocl, nodename)
				if err != nil {
					cont.log.Error("Could not delete the NodeInfoCR: ", nodename)
					return err
				}
				cont.log.Info("Successfully Deleted NodeInfoCR: ", nodename)
			}
		}
	}
	if localinfodel {
		snatLocalInfoClient := env.snatLocalInfoClient
		if snatLocalInfoClient != nil {
			err := util.DeleteSnatLocalInfoCr(*snatLocalInfoClient, nodename)
			if err != nil {
				cont.log.Error("Could not delete the snatlocalinfo: ", nodename)
				return err
			}
		}
	}
	return nil
}

func (cont *AciController) isNodeExists(name string) bool {
	_, exists, err := cont.nodeIndexer.GetByKey(name)
	if err == nil && exists {
		return true
	}
	return false
}

func (cont *AciController) handleSnatNodeInfo(nodeinfo *nodeinfo.NodeInfo) bool {
	cont.log.Debug("handle Node Info: ", nodeinfo)
	updated := false
	nodename := nodeinfo.ObjectMeta.Name
	ret := false
	// Cache needs to be updated
	if !cont.isSnatNodeInfoPresent(nodename) || len(nodeinfo.Spec.SnatPolicyNames) == 0 {
		cont.log.Debug("SnatPolicyNames are : ", nodeinfo.Spec.SnatPolicyNames)
		ret = cont.deleteNodeinfoFromGlInfoCache(nodeinfo.Spec.SnatPolicyNames, nodename)
		updated = true
	} else if !cont.isNodeExists(nodename) {
		if _, ok := cont.snatNodeInfoCache[nodename]; ok {
			delete(cont.snatNodeInfoCache, nodename)
			updated = true
		}
		err := cont.deleteStaleSnatResources(nodename, true, false)
		if err != nil {
			return false
		}
	} else {
		if cont.updateMacAddressIfChanged(nodename, nodeinfo.Spec.Macaddress) {
			updated = true
		}
		allocfailed := make(map[string]bool)
		markready := make(map[string]bool)
		for name := range nodeinfo.Spec.SnatPolicyNames {
			cont.indexMutex.Lock()
			snatpolicy, ok := cont.snatPolicyCache[name]
			cont.indexMutex.Unlock()
			if !ok {
				continue
			}
			cont.log.Debug("SnatPolicy Name: ", name)
			if len(snatpolicy.SnatIp) != 0 {
				nodeSNATEntryFound := cont.checkIfPolicyApplied(nodename, name, snatpolicy.ExpandedSnatIps)
				if nodeSNATEntryFound {
					cont.log.Debug("Allocation already done for nodename and snatpolicy", nodename, name)
					continue
				}
				snatIp, portrange, alloc := cont.getIpAndPortRange(nodename, snatpolicy, "")
				cont.log.Infof("Handling nodeinfo for node %s and snatpolicy %s: ", nodename, name)
				cont.log.Info("Allocated SNAT IP and Port Range: ", snatIp, portrange)
				if !alloc {
					cont.log.Errorf("Port Range Exhausted for node %s, snat policy %s", nodename, name)
					allocfailed[name] = true
					continue
				} else if cont.checksnatPolicyPortExhausted(name) {
					markready[name] = true
				}
				cont.updateGlobalInfoforPolicy(portrange, snatIp, nodename,
					nodeinfo.Spec.Macaddress, name)
				updated = true
			} else {
				snatIps := cont.getServiceIps(snatpolicy)
				nodeSNATEntryFound := cont.checkIfPolicyApplied(nodename, name, snatIps)
				if nodeSNATEntryFound {
					cont.log.Debug("Allocation already done for nodename and snatpolicy", nodename, name)
					continue
				}
				cont.log.Debug("Service Ips: ", snatIps)
				for _, snatip := range snatIps {
					snatIp, portrange, alloc := cont.getIpAndPortRange(nodename, snatpolicy, snatip)
					cont.log.Infof("Handling nodeinfo for node %s and snatpolicy %s: ", nodename, name)
					cont.log.Info("Allocated SNAT IP and Port Range: ", snatIp, portrange)
					if !alloc {
						cont.log.Errorf("Port Range Exhausted for node %s, snat policy %s", nodename, name)
						allocfailed[name] = true
						continue
					} else if cont.checksnatPolicyPortExhausted(name) {
						markready[name] = true
					}
					cont.updateGlobalInfoforPolicy(portrange, snatIp, nodename,
						nodeinfo.Spec.Macaddress, name)
					updated = true
				}
			}
		}
		deleted := cont.deleteStaleNodeInfoFromGlInfoCache(nodeinfo.Spec.SnatPolicyNames, nodename)
		if deleted {
			updated = true
		}
		ret = cont.setSnatPoliciesState(allocfailed, snatv1.IpPortsExhausted)
		ret = cont.setSnatPoliciesState(markready, snatv1.Ready) && ret
	}

	if updated {
		cont.scheduleSyncGlobalInfo()
		cont.log.Debug("Triggered scheduleSyncGlobalInfo")
	}
	return ret
}

func (cont *AciController) deleteStaleNodeInfoFromGlInfoCache(snatPolicyNames map[string]bool, nodename string) bool {
	deleted := false
	cont.indexMutex.Lock()
	defer cont.indexMutex.Unlock()
	for snatip, glinfos := range cont.snatGlobalInfoCache {
		if glinfo, ok := glinfos[nodename]; ok {
			found := false
			for snatpolicy := range snatPolicyNames {
				if snatpolicy == glinfo.SnatPolicyName {
					found = true
					break
				}
			}
			if !found {
				cont.log.Info("Deleting following node from snatglobalinfo: ", nodename, " for snat ip: ", snatip)
				delete(glinfos, nodename)
				deleted = true
			}
		}
		if len(glinfos) == 0 {
			cont.log.Info("Deleting snatip ", snatip, " from snatglobalinfo")
			delete(cont.snatGlobalInfoCache, snatip)
		} else {
			cont.snatGlobalInfoCache[snatip] = glinfos
		}
	}
	return deleted
}

func (cont *AciController) syncSnatGlobalInfo() bool {
	env := cont.env.(*K8sEnvironment)
	globalcl := env.snatGlobalClient
	if globalcl == nil || cont.isCNOEnabled() {
		return false
	}
	cont.indexMutex.Lock()
	cont.log.Debug("syncSnatGlobalInfo")
	glInfoCache := make(map[string]snatglobalinfo.GlobalInfoList)
	for _, glinfos := range cont.snatGlobalInfoCache {
		for name, v := range glinfos {
			globalinfo := &snatglobalinfo.GlobalInfo{}
			util.DeepCopyObj(*v, globalinfo)
			glInfoCache[name] = append(glInfoCache[name], *globalinfo)
		}
	}
	cont.indexMutex.Unlock()
	snatglobalInfo, err := util.GetGlobalInfoCR(*globalcl)
	if errors.IsNotFound(err) {
		spec := snatglobalinfo.SnatGlobalInfoSpec{
			GlobalInfos: glInfoCache,
		}
		if globalcl != nil {
			err := util.CreateSnatGlobalInfoCR(*globalcl, spec)
			if err != nil {
				cont.log.Error("SnatGlobalInfoCR Create failed requeue the request", err)
				return true
			}
		}
		return false
	} else if err != nil {
		cont.log.Error("SnatGlobalInfoCR Create failed requeue the request-1: ", err)
		return true
	}
	if reflect.DeepEqual(snatglobalInfo.Spec.GlobalInfos, glInfoCache) {
		return false
	}
	snatglobalInfo.Spec.GlobalInfos = glInfoCache
	cont.log.Debug("Update GlobalInfo cache: ", glInfoCache)
	cont.log.Debug("Updating GlobalInfo CR")
	err = util.UpdateGlobalInfoCR(*globalcl, &snatglobalInfo)
	if err != nil {
		cont.log.Error("GlobalInfo CR Update Failed: ", err)
		return true
	}
	cont.log.Debug("GlobalInfo CR successfully updated")
	return false
}

func (cont *AciController) updateGlobalInfoforPolicy(portrange snatglobalinfo.PortRange,
	snatIp, nodename, macaddr, plcyname string) {
	portlist := []snatglobalinfo.PortRange{}
	portlist = append(portlist, portrange)
	ip := net.ParseIP(snatIp)
	snatIpUuid, _ := uuid.FromBytes(ip)
	cont.log.Debug("Updating globalinfo for SNAT IP and Port range: ", snatIp, portrange)
	cont.indexMutex.Lock()
	glinfo := &snatglobalinfo.GlobalInfo{
		MacAddress:     macaddr,
		PortRanges:     portlist,
		SnatIp:         snatIp,
		SnatIpUid:      snatIpUuid.String(),
		SnatPolicyName: plcyname,
	}
	if _, ok := cont.snatGlobalInfoCache[snatIp]; !ok {
		cont.snatGlobalInfoCache[snatIp] = make(map[string]*snatglobalinfo.GlobalInfo)
	}
	cont.snatGlobalInfoCache[snatIp][nodename] = glinfo
	cont.log.Info("Node name and globalinfo: ", nodename, glinfo)
	cont.indexMutex.Unlock()
}

func (cont *AciController) updateMacAddressIfChanged(nodename, macaddress string) bool {
	var updated bool
	cont.indexMutex.Lock()
	defer cont.indexMutex.Unlock()
	for snatip, glinfos := range cont.snatGlobalInfoCache {
		if v, ok := glinfos[nodename]; ok {
			if v.MacAddress != macaddress {
				cont.log.Info("Mismatch in macAddress of ", nodename, " in SnatGlobalInfo and NodeInfo. Updating macAdress from ", v.MacAddress, " to ", macaddress, " in SnatGlobalInfo for snat ip ", snatip)
				v.MacAddress = macaddress
				cont.snatGlobalInfoCache[snatip][nodename] = v
				updated = true
			}
		}
	}
	return updated
}

func (cont *AciController) checkIfPolicyApplied(nodename, snatpolicyname string, snatIps []string) bool {
	var nodeSNATEntryFound bool
	for _, snatip := range snatIps {
		if policyEntries, ok := cont.snatGlobalInfoCache[snatip]; ok {
			if glinfo, nodepresent := policyEntries[nodename]; nodepresent {
				if glinfo.SnatPolicyName == snatpolicyname {
					nodeSNATEntryFound = true
				}
			}
		}
	}
	return nodeSNATEntryFound
}

func (cont *AciController) getIpAndPortRange(nodename string, snatpolicy *ContSnatPolicy, serviceIp string) (string,
	snatglobalinfo.PortRange, bool) {
	expandedsnatports := snatpolicy.ExpandedSnatPorts
	if len(snatpolicy.SnatIp) != 0 {
		snatIps := snatpolicy.ExpandedSnatIps
		if len(snatIps) == 0 {
			return "", snatglobalinfo.PortRange{}, false
		}
		return cont.allocateIpSnatPortRange(snatIps, nodename, expandedsnatports)
	} else {
		var snatIps []string
		snatIps = append(snatIps, serviceIp)
		return cont.allocateIpSnatPortRange(snatIps, nodename, expandedsnatports)
	}
}

func (cont *AciController) allocateIpSnatPortRange(snatIps []string, nodename string,
	expandedsnatports []snatglobalinfo.PortRange) (string, snatglobalinfo.PortRange, bool) {
	if len(expandedsnatports) < 1 {
		return "", snatglobalinfo.PortRange{}, false
	}
	for _, snatip := range snatIps {
		cont.indexMutex.Lock()
		globalInfo, ok := cont.snatGlobalInfoCache[snatip]
		if !ok {
			cont.indexMutex.Unlock()
			return snatip, expandedsnatports[0], true
		} else if len(globalInfo) < len(expandedsnatports) {
			if _, ok := globalInfo[nodename]; !ok {
				seen := make(map[int]int)
				for _, val := range globalInfo {
					seen[val.PortRanges[0].Start] = val.PortRanges[0].End
				}
				for _, val := range expandedsnatports {
					if _, ok := seen[val.Start]; !ok {
						cont.indexMutex.Unlock()
						return snatip, val, true
					}
				}
			} else {
				ip := globalInfo[nodename].SnatIp
				portrange := &snatglobalinfo.PortRange{}
				util.DeepCopyObj(globalInfo[nodename].PortRanges[0], portrange)
				cont.indexMutex.Unlock()
				return ip, *portrange, true
			}
		}
		cont.indexMutex.Unlock()
	}
	return "", snatglobalinfo.PortRange{}, false
}

func (cont *AciController) deleteNodeinfoFromGlInfoCache(snatPolicyNames map[string]bool, nodename string) bool {
	cont.indexMutex.Lock()
	defer cont.indexMutex.Unlock()
	for snatip, glinfos := range cont.snatGlobalInfoCache {
		if v, ok := glinfos[nodename]; ok {
			if cont.checksnatPolicyPortExhausted(v.SnatPolicyName) {
				if cont.setSnatPolicyStatus(v.SnatPolicyName, snatv1.Ready) {
					return true
				}
			}
			cont.log.Info("Deleting following node from globalinfo: ", nodename)
			delete(glinfos, nodename)
			if len(glinfos) == 0 {
				delete(cont.snatGlobalInfoCache, snatip)
			}
		}
	}
	// When the policy status is IPPortExhausted and cannot update to ready state when a node is deleted,
	// we iterate through the snatPolicyNames and check the status for each policy.
	// This is beacuse when there are no more ports that can be allocated, there is no entry of that node
	// in the global info cache.
	for name := range snatPolicyNames {
		if cont.checksnatPolicyPortExhausted(name) {
			if cont.setSnatPolicyStatus(name, snatv1.Ready) {
				return true
			}
		}
	}
	return false
}

func (cont *AciController) getServiceIps(policy *ContSnatPolicy) (serviceIps []string) {
	services := cont.getServicesBySelector(labels.SelectorFromSet(policy.Selector.Labels),
		policy.Selector.Namespace)
	for _, service := range services {
		var ips []string
		for _, ip := range service.Status.LoadBalancer.Ingress {
			ips = append(ips, ip.IP)
		}
		serviceIps = append(serviceIps, ips...)
	}
	return serviceIps
}

func (cont *AciController) updateSnatIpandPorts(oldPolicyNames,
	newPolicynames map[string]bool, nodename string) {
	for oldkey := range oldPolicyNames {
		if _, ok := newPolicynames[oldkey]; !ok {
			cont.clearSnatGlobalCache(oldkey, nodename)
			if cont.checksnatPolicyPortExhausted(oldkey) {
				if !cont.setSnatPolicyStatus(oldkey, snatv1.Ready) {
					cont.log.Error("Failed to set the status for snat policy: ", oldkey)
				}
			}
		}
	}
}

func (cont *AciController) clearSnatGlobalCache(policyName, nodename string) {
	var expandedIps []string
	contSnatPolicy, ok := cont.snatPolicyCache[policyName]
	if !ok {
		return
	}
	if len(contSnatPolicy.SnatIp) > 0 {
		expandedIps = contSnatPolicy.ExpandedSnatIps
	} else {
		expandedIps = cont.getServiceIps(contSnatPolicy)
	}
	for _, snatip := range expandedIps {
		if v, ok := cont.snatGlobalInfoCache[snatip]; ok {
			if len(nodename) > 0 {
				if _, exists := v[nodename]; exists {
					delete(v, nodename)
					if len(v) == 0 {
						cont.log.Info("Clearing following snat IP from snatglobalinfo: ", snatip)
						delete(cont.snatGlobalInfoCache, snatip)
					}
					break
				}
			} else {
				cont.log.Info("Clearing following snat IP from snatglobalinfo: ", snatip)
				delete(cont.snatGlobalInfoCache, snatip)
			}
		} else {
			break
		}
	}
	cont.scheduleSyncGlobalInfo()
}

func (cont *AciController) getNodeInfoKeys(policyName string, nodeinfokeys map[string]bool) {
	for _, nodeinfo := range cont.snatNodeInfoCache {
		if _, ok := nodeinfo.Spec.SnatPolicyNames[policyName]; ok {
			nodeinfokey, err := cache.MetaNamespaceKeyFunc(nodeinfo)
			if err != nil {
				continue
			}
			nodeinfokeys[nodeinfokey] = true
		}
	}
}

func (cont *AciController) setSnatPoliciesState(names map[string]bool, status snatv1.PolicyState) bool {
	// Any alloc failures mark the policy with Status IpPortsExhausted
	ret := false
	for name := range names {
		if cont.setSnatPolicyStatus(name, status) {
			cont.log.Info("Set status true for policy name: ", name)
			ret = true
		}
	}
	return ret
}
