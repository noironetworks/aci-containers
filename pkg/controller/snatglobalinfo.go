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
	uuid "github.com/google/uuid"
	nodeinfo "github.com/noironetworks/aci-containers/pkg/nodeinfo/apis/aci.snat/v1"
	nodeinfoclset "github.com/noironetworks/aci-containers/pkg/nodeinfo/clientset/versioned"
	snatglobalinfo "github.com/noironetworks/aci-containers/pkg/snatglobalinfo/apis/aci.snat/v1"
	snatv1 "github.com/noironetworks/aci-containers/pkg/snatpolicy/apis/aci.snat/v1"
	"github.com/noironetworks/aci-containers/pkg/util"
	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"net"
	"reflect"
	"strconv"
)

type set map[string]bool

func (cont *AciController) initSnatNodeInformerFromClient(
	snatClient *nodeinfoclset.Clientset) {
	cont.initSnatNodeInformerBase(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				return snatClient.AciV1().NodeInfos(metav1.NamespaceAll).List(context.TODO(), options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				return snatClient.AciV1().NodeInfos(metav1.NamespaceAll).Watch(context.TODO(), options)
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
				return kubeClient.CoreV1().ConfigMaps(
					"aci-containers-system").List(context.TODO(), options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				options.FieldSelector =
					fields.Set{"metadata.name": "snat-operator-config"}.String()
				return kubeClient.CoreV1().ConfigMaps(
					"aci-containers-system").Watch(context.TODO(), options)
			},
		})
}

func (cont *AciController) initSnatCfgInformerBase(listWatch *cache.ListWatch) {
	_, cont.snatCfgInformer = cache.NewIndexerInformer(
		listWatch,
		&v1.ConfigMap{}, 0,
		cache.ResourceEventHandlerFuncs{
			UpdateFunc: func(_, obj interface{}) {
				cont.snatCfgUpdate(obj)
			},
		},
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	cont.log.Info("Initializing SnatCfg  Informers: ")
}

// Handle any changes to snatOperator Config
func (cont *AciController) snatCfgUpdate(obj interface{}) {
	snatcfg := obj.(*v1.ConfigMap)
	var portRange snatglobalinfo.PortRange
	cont.log.Info("snatCfgUpdated: ", snatcfg)
	data := snatcfg.Data
	start, err1 := strconv.Atoi(data["start"])
	end, err2 := strconv.Atoi(data["end"])
	portsPerNode, err3 := strconv.Atoi(data["ports-per-node"])
	if err1 != nil || err2 != nil || err3 != nil ||
		start < 5000 || end > 65000 || start > end || portsPerNode > end-start+1 {
		return
	}
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

func (cont *AciController) snatNodeInfoAdded(obj interface{}) {
	nodeinfo := obj.(*nodeinfo.NodeInfo)
	nodeinfokey, err := cache.MetaNamespaceKeyFunc(nodeinfo)
	if err != nil {
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

func (cont *AciController) snatNodeInfoUpdated(oldobj interface{}, newobj interface{}) {
	oldnodeinfo := oldobj.(*nodeinfo.NodeInfo)
	newnodeinfo := newobj.(*nodeinfo.NodeInfo)
	nodeinfokey, err := cache.MetaNamespaceKeyFunc(newnodeinfo)
	if err != nil {
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
	nodeinfo := obj.(*nodeinfo.NodeInfo)
	nodeinfokey, err := cache.MetaNamespaceKeyFunc(nodeinfo)
	if err != nil {
		return
	}
	cont.indexMutex.Lock()
	cont.log.Info("Deleting nodeinfo object with name: ", nodeinfo.ObjectMeta.Name)
	delete(cont.snatNodeInfoCache, nodeinfo.ObjectMeta.Name)
	cont.indexMutex.Unlock()
	cont.queueNodeInfoUpdateByKey(nodeinfokey)
}

func (cont *AciController) setSnatPolicyStaus(snatPolicyName string, status snatv1.PolicyState) bool {
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

func (cont *AciController) handleSnatNodeInfo(nodeinfo *nodeinfo.NodeInfo) bool {
	cont.log.Debug("handle Node Info: ", nodeinfo)
	updated := false
	nodename := nodeinfo.ObjectMeta.Name
	ret := false
	// Cache needs to be updated
	if !cont.isSnatNodeInfoPresent(nodename) || len(nodeinfo.Spec.SnatPolicyNames) == 0 {
		ret = cont.deleteNodeinfoFromGlInfoCache(nodename)
		updated = true
	} else {
		// This case ignores any stale entry is present in nodeinfo
		_, _, err := cont.nodeIndexer.GetByKey(nodename)
		if err != nil {
			cont.log.Info("Could not lookup node: ", err, "nodeName: ", nodename)
			return false
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
				snatIp, portrange, alloc := cont.getIpAndPortRange(nodename, snatpolicy, "")
				cont.log.Debug("SnatIP and Port range: ", snatIp, portrange)
				if alloc == false {
					cont.log.Error("Port Range Exhausted: ", name)
					allocfailed[name] = true
					continue
				} else {
					if cont.checksnatPolicyPortExhausted(name) {
						markready[name] = true
					}
				}
				cont.updateGlobalInfoforPolicy(portrange, snatIp, nodename,
					nodeinfo.Spec.Macaddress, name)
				updated = true
			} else {
				snatIps := cont.getServiceIps(snatpolicy)
				cont.log.Debug("Service Ips: ", snatIps)
				for _, snatip := range snatIps {
					snatIp, portrange, alloc := cont.getIpAndPortRange(nodename, snatpolicy, snatip)
					cont.log.Debug("SnatIP and Port range: ", snatIp, portrange)
					if alloc == false {
						cont.log.Error("Port Range Exhausted: ", name)
						allocfailed[name] = true
						continue
					} else {
						if cont.checksnatPolicyPortExhausted(name) {
							markready[name] = true
						}
					}
					cont.updateGlobalInfoforPolicy(portrange, snatIp, nodename,
						nodeinfo.Spec.Macaddress, name)
					updated = true
				}
			}
		}
		ret = cont.setSnatPoliciesState(allocfailed, snatv1.IpPortsExhausted)
		ret = cont.setSnatPoliciesState(markready, snatv1.Ready)
	}

	if updated {
		cont.scheduleSyncGlobalInfo()
	}
	return ret
}

func (cont *AciController) syncSnatGlobalInfo() bool {
	env := cont.env.(*K8sEnvironment)
	globalcl := env.snatGlobalClient
	if globalcl == nil {
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
				cont.log.Info("Create failed requeue the request", err)
				return true
			}
		}
		return false
	} else if err != nil {
		cont.log.Info("Create failed requeue the request-1: ", err)
		return true
	}
	if reflect.DeepEqual(snatglobalInfo.Spec.GlobalInfos, glInfoCache) {
		return false
	}
	snatglobalInfo.Spec.GlobalInfos = glInfoCache
	cont.log.Debug("Update GlobalInfo: ", glInfoCache)
	err = util.UpdateGlobalInfoCR(*globalcl, snatglobalInfo)
	if err != nil {
		cont.log.Info("Update Failed: ", err)
		return true
	}
	return false
}

func (cont *AciController) updateGlobalInfoforPolicy(portrange snatglobalinfo.PortRange,
	snatIp, nodename, macaddr, plcyname string) {
	portlist := []snatglobalinfo.PortRange{}
	portlist = append(portlist, portrange)
	ip := net.ParseIP(snatIp)
	snatIpUuid, _ := uuid.FromBytes(ip)
	cont.log.Debug("SnatIP and Port range: ", snatIp, portrange)
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
	return "", snatglobalinfo.PortRange{}, false
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

func (cont *AciController) deleteNodeinfoFromGlInfoCache(nodename string) bool {
	cont.indexMutex.Lock()
	defer cont.indexMutex.Unlock()
	for snatip, glinfos := range cont.snatGlobalInfoCache {
		if v, ok := glinfos[nodename]; ok {
			if cont.checksnatPolicyPortExhausted(v.SnatPolicyName) {
				if cont.setSnatPolicyStaus(v.SnatPolicyName, snatv1.Ready) == true {
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
	return false
}

func (cont *AciController) getServiceIps(policy *ContSnatPolicy) (serviceIps []string) {
	services := cont.getServicesBySelector(labels.SelectorFromSet(
		labels.Set(policy.Selector.Labels)),
		policy.Selector.Namespace)
	for _, service := range services {
		serviceIps = append(serviceIps, service.Status.LoadBalancer.Ingress[0].IP)
	}
	return
}

func (cont *AciController) updateSnatIpandPorts(oldPolicyNames map[string]bool,
	newPolicynames map[string]bool, nodename string) {
	for oldkey := range oldPolicyNames {
		if _, ok := newPolicynames[oldkey]; !ok {
			cont.clearSnatGlobalCache(oldkey, nodename)
		}
	}
}

func (cont *AciController) clearSnatGlobalCache(policyName string, nodename string) {
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
		if cont.setSnatPolicyStaus(name, status) == true {
			cont.log.Info("Set status true for policy name: ", name)
			ret = true
		}
	}
	return ret
}
