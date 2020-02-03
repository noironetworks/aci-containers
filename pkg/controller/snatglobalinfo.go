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
	uuid "github.com/google/uuid"
	nodeinfo "github.com/noironetworks/aci-containers/pkg/nodeinfo/apis/aci.snat/v1"
	nodeinfoclset "github.com/noironetworks/aci-containers/pkg/nodeinfo/clientset/versioned"
	snatglobalinfo "github.com/noironetworks/aci-containers/pkg/snatglobalinfo/apis/aci.snat/v1"
	"github.com/noironetworks/aci-containers/pkg/util"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
	"net"
	"reflect"
)

type set map[string]bool

func (cont *AciController) initSnatNodeInformerFromClient(
	snatClient *nodeinfoclset.Clientset) {
	cont.initSnatNodeInformerBase(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				return snatClient.AciV1().NodeInfos(metav1.NamespaceAll).List(options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				return snatClient.AciV1().NodeInfos(metav1.NamespaceAll).Watch(options)
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

func (cont *AciController) snatNodeInfoAdded(obj interface{}) {
	nodeinfo := obj.(*nodeinfo.NodeInfo)
	nodeinfokey, err := cache.MetaNamespaceKeyFunc(nodeinfo)
	if err != nil {
		return
	}
	cont.log.Debug("Node Info Added: ", nodeinfokey)
	cont.snatNodeInfoCache[nodeinfo.ObjectMeta.Name] = nodeinfo
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
	delete(cont.snatNodeInfoCache, nodeinfo.ObjectMeta.Name)
	cont.queueNodeInfoUpdateByKey(nodeinfokey)
}

func (cont *AciController) handleSnatNodeInfo(nodeinfo *nodeinfo.NodeInfo) bool {
	nodename := nodeinfo.ObjectMeta.Name
	nodeinfocache, ok := cont.snatNodeInfoCache[nodename]
	cont.log.Debug("handle Node Info: ", nodeinfo)
	updated := false
	// Cache needs to be updated
	if !ok || len(nodeinfo.Spec.SnatPolicyNames) == 0 {
		cont.deleteNodeinfoFromGlInfoCache(nodename)
		updated = true
	} else {
		for name, _ := range nodeinfo.Spec.SnatPolicyNames {
			snatpolicy, ok := cont.snatPolicyCache[name]
			if !ok {
				continue
			}
			cont.log.Debug("SnatPolicy Name: ", name)
			if len(snatpolicy.SnatIp) != 0 {
				snatIp, portrange, alloc := cont.getIpAndPortRange(nodename, snatpolicy, "")
				cont.log.Debug("SnatIP and Port range: ", snatIp, portrange)
				//TODO need to handle Port Exhaustion case
				if alloc == false {
					cont.log.Error("Port Range Exhausted: ", name)
					continue
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
						continue
					}
					cont.updateGlobalInfoforPolicy(portrange, snatIp, nodename,
						nodeinfo.Spec.Macaddress, name)
					updated = true
				}
			}
		}
	}
	if updated {
		cont.scheduleSyncGlobalInfo()
	}
	cont.log.Debug("nodeinfocache", nodeinfocache)
	return false
}

func (cont *AciController) syncSnatGlobalInfo() bool {
	env := cont.env.(*K8sEnvironment)
	globalcl := env.snatGlobalClient
	if globalcl == nil {
		return false
	}
	cont.indexMutex.Lock()
	defer cont.indexMutex.Unlock()
	cont.log.Debug("syncSnatGlobalInfo")
	glInfoCache := make(map[string][]snatglobalinfo.GlobalInfo)
	for _, glinfos := range cont.snatGlobalInfoCache {
		for name, v := range glinfos {
			glInfoCache[name] = append(glInfoCache[name], *v)
		}
	}
	snatglobalInfo, err := util.GetGlobalInfoCR(*globalcl)
	if errors.IsNotFound(err) {
		spec := snatglobalinfo.SnatGlobalInfoSpec{
			GlobalInfos: glInfoCache,
		}
		if globalcl != nil {
			err := util.CreateSnatGlobalInfoCR(*globalcl, spec)
			if err != nil {
				cont.log.Info("Create failed requeue the request")
				return true
			}
		}
		return false
	} else if err != nil {
		return true
	}
	if reflect.DeepEqual(snatglobalInfo.Spec.GlobalInfos, glInfoCache) {
		return false
	}
	snatglobalInfo.Spec.GlobalInfos = glInfoCache
	cont.log.Debug("Update GlobalInfo: ", glInfoCache)
	err = util.UpdateGlobalInfoCR(*globalcl, snatglobalInfo)
	if err != nil {
		cont.log.Debug("Update Failed: ", glInfoCache)
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
	glinfo := snatglobalinfo.GlobalInfo{
		MacAddress:     macaddr,
		PortRanges:     portlist,
		SnatIp:         snatIp,
		SnatIpUid:      snatIpUuid.String(),
		SnatPolicyName: plcyname,
	}
	if _, ok := cont.snatGlobalInfoCache[snatIp]; !ok {
		cont.snatGlobalInfoCache[snatIp] = make(map[string]*snatglobalinfo.GlobalInfo)
	}
	cont.indexMutex.Lock()
	cont.snatGlobalInfoCache[snatIp][nodename] = &glinfo
	cont.log.Debug("Node name and globalinfo: ", nodename, glinfo)
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
	for _, snatip := range snatIps {
		if _, ok := cont.snatGlobalInfoCache[snatip]; !ok {
			return snatip, expandedsnatports[0], true
		} else if len(cont.snatGlobalInfoCache[snatip]) < len(expandedsnatports) {
			globalInfo, _ := cont.snatGlobalInfoCache[snatip]
			if _, ok := globalInfo[nodename]; !ok {
				seen := make(map[int]int)
				for _, val := range globalInfo {
					seen[val.PortRanges[0].Start] = val.PortRanges[0].End
				}
				for _, val := range expandedsnatports {
					if _, ok := seen[val.Start]; !ok {
						return snatip, val, true
					}
				}
			} else {
				return globalInfo[nodename].SnatIp, globalInfo[nodename].PortRanges[0], true
			}
		}
	}
	return "", snatglobalinfo.PortRange{}, false
}

func (cont *AciController) deleteNodeinfoFromGlInfoCache(nodename string) {
	cont.indexMutex.Lock()
	for snatip, glinfos := range cont.snatGlobalInfoCache {
		if _, ok := glinfos[nodename]; ok {
			delete(glinfos, nodename)
			if len(glinfos) == 0 {
				delete(cont.snatGlobalInfoCache, snatip)
			}
		}
	}
	cont.indexMutex.Unlock()
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

func (cont *AciController) updateSnatIpandPorts(oldPolicyNames map[string]struct{},
	newPolicynames map[string]struct{}, nodename string) {
	for oldkey, _ := range oldPolicyNames {
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
		if _, ok := cont.snatGlobalInfoCache[snatip]; ok {
			if len(nodename) > 0 {
				delete(cont.snatGlobalInfoCache[snatip], nodename)
			} else {
				delete(cont.snatGlobalInfoCache, snatip)
			}
		} else {
			break
		}
	}
}

func (cont *AciController) handleSnatIpUpdate(policyName string) {
	for _, nodeinfo := range cont.snatNodeInfoCache {
		if _, ok := nodeinfo.Spec.SnatPolicyNames[policyName]; ok {
			nodeinfokey, err := cache.MetaNamespaceKeyFunc(nodeinfo)
			if err != nil {
				continue
			}
			cont.queueNodeInfoUpdateByKey(nodeinfokey)
		}
	}
}
