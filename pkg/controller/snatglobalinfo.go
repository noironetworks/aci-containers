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

type ContSnatGlobalInfo struct {
	SnatIp        string
	MacAddress    string
	SnatPortRange snatglobalinfo.PortRange
	SnatIpUid     string
}

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
	if reflect.DeepEqual(oldnodeinfo.Spec, newnodeinfo.Spec) {
		return
	}
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
	cont.indexMutex.Unlock()
	cont.snatNodeInfoCache[newnodeinfo.ObjectMeta.Name] = newnodeinfo
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
	env := cont.env.(*K8sEnvironment)
	globalcl := env.snatGlobalClient
	cont.log.Debug("handle Node Info: ", nodeinfo)
	updated := false
	// Cache needs to be updated
	var globalInfos []snatglobalinfo.GlobalInfo
	if !ok || len(nodeinfo.Spec.SnatPolicyNames) == 0 {
		snatglobalInfo, err := util.GetGlobalInfoCR(*globalcl)
		if err != nil {
			return true
		}
		if _, ok := snatglobalInfo.Spec.GlobalInfos[nodename]; ok {
			cont.deleteNodeinfoFromGlInfoCache(nodename, snatglobalInfo.Spec.GlobalInfos[nodename])
			delete(snatglobalInfo.Spec.GlobalInfos, nodename)
			err = util.UpdateGlobalInfoCR(*globalcl, snatglobalInfo)
			if err != nil {
				return true
			}
		}
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
				if cont.updateGlobalInfoforPolicy(&globalInfos, portrange, snatIp, nodename,
					nodeinfo.Spec.Macaddress, name) {
					return true
				}
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
					if cont.updateGlobalInfoforPolicy(&globalInfos, portrange, snatIp, nodename,
						nodeinfo.Spec.Macaddress, name) {
						return true
					}
					updated = true
				}
			}
		}
		if updated {
			if globalcl == nil {
				return false
			}
			snatglobalInfo, err := util.GetGlobalInfoCR(*globalcl)
			if err != nil {
				return true
			}
			if reflect.DeepEqual(snatglobalInfo.Spec.GlobalInfos[nodename], globalInfos) {
				return false
			}
			if snatglobalInfo.Spec.GlobalInfos == nil {
				tempMap := make(map[string][]snatglobalinfo.GlobalInfo)
				tempMap[nodename] = globalInfos
				snatglobalInfo.Spec.GlobalInfos = tempMap
			} else {
				snatglobalInfo.Spec.GlobalInfos[nodename] = globalInfos
			}
			cont.log.Debug("Update GlobalInfo: ", globalInfos)
			err = util.UpdateGlobalInfoCR(*globalcl, snatglobalInfo)
			if err != nil {
				cont.log.Debug("Update Failed: ", globalInfos)
				return true
			}
		}
	}
	cont.log.Debug("nodeinfocache", nodeinfocache)
	return false
}

func (cont *AciController) updateGlobalInfoforPolicy(globalInfos *[]snatglobalinfo.GlobalInfo,
	portrange snatglobalinfo.PortRange, snatIp, nodename, macaddr, plcyname string) (status bool) {
	env := cont.env.(*K8sEnvironment)
	globalcl := env.snatGlobalClient
	cont.log.Debug("SnatIP and Port range: ", snatIp, portrange)
	portlist := []snatglobalinfo.PortRange{}
	portlist = append(portlist, portrange)
	ip := net.ParseIP(snatIp)
	snatIpUuid, _ := uuid.FromBytes(ip)
	temp := snatglobalinfo.GlobalInfo{
		MacAddress:     macaddr,
		PortRanges:     portlist,
		SnatIp:         snatIp,
		SnatIpUid:      snatIpUuid.String(),
		SnatPolicyName: plcyname,
	}
	if globalcl != nil {
		_, err := util.GetGlobalInfoCR(*globalcl)
		if errors.IsNotFound(err) {
			var glinfo []snatglobalinfo.GlobalInfo
			glinfo = append(glinfo, temp)
			tempMap := make(map[string][]snatglobalinfo.GlobalInfo)
			tempMap[nodename] = glinfo
			spec := snatglobalinfo.SnatGlobalInfoSpec{
				GlobalInfos: tempMap,
			}
			if globalcl != nil {
				err := util.CreateSnatGlobalInfoCR(*globalcl, spec)
				if err != nil {
					cont.log.Info("Create failed requeue the request")
					return true
				}
			}
		}
	}
	*globalInfos = append(*globalInfos, temp)
	cont.UpdateGlobalInfoCache(snatIp, nodename, portrange)
	return false
}

func (cont *AciController) UpdateGlobalInfoCache(snatip string, nodename string, portrange snatglobalinfo.PortRange) {
	cont.indexMutex.Lock()
	if _, ok := cont.snatGlobalInfoCache[snatip]; !ok {
		cont.snatGlobalInfoCache[snatip] = make(map[string]*ContSnatGlobalInfo)
	}
	var glinfo ContSnatGlobalInfo
	glinfo.SnatIp = snatip
	glinfo.SnatPortRange = portrange
	cont.snatGlobalInfoCache[snatip][nodename] = &glinfo
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
					seen[val.SnatPortRange.Start] = val.SnatPortRange.End
				}
				for _, val := range expandedsnatports {
					if _, ok := seen[val.Start]; !ok {
						return snatip, val, true
					}
				}
			} else {
				return globalInfo[nodename].SnatIp, globalInfo[nodename].SnatPortRange, true
			}
		}
	}
	return "", snatglobalinfo.PortRange{}, false
}

func (cont *AciController) deleteNodeinfoFromGlInfoCache(nodename string, globalinfos []snatglobalinfo.GlobalInfo) {
	cont.indexMutex.Lock()
	for _, glinfo := range globalinfos {
		delete(cont.snatGlobalInfoCache[glinfo.SnatIp], nodename)
		if len(cont.snatGlobalInfoCache[glinfo.SnatIp]) == 0 {
			delete(cont.snatGlobalInfoCache, glinfo.SnatIp)
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
