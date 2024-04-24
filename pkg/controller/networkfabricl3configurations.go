// Copyright 2024 Cisco Systems, Inc.
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

// Handlers for network fabric l3 configuration updates.

package controller

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"reflect"
	"strconv"

	"github.com/noironetworks/aci-containers/pkg/apicapi"
	fabattv1 "github.com/noironetworks/aci-containers/pkg/fabricattachment/apis/aci.fabricattachment/v1"
	fabattclset "github.com/noironetworks/aci-containers/pkg/fabricattachment/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
	"k8s.io/kubernetes/pkg/controller"
)

const (
	netFabL3ConfigCRDName     = "networkfabricl3configurations.aci.fabricattachment"
	defaultMaxBGPPrefixes     = 200000
	defaultBGPPrefixAction    = "reject"
	defaultBGPPrefixThreshold = 75
)

type SviContext struct {
	present          bool
	podId            int
	vrf              fabattv1.VRF
	tenant           string
	connectedNw      *NfL3Networks
	l3out            apicapi.ApicObject
	l3outNodeP       apicapi.ApicObject
	l3outLifP        apicapi.ApicObject
	l3extVirtualLifP apicapi.ApicObject
	l3extRsPath      apicapi.ApicObject
	bgpPPP           apicapi.ApicObject
	nodeMap          map[string]bool
}

func networkFabricL3ConfigurationInit(cont *AciController, stopCh <-chan struct{}) {
	cont.log.Debug("Initializing networkfabricl3configuration client")
	restconfig := cont.env.RESTConfig()
	fabNetAttClient, err := fabattclset.NewForConfig(restconfig)
	if err != nil {
		cont.log.Errorf("Failed to intialize nodefabricnetworkattachment client")
		return
	}
	cont.fabNetAttClient = fabNetAttClient
	cont.initNetworkFabricL3ConfigurationInformerFromClient(fabNetAttClient)
	go cont.networkFabricL3ConfigurationInformer.Run(stopCh)
	go cont.processQueue(cont.netFabL3ConfigQueue, cont.networkFabricL3ConfigurationInformer.GetIndexer(),
		func(obj interface{}) bool {
			return cont.handleNetworkFabricL3ConfigurationUpdate(obj)
		}, func(key string) bool {
			return cont.handleNetworkFabricL3ConfigurationDelete(key)
		}, nil, stopCh)
	cache.WaitForCacheSync(stopCh, cont.networkFabricL3ConfigurationInformer.HasSynced)
	//cont.restoreNetworkFabricL3ConfigurationStatus()
}

func (cont *AciController) initNetworkFabricL3ConfigurationInformerFromClient(fabAttClient *fabattclset.Clientset) {
	cont.initNetworkFabricL3ConfigurationInformerBase(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				return fabAttClient.AciV1().NetworkFabricL3Configurations(metav1.NamespaceAll).List(context.TODO(), options)
			},

			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				return fabAttClient.AciV1().NetworkFabricL3Configurations(metav1.NamespaceAll).Watch(context.TODO(), options)
			},
		})
}

func (cont *AciController) initNetworkFabricL3ConfigurationInformerBase(listWatch *cache.ListWatch) {
	cont.networkFabricL3ConfigurationInformer = cache.NewSharedIndexInformer(
		listWatch, &fabattv1.NetworkFabricL3Configuration{}, controller.NoResyncPeriodFunc(),
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	cont.networkFabricL3ConfigurationInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			cont.networkFabricL3ConfigurationChanged(obj)
		},
		UpdateFunc: func(_ interface{}, newobj interface{}) {
			cont.networkFabricL3ConfigurationChanged(newobj)
		},
		DeleteFunc: func(obj interface{}) {
			cont.networkFabricL3ConfigurationDeleted(obj)
		},
	})
}

func (cont *AciController) queueNetFabL3ConfigByKey(key string) {
	cont.netFabL3ConfigQueue.Add(key)
}

func (cont *AciController) networkFabricL3ConfigurationChanged(obj interface{}) {
	netFabL3Config, ok := obj.(*fabattv1.NetworkFabricL3Configuration)
	if !ok {
		cont.log.Error("nodeFabNetAttChanged: Bad object type")
		return
	}
	key, err := cache.MetaNamespaceKeyFunc(netFabL3Config)
	if err != nil {
		return
	}
	cont.queueNetFabL3ConfigByKey(key)
}

func (cont *AciController) networkFabricL3ConfigurationDeleted(obj interface{}) {
	netFabL3Config, ok := obj.(*fabattv1.NetworkFabricL3Configuration)
	if !ok {
		deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			cont.log.Errorf("Received unexpected object: %s/%s", netFabL3Config.TypeMeta.Kind, netFabL3Config.ObjectMeta.Name)
			return
		}
		netFabL3Config, ok = deletedState.Obj.(*fabattv1.NetworkFabricL3Configuration)
		if !ok {
			cont.log.Errorf("DeletedFinalStateUnknown contained non-nodefabricnetworkattachment object: %s/%s", netFabL3Config.TypeMeta.Kind, netFabL3Config.ObjectMeta.Name)
			return
		}
	}
	key, err := cache.MetaNamespaceKeyFunc(netFabL3Config)
	if err != nil {
		return
	}
	cont.queueNetFabL3ConfigByKey("DELETED_" + key)
}

func (cont *AciController) getNodeRtrId(ctxt *SviContext, node int) string {
	rtrId := ""
	if tenantData, ok := cont.sharedEncapTenantCache[ctxt.tenant]; ok {
		if rtrNode, ok := tenantData.L3OutConfig[ctxt.connectedNw.L3OutName].RtrNodeMap[node]; ok {
			rtrId = rtrNode.RtrId
		}
	} else {
		remL := node % 256
		remH := (node / 256) % 256
		rtrId = fmt.Sprintf("%d.%d.%d.%d", remL, remL, remH, remL)
	}
	return rtrId
}

func (cont *AciController) applyInverseMask(addr net.IP, msk net.IPMask) {
	if len(addr) != len(msk) {
		return
	}
	for ctr := 0; ctr < len(addr); ctr++ {
		addr[ctr] |= 0xff ^ msk[ctr]
	}
}

// Basic IPAM for SVI
const (
	DefaultMaxL3OutNodes = 6
	FloatingAddressIdx   = 7
	SecondaryAddressIdx  = 6
)

func (cont *AciController) allocateSviAddress(vlan int, ctxt *SviContext, rtdNetData *RoutedNetworkData, node string) (nodeAddrStr string, err error) {
	nodeId, _ := strconv.Atoi(node)
	if fabL3OutNode, ok := cont.sharedEncapSviCache[vlan].Nodes[nodeId]; ok {
		if ctxt.connectedNw.PrimarySubnet == rtdNetData.subnet {
			_, nw, err := net.ParseCIDR(fabL3OutNode.PrimaryAddress)
			mskLen, _ := nw.Mask.Size()
			if (err == nil) && (nw.IP.String() == rtdNetData.netAddress) && (mskLen == rtdNetData.maskLen) {
				nodeAddrStr = fabL3OutNode.PrimaryAddress
				cont.deallocateSviAddress(rtdNetData, node)
			}
		} else {
			for _, secAddr := range fabL3OutNode.SecondaryAddresses {
				_, nw, err := net.ParseCIDR(secAddr)
				mskLen, _ := nw.Mask.Size()
				if (err == nil) && (nw.IP.String() == rtdNetData.netAddress) && (mskLen == rtdNetData.maskLen) {
					nodeAddrStr = secAddr
					cont.deallocateSviAddress(rtdNetData, node)
					break
				}
			}
		}
	}
	if nodeAddrStr != "" {
		return
	}
	if nodeAddr, ok := rtdNetData.nodeMap[node]; ok {
		nodeAddrStr = nodeAddr.addr
		return
	}
	for i := 0; i < rtdNetData.maxAddresses; i++ {
		if rtdNetData.availableMap[i] {
			addrlen := len(rtdNetData.baseAddress)
			nodeAddr := make(net.IP, addrlen)
			copy(nodeAddr, rtdNetData.baseAddress)
			nodeAddr[addrlen-1] += byte(i)
			nodeAddrStr = fmt.Sprintf("%s/%d", nodeAddr.String(), rtdNetData.maskLen)
			rtdNetData.availableMap[i] = false
			rtdNetData.nodeMap[node] = RoutedNodeData{
				addr: nodeAddrStr,
				idx:  i,
			}
			err = nil
			return
		}
	}
	err = fmt.Errorf("svi address pool exhausted")
	return
}

// TODO: Address Deletion case
func (cont *AciController) deallocateSviAddress(rtdNetData *RoutedNetworkData, node string) {
	if nodeAddr, ok := rtdNetData.nodeMap[node]; ok {
		delete(rtdNetData.nodeMap, node)
		rtdNetData.availableMap[nodeAddr.idx] = true
		return
	}
}

func (cont *AciController) generateSviAddress(nw *net.IPNet, idx int, addrStr *string) {
	addrlen := len(nw.IP)
	mskLen, _ := nw.Mask.Size()
	addr := make(net.IP, addrlen)
	copy(addr, nw.IP)
	addr[addrlen-1] += byte(idx)
	*addrStr = fmt.Sprintf("%s/%d", addr.String(), mskLen)
}

func (cont *AciController) getSviNetworkPool(ctxt *SviContext, subnet string) (floatingAddrStr, secondaryAddrStr string, rtdNetData *RoutedNetworkData, err error) {
	_, nw, err := net.ParseCIDR(subnet)
	if err != nil {
		cont.log.Errorf("Failed to parse connected subnet [%s]: %v", subnet, err)
		return
	}
	sviCacheData, ok := cont.sharedEncapSviCache[ctxt.connectedNw.Encap]
	if !ok {
		cont.log.Errorf("svi Cache missing : vlan %d", ctxt.connectedNw.Encap)
		return
	}
	rtdNetKey := nw.String()
	rtdNetData = sviCacheData.NetAddr[rtdNetKey]
	if rtdNetData == nil {
		cont.applyInverseMask(nw.IP, nw.Mask)
		addrlen := len(nw.IP)
		mskLen, _ := nw.Mask.Size()
		maxAddresses := DefaultMaxL3OutNodes
		if ctxt.connectedNw.PrimaryNetwork.MaxNodes != 0 {
			maxAddresses = ctxt.connectedNw.PrimaryNetwork.MaxNodes
		}
		nw.IP[addrlen-1] -= byte(2 + maxAddresses)
		rtdNetData = &RoutedNetworkData{
			subnet:       subnet,
			netAddress:   nw.IP.String(),
			maskLen:      mskLen,
			baseAddress:  make(net.IP, addrlen),
			numAllocated: 0,
			maxAddresses: maxAddresses,
			nodeMap:      make(map[string]RoutedNodeData),
			availableMap: make(map[int]bool),
		}
		for i := 0; i < maxAddresses; i++ {
			rtdNetData.availableMap[i] = true
		}
		copy(rtdNetData.baseAddress, nw.IP)
		sviCacheData.NetAddr[rtdNetKey] = rtdNetData
		cont.log.Debugf("baseAddress: %s", rtdNetData.baseAddress.String())
	}
	if fabL3Subnet, ok := ctxt.connectedNw.Subnets[subnet]; !ok {
		cont.generateSviAddress(nw, FloatingAddressIdx, &floatingAddrStr)
		cont.generateSviAddress(nw, SecondaryAddressIdx, &secondaryAddrStr)
	} else {
		if fabL3Subnet.FloatingAddress != "" {
			floatingAddrStr = fabL3Subnet.FloatingAddress
		} else {
			cont.generateSviAddress(nw, FloatingAddressIdx, &floatingAddrStr)
		}
		if fabL3Subnet.FloatingAddress != "" {
			secondaryAddrStr = fabL3Subnet.SecondaryAddress
		} else {
			cont.generateSviAddress(nw, SecondaryAddressIdx, &secondaryAddrStr)
		}
	}
	return
}

func (cont *AciController) createNodeFabNetAttSviProtocolPolicies(ctxt *SviContext) {
	if !ctxt.connectedNw.BGPPeerPolicy.Enabled {
		return
	}
	var baseObj apicapi.ApicObject
	if ctxt.connectedNw.SviType == fabattv1.FloatingSviType || ctxt.connectedNw.SviType == "" {
		baseObj = ctxt.l3extVirtualLifP
	} else {
		baseObj = ctxt.l3extRsPath
	}
	prefix := ctxt.connectedNw.BGPPeerPolicy.Prefix
	if prefix == "" {
		prefix = ctxt.connectedNw.PrimarySubnet
	}
	bgpPeerP := apicapi.NewBGPPeerP(baseObj.GetDn(),
		prefix, ctxt.connectedNw.BGPPeerPolicy.Ctrl,
		ctxt.connectedNw.BGPPeerPolicy.PeerCtl)
	if ctxt.connectedNw.BGPPeerPolicy.Secret.Name != "" {
		namespace := "default"
		if ctxt.connectedNw.BGPPeerPolicy.Secret.Namespace != "" {
			namespace = ctxt.connectedNw.BGPPeerPolicy.Secret.Namespace
		}
		kubeClient := cont.env.(*K8sEnvironment).kubeClient
		secret, err := kubeClient.CoreV1().Secrets(namespace).Get(context.TODO(), ctxt.connectedNw.BGPPeerPolicy.Secret.Name, metav1.GetOptions{})
		if err == nil {
			secBytes := secret.Data["password"]
			password := bytes.NewBuffer(secBytes).String()
			bgpPeerP.SetAttr("password", password)
		} else {
			cont.log.Error(err)
		}
	}
	peerASN := fmt.Sprintf("%d", ctxt.connectedNw.BGPPeerPolicy.PeerASN)
	bgpAsP := apicapi.NewBGPAsP(bgpPeerP.GetDn(), peerASN)
	bgpPeerP.AddChild(bgpAsP)
	if ctxt.connectedNw.BGPPeerPolicy.PrefixPolicy != "" {
		bgpRsPPfxPol := apicapi.NewBGPRsPeerPfxPol(bgpPeerP.GetDn(), ctxt.tenant, ctxt.connectedNw.BGPPeerPolicy.PrefixPolicy)
		bgpPeerP.AddChild(bgpRsPPfxPol)
	}
	baseObj.AddChild(bgpPeerP)
}

func (cont *AciController) createNodeFabNetAttStaticRoutes(ctxt *SviContext, l3extRsNodeL3OutAtt apicapi.ApicObject, node int) {
	if nfTenantData, ok := cont.sharedEncapTenantCache[ctxt.tenant]; ok {
		if nfL3OutData, ok := nfTenantData.L3OutConfig[ctxt.connectedNw.L3OutName]; ok {
			if rtrNode, ok := nfL3OutData.RtrNodeMap[node]; ok {
				for _, staticRoute := range rtrNode.StaticRoutes {
					ipRoute := apicapi.NewIpRouteP(l3extRsNodeL3OutAtt.GetDn(), staticRoute.Prefix, staticRoute.Ctrl)
					for _, nh := range staticRoute.NextHops {
						ipNexthopP := apicapi.NewIpNexthopP(ipRoute.GetDn(), nh.Addr, nh.Preference)
						ipRoute.AddChild(ipNexthopP)
					}
					l3extRsNodeL3OutAtt.AddChild(ipRoute)
				}
			}
		}
	}
}

func (cont *AciController) createNodeFabNetAttSviPaths(vlan int, ctxt *SviContext, fabricLink, pod string, nodes []string) {
	encapVlan := fmt.Sprintf("vlan-%d", vlan)
	podId, _ := strconv.Atoi(pod)
	if ctxt.podId == 0 {
		ctxt.podId = podId
		nfL3Data, ok := cont.sharedEncapSviCache[vlan]
		if ok {
			nfL3Data.PodId = podId
		}
	} else if ctxt.podId != podId {
		cont.log.Errorf("Invalid configuration: cannot associate one vlan across multiple ACI pods: vlan %d, ACI pods: %v", vlan, []int{ctxt.podId, podId})
		return
	}
	if ctxt.connectedNw.SviType == fabattv1.ConventionalSviType {
		_, secondaryAddr, rtdNetData, err := cont.getSviNetworkPool(ctxt, ctxt.connectedNw.PrimarySubnet)
		if err != nil {
			return
		}
		cont.log.Info("Creating regular svi for ", vlan)
		ctxt.l3extRsPath = apicapi.NewL3ExtRsPathL3OutAtt(ctxt.l3outLifP.GetDn(), fabricLink, "ext-svi", encapVlan)
		if len(nodes) > 2 {
			cont.log.Errorf("Static path has more than 2 nodes: %s", fabricLink)
			return
		}
		side := []string{"A", "B"}
		for idx := range nodes {
			primaryAddr, err := cont.allocateSviAddress(vlan, ctxt, rtdNetData, nodes[idx])
			if err != nil {
				continue
			}
			l3extMember := apicapi.NewL3ExtMember(ctxt.l3extRsPath.GetDn(), side[idx], primaryAddr)
			l3extIp := apicapi.NewL3ExtIp(l3extMember.GetDn(), secondaryAddr)
			l3extMember.AddChild(l3extIp)
			for _, fabL3Subnet := range ctxt.connectedNw.Subnets {
				if ctxt.connectedNw.PrimarySubnet == fabL3Subnet.ConnectedSubnet {
					continue
				}
				_, secondaryAddr2, rtdNetData2, err := cont.getSviNetworkPool(ctxt, fabL3Subnet.ConnectedSubnet)
				if err != nil {
					continue
				}
				l3extIp = apicapi.NewL3ExtIp(l3extMember.GetDn(), secondaryAddr2)
				l3extMember.AddChild(l3extIp)
				primaryAddr, err = cont.allocateSviAddress(vlan, ctxt, rtdNetData2, nodes[idx])
				if err != nil {
					l3extIp = apicapi.NewL3ExtIp(l3extMember.GetDn(), primaryAddr)
					l3extMember.AddChild(l3extIp)
				}
			}
			nodeDn := fmt.Sprintf("topology/pod-%s/node-%s", pod, nodes[idx])
			nodeId, _ := strconv.Atoi(nodes[idx])
			rtrId := cont.getNodeRtrId(ctxt, nodeId)
			ctxt.l3extRsPath.AddChild(l3extMember)
			if _, ok := ctxt.nodeMap[nodes[idx]]; !ok {
				ctxt.nodeMap[nodes[idx]] = true
				l3extRsNodeL3OutAtt := apicapi.NewL3ExtRsNodeL3OutAtt(ctxt.l3outNodeP.GetDn(), nodeDn, rtrId)
				cont.createNodeFabNetAttStaticRoutes(ctxt, l3extRsNodeL3OutAtt, nodeId)
				ctxt.l3outNodeP.AddChild(l3extRsNodeL3OutAtt)
			}
		}
		cont.createNodeFabNetAttSviProtocolPolicies(ctxt)
		ctxt.l3outLifP.AddChild(ctxt.l3extRsPath)
		return
	}
	floatingAddr, secondaryAddr, rtdNetData, err := cont.getSviNetworkPool(ctxt, ctxt.connectedNw.PrimarySubnet)
	if err != nil {
		return
	}
	cont.log.Info("Creating floating svi for ", vlan)
	for _, node := range nodes {
		if _, ok := ctxt.nodeMap[node]; !ok {
			var err error
			primaryAddr := ""
			nodeId, _ := strconv.Atoi(node)
			rtrId := cont.getNodeRtrId(ctxt, nodeId)
			nodeDn := fmt.Sprintf("topology/pod-%s/node-%s", pod, node)
			primaryAddr, err = cont.allocateSviAddress(vlan, ctxt, rtdNetData, node)
			if err == nil {
				ctxt.nodeMap[node] = true
				ctxt.l3extVirtualLifP = apicapi.NewL3ExtVirtualLifP(ctxt.l3outLifP.GetDn(), "ext-svi", nodeDn, encapVlan, primaryAddr)
				l3extRsDynPathAtt := apicapi.NewL3ExtRsDynPathAtt(ctxt.l3extVirtualLifP.GetDn(), cont.globalVlanConfig.SharedPhysDom.GetDn(), floatingAddr, encapVlan)
				l3extIp := apicapi.NewL3ExtIp(ctxt.l3extVirtualLifP.GetDn(), secondaryAddr)
				ctxt.l3extVirtualLifP.AddChild(l3extRsDynPathAtt)
				ctxt.l3extVirtualLifP.AddChild(l3extIp)
				for _, fabL3Subnet := range ctxt.connectedNw.Subnets {
					if ctxt.connectedNw.PrimarySubnet == fabL3Subnet.ConnectedSubnet {
						continue
					}
					_, secondaryAddr2, rtdNetData2, err := cont.getSviNetworkPool(ctxt, fabL3Subnet.ConnectedSubnet)
					if err != nil {
						continue
					}
					l3extIp = apicapi.NewL3ExtIp(ctxt.l3extVirtualLifP.GetDn(), secondaryAddr2)
					ctxt.l3extVirtualLifP.AddChild(l3extIp)
					primaryAddr, err = cont.allocateSviAddress(vlan, ctxt, rtdNetData2, node)
					if err != nil {
						l3extIp = apicapi.NewL3ExtIp(ctxt.l3extVirtualLifP.GetDn(), primaryAddr)
						ctxt.l3extVirtualLifP.AddChild(l3extIp)
					}
				}
				cont.createNodeFabNetAttSviProtocolPolicies(ctxt)
				ctxt.l3outLifP.AddChild(ctxt.l3extVirtualLifP)
			}
			l3extRsNodeL3OutAtt := apicapi.NewL3ExtRsNodeL3OutAtt(ctxt.l3outNodeP.GetDn(), nodeDn, rtrId)
			cont.createNodeFabNetAttStaticRoutes(ctxt, l3extRsNodeL3OutAtt, nodeId)
			ctxt.l3outNodeP.AddChild(l3extRsNodeL3OutAtt)
		}
	}

}

func (cont *AciController) createNodeFabNetAttSvi(vlan int, sviContext *SviContext) {
	cont.log.Info("Creating svi for ", vlan)
	prefixPolicyFound := false
	if !sviContext.connectedNw.UseExistingL3Out {
		nfTenantData, tenantConfigured := cont.sharedEncapTenantCache[sviContext.tenant]
		nfL3Out := &NfL3OutData{}
		l3OutConfigured := false
		rtCtrl := ""
		if tenantConfigured {
			nfL3Out, l3OutConfigured := nfTenantData.L3OutConfig[sviContext.connectedNw.L3OutName]
			if l3OutConfigured {
				rtCtrl = nfL3Out.RtCtrl
			}
		}
		sviContext.l3out = apicapi.NewL3ExtOut(sviContext.tenant, sviContext.connectedNw.L3OutName, rtCtrl)
		rsEctx := apicapi.NewL3ExtRsEctx(sviContext.tenant, sviContext.connectedNw.L3OutName, sviContext.vrf.Name)
		sviContext.l3out.AddChild(rsEctx)
		rsl3DomAtt := apicapi.NewL3ExtRsL3DomAtt(sviContext.tenant, sviContext.connectedNw.L3OutName, cont.config.AciL3Dom)
		sviContext.l3out.AddChild(rsl3DomAtt)
		// With pre-existing l3out, an expectation is that atleast one external epg is configured. Otherwise
		// forwarding will not work. For a managed l3out, it is required that user configure one external epg.
		if tenantConfigured && l3OutConfigured {
			for _, extepg := range nfL3Out.ExtEpgMap {
				l3ExtInstP := apicapi.NewL3extInstP(sviContext.tenant, sviContext.connectedNw.L3OutName, extepg.Name)
				for _, pp := range extepg.PolicyPrefixes {
					l3ExtSubnet := apicapi.NewL3extSubnet(l3ExtInstP.GetDn(), pp.Subnet, pp.Scope, pp.Aggregate)
					l3ExtInstP.AddChild(l3ExtSubnet)
				}
				for _, consumer := range extepg.Contracts.Consumer {
					fvRsCons := apicapi.NewFvRsCons(l3ExtInstP.GetDn(), consumer)
					l3ExtInstP.AddChild(fvRsCons)
				}
				for _, provider := range extepg.Contracts.Provider {
					fvRsProv := apicapi.NewFvRsProv(l3ExtInstP.GetDn(), provider)
					l3ExtInstP.AddChild(fvRsProv)
				}
				sviContext.l3out.AddChild(l3ExtInstP)
			}
		}
		if sviContext.connectedNw.BGPPeerPolicy.PrefixPolicy != "" {
			if tenantConfigured {
				if bgpPPP, ok := nfTenantData.BGPPeerPfxConfig[sviContext.connectedNw.BGPPeerPolicy.PrefixPolicy]; ok {
					sviContext.bgpPPP = apicapi.NewBGPPeerPfxPol(sviContext.tenant,
						sviContext.connectedNw.BGPPeerPolicy.PrefixPolicy, bgpPPP.MaxPrefixes, bgpPPP.Action, defaultBGPPrefixThreshold)
					prefixPolicyFound = true
				}
			}
		}
	}
	if sviContext.connectedNw.BGPPeerPolicy.PrefixPolicy != "" {
		if !prefixPolicyFound {
			/*Use default policy*/
			sviContext.bgpPPP = apicapi.NewBGPPeerPfxPol(sviContext.tenant,
				sviContext.connectedNw.BGPPeerPolicy.PrefixPolicy, defaultMaxBGPPrefixes, defaultBGPPrefixAction, defaultBGPPrefixThreshold)
		}
	}
	nodeProfileName := fmt.Sprintf("%s-vlan-%d", sviContext.connectedNw.L3OutName+"_"+globalScopeVlanLNodePPrefix, vlan)
	intfProfileName := fmt.Sprintf("%s-vlan-%d", sviContext.connectedNw.L3OutName+"_"+globalScopeVlanExtLifPPrefix, vlan)
	sviContext.l3outNodeP = apicapi.NewL3ExtLNodeP(sviContext.tenant, sviContext.connectedNw.L3OutName, nodeProfileName)
	sviContext.l3outLifP = apicapi.NewL3ExtLifP(sviContext.tenant, sviContext.connectedNw.L3OutName, nodeProfileName, intfProfileName)
}

func (cont *AciController) getSharedEncapNfCacheSviLocked(encap int) *SviContext {
	sviContext := &SviContext{}
	if nfL3Data, nfcExists := cont.sharedEncapSviCache[encap]; nfcExists {
		sviContext.present = true
		sviContext.tenant = nfL3Data.Tenant
		sviContext.vrf = nfL3Data.Vrf
		sviContext.connectedNw = nfL3Data.ConnectedNw
		sviContext.nodeMap = make(map[string]bool)
	}

	return sviContext
}

func (cont *AciController) populateSviData(sviData *fabattv1.ConnectedL3Network, vrf *fabattv1.VRF) {
	sviTenant := cont.config.AciPolicyTenant
	if sviData.L3OutOnCommonTenant {
		sviTenant = "common"
	}
	nfL3Data := &NfL3Data{
		Tenant: sviTenant,
		Vrf:    *vrf,
		ConnectedNw: &NfL3Networks{
			PrimaryNetwork: sviData.PrimaryNetwork,
			Subnets:        make(map[string]*fabattv1.FabricL3Subnet),
		},
		NetAddr: make(map[string]*RoutedNetworkData),
		Nodes:   make(map[int]fabattv1.FabricL3OutNode),
	}
	for _, subnet := range sviData.Subnets {
		subnetCopy := subnet
		nfL3Data.ConnectedNw.Subnets[subnet.ConnectedSubnet] = &subnetCopy
	}
	for _, fabricNode := range sviData.Nodes {
		fabNode := fabricNode
		nfL3Data.Nodes[fabNode.NodeRef.NodeId] = fabNode
	}
	cont.sharedEncapSviCache[sviData.Encap] = nfL3Data
}

func (cont *AciController) populateTenantData(tenantData *fabattv1.FabricTenantConfiguration, currSviMap map[string]map[string]map[int]bool) (*NfTenantData, string) {
	l3outTenant := cont.config.AciPolicyTenant
	commonTenant := false
	if tenantData.CommonTenant {
		l3outTenant = "common"
		commonTenant = true
	}
	nfTenantData := &NfTenantData{
		CommonTenant:     commonTenant,
		L3OutConfig:      make(map[string]*NfL3OutData),
		BGPPeerPfxConfig: make(map[string]*fabattv1.BGPPeerPrefixPolicy),
	}
	for _, l3OutData := range tenantData.L3OutInstances {
		var sviMap map[int]bool
		if _, ok := currSviMap[l3outTenant]; ok {
			if _, ok := currSviMap[l3outTenant][l3OutData.Name]; ok {
				sviMap = currSviMap[l3outTenant][l3OutData.Name]
			}
		}
		nfL3OutData := cont.populateL3OutData(&l3OutData, sviMap)
		nfTenantData.L3OutConfig[l3OutData.Name] = nfL3OutData
	}
	return nfTenantData, l3outTenant
}

func (cont *AciController) populateL3OutData(l3OutData *fabattv1.FabricL3Out, sviMap map[int]bool) *NfL3OutData {
	nfL3OutData := &NfL3OutData{
		RtCtrl:     l3OutData.RtCtrl,
		PodId:      l3OutData.PodRef.PodId,
		RtrNodeMap: make(map[int]*fabattv1.FabricL3OutRtrNode),
		ExtEpgMap:  make(map[string]*fabattv1.PolicyPrefixGroup),
		SviMap:     make(map[int]bool),
	}
	if sviMap != nil {
		for key := range sviMap {
			nfL3OutData.SviMap[key] = true
		}
	}
	for _, rtrNode := range l3OutData.RtrNodes {
		rtrNode2 := rtrNode
		nfL3OutData.RtrNodeMap[rtrNode.NodeRef.NodeId] = &rtrNode2
	}
	for _, extEpg := range l3OutData.ExternalEpgs {
		extEpg2 := extEpg
		nfL3OutData.ExtEpgMap[extEpg.Name] = &extEpg2
	}
	return nfL3OutData
}

func (cont *AciController) computeFabricL3OutNodes(nfL3Data *NfL3Data) []fabattv1.FabricL3OutNode {
	nodeMap := make(map[string]*fabattv1.FabricL3OutNode)
	fabricL3OutNodes := []fabattv1.FabricL3OutNode{}
	_, nw, _ := net.ParseCIDR(nfL3Data.ConnectedNw.PrimarySubnet)
	for subnet, rtdNetData := range nfL3Data.NetAddr {
		for node, rtdNodeData := range rtdNetData.nodeMap {
			nodeId, err := strconv.Atoi(node)
			if err == nil {
				fabricL3OutNode, ok := nodeMap[node]
				if !ok {
					fabricL3OutNode = &fabattv1.FabricL3OutNode{
						NodeRef: fabattv1.FabricNodeRef{
							FabricPodRef: fabattv1.FabricPodRef{
								PodId: nfL3Data.PodId,
							},
							NodeId: nodeId,
						},
					}
					nodeMap[node] = fabricL3OutNode
				}
				if nw.String() == subnet {
					fabricL3OutNode.PrimaryAddress = rtdNodeData.addr
				} else {
					fabricL3OutNode.SecondaryAddresses = append(fabricL3OutNode.SecondaryAddresses, rtdNodeData.addr)
				}
			}
		}
	}
	for _, fabricL3OutNode := range nodeMap {
		fabricL3OutNodes = append(fabricL3OutNodes, *fabricL3OutNode)
	}
	return fabricL3OutNodes
}

func (cont *AciController) compareSvi(vrf *fabattv1.VRF, sviData *fabattv1.ConnectedL3Network, nfSvi *NfL3Data) bool {
	sviTenant := cont.config.AciPolicyTenant
	if sviData.L3OutOnCommonTenant {
		sviTenant = "common"
	}
	subnetUpdated := false
	if sviData.FabricL3Network.PrimaryNetwork != nfSvi.ConnectedNw.PrimaryNetwork {
		nfSvi.ConnectedNw.PrimaryNetwork = sviData.FabricL3Network.PrimaryNetwork
		subnetUpdated = true
	}
	subnetPresent := make(map[string]bool)
	for _, subnet := range sviData.FabricL3Network.Subnets {
		if nfSubnet, ok := nfSvi.ConnectedNw.Subnets[subnet.ConnectedSubnet]; !ok || subnet != *nfSubnet {
			subnetCopy := subnet
			nfSvi.ConnectedNw.Subnets[subnet.ConnectedSubnet] = &subnetCopy
			subnetUpdated = true
		}
		subnetPresent[subnet.ConnectedSubnet] = true
	}
	for subnet := range nfSvi.ConnectedNw.Subnets {
		if _, ok := subnetPresent[subnet]; !ok {
			delete(nfSvi.ConnectedNw.Subnets, subnet)
			subnetUpdated = true
		}
	}
	return subnetUpdated || sviTenant != nfSvi.Tenant || *vrf != cont.sharedEncapSviCache[sviData.Encap].Vrf
}

func (cont *AciController) compareL3Out(vrf *fabattv1.VRF, l3Out *fabattv1.FabricL3Out, nfL3Out *NfL3OutData) bool {
	if l3Out.RtCtrl != nfL3Out.RtCtrl || l3Out.PodRef.PodId != nfL3Out.PodId ||
		(len(l3Out.RtrNodes) != len(nfL3Out.RtrNodeMap)) || (len(l3Out.ExternalEpgs) != len(nfL3Out.ExtEpgMap)) {
		return true
	}
	for _, rtrNode := range l3Out.RtrNodes {
		if nfRtrNode, ok := nfL3Out.RtrNodeMap[rtrNode.NodeRef.NodeId]; !ok {
			return true
		} else if !reflect.DeepEqual(*nfRtrNode, rtrNode) {
			return true
		}
	}
	for _, extEpg := range l3Out.ExternalEpgs {
		if nfExtEpg, ok := nfL3Out.ExtEpgMap[extEpg.Name]; !ok {
			return true
		} else if !reflect.DeepEqual(*nfExtEpg, extEpg) {
			return true
		}
	}
	return false
}

func (cont *AciController) getL3OutTenant(tenantData *fabattv1.FabricTenantConfiguration) string {

	l3outTenant := cont.config.AciPolicyTenant
	if tenantData.CommonTenant {
		l3outTenant = "common"
	}
	return l3outTenant
}

func (cont *AciController) getSviL3OutTenant(sviData *fabattv1.ConnectedL3Network) string {
	l3outTenant := cont.config.AciPolicyTenant
	if sviData.L3OutOnCommonTenant {
		l3outTenant = "common"
	}
	return l3outTenant
}

func (cont *AciController) getNfSviVrfKey(nfL3Data *NfL3Data) string {

	vrfTenant := cont.config.AciPolicyTenant
	if nfL3Data.Vrf.CommonTenant {
		vrfTenant = "common"
	}
	vrfKey := vrfTenant + "/" + nfL3Data.Vrf.Name
	return vrfKey
}

func (cont *AciController) updateNetworkFabricL3ConfigObj(obj *fabattv1.NetworkFabricL3Configuration) map[string]apicapi.ApicSlice {
	progMap := make(map[string]apicapi.ApicSlice)
	cont.log.Info("networkFabricL3Configuration update: ")
	currSviMap := make(map[int]bool)
	currVrfMap := make(map[string]bool)
	currTenantMap := make(map[string]bool)
	currL3OutMap := make(map[string]map[string]map[int]bool)
	affectedVlanMap := make(map[int]bool)
	cont.indexMutex.Lock()
	for _, vrf := range obj.Spec.Vrfs {
		vrfTenant := cont.config.AciPolicyTenant
		if vrf.Vrf.CommonTenant {
			vrfTenant = "common"
		}
		vrfKey := vrfTenant + "/" + vrf.Vrf.Name
		if nfVrfData, ok := cont.sharedEncapVrfCache[vrfKey]; !ok {
			nfVrfData = &NfVrfData{
				TenantConfig: make(map[string]*NfTenantData),
			}
			for _, sviData := range vrf.DirectlyConnectedNetworks {
				sviDataCopy := sviData
				cont.populateSviData(&sviDataCopy, &vrf.Vrf)
				affectedVlanMap[sviData.Encap] = true
				currSviMap[sviData.Encap] = true
				l3outTenant := cont.getSviL3OutTenant(&sviData)
				l3outMap, ok := currL3OutMap[l3outTenant]
				if !ok {
					l3outMap = make(map[string]map[int]bool)
					l3outMap[sviData.L3OutName] = make(map[int]bool)
					l3outMap[sviData.L3OutName][sviData.Encap] = true
				} else {
					sviMap, ok := l3outMap[sviData.L3OutName]
					if !ok {
						sviMap = make(map[int]bool)
					}
					sviMap[sviData.Encap] = true
					l3outMap[sviData.L3OutName] = sviMap
				}
				currL3OutMap[l3outTenant] = l3outMap
			}
			for _, tenantData := range vrf.Tenants {
				l3outTenant := cont.getL3OutTenant(&tenantData)
				nfTenantData, tenantExisting := cont.sharedEncapTenantCache[l3outTenant]
				if !tenantExisting {
					nfTenantData, _ = cont.populateTenantData(&tenantData, currL3OutMap)
					nfVrfData.TenantConfig[l3outTenant] = nfTenantData
				} else {
					for _, l3out := range tenantData.L3OutInstances {
						if l3outData, ok := nfTenantData.L3OutConfig[l3out.Name]; !ok {
							var sviMap map[int]bool
							if _, ok := currL3OutMap[l3outTenant]; ok {
								if _, ok := currL3OutMap[l3outTenant][l3out.Name]; ok {
									sviMap = currL3OutMap[l3outTenant][l3out.Name]
								}
							}
							l3outData = cont.populateL3OutData(&l3out, sviMap)
							nfTenantData.L3OutConfig[l3out.Name] = l3outData
						}
						// L3Out cannot be pre-existing since VRF is new here
					}
				}
				currTenantMap[l3outTenant] = true
			}
			cont.sharedEncapVrfCache[vrfKey] = nfVrfData
		} else {
			for _, sviData := range vrf.DirectlyConnectedNetworks {
				sviDataCopy := sviData
				sviTenant := cont.getSviL3OutTenant(&sviData)
				if nfSvi, ok := cont.sharedEncapSviCache[sviData.Encap]; !ok {
					cont.populateSviData(&sviDataCopy, &vrf.Vrf)
					affectedVlanMap[sviData.Encap] = true
				} else if cont.compareSvi(&vrf.Vrf, &sviData, nfSvi) {
					cont.sharedEncapSviCache[sviData.Encap].ConnectedNw = &NfL3Networks{
						PrimaryNetwork: sviDataCopy.FabricL3Network.PrimaryNetwork,
						Subnets:        make(map[string]*fabattv1.FabricL3Subnet),
					}
					for _, fabSubnet := range sviDataCopy.FabricL3Network.Subnets {
						fabSubnet2 := fabSubnet
						cont.sharedEncapSviCache[sviData.Encap].ConnectedNw.Subnets[fabSubnet.ConnectedSubnet] = &fabSubnet2
					}
					cont.sharedEncapSviCache[sviData.Encap].Tenant = sviTenant
					cont.sharedEncapSviCache[sviData.Encap].Vrf = vrf.Vrf
					affectedVlanMap[sviData.Encap] = true
				}
				currSviMap[sviData.Encap] = true
				l3outMap, ok := currL3OutMap[sviTenant]
				if !ok {
					l3outMap = make(map[string]map[int]bool)
					l3outMap[sviData.L3OutName] = make(map[int]bool)
					l3outMap[sviData.L3OutName][sviData.Encap] = true
				} else {
					sviMap, ok := l3outMap[sviData.L3OutName]
					if !ok {
						sviMap = make(map[int]bool)
					}
					sviMap[sviData.Encap] = true
					l3outMap[sviData.L3OutName] = sviMap
				}
				currL3OutMap[sviTenant] = l3outMap
			}
			for _, tenantData := range vrf.Tenants {
				l3outTenant := cont.config.AciPolicyTenant
				if tenantData.CommonTenant {
					l3outTenant = "common"
				}
				if nfTenantData, ok := cont.sharedEncapTenantCache[l3outTenant]; !ok {
					nfTenantData, l3outTenant := cont.populateTenantData(&tenantData, currL3OutMap)
					nfVrfData.TenantConfig[l3outTenant] = nfTenantData
				} else {
					for _, l3OutData := range tenantData.L3OutInstances {
						var sviMap map[int]bool
						if _, ok := currL3OutMap[l3outTenant]; ok {
							if _, ok := currL3OutMap[l3outTenant][l3OutData.Name]; ok {
								sviMap = currL3OutMap[l3outTenant][l3OutData.Name]
							}
						}
						if nfL3OutData, ok := nfTenantData.L3OutConfig[l3OutData.Name]; !ok {
							nfL3OutData := cont.populateL3OutData(&l3OutData, sviMap)
							nfTenantData.L3OutConfig[l3OutData.Name] = nfL3OutData
						} else {
							nfL3OutData.SviMap = sviMap
							if cont.compareL3Out(&vrf.Vrf, &l3OutData, nfL3OutData) {
								nfL3OutData.RtCtrl = l3OutData.RtCtrl
								nfL3OutData.PodId = l3OutData.PodRef.PodId
								nfL3OutData.RtrNodeMap = make(map[int]*fabattv1.FabricL3OutRtrNode)
								for _, rtrNode := range l3OutData.RtrNodes {
									rtrNode2 := rtrNode
									nfL3OutData.RtrNodeMap[rtrNode.NodeRef.NodeId] = &rtrNode2
								}
								nfL3OutData.ExtEpgMap = make(map[string]*fabattv1.PolicyPrefixGroup)
								for _, extEpg := range l3OutData.ExternalEpgs {
									extEpg2 := extEpg
									nfL3OutData.ExtEpgMap[extEpg.Name] = &extEpg2
								}
								for vlan := range sviMap {
									affectedVlanMap[vlan] = true
								}
							}
							nfTenantData.L3OutConfig[l3OutData.Name] = nfL3OutData
						}
					}
					nfVrfData.TenantConfig[l3outTenant] = nfTenantData
				}
				currTenantMap[l3outTenant] = true
			}
			cont.sharedEncapVrfCache[vrfKey] = nfVrfData
		}
		currVrfMap[vrfKey] = true
	}

	for encap := range cont.sharedEncapSviCache {
		if _, ok := currSviMap[encap]; !ok {
			delete(cont.sharedEncapSviCache, encap)
			affectedVlanMap[encap] = true
		}
	}
	for vrf := range cont.sharedEncapVrfCache {
		if _, ok := currVrfMap[vrf]; !ok {
			delete(cont.sharedEncapVrfCache, vrf)
		}
	}
	for tenant := range cont.sharedEncapTenantCache {
		if _, ok := currTenantMap[tenant]; !ok {
			delete(cont.sharedEncapTenantCache, tenant)
		}
	}
	cont.indexMutex.Unlock()
	affectedVlans := []int{}
	for vlan := range affectedVlanMap {
		affectedVlans = append(affectedVlans, vlan)
	}
	cont.updateNodeFabNetAttStaticAttachments(affectedVlans, progMap)
	return progMap
}

func (cont *AciController) deleteNetworkFabricL3ConfigObj() map[string]apicapi.ApicSlice {
	progMap := make(map[string]apicapi.ApicSlice)
	affectedVlans := []int{}
	cont.log.Info("networkFabricL3Configuration delete: ")
	cont.indexMutex.Lock()
	for encap := range cont.sharedEncapSviCache {
		delete(cont.sharedEncapSviCache, encap)
		affectedVlans = append(affectedVlans, encap)
	}
	cont.indexMutex.Unlock()
	cont.updateNodeFabNetAttStaticAttachments(affectedVlans, progMap)
	return progMap
}

// func returns false if executed without error, true if the caller has to requeue.
func (cont *AciController) handleNetworkFabricL3ConfigurationUpdate(obj interface{}) bool {
	netFabL3Config, ok := obj.(*fabattv1.NetworkFabricL3Configuration)
	if !ok {
		cont.log.Error("handleNetworkFabricL3ConfigurationUpdate: Bad object type")
		return false
	}
	progMap := cont.updateNetworkFabricL3ConfigObj(netFabL3Config)
	for labelKey, apicSlice := range progMap {
		if apicSlice == nil {
			cont.apicConn.ClearApicObjects(labelKey)
			continue
		}
		cont.apicConn.WriteApicObjects(labelKey, apicSlice)
	}
	return false
}

func (cont *AciController) handleNetworkFabricL3ConfigurationDelete(key string) bool {
	progMap := cont.deleteNetworkFabricL3ConfigObj()
	for labelKey, apicSlice := range progMap {
		if apicSlice == nil {
			cont.apicConn.ClearApicObjects(labelKey)
			continue
		}
		cont.apicConn.WriteApicObjects(labelKey, apicSlice)
	}
	return false
}

/* TODO: Fix this
func (cont *AciController) restoreNetworkFabricL3ConfigurationStatus() {

		fabl3Config, err := cont.fabNetAttClient.AciV1().NetworkFabricL3Configurations(metav1.NamespaceAll).Get(context.TODO(), "networkfabricl3configuration", metav1.GetOptions{})
		if err == nil {
			//for _, vrfData := range fabl3Config.Status.Vrfs {
			//		vrfKey := cont.getL3OutVrfKey(vrfData.Vrf)
			//}
		} else {
			cont.log.Errorf("%v. Skip restoring NetworkFabricL3Configuration status", err)
		}
}
*/

func (cont *AciController) computeNetworkFabricL3ConfigurationStatus() *fabattv1.NetworkFabricL3ConfigStatus {
	fabVrfs := make(map[string]*fabattv1.FabricVrfConfigurationStatus)
	fabTenants := make(map[string]*fabattv1.FabricTenantConfiguration)

	fabL3ConfigStatus := &fabattv1.NetworkFabricL3ConfigStatus{}
	for _, sviData := range cont.sharedEncapSviCache {
		if len(sviData.NetAddr) > 0 {
			vrfErrStr := ""
			vrfKey := cont.getNfSviVrfKey(sviData)
			fabVrf, ok := fabVrfs[vrfKey]
			if !ok {
				fabVrf = &fabattv1.FabricVrfConfigurationStatus{
					FabricVrfConfiguration: fabattv1.FabricVrfConfiguration{
						Vrf: sviData.Vrf,
					},
				}
			}
			connectedL3Network := fabattv1.ConnectedL3Network{
				FabricL3Network: fabattv1.FabricL3Network{
					PrimaryNetwork: sviData.ConnectedNw.PrimaryNetwork,
				},
			}
			subnets := []fabattv1.FabricL3Subnet{}
			for _, fabL3Subnet := range sviData.ConnectedNw.Subnets {
				subnets = append(subnets, *fabL3Subnet)
			}
			connectedL3Network.FabricL3Network.Subnets = subnets
			connectedL3Network.Nodes = cont.computeFabricL3OutNodes(sviData)
			fabVrf.DirectlyConnectedNetworks = append(fabVrf.DirectlyConnectedNetworks, connectedL3Network)
			fabVrfs[vrfKey] = fabVrf
			tenantData, ok := fabTenants[sviData.Tenant]
			if !ok {
				commonTenant := false
				if sviData.Tenant == "common" {
					commonTenant = true
				}
				tenantData = &fabattv1.FabricTenantConfiguration{
					CommonTenant: commonTenant,
				}
			}
			nfTenantData, ok := cont.sharedEncapTenantCache[sviData.Tenant]
			if !ok {
				l3OutData := fabattv1.FabricL3Out{
					Name:   connectedL3Network.L3OutName,
					PodRef: fabattv1.FabricPodRef{PodId: sviData.PodId},
				}
				for _, node := range connectedL3Network.Nodes {
					nodeId := node.NodeRef.NodeId
					nodeIdMod := nodeId % 256
					rtrNode := &fabattv1.FabricL3OutRtrNode{
						NodeRef: node.NodeRef,
						RtrId:   fmt.Sprintf("%d.%d.%d.%d", nodeIdMod, nodeIdMod, nodeId/256, nodeIdMod),
					}
					l3OutData.RtrNodes = append(l3OutData.RtrNodes, *rtrNode)
				}
				if len(l3OutData.RtrNodes) > 0 {
					tenantData.L3OutInstances = append(tenantData.L3OutInstances, l3OutData)
					fabVrf.Tenants = append(fabVrf.Tenants, *tenantData)
					if vrfErrStr != "" {
						if fabVrf.Status != "" {
							fabVrf.Status += "/n"
						}
						fabVrf.Status += vrfErrStr
					}
				}
				continue
			}
			for l3OutName, nfL3OutData := range nfTenantData.L3OutConfig {
				l3OutData := fabattv1.FabricL3Out{
					Name:   l3OutName,
					RtCtrl: nfL3OutData.RtCtrl,
					PodRef: fabattv1.FabricPodRef{PodId: nfL3OutData.PodId},
				}
				for _, node := range connectedL3Network.Nodes {
					if rtrNode, ok := nfL3OutData.RtrNodeMap[node.NodeRef.NodeId]; ok {
						l3OutData.RtrNodes = append(l3OutData.RtrNodes, *rtrNode)
						continue
					}
					nodeId := node.NodeRef.NodeId
					nodeIdMod := nodeId % 256
					rtrNode := &fabattv1.FabricL3OutRtrNode{
						NodeRef: node.NodeRef,
						RtrId:   fmt.Sprintf("%d.%d.%d.%d", nodeIdMod, nodeIdMod, nodeId/256, nodeIdMod),
					}
					l3OutData.RtrNodes = append(l3OutData.RtrNodes, *rtrNode)
				}
				for _, rtrNode := range nfL3OutData.RtrNodeMap {
					l3OutData.RtrNodes = append(l3OutData.RtrNodes, *rtrNode)
				}
				for _, pPfxGroup := range nfL3OutData.ExtEpgMap {
					l3OutData.ExternalEpgs = append(l3OutData.ExternalEpgs, *pPfxGroup)
				}
				tenantData.L3OutInstances = append(tenantData.L3OutInstances, l3OutData)
			}
			for _, bgpPeerPrefixPolicy := range nfTenantData.BGPPeerPfxConfig {
				tenantData.BGPPeerPrefixPolicies = append(tenantData.BGPPeerPrefixPolicies, *bgpPeerPrefixPolicy)
			}
			fabVrf.Tenants = append(fabVrf.Tenants, *tenantData)
			if vrfErrStr != "" {
				if fabVrf.Status != "" {
					fabVrf.Status += "/n"
				}
				fabVrf.Status += vrfErrStr
			}
		}
	}
	for _, fabVrf := range fabVrfs {
		fabL3ConfigStatus.Vrfs = append(fabL3ConfigStatus.Vrfs, *fabVrf)
	}
	return fabL3ConfigStatus

}

func (cont *AciController) updateNetworkFabricL3ConfigurationStatus() {
	if cont.unitTestMode {
		return
	}
	fabl3Config, err := cont.fabNetAttClient.AciV1().NetworkFabricL3Configurations(metav1.NamespaceAll).Get(context.TODO(), "networkfabricl3configuration", metav1.GetOptions{})
	if err == nil {
		fabl3Config.Status = *cont.computeNetworkFabricL3ConfigurationStatus()
		_, err = cont.fabNetAttClient.AciV1().NetworkFabricL3Configurations(metav1.NamespaceAll).UpdateStatus(context.TODO(), fabl3Config, metav1.UpdateOptions{})
		if err != nil {
			cont.log.Errorf("Failed to update NetworkFabricL3ConfigurationStatus: %v", err)
		}
	} else {
		cont.log.Errorf("%v. Skip updating status", err)
	}
}
