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

// Handlers for node fabric network attachments updates.

package controller

import (
	"fmt"
	fabattv1 "github.com/noironetworks/aci-containers/pkg/fabricattachment/apis/aci.fabricattachment/v1"
	fabattclset "github.com/noironetworks/aci-containers/pkg/fabricattachment/clientset/versioned"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/tools/cache"
	"strconv"
	"strings"

	"github.com/noironetworks/aci-containers/pkg/apicapi"
)

const (
	nodeFabNetAttCRDName     = "nodefabricnetworkattachments.aci.fabricattachment"
	globalScopeVlanEpgPrefix = "secondary-vlan"
	globalScopeVlanBdPrefix  = "secondary-bd"
	globalScopeVlanDomPrefix = "secondary"
)

func NodeFabricNetworkAttachmentLogger(log *logrus.Logger, nodeFabNetAtt *fabattv1.NodeFabricNetworkAttachment) *logrus.Entry {
	return log.WithFields(logrus.Fields{
		"name": nodeFabNetAtt.ObjectMeta.Name,
		"spec": nodeFabNetAtt.Spec,
	})
}

func nodeFabNetAttInit(cont *AciController, stopCh <-chan struct{}) {
	cont.log.Debug("Initializing nodefabricnetworkattachment client")
	restconfig := cont.env.RESTConfig()
	fabNetAttClient, err := fabattclset.NewForConfig(restconfig)
	if err != nil {
		cont.log.Errorf("Failed to intialize nodefabricnetworkattachment client")
		return
	}
	cont.initNodeFabNetAttInformerFromClient(fabNetAttClient)
	go cont.nodeFabNetAttInformer.Run(stopCh)
	go cont.processQueue(cont.nodeFabNetAttQueue, cont.nodeFabNetAttIndexer,
		func(obj interface{}) bool {
			return cont.handleNodeFabricNetworkAttachmentUpdate(obj)
		}, func(key string) bool {
			return cont.handleNodeFabricNetworkAttachmentDelete(key)
		}, nil, stopCh)
	cache.WaitForCacheSync(stopCh, cont.nodeFabNetAttInformer.HasSynced)
}

func (cont *AciController) staticChainedModeObjs() apicapi.ApicSlice {
	var apicSlice apicapi.ApicSlice
	tenant := apicapi.NewFvTenant(cont.config.AciPolicyTenant)
	ap := apicapi.NewFvAP("netop-" + cont.config.AciPolicyTenant)
	bd := apicapi.NewFvBD(cont.config.AciPolicyTenant, "netop-nodes")
	bd.SetAttr("arpFlood", "yes")
	bd.SetAttr("ipLearning", "no")
	bd.SetAttr("unkMacUcastAct", "flood")
	fvRsCtx := apicapi.NewFvRsCtx(bd.GetDn(), cont.config.AciVrf)
	bd.AddChild(fvRsCtx)
	epg := apicapi.NewFvAEPg(cont.config.AciPolicyTenant, "netop-"+cont.config.AciPolicyTenant, "netop-nodes")
	fvRsBd := apicapi.NewFvRsBD(epg.GetDn(), "netop-nodes")
	epg.AddChild(fvRsBd)
	fvRsDomAtt := apicapi.NewFvRsDomAttPhysDom(epg.GetDn(), cont.config.AciPhysDom)
	epg.AddChild(fvRsDomAtt)
	ap.AddChild(epg)
	tenant.AddChild(bd)
	tenant.AddChild(ap)
	apicSlice = append(apicSlice, tenant)
	return apicSlice
}

func (cont *AciController) initStaticChainedModeObjs() {
	if !cont.config.ReconcileStaticObjects {
		return
	}
	cont.apicConn.WriteApicObjects(cont.config.AciPrefix+"_chainedmode_static",
		cont.staticChainedModeObjs())
}

func (cont *AciController) initNodeFabNetAttInformerFromClient(fabAttClient *fabattclset.Clientset) {
	cont.initNodeFabNetAttInformerBase(
		cache.NewListWatchFromClient(
			fabAttClient.AciV1().RESTClient(), "nodefabricnetworkattachments",
			"aci-containers-system", fields.Everything()))
}

func (cont *AciController) initNodeFabNetAttInformerBase(listWatch *cache.ListWatch) {
	cont.nodeFabNetAttIndexer, cont.nodeFabNetAttInformer = cache.NewIndexerInformer(
		listWatch, &fabattv1.NodeFabricNetworkAttachment{}, 0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				cont.nodeFabNetAttChanged(obj)
			},
			UpdateFunc: func(_ interface{}, obj interface{}) {
				cont.nodeFabNetAttChanged(obj)
			},
			DeleteFunc: func(obj interface{}) {
				cont.nodeFabNetAttDeleted(obj)
			},
		},
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
}

func (cont *AciController) clearGlobalScopeVlanConfig(progMap map[string]apicapi.ApicSlice) {
	labelKey := cont.aciNameForKey("nfna", globalScopeVlanDomPrefix)
	progMap[labelKey] = nil
	labelKey = cont.aciNameForKey("nfna", globalScopeVlanBdPrefix)
	progMap[labelKey] = nil
	cont.globalVlanConfig.SharedPhysDom = nil
}

func (cont *AciController) setGlobalScopeVlanConfig(encapStr string, progMap map[string]apicapi.ApicSlice) {
	var apicSlice apicapi.ApicSlice
	if !cont.config.AciUseGlobalScopeVlan {
		cont.log.Errorf("Cannot set globalscope objects in per-port vlan mode")
		return
	}
	if cont.globalVlanConfig.SharedPhysDom != nil {
		return
	}
	_, encapBlks, err := cont.parseNodeFabNetAttVlanList(encapStr)
	if err != nil {
		cont.log.Errorf("Error setting GlobalScopeVlanConfig: %v", err)
		return
	}
	apicSlice = cont.updateNodeFabNetAttDom(encapBlks, globalScopeVlanDomPrefix)
	labelKey := cont.aciNameForKey("nfna", globalScopeVlanDomPrefix)
	progMap[labelKey] = apicSlice
	var apicSlice2 apicapi.ApicSlice
	apicSlice2 = append(apicSlice2, cont.createNodeFabNetAttBd(globalScopeVlanBdPrefix))
	labelKey = cont.aciNameForKey("nfna", globalScopeVlanBdPrefix)
	progMap[labelKey] = apicSlice2
}

func (cont *AciController) getLLDPIf(fabricLink string) string {
	var lldpIf, apicIf string
	if lldpIf, ok := cont.lldpIfCache[fabricLink]; ok {
		return lldpIf
	}
	fabricPathParts := strings.SplitN(fabricLink, "/", 4)
	if len(fabricPathParts) < 4 {
		cont.log.Errorf("getLLDPIf: fabricPath(%s) is not formed properly: %d",
			fabricLink, len(fabricPathParts))
		return lldpIf
	}
	apicPodLeaf := fabricPathParts[0] + "/" + fabricPathParts[1] + "/" + fabricPathParts[2]
	_, portStr, _ := strings.Cut(fabricPathParts[3], "[")
	apicIf, _, _ = strings.Cut(portStr, "]")
	lldpIfQuery := fmt.Sprintf("/api/node/mo/%s/sys/lldp/inst/if-[%s].json?query-target=self", apicPodLeaf, apicIf)
	apicresp, err := cont.apicConn.GetApicResponse(lldpIfQuery)
	if err != nil {
		cont.log.Errorf("getLLDPIf: apic error for lldpIf %s: %v", fabricLink, err)
		return lldpIf
	}
	for _, obj := range apicresp.Imdata {
		lresp, ok := obj["lldpIf"]
		if !ok {
			cont.log.Errorf("getLLDPIf: lldpIf Object not found in response")
			break
		}
		if val, ok := lresp.Attributes["portDesc"]; ok {
			lldpIf = val.(string)
		} else {
			cont.log.Errorf("getLLDPIf: portDesc missing for lldpIf %s: %v", fabricLink, err)
			break
		}
	}
	if lldpIf != "" {
		cont.lldpIfCache[fabricLink] = lldpIf
		cont.log.Infof("getLLDPIf: Found port=>pc/vpc mapping: %s=>%s", fabricLink, lldpIf)
	}
	return lldpIf
}

func (cont *AciController) depopulateFabricPaths(epg apicapi.ApicObject, encap int, nodeFabNetAttKey string) apicapi.ApicSlice {
	var apicSlice apicapi.ApicSlice
	if !cont.config.AciUseGlobalScopeVlan {
		return nil
	}
	nfnaMap := cont.sharedEncapCache[encap]
	for nfnaKey, currNet := range nfnaMap {
		if nfnaKey == nodeFabNetAttKey {
			continue
		}
		apicSlice = cont.populateNodeFabNetAttPaths(epg, encap, currNet, apicSlice)
	}
	return apicSlice
}

func (cont *AciController) populateNodeFabNetAttPaths(epg apicapi.ApicObject, encap int, addNet *AdditionalNetworkMeta, apicSlice apicapi.ApicSlice) apicapi.ApicSlice {
	fabLinks := make(map[string]bool)
	encapVlan := fmt.Sprintf("%d", encap)
	for _, localIfaceMap := range addNet.FabricLink {
		for localIface, fabricLinks := range localIfaceMap {
			var actualFabricLink, vpcIf string
			// Check if port is part of a PC
			for i := range fabricLinks {
				lldpIf := cont.getLLDPIf(fabricLinks[i])
				if vpcIf != "" && lldpIf != vpcIf {
					cont.log.Errorf(" Individual fabricLinks are part of different vpcs(%s): %s %s", localIface, lldpIf, vpcIf)
					continue
				}
				vpcIf = lldpIf
			}
			if len(fabricLinks) > 2 {
				cont.log.Errorf("populate Failed : %d(>2) fabriclinks found ", len(fabricLinks))
				continue
			}
			if vpcIf != "" {
				actualFabricLink = vpcIf
			} else {
				actualFabricLink = strings.Replace(fabricLinks[0], "node-", "paths-", 1)
			}
			// eliminate duplicates in case of VPC links
			if _, ok := fabLinks[actualFabricLink]; !ok {
				fabLinks[actualFabricLink] = true
				fvRsPathAtt := apicapi.NewFvRsPathAtt(epg.GetDn(), actualFabricLink, encapVlan)
				epg.AddChild(fvRsPathAtt)
			}
		}
	}
	apicSlice = append(apicSlice, epg)
	return apicSlice
}

func (cont *AciController) populateFabricPaths(epg apicapi.ApicObject, encap int, addNet *AdditionalNetworkMeta, apicSlice apicapi.ApicSlice) apicapi.ApicSlice {
	if cont.config.AciUseGlobalScopeVlan {
		nfnaMap := cont.sharedEncapCache[encap]
		for _, currNet := range nfnaMap {
			apicSlice = cont.populateNodeFabNetAttPaths(epg, encap, currNet, apicSlice)
		}
		return apicSlice
	} else {
		return cont.populateNodeFabNetAttPaths(epg, encap, addNet, apicSlice)
	}
}

func (cont *AciController) parseNodeFabNetAttVlanList(vlan string) (vlans []int, vlanBlks []string, err error) {
	listContents := vlan
	_, after, found := strings.Cut(vlan, "[")
	if found {
		listContents, _, found = strings.Cut(after, "]")
		if !found {
			err := fmt.Errorf("Failed to parse vlan list: Mismatched brackets: %s", vlan)
			return vlans, vlanBlks, err
		}
	}
	vlanElems := strings.Split(listContents, ",")
	for idx := range vlanElems {
		vlanStr := strings.TrimSpace(vlanElems[idx])
		if strings.Contains(vlanStr, "-") {
			rangeErr := fmt.Errorf("Failed to parse vlan list: vlan range unformed: %s[%s]", vlan, vlanStr)
			vlanRange := strings.Split(vlanStr, "-")
			if len(vlanRange) != 2 {
				return vlans, vlanBlks, rangeErr
			}
			vlanFrom, errFrom := strconv.Atoi(vlanRange[0])
			vlanTo, errTo := strconv.Atoi(vlanRange[1])
			if errFrom != nil || errTo != nil {
				return vlans, vlanBlks, rangeErr
			}
			if vlanFrom > vlanTo || vlanTo > 4095 {
				return vlans, vlanBlks, rangeErr
			}
			for i := vlanFrom; i <= vlanTo; i++ {
				vlans = append(vlans, i)
			}
		} else {
			vlan, err := strconv.Atoi(vlanStr)
			if err != nil || vlan > 4095 {
				err := fmt.Errorf("Failed to parse vlan list: vlan incorrect: %d[%s]", vlan, vlanStr)
				return vlans, vlanBlks, err
			}
			vlans = append(vlans, vlan)
		}
		vlanBlks = append(vlanBlks, vlanStr)
	}
	return vlans, vlanBlks, err
}

func (cont *AciController) createNodeFabNetAttBd(name string) apicapi.ApicObject {
	bd := apicapi.NewFvBD(cont.config.AciPolicyTenant, name)
	bd.SetAttr("arpFlood", "yes")
	bd.SetAttr("ipLearning", "no")
	bd.SetAttr("unkMacUcastAct", "flood")
	bd.SetAttr("unicastRoute", "no")
	fvRsCtx := apicapi.NewFvRsCtx(bd.GetDn(), cont.config.AciVrf)
	bd.AddChild(fvRsCtx)
	return bd
}

func (cont *AciController) createNodeFabNetAttEpg(vlan int, name string) apicapi.ApicObject {
	var fvRsDomAtt apicapi.ApicObject
	apName := "netop-" + cont.config.AciPolicyTenant
	var epgName, bdName string
	if !cont.config.AciUseGlobalScopeVlan {
		epgName = fmt.Sprintf("%s-vlan-%d", name, vlan)
		bdName = name
	} else {
		epgName = fmt.Sprintf("%s-%d", globalScopeVlanEpgPrefix, vlan)
		bdName = globalScopeVlanBdPrefix
	}
	epg := apicapi.NewFvAEPg(cont.config.AciPolicyTenant, apName, epgName)
	fvRsBd := apicapi.NewFvRsBD(epg.GetDn(), bdName)
	epg.AddChild(fvRsBd)
	if !cont.config.AciUseGlobalScopeVlan {
		fvRsDomAtt = apicapi.NewFvRsDomAttPhysDom(epg.GetDn(), cont.config.AciPolicyTenant+"-"+name)
	} else {
		fvRsDomAtt = apicapi.NewFvRsDomAttPhysDom(epg.GetDn(), cont.config.AciPolicyTenant+"-"+globalScopeVlanDomPrefix)
	}
	epg.AddChild(fvRsDomAtt)
	return epg
}

func (cont *AciController) updateNodeFabNetAttDom(encapBlks []string, networkName string) apicapi.ApicSlice {
	var apicSlice apicapi.ApicSlice
	// Create vlan pool
	fvnsVlanInstP := apicapi.NewFvnsVlanInstP(cont.config.AciPolicyTenant, networkName)
	// Create vlan blocks
	for _, encapBlk := range encapBlks {
		var vlanRange []string
		vlanStr := strings.TrimSpace(encapBlk)
		if strings.Contains(encapBlk, "-") {
			vlanRange = strings.Split(vlanStr, "-")
		} else {
			vlanRange = append(vlanRange, vlanStr)
			vlanRange = append(vlanRange, vlanStr)
		}
		fvnsEncapBlk := apicapi.NewFvnsEncapBlk(fvnsVlanInstP.GetDn(), vlanRange[0], vlanRange[1])
		fvnsVlanInstP.AddChild(fvnsEncapBlk)
	}
	apicSlice = append(apicSlice, fvnsVlanInstP)
	// Create physdom
	physDom := apicapi.NewPhysDomP(cont.config.AciPolicyTenant + "-" + networkName)
	infraRsVlanNs := apicapi.NewInfraRsVlanNs(physDom.GetDn(), fvnsVlanInstP.GetDn())
	physDom.AddChild(infraRsVlanNs)
	apicSlice = append(apicSlice, physDom)
	// associate aep with physdom
	secondaryAepDn := "uni/infra/attentp-" + cont.config.AciAdditionalAep
	infraRsDomP := apicapi.NewInfraRsDomP(secondaryAepDn, physDom.GetDn())
	apicSlice = append(apicSlice, infraRsDomP)
	if cont.config.AciUseGlobalScopeVlan {
		cont.globalVlanConfig.SharedPhysDom = physDom
	}
	return apicSlice

}

func (cont *AciController) deleteNodeFabNetAttGlobalEncapVlan(vlan int, nodeFabNetAttKey string, progMap map[string]apicapi.ApicSlice) {
	epgName := fmt.Sprintf("%s-%d", globalScopeVlanEpgPrefix, vlan)
	labelKey := cont.aciNameForKey("nfna", epgName)
	nfnaMap := cont.sharedEncapCache[vlan]
	delete(nfnaMap, nodeFabNetAttKey)
	cont.sharedEncapCache[vlan] = nfnaMap
	if len(cont.sharedEncapCache[vlan]) == 0 {
		cont.log.Infof("clear shared encap epg: %d", vlan)
		progMap[labelKey] = nil
		delete(cont.sharedEncapCache, vlan)
		return
	}
	epg := cont.createNodeFabNetAttEpg(vlan, globalScopeVlanEpgPrefix)
	apicSlice := cont.depopulateFabricPaths(epg, vlan, nodeFabNetAttKey)
	progMap[labelKey] = apicSlice
}

func (cont *AciController) applyNodeFabNetAttObj(vlans []int, addNet *AdditionalNetworkMeta, apicSlice apicapi.ApicSlice, progMap map[string]apicapi.ApicSlice) {
	for _, encap := range vlans {
		if !cont.config.AciUseGlobalScopeVlan {
			epg := cont.createNodeFabNetAttEpg(encap, addNet.NetworkName)
			apicSlice = cont.populateFabricPaths(epg, encap, addNet, apicSlice)
			continue
		}
		var apicSlice2 apicapi.ApicSlice
		epgName := fmt.Sprintf("%s-%d", globalScopeVlanEpgPrefix, encap)
		labelKey := cont.aciNameForKey("nfna", epgName)
		epg := cont.createNodeFabNetAttEpg(encap, epgName)
		apicSlice2 = cont.populateFabricPaths(epg, encap, addNet, apicSlice2)
		progMap[labelKey] = apicSlice2
	}
	if !cont.config.AciUseGlobalScopeVlan {
		labelKey := cont.aciNameForKey("nfna", addNet.NetworkName)
		progMap[labelKey] = apicSlice
	}
}

func (cont *AciController) updateNodeFabNetAttObj(nodeFabNetAtt *fabattv1.NodeFabricNetworkAttachment) (progMap map[string]apicapi.ApicSlice) {
	var apicSlice apicapi.ApicSlice
	var addNet *AdditionalNetworkMeta
	progMap = make(map[string]apicapi.ApicSlice)
	vlans, encapBlks, err := cont.parseNodeFabNetAttVlanList(nodeFabNetAtt.Spec.EncapVlan.VlanList)
	if err != nil {
		cont.log.Errorf("%v", err)
		return progMap
	}
	cont.log.Debugf("parsed vlan list: %v", vlans)
	addNetKey := nodeFabNetAtt.Spec.NetworkRef.Namespace + "/" + nodeFabNetAtt.Spec.NetworkRef.Name
	addNet, ok := cont.additionalNetworkCache[addNetKey]
	if !ok {
		addNet = &AdditionalNetworkMeta{
			NetworkName: nodeFabNetAtt.Spec.NetworkRef.Namespace + "-" + nodeFabNetAtt.Spec.NetworkRef.Name,
			EncapVlan:   nodeFabNetAtt.Spec.EncapVlan.VlanList,
			FabricLink:  make(map[string]map[string][]string),
			NodeCache:   make(map[string]*fabattv1.NodeFabricNetworkAttachment)}
		cont.additionalNetworkCache[addNetKey] = addNet
	} else if cont.config.AciUseGlobalScopeVlan {
		if addNet.EncapVlan != nodeFabNetAtt.Spec.EncapVlan.VlanList {
			cont.log.Debugf("%s:Change in encap: %s=>%s", addNetKey, addNet.EncapVlan, nodeFabNetAtt.Spec.EncapVlan.VlanList)
			changeSet := make(map[int]bool)
			// manage the diff in encapvlan set
			old_vlans, _, _ := cont.parseNodeFabNetAttVlanList(addNet.EncapVlan)
			addNet.EncapVlan = nodeFabNetAtt.Spec.EncapVlan.VlanList
			for _, vlan := range old_vlans {
				changeSet[vlan] = false
			}
			for _, vlan := range vlans {
				changeSet[vlan] = true
			}
			for vlan, present := range changeSet {
				if !present {
					cont.deleteNodeFabNetAttGlobalEncapVlan(vlan, addNetKey, progMap)
				}
			}
		}
	}
	addNet.EncapVlan = nodeFabNetAtt.Spec.EncapVlan.VlanList
	addNet.NodeCache[nodeFabNetAtt.Spec.NodeName] = nodeFabNetAtt

	cont.log.Infof("nfna update: %v", addNetKey)
	if cont.config.AciUseGlobalScopeVlan {
		cont.setGlobalScopeVlanConfig(cont.config.AciAdditionalVlans, progMap)
		for _, vlan := range vlans {
			if _, ok := cont.sharedEncapCache[vlan]; !ok {
				cont.sharedEncapCache[vlan] = make(map[string]*AdditionalNetworkMeta)
			}
			cont.sharedEncapCache[vlan][addNetKey] = addNet
		}
	} else {
		apicSlice = append(apicSlice, cont.createNodeFabNetAttBd(addNet.NetworkName))
		apicSlice = append(apicSlice, cont.updateNodeFabNetAttDom(encapBlks, addNet.NetworkName)...)
	}
	// manage the diff in fabriclink set
	linkPresent := map[string]bool{}
	for iface, aciLink := range nodeFabNetAtt.Spec.AciTopology {
		if _, ok := addNet.FabricLink[nodeFabNetAtt.Spec.NodeName]; !ok || (addNet.FabricLink[nodeFabNetAtt.Spec.NodeName] == nil) {
			addNet.FabricLink[nodeFabNetAtt.Spec.NodeName] = make(map[string][]string)
		}
		addNet.FabricLink[nodeFabNetAtt.Spec.NodeName][iface] = aciLink.FabricLink
		linkPresent[iface] = true
	}
	nodeIfaceMap := addNet.FabricLink[nodeFabNetAtt.Spec.NodeName]
	for iface := range nodeIfaceMap {
		if _, ok := linkPresent[iface]; !ok {
			delete(nodeIfaceMap, iface)
		}
	}
	addNet.FabricLink[nodeFabNetAtt.Spec.NodeName] = nodeIfaceMap
	cont.applyNodeFabNetAttObj(vlans, addNet, apicSlice, progMap)
	return progMap
}

func (cont *AciController) nodeFabNetAttChanged(obj interface{}) {
	fabNetAttDef, ok := obj.(*fabattv1.NodeFabricNetworkAttachment)
	if !ok {
		cont.log.Error("nodeFabNetAttChanged: Bad object type")
		return
	}
	key, err := cache.MetaNamespaceKeyFunc(fabNetAttDef)
	if err != nil {
		return
	}
	cont.queueNodeFabNetAttByKey(key)
}

func (cont *AciController) nodeFabNetAttDeleted(obj interface{}) {
	nodeFabNetAtt, ok := obj.(*fabattv1.NodeFabricNetworkAttachment)
	if !ok {
		deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			NodeFabricNetworkAttachmentLogger(cont.log, nodeFabNetAtt).
				Error("Received unexpected object: ", obj)
			return
		}
		nodeFabNetAtt, ok = deletedState.Obj.(*fabattv1.NodeFabricNetworkAttachment)
		if !ok {
			NodeFabricNetworkAttachmentLogger(cont.log, nodeFabNetAtt).
				Error("DeletedFinalStateUnknown contained non-nodefabricnetworkattachment object: ", deletedState.Obj)
			return
		}
	}

	addNetKey := nodeFabNetAtt.Spec.NetworkRef.Namespace + "/" + nodeFabNetAtt.Spec.NetworkRef.Name
	cont.queueNodeFabNetAttByKey("DELETED_" + nodeFabNetAtt.Spec.NodeName + "_" + addNetKey)
}

func (cont *AciController) deleteNodeFabNetAttObj(key string) (progMap map[string]apicapi.ApicSlice) {
	var apicSlice apicapi.ApicSlice
	parts := strings.Split(key, "_")
	nodeName := parts[0]
	nodeFabNetAttKey := parts[1]

	cont.log.Infof("nfna delete: %v", nodeFabNetAttKey)
	progMap = make(map[string]apicapi.ApicSlice)
	addNet, ok := cont.additionalNetworkCache[nodeFabNetAttKey]
	if !ok {
		return progMap
	}
	nodeCache, ok := addNet.NodeCache[nodeName]
	if !ok {
		return progMap
	}
	// already admitted.No error handling needed
	vlans, encapBlks, _ := cont.parseNodeFabNetAttVlanList(addNet.EncapVlan)
	delete(addNet.NodeCache, nodeName)

	if len(addNet.NodeCache) == 0 {
		delete(cont.additionalNetworkCache, nodeFabNetAttKey)
		if !cont.config.AciUseGlobalScopeVlan {
			labelKey := cont.aciNameForKey("nfna", addNet.NetworkName)
			progMap[labelKey] = nil
			return progMap
		} else {
			for _, encap := range vlans {
				cont.deleteNodeFabNetAttGlobalEncapVlan(encap, nodeFabNetAttKey, progMap)
			}
			if len(cont.additionalNetworkCache) == 0 {
				cont.clearGlobalScopeVlanConfig(progMap)
				return progMap
			}
			return progMap
		}
	}

	for iface := range nodeCache.Spec.AciTopology {
		if _, ok := addNet.FabricLink[nodeName]; !ok {
			break
		}
		localIfaceMap := addNet.FabricLink[nodeName]
		delete(localIfaceMap, iface)
		addNet.FabricLink[nodeName] = localIfaceMap
	}
	if !cont.config.AciUseGlobalScopeVlan {
		apicSlice = append(apicSlice, cont.createNodeFabNetAttBd(addNet.NetworkName))
		apicSlice = append(apicSlice, cont.updateNodeFabNetAttDom(encapBlks, addNet.NetworkName)...)
	}

	cont.applyNodeFabNetAttObj(vlans, addNet, apicSlice, progMap)
	return progMap
}

func (cont *AciController) queueNodeFabNetAttByKey(key string) {
	cont.nodeFabNetAttQueue.Add(key)
}

// func returns false if executed without error, true if the caller has to requeue.
func (cont *AciController) handleNodeFabricNetworkAttachmentUpdate(obj interface{}) bool {
	nodeFabNetAtt, ok := obj.(*fabattv1.NodeFabricNetworkAttachment)
	if !ok {
		cont.log.Error("handleNodeFabricNetworkAttUpdate: Bad object type")
		return false
	}
	progMap := cont.updateNodeFabNetAttObj(nodeFabNetAtt)
	for labelKey, apicSlice := range progMap {
		if apicSlice == nil {
			cont.apicConn.ClearApicObjects(labelKey)
			continue
		}
		cont.apicConn.WriteApicObjects(labelKey, apicSlice)
	}
	return false
}

func (cont *AciController) handleNodeFabricNetworkAttachmentDelete(key string) bool {
	progMap := cont.deleteNodeFabNetAttObj(key)
	for labelKey, apicSlice := range progMap {
		if apicSlice == nil {
			cont.apicConn.ClearApicObjects(labelKey)
			continue
		}
		cont.apicConn.WriteApicObjects(labelKey, apicSlice)
	}
	return false
}
