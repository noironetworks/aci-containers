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
	"context"
	"fmt"
	"strings"

	"github.com/noironetworks/aci-containers/pkg/apicapi"
	fabattv1 "github.com/noironetworks/aci-containers/pkg/fabricattachment/apis/aci.fabricattachment/v1"
	fabattclset "github.com/noironetworks/aci-containers/pkg/fabricattachment/clientset/versioned"
	"github.com/noironetworks/aci-containers/pkg/util"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
	"k8s.io/kubernetes/pkg/controller"
)

const (
	nodeFabNetAttCRDName         = "nodefabricnetworkattachments.aci.fabricattachment"
	globalScopeVlanEpgPrefix     = "secondary-vlan"
	globalScopeVlanBdPrefix      = "secondary-bd"
	globalScopeVlanDomPrefix     = "secondary"
	globalScopeVlanLNodePPrefix  = "secondary-ndp"
	globalScopeVlanExtLifPPrefix = "secondary-intfp"
)

func (cont *AciController) updateGlobalConfig(encapStr string, progMap map[string]apicapi.ApicSlice) {
	var apicSlice apicapi.ApicSlice
	if !cont.config.AciUseGlobalScopeVlan {
		cont.log.Errorf("Cannot set globalscope objects in per-port vlan mode")
		return
	}
	_, encapBlks, _, err := util.ParseVlanList([]string{encapStr})
	if err != nil {
		cont.log.Errorf("Error updating GlobalScopeVlanConfig: %v", err)
		return
	}
	cont.log.Infof("Setting globalvlanpool: %s", encapStr)
	apicSlice = cont.updateNodeFabNetAttDom(encapBlks, globalScopeVlanDomPrefix)
	labelKey := cont.aciNameForKey("nfna", globalScopeVlanDomPrefix)
	progMap[labelKey] = apicSlice
}

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
	go cont.processQueue(cont.nodeFabNetAttQueue, cont.nodeFabNetAttInformer.GetIndexer(),
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
	ap := apicapi.NewFvAP(cont.config.AciPolicyTenant, "netop-"+cont.config.AciPrefix)
	apCommon := apicapi.NewFvAP("common", "netop-common")
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
	apicSlice = append(apicSlice, tenant)
	apicSlice = append(apicSlice, bd)
	apicSlice = append(apicSlice, ap)
	apicSlice = append(apicSlice, apCommon)
	apicSlice = append(apicSlice, epg)
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
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				return fabAttClient.AciV1().NodeFabricNetworkAttachments("aci-containers-system").List(context.TODO(), options)
			},

			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				return fabAttClient.AciV1().NodeFabricNetworkAttachments("aci-containers-system").Watch(context.TODO(), options)
			},
		})
}

func (cont *AciController) initNodeFabNetAttInformerBase(listWatch *cache.ListWatch) {
	cont.nodeFabNetAttInformer = cache.NewSharedIndexInformer(
		listWatch, &fabattv1.NodeFabricNetworkAttachment{}, controller.NoResyncPeriodFunc(),
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	cont.nodeFabNetAttInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			cont.nodeFabNetAttChanged(obj)
		},
		UpdateFunc: func(_ interface{}, newobj interface{}) {
			cont.nodeFabNetAttChanged(newobj)
		},
		DeleteFunc: func(obj interface{}) {
			cont.nodeFabNetAttDeleted(obj)
		},
	})
}

func (cont *AciController) clearGlobalScopeVlanConfig(progMap map[string]apicapi.ApicSlice) {
	labelKey := cont.aciNameForKey("nfna", globalScopeVlanDomPrefix)
	progMap[labelKey] = nil
	cont.globalVlanConfig.SharedPhysDom = nil
	cont.globalVlanConfig.SharedL3Dom = nil
}

func (cont *AciController) setGlobalScopeVlanConfig(encapStr string, progMap map[string]apicapi.ApicSlice) {
	var apicSlice apicapi.ApicSlice
	if !cont.config.AciUseGlobalScopeVlan {
		cont.log.Errorf("Cannot set globalscope objects in per-port vlan mode")
		return
	}
	if (cont.globalVlanConfig.SharedPhysDom != nil) && (cont.globalVlanConfig.SharedL3Dom != nil) {
		return
	}
	_, encapBlks, _, err := util.ParseVlanList([]string{encapStr})
	if err != nil {
		cont.log.Errorf("Error setting GlobalScopeVlanConfig: %v", err)
		return
	}
	apicSlice = cont.updateNodeFabNetAttDom(encapBlks, globalScopeVlanDomPrefix)
	labelKey := cont.aciNameForKey("nfna", globalScopeVlanDomPrefix)
	progMap[labelKey] = apicSlice
}

func (cont *AciController) deletelldpIf(dn string) {
	fabricLink := strings.Replace(dn, "/sys/lldp/inst/if-", "/pathep-", 1)
	cont.indexMutex.Lock()
	cont.log.Info("deletelldpIf: deleted mapping for ", fabricLink)
	cont.apicConn.UnsubscribeImmediateDnLocked(dn, []string{"lldpIf"})
	delete(cont.lldpIfCache, fabricLink)
	cont.indexMutex.Unlock()
}

func (cont *AciController) updateLLDPIf(obj apicapi.ApicObject) {
	var lldpIf, fabricLink string
	lresp, ok := obj["lldpIf"]
	updateNeeded := false
	if !ok {
		cont.log.Errorf("updateLLDPIf: lldpIf Object not found in response")
		return
	}
	if val, ok := lresp.Attributes["portDesc"]; ok {
		lldpIf = val.(string)
		if lldpIf != "" {
			if val2, ok2 := lresp.Attributes["dn"]; ok2 {
				fabricLink = strings.Replace(val2.(string), "/sys/lldp/inst/if-", "/pathep-", 1)
			}
		}
		cont.indexMutex.Lock()
		if fabricLink != "" {
			if oldIf, ok := cont.lldpIfCache[fabricLink]; ok {
				if oldIf.LLDPIf != lldpIf {
					updateNeeded = true
					cont.log.Infof("updateLLDPIf: updated mapping fabricLink %s => %s", fabricLink, lldpIf)
					cont.lldpIfCache[fabricLink].LLDPIf = lldpIf

				}
			}
		}
		cont.indexMutex.Unlock()
		if updateNeeded {
			cont.lldpIfQueue.Add(fabricLink)
		}
	}
}

func (cont *AciController) clearLLDPIf(addNetKey string) {
	for fabricLink, lldpIfData := range cont.lldpIfCache {
		if _, ok := lldpIfData.Refs[addNetKey]; !ok {
			continue
		}
		delete(cont.lldpIfCache[fabricLink].Refs, addNetKey)
		if len(cont.lldpIfCache[fabricLink].Refs) == 0 {
			dn := strings.Replace(fabricLink, "/pathep-", "/sys/lldp/inst/if-", 1)
			cont.apicConn.UnsubscribeImmediateDnLocked(dn, []string{"lldpIf"})
		}
	}
}

func (cont *AciController) getLLDPIf(fabricLink string, addNetKey string) string {
	var lldpIf, apicIf string
	if lldpIf, ok := cont.lldpIfCache[fabricLink]; ok {
		cont.lldpIfCache[fabricLink].Refs[addNetKey] = true
		return lldpIf.LLDPIf
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
		cont.lldpIfCache[fabricLink] = &NfLLDPIfData{
			LLDPIf: lldpIf,
			Refs: map[string]bool{
				addNetKey: true,
			}}
		cont.log.Infof("getLLDPIf: Found port=>pc/vpc mapping: %s=>%s", fabricLink, lldpIf)
		dn := fmt.Sprintf("%s/sys/lldp/inst/if-[%s]", apicPodLeaf, apicIf)
		cont.apicConn.AddImmediateSubscriptionDnLocked(dn, []string{"lldpIf"},
			func(obj apicapi.ApicObject) bool {
				cont.updateLLDPIf(obj)
				return true
			},
			func(dn string) {
				cont.deletelldpIf(dn)
			})
	}
	return lldpIf
}

func (cont *AciController) populateNodeFabNetAttPaths(epg apicapi.ApicObject, encap int, ctxt *SviContext, addNet *AdditionalNetworkMeta, skipNode string, resultingLinks map[string]bool) {
	fabLinks := make(map[string]bool)
	encapVlan := fmt.Sprintf("%d", encap)
	var addNetKey string
	for _, nfna := range addNet.NodeCache {
		addNetKey = nfna.Spec.NetworkRef.Namespace + "/" + nfna.Spec.NetworkRef.Name
		break
	}
	for node, localIfaceMap := range addNet.FabricLink {
		if node == skipNode {
			continue
		}
		for _, fabricLinks := range localIfaceMap {
			if (len(fabricLinks.Pods) == 0) && (!ctxt.present || ctxt.connectedNw.RequirePodToProvision) {
				continue
			}
			var actualFabricLink, lldpIf string
			// Check if port is part of a PC
			for i := range fabricLinks.Link {
				lldpIf = cont.getLLDPIf(fabricLinks.Link[i], addNetKey)
				if lldpIf != "" {
					actualFabricLink = lldpIf
				} else {
					actualFabricLink = strings.Replace(fabricLinks.Link[0], "node-", "paths-", 1)
				}
				// eliminate duplicates in case of VPC links
				if _, ok := fabLinks[actualFabricLink]; !ok {
					fabLinks[actualFabricLink] = true
					if ctxt == nil || !ctxt.present {
						fvRsPathAtt := apicapi.NewFvRsPathAtt(epg.GetDn(), actualFabricLink, encapVlan, addNet.Mode.String())
						if _, ok := resultingLinks[actualFabricLink]; !ok {
							resultingLinks[actualFabricLink] = true
							epg.AddChild(fvRsPathAtt)
						}
					} else {
						//Collect Nodes in the fabricpath
						_, podStr, found := strings.Cut(actualFabricLink, "pod-")
						if !found {
							cont.log.Errorf("Could not parse for pod in fabriclink:%s", actualFabricLink)
							continue
						}
						pod, _, found := strings.Cut(podStr, "/")
						if !found {
							cont.log.Errorf("Could not parse for pod id in fabriclink:%s", actualFabricLink)
							continue
						}
						var nodes []string
						var nodeStr string
						found = false
						if lldpIf != "" {
							_, nodeStr, found = strings.Cut(lldpIf, "protpaths-")
							if !found {
								_, nodeStr, found = strings.Cut(lldpIf, "paths-")
							}
						} else {
							_, nodeStr, found = strings.Cut(actualFabricLink, "paths-")
						}
						if found {
							nodeCombined, _, found := strings.Cut(nodeStr, "/")
							if found {
								nodes = strings.Split(nodeCombined, "-")
							}
						}
						if len(nodes) == 0 {
							cont.log.Errorf("Could not parse for node id in %s", nodeStr)
						}
						cont.log.Debugf("l3out-svi:pod: %s nodes :%v", pod, nodes)
						cont.createNodeFabNetAttSviPaths(encap, ctxt, actualFabricLink, pod, nodes)
					}
				}
			}
		}
	}
	if ctxt.present {
		cont.updateNetworkFabricL3ConfigurationStatus(true)
	}
}

func (cont *AciController) depopulateFabricPaths(epg apicapi.ApicObject, encap int, nodeName, nodeFabNetAttKey string, sviContext *SviContext) apicapi.ApicSlice {
	var apicSlice apicapi.ApicSlice
	if !cont.config.AciUseGlobalScopeVlan {
		return nil
	}
	fabLinks := make(map[string]bool)
	nfnaMap := cont.sharedEncapCache[encap].NetRef
	for nfnaKey, currNet := range nfnaMap {
		skipNode := ""
		if nfnaKey == nodeFabNetAttKey {
			skipNode = nodeName
		}
		cont.populateNodeFabNetAttPaths(epg, encap, sviContext, currNet, skipNode, fabLinks)
	}
	apicSlice = append(apicSlice, epg)
	return apicSlice
}

func (cont *AciController) populateFabricPaths(epg apicapi.ApicObject, encap int, sviContext *SviContext, addNet *AdditionalNetworkMeta) {
	fabLinks := make(map[string]bool)
	if cont.config.AciUseGlobalScopeVlan {
		nfnaMap := cont.sharedEncapCache[encap].NetRef
		for _, currNet := range nfnaMap {
			cont.populateNodeFabNetAttPaths(epg, encap, sviContext, currNet, "", fabLinks)
		}
	} else {
		cont.populateNodeFabNetAttPaths(epg, encap, sviContext, addNet, "", fabLinks)
	}
}

func (cont *AciController) createNodeFabNetAttEpgStaticAttachments(vlan int, aep, networkName string, discoveryType fabattv1.StaticPathMgmtType, epg apicapi.ApicObject, progMap map[string]apicapi.ApicSlice) (apicSlice apicapi.ApicSlice) {
	aepDn := "uni/infra/attentp-" + aep
	var physDom string
	if cont.config.AciUseGlobalScopeVlan {
		physDom = cont.config.AciPolicyTenant + "-" + globalScopeVlanDomPrefix
	} else {
		physDom = cont.config.AciPolicyTenant + "-" + networkName
	}

	labelKey := cont.aciNameForKey("aepPhysDom", aep)
	if discoveryType != fabattv1.StaticPathMgmtTypeLLDP {
		var apicSlice2 apicapi.ApicSlice
		secondaryPhysDomDn := "uni/phys-" + physDom
		infraRsDomP := apicapi.NewInfraRsDomP(aepDn, secondaryPhysDomDn)
		apicSlice2 = append(apicSlice2, infraRsDomP)
		cont.sharedEncapCache[vlan].Aeps[aep] = true
		progMap[labelKey] = apicSlice2
		if _, ok := cont.sharedEncapAepCache[aep]; !ok {
			cont.sharedEncapAepCache[aep] = make(map[int]bool)
		}
		cont.sharedEncapAepCache[aep][vlan] = true
	} else {
		delete(cont.sharedEncapCache[vlan].Aeps, aep)
		if _, ok := cont.sharedEncapAepCache[aep]; ok {
			delete(cont.sharedEncapAepCache[aep], vlan)
			if len(cont.sharedEncapAepCache[aep]) == 0 {
				delete(cont.sharedEncapAepCache, aep)
				progMap[labelKey] = nil
				cont.log.Infof("Remove physdom association for AEP %s", aep)
			}
		}
	}

	if discoveryType != fabattv1.StaticPathMgmtTypeLLDP {
		// Workaround alert: Due to the fact that infraGeneric cannot take
		// any other name than default, we have to follow this hack of not adding
		// infraRsFuncToEpg as a child and making infraGeneric not deletable.
		infraGeneric := apicapi.NewInfraGeneric(aep)
		encap := fmt.Sprintf("%d", vlan)
		infraRsFuncToEpg := apicapi.NewInfraRsFuncToEpg(infraGeneric.GetDn(), epg.GetDn(), encap, "regular")
		apicSlice = append(apicSlice, infraGeneric)
		apicSlice = append(apicSlice, infraRsFuncToEpg)
	}
	return apicSlice
}

func (cont *AciController) createNodeFabNetAttBd(vlan int, name string, explicitTenantName, explicitVrfName, explicitBdName string, subnets []string) apicapi.ApicObject {
	bdName := explicitBdName
	tenantName := explicitTenantName
	vrfName := explicitVrfName
	if bdName == "" {
		bdName = fmt.Sprintf("%s-%s-vlan-%d", cont.config.AciPrefix, name, vlan)
	}
	if tenantName == "" {
		tenantName = cont.config.AciPolicyTenant
	}
	bd := apicapi.NewFvBD(tenantName, bdName)
	bd.SetAttr("arpFlood", "yes")
	bd.SetAttr("ipLearning", "no")
	bd.SetAttr("unkMacUcastAct", "flood")
	bd.SetAttr("unicastRoute", "no")
	if len(subnets) != 0 {
		bd.SetAttr("unicastRoute", "yes")
	}
	if vrfName == "" {
		vrfName = cont.config.AciVrf
	}
	fvRsCtx := apicapi.NewFvRsCtx(bd.GetDn(), vrfName)
	bd.AddChild(fvRsCtx)

	// add subnets to BD
	for _, subnet := range subnets {
		fvSubnet := apicapi.NewFvSubnet(bd.GetDn(), subnet)
		bd.AddChild(fvSubnet)
	}
	return bd
}

func (cont *AciController) getNodeFabNetAttTenant(explicitTenantName string) string {
	tenantName := explicitTenantName
	if tenantName == "" {
		tenantName = cont.config.AciPolicyTenant
	}
	return tenantName
}

func (cont *AciController) getNodeFabNetAttAp(explicitApName, tenantName string) string {
	apName := explicitApName
	if apName == "" {
		apName = "netop-" + tenantName
		if tenantName != cont.config.AciPrefix {
			apName = "netop-" + cont.config.AciPrefix
		}
	}
	return apName
}

func (cont *AciController) createNodeFabNetAttAp(explicitTenantName, name string) apicapi.ApicObject {
	tenantName := cont.getNodeFabNetAttTenant(explicitTenantName)
	apName := cont.getNodeFabNetAttAp(name, tenantName)
	return apicapi.NewFvAP(tenantName, apName)
}

func (cont *AciController) createNodeFabNetAttEpg(vlan int, name string, explicitTenantName, explicitBdName, explicitApName, explicitEpgName, explicitVrfName string, consumers, providers []string) apicapi.ApicObject {
	var fvRsDomAtt apicapi.ApicObject
	epgName := explicitEpgName
	bdName := explicitBdName
	tenantName := cont.getNodeFabNetAttTenant(explicitTenantName)
	apName := cont.getNodeFabNetAttAp(explicitApName, tenantName)
	if !cont.config.AciUseGlobalScopeVlan {
		if epgName == "" {
			epgName = fmt.Sprintf("%s-vlan-%d", name, vlan)
		}
		if bdName == "" {
			bdName = fmt.Sprintf("%s-%s-vlan-%d", cont.config.AciPrefix, name, vlan)
		}
	} else {
		if epgName == "" {
			epgName = fmt.Sprintf("%s-%d", globalScopeVlanEpgPrefix, vlan)
		}
		if bdName == "" {
			bdName = fmt.Sprintf("%s-%s-vlan-%d", cont.config.AciPrefix, globalScopeVlanBdPrefix, vlan)
		}
	}
	_ = explicitVrfName
	epg := apicapi.NewFvAEPg(tenantName, apName, epgName)
	fvRsBd := apicapi.NewFvRsBD(epg.GetDn(), bdName)
	epg.AddChild(fvRsBd)
	if !cont.config.AciUseGlobalScopeVlan {
		fvRsDomAtt = apicapi.NewFvRsDomAttPhysDom(epg.GetDn(), cont.config.AciPolicyTenant+"-"+name)
	} else {
		fvRsDomAtt = apicapi.NewFvRsDomAttPhysDom(epg.GetDn(), cont.config.AciPolicyTenant+"-"+globalScopeVlanDomPrefix)
	}
	epg.AddChild(fvRsDomAtt)
	for _, consumer := range consumers {
		fvRsCons := apicapi.NewFvRsCons(epg.GetDn(), consumer)
		epg.AddChild(fvRsCons)
	}
	for _, provider := range providers {
		fvRsProv := apicapi.NewFvRsProv(epg.GetDn(), provider)
		epg.AddChild(fvRsProv)
	}
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
	// Create l3dom
	l3Dom := apicapi.NewL3DomP(cont.config.AciPolicyTenant + "-" + networkName)
	infraRsVlanNs2 := apicapi.NewInfraRsVlanNs(l3Dom.GetDn(), fvnsVlanInstP.GetDn())
	l3Dom.AddChild(infraRsVlanNs2)
	apicSlice = append(apicSlice, l3Dom)
	// associate aep with physdom
	secondaryAepDn := "uni/infra/attentp-" + cont.config.AciAdditionalAep
	infraRsDomP := apicapi.NewInfraRsDomP(secondaryAepDn, physDom.GetDn())
	apicSlice = append(apicSlice, infraRsDomP)
	// associate aep with l3dom
	infraRsDomP2 := apicapi.NewInfraRsDomP(secondaryAepDn, l3Dom.GetDn())
	apicSlice = append(apicSlice, infraRsDomP2)
	if cont.config.AciUseGlobalScopeVlan {
		cont.globalVlanConfig.SharedPhysDom = physDom
		cont.globalVlanConfig.SharedL3Dom = l3Dom
	}
	return apicSlice
}

func (cont *AciController) addNodeFabNetAttStaticAttachmentsLocked(vlan int, networkName string, epg apicapi.ApicObject, apicSlice apicapi.ApicSlice, progMap map[string]apicapi.ApicSlice) apicapi.ApicSlice {
	nfcData, ok := cont.sharedEncapNfcCache[vlan]
	if ok {
		for aep := range nfcData.Aeps {
			apicSlice = append(apicSlice, cont.createNodeFabNetAttEpgStaticAttachments(vlan, aep, networkName, nfcData.Epg.DiscoveryType, epg, progMap)...)
		}
	}
	return apicSlice
}

func (cont *AciController) deleteNodeFabNetAttGlobalEncapVlanLocked(vlan int, nodeName string, nodeFabNetAttKey string, progMap map[string]apicapi.ApicSlice) {
	nfcEpgTenant, _, nfcEpgAp, nfcEpg, nfcEpgConsumers, nfcEpgProviders, nfcDiscovery := cont.getSharedEncapNfcCacheEpgLocked(vlan)
	epgName := fmt.Sprintf("%s-%d", globalScopeVlanEpgPrefix, vlan)
	labelKey := cont.aciNameForKey("nfna", epgName)
	nfnaMap := cont.sharedEncapCache[vlan].NetRef
	addNet, addNetOk := nfnaMap[nodeFabNetAttKey]
	if addNetOk {
		if len(addNet.NodeCache) == 0 {
			delete(nfnaMap, nodeFabNetAttKey)
		}
	}
	if nodeNads, ok := cont.sharedEncapCache[vlan].Pods[nodeName]; ok {
		delete(nodeNads, nodeFabNetAttKey)
		cont.sharedEncapCache[vlan].Pods[nodeName] = nodeNads
		if len(nodeNads) == 0 {
			delete(cont.sharedEncapCache[vlan].Pods, nodeName)
		}
	}
	cont.sharedEncapCache[vlan] = &sharedEncapData{
		Pods:   cont.sharedEncapCache[vlan].Pods,
		NetRef: nfnaMap,
		Aeps:   cont.sharedEncapCache[vlan].Aeps,
	}
	if len(cont.sharedEncapCache[vlan].NetRef) == 0 {
		cont.log.Infof("clear shared encap epg: %d", vlan)
		progMap[labelKey] = nil
		for aep := range cont.sharedEncapCache[vlan].Aeps {
			delete(cont.sharedEncapAepCache[aep], vlan)
			if len(cont.sharedEncapAepCache[aep]) == 0 {
				lblKey := cont.aciNameForKey("aepPhysDom", aep)
				progMap[lblKey] = nil
				delete(cont.sharedEncapAepCache, aep)
				cont.log.Infof("Delete physdom association for AEP %s", aep)
			}
		}
		delete(cont.sharedEncapCache, vlan)
		return
	}
	var epg apicapi.ApicObject
	var apicSlice2 apicapi.ApicSlice
	nfcBdTenant, nfcVrf, nfcBd, nfcBdSubnets := cont.getSharedEncapNfcCacheBDLocked(vlan)
	sviContext := cont.getSharedEncapNfCacheSviLocked(vlan)
	if !sviContext.present {
		apicSlice2 = append(apicSlice2, cont.createNodeFabNetAttBd(vlan, globalScopeVlanBdPrefix, nfcBdTenant,
			nfcVrf, nfcBd, nfcBdSubnets))
		epg = cont.createNodeFabNetAttEpg(vlan, globalScopeVlanEpgPrefix, nfcEpgTenant, nfcBd, nfcEpgAp, nfcEpg, nfcVrf, nfcEpgConsumers, nfcEpgProviders)
	}
	programNodeFabNetAttObjs := func() {
		if !sviContext.present {
			apicSlice2 = append(apicSlice2, epg)
			for aep := range cont.sharedEncapCache[vlan].Aeps {
				delete(cont.sharedEncapAepCache[aep], vlan)
				if len(cont.sharedEncapAepCache[aep]) == 0 {
					lblKey := cont.aciNameForKey("aepPhysDom", aep)
					progMap[lblKey] = nil
					delete(cont.sharedEncapAepCache, aep)
					cont.log.Infof("Deleting physdom association for AEP %s", aep)
				}
				delete(cont.sharedEncapCache[vlan].Aeps, aep)
			}
			return
		}
		if sviContext.connectedNw.UseExistingL3Out {
			sviContext.l3outNodeP.AddChild(sviContext.l3outLifP)
			apicSlice2 = append(apicSlice2, sviContext.l3outNodeP)
			return
		}
		apicSlice2 = append(apicSlice2, sviContext.l3out)

	}
	if cont.isNodeFabNetAttVlanProgrammable(vlan, sviContext, nil) {
		if nfcDiscovery != fabattv1.StaticPathMgmtTypeAEP || sviContext.present {
			apicSlice2 = append(apicSlice2, cont.depopulateFabricPaths(epg, vlan, nodeName, nodeFabNetAttKey, sviContext)...)
		}
		if !sviContext.present {
			apicSlice2 = cont.addNodeFabNetAttStaticAttachmentsLocked(vlan, "", epg, apicSlice2, progMap)
		}
	} else {
		programNodeFabNetAttObjs()
	}
	progMap[labelKey] = apicSlice2
}

func (cont *AciController) isNodeFabNetAttVlanProgrammable(vlan int, sviCtxt *SviContext, addNet *AdditionalNetworkMeta) bool {
	podCount := 0
	if !cont.config.AciUseGlobalScopeVlan {
		for _, nodeIfaceMap := range addNet.FabricLink {
			for _, aciLink := range nodeIfaceMap {
				podCount += len(aciLink.Pods)
			}
		}
		return podCount > 0
	}
	shrdEncapData, ok := cont.sharedEncapCache[vlan]
	if !ok {
		return false
	}
	if sviCtxt.present && !sviCtxt.connectedNw.RequirePodToProvision {
		return true
	}
	for _, nodeNads := range shrdEncapData.Pods {
		for _, podList := range nodeNads {
			podCount += len(podList)
		}
	}
	return podCount > 0
}

func (cont *AciController) applyNodeFabNetAttObjLocked(vlans []int, addNet *AdditionalNetworkMeta, apicSlice apicapi.ApicSlice, progMap map[string]apicapi.ApicSlice) {
	skipProgramming := false
	for _, encap := range vlans {
		if !cont.config.AciUseGlobalScopeVlan {
			if skipProgramming || !cont.isNodeFabNetAttVlanProgrammable(encap, nil, addNet) {
				skipProgramming = true
				bd := cont.createNodeFabNetAttBd(encap, addNet.NetworkName, "", "", "", []string{})
				apicSlice = append(apicSlice, bd)
				epg := cont.createNodeFabNetAttEpg(encap, addNet.NetworkName, "", "", "", "", "",
					[]string{}, []string{})
				apicSlice = append(apicSlice, epg)
				cont.log.Infof("Skipping static paths as NAD has no pods yet: %s", addNet.NetworkName)
				continue
			}
			bd := cont.createNodeFabNetAttBd(encap, addNet.NetworkName, "", "", "", []string{})
			apicSlice = append(apicSlice, bd)
			epg := cont.createNodeFabNetAttEpg(encap, addNet.NetworkName, "", "", "", "", "",
				[]string{}, []string{})
			cont.populateFabricPaths(epg, encap, &SviContext{}, addNet)
			apicSlice = append(apicSlice, epg)
			continue
		}
		nfcEpgTenant, _, nfcEpgAp, nfcEpg, nfcEpgConsumers, nfcEpgProviders, nfcDiscovery := cont.getSharedEncapNfcCacheEpgLocked(encap)
		nfcBdTenant, nfcVrf, nfcBd, nfcBdSubnets := cont.getSharedEncapNfcCacheBDLocked(encap)
		sviContext := cont.getSharedEncapNfCacheSviLocked(encap)
		var labelKey string
		var apicSlice2 apicapi.ApicSlice
		var epg apicapi.ApicObject
		epgName := fmt.Sprintf("%s-%d", globalScopeVlanEpgPrefix, encap)
		labelKey = cont.aciNameForKey("nfna", epgName)
		if !sviContext.present {
			bd := cont.createNodeFabNetAttBd(encap, globalScopeVlanBdPrefix, nfcBdTenant,
				nfcVrf, nfcBd, nfcBdSubnets)
			apicSlice2 = append(apicSlice2, bd)
			epg = cont.createNodeFabNetAttEpg(encap, epgName, nfcEpgTenant, nfcBd, nfcEpgAp, nfcEpg, nfcVrf, nfcEpgConsumers, nfcEpgProviders)
		} else {
			cont.createNodeFabNetAttSvi(encap, sviContext)
		}
		if _, ok := cont.sharedEncapCache[encap]; !ok {
			apicSlice2 = nil
			cont.log.Infof("Skip shared encap vlan-%d with no nad references", encap)
		} else {
			programNodeFabNetAttObjs := func() {
				if !sviContext.present {
					apicSlice2 = append(apicSlice2, epg)
					return
				}
				if sviContext.connectedNw.BGPPeerPolicy.PrefixPolicy != "" {
					bgpPPPLabelKey := cont.aciNameForKey("bgpPeerPfxPol",
						sviContext.connectedNw.BGPPeerPolicy.PrefixPolicy)
					apicSlice3 := apicapi.ApicSlice{}
					apicSlice3 = append(apicSlice3, sviContext.bgpPPP)
					progMap[bgpPPPLabelKey] = apicSlice3
				}
				sviContext.l3outNodeP.AddChild(sviContext.l3outLifP)
				if sviContext.connectedNw.UseExistingL3Out {
					apicSlice2 = append(apicSlice2, sviContext.l3outNodeP)
					return
				}
				sviContext.l3out.AddChild(sviContext.l3outNodeP)
				apicSlice2 = append(apicSlice2, sviContext.l3out)
			}
			if cont.isNodeFabNetAttVlanProgrammable(encap, sviContext, addNet) {
				if (nfcDiscovery != fabattv1.StaticPathMgmtTypeAEP) || sviContext.present {
					cont.populateFabricPaths(epg, encap, sviContext, addNet)
				}
				programNodeFabNetAttObjs()
				if !sviContext.present {
					apicSlice2 = cont.addNodeFabNetAttStaticAttachmentsLocked(encap, "", epg, apicSlice2, progMap)
				}
			} else {
				programNodeFabNetAttObjs()
				cont.log.Infof("Skipping staticpaths of shared encap vlan-%d with no pods", encap)
				for aep := range cont.sharedEncapCache[encap].Aeps {
					delete(cont.sharedEncapAepCache[aep], encap)
					if len(cont.sharedEncapAepCache[aep]) == 0 {
						lblKey := cont.aciNameForKey("aepPhysDom", aep)
						progMap[lblKey] = nil
						delete(cont.sharedEncapAepCache, aep)
						cont.log.Infof("Clearing physdom association for AEP %s", aep)
					}
					delete(cont.sharedEncapCache[encap].Aeps, aep)
				}
			}
		}
		progMap[labelKey] = apicSlice2
	}
	if !cont.config.AciUseGlobalScopeVlan {
		labelKey := cont.aciNameForKey("nfna", addNet.NetworkName)
		progMap[labelKey] = apicSlice
	}
}

func (cont *AciController) updateNodeFabNetAttPods(nodeFabNetAtt *fabattv1.NodeFabricNetworkAttachment, vlan int) {
	addNetKey := nodeFabNetAtt.Spec.NetworkRef.Namespace + "/" + nodeFabNetAtt.Spec.NetworkRef.Name
	if cont.config.AciUseGlobalScopeVlan {
		shrdEncapData, ok := cont.sharedEncapCache[vlan]
		if ok {
			// Remove old Pods
			nodeNADs, ok := shrdEncapData.Pods[nodeFabNetAtt.Spec.NodeName]
			if ok {
				delete(nodeNADs, addNetKey)
			}
			if len(nodeNADs) != 0 {
				shrdEncapData.Pods[nodeFabNetAtt.Spec.NodeName] = nodeNADs
			} else {
				delete(shrdEncapData.Pods, nodeFabNetAtt.Spec.NodeName)
			}
		} else {
			shrdEncapData = &sharedEncapData{
				NetRef: make(map[string]*AdditionalNetworkMeta),
				Pods:   make(map[string]map[string][]string),
				Aeps:   make(map[string]bool),
			}
			cont.sharedEncapCache[vlan] = shrdEncapData
		}

		for _, aciLink := range nodeFabNetAtt.Spec.AciTopology {
			podList := []string{}
			for _, podAtt := range aciLink.Pods {
				podRefStr := podAtt.PodRef.Namespace + "/" + podAtt.PodRef.Name
				podList = append(podList, podRefStr)
			}
			if len(podList) != 0 {
				nodeNADs, ok := shrdEncapData.Pods[nodeFabNetAtt.Spec.NodeName]
				if !ok {
					nodeNADs = make(map[string][]string)
				}
				nodeNADs[addNetKey] = podList
				shrdEncapData.Pods[nodeFabNetAtt.Spec.NodeName] = nodeNADs
			}
		}
	}
}

func (cont *AciController) updateNodeFabNetAttVlans(nodeFabNetAtt *fabattv1.NodeFabricNetworkAttachment, vlans []int, addNet *AdditionalNetworkMeta, progMap map[string]apicapi.ApicSlice) {
	addNetKey := nodeFabNetAtt.Spec.NetworkRef.Namespace + "/" + nodeFabNetAtt.Spec.NetworkRef.Name
	if cont.config.AciUseGlobalScopeVlan {
		if addNet.EncapVlan != nodeFabNetAtt.Spec.EncapVlan.VlanList {
			cont.log.Debugf("%s:Change in encap: %s=>%s", addNetKey, addNet.EncapVlan, nodeFabNetAtt.Spec.EncapVlan.VlanList)
			changeSet := make(map[int]bool)
			// manage the diff in encapvlan set
			old_vlans, _, _, _ := util.ParseVlanList([]string{addNet.EncapVlan})
			addNet.EncapVlan = nodeFabNetAtt.Spec.EncapVlan.VlanList
			for _, vlan := range vlans {
				changeSet[vlan] = true
			}
			for _, old_vlan := range old_vlans {
				if _, ok := changeSet[old_vlan]; !ok {
					cont.deleteNodeFabNetAttGlobalEncapVlanLocked(old_vlan, nodeFabNetAtt.Spec.NodeName, addNetKey, progMap)
				}
			}
		}
	}
	addNet.EncapVlan = nodeFabNetAtt.Spec.EncapVlan.VlanList
}

func (cont *AciController) updateNodeFabNetAttFabricLinks(nodeFabNetAtt *fabattv1.NodeFabricNetworkAttachment, addNet *AdditionalNetworkMeta) {
	linkPresent := map[string]bool{}
	for iface, aciLink := range nodeFabNetAtt.Spec.AciTopology {
		if _, ok := addNet.FabricLink[nodeFabNetAtt.Spec.NodeName]; !ok || (addNet.FabricLink[nodeFabNetAtt.Spec.NodeName] == nil) {
			addNet.FabricLink[nodeFabNetAtt.Spec.NodeName] = make(map[string]LinkData)
		}
		podList := []string{}
		for _, podAtt := range aciLink.Pods {
			podRefStr := podAtt.PodRef.Namespace + "/" + podAtt.PodRef.Name
			podList = append(podList, podRefStr)
		}
		addNet.FabricLink[nodeFabNetAtt.Spec.NodeName][iface] = LinkData{
			Link: aciLink.FabricLink,
			Pods: podList}
		linkPresent[iface] = true
	}
	nodeIfaceMap := addNet.FabricLink[nodeFabNetAtt.Spec.NodeName]
	for iface := range nodeIfaceMap {
		if _, ok := linkPresent[iface]; !ok {
			delete(nodeIfaceMap, iface)
		}
	}
	addNet.FabricLink[nodeFabNetAtt.Spec.NodeName] = nodeIfaceMap
}

func (cont *AciController) updateNodeFabNetAttObj(nodeFabNetAtt *fabattv1.NodeFabricNetworkAttachment) (progMap map[string]apicapi.ApicSlice) {
	var apicSlice apicapi.ApicSlice
	var addNet *AdditionalNetworkMeta
	progMap = make(map[string]apicapi.ApicSlice)
	vlans, encapBlks, _, err := util.ParseVlanList([]string{nodeFabNetAtt.Spec.EncapVlan.VlanList})
	if err != nil {
		cont.log.Errorf("%v", err)
		return progMap
	}
	addNetKey := nodeFabNetAtt.Spec.NetworkRef.Namespace + "/" + nodeFabNetAtt.Spec.NetworkRef.Name
	cont.log.Infof("nfna update: %v", addNetKey)
	cont.log.Debugf("parsed vlan list: %v", vlans)
	cont.indexMutex.Lock()
	addNet, ok := cont.additionalNetworkCache[addNetKey]
	if !ok {
		addNet = &AdditionalNetworkMeta{
			NetworkName: nodeFabNetAtt.Spec.NetworkRef.Namespace + "-" + nodeFabNetAtt.Spec.NetworkRef.Name,
			EncapVlan:   nodeFabNetAtt.Spec.EncapVlan.VlanList,
			FabricLink:  make(map[string]map[string]LinkData),
			NodeCache:   make(map[string]*fabattv1.NodeFabricNetworkAttachment),
			Mode:        util.ToEncapMode(nodeFabNetAtt.Spec.EncapVlan.Mode)}
		cont.additionalNetworkCache[addNetKey] = addNet
	} else {
		cont.updateNodeFabNetAttVlans(nodeFabNetAtt, vlans, addNet, progMap)
	}
	addNet.NodeCache[nodeFabNetAtt.Spec.NodeName] = nodeFabNetAtt

	// manage the diff in fabriclink set
	cont.updateNodeFabNetAttFabricLinks(nodeFabNetAtt, addNet)

	if cont.config.AciUseGlobalScopeVlan {
		encapStr := cont.getGlobalFabricVlanPoolLocked()
		cont.setGlobalScopeVlanConfig(encapStr, progMap)
		for _, vlan := range vlans {
			cont.updateNodeFabNetAttPods(nodeFabNetAtt, vlan)
			cont.sharedEncapCache[vlan].NetRef[addNetKey] = addNet
		}
	} else {
		apicSlice = append(apicSlice, cont.updateNodeFabNetAttDom(encapBlks, addNet.NetworkName)...)
	}
	cont.applyNodeFabNetAttObjLocked(vlans, addNet, apicSlice, progMap)
	cont.indexMutex.Unlock()
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
	cont.indexMutex.Lock()
	defer cont.indexMutex.Unlock()
	addNet, ok := cont.additionalNetworkCache[nodeFabNetAttKey]
	if !ok {
		return progMap
	}
	nodeCache, ok := addNet.NodeCache[nodeName]
	if !ok {
		return progMap
	}
	// already admitted.No error handling needed
	vlans, encapBlks, _, _ := util.ParseVlanList([]string{addNet.EncapVlan})
	delete(addNet.NodeCache, nodeName)

	if len(addNet.NodeCache) == 0 {
		delete(cont.additionalNetworkCache, nodeFabNetAttKey)
		if !cont.config.AciUseGlobalScopeVlan {
			labelKey := cont.aciNameForKey("nfna", addNet.NetworkName)
			progMap[labelKey] = nil
			return progMap
		} else {
			for _, encap := range vlans {
				cont.deleteNodeFabNetAttGlobalEncapVlanLocked(encap, nodeName, nodeFabNetAttKey, progMap)
			}
			cont.clearLLDPIf(nodeFabNetAttKey)
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
		apicSlice = append(apicSlice, cont.updateNodeFabNetAttDom(encapBlks, addNet.NetworkName)...)
	}

	cont.applyNodeFabNetAttObjLocked(vlans, addNet, apicSlice, progMap)
	return progMap
}

func (cont *AciController) queueNodeFabNetAttByKey(key string) {
	cont.nodeFabNetAttQueue.Add(key)
}

func (cont *AciController) updateNodeFabNetAttStaticAttachments(vlans []int, progMap map[string]apicapi.ApicSlice) {
	if cont.config.AciUseGlobalScopeVlan {
		var apicSlice apicapi.ApicSlice
		cont.indexMutex.Lock()
		cont.applyNodeFabNetAttObjLocked(vlans, nil, apicSlice, progMap)
		cont.indexMutex.Unlock()
	}
}

func (cont *AciController) handleLLDPIfUpdate(fabricLink string) bool {
	cont.indexMutex.Lock()
	defer cont.indexMutex.Unlock()
	lldpIfData, ok := cont.lldpIfCache[fabricLink]
	if !ok {
		return false
	}
	for addNetKey := range lldpIfData.Refs {
		progMap := make(map[string]apicapi.ApicSlice)
		var apicSlice apicapi.ApicSlice
		addNet, ok := cont.additionalNetworkCache[addNetKey]
		if !ok {
			continue
		}
		vlans, _, _, _ := util.ParseVlanList([]string{addNet.EncapVlan})
		cont.applyNodeFabNetAttObjLocked(vlans, addNet, apicSlice, progMap)
		for labelKey, apicSlice := range progMap {
			if apicSlice == nil {
				cont.apicConn.ClearApicObjects(labelKey)
				continue
			}
			cont.apicConn.WriteApicObjects(labelKey, apicSlice)
		}
	}
	return false
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
