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

package controller

import (
	"fmt"
	"github.com/sirupsen/logrus"
	"regexp"
	"strconv"
	"strings"

	"github.com/noironetworks/aci-containers/pkg/apicapi"
	erspanpolicy "github.com/noironetworks/aci-containers/pkg/erspanpolicy/apis/aci.erspan/v1alpha"
	erspanclientset "github.com/noironetworks/aci-containers/pkg/erspanpolicy/clientset/versioned"
	podIfpolicy "github.com/noironetworks/aci-containers/pkg/gbpcrd/apis/acipolicy/v1"
	"github.com/noironetworks/aci-containers/pkg/index"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
)

const (
	erspanCRDName = "erspanpolicies.aci.erspan"
)

func ErspanPolicyLogger(log *logrus.Logger, erspan *erspanpolicy.ErspanPolicy) *logrus.Entry {
	return log.WithFields(logrus.Fields{
		"namespace": erspan.ObjectMeta.Namespace,
		"name":      erspan.ObjectMeta.Name,
		"spec":      erspan.Spec,
	})
}

func erspanInit(cont *AciController, stopCh <-chan struct{}) {
	cont.log.Debug("Initializing erspan client")
	restconfig := cont.env.RESTConfig()
	erspanClient, err := erspanclientset.NewForConfig(restconfig)
	if err != nil {
		cont.log.Errorf("Failed to intialize erspan client")
		return
	}
	cont.initErspanInformerFromClient(erspanClient)
	go cont.erspanInformer.Run(stopCh)
	go cont.processQueue(cont.erspanQueue, cont.erspanIndexer,
		func(obj interface{}) bool {
			return cont.handleErspanUpdate(obj.(*erspanpolicy.ErspanPolicy))
		}, stopCh)
	cache.WaitForCacheSync(stopCh, cont.erspanInformer.HasSynced)
	cont.erspanSyncOpflexDev()
}

func (cont *AciController) initErspanInformerFromClient(
	erspanClient *erspanclientset.Clientset) {
	cont.initErspanInformerBase(
		cache.NewListWatchFromClient(
			erspanClient.AciV1alpha().RESTClient(), "erspanpolicies",
			metav1.NamespaceAll, fields.Everything()))
}

func (cont *AciController) initErspanInformerBase(listWatch *cache.ListWatch) {
	cont.erspanIndexer, cont.erspanInformer = cache.NewIndexerInformer(
		listWatch, &erspanpolicy.ErspanPolicy{}, 0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				cont.erspanPolicyUpdated(obj)
			},
			UpdateFunc: func(_, obj interface{}) {
				cont.erspanPolicyUpdated(obj)
			},
			DeleteFunc: func(obj interface{}) {
				cont.erspanPolicyDeleted(obj)
			},
		},
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	cont.log.Debug("Initializing erspan Policy Informers")
}

func isValidEPG(podif *podIfpolicy.PodIF) bool {
	pattern := regexp.MustCompile("\\|")
	idx := pattern.FindAllStringIndex(podif.Status.EPG, -1)
	if len(idx) != 1 || idx[0][0] == 0 || idx[0][0] == len(podif.Status.EPG)-1 {
		return false
	}
	return true
}

func (cont *AciController) queueErspanUpdateByKey(key string) {
	cont.erspanQueue.Add(key)
}

func (cont *AciController) erspanPolicyUpdated(obj interface{}) {
	erspanPolicy, ok := obj.(*erspanpolicy.ErspanPolicy)
	if !ok {
		cont.log.Error("erspanPolicyUpdated: Bad object type")
		return
	}
	key, err := cache.MetaNamespaceKeyFunc(erspanPolicy)
	if err != nil {
		ErspanPolicyLogger(cont.log, erspanPolicy).
			Error("Could not create key:" + err.Error())
		return
	}
	cont.queueErspanUpdateByKey(key)
	cont.erspanPolPods.UpdateSelectorObj(obj)
	cont.log.Infof("erspan policy updated: %s", erspanPolicy.ObjectMeta.Name)
}

func (cont *AciController) erspanPolicyDeleted(obj interface{}) {
	span, isSpan := obj.(*erspanpolicy.ErspanPolicy)
	if !isSpan {
		deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			ErspanPolicyLogger(cont.log, span).
				Error("Received unexpected object: ", obj)
			return
		}
		span, ok = deletedState.Obj.(*erspanpolicy.ErspanPolicy)
		if !ok {
			ErspanPolicyLogger(cont.log, span).
				Error("DeletedFinalStateUnknown contained non-erspan object: ", deletedState.Obj)
			return
		}
	}
	spankey, err := cache.MetaNamespaceKeyFunc(span)
	if err != nil {
		ErspanPolicyLogger(cont.log, span).
			Error("Could not create erspan key: ", err)
		return
	}
	cont.apicConn.ClearApicObjects(cont.aciNameForKey("span", spankey))
	cont.erspanPolPods.DeleteSelectorObj(obj)

}

func (cont *AciController) erspanSyncOpflexDev() {
	if cont.erspanIndexer == nil {
		return
	}
	cache.ListAll(cont.erspanIndexer, labels.Everything(),
		func(spanObj interface{}) {
			cont.queueErspanUpdate(spanObj.(*erspanpolicy.ErspanPolicy))
		})
}

func (cont *AciController) queueErspanUpdate(span *erspanpolicy.ErspanPolicy) {
	key, err := cache.MetaNamespaceKeyFunc(span)
	if err != nil {
		ErspanPolicyLogger(cont.log, span).
			Error("Could not create span key:" + err.Error())
		return
	}
	cont.erspanQueue.Add(key)
}

func (cont *AciController) initErspanPolPodIndex() {
	cont.erspanPolPods = index.NewPodSelectorIndex(cont.log,
		cont.podIndexer, cont.namespaceIndexer, cont.erspanIndexer,
		cache.MetaNamespaceKeyFunc,
		func(obj interface{}) []index.PodSelector {
			span := obj.(*erspanpolicy.ErspanPolicy)
			ls := &metav1.LabelSelector{MatchLabels: span.Spec.Selector.Labels}
			return index.PodSelectorFromNsAndSelector(span.Spec.Selector.Namespace, ls)
		},
	)
	spanupdate := func(spankey string) {
		spanobj, exists, err := cont.erspanIndexer.GetByKey(spankey)
		if exists && err == nil {
			cont.queueErspanUpdate(spanobj.(*erspanpolicy.ErspanPolicy))
		}
	}
	spanhash := func(pod *v1.Pod) string {
		return pod.Status.PodIP
	}

	// Callback when pods selected by erspan object change
	cont.erspanPolPods.SetObjUpdateCallback(spanupdate)
	cont.erspanPolPods.SetPodHashFunc(spanhash)
}

func (cont *AciController) getFabricPaths() []string {
	var paths []string
	cont.indexMutex.Lock()
	for node := range cont.nodeOpflexDevice {
		fabricPath, ok := cont.fabricPathForNode(node)
		if !ok {
			continue
		}
		paths = append(paths, fabricPath)
	}
	cont.indexMutex.Unlock()
	return paths
}

func (cont *AciController) getVpcs() []string {
	var vpcs []string
	vpcPaths := cont.getFabricPaths()
	for _, path := range vpcPaths {
		// VPC identified
		if strings.Contains(path, "/protpaths-") {
			vpc := strings.Split(path, "/pathep-[")
			vpcUnTrimmed := vpc[len(vpc)-1]
			vpcTrimmed := strings.TrimSuffix(vpcUnTrimmed, "]")
			vpcs = append(vpcs, vpcTrimmed)
		}
	}
	return vpcs
}

func (cont *AciController) getAccLeafPorts() []string {
	var accPorts []string
	portPaths := cont.getFabricPaths()
	for _, path := range portPaths {
		// Leaf Access Port identified
		if strings.Contains(path, "/paths-") {
			accPort := strings.Split(path, "/pathep-[")
			accPortUnTrimmed := accPort[len(accPort)-1]
			accPortTrimmed := strings.TrimSuffix(accPortUnTrimmed, "]")
			accPorts = append(accPorts, accPortTrimmed)
		}
	}
	return accPorts
}

func (cont *AciController) buildErspanObjs(span *erspanpolicy.ErspanPolicy) apicapi.ApicSlice {

	spankey, _ := cache.MetaNamespaceKeyFunc(span)
	labelKey := cont.aciNameForKey("span", spankey)
	cont.log.Infof("Creating erspan policy: %s", span.ObjectMeta.Name)

	// Source policies
	srcGrp := apicapi.NewSpanVSrcGrp(labelKey)
	srcName := labelKey + "_Src"
	apicSlice := apicapi.ApicSlice{srcGrp}
	srcGrp.SetAttr("adminSt", span.Spec.Source.AdminState)
	src := apicapi.NewSpanVSrc(srcGrp.GetDn(), srcName)
	srcGrp.AddChild(src)
	src.SetAttr("dir", span.Spec.Source.Direction)

	// Build fvCEp for matching pods
	cont.indexMutex.Lock()
	podKeys := cont.erspanPolPods.GetPodForObj(spankey)
	for _, podkey := range podKeys {
		if podkey, ok := cont.podIftoEp[podkey]; !ok {
			cont.log.Warning("Could not find podif data for ", podkey)
			continue
		}
		macRaw := cont.podIftoEp[podkey].MacAddr
		mac := strings.ToUpper(macRaw)
		epg := cont.podIftoEp[podkey].EPG
		appProfile := cont.podIftoEp[podkey].AppProfile
		fvCEpDn := fmt.Sprintf("uni/tn-%s/ap-%s/epg-%s/cep-%s",
			cont.config.AciPolicyTenant, appProfile, epg, mac)
		srcCEp := apicapi.NewSpanRsSrcToVPort(src.GetDn(), fvCEpDn)
		src.AddChild(srcCEp)
	}
	cont.indexMutex.Unlock()

	// Destination policies
	destGrp := apicapi.NewSpanVDestGrp(labelKey)
	destName := labelKey + "_Dest"
	dest := apicapi.NewSpanVDest(destGrp.GetDn(), destName)
	destGrp.AddChild(dest)
	destSummary := apicapi.NewSpanVEpgSummary(dest.GetDn())
	dest.AddChild(destSummary)
	destSummary.SetAttr("dstIp", span.Spec.Dest.DestIP)
	destSummary.SetAttr("flowId", strconv.Itoa(span.Spec.Dest.FlowID))
	apicSlice = append(apicSlice, destGrp)

	// Erspan policy binding to Virtual Port Channels.
	vpcs := cont.getVpcs()
	if len(vpcs) == 0 {
		cont.log.Info("No Virtual Port Channels found for erspan binding.")
	}
	for _, bundleName := range vpcs {

		accBndlGrp := apicapi.NewInfraAccBndlGrp(bundleName)
		infraRsSpanVSrcGrp := apicapi.NewInfraRsSpanVSrcGrp(bundleName, labelKey)
		accBndlGrp.AddChild(infraRsSpanVSrcGrp)
		apicSlice = append(apicSlice, infraRsSpanVSrcGrp)
		infraRsSpanVDstGrp := apicapi.NewInfraRsSpanVDestGrp(bundleName, labelKey)
		accBndlGrp.AddChild(infraRsSpanVDstGrp)
		apicSlice = append(apicSlice, infraRsSpanVDstGrp)
	}
	// Erspan policy binding to Leaf Access Ports.

	accPorts := cont.getAccLeafPorts()
	if len(accPorts) == 0 {
		cont.log.Info("No Leaf Access Ports found for erspan binding.")
	}
	for _, portName := range accPorts {

		accPortGrp := apicapi.NewInfraAccPortGrp(portName)
		infraRsSpanVSrcGrpAP := apicapi.NewInfraRsSpanVSrcGrpAP(portName, labelKey)
		accPortGrp.AddChild(infraRsSpanVSrcGrpAP)
		apicSlice = append(apicSlice, infraRsSpanVSrcGrpAP)
		infraRsSpanVDstGrpAP := apicapi.NewInfraRsSpanVDestGrpAP(portName, labelKey)
		accPortGrp.AddChild(infraRsSpanVDstGrpAP)
		apicSlice = append(apicSlice, infraRsSpanVDstGrpAP)
	}

	lbl := apicapi.NewSpanSpanLbl(srcGrp.GetDn(), labelKey)
	srcGrp.AddChild(lbl)

	cont.log.Info("Erspan APIC slice: ", apicSlice)
	cont.log.Debug("erspan object: ", span)

	return apicSlice
}

func (cont *AciController) handleErspanUpdate(obj interface{}) bool {
	span, ok := obj.(*erspanpolicy.ErspanPolicy)
	if !ok {
		cont.log.Error("handleErspanUpdate: Bad object type")
		return false
	}
	erspanLogger := ErspanPolicyLogger(cont.log, span)
	spankey, err := cache.MetaNamespaceKeyFunc(span)
	if err != nil {
		erspanLogger.Error("Could not create erspan policy key: ", err)
		return false
	}
	labelKey := cont.aciNameForKey("span", spankey)
	cont.apicConn.WriteApicObjects(labelKey, cont.buildErspanObjs(span))

	return false
}
