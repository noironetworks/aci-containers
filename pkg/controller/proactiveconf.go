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

// Handlers for ProactiveConf CR updates.

package controller

import (
	"context"
	"fmt"
	"strings"

	"github.com/noironetworks/aci-containers/pkg/apicapi"
	pcv1 "github.com/noironetworks/aci-containers/pkg/proactiveconf/apis/aci.pc/v1"
	proactiveconfclientset "github.com/noironetworks/aci-containers/pkg/proactiveconf/clientset/versioned"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
	"k8s.io/kubernetes/pkg/controller"
)

const (
	proactiveConfCRDName = "proactiveconfs.aci.pc"
)

func proactiveConfInit(cont *AciController, stopCh <-chan struct{}) {
	cont.log.Debug("Initializing proactiveConfClient")
	restconfig := cont.env.RESTConfig()
	proactiveConfClient, err := proactiveconfclientset.NewForConfig(restconfig)
	if err != nil {
		cont.log.Errorf("Failed to intialize proactiveConfClient")
		return
	}

	cont.initProactiveConfInformerFromClient(proactiveConfClient)
	go cont.proactiveConfInformer.Run(stopCh)
	cache.WaitForCacheSync(stopCh, cont.proactiveConfInformer.HasSynced)
}

func (cont *AciController) initProactiveConfInformerFromClient(
	proactiveConfClient *proactiveconfclientset.Clientset) {
	cont.initProactiveConfInformerBase(
		&cache.ListWatch{
			ListWithContextFunc: func(ctx context.Context, options metav1.ListOptions) (runtime.Object, error) {
				return proactiveConfClient.AciV1().ProactiveConfs().List(ctx, options)
			},
			WatchFuncWithContext: func(ctx context.Context, options metav1.ListOptions) (watch.Interface, error) {
				return proactiveConfClient.AciV1().ProactiveConfs().Watch(ctx, options)
			},
		})
}

func (cont *AciController) initProactiveConfInformerBase(listWatch *cache.ListWatch) {
	cont.proactiveConfInformer = cache.NewSharedIndexInformer(
		listWatch,
		&pcv1.ProactiveConf{},
		controller.NoResyncPeriodFunc(),
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	cont.proactiveConfInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			cont.proactiveConfAdded(obj)
		},
		UpdateFunc: func(oldobj interface{}, newobj interface{}) {
			cont.proactiveConfUpdate(oldobj, newobj)
		},
		DeleteFunc: func(obj interface{}) {
			cont.proactiveConfDelete(obj)
		},
	})
}

func (cont *AciController) proactiveConfAdded(obj interface{}) {
	policy := obj.(*pcv1.ProactiveConf)
	cont.log.Infof("ProactiveConf added: %s", policy.Name)
	cont.updateProactiveConf(policy)
}

func (cont *AciController) proactiveConfUpdate(oldobj interface{}, newobj interface{}) {
	oldpolicy := oldobj.(*pcv1.ProactiveConf)
	newpolicy := newobj.(*pcv1.ProactiveConf)
	cont.log.Infof("ProactiveConf updated: %s", newpolicy.Name)
	if oldpolicy.Spec.VmmEpgDeploymentImmediacy == newpolicy.Spec.VmmEpgDeploymentImmediacy {
		cont.log.Infof("ProactiveConf update: No change in VmmEpgDeploymentImmediacy")
		return
	}
	cont.updateProactiveConf(newpolicy)
}

func (cont *AciController) proactiveConfDelete(obj interface{}) {
	cont.indexMutex.Lock()
	defer cont.indexMutex.Unlock()
	policy := obj.(*pcv1.ProactiveConf)
	cont.log.Infof("ProactiveConf deleted: %s", policy.Name)
	fvRsDomAttSlice := cont.getfvRsDomAtt()
	cont.deleteProactiveConf(fvRsDomAttSlice)
}

func (cont *AciController) filterfvRsDomAtt(imdata []apicapi.ApicObject) []apicapi.ApicObject {
	systemDnsToFilter := []string{
		fmt.Sprintf("uni/tn-%s/ap-aci-containers-%s/epg-aci-containers-system", cont.config.AciPolicyTenant, cont.config.AciPrefix),
		fmt.Sprintf("uni/tn-%s/ap-aci-containers-%s/epg-aci-containers-istio", cont.config.AciPolicyTenant, cont.config.AciPrefix),
		fmt.Sprintf("uni/tn-%s/ap-aci-containers-%s/epg-aci-containers-nodes", cont.config.AciPolicyTenant, cont.config.AciPrefix),
	}

	vmmDomPDn := fmt.Sprintf("uni/vmmp-%s/dom-%s", cont.config.AciVmmDomainType, cont.config.AciVmmDomain)

	var fvRsDomAttSlice []apicapi.ApicObject
	for _, fvRsDomAtt := range imdata {
		dn := fvRsDomAtt.GetAttr("dn").(string)

		rsdomAttIndex := strings.LastIndex(dn, "/rsdomAtt-")
		if rsdomAttIndex == -1 {
			continue
		}

		skipEpg := false
		for _, epgDn := range systemDnsToFilter {
			if strings.HasPrefix(dn, epgDn) {
				skipEpg = true
				break
			}
		}
		if skipEpg {
			continue
		}

		rsdomAttDn := dn[rsdomAttIndex+len("/rsdomAtt-"):]
		rsdomAttDn = strings.Trim(rsdomAttDn, "[]")
		if rsdomAttDn == vmmDomPDn {
			fvRsDomAttSlice = append(fvRsDomAttSlice, fvRsDomAtt)
		}
	}

	return fvRsDomAttSlice
}

func (cont *AciController) getfvRsDomAtt() []apicapi.ApicObject {
	uri := fmt.Sprintf("/api/node/class/fvRsDomAtt.json?query-target-filter=and(wcard(fvRsDomAtt.dn,\"%s\"))", cont.config.AciPolicyTenant)
	resp, err := cont.apicConn.GetApicResponse(uri)
	if err != nil {
		cont.log.Errorf("Failed to get response from APIC: %v", err)
		return nil
	}
	return cont.filterfvRsDomAtt(resp.Imdata)
}

func (cont *AciController) postfvRsDomAtt(fvRsDomAttSlice []apicapi.ApicObject) {
	uri := fmt.Sprintf("/api/node/mo/uni/tn-%s.json", cont.config.AciPolicyTenant)
	err := cont.apicConn.PostApicObjects(uri, fvRsDomAttSlice)
	if err != nil {
		cont.log.Errorf("Failed to update the fvRsDomAtt: %v", err)
	}
}

func (cont *AciController) updateFvRsDomAttImmediacy(fvRsDomAttSlice []apicapi.ApicObject, instrImedcy, resImedcy string) {
	for _, fvRsDomAtt := range fvRsDomAttSlice {
		dn := fvRsDomAtt.GetAttr("dn").(string)
		fvRsDomAttNew := apicapi.EmptyApicObject("fvRsDomAtt", dn)
		fvRsDomAttNew.SetAttr("instrImedcy", instrImedcy)
		fvRsDomAttNew.SetAttr("resImedcy", resImedcy)
		cont.postfvRsDomAtt([]apicapi.ApicObject{fvRsDomAttNew})
	}
}

func (cont *AciController) updateProactiveConf(policy *pcv1.ProactiveConf) {
	cont.indexMutex.Lock()
	defer cont.indexMutex.Unlock()
	vmmEpgDeploymentImmediacy := policy.Spec.VmmEpgDeploymentImmediacy
	fvRsDomAttSlice := cont.getfvRsDomAtt()

	if vmmEpgDeploymentImmediacy == pcv1.VmmEpgDeploymentImmediacyTypeImmediate {
		cont.updateFvRsDomAttImmediacy(fvRsDomAttSlice, "immediate", "pre-provision")
	} else {
		cont.deleteProactiveConf(fvRsDomAttSlice)
	}
}

func (cont *AciController) deleteProactiveConf(fvRsDomAttSlice []apicapi.ApicObject) {
	cont.updateFvRsDomAttImmediacy(fvRsDomAttSlice, "lazy", "lazy")
}
