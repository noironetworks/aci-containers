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

// Handlers for outofbandpolicy updates.

package controller

import (
	"context"
	"fmt"
	"strings"

	"github.com/noironetworks/aci-containers/pkg/apicapi"
	oobv1 "github.com/noironetworks/aci-containers/pkg/oobpolicy/apis/aci.oob/v1"
	oobpolicyclientset "github.com/noironetworks/aci-containers/pkg/oobpolicy/clientset/versioned"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
	"k8s.io/kubernetes/pkg/controller"
)

const (
	oobPolicyCRDName = "outofbandpolicies.aci.oob"
)

func oobPolicyInit(cont *AciController, stopCh <-chan struct{}) {
	cont.log.Debug("Initializing oobPolicy client")
	restconfig := cont.env.RESTConfig()
	oobPolicyClient, err := oobpolicyclientset.NewForConfig(restconfig)
	if err != nil {
		cont.log.Errorf("Failed to intialize oobPolicyClient")
		return
	}

	cont.initOOBPolicyInformerFromClient(oobPolicyClient)
	go cont.oobPolicyInformer.Run(stopCh)
	cache.WaitForCacheSync(stopCh, cont.oobPolicyInformer.HasSynced)
}

func (cont *AciController) initOOBPolicyInformerFromClient(
	oobPolicyClient *oobpolicyclientset.Clientset) {
	cont.initOOBPolicyInformerBase(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				return oobPolicyClient.AciV1().OutOfBandPolicies(metav1.NamespaceAll).List(context.TODO(), options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				return oobPolicyClient.AciV1().OutOfBandPolicies(metav1.NamespaceAll).Watch(context.TODO(), options)
			},
		})
}

func (cont *AciController) initOOBPolicyInformerBase(listWatch *cache.ListWatch) {
	cont.oobPolicyInformer = cache.NewSharedIndexInformer(
		listWatch,
		&oobv1.OutOfBandPolicy{},
		controller.NoResyncPeriodFunc(),
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	cont.oobPolicyInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			cont.oobPolicyAdded(obj)
		},
		UpdateFunc: func(oldobj interface{}, newobj interface{}) {
			cont.oobPolicyUpdate(oldobj, newobj)
		},
		DeleteFunc: func(obj interface{}) {
			cont.oobPolicyDelete(obj)
		},
	})
}

func (cont *AciController) oobPolicyAdded(obj interface{}) {
	policy := obj.(*oobv1.OutOfBandPolicy)
	cont.log.Infof("OutOfBandPolicy added: %s", policy.Name)
	cont.updateOOBPolicy(policy)
}

func (cont *AciController) oobPolicyUpdate(oldobj interface{}, newobj interface{}) {
	oldpolicy := oldobj.(*oobv1.OutOfBandPolicy)
	newpolicy := newobj.(*oobv1.OutOfBandPolicy)
	cont.log.Infof("OutOfBandPolicy updated: %s", newpolicy.Name)
	if oldpolicy.Spec.VmmEpgDeploymentImmediacy == newpolicy.Spec.VmmEpgDeploymentImmediacy {
		cont.log.Infof("OutOfBandPolicy update: No change in VmmEpgDeploymentImmediacy")
		return
	}
	cont.updateOOBPolicy(newpolicy)
}

func (cont *AciController) oobPolicyDelete(obj interface{}) {
	cont.indexMutex.Lock()
	defer cont.indexMutex.Unlock()
	policy := obj.(*oobv1.OutOfBandPolicy)
	cont.log.Infof("OutOfBandPolicy deleted: %s", policy.Name)
	fvRsDomAttSlice := cont.getfvRsDomAtt()
	cont.deleteOOBPolicy(fvRsDomAttSlice)
}

func (cont *AciController) filterfvRsDomAtt(imdata []apicapi.ApicObject) []apicapi.ApicObject {
	epgDnsSet := make(map[string]struct{}, len(cont.cachedEpgDns)+1)
	for _, epgDn := range cont.cachedEpgDns {
		epgDnsSet[epgDn] = struct{}{}
	}

	systemDnsToFilter := []string{
		fmt.Sprintf("uni/tn-%s/ap-aci-containers-%s/epg-aci-containers-system", cont.config.AciPolicyTenant, cont.config.AciVmmDomain),
		fmt.Sprintf("uni/tn-%s/ap-aci-containers-%s/epg-aci-containers-istio", cont.config.AciPolicyTenant, cont.config.AciVmmDomain),
		fmt.Sprintf("uni/tn-%s/ap-aci-containers-%s/epg-aci-containers-nodes", cont.config.AciPolicyTenant, cont.config.AciVmmDomain),
	}

	for _, dn := range systemDnsToFilter {
		delete(epgDnsSet, dn)
	}

	vmmDomPDn := fmt.Sprintf("uni/vmmp-%s/dom-%s", cont.vmmDomainProvider(), cont.config.AciVmmDomain)

	var fvRsDomAttSlice []apicapi.ApicObject
	for _, fvRsDomAtt := range imdata {
		dn := fvRsDomAtt.GetAttr("dn").(string)

		rsdomAttIndex := strings.LastIndex(dn, "/rsdomAtt-")
		if rsdomAttIndex == -1 {
			continue
		}

		parentDn := dn[:rsdomAttIndex]
		if _, found := epgDnsSet[parentDn]; !found {
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

func (cont *AciController) updateFvRsDomAttInstrImedcy(fvRsDomAttSlice []apicapi.ApicObject, immediacy string) {
	for _, fvRsDomAtt := range fvRsDomAttSlice {
		dn := fvRsDomAtt.GetAttr("dn").(string)
		fvRsDomAttNew := apicapi.EmptyApicObject("fvRsDomAtt", dn)
		fvRsDomAttNew.SetAttr("instrImedcy", immediacy)
		fvRsDomAttNew.SetAttr("resImedcy", immediacy)
		cont.postfvRsDomAtt([]apicapi.ApicObject{fvRsDomAttNew})
	}
}

func (cont *AciController) updateOOBPolicy(policy *oobv1.OutOfBandPolicy) {
	cont.indexMutex.Lock()
	defer cont.indexMutex.Unlock()
	vmmEpgDeploymentImmediacy := policy.Spec.VmmEpgDeploymentImmediacy
	fvRsDomAttSlice := cont.getfvRsDomAtt()

	if vmmEpgDeploymentImmediacy == oobv1.VmmEpgDeploymentImmediacyTypeImmediate {
		cont.updateFvRsDomAttInstrImedcy(fvRsDomAttSlice, "immediate")
	} else {
		cont.deleteOOBPolicy(fvRsDomAttSlice)
	}
}

func (cont *AciController) deleteOOBPolicy(fvRsDomAttSlice []apicapi.ApicObject) {
	cont.updateFvRsDomAttInstrImedcy(fvRsDomAttSlice, "lazy")
}

func (cont *AciController) handleEpgDnCacheUpdate(epgDnCacheUpdated bool) bool {
	if epgDnCacheUpdated {
		env := cont.env.(*K8sEnvironment)
		oobcl := env.oobPolicyClient
		if oobcl == nil {
			cont.log.Error("oobPolicyClient not found")
			return false
		}
		oobPolList, err := oobcl.AciV1().OutOfBandPolicies(metav1.NamespaceAll).List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			cont.log.Errorf("Failed to get OutOfBandPolicies: %v", err)
			return false
		}
		for _, oobPol := range oobPolList.Items {
			cont.updateOOBPolicy(&oobPol)
		}
	}
	return false
}
