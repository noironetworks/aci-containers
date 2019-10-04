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
	"github.com/Sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
	snatclientset "github.com/noironetworks/aci-containers/pkg/snatpolicy/clientset/versioned"
	snatpolicy "github.com/noironetworks/aci-containers/pkg/snatpolicy/apis/aci.snat/v1"
)

const snatGraphName = "svcgraph"

type ContPodSelector struct {
	Labels     map[string]string
	Namespace  string
}

type ContPortRange struct {
	Start int `json:"start,omitempty"`
	End   int `json:"end,omitempty"`
}

type ContSnatPolicy struct {
	SnatIp    []string
	Selector  ContPodSelector
	PortRange []ContPortRange
	Protocols []string
}

func SnatPolicyLogger(log *logrus.Logger, snat *snatpolicy.SnatPolicy) *logrus.Entry {
	return log.WithFields(logrus.Fields{
		"namespace": snat.ObjectMeta.Namespace,
		"name":      snat.ObjectMeta.Name,
		"spec":      snat.Spec,
	})
}

func (cont *AciController) initSnatInformerFromClient(
	snatClient *snatclientset.Clientset) {
	cont.initSnatInformerBase(
		cache.NewListWatchFromClient(
			snatClient.AciV1().RESTClient(), "snatpolicies",
			metav1.NamespaceAll, fields.Everything()))
}

func (cont *AciController) initSnatInformerBase(listWatch *cache.ListWatch) {
	cont.snatIndexer, cont.snatInformer = cache.NewIndexerInformer(
		listWatch,
		&snatpolicy.SnatPolicy{}, 0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				cont.snatUpdated(obj)
			},
			UpdateFunc: func(_ interface{}, obj interface{}) {
				cont.snatUpdated(obj)
			},
			DeleteFunc: func(obj interface{}) {
				cont.snatPolicyDelete(obj)
			},
		},
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	cont.log.Debug("Initializing Snat Policy Informers")

}

func(cont *AciController) snatUpdated(obj interface{}) {
	snat := obj.(*snatpolicy.SnatPolicy)
	key, err := cache.MetaNamespaceKeyFunc(snat)
	if err != nil {
		SnatPolicyLogger(cont.log, snat).
			Error("Could not create key:" + err.Error())
		return
	}
	cont.queueSnatUpdateByKey(key)
}

func (cont *AciController) queueSnatUpdateByKey(key string) {
	cont.snatQueue.Add(key)
}

func (cont *AciController) queueSnatUpdate(snatpolicy *snatpolicy.SnatPolicy) {
	key, err := cache.MetaNamespaceKeyFunc(snatpolicy)
	if err != nil {
		SnatPolicyLogger(cont.log, snatpolicy).
			Error("Could not create key:" + err.Error())
		return
	}
	cont.snatQueue.Add(key)
}

func (cont *AciController) handleSnatUpdate(snatpolicy *snatpolicy.SnatPolicy) bool {
	_, err := cache.MetaNamespaceKeyFunc(snatpolicy)
	if err != nil {
		SnatPolicyLogger(cont.log, snatpolicy).
			Error("Could not create key:" + err.Error())
		return false
	}

	policyName := snatpolicy.ObjectMeta.Name
	var requeue bool
	if len(snatpolicy.Spec.SnatIp) > 0 {
		cont.indexMutex.Lock()
		cont.updateSnatPolicyCache(policyName, snatpolicy)
		cont.indexMutex.Unlock()
	}
	cont.indexMutex.Lock()
	if cont.snatSyncEnabled {
		cont.indexMutex.Unlock()

		if len(snatpolicy.Spec.SnatIp) == 0 {
			err = cont.handleSnatPolicyForServices(snatpolicy)
		} else {
			err = cont.updateServiceDeviceInstanceSnat(snatGraphName)
		}
		if err != nil {
			requeue = true
		}
	} else {
		cont.indexMutex.Unlock()
	}
	return requeue
}

func (cont *AciController) handleSnatPolicyForServices(snatpolicy *snatpolicy.SnatPolicy ) error {

	selector := labels.Set(snatpolicy.Spec.Selector.Labels).String()
	ServicesList, err := cont.listServicesBySelector(selector)
	if err != nil {
		cont.log.Debug("Error getting matching services: ", err)
	}
	if len(ServicesList.Items) == 0 {
		return nil
	}
	for _, service := range ServicesList.Items {
		if service.Spec.Type == v1.ServiceTypeLoadBalancer {
			servicekey, err := cache.MetaNamespaceKeyFunc(service)
			if err != nil {
				servicekey = service.ObjectMeta.Namespace + "/" + service.ObjectMeta.Name
			}
			cont.indexMutex.Lock()
			if service.GetDeletionTimestamp() == nil {
				cont.snatServices[servicekey] = true
				cont.queueServiceUpdateByKey(servicekey)
			}
			cont.indexMutex.Unlock()
		}
	}
	return nil
}

func (cont *AciController) updateSnatPolicyCache(key string, snatpolicy *snatpolicy.SnatPolicy) {
	var policy ContSnatPolicy
	policy.SnatIp = snatpolicy.Spec.SnatIp
	policy.Selector = ContPodSelector{Labels: snatpolicy.Spec.Selector.Labels, Namespace: snatpolicy.Spec.Selector.Namespace}
	cont.snatPolicyCache[key] = &policy
}

func (cont *AciController) snatPolicyDelete(snatobj interface{}) {
        snatpolicy := snatobj.(*snatpolicy.SnatPolicy)
	cont.indexMutex.Lock()
	delete(cont.snatPolicyCache, snatpolicy.ObjectMeta.Name)

	if len(snatpolicy.Spec.SnatIp) == 0 {
		selector := labels.Set(snatpolicy.Spec.Selector.Labels).String()
		ServicesList, err := cont.listServicesBySelector(selector)
		if err == nil {
			if len(ServicesList.Items) > 0 {
				for _, service := range ServicesList.Items {
					if service.Spec.Type == v1.ServiceTypeLoadBalancer {
						servicekey, err1 := cache.MetaNamespaceKeyFunc(service)
						if err1 != nil {
							servicekey = service.ObjectMeta.Namespace + "/" + service.ObjectMeta.Name
						}
						delete(cont.snatServices, servicekey)
						cont.queueServiceUpdateByKey(servicekey)
					}
				}
			}
		}
	} else {
		if len(cont.snatPolicyCache) == 0 {
			cont.log.Debug("No more snat policies, deleting graph")
			graphName := cont.aciNameForKey("snat", snatGraphName)
			go cont.apicConn.ClearApicObjects(graphName)
		} else {
			go cont.updateServiceDeviceInstanceSnat(snatGraphName)
		}
	}
	cont.indexMutex.Unlock()
}

func (cont *AciController) snatFullSync() {
	cache.ListAll(cont.snatIndexer, labels.Everything(),
		func(sobj interface{}) {
			cont.queueSnatUpdate(sobj.(*snatpolicy.SnatPolicy))
		})
}

