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
	"fmt"
	snatglobalinfo "github.com/noironetworks/aci-containers/pkg/snatglobalinfo/apis/aci.snat/v1"
	snatpolicy "github.com/noironetworks/aci-containers/pkg/snatpolicy/apis/aci.snat/v1"
	snatclientset "github.com/noironetworks/aci-containers/pkg/snatpolicy/clientset/versioned"
	"github.com/noironetworks/aci-containers/pkg/util"
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
	"net"
	"reflect"
)

const snatGraphName = "svcgraph"

type ContPodSelector struct {
	Labels    map[string]string
	Namespace string
}

type ContPortRange struct {
	Start int `json:"start,omitempty"`
	End   int `json:"end,omitempty"`
}

type ContSnatPolicy struct {
	SnatIp            []string
	Selector          ContPodSelector
	PortRange         []ContPortRange
	Protocols         []string
	ExpandedSnatIps   []string
	ExpandedSnatPorts []snatglobalinfo.PortRange
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
				cont.snatPolicyUpdated(obj)
			},
			UpdateFunc: func(_, obj interface{}) {
				cont.snatPolicyUpdated(obj)
			},
			DeleteFunc: func(obj interface{}) {
				cont.snatPolicyDelete(obj)
			},
		},
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	cont.log.Debug("Initializing Snat Policy Informers")

}

func (cont *AciController) snatPolicyUpdated(obj interface{}) {
	snatPolicy := obj.(*snatpolicy.SnatPolicy)
	key, err := cache.MetaNamespaceKeyFunc(snatPolicy)
	if err != nil {
		SnatPolicyLogger(cont.log, snatPolicy).
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

func (cont *AciController) handleSnatUpdate(snatPolicy *snatpolicy.SnatPolicy) bool {
	_, err := cache.MetaNamespaceKeyFunc(snatPolicy)
	if err != nil {
		SnatPolicyLogger(cont.log, snatPolicy).
			Error("Could not create key:" + err.Error())
		return false
	}
	policyName := snatPolicy.ObjectMeta.Name
	if snatPolicy.Status.State != snatpolicy.Ready {
		if snatPolicy.Status.State == snatpolicy.IpPortsExhausted {
			return false
		}
		if status, err := cont.validateCr(snatPolicy); !status {
			cont.log.Error("SnatPolicy Failed: ", err)
			return cont.setSnatPolicyStaus(policyName, snatpolicy.Failed)
		}
		return cont.setSnatPolicyStaus(policyName, snatpolicy.Ready)
	}
	cont.updateSnatPolicyCache(policyName, snatPolicy)
	var requeue bool
	cont.indexMutex.Lock()
	if cont.snatSyncEnabled {
		cont.indexMutex.Unlock()

		if len(snatPolicy.Spec.SnatIp) == 0 {
			err = cont.handleSnatPolicyForServices(snatPolicy)
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

func (cont *AciController) getServicesBySelector(selector labels.Selector, ns string) []*v1.Service {
	var services []*v1.Service
	cache.ListAll(cont.serviceIndexer, selector,
		func(servobj interface{}) {
			service := servobj.(*v1.Service)
			if len(ns) == 0 || (len(ns) > 0 && ns == service.ObjectMeta.Namespace) {
				if len(service.Status.LoadBalancer.Ingress) != 0 {
					services = append(services, service)
				}
			}
		})
	return services
}

func (cont *AciController) handleSnatPolicyForServices(snatpolicy *snatpolicy.SnatPolicy) error {
	ServiceList := cont.getServicesBySelector(labels.SelectorFromSet(
		labels.Set(snatpolicy.Spec.Selector.Labels)),
		snatpolicy.Spec.Selector.Namespace)

	if len(ServiceList) == 0 {
		return nil
	}
	for _, service := range ServiceList {
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
	return nil
}

func (cont *AciController) updateSnatPolicyCache(key string, snatpolicy *snatpolicy.SnatPolicy) {
	cont.indexMutex.Lock()
	var policy ContSnatPolicy
	env := cont.env.(*K8sEnvironment)
	policy.SnatIp = snatpolicy.Spec.SnatIp
	policy.ExpandedSnatIps = util.ExpandCIDRs(policy.SnatIp)
	portRange := snatglobalinfo.PortRange{Start: 5000, End: 65000}
	portsPerNode := 3000
	if env.kubeClient != nil {
		portRange, portsPerNode = util.GetPortRangeFromConfigMap(env.kubeClient)
	}
	var currPortRange []snatglobalinfo.PortRange
	currPortRange = append(currPortRange, portRange)
	policy.ExpandedSnatPorts = util.ExpandPortRanges(currPortRange, portsPerNode)
	policy.Selector = ContPodSelector{Labels: snatpolicy.Spec.Selector.Labels, Namespace: snatpolicy.Spec.Selector.Namespace}
	Update := false
	if snatInfo, ok := cont.snatPolicyCache[key]; ok {
		if !reflect.DeepEqual(policy.SnatIp, snatInfo.SnatIp) {
			cont.clearSnatGlobalCache(snatpolicy.ObjectMeta.Name, "")
			Update = true
		}
	}
	cont.snatPolicyCache[key] = &policy
	if Update {
		cont.handleSnatPoilcyUpdate(snatpolicy.ObjectMeta.Name)
	}
	cont.indexMutex.Unlock()
}

func (cont *AciController) snatPolicyDelete(snatobj interface{}) {
	snatpolicy := snatobj.(*snatpolicy.SnatPolicy)
	cont.indexMutex.Lock()
	cont.clearSnatGlobalCache(snatpolicy.ObjectMeta.Name, "")
	delete(cont.snatPolicyCache, snatpolicy.ObjectMeta.Name)

	if len(snatpolicy.Spec.SnatIp) == 0 {
		ServiceList := cont.getServicesBySelector(labels.SelectorFromSet(
			labels.Set(snatpolicy.Spec.Selector.Labels)),
			snatpolicy.Spec.Selector.Namespace)
		if len(ServiceList) > 0 {
			for _, service := range ServiceList {
				servicekey, err1 := cache.MetaNamespaceKeyFunc(service)
				if err1 != nil {
					servicekey = service.ObjectMeta.Namespace + "/" + service.ObjectMeta.Name
				}
				delete(cont.snatServices, servicekey)
				cont.queueServiceUpdateByKey(servicekey)
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

func (cont *AciController) validateCr(cr *snatpolicy.SnatPolicy) (bool, string) {
	cont.indexMutex.Lock()
	snatPolicyCache := make(map[string]*ContSnatPolicy)
	for k, v := range cont.snatPolicyCache {
		snatPolicyCache[k] = v
	}
	cont.indexMutex.Unlock()
	if len(cont.snatPolicyCache) >= 1 {
		cr_labels := cr.Spec.Selector.Labels
		cr_ns := cr.Spec.Selector.Namespace
		for key, item := range snatPolicyCache {
			if cr.ObjectMeta.Name != key {
				if (len(item.Selector.Labels) == 0) && (len(cr_labels) == 0) &&
					(cr_ns == item.Selector.Namespace) {
					return false, fmt.Sprintf(
						"Namespace is conflicting with the snatpolicy %s",
						cr.ObjectMeta.Name)
				}
				for _, val := range item.SnatIp {
					_, net1, _ := parseIP(val)
					for _, ip := range cr.Spec.SnatIp {
						_, net2, err := parseIP(ip)
						if err != nil {
							return false, fmt.Sprintf(
								"Invalid incoming SnatIP %s", ip)
						}
						if net2.Contains(net1.IP) || net1.Contains(net2.IP) {
							return false, fmt.Sprintf(
								"SnatIP's are conflicting with the snatpolicy %s",
								cr.ObjectMeta.Name)
						}
					}
				}
			}
		}
	} else {
		for _, ip := range cr.Spec.SnatIp {
			_, _, err := parseIP(ip)
			if err != nil {
				return false, fmt.Sprintf(
					"Invalid incoming SnatIP %s", ip)
			}
		}
	}
	for _, ip := range cr.Spec.DestIp {
		_, _, err := parseIP(ip)
		if err != nil {
			return false, fmt.Sprintf(
				"Invalid incoming DestIP %s", ip)
		}
	}

	return true, ""
}

func parseIP(cidr string) (net.IP, *net.IPNet, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		ip_temp := net.ParseIP(cidr)
		if ip_temp != nil && ip_temp.To4() != nil {
			cidr = cidr + "/32"
			ip, ipnet, _ = net.ParseCIDR(cidr)
			return ip, ipnet, nil
		} else if ip_temp != nil && ip_temp.To16() != nil {
			cidr = cidr + "/128"
			ip, ipnet, _ = net.ParseCIDR(cidr)
			return ip, ipnet, nil
		} else {
			return nil, nil, err
		}
	}
	return ip, ipnet, err
}
