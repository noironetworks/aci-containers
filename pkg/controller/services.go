// Copyright 2016 Cisco Systems, Inc.
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

package controller

import (
	"net"
	"reflect"

	"github.com/Sirupsen/logrus"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	v1 "k8s.io/client-go/pkg/api/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/kubernetes/pkg/controller"
)

func (cont *AciController) initEndpointsInformerFromClient(
	kubeClient kubernetes.Interface) {

	cont.initEndpointsInformerBase(&cache.ListWatch{
		ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
			return kubeClient.CoreV1().Endpoints(metav1.NamespaceAll).List(options)
		},
		WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
			return kubeClient.CoreV1().Endpoints(metav1.NamespaceAll).Watch(options)
		},
	})
}

func (cont *AciController) initEndpointsInformerBase(listWatch *cache.ListWatch) {
	cont.endpointsInformer = cache.NewSharedIndexInformer(
		listWatch,
		&v1.Endpoints{},
		controller.NoResyncPeriodFunc(),
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	cont.endpointsInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			cont.endpointsChanged(obj)
		},
		UpdateFunc: func(_ interface{}, obj interface{}) {
			cont.endpointsChanged(obj)
		},
		DeleteFunc: func(obj interface{}) {
			cont.endpointsChanged(obj)
		},
	})

}

func (cont *AciController) initServiceInformerFromClient(
	kubeClient *kubernetes.Clientset) {

	cont.initServiceInformerBase(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				return kubeClient.CoreV1().Services(metav1.NamespaceAll).List(options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				return kubeClient.CoreV1().Services(metav1.NamespaceAll).Watch(options)
			},
		})
}

func (cont *AciController) initServiceInformerBase(listWatch *cache.ListWatch) {
	cont.serviceInformer = cache.NewSharedIndexInformer(
		listWatch,
		&v1.Service{},
		controller.NoResyncPeriodFunc(),
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	cont.serviceInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			cont.serviceChanged(obj)
		},
		UpdateFunc: func(_ interface{}, obj interface{}) {
			cont.serviceChanged(obj)
		},
		DeleteFunc: func(obj interface{}) {
			cont.serviceDeleted(obj)
		},
	})
}

func serviceLogger(log *logrus.Logger, as *v1.Service) *logrus.Entry {
	return log.WithFields(logrus.Fields{
		"namespace": as.ObjectMeta.Namespace,
		"name":      as.ObjectMeta.Name,
		"type":      as.Spec.Type,
	})
}

func (cont *AciController) endpointsChanged(obj interface{}) {
	cont.indexMutex.Lock()
	defer cont.indexMutex.Unlock()

	//	endpoints := obj.(*v1.Endpoints)
}

func returnIps(pool *netIps, ips []net.IP) {
	for _, ip := range ips {
		if ip.To4() != nil {
			pool.V4.AddIp(ip)
		} else if ip.To16() != nil {
			pool.V6.AddIp(ip)
		}
	}
}

func (cont *AciController) serviceChanged(obj interface{}) {
	cont.indexMutex.Lock()
	defer cont.indexMutex.Unlock()

	service := obj.(*v1.Service)
	logger := serviceLogger(cont.log, service)

	servicekey, err := cache.MetaNamespaceKeyFunc(service)
	if err != nil {
		logger.Error("Could not create service key: ", err)
		return
	}
	meta, ok := cont.serviceMetaCache[servicekey]
	isLoadBalancer := service.Spec.Type == v1.ServiceTypeLoadBalancer
	if ok && !isLoadBalancer {
		cont.serviceDeleted(obj)
		return
	}
	if !isLoadBalancer {
		return
	}
	if !ok {
		meta = &serviceMeta{}
		cont.serviceMetaCache[servicekey] = meta

		// Read any existing IPs and attempt to allocate them to the pod
		for _, ingress := range service.Status.LoadBalancer.Ingress {
			ip := net.ParseIP(ingress.IP)
			if ip == nil {
				continue
			}
			if ip.To4() != nil {
				if cont.serviceIps.V4.RemoveIp(ip) {
					meta.ingressIps = append(meta.ingressIps, ip)
				} else if cont.staticServiceIps.V4.RemoveIp(ip) {
					meta.staticIngressIps = append(meta.staticIngressIps, ip)
				}
			} else if ip.To16() != nil {
				if cont.serviceIps.V6.RemoveIp(ip) {
					meta.ingressIps = append(meta.ingressIps, ip)
				} else if cont.staticServiceIps.V6.RemoveIp(ip) {
					meta.staticIngressIps = append(meta.staticIngressIps, ip)
				}
			}
		}
	}

	// try to give the requested load balancer IP to the pod
	requestedIp := net.ParseIP(service.Spec.LoadBalancerIP)
	if requestedIp != nil {
		hasRequestedIp := false
		for _, ip := range meta.ingressIps {
			if reflect.DeepEqual(requestedIp, ip) {
				hasRequestedIp = true
			}
		}
		if !hasRequestedIp {
			if requestedIp.To4() != nil &&
				cont.staticServiceIps.V4.RemoveIp(requestedIp) {
				hasRequestedIp = true
			} else if requestedIp.To16() != nil &&
				cont.staticServiceIps.V6.RemoveIp(requestedIp) {
				hasRequestedIp = true
			}
		}
		if hasRequestedIp {
			returnIps(cont.serviceIps, meta.ingressIps)
			meta.ingressIps = nil
			meta.staticIngressIps = []net.IP{requestedIp}
			meta.requestedIp = requestedIp
		}
	} else if meta.requestedIp != nil {
		meta.requestedIp = nil
		returnIps(cont.staticServiceIps, meta.staticIngressIps)
		meta.staticIngressIps = nil
	}

	if len(meta.ingressIps) == 0 && len(meta.staticIngressIps) == 0 {
		ipv4, err := cont.serviceIps.V4.GetIp()
		if err != nil {
			logger.Error("No IP addresses available for service")
		} else {
			meta.ingressIps = []net.IP{ipv4}
		}
	}

	var newIngress []v1.LoadBalancerIngress
	for _, ip := range meta.ingressIps {
		newIngress = append(newIngress, v1.LoadBalancerIngress{IP: ip.String()})
	}
	for _, ip := range meta.staticIngressIps {
		newIngress = append(newIngress, v1.LoadBalancerIngress{IP: ip.String()})
	}

	if !reflect.DeepEqual(newIngress, service.Status.LoadBalancer.Ingress) {
		service.Status.LoadBalancer.Ingress = newIngress

		_, err := cont.updateServiceStatus(service)
		if err != nil {
			logger.Error("Failed to update service: ", err)
		} else {
			logger.WithFields(logrus.Fields{
				"status": service.Status.LoadBalancer.Ingress,
			}).Info("Updated service load balancer status")
		}
	}
}

func (cont *AciController) serviceDeleted(obj interface{}) {
	cont.indexMutex.Lock()
	defer cont.indexMutex.Unlock()

	service := obj.(*v1.Service)
	logger := serviceLogger(cont.log, service)

	servicekey, err := cache.MetaNamespaceKeyFunc(service)
	if err != nil {
		logger.Error("Could not create service key: ", err)
		return
	}
	if meta, ok := cont.serviceMetaCache[servicekey]; ok {
		returnIps(cont.serviceIps, meta.ingressIps)
		returnIps(cont.staticServiceIps, meta.staticIngressIps)
		delete(cont.serviceMetaCache, servicekey)
	}
}
