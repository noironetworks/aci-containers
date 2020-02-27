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
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package loadbalancer

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/kubernetes/pkg/controller"
	"strings"
	"sync"
)

type LBProvider interface {
	// set up the service to redirect traffic to targets
	UpdateService(*v1.Service, []string) error
}

type NSLoadBalancer struct {
	sync.Mutex
	provider          LBProvider
	stopCh            chan struct{}
	kubeClient        *kubernetes.Clientset
	endpointsInformer cache.SharedIndexInformer
	serviceInformer   cache.SharedIndexInformer
}

func NewNSLB(p LBProvider) (*NSLoadBalancer, error) {
	cfg, err := restclient.InClusterConfig()
	if err != nil {
		return nil, err
	}

	kubeClient, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}

	nslb := &NSLoadBalancer{
		provider:   p,
		kubeClient: kubeClient,
		stopCh:     make(chan struct{}),
	}

	nslb.initEPWatch()
	nslb.initSvcWatch()

	return nslb, nil

}

func (n *NSLoadBalancer) Stop() {
	close(n.stopCh)
}

func (n *NSLoadBalancer) initEPWatch() {
	epLW := &cache.ListWatch{
		ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
			return n.kubeClient.CoreV1().Endpoints(metav1.NamespaceAll).List(options)
		},
		WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
			return n.kubeClient.CoreV1().Endpoints(metav1.NamespaceAll).Watch(options)
		},
	}

	n.endpointsInformer = cache.NewSharedIndexInformer(
		epLW,
		&v1.Endpoints{},
		controller.NoResyncPeriodFunc(),
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)

	n.endpointsInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			n.endpointsChanged(obj)
		},
		UpdateFunc: func(_ interface{}, obj interface{}) {
			n.endpointsChanged(obj)
		},
		DeleteFunc: func(obj interface{}) {
			n.endpointsChanged(obj)
		},
	})

	go n.endpointsInformer.Run(n.stopCh)
}

func (n *NSLoadBalancer) initSvcWatch() {
	svcLW := &cache.ListWatch{
		ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
			return n.kubeClient.CoreV1().Services(metav1.NamespaceAll).List(options)
		},
		WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
			return n.kubeClient.CoreV1().Services(metav1.NamespaceAll).Watch(options)
		},
	}

	n.serviceInformer = cache.NewSharedIndexInformer(
		svcLW,
		&v1.Service{},
		controller.NoResyncPeriodFunc(),
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)

	n.serviceInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			n.serviceChanged(obj)
		},
		UpdateFunc: func(_ interface{}, obj interface{}) {
			n.serviceChanged(obj)
		},
		DeleteFunc: func(obj interface{}) {
			n.serviceDeleted(obj)
		},
	})

	go n.serviceInformer.Run(n.stopCh)
}

func (n *NSLoadBalancer) endpointsChanged(obj interface{}) {
	n.Lock()
	defer n.Unlock()

	endpoints, ok := obj.(*v1.Endpoints)
	if !ok {
		log.Errorf("endpointsChanged: bad obj")
		return
	}

	key, err := cache.MetaNamespaceKeyFunc(endpoints)
	if err != nil {
		log.Errorf("endpointsChanged: create key: %v", err)
		return
	}

	n.updateSvc(key)
}

func (n *NSLoadBalancer) serviceChanged(obj interface{}) {
	n.Lock()
	defer n.Unlock()

	svc, ok := obj.(*v1.Service)
	if !ok {
		log.Errorf("serviceChanged: bad obj")
		return
	}

	key, err := cache.MetaNamespaceKeyFunc(svc)
	if err != nil {
		log.Errorf("serviceChanged: create key: %v", err)
		return
	}

	n.updateSvc(key)
}

func (n *NSLoadBalancer) serviceDeleted(obj interface{}) {
}

func (n *NSLoadBalancer) updateSvc(key string) {
	endpointsobj, exists, err :=
		n.endpointsInformer.GetStore().GetByKey(key)
	if err != nil {
		log.Error("Could not lookup endpoints for " +
			key + ": " + err.Error())
		return
	}
	if !exists || endpointsobj == nil {
		return
	}
	svcobj, exists, err := n.serviceInformer.GetStore().GetByKey(key)
	if err != nil {
		log.Error("Could not lookup service for " +
			key + ": " + err.Error())
		return
	}
	if !exists || svcobj == nil {
		return
	}

	endpoints, ok := endpointsobj.(*v1.Endpoints)
	if !ok {
		log.Errorf("updateSvc: bad endpoints obj")
		return
	}
	svc, ok := svcobj.(*v1.Service)
	if !ok {
		log.Errorf("updateSvc: bad endpoints obj")
		return
	}

	nodeList := getNodes(endpoints)
	err = n.provider.UpdateService(svc, nodeList)
	if err != nil {
		// FIXME need retries
		log.Errorf("UpdateService: %v", err)
	}
}

func getNodes(e *v1.Endpoints) []string {
	var res []string
	for _, ss := range e.Subsets {
		for _, a := range ss.Addresses {
			res = append(res, getNodeIP(a.NodeName))
		}
	}

	return res
}

// FIXME: This assumes aws for now.
func getNodeIP(name *string) string {
	if name == nil {
		log.Errorf("nodename not present")
		return "parse-error"
	}
	parts := strings.Split(*name, ".")
	parts = strings.Split(parts[0], "-")

	if len(parts) < 5 {
		log.Errorf("nodename %s not parsable", *name)
		return "parse-error"
	}
	return fmt.Sprintf("%s.%s.%s.%s", parts[1], parts[2], parts[3], parts[4])
}
