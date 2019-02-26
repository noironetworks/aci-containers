/***
Copyright 2019 Cisco Systems Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package apiserver

import (
	log "github.com/Sirupsen/logrus"
	"k8s.io/apimachinery/pkg/fields"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"

	aciv1 "github.com/noironetworks/aci-containers/pkg/gbpcrd/apis/aci.aw/v1"
	aciawclientset "github.com/noironetworks/aci-containers/pkg/gbpcrd/clientset/versioned"
)

const (
	sysNs = "kube-system"
)

func InitCRDInformers(stopCh <-chan struct{}) error {
	// creates the in-cluster config
	cfg, err := restclient.InClusterConfig()
	if err != nil {
		return err
	}

	aciawClient, err := aciawclientset.NewForConfig(cfg)
	if err != nil {
		return err
	}

	restClient := aciawClient.AciV1().RESTClient()
	watchEpgs(restClient, stopCh)
	watchContracts(restClient, stopCh)
	return nil
}

func watchEpgs(rc restclient.Interface, stopCh <-chan struct{}) {

	epgLw := cache.NewListWatchFromClient(rc, "epgs", sysNs, fields.Everything())
	_, epgInformer := cache.NewInformer(epgLw, &aciv1.Epg{}, 0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				epgAdded(obj)
			},
			UpdateFunc: func(oldobj interface{}, newobj interface{}) {
				epgAdded(newobj)
			},
			DeleteFunc: func(obj interface{}) {
				epgDeleted(obj)
			},
		})
	go epgInformer.Run(stopCh)
}

func watchContracts(rc restclient.Interface, stopCh <-chan struct{}) {

	contractLw := cache.NewListWatchFromClient(rc, "contracts", sysNs, fields.Everything())
	_, contractInformer := cache.NewInformer(contractLw, &aciv1.Contract{}, 0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				contractAdded(obj)
			},
			UpdateFunc: func(oldobj interface{}, newobj interface{}) {
				contractAdded(newobj)
			},
			DeleteFunc: func(obj interface{}) {
				contractDeleted(obj)
			},
		})
	go contractInformer.Run(stopCh)
}

func epgAdded(obj interface{}) {
	gMutex.Lock()
	defer gMutex.Unlock()
	epgv1, ok := obj.(*aciv1.Epg)
	if !ok {
		log.Errorf("epgAdded: Bad object type")
		return
	}

	log.Infof("epgAdded - %s", epgv1.Spec.Name)
	e := &EPG{
		Tenant:        kubeTenant,
		Name:          epgv1.Spec.Name,
		ConsContracts: epgv1.Spec.ConsContracts,
		ProvContracts: epgv1.Spec.ProvContracts,
	}

	err := e.Make()
	if err != nil {
		log.Errorf("epgAdded: %v", err)
	}
}

func epgDeleted(obj interface{}) {
	gMutex.Lock()
	defer gMutex.Unlock()
	epgv1, ok := obj.(*aciv1.Epg)
	if !ok {
		log.Errorf("epgAdded: Bad object type")
		return
	}

	log.Infof("epgDeleted - %s", epgv1.Spec.Name)
	e := &EPG{
		Tenant: kubeTenant,
		Name:   epgv1.Spec.Name,
	}

	key := e.getURI()
	delete(MoDB, key)
}

func contractAdded(obj interface{}) {
	gMutex.Lock()
	defer gMutex.Unlock()
	contractv1, ok := obj.(*aciv1.Contract)
	if !ok {
		log.Errorf("contractAdded: Bad object type")
		return
	}

	log.Infof("contractAdded - %s", contractv1.Spec.Name)
	c := &Contract{
		Tenant:    kubeTenant,
		Name:      contractv1.Spec.Name,
		AllowList: contractv1.Spec.AllowList,
	}

	err := c.Make()
	if err != nil {
		log.Errorf("contractAdded: %v", err)
	}
}

func contractDeleted(obj interface{}) {
}
