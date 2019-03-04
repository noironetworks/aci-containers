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
	"fmt"
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
	watchPodIFs(restClient, stopCh)
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

func watchPodIFs(rc restclient.Interface, stopCh <-chan struct{}) {

	podIFLw := cache.NewListWatchFromClient(rc, "podifs", sysNs, fields.Everything())
	_, podIFInformer := cache.NewInformer(podIFLw, &aciv1.PodIF{}, 0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				podIFAdded(obj)
			},
			UpdateFunc: func(oldobj interface{}, newobj interface{}) {
				podIFAdded(newobj)
			},
			DeleteFunc: func(obj interface{}) {
				podIFDeleted(obj)
			},
		})
	go podIFInformer.Run(stopCh)
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
	DoAll()
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
	DoAll()
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
	DoAll()
}

func contractDeleted(obj interface{}) {
}

func podIFAdded(obj interface{}) {
	gMutex.Lock()
	defer gMutex.Unlock()
	podif, ok := obj.(*aciv1.PodIF)
	if !ok {
		log.Errorf("podIFAdded: Bad object type")
		return
	}

	log.Infof("podIFAdded - %s/%s", podif.Status.PodNS, podif.Status.PodName)
	uid := fmt.Sprintf("%s.%s.%s", podif.Status.PodNS, podif.Status.PodName, podif.Status.ContainerID)
	ep := &Endpoint{
		Uuid:    uid,
		MacAddr: podif.Status.MacAddr,
		IPAddr:  podif.Status.IPAddr,
		EPG:     podif.Status.IPAddr,
		VTEP:    podif.Status.VTEP,
	}

	_, err := ep.Add()
	if err != nil {
		log.Errorf("podIFAdded: %v", err)
		return
	}

	DoAll()
}

func podIFDeleted(obj interface{}) {
	gMutex.Lock()
	defer gMutex.Unlock()
	podif, ok := obj.(*aciv1.PodIF)
	if !ok {
		log.Errorf("podIFDeleted: Bad object type")
		return
	}

	log.Infof("podIFDeleted - %s/%s", podif.Status.PodNS, podif.Status.PodName)
	uid := fmt.Sprintf("%s.%s.%s", podif.Status.PodNS, podif.Status.PodName, podif.Status.ContainerID)
	ep := &Endpoint{
		Uuid:    uid,
		MacAddr: podif.Status.MacAddr,
		IPAddr:  podif.Status.IPAddr,
		EPG:     podif.Status.IPAddr,
		VTEP:    podif.Status.VTEP,
	}

	err := ep.Delete()
	if err != nil {
		log.Errorf("podIFDeleted: %v", err)
	}

	DoAll()
}
