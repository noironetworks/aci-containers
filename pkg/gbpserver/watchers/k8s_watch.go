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

package watchers

import (
	"fmt"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/fields"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"strings"

	aciv1 "github.com/noironetworks/aci-containers/pkg/gbpcrd/apis/acipolicy/v1"
	aciawclientset "github.com/noironetworks/aci-containers/pkg/gbpcrd/clientset/versioned"
	"github.com/noironetworks/aci-containers/pkg/gbpserver"
)

const (
	sysNs = "kube-system"
)

type K8sWatcher struct {
	log *logrus.Entry
	gs  *gbpserver.Server
	idb *intentDB
	rc  restclient.Interface
}

func NewK8sWatcher(gs *gbpserver.Server) (*K8sWatcher, error) {
	level, err := logrus.ParseLevel(gs.Config().WatchLogLevel)
	if err != nil {
		panic(err.Error())
	}
	logger := logrus.New()
	logger.Level = level
	log := logger.WithField("mod", "K8S-W")
	cfg, err := restclient.InClusterConfig()
	if err != nil {
		return nil, err
	}

	aciawClient, err := aciawclientset.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	restClient := aciawClient.AciV1().RESTClient()
	return &K8sWatcher{
		log: log,
		rc:  restClient,
		gs:  gs,
		idb: newIntentDB(gs, log),
	}, nil
}

func (kw *K8sWatcher) InitEPInformer(stopCh <-chan struct{}) error {
	kw.watchPodIFs(stopCh)
	return nil
}

func (kw *K8sWatcher) InitIntentInformers(stopCh <-chan struct{}) error {
	kw.watchEpgs(stopCh)
	kw.watchContracts(stopCh)
	return nil
}

func (kw *K8sWatcher) watchEpgs(stopCh <-chan struct{}) {

	epgLw := cache.NewListWatchFromClient(kw.rc, "epgs", sysNs, fields.Everything())
	_, epgInformer := cache.NewInformer(epgLw, &aciv1.Epg{}, 0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				kw.epgAdded(obj)
			},
			UpdateFunc: func(oldobj interface{}, newobj interface{}) {
				kw.epgAdded(newobj)
			},
			DeleteFunc: func(obj interface{}) {
				kw.epgDeleted(obj)
			},
		})
	go epgInformer.Run(stopCh)
}

func (kw *K8sWatcher) watchContracts(stopCh <-chan struct{}) {

	contractLw := cache.NewListWatchFromClient(kw.rc, "contracts", sysNs, fields.Everything())
	_, contractInformer := cache.NewInformer(contractLw, &aciv1.Contract{}, 0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				kw.contractAdded(obj)
			},
			UpdateFunc: func(oldobj interface{}, newobj interface{}) {
				kw.contractAdded(newobj)
			},
			DeleteFunc: func(obj interface{}) {
				kw.contractDeleted(obj)
			},
		})
	go contractInformer.Run(stopCh)
}

func (kw *K8sWatcher) watchPodIFs(stopCh <-chan struct{}) {

	podIFLw := cache.NewListWatchFromClient(kw.rc, "podifs", sysNs, fields.Everything())
	_, podIFInformer := cache.NewInformer(podIFLw, &aciv1.PodIF{}, 0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				kw.podIFAdded(obj)
			},
			UpdateFunc: func(oldobj interface{}, newobj interface{}) {
				kw.podIFAdded(newobj)
			},
			DeleteFunc: func(obj interface{}) {
				kw.podIFDeleted(obj)
			},
		})
	go podIFInformer.Run(stopCh)
}

func (kw *K8sWatcher) epgAdded(obj interface{}) {
	epgv1, ok := obj.(*aciv1.Epg)
	if !ok {
		kw.log.Errorf("epgAdded: Bad object type")
		return
	}

	kw.log.Infof("epgAdded - %s", epgv1.Spec.Name)
	e := &gbpserver.EPG{
		Tenant:        kw.gs.Config().AciPolicyTenant,
		Name:          epgv1.Spec.Name,
		ConsContracts: epgv1.Spec.ConsContracts,
		ProvContracts: epgv1.Spec.ProvContracts,
	}

	// normalize contract names to include tenant
	normalizer := func(names []string) {
		for ix, n := range names {
			if len(strings.Split(n, "/")) == 1 {
				names[ix] = fmt.Sprintf("%s/%s", e.Tenant, n)
			}
		}
	}

	normalizer(e.ConsContracts)
	normalizer(e.ProvContracts)
	kw.idb.saveEPG(e)
}

func (kw *K8sWatcher) epgDeleted(obj interface{}) {
	epgv1, ok := obj.(*aciv1.Epg)
	if !ok {
		kw.log.Errorf("epgAdded: Bad object type")
		return
	}

	kw.log.Infof("epgDeleted - %s", epgv1.Spec.Name)
	e := &gbpserver.EPG{
		Tenant: kw.gs.Config().AciPolicyTenant,
		Name:   epgv1.Spec.Name,
	}

	kw.idb.deleteEPG(e)
}

func (kw *K8sWatcher) contractAdded(obj interface{}) {
	contractv1, ok := obj.(*aciv1.Contract)
	if !ok {
		kw.log.Errorf("contractAdded: Bad object type")
		return
	}

	kw.log.Infof("contractAdded - %s", contractv1.Spec.Name)
	c := &gbpserver.Contract{
		Tenant:    kw.gs.Config().AciPolicyTenant,
		Name:      contractv1.Spec.Name,
		AllowList: contractv1.Spec.AllowList,
	}

	kw.idb.saveGbpContract(c)
}

func (kw *K8sWatcher) contractDeleted(obj interface{}) {
	contractv1, ok := obj.(*aciv1.Contract)
	if !ok {
		kw.log.Errorf("contractDeleted: Bad object type")
		return
	}
	kw.log.Infof("contractDeleted - %s", contractv1.Spec.Name)
	c := &gbpserver.Contract{
		Tenant:    kw.gs.Config().AciPolicyTenant,
		Name:      contractv1.Spec.Name,
		AllowList: contractv1.Spec.AllowList,
	}

	kw.idb.deleteGbpContract(c)
}

func (kw *K8sWatcher) podIFAdded(obj interface{}) {
	podif, ok := obj.(*aciv1.PodIF)
	if !ok {
		kw.log.Errorf("podIFAdded: Bad object type")
		return
	}

	kw.log.Infof("podIFAdded - %s", podif.ObjectMeta.Name)
	ep := gbpserver.Endpoint{
		Uuid:      getEPUuid(podif),
		MacAddr:   podif.Status.MacAddr,
		IPAddr:    []string{podif.Status.IPAddr},
		EPG:       podif.Status.EPG,
		VTEP:      podif.Status.VTEP,
		IFName:    podif.Status.IFName,
		Namespace: podif.Status.PodNS,
		PodName:   podif.Status.PodName,
	}

	kw.gs.AddEP(ep)
}

func (kw *K8sWatcher) podIFDeleted(obj interface{}) {
	podif, ok := obj.(*aciv1.PodIF)
	if !ok {
		kw.log.Errorf("podIFDeleted: Bad object type")
		return
	}

	kw.log.Infof("podIFDeleted - %s", podif.ObjectMeta.Name)
	ep := gbpserver.Endpoint{
		Uuid:      getEPUuid(podif),
		MacAddr:   podif.Status.MacAddr,
		IPAddr:    []string{podif.Status.IPAddr},
		EPG:       podif.Status.EPG,
		VTEP:      podif.Status.VTEP,
		IFName:    podif.Status.IFName,
		Namespace: podif.Status.PodNS,
		PodName:   podif.Status.PodName,
	}

	kw.gs.DelEP(ep)
}

func getEPUuid(podif *aciv1.PodIF) string {
	if podif.Status.ContainerID == "" {
		return fmt.Sprintf("%s.%s", podif.ObjectMeta.Name, gbpserver.NoContainer)
	} else {
		return fmt.Sprintf("%s.%s.%s", podif.Status.PodNS, podif.Status.PodName, podif.Status.ContainerID)
	}
}
