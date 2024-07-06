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
	}, nil
}

func (kw *K8sWatcher) InitEPInformer(stopCh <-chan struct{}) error {
	kw.watchPodIFs(stopCh)
	return nil
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
	}
	return fmt.Sprintf("%s.%s.%s", podif.Status.PodNS, podif.Status.PodName, podif.Status.ContainerID)
}
