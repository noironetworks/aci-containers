// Copyright 2021 Cisco Systems, Inc.
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
	podIfpolicy "github.com/noironetworks/aci-containers/pkg/gbpcrd/apis/acipolicy/v1"
	podIfclientset "github.com/noironetworks/aci-containers/pkg/gbpcrd/clientset/versioned"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/tools/cache"
	"reflect"
	"strings"
)

const (
	podIfCRDName = "podifs.aci.aw"
)

func PodIfPolicyLogger(log *logrus.Logger, podIf *podIfpolicy.PodIF) *logrus.Entry {
	return log.WithFields(logrus.Fields{
		"namespace": podIf.ObjectMeta.Namespace,
		"name":      podIf.ObjectMeta.Name,
	})
}

func podIfInit(cont *AciController, stopCh <-chan struct{}) {
	cont.log.Debug("Initializing podIf client")
	restconfig := cont.env.RESTConfig()
	podIfClient, err := podIfclientset.NewForConfig(restconfig)
	if err != nil {
		cont.log.Errorf("Failed to intialize podif client")
		return
	}
	cont.initPodIfInformerFromClient(podIfClient)
	cont.podIfInformer.Run(stopCh)
}

func (cont *AciController) initPodIfInformerFromClient(
	podIfClient *podIfclientset.Clientset) {
	cont.initPodIfInformerBase(
		cache.NewListWatchFromClient(
			podIfClient.AciV1().RESTClient(), "podifs",
			metav1.NamespaceAll, fields.Everything()))
}

func (cont *AciController) initPodIfInformerBase(listWatch *cache.ListWatch) {
	cont.podIfIndexer, cont.podIfInformer = cache.NewIndexerInformer(
		listWatch, &podIfpolicy.PodIF{}, 0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				cont.podIFAdded(obj)
			},
			UpdateFunc: func(oldobj interface{}, newobj interface{}) {
				cont.podIFUpdated(oldobj, newobj)
			},
			DeleteFunc: func(obj interface{}) {
				cont.podIFDeleted(obj)
			},
		},
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	cont.log.Debug("Initializing podif Informers")
}

func getPodifKey(podif *podIfpolicy.PodIF) string {
	return podif.Status.PodNS + "/" + podif.Status.PodName
}

func getPodifEPG(podif *podIfpolicy.PodIF) string {
	deconcatenate := strings.Split(podif.Status.EPG, "|")
	deconEPG := deconcatenate[len(deconcatenate)-1]
	return deconEPG
}

func getPodifAppProfile(podif *podIfpolicy.PodIF) string {
	deconcatenate := strings.Split(podif.Status.EPG, "|")
	deconAppProfile := deconcatenate[0]
	return deconAppProfile
}

func (cont *AciController) podIFAdded(obj interface{}) {
	podif := obj.(*podIfpolicy.PodIF)
	cont.log.Infof("podif Added: %s", podif.ObjectMeta.Name)
	cont.indexMutex.Lock()
	podifdata := &EndPointData{
		MacAddr:    podif.Status.MacAddr,
		EPG:        getPodifEPG(podif),
		Namespace:  podif.Status.PodNS,
		AppProfile: getPodifAppProfile(podif),
	}
	podifKey := getPodifKey(podif)
	cont.podIftoEp[podifKey] = podifdata
	cont.indexMutex.Unlock()
}

func (cont *AciController) podIFUpdated(oldobj interface{}, newobj interface{}) {
	oldpodif := oldobj.(*podIfpolicy.PodIF)
	newpodif := newobj.(*podIfpolicy.PodIF)
	cont.log.Infof("podif updated: %s", oldpodif.ObjectMeta.Name)
	if !reflect.DeepEqual(oldpodif.Status, newpodif.Status) {
		cont.indexMutex.Lock()
		podifdata := &EndPointData{
			MacAddr:    newpodif.Status.MacAddr,
			EPG:        getPodifEPG(newpodif),
			AppProfile: getPodifAppProfile(newpodif),
		}
		podifKey := getPodifKey(newpodif)
		cont.podIftoEp[podifKey] = podifdata
		cont.indexMutex.Unlock()
		spankeys := cont.erspanPolPods.GetObjForPod(podifKey)
		// PodIF reconciliation with ERSPAN source CEPs
		for _, spankey := range spankeys {
			cont.queueErspanUpdateByKey(spankey)
		}
	}
}

func (cont *AciController) podIFDeleted(obj interface{}) {
	podif := obj.(*podIfpolicy.PodIF)
	cont.log.Infof("podif Deleted: %s", podif.ObjectMeta.Name)
	cont.indexMutex.Lock()
	delete(cont.podIftoEp, getPodifKey(podif))
	cont.indexMutex.Unlock()
}
