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
	nodePodIf "github.com/noironetworks/aci-containers/pkg/nodepodif/apis/acipolicy/v1"
	nodePodIfclientset "github.com/noironetworks/aci-containers/pkg/nodepodif/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/tools/cache"
	"reflect"
	"strings"
)

const (
	nodePodIfCRDName = "nodepodifs.aci.aw"
)

func nodePodIfInit(cont *AciController, stopCh <-chan struct{}) {
	cont.log.Debug("Initializing nodePodIF client")
	restconfig := cont.env.RESTConfig()
	nodePodIfClient, err := nodePodIfclientset.NewForConfig(restconfig)
	if err != nil {
		cont.log.Errorf("Failed to intialize nodepodif client")
		return
	}
	cont.initNodePodIfInformerFromClient(nodePodIfClient)
	cont.nodePodIfInformer.Run(stopCh)
}

func (cont *AciController) initNodePodIfInformerFromClient(
	nodePodIfClient *nodePodIfclientset.Clientset) {
	cont.initNodePodIfInformerBase(
		cache.NewListWatchFromClient(
			nodePodIfClient.AciV1().RESTClient(), "nodepodifs",
			metav1.NamespaceAll, fields.Everything()))
}

func (cont *AciController) initNodePodIfInformerBase(listWatch *cache.ListWatch) {
	cont.nodePodIfIndexer, cont.nodePodIfInformer = cache.NewIndexerInformer(
		listWatch, &nodePodIf.NodePodIF{}, 0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				cont.nodePodIFAdded(obj)
			},
			UpdateFunc: func(oldobj interface{}, newobj interface{}) {
				cont.nodePodIFUpdated(oldobj, newobj)
			},
			DeleteFunc: func(obj interface{}) {
				cont.nodePodIFDeleted(obj)
			},
		},
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	cont.log.Debug("Initializing nodepodif Informers")
}

func getPodifKey(podif nodePodIf.PodIF) string {
	return podif.PodNS + "/" + podif.PodName
}

func getPodifEPG(podif nodePodIf.PodIF) string {
	deconcatenate := strings.Split(podif.EPG, "|")
	deconEPG := deconcatenate[len(deconcatenate)-1]
	return deconEPG
}

func getPodifAppProfile(podif nodePodIf.PodIF) string {
	deconcatenate := strings.Split(podif.EPG, "|")
	deconAppProfile := deconcatenate[0]
	return deconAppProfile
}

func (cont *AciController) nodePodIFAdded(obj interface{}) {
	np, ok := obj.(*nodePodIf.NodePodIF)
	if !ok {
		cont.log.Errorf("nodePodIFAdded: Bad object type")
		return
	}
	cont.log.Infof("nodepodif Added: %s", np.ObjectMeta.Name)
	podifs := np.Spec.PodIFs

	for _, podif := range podifs {
		cont.indexMutex.Lock()
		podifdata := &EndPointData{
			MacAddr:    podif.MacAddr,
			EPG:        getPodifEPG(podif),
			Namespace:  podif.PodNS,
			AppProfile: getPodifAppProfile(podif),
		}
		podifKey := getPodifKey(podif)
		cont.podIftoEp[podifKey] = podifdata
		cont.indexMutex.Unlock()
	}
}

func (cont *AciController) nodePodIFUpdated(oldobj interface{}, newobj interface{}) {
	oldnp := oldobj.(*nodePodIf.NodePodIF)
	newnp := newobj.(*nodePodIf.NodePodIF)
	cont.log.Infof("nodepodif updated: %s", oldnp.ObjectMeta.Name)
	if !reflect.DeepEqual(oldnp.Spec.PodIFs, newnp.Spec.PodIFs) {
		podifs := newnp.Spec.PodIFs
		for _, newpodif := range podifs {
			cont.indexMutex.Lock()
			podifdata := &EndPointData{
				MacAddr:    newpodif.MacAddr,
				EPG:        getPodifEPG(newpodif),
				Namespace:  newpodif.PodNS,
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
}

func (cont *AciController) nodePodIFDeleted(obj interface{}) {
	np, ok := obj.(*nodePodIf.NodePodIF)
	if !ok {
		cont.log.Errorf("nodePodIFDeleted: Bad object type")
		return
	}
	cont.log.Infof("nodepodif Deleted: %s", np.ObjectMeta.Name)
	podifs := np.Spec.PodIFs
	for _, podif := range podifs {
		cont.indexMutex.Lock()
		if _, ok := cont.podIftoEp[getPodifKey(podif)]; ok {
			delete(cont.podIftoEp, getPodifKey(podif))
		}
		cont.indexMutex.Unlock()
	}
}
