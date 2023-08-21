package controller

import (
	"context"
	fabattv1 "github.com/noironetworks/aci-containers/pkg/fabricattachment/apis/aci.fabricattachment/v1"
	fabattclset "github.com/noironetworks/aci-containers/pkg/fabricattachment/clientset/versioned"
	"k8s.io/client-go/tools/cache"

	"github.com/noironetworks/aci-containers/pkg/apicapi"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/kubernetes/pkg/controller"
)

const (
	nadVlanMapCRDName = "nadvlanmaps.aci.fabricattachment"
)

func (cont *AciController) queueNadVlanMapByKey(key string) {
	cont.nadVlanMapQueue.Add(key)
}

func (cont *AciController) nadVlanMapChanged(obj interface{}) {

	nadVlanMap, ok := obj.(*fabattv1.NadVlanMap)
	if !ok {
		cont.log.Error("nadVlanMapChanged: Bad object type")
		return
	}
	key, err := cache.MetaNamespaceKeyFunc(nadVlanMap)
	if err != nil {
		return
	}
	cont.queueNadVlanMapByKey(key)
}

func (cont *AciController) nadVlanMapDeleted(obj interface{}) {

	nadVlanMap, ok := obj.(*fabattv1.NadVlanMap)
	if !ok {
		deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			cont.log.Errorf("Received unexpected object: ")
			return
		}
		nadVlanMap, ok = deletedState.Obj.(*fabattv1.NadVlanMap)
		if !ok {
			cont.log.Errorf("DeletedFinalStateUnknown contained non-nadvlanmap object: %v", deletedState.Obj)
			return
		}
	}

	key, err := cache.MetaNamespaceKeyFunc(nadVlanMap)
	if err != nil {
		return
	}
	cont.queueNadVlanMapByKey("DELETED_" + key)
}

func (cont *AciController) initNadVlanMapInformerBase(listWatch *cache.ListWatch) {
	cont.nadVlanMapInformer = cache.NewSharedIndexInformer(
		listWatch, &fabattv1.NadVlanMap{}, controller.NoResyncPeriodFunc(),
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	cont.nadVlanMapInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			cont.nadVlanMapChanged(obj)
		},
		UpdateFunc: func(_ interface{}, newobj interface{}) {
			cont.nadVlanMapChanged(newobj)
		},
		DeleteFunc: func(obj interface{}) {
			cont.nadVlanMapDeleted(obj)
		},
	})
}

func (cont *AciController) initNadVlanMapInformerFromClient(fabAttClient *fabattclset.Clientset) {
	cont.initNadVlanMapInformerBase(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				return fabAttClient.AciV1().NadVlanMaps(metav1.NamespaceAll).List(context.TODO(), options)
			},

			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				return fabAttClient.AciV1().NadVlanMaps(metav1.NamespaceAll).Watch(context.TODO(), options)
			},
		})
}

func nadVlanMapInit(cont *AciController, stopCh <-chan struct{}) {
	cont.log.Debug("Initializing nadvlanmap client")
	restconfig := cont.env.RESTConfig()
	fabNetAttClient, err := fabattclset.NewForConfig(restconfig)
	if err != nil {
		cont.log.Errorf("Failed to intialize nadvlanmap client")
		return
	}
	cont.initNadVlanMapInformerFromClient(fabNetAttClient)
	go cont.nadVlanMapInformer.Run(stopCh)
	go cont.processQueue(cont.nadVlanMapQueue, cont.nadVlanMapInformer.GetIndexer(),
		func(obj interface{}) bool {
			return cont.handleNadVlanMapUpdate(obj)
		}, func(key string) bool {
			return cont.handleNadVlanMapDelete(key)
		}, nil, stopCh)
	cache.WaitForCacheSync(stopCh, cont.nadVlanMapInformer.HasSynced)
}

func (cont *AciController) handleNadVlanMapUpdate(obj interface{}) bool {
	nadVlanMapObj, ok := obj.(*fabattv1.NadVlanMap)
	if !ok {
		cont.log.Error("handleNadVlanMapUpdate: Bad object type")
		return false
	}
	cont.log.Info("nadvlanmap update: ")

	progMap := make(map[string]apicapi.ApicSlice)
	cont.indexMutex.Lock()
	cont.sharedEncapLabelMap = make(map[string][]int)
	for _, vlanMappingList := range nadVlanMapObj.Spec.NadVlanMapping {
		for _, vlanLabel := range vlanMappingList {
			vlans, _, err := cont.parseNodeFabNetAttVlanList(vlanLabel.Vlans)
			if err != nil {
				cont.log.Errorf("vlan list for %s incorrect: %s", vlanLabel.Label, vlanLabel.Vlans)
				continue
			}
			cont.sharedEncapLabelMap[vlanLabel.Label] = vlans
		}
	}
	cont.indexMutex.Unlock()
	affectedVlans := cont.updateSfnaCombinedCache()
	cont.updateNodeFabNetAttStaticAttachments(affectedVlans, progMap)
	for labelKey, apicSlice := range progMap {
		if apicSlice == nil {
			cont.apicConn.ClearApicObjects(labelKey)
			continue
		}
		cont.apicConn.WriteApicObjects(labelKey, apicSlice)
	}
	return false
}

func (cont *AciController) handleNadVlanMapDelete(key string) bool {
	cont.log.Info("nadvlanmap delete: ")
	progMap := make(map[string]apicapi.ApicSlice)
	cont.sharedEncapLabelMap = make(map[string][]int)
	affectedVlans := cont.updateSfnaCombinedCache()
	cont.updateNodeFabNetAttStaticAttachments(affectedVlans, progMap)
	for labelKey, apicSlice := range progMap {
		if apicSlice == nil {
			cont.apicConn.ClearApicObjects(labelKey)
			continue
		}
		cont.apicConn.WriteApicObjects(labelKey, apicSlice)
	}
	return false
}
