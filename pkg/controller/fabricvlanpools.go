package controller

import (
	"context"
	fabattv1 "github.com/noironetworks/aci-containers/pkg/fabricattachment/apis/aci.fabricattachment/v1"
	fabattclset "github.com/noironetworks/aci-containers/pkg/fabricattachment/clientset/versioned"
	"k8s.io/client-go/tools/cache"

	"github.com/noironetworks/aci-containers/pkg/apicapi"
	"github.com/noironetworks/aci-containers/pkg/util"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/kubernetes/pkg/controller"
	"strings"
)

const (
	fabricVlanPoolCRDName = "fabricvlanpools.aci.fabricattachment"
)

// APIs

func (cont *AciController) getGlobalFabricVlanPoolLocked() (combinedStr string) {
	for _, nsVlanPool := range cont.fabricVlanPoolMap {
		for _, vlanStr := range nsVlanPool {
			if len(vlanStr) == 0 {
				continue
			}
			if len(combinedStr) == 0 {
				combinedStr = vlanStr
				continue
			}
			combinedStr += "," + vlanStr
		}
	}
	return combinedStr
}

// End APIs

func (cont *AciController) queueFabricVlanPoolByKey(key string) {
	cont.fabricVlanPoolQueue.Add(key)
}

func (cont *AciController) fabricVlanPoolChanged(obj interface{}) {

	fabricVlanPool, ok := obj.(*fabattv1.FabricVlanPool)
	if !ok {
		cont.log.Error("fabricVlanPoolChanged: Bad object type")
		return
	}
	key, err := cache.MetaNamespaceKeyFunc(fabricVlanPool)
	if err != nil {
		return
	}
	cont.queueFabricVlanPoolByKey(key)
}

func (cont *AciController) fabricVlanPoolDeleted(obj interface{}) {

	fabricVlanPool, ok := obj.(*fabattv1.FabricVlanPool)
	if !ok {
		deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			cont.log.Errorf("Received unexpected object: ")
			return
		}
		fabricVlanPool, ok = deletedState.Obj.(*fabattv1.FabricVlanPool)
		if !ok {
			cont.log.Errorf("DeletedFinalStateUnknown contained non-fabricvlanpool object: %v", deletedState.Obj)
			return
		}
	}

	key, err := cache.MetaNamespaceKeyFunc(fabricVlanPool)
	if err != nil {
		return
	}
	cont.queueFabricVlanPoolByKey("DELETED_" + key)
}

func (cont *AciController) initFabricVlanPoolInformerBase(listWatch *cache.ListWatch) {
	cont.fabricVlanPoolInformer = cache.NewSharedIndexInformer(
		listWatch, &fabattv1.FabricVlanPool{}, controller.NoResyncPeriodFunc(),
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	cont.fabricVlanPoolInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			cont.fabricVlanPoolChanged(obj)
		},
		UpdateFunc: func(_ interface{}, newobj interface{}) {
			cont.fabricVlanPoolChanged(newobj)
		},
		DeleteFunc: func(obj interface{}) {
			cont.fabricVlanPoolDeleted(obj)
		},
	})
}

func (cont *AciController) initFabricVlanPoolInformerFromClient(fabAttClient *fabattclset.Clientset) {
	cont.initFabricVlanPoolInformerBase(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				return fabAttClient.AciV1().FabricVlanPools(metav1.NamespaceAll).List(context.TODO(), options)
			},

			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				return fabAttClient.AciV1().FabricVlanPools(metav1.NamespaceAll).Watch(context.TODO(), options)
			},
		})
}

func fabricVlanPoolInit(cont *AciController, stopCh <-chan struct{}) {
	cont.log.Debug("Initializing fabricVlanPool client")
	restconfig := cont.env.RESTConfig()
	fabNetAttClient, err := fabattclset.NewForConfig(restconfig)
	if err != nil {
		cont.log.Errorf("Failed to intialize fabricVlanPool client")
		return
	}
	cont.initFabricVlanPoolInformerFromClient(fabNetAttClient)
	go cont.fabricVlanPoolInformer.Run(stopCh)
	go cont.processQueue(cont.fabricVlanPoolQueue, cont.fabricVlanPoolInformer.GetIndexer(),
		func(obj interface{}) bool {
			return cont.handleFabricVlanPoolUpdate(obj)
		}, func(key string) bool {
			return cont.handleFabricVlanPoolDelete(key)
		}, nil, stopCh)
	cache.WaitForCacheSync(stopCh, cont.fabricVlanPoolInformer.HasSynced)
}

func (cont *AciController) handleFabricVlanPoolUpdate(obj interface{}) bool {
	fabricVlanPoolObj, ok := obj.(*fabattv1.FabricVlanPool)
	if !ok {
		cont.log.Error("handleFabricVlanPoolUpdate: Bad object type")
		return false
	}
	cont.log.Infof("fabricvlanpool update: %s/%s", fabricVlanPoolObj.Namespace, fabricVlanPoolObj.Name)

	cont.indexMutex.Lock()
	defer cont.indexMutex.Unlock()
	nsVlanPoolMap, ok := cont.fabricVlanPoolMap[fabricVlanPoolObj.Namespace]
	if !ok {
		nsVlanPoolMap = make(map[string]string)
	}
	_, _, vlanStr, err := util.ParseVlanList(fabricVlanPoolObj.Spec.Vlans)
	if err != nil {
		cont.log.Error(err)
	}
	cont.log.Debugf("vlans: %s", vlanStr)
	nsVlanPoolMap[fabricVlanPoolObj.Name] = vlanStr
	cont.fabricVlanPoolMap[fabricVlanPoolObj.Namespace] = nsVlanPoolMap
	encapStr := cont.getGlobalFabricVlanPoolLocked()
	progMap := make(map[string]apicapi.ApicSlice)
	cont.updateGlobalConfig(encapStr, progMap)
	for labelKey, apicSlice := range progMap {
		if apicSlice == nil {
			cont.apicConn.ClearApicObjects(labelKey)
			continue
		}
		cont.apicConn.WriteApicObjects(labelKey, apicSlice)
	}
	return false
}

func (cont *AciController) handleFabricVlanPoolDelete(key string) bool {
	cont.log.Infof("fabricvlanpool delete: %s", key)
	fabricVlanPoolElems := strings.Split("/", key)
	cont.indexMutex.Lock()
	defer cont.indexMutex.Unlock()
	nsVlanPoolMap, ok := cont.fabricVlanPoolMap[fabricVlanPoolElems[0]]
	if !ok {
		return false
	}
	delete(nsVlanPoolMap, fabricVlanPoolElems[1])
	cont.fabricVlanPoolMap[fabricVlanPoolElems[0]] = nsVlanPoolMap
	if len(nsVlanPoolMap) == 0 {
		delete(cont.fabricVlanPoolMap, fabricVlanPoolElems[0])
	}
	encapStr := cont.getGlobalFabricVlanPoolLocked()
	progMap := make(map[string]apicapi.ApicSlice)
	cont.updateGlobalConfig(encapStr, progMap)
	for labelKey, apicSlice := range progMap {
		if apicSlice == nil {
			cont.apicConn.ClearApicObjects(labelKey)
			continue
		}
		cont.apicConn.WriteApicObjects(labelKey, apicSlice)
	}
	return false
}
