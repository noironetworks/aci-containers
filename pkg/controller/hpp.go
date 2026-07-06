package controller

import (
	"context"

	hppv1 "github.com/noironetworks/aci-containers/pkg/hpp/apis/aci.hpp/v1"
	hppclset "github.com/noironetworks/aci-containers/pkg/hpp/clientset/versioned"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
)

func (cont *AciController) initHppInformerFromClient(
	hppClient hppclset.Interface) {
	lw := &cache.ListWatch{
		ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
			return hppClient.AciV1().HostprotPols(metav1.NamespaceAll).List(context.TODO(), options)
		},
		WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
			return hppClient.AciV1().HostprotPols(metav1.NamespaceAll).Watch(context.TODO(), options)
		},
	}
	cont.initHppInformerBase(cache.ToListWatcherWithWatchListSemantics(lw, hppClient))
}

func (cont *AciController) initHppRemoteIpInformerFromClient(
	hppClient hppclset.Interface) {
	lw := &cache.ListWatch{
		ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
			return hppClient.AciV1().HostprotRemoteIpContainers(metav1.NamespaceAll).List(context.TODO(), options)
		},
		WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
			return hppClient.AciV1().HostprotRemoteIpContainers(metav1.NamespaceAll).Watch(context.TODO(), options)
		},
	}
	cont.initHppRemoteIpInformerBase(cache.ToListWatcherWithWatchListSemantics(lw, hppClient))
}

func (cont *AciController) initHppInformerBase(listWatch cache.ListerWatcher) {
	cont.hppInformer = cache.NewSharedIndexInformer(
		listWatch, &hppv1.HostprotPol{}, 0,
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	cont.hppInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			cont.hppChanged(obj)
		},
		UpdateFunc: func(_, obj interface{}) {
			cont.hppChanged(obj)
		},
		DeleteFunc: func(obj interface{}) {
			cont.hppDeleted(obj)
		},
	})
}

func (cont *AciController) initHppRemoteIpInformerBase(listWatch cache.ListerWatcher) {
	cont.hppRemoteIpInformer = cache.NewSharedIndexInformer(
		listWatch, &hppv1.HostprotRemoteIpContainer{}, 0,
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	cont.hppRemoteIpInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			cont.hppRemoteIpChanged(obj)
		},
		UpdateFunc: func(_, newObj interface{}) {
			cont.hppRemoteIpChanged(newObj)
		},
		DeleteFunc: func(obj interface{}) {
			cont.hppRemoteIpDeleted(obj)
		},
	})
}

func (cont *AciController) hppChanged(obj interface{}) {
	cont.queueRemoteIpConUpdateByKey(obj.(metav1.Object).GetName())
}

func (cont *AciController) hppDeleted(obj interface{}) {
	// hpp, ok := obj.(*hppv1.HostprotPol)
	// if !ok {
	// 	deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
	// 	if !ok {
	// 		cont.log.Error("hppDeleted: received unexpected object: ", obj)
	// 		return
	// 	}
	// 	hpp, ok = deletedState.Obj.(*hppv1.HostprotPol)
	// 	if !ok {
	// 		cont.log.Error("hppDeleted: DeletedFinalStateUnknown contained non-HostprotPol object")
	// 		return
	// 	}
	// }
	if tombstone, ok := obj.(cache.DeletedFinalStateUnknown); ok {
		obj = tombstone.Obj
	}
	cont.queueRemoteIpConUpdateByKey(obj.(metav1.Object).GetName())
}

func (cont *AciController) hppRemoteIpChanged(newObj interface{}) {
	cont.remIpContQueue.Add(newObj.(metav1.Object).GetName())
}

func (cont *AciController) hppRemoteIpDeleted(obj interface{}) {
	if tombstone, ok := obj.(cache.DeletedFinalStateUnknown); ok {
		obj = tombstone.Obj
	}
	cont.remIpContQueue.Add(obj.(metav1.Object).GetName())
}
