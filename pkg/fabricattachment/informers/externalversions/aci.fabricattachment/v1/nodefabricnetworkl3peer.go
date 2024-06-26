/***
Copyright 2021 Cisco Systems Inc. All rights reserved.

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

// Code generated by informer-gen. DO NOT EDIT.

package v1

import (
	"context"
	time "time"

	acifabricattachmentv1 "github.com/noironetworks/aci-containers/pkg/fabricattachment/apis/aci.fabricattachment/v1"
	versioned "github.com/noironetworks/aci-containers/pkg/fabricattachment/clientset/versioned"
	internalinterfaces "github.com/noironetworks/aci-containers/pkg/fabricattachment/informers/externalversions/internalinterfaces"
	v1 "github.com/noironetworks/aci-containers/pkg/fabricattachment/listers/aci.fabricattachment/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	watch "k8s.io/apimachinery/pkg/watch"
	cache "k8s.io/client-go/tools/cache"
)

// NodeFabricNetworkL3PeerInformer provides access to a shared informer and lister for
// NodeFabricNetworkL3Peers.
type NodeFabricNetworkL3PeerInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() v1.NodeFabricNetworkL3PeerLister
}

type nodeFabricNetworkL3PeerInformer struct {
	factory          internalinterfaces.SharedInformerFactory
	tweakListOptions internalinterfaces.TweakListOptionsFunc
}

// NewNodeFabricNetworkL3PeerInformer constructs a new informer for NodeFabricNetworkL3Peer type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewNodeFabricNetworkL3PeerInformer(client versioned.Interface, resyncPeriod time.Duration, indexers cache.Indexers) cache.SharedIndexInformer {
	return NewFilteredNodeFabricNetworkL3PeerInformer(client, resyncPeriod, indexers, nil)
}

// NewFilteredNodeFabricNetworkL3PeerInformer constructs a new informer for NodeFabricNetworkL3Peer type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewFilteredNodeFabricNetworkL3PeerInformer(client versioned.Interface, resyncPeriod time.Duration, indexers cache.Indexers, tweakListOptions internalinterfaces.TweakListOptionsFunc) cache.SharedIndexInformer {
	return cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.AciV1().NodeFabricNetworkL3Peers().List(context.TODO(), options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.AciV1().NodeFabricNetworkL3Peers().Watch(context.TODO(), options)
			},
		},
		&acifabricattachmentv1.NodeFabricNetworkL3Peer{},
		resyncPeriod,
		indexers,
	)
}

func (f *nodeFabricNetworkL3PeerInformer) defaultInformer(client versioned.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
	return NewFilteredNodeFabricNetworkL3PeerInformer(client, resyncPeriod, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, f.tweakListOptions)
}

func (f *nodeFabricNetworkL3PeerInformer) Informer() cache.SharedIndexInformer {
	return f.factory.InformerFor(&acifabricattachmentv1.NodeFabricNetworkL3Peer{}, f.defaultInformer)
}

func (f *nodeFabricNetworkL3PeerInformer) Lister() v1.NodeFabricNetworkL3PeerLister {
	return v1.NewNodeFabricNetworkL3PeerLister(f.Informer().GetIndexer())
}
