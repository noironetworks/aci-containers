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

// NetworkFabricL3ConfigurationInformer provides access to a shared informer and lister for
// NetworkFabricL3Configurations.
type NetworkFabricL3ConfigurationInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() v1.NetworkFabricL3ConfigurationLister
}

type networkFabricL3ConfigurationInformer struct {
	factory          internalinterfaces.SharedInformerFactory
	tweakListOptions internalinterfaces.TweakListOptionsFunc
}

// NewNetworkFabricL3ConfigurationInformer constructs a new informer for NetworkFabricL3Configuration type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewNetworkFabricL3ConfigurationInformer(client versioned.Interface, resyncPeriod time.Duration, indexers cache.Indexers) cache.SharedIndexInformer {
	return NewFilteredNetworkFabricL3ConfigurationInformer(client, resyncPeriod, indexers, nil)
}

// NewFilteredNetworkFabricL3ConfigurationInformer constructs a new informer for NetworkFabricL3Configuration type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewFilteredNetworkFabricL3ConfigurationInformer(client versioned.Interface, resyncPeriod time.Duration, indexers cache.Indexers, tweakListOptions internalinterfaces.TweakListOptionsFunc) cache.SharedIndexInformer {
	return cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.AciV1().NetworkFabricL3Configurations().List(context.TODO(), options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.AciV1().NetworkFabricL3Configurations().Watch(context.TODO(), options)
			},
		},
		&acifabricattachmentv1.NetworkFabricL3Configuration{},
		resyncPeriod,
		indexers,
	)
}

func (f *networkFabricL3ConfigurationInformer) defaultInformer(client versioned.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
	return NewFilteredNetworkFabricL3ConfigurationInformer(client, resyncPeriod, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, f.tweakListOptions)
}

func (f *networkFabricL3ConfigurationInformer) Informer() cache.SharedIndexInformer {
	return f.factory.InformerFor(&acifabricattachmentv1.NetworkFabricL3Configuration{}, f.defaultInformer)
}

func (f *networkFabricL3ConfigurationInformer) Lister() v1.NetworkFabricL3ConfigurationLister {
	return v1.NewNetworkFabricL3ConfigurationLister(f.Informer().GetIndexer())
}
