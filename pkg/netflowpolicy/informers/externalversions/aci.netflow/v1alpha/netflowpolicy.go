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

package v1alpha

import (
	"context"
	time "time"

	acinetflowv1alpha "github.com/noironetworks/aci-containers/pkg/netflowpolicy/apis/aci.netflow/v1alpha"
	versioned "github.com/noironetworks/aci-containers/pkg/netflowpolicy/clientset/versioned"
	internalinterfaces "github.com/noironetworks/aci-containers/pkg/netflowpolicy/informers/externalversions/internalinterfaces"
	v1alpha "github.com/noironetworks/aci-containers/pkg/netflowpolicy/listers/aci.netflow/v1alpha"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	watch "k8s.io/apimachinery/pkg/watch"
	cache "k8s.io/client-go/tools/cache"
)

// NetflowPolicyInformer provides access to a shared informer and lister for
// NetflowPolicies.
type NetflowPolicyInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() v1alpha.NetflowPolicyLister
}

type netflowPolicyInformer struct {
	factory          internalinterfaces.SharedInformerFactory
	tweakListOptions internalinterfaces.TweakListOptionsFunc
}

// NewNetflowPolicyInformer constructs a new informer for NetflowPolicy type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewNetflowPolicyInformer(client versioned.Interface, resyncPeriod time.Duration, indexers cache.Indexers) cache.SharedIndexInformer {
	return NewFilteredNetflowPolicyInformer(client, resyncPeriod, indexers, nil)
}

// NewFilteredNetflowPolicyInformer constructs a new informer for NetflowPolicy type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewFilteredNetflowPolicyInformer(client versioned.Interface, resyncPeriod time.Duration, indexers cache.Indexers, tweakListOptions internalinterfaces.TweakListOptionsFunc) cache.SharedIndexInformer {
	return cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options v1.ListOptions) (runtime.Object, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.AciV1alpha().NetflowPolicies().List(context.TODO(), options)
			},
			WatchFunc: func(options v1.ListOptions) (watch.Interface, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.AciV1alpha().NetflowPolicies().Watch(context.TODO(), options)
			},
		},
		&acinetflowv1alpha.NetflowPolicy{},
		resyncPeriod,
		indexers,
	)
}

func (f *netflowPolicyInformer) defaultInformer(client versioned.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
	return NewFilteredNetflowPolicyInformer(client, resyncPeriod, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, f.tweakListOptions)
}

func (f *netflowPolicyInformer) Informer() cache.SharedIndexInformer {
	return f.factory.InformerFor(&acinetflowv1alpha.NetflowPolicy{}, f.defaultInformer)
}

func (f *netflowPolicyInformer) Lister() v1alpha.NetflowPolicyLister {
	return v1alpha.NewNetflowPolicyLister(f.Informer().GetIndexer())
}
