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

	acipcv1 "github.com/noironetworks/aci-containers/pkg/proactiveconf/apis/aci.pc/v1"
	versioned "github.com/noironetworks/aci-containers/pkg/proactiveconf/clientset/versioned"
	internalinterfaces "github.com/noironetworks/aci-containers/pkg/proactiveconf/informers/externalversions/internalinterfaces"
	v1 "github.com/noironetworks/aci-containers/pkg/proactiveconf/listers/aci.pc/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	watch "k8s.io/apimachinery/pkg/watch"
	cache "k8s.io/client-go/tools/cache"
)

// ProactiveConfInformer provides access to a shared informer and lister for
// ProactiveConfs.
type ProactiveConfInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() v1.ProactiveConfLister
}

type proactiveConfInformer struct {
	factory          internalinterfaces.SharedInformerFactory
	tweakListOptions internalinterfaces.TweakListOptionsFunc
}

// NewProactiveConfInformer constructs a new informer for ProactiveConf type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewProactiveConfInformer(client versioned.Interface, resyncPeriod time.Duration, indexers cache.Indexers) cache.SharedIndexInformer {
	return NewFilteredProactiveConfInformer(client, resyncPeriod, indexers, nil)
}

// NewFilteredProactiveConfInformer constructs a new informer for ProactiveConf type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewFilteredProactiveConfInformer(client versioned.Interface, resyncPeriod time.Duration, indexers cache.Indexers, tweakListOptions internalinterfaces.TweakListOptionsFunc) cache.SharedIndexInformer {
	return cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.AciV1().ProactiveConfs().List(context.TODO(), options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.AciV1().ProactiveConfs().Watch(context.TODO(), options)
			},
		},
		&acipcv1.ProactiveConf{},
		resyncPeriod,
		indexers,
	)
}

func (f *proactiveConfInformer) defaultInformer(client versioned.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
	return NewFilteredProactiveConfInformer(client, resyncPeriod, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, f.tweakListOptions)
}

func (f *proactiveConfInformer) Informer() cache.SharedIndexInformer {
	return f.factory.InformerFor(&acipcv1.ProactiveConf{}, f.defaultInformer)
}

func (f *proactiveConfInformer) Lister() v1.ProactiveConfLister {
	return v1.NewProactiveConfLister(f.Informer().GetIndexer())
}
