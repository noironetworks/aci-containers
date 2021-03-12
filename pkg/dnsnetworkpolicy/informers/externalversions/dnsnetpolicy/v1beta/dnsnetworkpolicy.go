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

package v1beta

import (
	"context"
	time "time"

	dnsnetpolicyv1beta "github.com/noironetworks/aci-containers/pkg/dnsnetworkpolicy/apis/dnsnetpolicy/v1beta"
	versioned "github.com/noironetworks/aci-containers/pkg/dnsnetworkpolicy/clientset/versioned"
	internalinterfaces "github.com/noironetworks/aci-containers/pkg/dnsnetworkpolicy/informers/externalversions/internalinterfaces"
	v1beta "github.com/noironetworks/aci-containers/pkg/dnsnetworkpolicy/listers/dnsnetpolicy/v1beta"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	watch "k8s.io/apimachinery/pkg/watch"
	cache "k8s.io/client-go/tools/cache"
)

// DnsNetworkPolicyInformer provides access to a shared informer and lister for
// DnsNetworkPolicies.
type DnsNetworkPolicyInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() v1beta.DnsNetworkPolicyLister
}

type dnsNetworkPolicyInformer struct {
	factory          internalinterfaces.SharedInformerFactory
	tweakListOptions internalinterfaces.TweakListOptionsFunc
	namespace        string
}

// NewDnsNetworkPolicyInformer constructs a new informer for DnsNetworkPolicy type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewDnsNetworkPolicyInformer(client versioned.Interface, namespace string, resyncPeriod time.Duration, indexers cache.Indexers) cache.SharedIndexInformer {
	return NewFilteredDnsNetworkPolicyInformer(client, namespace, resyncPeriod, indexers, nil)
}

// NewFilteredDnsNetworkPolicyInformer constructs a new informer for DnsNetworkPolicy type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewFilteredDnsNetworkPolicyInformer(client versioned.Interface, namespace string, resyncPeriod time.Duration, indexers cache.Indexers, tweakListOptions internalinterfaces.TweakListOptionsFunc) cache.SharedIndexInformer {
	return cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options v1.ListOptions) (runtime.Object, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.AciV1beta().DnsNetworkPolicies(namespace).List(context.TODO(), options)
			},
			WatchFunc: func(options v1.ListOptions) (watch.Interface, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.AciV1beta().DnsNetworkPolicies(namespace).Watch(context.TODO(), options)
			},
		},
		&dnsnetpolicyv1beta.DnsNetworkPolicy{},
		resyncPeriod,
		indexers,
	)
}

func (f *dnsNetworkPolicyInformer) defaultInformer(client versioned.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
	return NewFilteredDnsNetworkPolicyInformer(client, f.namespace, resyncPeriod, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, f.tweakListOptions)
}

func (f *dnsNetworkPolicyInformer) Informer() cache.SharedIndexInformer {
	return f.factory.InformerFor(&dnsnetpolicyv1beta.DnsNetworkPolicy{}, f.defaultInformer)
}

func (f *dnsNetworkPolicyInformer) Lister() v1beta.DnsNetworkPolicyLister {
	return v1beta.NewDnsNetworkPolicyLister(f.Informer().GetIndexer())
}