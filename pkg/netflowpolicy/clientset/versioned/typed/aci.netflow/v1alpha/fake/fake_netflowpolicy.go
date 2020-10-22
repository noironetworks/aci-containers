/***
Copyright 2019 Cisco Systems Inc. All rights reserved.

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

// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	"context"

	v1alpha "github.com/noironetworks/aci-containers/pkg/netflowpolicy/apis/aci.netflow/v1alpha"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeNetflowPolicies implements NetflowPolicyInterface
type FakeNetflowPolicies struct {
	Fake *FakeAciV1alpha
}

var netflowpoliciesResource = schema.GroupVersionResource{Group: "aci.netflow", Version: "v1alpha", Resource: "netflowpolicies"}

var netflowpoliciesKind = schema.GroupVersionKind{Group: "aci.netflow", Version: "v1alpha", Kind: "NetflowPolicy"}

// Get takes name of the netflowPolicy, and returns the corresponding netflowPolicy object, and an error if there is any.
func (c *FakeNetflowPolicies) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha.NetflowPolicy, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootGetAction(netflowpoliciesResource, name), &v1alpha.NetflowPolicy{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha.NetflowPolicy), err
}

// List takes label and field selectors, and returns the list of NetflowPolicies that match those selectors.
func (c *FakeNetflowPolicies) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha.NetflowPolicyList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootListAction(netflowpoliciesResource, netflowpoliciesKind, opts), &v1alpha.NetflowPolicyList{})
	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1alpha.NetflowPolicyList{ListMeta: obj.(*v1alpha.NetflowPolicyList).ListMeta}
	for _, item := range obj.(*v1alpha.NetflowPolicyList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested netflowPolicies.
func (c *FakeNetflowPolicies) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewRootWatchAction(netflowpoliciesResource, opts))
}

// Create takes the representation of a netflowPolicy and creates it.  Returns the server's representation of the netflowPolicy, and an error, if there is any.
func (c *FakeNetflowPolicies) Create(ctx context.Context, netflowPolicy *v1alpha.NetflowPolicy, opts v1.CreateOptions) (result *v1alpha.NetflowPolicy, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootCreateAction(netflowpoliciesResource, netflowPolicy), &v1alpha.NetflowPolicy{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha.NetflowPolicy), err
}

// Update takes the representation of a netflowPolicy and updates it. Returns the server's representation of the netflowPolicy, and an error, if there is any.
func (c *FakeNetflowPolicies) Update(ctx context.Context, netflowPolicy *v1alpha.NetflowPolicy, opts v1.UpdateOptions) (result *v1alpha.NetflowPolicy, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateAction(netflowpoliciesResource, netflowPolicy), &v1alpha.NetflowPolicy{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha.NetflowPolicy), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakeNetflowPolicies) UpdateStatus(ctx context.Context, netflowPolicy *v1alpha.NetflowPolicy, opts v1.UpdateOptions) (*v1alpha.NetflowPolicy, error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateSubresourceAction(netflowpoliciesResource, "status", netflowPolicy), &v1alpha.NetflowPolicy{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha.NetflowPolicy), err
}

// Delete takes name of the netflowPolicy and deletes it. Returns an error if one occurs.
func (c *FakeNetflowPolicies) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewRootDeleteAction(netflowpoliciesResource, name), &v1alpha.NetflowPolicy{})
	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeNetflowPolicies) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	action := testing.NewRootDeleteCollectionAction(netflowpoliciesResource, listOpts)

	_, err := c.Fake.Invokes(action, &v1alpha.NetflowPolicyList{})
	return err
}

// Patch applies the patch and returns the patched netflowPolicy.
func (c *FakeNetflowPolicies) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha.NetflowPolicy, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootPatchSubresourceAction(netflowpoliciesResource, name, pt, data, subresources...), &v1alpha.NetflowPolicy{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha.NetflowPolicy), err
}