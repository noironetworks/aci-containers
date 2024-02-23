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

// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	"context"
	json "encoding/json"
	"fmt"

	v1 "github.com/noironetworks/aci-containers/pkg/fabricattachment/apis/aci.fabricattachment/v1"
	acifabricattachmentv1 "github.com/noironetworks/aci-containers/pkg/fabricattachment/applyconfiguration/aci.fabricattachment/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeFabricVlanPools implements FabricVlanPoolInterface
type FakeFabricVlanPools struct {
	Fake *FakeAciV1
	ns   string
}

var fabricvlanpoolsResource = v1.SchemeGroupVersion.WithResource("fabricvlanpools")

var fabricvlanpoolsKind = v1.SchemeGroupVersion.WithKind("FabricVlanPool")

// Get takes name of the fabricVlanPool, and returns the corresponding fabricVlanPool object, and an error if there is any.
func (c *FakeFabricVlanPools) Get(ctx context.Context, name string, options metav1.GetOptions) (result *v1.FabricVlanPool, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewGetAction(fabricvlanpoolsResource, c.ns, name), &v1.FabricVlanPool{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1.FabricVlanPool), err
}

// List takes label and field selectors, and returns the list of FabricVlanPools that match those selectors.
func (c *FakeFabricVlanPools) List(ctx context.Context, opts metav1.ListOptions) (result *v1.FabricVlanPoolList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewListAction(fabricvlanpoolsResource, fabricvlanpoolsKind, c.ns, opts), &v1.FabricVlanPoolList{})

	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1.FabricVlanPoolList{ListMeta: obj.(*v1.FabricVlanPoolList).ListMeta}
	for _, item := range obj.(*v1.FabricVlanPoolList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested fabricVlanPools.
func (c *FakeFabricVlanPools) Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewWatchAction(fabricvlanpoolsResource, c.ns, opts))

}

// Create takes the representation of a fabricVlanPool and creates it.  Returns the server's representation of the fabricVlanPool, and an error, if there is any.
func (c *FakeFabricVlanPools) Create(ctx context.Context, fabricVlanPool *v1.FabricVlanPool, opts metav1.CreateOptions) (result *v1.FabricVlanPool, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewCreateAction(fabricvlanpoolsResource, c.ns, fabricVlanPool), &v1.FabricVlanPool{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1.FabricVlanPool), err
}

// Update takes the representation of a fabricVlanPool and updates it. Returns the server's representation of the fabricVlanPool, and an error, if there is any.
func (c *FakeFabricVlanPools) Update(ctx context.Context, fabricVlanPool *v1.FabricVlanPool, opts metav1.UpdateOptions) (result *v1.FabricVlanPool, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateAction(fabricvlanpoolsResource, c.ns, fabricVlanPool), &v1.FabricVlanPool{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1.FabricVlanPool), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakeFabricVlanPools) UpdateStatus(ctx context.Context, fabricVlanPool *v1.FabricVlanPool, opts metav1.UpdateOptions) (*v1.FabricVlanPool, error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateSubresourceAction(fabricvlanpoolsResource, "status", c.ns, fabricVlanPool), &v1.FabricVlanPool{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1.FabricVlanPool), err
}

// Delete takes name of the fabricVlanPool and deletes it. Returns an error if one occurs.
func (c *FakeFabricVlanPools) Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewDeleteActionWithOptions(fabricvlanpoolsResource, c.ns, name, opts), &v1.FabricVlanPool{})

	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeFabricVlanPools) DeleteCollection(ctx context.Context, opts metav1.DeleteOptions, listOpts metav1.ListOptions) error {
	action := testing.NewDeleteCollectionAction(fabricvlanpoolsResource, c.ns, listOpts)

	_, err := c.Fake.Invokes(action, &v1.FabricVlanPoolList{})
	return err
}

// Patch applies the patch and returns the patched fabricVlanPool.
func (c *FakeFabricVlanPools) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions, subresources ...string) (result *v1.FabricVlanPool, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(fabricvlanpoolsResource, c.ns, name, pt, data, subresources...), &v1.FabricVlanPool{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1.FabricVlanPool), err
}

// Apply takes the given apply declarative configuration, applies it and returns the applied fabricVlanPool.
func (c *FakeFabricVlanPools) Apply(ctx context.Context, fabricVlanPool *acifabricattachmentv1.FabricVlanPoolApplyConfiguration, opts metav1.ApplyOptions) (result *v1.FabricVlanPool, err error) {
	if fabricVlanPool == nil {
		return nil, fmt.Errorf("fabricVlanPool provided to Apply must not be nil")
	}
	data, err := json.Marshal(fabricVlanPool)
	if err != nil {
		return nil, err
	}
	name := fabricVlanPool.Name
	if name == nil {
		return nil, fmt.Errorf("fabricVlanPool.Name must be provided to Apply")
	}
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(fabricvlanpoolsResource, c.ns, *name, types.ApplyPatchType, data), &v1.FabricVlanPool{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1.FabricVlanPool), err
}

// ApplyStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating ApplyStatus().
func (c *FakeFabricVlanPools) ApplyStatus(ctx context.Context, fabricVlanPool *acifabricattachmentv1.FabricVlanPoolApplyConfiguration, opts metav1.ApplyOptions) (result *v1.FabricVlanPool, err error) {
	if fabricVlanPool == nil {
		return nil, fmt.Errorf("fabricVlanPool provided to Apply must not be nil")
	}
	data, err := json.Marshal(fabricVlanPool)
	if err != nil {
		return nil, err
	}
	name := fabricVlanPool.Name
	if name == nil {
		return nil, fmt.Errorf("fabricVlanPool.Name must be provided to Apply")
	}
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(fabricvlanpoolsResource, c.ns, *name, types.ApplyPatchType, data, "status"), &v1.FabricVlanPool{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1.FabricVlanPool), err
}