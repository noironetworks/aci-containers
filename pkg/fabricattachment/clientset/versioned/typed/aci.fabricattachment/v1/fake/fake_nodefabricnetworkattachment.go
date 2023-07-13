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

	acifabricattachmentv1 "github.com/noironetworks/aci-containers/pkg/fabricattachment/apis/aci.fabricattachment/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeNodeFabricNetworkAttachments implements NodeFabricNetworkAttachmentInterface
type FakeNodeFabricNetworkAttachments struct {
	Fake *FakeAciV1
	ns   string
}

var nodefabricnetworkattachmentsResource = schema.GroupVersionResource{Group: "aci.fabricattachment", Version: "v1", Resource: "nodefabricnetworkattachments"}

var nodefabricnetworkattachmentsKind = schema.GroupVersionKind{Group: "aci.fabricattachment", Version: "v1", Kind: "NodeFabricNetworkAttachment"}

// Get takes name of the nodeFabricNetworkAttachment, and returns the corresponding nodeFabricNetworkAttachment object, and an error if there is any.
func (c *FakeNodeFabricNetworkAttachments) Get(ctx context.Context, name string, options v1.GetOptions) (result *acifabricattachmentv1.NodeFabricNetworkAttachment, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewGetAction(nodefabricnetworkattachmentsResource, c.ns, name), &acifabricattachmentv1.NodeFabricNetworkAttachment{})

	if obj == nil {
		return nil, err
	}
	return obj.(*acifabricattachmentv1.NodeFabricNetworkAttachment), err
}

// List takes label and field selectors, and returns the list of NodeFabricNetworkAttachments that match those selectors.
func (c *FakeNodeFabricNetworkAttachments) List(ctx context.Context, opts v1.ListOptions) (result *acifabricattachmentv1.NodeFabricNetworkAttachmentList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewListAction(nodefabricnetworkattachmentsResource, nodefabricnetworkattachmentsKind, c.ns, opts), &acifabricattachmentv1.NodeFabricNetworkAttachmentList{})

	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &acifabricattachmentv1.NodeFabricNetworkAttachmentList{ListMeta: obj.(*acifabricattachmentv1.NodeFabricNetworkAttachmentList).ListMeta}
	for _, item := range obj.(*acifabricattachmentv1.NodeFabricNetworkAttachmentList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested nodeFabricNetworkAttachments.
func (c *FakeNodeFabricNetworkAttachments) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewWatchAction(nodefabricnetworkattachmentsResource, c.ns, opts))

}

// Create takes the representation of a nodeFabricNetworkAttachment and creates it.  Returns the server's representation of the nodeFabricNetworkAttachment, and an error, if there is any.
func (c *FakeNodeFabricNetworkAttachments) Create(ctx context.Context, nodeFabricNetworkAttachment *acifabricattachmentv1.NodeFabricNetworkAttachment, opts v1.CreateOptions) (result *acifabricattachmentv1.NodeFabricNetworkAttachment, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewCreateAction(nodefabricnetworkattachmentsResource, c.ns, nodeFabricNetworkAttachment), &acifabricattachmentv1.NodeFabricNetworkAttachment{})

	if obj == nil {
		return nil, err
	}
	return obj.(*acifabricattachmentv1.NodeFabricNetworkAttachment), err
}

// Update takes the representation of a nodeFabricNetworkAttachment and updates it. Returns the server's representation of the nodeFabricNetworkAttachment, and an error, if there is any.
func (c *FakeNodeFabricNetworkAttachments) Update(ctx context.Context, nodeFabricNetworkAttachment *acifabricattachmentv1.NodeFabricNetworkAttachment, opts v1.UpdateOptions) (result *acifabricattachmentv1.NodeFabricNetworkAttachment, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateAction(nodefabricnetworkattachmentsResource, c.ns, nodeFabricNetworkAttachment), &acifabricattachmentv1.NodeFabricNetworkAttachment{})

	if obj == nil {
		return nil, err
	}
	return obj.(*acifabricattachmentv1.NodeFabricNetworkAttachment), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakeNodeFabricNetworkAttachments) UpdateStatus(ctx context.Context, nodeFabricNetworkAttachment *acifabricattachmentv1.NodeFabricNetworkAttachment, opts v1.UpdateOptions) (*acifabricattachmentv1.NodeFabricNetworkAttachment, error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateSubresourceAction(nodefabricnetworkattachmentsResource, "status", c.ns, nodeFabricNetworkAttachment), &acifabricattachmentv1.NodeFabricNetworkAttachment{})

	if obj == nil {
		return nil, err
	}
	return obj.(*acifabricattachmentv1.NodeFabricNetworkAttachment), err
}

// Delete takes name of the nodeFabricNetworkAttachment and deletes it. Returns an error if one occurs.
func (c *FakeNodeFabricNetworkAttachments) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewDeleteActionWithOptions(nodefabricnetworkattachmentsResource, c.ns, name, opts), &acifabricattachmentv1.NodeFabricNetworkAttachment{})

	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeNodeFabricNetworkAttachments) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	action := testing.NewDeleteCollectionAction(nodefabricnetworkattachmentsResource, c.ns, listOpts)

	_, err := c.Fake.Invokes(action, &acifabricattachmentv1.NodeFabricNetworkAttachmentList{})
	return err
}

// Patch applies the patch and returns the patched nodeFabricNetworkAttachment.
func (c *FakeNodeFabricNetworkAttachments) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *acifabricattachmentv1.NodeFabricNetworkAttachment, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(nodefabricnetworkattachmentsResource, c.ns, name, pt, data, subresources...), &acifabricattachmentv1.NodeFabricNetworkAttachment{})

	if obj == nil {
		return nil, err
	}
	return obj.(*acifabricattachmentv1.NodeFabricNetworkAttachment), err
}