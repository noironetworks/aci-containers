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

// FakeNodeFabricL3Peerses implements NodeFabricL3PeersInterface
type FakeNodeFabricL3Peerses struct {
	Fake *FakeAciV1
}

var nodefabricl3peersesResource = v1.SchemeGroupVersion.WithResource("nodefabricl3peerses")

var nodefabricl3peersesKind = v1.SchemeGroupVersion.WithKind("NodeFabricL3Peers")

// Get takes name of the nodeFabricL3Peers, and returns the corresponding nodeFabricL3Peers object, and an error if there is any.
func (c *FakeNodeFabricL3Peerses) Get(ctx context.Context, name string, options metav1.GetOptions) (result *v1.NodeFabricL3Peers, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootGetAction(nodefabricl3peersesResource, name), &v1.NodeFabricL3Peers{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1.NodeFabricL3Peers), err
}

// List takes label and field selectors, and returns the list of NodeFabricL3Peerses that match those selectors.
func (c *FakeNodeFabricL3Peerses) List(ctx context.Context, opts metav1.ListOptions) (result *v1.NodeFabricL3PeersList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootListAction(nodefabricl3peersesResource, nodefabricl3peersesKind, opts), &v1.NodeFabricL3PeersList{})
	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1.NodeFabricL3PeersList{ListMeta: obj.(*v1.NodeFabricL3PeersList).ListMeta}
	for _, item := range obj.(*v1.NodeFabricL3PeersList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested nodeFabricL3Peerses.
func (c *FakeNodeFabricL3Peerses) Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewRootWatchAction(nodefabricl3peersesResource, opts))
}

// Create takes the representation of a nodeFabricL3Peers and creates it.  Returns the server's representation of the nodeFabricL3Peers, and an error, if there is any.
func (c *FakeNodeFabricL3Peerses) Create(ctx context.Context, nodeFabricL3Peers *v1.NodeFabricL3Peers, opts metav1.CreateOptions) (result *v1.NodeFabricL3Peers, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootCreateAction(nodefabricl3peersesResource, nodeFabricL3Peers), &v1.NodeFabricL3Peers{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1.NodeFabricL3Peers), err
}

// Update takes the representation of a nodeFabricL3Peers and updates it. Returns the server's representation of the nodeFabricL3Peers, and an error, if there is any.
func (c *FakeNodeFabricL3Peerses) Update(ctx context.Context, nodeFabricL3Peers *v1.NodeFabricL3Peers, opts metav1.UpdateOptions) (result *v1.NodeFabricL3Peers, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateAction(nodefabricl3peersesResource, nodeFabricL3Peers), &v1.NodeFabricL3Peers{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1.NodeFabricL3Peers), err
}

// Delete takes name of the nodeFabricL3Peers and deletes it. Returns an error if one occurs.
func (c *FakeNodeFabricL3Peerses) Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewRootDeleteActionWithOptions(nodefabricl3peersesResource, name, opts), &v1.NodeFabricL3Peers{})
	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeNodeFabricL3Peerses) DeleteCollection(ctx context.Context, opts metav1.DeleteOptions, listOpts metav1.ListOptions) error {
	action := testing.NewRootDeleteCollectionAction(nodefabricl3peersesResource, listOpts)

	_, err := c.Fake.Invokes(action, &v1.NodeFabricL3PeersList{})
	return err
}

// Patch applies the patch and returns the patched nodeFabricL3Peers.
func (c *FakeNodeFabricL3Peerses) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions, subresources ...string) (result *v1.NodeFabricL3Peers, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootPatchSubresourceAction(nodefabricl3peersesResource, name, pt, data, subresources...), &v1.NodeFabricL3Peers{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1.NodeFabricL3Peers), err
}

// Apply takes the given apply declarative configuration, applies it and returns the applied nodeFabricL3Peers.
func (c *FakeNodeFabricL3Peerses) Apply(ctx context.Context, nodeFabricL3Peers *acifabricattachmentv1.NodeFabricL3PeersApplyConfiguration, opts metav1.ApplyOptions) (result *v1.NodeFabricL3Peers, err error) {
	if nodeFabricL3Peers == nil {
		return nil, fmt.Errorf("nodeFabricL3Peers provided to Apply must not be nil")
	}
	data, err := json.Marshal(nodeFabricL3Peers)
	if err != nil {
		return nil, err
	}
	name := nodeFabricL3Peers.Name
	if name == nil {
		return nil, fmt.Errorf("nodeFabricL3Peers.Name must be provided to Apply")
	}
	obj, err := c.Fake.
		Invokes(testing.NewRootPatchSubresourceAction(nodefabricl3peersesResource, *name, types.ApplyPatchType, data), &v1.NodeFabricL3Peers{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1.NodeFabricL3Peers), err
}
