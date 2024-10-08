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

	v1 "github.com/noironetworks/aci-containers/pkg/proactiveconf/apis/aci.pc/v1"
	acipcv1 "github.com/noironetworks/aci-containers/pkg/proactiveconf/applyconfiguration/aci.pc/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeProactiveConfs implements ProactiveConfInterface
type FakeProactiveConfs struct {
	Fake *FakeAciV1
}

var proactiveconfsResource = v1.SchemeGroupVersion.WithResource("proactiveconfs")

var proactiveconfsKind = v1.SchemeGroupVersion.WithKind("ProactiveConf")

// Get takes name of the proactiveConf, and returns the corresponding proactiveConf object, and an error if there is any.
func (c *FakeProactiveConfs) Get(ctx context.Context, name string, options metav1.GetOptions) (result *v1.ProactiveConf, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootGetAction(proactiveconfsResource, name), &v1.ProactiveConf{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1.ProactiveConf), err
}

// List takes label and field selectors, and returns the list of ProactiveConfs that match those selectors.
func (c *FakeProactiveConfs) List(ctx context.Context, opts metav1.ListOptions) (result *v1.ProactiveConfList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootListAction(proactiveconfsResource, proactiveconfsKind, opts), &v1.ProactiveConfList{})
	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1.ProactiveConfList{ListMeta: obj.(*v1.ProactiveConfList).ListMeta}
	for _, item := range obj.(*v1.ProactiveConfList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested proactiveConfs.
func (c *FakeProactiveConfs) Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewRootWatchAction(proactiveconfsResource, opts))
}

// Create takes the representation of a proactiveConf and creates it.  Returns the server's representation of the proactiveConf, and an error, if there is any.
func (c *FakeProactiveConfs) Create(ctx context.Context, proactiveConf *v1.ProactiveConf, opts metav1.CreateOptions) (result *v1.ProactiveConf, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootCreateAction(proactiveconfsResource, proactiveConf), &v1.ProactiveConf{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1.ProactiveConf), err
}

// Update takes the representation of a proactiveConf and updates it. Returns the server's representation of the proactiveConf, and an error, if there is any.
func (c *FakeProactiveConfs) Update(ctx context.Context, proactiveConf *v1.ProactiveConf, opts metav1.UpdateOptions) (result *v1.ProactiveConf, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateAction(proactiveconfsResource, proactiveConf), &v1.ProactiveConf{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1.ProactiveConf), err
}

// Delete takes name of the proactiveConf and deletes it. Returns an error if one occurs.
func (c *FakeProactiveConfs) Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewRootDeleteActionWithOptions(proactiveconfsResource, name, opts), &v1.ProactiveConf{})
	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeProactiveConfs) DeleteCollection(ctx context.Context, opts metav1.DeleteOptions, listOpts metav1.ListOptions) error {
	action := testing.NewRootDeleteCollectionAction(proactiveconfsResource, listOpts)

	_, err := c.Fake.Invokes(action, &v1.ProactiveConfList{})
	return err
}

// Patch applies the patch and returns the patched proactiveConf.
func (c *FakeProactiveConfs) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions, subresources ...string) (result *v1.ProactiveConf, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootPatchSubresourceAction(proactiveconfsResource, name, pt, data, subresources...), &v1.ProactiveConf{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1.ProactiveConf), err
}

// Apply takes the given apply declarative configuration, applies it and returns the applied proactiveConf.
func (c *FakeProactiveConfs) Apply(ctx context.Context, proactiveConf *acipcv1.ProactiveConfApplyConfiguration, opts metav1.ApplyOptions) (result *v1.ProactiveConf, err error) {
	if proactiveConf == nil {
		return nil, fmt.Errorf("proactiveConf provided to Apply must not be nil")
	}
	data, err := json.Marshal(proactiveConf)
	if err != nil {
		return nil, err
	}
	name := proactiveConf.Name
	if name == nil {
		return nil, fmt.Errorf("proactiveConf.Name must be provided to Apply")
	}
	obj, err := c.Fake.
		Invokes(testing.NewRootPatchSubresourceAction(proactiveconfsResource, *name, types.ApplyPatchType, data), &v1.ProactiveConf{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1.ProactiveConf), err
}
