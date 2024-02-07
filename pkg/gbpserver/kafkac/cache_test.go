/*
**
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
package kafkac

import (
	"context"
	"testing"

	crdv1 "github.com/noironetworks/aci-containers/pkg/gbpcrd/apis/acipolicy/v1"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Stub for crdv1.AciV1Interface
type StubAciV1Interface struct {
	PodIFsFunc func(namespace string) crdv1.PodIF
}

func (s *StubAciV1Interface) PodIFs(namespace string) crdv1.PodIF {
	return s.PodIFsFunc(namespace)
}

// Stub for crdv1.PodIF
type StubPodIF struct {
	GetFunc    func(ctx context.Context, name string, options metav1.GetOptions) (*crdv1.PodIF, error)
	CreateFunc func(ctx context.Context, podif *crdv1.PodIF, options metav1.CreateOptions) (*crdv1.PodIF, error)
	UpdateFunc func(ctx context.Context, podif *crdv1.PodIF, options metav1.UpdateOptions) (*crdv1.PodIF, error)
}

func (s *StubPodIF) Get(ctx context.Context, name string, options metav1.GetOptions) (*crdv1.PodIF, error) {
	return s.GetFunc(ctx, name, options)
}

func (s *StubPodIF) Create(ctx context.Context, podif *crdv1.PodIF, options metav1.CreateOptions) (*crdv1.PodIF, error) {
	return s.CreateFunc(ctx, podif, options)
}

func (s *StubPodIF) Update(ctx context.Context, podif *crdv1.PodIF, options metav1.UpdateOptions) (*crdv1.PodIF, error) {
	return s.UpdateFunc(ctx, podif, options)
}

func TestInit(t *testing.T) {
	logger := logrus.New().WithField("module", "podIFCache")

	pc := &podIFCache{
		log:       logger,
		readyChan: make(chan bool),
	}

	err := pc.Init()

	assert.Error(t, err, "Init should not return an error")
	assert.Nil(t, pc.crdClient, "CRD client should be set")
	assert.NotNil(t, pc.readyChan, "Ready channel should be set")
}
