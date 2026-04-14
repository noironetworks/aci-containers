// Copyright 2020 Cisco Systems, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package util

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/wait"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ApplyResourcesFromFile reads a multi-document YAML file and applies each
// resource to the cluster using server-side apply via controller-runtime.
func ApplyResourcesFromFile(c client.Client, filename, fieldManager string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("reading %s: %w", filename, err)
	}
	return ApplyResources(c, data, fieldManager)
}

// ApplyResources applies each resource in a multi-document YAML byte slice
// to the cluster using server-side apply via controller-runtime.
func ApplyResources(c client.Client, data []byte, fieldManager string) error {
	decoder := utilyaml.NewYAMLOrJSONDecoder(strings.NewReader(string(data)), 4096)

	var errs []error
	for {
		obj := &unstructured.Unstructured{}
		err := decoder.Decode(obj)
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("decoding YAML document: %w", err)
		}
		if obj.Object == nil {
			continue
		}

		log.Infof("Applying %s %s/%s", obj.GetKind(), obj.GetNamespace(), obj.GetName())
		if err := applyWithRetry(context.TODO(), c, obj, fieldManager); err != nil {
			errs = append(errs, fmt.Errorf("applying %s %s/%s: %w",
				obj.GetKind(), obj.GetNamespace(), obj.GetName(), err))
		}
	}

	return errors.Join(errs...)
}

// applyWithRetry applies a single resource using server-side apply.
// It retries only on NoMatch errors (CRD-then-CR race); all other
// errors are returned immediately, matching kubectl apply behaviour.
func applyWithRetry(ctx context.Context, c client.Client, obj *unstructured.Unstructured, fieldManager string) error {
	patch := func() error {
		return c.Patch(ctx, obj, client.Apply, client.FieldOwner(fieldManager), client.ForceOwnership)
	}

	err := patch()
	if err == nil || !meta.IsNoMatchError(err) {
		return err
	}

	// CRD is not yet registered — back off and retry.
	// The API server CRD controller typically establishes new
	// endpoints within 1-3s; the DynamicRESTMapper auto-resets
	// its discovery cache on NoMatchError.
	backoff := wait.Backoff{
		Steps:    4,
		Duration: 1 * time.Second,
		Factor:   2.0,
		Cap:      10 * time.Second,
	}

	return wait.ExponentialBackoffWithContext(ctx, backoff, func(ctx context.Context) (bool, error) {
		log.Debugf("API not yet available for %s %s/%s, retrying...",
			obj.GetKind(), obj.GetNamespace(), obj.GetName())
		err := patch()
		if err == nil {
			return true, nil
		}
		if meta.IsNoMatchError(err) {
			return false, nil
		}
		return false, err
	})
}
