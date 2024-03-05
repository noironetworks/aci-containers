// Copyright 2017 Cisco Systems, Inc.
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

package apicapi

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInjectedSvcPortNormalizer(t *testing.T) {
	t.Run("Empty Attributes", func(t *testing.T) {
		b := &ApicObjectBody{
			Attributes: nil,
		}

		injectedSvcPortNormalizer(b)

		assert.Nil(t, b.Attributes)
	})

	t.Run("Normalize Ports", func(t *testing.T) {
		b := &ApicObjectBody{
			Attributes: map[string]interface{}{
				"port":     "80",
				"nodePort": "30000",
			},
		}

		injectedSvcPortNormalizer(b)

		expected := map[string]interface{}{
			"port":     normalizePort("80"),
			"nodePort": normalizePort("30000"),
		}

		assert.Equal(t, expected, b.Attributes)
	})

	t.Run("Normalize Protocol", func(t *testing.T) {
		b := &ApicObjectBody{
			Attributes: map[string]interface{}{
				"protocol": "TCP",
			},
		}

		injectedSvcPortNormalizer(b)

		expected := map[string]interface{}{
			"protocol": normalizeProto("TCP"),
		}

		assert.Equal(t, expected, b.Attributes)
	})

	t.Run("No Protocol Attribute", func(t *testing.T) {
		b := &ApicObjectBody{
			Attributes: map[string]interface{}{
				"port": "80",
			},
		}

		injectedSvcPortNormalizer(b)

		expected := map[string]interface{}{
			"port": "http",
		}

		assert.Equal(t, expected, b.Attributes)
	})

	t.Run("Non-string Protocol Attribute", func(t *testing.T) {
		b := &ApicObjectBody{
			Attributes: map[string]interface{}{
				"protocol": 123,
			},
		}

		injectedSvcPortNormalizer(b)

		expected := map[string]interface{}{
			"protocol": 123,
		}

		assert.Equal(t, expected, b.Attributes)
	})
}

func TestAddMetaDataChild(t *testing.T) {
	t.Run("Existing Parent and Child", func(t *testing.T) {
		parent := "fvTenant"
		child := "cloudAwsProvider"

		err := AddMetaDataChild(parent, child)

		assert.NoError(t, err)
		assert.Contains(t, metadata[parent].children, child)
	})

	t.Run("Non-existing Parent", func(t *testing.T) {
		parent := "parent2"
		child := "fvTenant"

		err := AddMetaDataChild(parent, child)

		assert.Error(t, err)
		assert.EqualError(t, err, fmt.Sprintf("parent %s not found", parent))
	})

	t.Run("Non-existing Child", func(t *testing.T) {
		parent := "fvTenant"
		child := "child3"

		err := AddMetaDataChild(parent, child)

		assert.Error(t, err)
		assert.EqualError(t, err, fmt.Sprintf("child %s not found", child))
		assert.NotContains(t, metadata[parent].children, child)
	})
}
