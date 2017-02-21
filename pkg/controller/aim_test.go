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

package controller

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

type uniqueNameTest struct {
	components []string
	result     string
	desc       string
}

var uniqueNameTests = []uniqueNameTest{
	{[]string{}, "", "empty"},
	{[]string{"a", "b", "c"}, "a-b-c", "simple"},
	{[]string{"a -", "-", "_"}, "a--20---2d----2d----5f-", "encode"},
}

func TestUniqueName(t *testing.T) {
	for _, at := range uniqueNameTests {
		assert.Equal(t, at.result,
			generateUniqueName(at.components...), at.desc)
	}
}

func TestNetworkPolicy(t *testing.T) {
	cont := testController()
	cont.run()

	cont.stop()
}
