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

package testutil

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

// Wait for the predicate to become true by testing it repeatedly on a
// timer.  Asserts a failure if the predicate does not become true
// before the timeout
func WaitFor(t *testing.T, desc string, timeout time.Duration,
	testFunc func(bool) (bool, error)) error {
	end := time.Now().Add(timeout)
	for now := time.Now(); now.Before(end); time.Sleep(10 * time.Millisecond) {
		now = time.Now()
		r, err := testFunc(false)
		if err != nil {
			assert.Fail(t, desc, "Test failure", err)
			return err
		}
		if r {
			return nil
		}
	}
	if r, _ := testFunc(true); !r {
		assert.Fail(t, desc, "Test timeout")
	}
	return nil
}

// returns true if the comparison is true.  If final is true, also
// asserts that that the comparison is true
func WaitCondition(t *testing.T, final bool, comp assert.Comparison,
	msgAndArgs ...interface{}) bool {
	if final {
		assert.Condition(t, comp, msgAndArgs...)
	}
	return comp()
}

// returns true if the objects are equal.  If final is true, also
// asserts that they are equal to the test interface
func WaitEqual(t *testing.T, final bool, expected,
	actual interface{}, msgAndArgs ...interface{}) bool {
	if final {
		assert.Equal(t, expected, actual, msgAndArgs...)
	}
	return assert.ObjectsAreEqual(expected, actual)
}
