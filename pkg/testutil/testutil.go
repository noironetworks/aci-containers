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
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
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

// Wait for the given condition to become true
func WaitForComp(t *testing.T, desc string, timeout time.Duration,
	cond assert.Comparison) error {
	return WaitFor(t, desc, 500*time.Millisecond,
		func(last bool) (bool, error) {
			return cond(), nil
		})
}

// isNil checks if a specified object is nil or not, without Failing.
func isNil(object interface{}) bool {
	if object == nil {
		return true
	}

	value := reflect.ValueOf(object)
	kind := value.Kind()
	if kind >= reflect.Chan && kind <= reflect.Slice && value.IsNil() {
		return true
	}

	return false
}

// returns true if the object is nil.  If final is true, also
// asserts that that the object is nil.
func WaitNil(t *testing.T, final bool, object interface{}, msgAndArgs ...interface{}) bool {
	if final {
		assert.Nil(t, object, msgAndArgs...)
	}

	return isNil(object)
}

// returns true if the object is not nil.  If final is true, also
// asserts that that the object is not nil.
func WaitNotNil(t *testing.T, final bool, object interface{}, msgAndArgs ...interface{}) bool {
	if final {
		assert.NotNil(t, object, msgAndArgs...)
	}
	return !isNil(object)
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

// returns true if the objects are not equal.  If final is true, also
// asserts that they are not equal to the test interface
func WaitNotEqual(t *testing.T, final bool, expected,
	actual interface{}, msgAndArgs ...interface{}) bool {
	if final {
		assert.NotEqual(t, expected, actual, msgAndArgs...)
	}
	return !assert.ObjectsAreEqual(expected, actual)
}
