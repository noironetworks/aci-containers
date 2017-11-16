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
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	tu "github.com/noironetworks/aci-containers/pkg/testutil"
)

func TestCfPoller(t *testing.T) {
	env := testCfEnvironment(t)

	iter := 0
	pf := func() (map[string]interface{}, interface{}, error) {
		out := make(map[string]interface{})
		var hash interface{}
		switch iter {
		case 0:
			iter += 1
			return nil, nil, fmt.Errorf("fake error")
		case 1:
			fallthrough
		case 2:
			out["a"] = "a"
			out["b"] = "b"
			hash = "a"
			iter += 1
		case 3:
			out["a"] = "a1"
			out["c"] = "c"
			hash = "c"
			iter += 1
		}
		return out, hash, nil
	}

	handle_count := 0
	hf := func(updates map[string]interface{}, deletes map[string]interface{}) {
		switch iter {
		case 2:
			assert.Equal(t, 0, handle_count)
			assert.Contains(t, updates, "a")
			assert.Contains(t, updates, "b")
			assert.Equal(t, 0, len(deletes))
			handle_count += 1
		case 4:
			assert.Equal(t, 1, handle_count)
			assert.Contains(t, updates, "a")
			assert.Contains(t, updates, "c")
			assert.Contains(t, deletes, "b")
			handle_count += 1
		default:
			assert.False(t, true)
		}
	}

	poller := NewCfPoller("test", 50*time.Millisecond, 0, pf, hf, env.log)
	runEnded := false
	ch := make(chan struct{})
	go func() {
		poller.Run(true, ch)
		runEnded = true
	}()
	tu.WaitFor(t, "Waiting to sync", 200*time.Millisecond,
		func(bool) (bool, error) { return poller.Synced(), nil })
	tu.WaitFor(t, "Waiting for all poll iterations", 500*time.Millisecond,
		func(bool) (bool, error) { return iter > 3, nil })
	tu.WaitFor(t, "Waiting for all handle iterations", 500*time.Millisecond,
		func(bool) (bool, error) { return handle_count == 2, nil })

	close(ch)
	tu.WaitFor(t, "Waiting for Run() to end", 500*time.Millisecond,
		func(bool) (bool, error) { return runEnded, nil })
}
