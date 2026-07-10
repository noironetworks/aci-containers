// Copyright 2026 Cisco Systems, Inc.
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

package hostagent

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestEnableSyncConcurrentAccess guards against regression of a data race
// where agent.syncEnabled was read (by syncEps, syncServices, syncSnat,
// syncSnatNodeInfo, syncRdConfig, syncNodePodIfs, cleanupSetup) without
// synchronization while EnableSync wrote it under indexMutex. syncEnabled
// is now an atomic.Bool. Run with `go test -race` to verify there is no
// data race between concurrent EnableSync callers and concurrent readers.
func TestEnableSyncConcurrentAccess(t *testing.T) {
	agent := testAgent()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			agent.EnableSync()
		}
	}()

	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			_ = agent.syncEnabled.Load()
		}
	}()

	wg.Wait()

	assert.True(t, agent.syncEnabled.Load(), "expected syncEnabled to be true after EnableSync")
}
