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

package hostagent

/*import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetSandboxUserId(t *testing.T) {
	log := testAgent().log.WithField("test", "TestGetSandboxUserId")

	exp_uid := fmt.Sprintf("%d", os.Getuid())
	assert.Equal(t,
		exp_uid,
		getSandboxUserId(log, fmt.Sprintf("/proc/%d/ns/net", os.Getpid())))

	assert.Equal(t, "", getSandboxUserId(log, "/var/vcap/data/1234"))
}*/
