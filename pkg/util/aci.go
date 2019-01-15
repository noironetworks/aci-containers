// Copyright 2018 Cisco Systems, Inc.
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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// AciNameForKey generates an ACI object name based on the params passed
func AciNameForKey(prefix, ktype, key string) string {
	name := prefix + "_" + ktype +
		"_" + strings.Replace(key, "/", "_", -1)
	if len(name) < 64 {
		return name
	}

	hash := sha256.New()
	if len(prefix)+len(ktype)+1 > 31 {
		if len(prefix) > 31 {
			hash.Write([]byte(prefix))
			hash.Write([]byte("_"))
		} else {
			name = prefix
		}

		hash.Write([]byte(ktype))
		hash.Write([]byte("_"))
	} else {
		name = prefix + "_" + ktype
	}
	hash.Write([]byte(key))

	hashstr := hex.EncodeToString(hash.Sum(nil)[:16])
	if len(prefix) > 31 {
		return hashstr
	} else {
		return fmt.Sprintf("%s_%s", name, hashstr)
	}
}
