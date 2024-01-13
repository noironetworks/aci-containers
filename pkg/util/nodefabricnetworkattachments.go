// Copyright 2023 Cisco Systems, Inc.
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
	fabattv1 "github.com/noironetworks/aci-containers/pkg/fabricattachment/apis/aci.fabricattachment/v1"
)

type EncapMode int

const (
	EncapModeTrunk    EncapMode = 0
	EncapModeNative   EncapMode = 1
	EncapModeUntagged EncapMode = 2
)

func (e EncapMode) ToFabAttEncapMode() fabattv1.EncapMode {
	switch e {
	case EncapModeTrunk:
		return fabattv1.EncapModeTrunk
	case EncapModeNative:
		return fabattv1.EncapModeNative
	case EncapModeUntagged:
		return fabattv1.EncapModeUntagged
	default:
		return ""
	}
}

func (e EncapMode) String() string {
	switch e {
	case EncapModeTrunk:
		return "regular"
	case EncapModeNative:
		return "native"
	case EncapModeUntagged:
		return "untagged"
	default:
		return ""
	}
}

func ToEncapMode(encapModeString fabattv1.EncapMode) EncapMode {
	switch encapModeString {
	case fabattv1.EncapModeTrunk:
		return EncapModeTrunk
	case fabattv1.EncapModeNative:
		return EncapModeNative
	case fabattv1.EncapModeUntagged:
		return EncapModeUntagged
	default:
		return EncapModeTrunk
	}
}
