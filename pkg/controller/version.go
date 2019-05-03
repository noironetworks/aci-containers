// Copyright 2019 Cisco Systems, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package controller

import "fmt"

// Variables set during build time for release info
var (
	gitCommit string
	buildTime string
)

// Info enlists version and build information
type VersionInfo struct {
	GitCommit string
	BuildTime string
}

// Get gets the version information
func GetVersion() *VersionInfo {
	ver := VersionInfo{}
	ver.GitCommit = gitCommit
	ver.BuildTime = buildTime

	return &ver
}

// String returns printable version string
func VersionString() string {
	ver := GetVersion()
	return StringFromInfo(ver)
}

// StringFromInfo prints the versioning details
func StringFromInfo(ver *VersionInfo) string {
	return fmt.Sprintf("GitCommit: %s\n", ver.GitCommit) +
		fmt.Sprintf("BuildTime: %s\n", ver.BuildTime)
}
