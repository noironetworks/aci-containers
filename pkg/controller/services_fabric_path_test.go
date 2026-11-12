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
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package controller

import (
	"testing"

	"github.com/noironetworks/aci-containers/pkg/apicapi"
)

const testFabricPath = "topology/pod-1/paths-301/pathep-[eth1/33]"

func TestFabricPathForNodeRequiresPath(t *testing.T) {
	tests := []struct {
		name     string
		state    string
		path     interface{}
		setPath  bool
		wantPath string
		wantOK   bool
	}{
		{name: "connected missing", state: "connected"},
		{name: "connected empty", state: "connected", path: "", setPath: true},
		{name: "connected spaces", state: "connected", path: "   ", setPath: true},
		{name: "connected non-string", state: "connected", path: 123, setPath: true},
		{name: "disconnected missing", state: "disconnected"},
		{name: "disconnected empty", state: "disconnected", path: "", setPath: true},
		{name: "connected valid", state: "connected", path: testFabricPath,
			setPath: true, wantPath: testFabricPath, wantOK: true},
		{name: "disconnected valid", state: "disconnected", path: testFabricPath,
			setPath: true, wantPath: testFabricPath, wantOK: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cont := testController()
			device := apicapi.EmptyApicObject("opflexODev", "dev1")
			device.SetAttr("hostName", "node1")
			device.SetAttr("state", tt.state)
			if tt.setPath {
				device.SetAttr("fabricPathDn", tt.path)
			}
			cont.nodeOpflexDevice["node1"] = apicapi.ApicSlice{device}

			path, ok := cont.fabricPathForNode("node1")
			if path != tt.wantPath || ok != tt.wantOK {
				t.Fatalf("got path=%q, ok=%t; want path=%q, ok=%t",
					path, ok, tt.wantPath, tt.wantOK)
			}
		})
	}
}

func TestOpenStackDevicePathRecovery(t *testing.T) {
	cont := testController()
	cont.openStackSystemId = "system1"

	device := apicapi.EmptyApicObject("opflexODev", "dev1")
	device.SetAttr("hostName", "host1")
	device.SetAttr("compHvDn",
		"comp/prov-OpenStack/ctrlr-[system1]-system1")

	if cont.openStackOpflexOdevUpdate(device) {
		t.Fatal("incomplete device must not trigger a graph update")
	}
	if _, exists := cont.openStackFabricPathDnMap["host1"]; exists {
		t.Fatal("incomplete device must not be cached")
	}

	device.SetAttr("fabricPathDn", testFabricPath)
	if !cont.openStackOpflexOdevUpdate(device) {
		t.Fatal("valid path must trigger a graph update")
	}
	if got := cont.openStackFabricPathDnMap["host1"].fabricPathDn; got != testFabricPath {
		t.Fatalf("cached path = %q; want %q", got, testFabricPath)
	}

	device.SetAttr("fabricPathDn", "")
	if cont.openStackOpflexOdevUpdate(device) {
		t.Fatal("blank update must not trigger a graph update")
	}
	if got := cont.openStackFabricPathDnMap["host1"].fabricPathDn; got != testFabricPath {
		t.Fatalf("blank update replaced valid cached path with %q", got)
	}
}

func TestUpdateHostFabricPathDnMapRequiresAttributes(t *testing.T) {
	const (
		bundleDn = "uni/infra/funcprof/accbundle-host1"
		vpcIfDn  = "topology/pod-1/node-101/sys/vpc/inst/dom-test"
	)

	tests := []struct {
		name    string
		path    interface{}
		setPath bool
		dn      interface{}
		setDn   bool
		valid   bool
	}{
		{name: "missing fabric path", dn: vpcIfDn, setDn: true},
		{name: "empty fabric path", path: "", setPath: true, dn: vpcIfDn, setDn: true},
		{name: "spaces fabric path", path: "   ", setPath: true, dn: vpcIfDn, setDn: true},
		{name: "non-string fabric path", path: 123, setPath: true, dn: vpcIfDn, setDn: true},
		{name: "missing dn", path: testFabricPath, setPath: true},
		{name: "empty dn", path: testFabricPath, setPath: true, dn: "", setDn: true},
		{name: "spaces dn", path: testFabricPath, setPath: true, dn: "   ", setDn: true},
		{name: "non-string dn", path: testFabricPath, setPath: true, dn: 123, setDn: true},
		{name: "valid", path: testFabricPath, setPath: true, dn: vpcIfDn, setDn: true, valid: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cont := testController()
			cont.hostFabricPathDnMap[bundleDn] = hostFabricInfo{
				host:    "host1",
				vpcIfDn: make(map[string]struct{}),
			}

			obj := apicapi.EmptyApicObject("vpcIf", vpcIfDn)
			obj.SetAttr("accBndlGrpDn", bundleDn)
			if tt.setPath {
				obj.SetAttr("fabricPathDn", tt.path)
			}
			if tt.setDn {
				obj.SetAttr("dn", tt.dn)
			} else {
				for _, body := range obj {
					delete(body.Attributes, "dn")
				}
			}

			updated := cont.updateHostFabricPathDnMap(obj)
			if updated != tt.valid {
				t.Fatalf("updated=%t; want %t", updated, tt.valid)
			}

			hostInfo := cont.hostFabricPathDnMap[bundleDn]
			if tt.valid {
				if hostInfo.fabricPathDn != testFabricPath {
					t.Fatalf("cached path=%q; want %q", hostInfo.fabricPathDn, testFabricPath)
				}
				if _, exists := hostInfo.vpcIfDn[vpcIfDn]; !exists {
					t.Fatalf("valid vpcIf DN %q was not cached", vpcIfDn)
				}
			} else if hostInfo.fabricPathDn != "" || len(hostInfo.vpcIfDn) != 0 {
				t.Fatalf("invalid vpcIf changed cache: %+v", hostInfo)
			}
		})
	}
}
