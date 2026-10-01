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

func TestDeviceClusterSkipsBlankPaths(t *testing.T) {
	nodes := []string{"missing", "spaces", "valid"}
	paths := map[string]string{
		"missing": "",
		"spaces":  "   ",
		"valid":   testFabricPath,
	}

	cluster, _ := apicDeviceCluster(
		"test_svc_global", "common", "service-physdom",
		"vlan-4001", nodes, paths,
	)

	devices := objectsOfClass(cluster, "vnsCDev")
	if len(devices) != 1 || devices[0].GetAttrStr("name") != "valid" {
		t.Fatalf("want only valid concrete device; got %v", devices)
	}

	relations := objectsOfClass(cluster, "vnsRsCIfPathAtt")
	if len(relations) != 1 || relations[0].GetAttrStr("tDn") != testFabricPath {
		t.Fatalf("want one relation with valid path; got %v", relations)
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

	newPath := "topology/pod-1/paths-302/pathep-[eth1/34]"
	device.SetAttr("fabricPathDn", newPath)
	if !cont.openStackOpflexOdevUpdate(device) {
		t.Fatal("changed path must trigger a graph update")
	}
	if got := cont.openStackFabricPathDnMap["host1"].fabricPathDn; got != newPath {
		t.Fatalf("cached path = %q; want %q", got, newPath)
	}

	device.SetAttr("fabricPathDn", "")
	if cont.openStackOpflexOdevUpdate(device) {
		t.Fatal("blank update must not trigger a graph update")
	}
	if got := cont.openStackFabricPathDnMap["host1"].fabricPathDn; got != newPath {
		t.Fatalf("blank update replaced valid cached path with %q", got)
	}
}

func objectsOfClass(root apicapi.ApicObject, class string) []apicapi.ApicObject {
	var result []apicapi.ApicObject
	var visit func(apicapi.ApicObject)
	visit = func(obj apicapi.ApicObject) {
		if _, exists := obj[class]; exists {
			result = append(result, obj)
		}
		for _, body := range obj {
			for _, child := range body.Children {
				visit(child)
			}
		}
	}
	visit(root)
	return result
}
