// Copyright 2023,2024 Cisco Systems, Inc.
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

package types

import (
	"sync"

	fabattv1 "github.com/noironetworks/aci-containers/pkg/fabricattachment/apis/aci.fabricattachment/v1"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

type FabricPeeringInfo struct {
	Encap  int
	ASN    int
	Peers  map[int]string
	Secret fabattv1.ObjRef
}

type RunTimeData struct {
	// NAD -> k8sNode -> encaps-> FabricNode
	FabricAdjs map[string]map[string]map[int][]int
	// encap -> FabricNode -> PeerInfo
	FabricPeerInfo map[int]*FabricPeeringInfo
	CommonMutex    sync.Mutex
	EligiblePods   map[string]bool
}

type Config struct {
	UnitTestMode         bool
	RequireNADAnnotation bool
	ContainerName        string
	RunTimeData
}

type Manager struct {
	Mgr    manager.Manager
	Config Config
}
