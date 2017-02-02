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

package main

import (
	"sync"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"github.com/noironetworks/aci-containers/ipam"
	md "github.com/noironetworks/aci-containers/metadata"
)

type hostAgent struct {
	config *hostAgentConfig

	indexMutex sync.Mutex

	opflexEps      map[string]*opflexEndpoint
	opflexServices map[string]*opflexService
	epMetadata     map[string]*md.ContainerMetadata
	serviceEp      md.ServiceEndpoint

	kubeClient        *kubernetes.Clientset
	podInformer       cache.SharedIndexInformer
	endpointsInformer cache.SharedIndexInformer
	serviceInformer   cache.SharedIndexInformer
	nodeInformer      cache.SharedIndexInformer

	podNetAnnotation string
	podIpsV4         *ipam.IpAlloc
	podIpsV6         *ipam.IpAlloc

	syncEnabled bool
}

func newHostAgent() *hostAgent {
	return &hostAgent{
		config:         &hostAgentConfig{},
		opflexEps:      make(map[string]*opflexEndpoint),
		opflexServices: make(map[string]*opflexService),
		epMetadata:     make(map[string]*md.ContainerMetadata),

		podIpsV4: ipam.New(),
		podIpsV6: ipam.New(),
	}
}
