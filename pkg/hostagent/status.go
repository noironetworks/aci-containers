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

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/noironetworks/aci-containers/pkg/metadata"
)

type agentStatus struct {
	Endpoints int             `json:"endpoints,omitempty"`
	Services  int             `json:"services,omitempty"`
	PodIps    metadata.NetIps `json:"pod-ips,omitempty"`
}

func (agent *HostAgent) RunStatus() {
	if agent.config.StatusPort <= 0 {
		return
	}

	http.HandleFunc("/endpoints", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		agent.indexMutex.Lock()
		eps := make([]*opflexEndpoint, 0, len(agent.opflexEps))
		for _, eps := range agent.opflexEps {
			for _, ep := range eps {
				eps = append(eps, ep)
			}
		}
		json.NewEncoder(w).Encode(eps)
		agent.indexMutex.Unlock()
	})
	http.HandleFunc("/services", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		agent.indexMutex.Lock()
		services := make([]*opflexService, 0, len(agent.opflexServices))
		for _, service := range agent.opflexServices {
			services = append(services, service)
		}
		json.NewEncoder(w).Encode(services)
		agent.indexMutex.Unlock()
	})
	http.HandleFunc("/config", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(agent.config)
	})
	http.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		agent.indexMutex.Lock()
		status := &agentStatus{
			Endpoints: len(agent.opflexEps),
			Services:  len(agent.opflexServices),
			PodIps: metadata.NetIps{
				V4: agent.podIps.CombineV4(),
				V6: agent.podIps.CombineV6(),
			},
		}
		json.NewEncoder(w).Encode(status)
		agent.indexMutex.Unlock()
	})
	agent.log.Info("Starting status server")
	panic(http.ListenAndServe(fmt.Sprintf(":%d", agent.config.StatusPort), nil))
}
