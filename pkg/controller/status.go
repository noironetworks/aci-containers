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

package controller

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/noironetworks/aci-containers/pkg/metadata"
)

type contStatus struct {
	PodIpPool           metadata.NetIps `json:"pod-ip-pool,omitempty"`
	ServiceIpPool       metadata.NetIps `json:"service-ip-pool,omitempty"`
	StaticServiceIpPool metadata.NetIps `json:"static-service-ip-pool,omitempty"`
	NodeServiceIpPool   metadata.NetIps `json:"node-service-ip-pool,omitempty"`
}

func (cont *AciController) RunStatus() {
	if cont.config.StatusPort <= 0 {
		return
	}

	http.HandleFunc("/config", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(cont.config)
	})
	http.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		cont.indexMutex.Lock()
		status := &contStatus{
			PodIpPool: metadata.NetIps{
				V4: cont.podNetworkIps.V4.FreeList,
				V6: cont.podNetworkIps.V6.FreeList,
			},
			ServiceIpPool: metadata.NetIps{
				V4: cont.serviceIps.CombineV4(),
				V6: cont.serviceIps.CombineV6(),
			},
			StaticServiceIpPool: metadata.NetIps{
				V4: cont.staticServiceIps.V4.FreeList,
				V6: cont.staticServiceIps.V6.FreeList,
			},
			NodeServiceIpPool: metadata.NetIps{
				V4: cont.nodeServiceIps.V4.FreeList,
				V6: cont.nodeServiceIps.V6.FreeList,
			},
		}
		json.NewEncoder(w).Encode(status)
		cont.indexMutex.Unlock()
	})
	cont.log.Info("Starting status server")
	panic(http.ListenAndServe(fmt.Sprintf(":%d", cont.config.StatusPort), nil))
}
