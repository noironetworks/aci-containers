// Copyright 2026 Cisco Systems, Inc.
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
	"strconv"
	"strings"

	v1 "k8s.io/api/core/v1"
)

type ingressNamedPortState struct {
	fingerprint string
	names       map[string]bool
}

func getIngressNamedPortState(pod *v1.Pod) ingressNamedPortState {
	if pod == nil || pod.Spec.HostNetwork || pod.Status.PodIP == "" {
		return ingressNamedPortState{}
	}
	// Detect IP assignment even when the Pod has no named ports.
	state := ingressNamedPortState{fingerprint: pod.Status.PodIP}
	var fingerprint strings.Builder
	collect := func(containers []v1.Container) {
		for _, container := range containers {
			for _, port := range container.Ports {
				if port.Name == "" {
					continue
				}
				if state.names == nil {
					state.names = make(map[string]bool)
					fingerprint.Grow(len(pod.Status.PodIP) + len(port.Name) + 16)
					fingerprint.WriteString(pod.Status.PodIP)
					fingerprint.WriteByte('|')
				}
				state.names[port.Name] = true
				// Port names cannot contain ':' or '|'. A reordered replacement
				// may cause an extra requeue, but cannot hide a change.
				fingerprint.WriteString(port.Name)
				fingerprint.WriteByte(':')
				fingerprint.WriteString(portProto(&port.Protocol))
				fingerprint.WriteByte(':')
				fingerprint.WriteString(strconv.Itoa(int(port.ContainerPort)))
				fingerprint.WriteByte('|')
			}
		}
	}
	collect(pod.Spec.Containers)
	collect(pod.Spec.InitContainers)
	if state.names != nil {
		state.fingerprint = fingerprint.String()
	}
	return state
}

func (cont *AciController) queueIngressNamedPortUpdates(npKeys []string, states ...ingressNamedPortState) {
	if len(npKeys) == 0 {
		return
	}
	names := make(map[string]bool)
	for _, state := range states {
		for name := range state.names {
			names[name] = true
		}
	}
	if len(names) == 0 {
		return
	}
	for _, npKey := range npKeys {
		if cont.checkNamedPortPresentInNpIngress(npKey, names) {
			cont.queueNetPolUpdateByKey(npKey)
		}
	}
}
