/***
Copyright 2019 Cisco Systems Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
// Pod stats -- filled in by lower layer

package metrics

import (
	"fmt"
	"k8s.io/api/core/v1"
	"sync"
	"time"
)

type Tuple struct {
	prot     string
	srcIP    string
	srcPort  string
	destIP   string
	destPort string
}

type PodStatsType struct {
	Ingress map[Tuple][]StatsRec
	Egress  map[Tuple][]StatsRec
	Labels  map[string]string
}

type StatsRec struct {
	connections int
	packets     int
	bytes       int
	timestamp   time.Time
}

type PodStatsObj struct {
	sync.Mutex
	PS         map[string]*PodStatsType
	ipToSvc    map[string]string
	svcEPToSvc map[string]map[string]bool
	podMeta    map[string]map[string]string
}

func NewPodStats() *PodStatsObj {
	return &PodStatsObj{
		PS:         make(map[string]*PodStatsType),
		ipToSvc:    make(map[string]string),
		svcEPToSvc: make(map[string]map[string]bool),
		podMeta:    make(map[string]map[string]string),
	}
}

// SvcUpdate maintains the necessary svc to address mapping
func (pso *PodStatsObj) SvcUpdate(svc *v1.Service, svcEPs *v1.Endpoints, add bool) {
	pso.Lock()
	defer pso.Unlock()

	clusterIP := svc.Spec.ClusterIP
	name := fmt.Sprintf("%s.%s", svc.ObjectMeta.Name, svc.ObjectMeta.Namespace)
	// delete existing endpoints
	for ep, m := range pso.svcEPToSvc {
		delete(m, name)
		if len(m) == 0 {
			delete(pso.svcEPToSvc, ep)
		}
	}

	if !add {
		delete(pso.ipToSvc, clusterIP)
		return
	}
	pso.ipToSvc[clusterIP] = name
	for _, ss := range svcEPs.Subsets {
		for _, ip := range ss.Addresses {
			for _, port := range ss.Ports {
				epKey := fmt.Sprintf("%s:%d", ip.IP, port.Port)
				m := pso.svcEPToSvc[epKey]
				if m == nil {
					m = make(map[string]bool)
				}
				m[name] = true
				pso.svcEPToSvc[epKey] = m
			}
		}
	}
}

func (pso *PodStatsObj) StatsUpdate(podID string, id Tuple, s StatsRec, dir string) {
	//s.timestamp = time.Now() // FIXME
	// if this pod does not exist, add it now
	_, exists := pso.PS[podID]
	if !exists {
		pso.PS[podID] = pso.newPodStats(podID)
	}

	// limit to one item for now.
	if dir == "ingress" {
		if pso.PS[podID].Ingress[id] == nil {
			pso.PS[podID].Ingress[id] = append(pso.PS[podID].Ingress[id], s)
		} else {
			pso.PS[podID].Ingress[id][0] = s
		}
	} else {
		if pso.PS[podID].Egress[id] == nil {
			pso.PS[podID].Egress[id] = append(pso.PS[podID].Egress[id], s)
		} else {
			pso.PS[podID].Egress[id][0] = s
		}
	}
}

func (pso *PodStatsObj) UpdatePodMeta(pod *v1.Pod, del bool) {
	uid := string(pod.ObjectMeta.UID)
	if del {
		delete(pso.podMeta, uid)
		return
	}

	pm, ok := pso.podMeta[uid]
	if !ok {
		pm = make(map[string]string)
		pso.podMeta[uid] = pm
	}

	// add all metadata
	for k, v := range pod.ObjectMeta.Labels {
		pm[k] = v
	}

	pm["Namespace"] = pod.ObjectMeta.Namespace

	// TODO -- add labels based on ownerReference
}

func (pso *PodStatsObj) newPodStats(podID string) *PodStatsType {

	return &PodStatsType{
		Ingress: make(map[Tuple][]StatsRec),
		Egress:  make(map[Tuple][]StatsRec),
		Labels:  pso.podMeta[podID],
	}
}
