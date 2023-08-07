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

package hostagent

import (
	"context"
	"fmt"
	fabattv1 "github.com/noironetworks/aci-containers/pkg/fabricattachment/apis/aci.fabricattachment/v1"
	fabattclientset "github.com/noironetworks/aci-containers/pkg/fabricattachment/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
	"k8s.io/kubernetes/pkg/controller"
	"strconv"
	"strings"
)

type nadVlanMatchData struct {
	NormalizedVlans string
	NadList         map[string]bool
	PendingDelete   bool
}

func (agent *HostAgent) initNadVlanInformerFromClient(client *fabattclientset.Clientset) {
	agent.initNadVlanInformerBase(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				return client.AciV1().NadVlanMaps(metav1.NamespaceAll).List(context.TODO(), options)
			},

			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				return client.AciV1().NadVlanMaps(metav1.NamespaceAll).Watch(context.TODO(), options)
			},
		})
}

func (agent *HostAgent) initNadVlanInformerBase(listWatch *cache.ListWatch) {
	agent.nadVlanMapInformer = cache.NewSharedIndexInformer(
		listWatch, &fabattv1.NadVlanMap{}, controller.NoResyncPeriodFunc(),
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	agent.nadVlanMapInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			agent.nadVlanMapAdded(obj)
		},
		UpdateFunc: func(oldobj interface{}, newobj interface{}) {
			agent.nadVlanMapUpdated(oldobj, newobj)
		},
		DeleteFunc: func(obj interface{}) {
			agent.nadVlanMapDeleted(obj)
		},
	})
}

func (agent *HostAgent) isNadVlanMapHit(nadNs, nadName, nadVlanKey string, nadVlanMatch *nadVlanMatchData) bool {
	nadVlanKeyElems := strings.Split(nadVlanKey, "/")
	if (nadNs == nadVlanKeyElems[0]) &&
		strings.HasPrefix(nadName, nadVlanKeyElems[1]) && !nadVlanMatch.PendingDelete {
		return true
	}
	return false
}

func (agent *HostAgent) getNadVlanMapMatchLocked(nadKey string) (string, string, bool) {
	nadKeyElems := strings.Split(nadKey, "/")
	for nadVlanKey, nadVlanMatch := range agent.nadVlanMap {
		if agent.isNadVlanMapHit(nadKeyElems[0], nadKeyElems[1], nadVlanKey, nadVlanMatch) {
			nadVlanMatch.NadList[nadKey] = true
			return nadVlanKey, nadVlanMatch.NormalizedVlans, true
		}
	}
	return "", "", false
}

func (agent *HostAgent) normalizeVlanList(vlanList []string) (string, error) {
	normalizedVlan := "["
	firstPass := true
	// TODO: Dedup var deDupMap map[int]bool
	for _, vlanStr := range vlanList {
		vlanElems := strings.Split(vlanStr, ",")
		for _, vlanElem := range vlanElems {
			vlanElemTrimmed := strings.TrimSpace(vlanElem)
			var vlanElemStr string
			if strings.Contains(vlanElemTrimmed, "-") {
				vlanRange := strings.Split(vlanElemTrimmed, "-")
				vlanRange[0] = strings.TrimSpace(vlanRange[0])
				vlanRange[1] = strings.TrimSpace(vlanRange[1])
				vlanFrom, err := strconv.Atoi(vlanRange[0])
				if err != nil {
					return "", err
				}
				vlanTo, err := strconv.Atoi(vlanRange[1])
				if err != nil {
					return "", err
				}
				if vlanFrom > vlanTo {
					err = fmt.Errorf("vlanRange incorrect: %d-%d", vlanFrom, vlanTo)
					return "", err
				}
				vlanElemStr = vlanRange[0] + "-" + vlanRange[1]
			} else {
				_, err := strconv.Atoi(vlanElemTrimmed)
				if err != nil {
					return "", err
				}
				vlanElemStr = vlanElemTrimmed
			}
			if firstPass {
				normalizedVlan += vlanElemStr
			} else {
				normalizedVlan += "," + vlanElemStr
			}
			firstPass = false
		}
	}
	normalizedVlan += "]"
	return normalizedVlan, nil
}

func (agent *HostAgent) nadVlanMapChanged(obj *fabattv1.NadVlanMap) {
	agent.indexMutex.Lock()
	mappingPresent := make(map[string]bool)
	for key, vlanMappingList := range obj.Spec.NadVlanMapping {
		newVlanList := []string{}
		for _, vlanMapping := range vlanMappingList {
			newVlanList = append(newVlanList, vlanMapping.Vlans)
		}
		mappingPresent[key] = true
		normalized, err := agent.normalizeVlanList(newVlanList)
		if err != nil {
			// TODO: Update err status
			agent.log.Errorf("Incorrect vlanlist specified for %s:%v", key, err)
			continue
		}
		nadData, ok := agent.nadVlanMap[key]
		if !ok {
			nadData = &nadVlanMatchData{
				NormalizedVlans: normalized,
				NadList:         make(map[string]bool),
				PendingDelete:   false,
			}
			for nadKey := range agent.netattdefmap {
				nadKeyElems := strings.Split(nadKey, "/")
				if agent.isNadVlanMapHit(nadKeyElems[0], nadKeyElems[1], key, nadData) {
					nadData.NadList[nadKey] = true
					agent.updateNodeFabricNetworkAttachmentForEncapChangeLocked(nadKey, key, normalized, false)
				}
			}
			agent.nadVlanMap[key] = nadData
		} else if nadData.NormalizedVlans != normalized {
			nadData.NormalizedVlans = normalized
			for nadKey := range nadData.NadList {
				agent.updateNodeFabricNetworkAttachmentForEncapChangeLocked(nadKey, key, normalized, false)
			}
		}
	}
	var toDelete []string
	for key, nadData := range agent.nadVlanMap {
		if _, ok := mappingPresent[key]; !ok {
			nadData.PendingDelete = true
			toDelete = append(toDelete, key)
			for nadKey := range nadData.NadList {
				agent.updateNodeFabricNetworkAttachmentForEncapChangeLocked(nadKey, key, "", true)
			}
		}
	}
	for idx := range toDelete {
		delete(agent.nadVlanMap, toDelete[idx])
	}
	agent.indexMutex.Unlock()
}

func (agent *HostAgent) nadVlanMapAdded(obj interface{}) {
	nadVlanMap, ok := obj.(*fabattv1.NadVlanMap)
	if !ok {
		agent.log.Error("Non NadVlanMap object")
		return
	}
	agent.log.Info("nadVlanMap added")
	agent.nadVlanMapChanged(nadVlanMap)

}

func (agent *HostAgent) nadVlanMapUpdated(oldObj interface{}, newObj interface{}) {
	nadVlanMap, ok := newObj.(*fabattv1.NadVlanMap)
	if !ok {
		agent.log.Error("Non NadVlanMap object")
		return
	}
	agent.log.Info("nadVlanMap updated")
	agent.nadVlanMapChanged(nadVlanMap)
}

func (agent *HostAgent) nadVlanMapDeleted(obj interface{}) {
	agent.log.Info("nadVlanMap deleted")
	agent.indexMutex.Lock()
	for key, nadData := range agent.nadVlanMap {
		nadData.PendingDelete = true
		for nadKey := range nadData.NadList {
			agent.updateNodeFabricNetworkAttachmentForEncapChangeLocked(nadKey, key, "", true)
		}
	}
	agent.nadVlanMap = make(map[string]*nadVlanMatchData)
	agent.indexMutex.Unlock()
}
