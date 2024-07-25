// Copyright 2024 Cisco Systems, Inc.
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

// Handlers for node fabric l3 peers updates.
// NodeFabricL3Peers is a status only CR. It has no user-interaction and hence doesn't need informers.

package controller

import (
	"context"
	"strconv"
	"strings"

	fabattv1 "github.com/noironetworks/aci-containers/pkg/fabricattachment/apis/aci.fabricattachment/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (cont *AciController) computeNodeFabricNetworkL3PeerStatus(lock_held bool) *fabattv1.NodeFabricNetworkL3PeerStatus {
	nodeFabl3PeersStatus := &fabattv1.NodeFabricNetworkL3PeerStatus{}
	nadAdjs := make(map[string]map[string]map[int][]int)
	if !lock_held {
		cont.indexMutex.Lock()
	}
	for _, sviData := range cont.sharedEncapSviCache {
		if len(sviData.NetAddr) > 0 {
			shEncapData, ok := cont.sharedEncapCache[sviData.ConnectedNw.Encap]
			if ok {
				for addNetKey, addNet := range shEncapData.NetRef {
					nadAdjs[addNetKey] = make(map[string]map[int][]int)
					for node, lifData := range addNet.FabricLink {
						nadAdjs[addNetKey][node] = make(map[int][]int)
						nodeMap := make(map[string]bool)
						for _, fabLinks := range lifData {
							for _, fabLink := range fabLinks.Link {
								fabricPathParts := strings.SplitN(fabLink, "/", 4)
								nodeMap[fabricPathParts[2]] = true
							}
						}
						fabNodes := []int{}
						for fabNode := range nodeMap {
							after, found := strings.CutPrefix(fabNode, "node-")
							if found {
								nodeId, err := strconv.Atoi(after)
								if err == nil {
									fabNodes = append(fabNodes, nodeId)
								}
							}
						}
						nadAdjs[addNetKey][node][sviData.ConnectedNw.Encap] = fabNodes
					}
				}
			}
		}
		if sviData.ConnectedNw.BGPPeerPolicy.Enabled {
			peeringInfo := fabattv1.NetworkFabricL3PeeringInfo{
				Encap:       sviData.ConnectedNw.Encap,
				ASN:         sviData.ConnectedNw.BGPPeerPolicy.PeerASN,
				Secret:      sviData.ConnectedNw.BGPPeerPolicy.Secret,
				FabricNodes: cont.computeFabricL3OutNodes(sviData),
			}
			nodeFabl3PeersStatus.PeeringInfo = append(nodeFabl3PeersStatus.PeeringInfo, peeringInfo)
		}
	}
	if !lock_held {
		cont.indexMutex.Unlock()
	}
	for nadKey, nadData := range nadAdjs {
		nadParts := strings.Split(nadKey, "/")
		nadFabL3Peer := fabattv1.NADFabricL3Peer{
			NAD: fabattv1.ObjRef{
				Namespace: nadParts[0],
				Name:      nadParts[1],
			},
		}
		for node, nodeData := range nadData {
			nodeFabL3Peer := fabattv1.NodeFabricL3Peer{
				NodeName: node,
			}
			for encap, fabPeers := range nodeData {
				fabL3Peer := fabattv1.FabricL3Peers{
					Encap:         encap,
					FabricPodId:   cont.sharedEncapSviCache[encap].PodId,
					FabricNodeIds: fabPeers,
				}
				nodeFabL3Peer.FabricL3Peers = append(nodeFabL3Peer.FabricL3Peers, fabL3Peer)
			}
			nadFabL3Peer.Nodes = append(nadFabL3Peer.Nodes, nodeFabL3Peer)
		}
		nodeFabl3PeersStatus.NADRefs = append(nodeFabl3PeersStatus.NADRefs, nadFabL3Peer)
	}
	return nodeFabl3PeersStatus
}

func (cont *AciController) updateNodeFabricNetworkL3Peer(lock_held bool) {
	if cont.unitTestMode {
		return
	}
	nodeFabricL3Peers, err := cont.fabNetAttClient.AciV1().NodeFabricNetworkL3Peers().Get(context.TODO(), "nodefabricnetworkl3peer", metav1.GetOptions{})
	if err == nil {
		nodeFabricL3Peers.Status = *cont.computeNodeFabricNetworkL3PeerStatus(lock_held)
		_, err = cont.fabNetAttClient.AciV1().NodeFabricNetworkL3Peers().Update(context.TODO(), nodeFabricL3Peers, metav1.UpdateOptions{})
		if err != nil {
			cont.log.Errorf("Failed to update NodeFabricL3Peers: %v", err)
		}
	} else if apierrors.IsNotFound(err) {
		nodeFabricL3Peers = &fabattv1.NodeFabricNetworkL3Peer{
			ObjectMeta: metav1.ObjectMeta{Name: "nodefabricnetworkl3peer",
				OwnerReferences: []metav1.OwnerReference{}},
			Status: *cont.computeNodeFabricNetworkL3PeerStatus(lock_held),
		}
		_, err = cont.fabNetAttClient.AciV1().NodeFabricNetworkL3Peers().Create(context.TODO(), nodeFabricL3Peers, metav1.CreateOptions{})
		if err != nil {
			cont.log.Errorf("Failed to update NodeFabricNetworkL3Peer: %v", err)
		}
	} else {
		cont.log.Errorf("%v. Skip updating NodeFabricNetworkL3Peer", err)
	}
}

func (cont *AciController) deleteNodeFabricNetworkL3Peer() {
	_, err := cont.fabNetAttClient.AciV1().NodeFabricNetworkL3Peers().Get(context.TODO(), "nodefabricnetworkl3peer", metav1.GetOptions{})
	if err == nil {
		err = cont.fabNetAttClient.AciV1().NodeFabricNetworkL3Peers().Delete(context.TODO(), "nodefabricnetworkl3peer", metav1.DeleteOptions{})
		if err != nil {
			cont.log.Errorf("Failed to update NodeFabricNetworkL3Peer: %v", err)
		}
	} else if !apierrors.IsNotFound(err) {
		cont.log.Errorf("%v. Failed to delete NodeFabricNetworkL3Peer", err)
	}
}
