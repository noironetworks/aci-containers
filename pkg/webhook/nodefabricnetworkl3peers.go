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

// Handlers for node fabric network l3 peer updates.

package webhook

import (
	"context"
	"fmt"

	fabattv1 "github.com/noironetworks/aci-containers/pkg/fabricattachment/apis/aci.fabricattachment/v1"
	types "github.com/noironetworks/aci-containers/pkg/webhook/types"
	"k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// ReconcileNFL3Peers reconciles NodeFabricNetworkL3Peer
type ReconcileNFL3Peers struct {
	// client can be used to retrieve objects from the APIServer.
	Client client.Client
	Config *types.RunTimeData
}

func (r *ReconcileNFL3Peers) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	prefixStr := fmt.Sprintf("NFNL3Peers Reconciler: ")
	log := ctrl.Log.WithName(prefixStr)
	log.Info(fmt.Sprintf("Handling %v", request.NamespacedName))
	r.Config.CommonMutex.Lock()
	defer r.Config.CommonMutex.Unlock()
	nfL3Peers := &fabattv1.NodeFabricNetworkL3Peer{}
	err := r.Client.Get(ctx, request.NamespacedName, nfL3Peers)
	if errors.IsNotFound(err) {
		log.Error(nil, "Could not find NodeFabricNetworkL3Peers")
		r.Config.FabricAdjs = make(map[string]map[string]map[int][]int)
		r.Config.FabricPeerInfo = make(map[int]*types.FabricPeeringInfo)
		return reconcile.Result{}, nil
	}

	if err != nil {
		return reconcile.Result{}, fmt.Errorf("could not fetch NodeFabricNetworkL3Peers: %+v", err)
	}
	encapVisited := map[int]bool{}
	for _, peerInfo := range nfL3Peers.Status.PeeringInfo {
		fabricPeeringInfo := &types.FabricPeeringInfo{
			Encap:  peerInfo.Encap,
			ASN:    peerInfo.ASN,
			Secret: peerInfo.Secret,
			Peers:  make(map[int]string),
		}
		for _, fabNode := range peerInfo.FabricNodes {
			fabricPeeringInfo.Peers[fabNode.NodeRef.NodeId] = fabNode.PrimaryAddress
		}
		r.Config.FabricPeerInfo[peerInfo.Encap] = fabricPeeringInfo
		encapVisited[peerInfo.Encap] = true
	}

	currMap := make(map[string]map[string]map[int]bool)
	for _, nadRef := range nfL3Peers.Status.NADRefs {
		nadKey := nadRef.NAD.Namespace + "/" + nadRef.NAD.Name
		currMap[nadKey] = make(map[string]map[int]bool)
		if _, ok := r.Config.FabricAdjs[nadKey]; !ok {
			r.Config.FabricAdjs[nadKey] = make(map[string]map[int][]int)
		}
		for _, node := range nadRef.Nodes {
			currMap[nadKey][node.NodeName] = make(map[int]bool)
			if _, ok := r.Config.FabricAdjs[nadKey][node.NodeName]; !ok {
				r.Config.FabricAdjs[nadKey][node.NodeName] = make(map[int][]int)
			}
			for _, fabricNode := range node.FabricL3Peers {
				r.Config.FabricAdjs[nadKey][node.NodeName][fabricNode.Encap] = []int{}
				currMap[nadKey][node.NodeName][fabricNode.Encap] = true
				for _, nodeId := range fabricNode.FabricNodeIds {
					r.Config.FabricAdjs[nadKey][node.NodeName][fabricNode.Encap] = append(r.Config.FabricAdjs[nadKey][node.NodeName][fabricNode.Encap], nodeId)
				}
			}
		}
	}
	// Delete old refs
	encapStr := ""
	for encap := range r.Config.FabricPeerInfo {
		if _, ok := encapVisited[encap]; !ok {
			delete(r.Config.FabricPeerInfo, encap)
		}
		encapStr += fmt.Sprintf("%d,", encap)
	}
	nadKeyStr := ""
	for nadKey, nadData := range r.Config.FabricAdjs {
		if _, ok := currMap[nadKey]; !ok {
			delete(r.Config.FabricAdjs, nadKey)
			continue
		}
		for node, nodeData := range nadData {
			if _, ok := currMap[nadKey][node]; !ok {
				delete(nadData, node)
				continue
			}
			for encap := range nodeData {
				if _, ok := currMap[nadKey][node][encap]; !ok {
					delete(nodeData, encap)
					continue
				}
			}
			nadData[node] = nodeData
		}
		r.Config.FabricAdjs[nadKey] = nadData
		nadKeyStr += nadKey + ","
	}
	statusStr := fmt.Sprintf("Encaps:%d(%s), NADs:%d(%s)", len(r.Config.FabricPeerInfo), encapStr, len(r.Config.FabricAdjs), nadKeyStr)
	log.Info(statusStr)
	return reconcile.Result{}, nil
}
