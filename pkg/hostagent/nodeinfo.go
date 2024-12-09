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
// WITHOUT WARRATIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// creates snat crs.

package hostagent

import (
	"context"
	"reflect"

	nodeInfov1 "github.com/noironetworks/aci-containers/pkg/nodeinfo/apis/aci.snat/v1"
	nodeInfoclientset "github.com/noironetworks/aci-containers/pkg/nodeinfo/clientset/versioned"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (agent *HostAgent) InformNodeInfo(nodeInfoClient *nodeInfoclientset.Clientset, snatpolicies map[string]bool, uplinkMacAddress string) bool {
	if nodeInfoClient == nil {
		agent.log.Debug("nodeInfo or Kube clients are not intialized")
		return true
	}
	nodeInfo, err := nodeInfoClient.AciV1().NodeInfos(agent.config.AciSnatNamespace).Get(context.TODO(), agent.config.NodeName, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			nodeInfoInstance := &nodeInfov1.NodeInfo{
				ObjectMeta: metav1.ObjectMeta{
					Name:      agent.config.NodeName,
					Namespace: agent.config.AciSnatNamespace,
				},
				Spec: nodeInfov1.NodeInfoSpec{
					SnatPolicyNames: snatpolicies,
					Macaddress:      uplinkMacAddress,
				},
			}
			_, err = nodeInfoClient.AciV1().NodeInfos(agent.config.AciSnatNamespace).Create(context.TODO(), nodeInfoInstance, metav1.CreateOptions{})
			if err != nil {
				agent.log.Debugf("Failed to create NodeInfo: %s, err: %v, instance: %+v", nodeInfo.ObjectMeta.Name, err, nodeInfoInstance)
			}
		}
	} else {
		if !reflect.DeepEqual(nodeInfo.Spec.SnatPolicyNames, snatpolicies) || nodeInfo.Spec.Macaddress != uplinkMacAddress {
			nodeInfo.Spec.SnatPolicyNames = snatpolicies
			nodeInfo.Spec.Macaddress = uplinkMacAddress
			_, err = nodeInfoClient.AciV1().NodeInfos(agent.config.AciSnatNamespace).Update(context.TODO(), nodeInfo, metav1.UpdateOptions{})
			if err != nil {
				agent.log.Debugf("Failed to update NodeInfo: %s, err: %v", nodeInfo.ObjectMeta.Name, err)
			}
		} else {
			// This case can hit restart of the Hostagent and having  same number of policeis present in nodinfo crd.
			agent.indexMutex.Lock()
			var poduids []string
			for name := range snatpolicies {
				for uuid := range agent.snatPods[name] {
					poduids = append(poduids, uuid)
				}
			}
			agent.updateEpFiles(poduids)
			agent.indexMutex.Unlock()
		}
	}
	if err == nil {
		agent.log.Debugf("NodeInfo Update Successful for: %s", nodeInfo.ObjectMeta.Name)
		return true
	}
	agent.log.Warn("NodeInfo update failed: ", err)
	return false
}
