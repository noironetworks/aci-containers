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
	nodeinfov1 "github.com/noironetworks/aci-containers/pkg/nodeinfo/apis/aci.snat/v1"
	nodeinfoclientset "github.com/noironetworks/aci-containers/pkg/nodeinfo/clientset/versioned"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (agent *HostAgent) InformNodeInfo(nodeInfoClient *nodeinfoclientset.Clientset) {
	if nodeInfoClient == nil {
		agent.log.Debug("nodeinfo or Kube clients are not intialized")
		return
	}
	nodeInfoInstance := &nodeinfov1.NodeInfo{
		ObjectMeta: metav1.ObjectMeta{
			Name:      agent.config.NodeName,
			Namespace: agent.config.AciSnatNamespace,
		},
		Spec: nodeinfov1.NodeInfoSpec{
			Nodename:   agent.config.NodeName,
			Macaddress: agent.config.UplinkMacAdress,
		},
	}
	result, err := nodeInfoClient.AciV1().NodeInfos(agent.config.AciSnatNamespace).Create(nodeInfoInstance)
	if err == nil {
		agent.log.Debug("NodeInfo CR is created: ", result)
	} else if apierrors.IsAlreadyExists(err) {
		agent.log.Debug("Node info CR already exists: ", result)
	} else {
		agent.log.Error("Failed to Create Node info CR, namespace not valid: ", agent.config.AciSnatNamespace)
	}
}
