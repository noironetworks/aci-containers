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
	nodeinfov1 "github.com/noironetworks/aci-containers/pkg/nodeinfo/apis/aci.nodeinfo/v1"
	nodeinfoclientset "github.com/noironetworks/aci-containers/pkg/nodeinfo/clientset/versioned"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
)

func (agent *HostAgent) InformNodeInfo(nodeInfoClient *nodeinfoclientset.Clientset,
	kubeClient *kubernetes.Clientset) {
	if nodeInfoClient == nil || kubeClient == nil {
		return
	}
	label := make(map[string]string, 0)
	label["name"] = "aci-containers-host"
	options := metav1.ListOptions{
		LabelSelector: labels.Set(label).String(),
		FieldSelector: fields.Set{"spec.nodeName": agent.config.NodeName}.String(),
	}
	existingPods, err1 := kubeClient.Core().Pods("").List(options)

	if err1 != nil {
		agent.log.Debug("failed to list existing pods in the podSet", err1)
		return
	}
	var namespace string
	// selecting the first pod under label aci-containers-host
	for _, v := range existingPods.Items {
		namespace = v.GetObjectMeta().GetNamespace()
		break
	}
	nodeInfoInstance := &nodeinfov1.Nodeinfo{
		ObjectMeta: metav1.ObjectMeta{
			Name:      agent.config.NodeName,
			Namespace: namespace,
		},
		Spec: nodeinfov1.NodeinfoSpec{
			Nodename:   agent.config.NodeName,
			Macaddress: agent.config.UplinkMacAdress,
		},
	}
	result, err := nodeInfoClient.AciV1().Nodeinfos(namespace).Create(nodeInfoInstance)
	if err == nil {
		agent.log.Debug("NodeInfo CR is created", result)
	} else if apierrors.IsAlreadyExists(err) {
		agent.log.Debug("Already exists: %#\n", result)
	} else {
		panic(err)
	}
}
