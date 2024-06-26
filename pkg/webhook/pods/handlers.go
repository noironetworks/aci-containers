// Copyright 2023,2024 Cisco Systems, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package pods

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	aciwebhooktypes "github.com/noironetworks/aci-containers/pkg/webhook/types"
	"gomodules.xyz/jsonpatch/v2"
	admv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	. "sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

const (
	cncfNetworkAnnotation  = "k8s.v1.cni.cncf.io/networks"
	fabattInjectAnnotation = "netop-cni.cisco.com/fabric-l3peer-inject"
)

var (
	// Build webhooks used for the various server
	// configuration options
	//
	// These handlers could be also be implementations
	// of the AdmissionHandler interface for more complex
	// implementations.
	ResourceName = "pod"
	MutatingHook = &Admission{
		Handler: admission.HandlerFunc(addPeeringInfotoPod),
	}

	ValidatingHook = &Admission{
		Handler: admission.HandlerFunc(func(ctx context.Context, req AdmissionRequest) AdmissionResponse {
			return Allowed("No required validation as of now")
		}),
	}
	Config = &aciwebhooktypes.Config{}
)

func RegisterHandlers(config *aciwebhooktypes.Config, registry map[string]*Admission) {
	Config = config
	mutatePath := fmt.Sprintf("/mutate-%s", ResourceName)
	registry[mutatePath] = MutatingHook
	validatePath := fmt.Sprintf("/validate-%s", ResourceName)
	registry[validatePath] = ValidatingHook
}

func addPeeringInfotoPod(ctx context.Context, req AdmissionRequest) AdmissionResponse {
	if req.Operation != admv1.Create {
		return Allowed("no op")
	}

	raw := req.Object.Raw
	pod := &corev1.Pod{}
	err := json.Unmarshal(raw, &pod)
	if err != nil {
		ctrl.Log.Info("Bad request while servicing pods")
		return Errored(http.StatusBadRequest, err)
	}
	prefixStr := fmt.Sprintf("PodHandler: %s/%s: ", pod.Namespace, pod.Name)
	webhookHdlrLog := ctrl.Log.WithName(prefixStr)

	l3peerInject, ok := pod.ObjectMeta.Annotations[fabattInjectAnnotation]
	if !ok {
		return Allowed("netop-cni.cisco.com/fabric-l3peer-inject annotation not present: no op")
	}
	if l3peerInject == "" {
		webhookHdlrLog.Info("netop-cni.cisco.com/fabric-l3peer-inject list is empty : no op")
		return Allowed("netop-cni.cisco.com/fabric-l3peer-inject is empty: no op")
	}

	injectNetworks := strings.Split(l3peerInject, ",")
	injectMap := make(map[string]bool)
	finalInjectMap := make(map[string]bool)
	for _, nw := range injectNetworks {
		nw2 := strings.TrimSpace(nw)
		injectMap[nw2] = true
	}

	secondaryNetworkStr, hasSecondaryNetworks := pod.ObjectMeta.Annotations[cncfNetworkAnnotation]
	if !hasSecondaryNetworks {
		webhookHdlrLog.Info("Pod is not part of any secondary networks: no op")
		return Allowed("Pod is not part of any secondary networks: no op")
	}
	secondaryNetworks := strings.Split(secondaryNetworkStr, ",")
	for _, secondaryNetwork := range secondaryNetworks {
		secondaryNw := strings.TrimSpace(secondaryNetwork)
		if _, ok := injectMap[secondaryNw]; ok {
			finalInjectMap[secondaryNw] = true
		}
	}

	envVars := []corev1.EnvVar{}
	Config.CommonMutex.Lock()
	for nw := range finalInjectMap {
		namespace := pod.Namespace
		if namespace == "" {
			namespace = "default"
		}
		nadKey := namespace + "/" + nw
		nwData, adjOk := Config.FabricAdjs[nadKey]
		if !adjOk {
			webhookHdlrLog.Error(err, "No peering info yet for ", "NAD", nw)
			continue
		}
		if nodeData, ok := nwData[pod.Spec.NodeName]; ok {
			// For now, only consider the least encap in a NAD
			// If at all, a NAD needs to include more than one vlan,
			// there needs to be some annotation on the pod that indicates
			// what vlan the container is intending to use.
			minEncap := 4096
			for encap := range nodeData {
				if encap < minEncap {
					minEncap = encap
				}
			}
			fabPeerInfo, peerInfoOk := Config.FabricPeerInfo[minEncap]
			if !peerInfoOk {
				webhookHdlrLog.Error(err, "No peering info for ", "NAD", nw)
				continue
			}
			fabricPeers := []string{}
			for _, fabricPeer := range nodeData[minEncap] {
				if addr, ok := fabPeerInfo.Peers[fabricPeer]; ok {
					fabricPeers = append(fabricPeers, addr)
				}
			}
			for _, envKey := range []string{"BGP_ASN", "BGP_PEERING_ENDPOINTS", "BGP_SECRET_PATH"} {
				var envVal string
				switch envKey {
				case "BGP_ASN":
					{
						envVal = fmt.Sprintf("%d", fabPeerInfo.ASN)
					}
				case "BGP_PEERING_ENDPOINTS":
					{
						envVal = fmt.Sprintf("%v", strings.Join(fabricPeers, ","))

					}
				case "BGP_SECRET_PATH":
					{
						if fabPeerInfo.Secret.Name != "" {
							envVal = fmt.Sprintf("%s/%s", fabPeerInfo.Secret.Namespace, fabPeerInfo.Secret.Name)
						}
					}
				}
				envVarKey := fmt.Sprintf("CNO_%s_%s", envKey, nw)
				envVars = append(envVars, corev1.EnvVar{Name: envVarKey, Value: envVal})
			}
		}
	}
	Config.CommonMutex.Unlock()
	if len(envVars) == 0 {
		webhookHdlrLog.Info("No resolved adjacencies yet")
		return Allowed("No resolved adjacencies yet")
	}
	targetContainerIndices := []int{}
	for idx, cntnr := range pod.Spec.Containers {
		if strings.Contains(cntnr.Name, Config.ContainerName) {
			targetContainerIndices = append(targetContainerIndices, idx)
		}
	}
	if len(targetContainerIndices) == 0 {
		webhookHdlrLog.Info("Named container not present: no op")
		return Allowed("Named container not present: no op")
	}

	jsonOps := []jsonpatch.Operation{}
	for idx := range targetContainerIndices {
		path := fmt.Sprintf("/spec/containers/%d/env", idx)
		jsonOps = append(jsonOps, JSONPatchOp{Operation: "add", Path: path, Value: envVars})
	}
	webhookHdlrLog.Info("Inserting fabric peering environment variables")
	return Patched("Insert Fabric peers", jsonOps...)
}
