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
	"strings"

	aciwebhooktypes "github.com/noironetworks/aci-containers/pkg/webhook/types"
	"gomodules.xyz/jsonpatch/v2"
	admv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	restclient "k8s.io/client-go/rest"
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
	config.EligiblePods = make(map[string]bool)
	mutatePath := fmt.Sprintf("/mutate-%s", ResourceName)
	registry[mutatePath] = MutatingHook
	validatePath := fmt.Sprintf("/validate-%s", ResourceName)
	registry[validatePath] = ValidatingHook
}

func createConfigMaps(kubeClient *kubernetes.Clientset, pod *corev1.Pod, podNode string, finalInjectMap map[string]bool) {
	prefixStr := fmt.Sprintf("PodHandler: %s/%s: ", pod.Namespace, pod.Name)
	webhookHdlrLog := ctrl.Log.WithName(prefixStr)
	err := fmt.Errorf("envVar insertion failed")
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
		webhookHdlrLog.Info("NwData: ", "nwData", nwData, "nodeName", podNode)
		if nodeData, ok := nwData[podNode]; ok {
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
				return
			}
			fabricPeers := []string{}
			for _, fabricPeer := range nodeData[minEncap] {
				if addr, ok := fabPeerInfo.Peers[fabricPeer]; ok {
					fabricPeers = append(fabricPeers, addr)
				}
			}
			configMapName := pod.Name + "-" + nw + "-bgp-config"
			cfgMap := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: configMapName,
					Namespace: pod.Namespace},
				Data: make(map[string]string),
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
				cfgMap.Data[envKey] = envVal
			}
			configMap, err := kubeClient.CoreV1().ConfigMaps(pod.Namespace).Get(context.TODO(), configMapName, metav1.GetOptions{})
			if err != nil {
				if apierrors.IsNotFound(err) {
					_, err = kubeClient.CoreV1().ConfigMaps(pod.Namespace).Create(context.TODO(), cfgMap, metav1.CreateOptions{})
					if err != nil {
						webhookHdlrLog.Error(err, "")
					} else {
						webhookHdlrLog.Info("Created ", "configmap", pod.Namespace+"/"+configMapName)
					}
				} else {
					webhookHdlrLog.Error(err, "")
				}
			} else {
				configMap.Data = cfgMap.Data
				_, err = kubeClient.CoreV1().ConfigMaps(pod.Namespace).Update(context.TODO(), configMap, metav1.UpdateOptions{})
				if err != nil {
					webhookHdlrLog.Error(err, "")
				} else {
					webhookHdlrLog.Info("Updated ", "configmap", pod.Namespace+"/"+configMapName)
				}
			}
		}
	}
	Config.CommonMutex.Unlock()
}

func deleteConfigMaps(kubeClient *kubernetes.Clientset, pod *corev1.Pod, finalInjectMap map[string]bool) {
	prefixStr := fmt.Sprintf("PodHandler: %s/%s: ", pod.Namespace, pod.Name)
	webhookHdlrLog := ctrl.Log.WithName(prefixStr)
	for nw := range finalInjectMap {
		configMapName := pod.Name + "-" + nw + "-bgp-config"
		err := kubeClient.CoreV1().ConfigMaps(pod.Namespace).Delete(context.TODO(), configMapName, metav1.DeleteOptions{})
		if err != nil && !apierrors.IsNotFound(err) {
			webhookHdlrLog.Error(err, "")
		} else if err == nil {
			webhookHdlrLog.Info("Deleted ", "configmap", pod.Namespace+"/"+configMapName)
		}
	}
	podKey := pod.Namespace + "/" + pod.Name
	delete(Config.EligiblePods, podKey)
}

func patchPod(targetContainerIndices []int, pod *corev1.Pod, finalInjectMap map[string]bool) []jsonpatch.Operation {
	prefixStr := fmt.Sprintf("PodHandler: %s/%s: ", pod.Namespace, pod.Name)
	webhookHdlrLog := ctrl.Log.WithName(prefixStr)
	jsonOps := []jsonpatch.Operation{}
	envVars := []corev1.EnvVar{}
	for nw := range finalInjectMap {
		configMapName := pod.Name + "-" + nw + "-bgp-config"
		for _, envKey := range []string{"BGP_ASN", "BGP_PEERING_ENDPOINTS", "BGP_SECRET_PATH"} {
			optional := true
			envVarKey := envKey + "_" + strings.ToUpper(nw)
			envVars = append(envVars, corev1.EnvVar{Name: envVarKey,
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{Name: configMapName},
						Key:                  envKey,
						Optional:             &optional}}})
		}
		for idx := range targetContainerIndices {
			path := fmt.Sprintf("/spec/containers/%d/env", idx)
			jsonOps = append(jsonOps, JSONPatchOp{Operation: "add", Path: path, Value: envVars})
		}
	}
	webhookHdlrLog.Info("Inserting fabric peering environment variables")
	return jsonOps
}

func addPeeringInfotoPod(ctx context.Context, req AdmissionRequest) AdmissionResponse {
	if req.Operation != admv1.Create && req.Operation != admv1.Delete {
		return Allowed("no op")
	}
	raw := req.Object.Raw
	binding := &corev1.Binding{}
	pod := &corev1.Pod{}
	if req.RequestKind.Kind == "Binding" {
		if req.Operation == admv1.Delete {
			return Allowed("no op")
		}
		if err := json.Unmarshal(raw, binding); err != nil {
			ctrl.Log.Error(err, "Bad request while servicing binding", "")
			return Allowed("Could not deserialize binding object")
		}
		pod.Name = binding.Name
		pod.Namespace = binding.Namespace
		podKey := pod.Namespace + "/" + pod.Name
		if _, ok := Config.EligiblePods[podKey]; !ok {
			return Allowed("Pod not seen or not eligible: no op")
		}
		ctrl.Log.Info("Binding:", "podName", pod.Name, "podNamespace", pod.Namespace, "node", binding.Target.Name)
	}
	if req.RequestKind.Kind == "Pod" {
		if req.Operation == admv1.Delete {
			raw = req.OldObject.Raw
		}
		err := json.Unmarshal(raw, pod)
		if err != nil {
			ctrl.Log.Error(err, "Bad request while servicing pods")
			return Allowed("Bad request while servicing pods")
		}
	}
	prefixStr := fmt.Sprintf("PodHandler: %s/%s: ", pod.Namespace, pod.Name)
	webhookHdlrLog := ctrl.Log.WithName(prefixStr)
	podNode := pod.Spec.NodeName

	restconfig, err := restclient.InClusterConfig()
	if err != nil {
		webhookHdlrLog.Error(err, "failed to initialize restclient ")
		return Allowed("Failed to initialize restclient")
	}
	kubeClient, err := kubernetes.NewForConfig(restconfig)
	if err != nil {
		webhookHdlrLog.Error(err, "failed to initialize kubeclient")
		return Allowed("Failed to initialize kubeclient")
	}

	// Fetch source pod if we came here through a binding update
	if len(pod.Spec.Containers) == 0 {
		pod, err = kubeClient.CoreV1().Pods(pod.Namespace).Get(context.TODO(), pod.Name, metav1.GetOptions{})
		if err != nil {
			webhookHdlrLog.Error(err, "failed to get pod ")
			return Allowed("failed to get node name")
		}
		if binding.Target.Name == "" && podNode == "" {
			return Allowed("failed to get node name")
		}
		if podNode == "" {
			podNode = binding.Target.Name
		}
	}

	// Check for injectable annotation
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

	// Check for membership in injectable networks
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
	// Check for named containers
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

	// Handle cleanup on Pod delete
	if req.RequestKind.Kind == "Pod" && req.Operation == admv1.Delete {
		deleteConfigMaps(kubeClient, pod, finalInjectMap)
		return Allowed("Deleted relevant configmaps")
	}
	// Cache eligible podkeys for configmap creation at bindtime
	if len(finalInjectMap) != 0 {
		podKey := pod.Namespace + "/" + pod.Name
		Config.EligiblePods[podKey] = true
	}

	// Insert envVars into Pod
	jsonOps := []jsonpatch.Operation{}
	if req.RequestKind.Kind == "Pod" {
		jsonOps = patchPod(targetContainerIndices, pod, finalInjectMap)
	}

	//Create configmaps if we have nodeData for statically scheduled pods or with separate binding
	if podNode != "" {
		createConfigMaps(kubeClient, pod, podNode, finalInjectMap)
	}
	if req.RequestKind.Kind == "Pod" {
		return Patched("Insert Fabric peers", jsonOps...)
	}
	return Allowed(": no op")
}
