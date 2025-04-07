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
package networkattachmentdefinition

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	cncfv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	aciwebhooktypes "github.com/noironetworks/aci-containers/pkg/webhook/types"
	admv1 "k8s.io/api/admission/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	. "sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

var (
	// Build webhooks used for the various server
	// configuration options
	//
	// These handlers could be also be implementations
	// of the AdmissionHandler interface for more complex
	// implementations.
	ResourceName = "nad"
	MutatingHook = &Admission{
		Handler: admission.HandlerFunc(addNetopToNAD),
	}

	ValidatingHook = &Admission{
		Handler: admission.HandlerFunc(func(ctx context.Context, req AdmissionRequest) AdmissionResponse {
			return Allowed("No required validation as of now")
		}),
	}
	RequireNADAnnotation = false
)

type Plugin struct {
	SupportedVersions []string `json:"supportedVersions,omitempty"`
	Type              string   `json:"type,omitempty"`
	ChainingMode      bool     `json:"chaining-mode,omitempty"`
	LogLevel          string   `json:"log-level,omitempty"`
	LogFile           string   `json:"log-file,omitempty"`
}

func RegisterHandlers(config *aciwebhooktypes.Config, registry map[string]*Admission) {
	RequireNADAnnotation = config.RequireNADAnnotation
	mutatePath := fmt.Sprintf("/mutate-%s", ResourceName)
	registry[mutatePath] = MutatingHook
	validatePath := fmt.Sprintf("/validate-%s", ResourceName)
	registry[validatePath] = ValidatingHook
}

func getCniType(cniPlugin map[string]interface{}) (string, error) {
	var err error
	var cniType string
	if _, ok := cniPlugin["type"]; !ok {
		err = fmt.Errorf("cni type missing")
	}
	cniType, ok := cniPlugin["type"].(string)
	if !ok {
		err = fmt.Errorf("cni type not a string")
	}
	return cniType, err
}

func addNetopToNAD(ctx context.Context, req AdmissionRequest) AdmissionResponse {
	if (req.Operation != admv1.Create) && (req.Operation != admv1.Update) {
		return Allowed("no op")
	}
	raw := req.Object.Raw
	nad := &cncfv1.NetworkAttachmentDefinition{}
	err := json.Unmarshal(raw, &nad)
	if err != nil {
		return Errored(http.StatusBadRequest, err)
	}
	prefixStr := fmt.Sprintf("NADHandler: %s/%s: ", nad.Namespace, nad.Name)
	webhookHdlrLog := ctrl.Log.WithName(prefixStr)
	var config map[string]interface{}
	nadBytes := bytes.NewBufferString(nad.Spec.Config)
	err = json.Unmarshal(nadBytes.Bytes(), &config)
	if err != nil {
		return Errored(http.StatusBadRequest, err)
	}

	needsUpdate := false
	pluginExists := false
	if name, ok := config["name"]; !ok || name == "" {
		config["name"] = nad.Name
		needsUpdate = true
	}
	if RequireNADAnnotation {
		if enableChaining, ok := nad.ObjectMeta.Annotations["netop-cni.cisco.com/auto-chain-cni"]; !ok {
			webhookHdlrLog.Info("netop-cni.cisco.com/auto-chain-cni annotation not present: no op")
			return Allowed("netop-cni.cisco.com/auto-chain-cni annotation not present: no op")
		} else if enableChaining != "true" {
			webhookHdlrLog.Info("netop-cni.cisco.com/auto-chain-cni != true: no op")
			return Allowed("netop-cni.cisco.com/auto-chain-cni != true: no op")
		}
	}
	netopPlugin := Plugin{
		SupportedVersions: []string{"0.3.0", "0.3.1", "0.4.0, 1.0.0"},
		Type:              "netop-cni",
		ChainingMode:      true,
		LogLevel:          "info",
		LogFile:           "/var/log/netopcni.log",
	}
	if plugins, ok := config["plugins"]; ok {
		cniPlugins := plugins.([]interface{})
		for _, plugin := range cniPlugins {
			cniPlugin := plugin.(map[string]interface{})
			cniType, err := getCniType(cniPlugin)
			if err != nil {
				webhookHdlrLog.Error(err, "Denying invalid cni-plugin config")
				return Errored(http.StatusBadRequest, err)
			}
			if (cniType == "netop-cni") || (cniType == "opflex-agent-cni") {
				pluginExists = true
				break
			}
		}
		if !pluginExists {
			pluginsAsIntf := plugins.([]interface{})
			pluginsAsIntf = append(pluginsAsIntf, netopPlugin)
			config["plugins"] = pluginsAsIntf
			needsUpdate = true
		}
		if needsUpdate {
			newConfig, err := json.Marshal(config)
			if err != nil {
				return Errored(http.StatusBadRequest, err)
			}
			webhookHdlrLog.Info("Appending netop-cni to")
			return Patched("Append Netop-CNI",
				JSONPatchOp{Operation: "replace", Path: "/spec/config", Value: bytes.NewBuffer(newConfig).String()})
		}
	} else {
		cniType, err := getCniType(config)
		if err != nil {
			webhookHdlrLog.Error(err, "Denying invalid cni-plugin config")
			return Errored(http.StatusBadRequest, err)
		}
		if (cniType == "netop-cni") || (cniType == "opflex-agent-cni") {
			webhookHdlrLog.Info("netop-cni already present. Allowing")
			return Allowed("already present")
		}
		stagingConf := make(map[string]interface{})
		if cniVersion, ok := config["cniVersion"]; ok {
			stagingConf["cniVersion"] = cniVersion
		}
		if name, ok := config["name"]; ok {
			stagingConf["name"] = name
		}
		var patchedPlugins []interface{}
		patchedPlugins = append(patchedPlugins, config)
		patchedPlugins = append(patchedPlugins, netopPlugin)
		stagingConf["plugins"] = patchedPlugins
		newConfig, err := json.Marshal(stagingConf)
		if err != nil {
			return Errored(http.StatusBadRequest, err)
		}
		webhookHdlrLog.Info("Inserting netop-cni to")
		return Patched("Insert Netop-CNI",
			JSONPatchOp{Operation: "replace", Path: "/spec/config", Value: bytes.NewBuffer(newConfig).String()})

	}
	return Allowed("No changes required")
}
