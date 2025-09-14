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
package webhook

import (
	nadhdlr "github.com/noironetworks/aci-containers/pkg/webhook/networkattachmentdefinition"
	nfchdlr "github.com/noironetworks/aci-containers/pkg/webhook/networkfabricconfiguration"
	nfl3confighdlr "github.com/noironetworks/aci-containers/pkg/webhook/networkfabricl3configuration"
	podhdlr "github.com/noironetworks/aci-containers/pkg/webhook/pods"
	aciwebhooktypes "github.com/noironetworks/aci-containers/pkg/webhook/types"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
)

var (
	registeredWebHooks map[string]*webhook.Admission
	WebHookConfig      *aciwebhooktypes.Config
)

func init() {
	registeredWebHooks = make(map[string]*webhook.Admission)
}

func AddWebHookHandlerToManager(mgr *aciwebhooktypes.Manager) {
	if WebHookConfig == nil {
		WebHookConfig = &mgr.Config
		//Register NAD webhooks
		nadhdlr.RegisterHandlers(WebHookConfig, registeredWebHooks)
		if mgr.Config.ChainedModeEnabled {
			//Register Pod webhooks
			podhdlr.RegisterHandlers(WebHookConfig, registeredWebHooks)
			nfchdlr.RegisterHandlers(WebHookConfig, registeredWebHooks)
			nfl3confighdlr.RegisterHandlers(WebHookConfig, registeredWebHooks)
		}
	}
	for path, hdlr := range registeredWebHooks {
		mgr.Mgr.GetWebhookServer().Register(path, hdlr)
	}
}
