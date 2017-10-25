// Copyright 2017 Cisco Systems, Inc.
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
	"github.com/Sirupsen/logrus"

	md "github.com/noironetworks/aci-containers/pkg/metadata"
)

type CfEnvironment struct {
}

func NewCfEnvironment(config *HostAgentConfig, log *logrus.Logger) (*CfEnvironment, error) {
	return &CfEnvironment{}, nil
}

func (env *CfEnvironment) Init(agent *HostAgent) error {
	return nil
}

func (env *CfEnvironment) PrepareRun(stopCh <-chan struct{}) error {
	return nil
}

func (env *CfEnvironment) CniDeviceChanged(metadataKey *string, id *md.ContainerId) {
}

func (env *CfEnvironment) CniDeviceDeleted(metadataKey *string, id *md.ContainerId) {
}

func (env *CfEnvironment) CheckPodExists(metadataKey *string) (bool, error) {
return false, nil
}
