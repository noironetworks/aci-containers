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

// Handlers for AIM ThirdPartyResource updates.  Allows creating
// objects in Kubernetes API that will be automatically synced into an
// APIC controller

package controller

import (
	"encoding/json"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type Aci struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`

	Spec AciObjectSpec `json:"spec"`
}

type AciList struct {
	metav1.TypeMeta `json:",inline"`
	Metadata        metav1.ListMeta `json:"metadata"`

	Items []Aci `json:"items"`
}

// Required to satisfy Object interface
func (ao *Aci) GetObjectKind() schema.ObjectKind {
	return &ao.TypeMeta
}

// Required to satisfy ObjectMetaAccessor interface
func (ao *Aci) GetObjectMeta() metav1.Object {
	return &ao.ObjectMeta
}

// Required to satisfy Object interface
func (aol *AciList) GetObjectKind() schema.ObjectKind {
	return &aol.TypeMeta
}

// Required to satisfy ListMetaAccessor interface
func (aol *AciList) GetListMeta() metav1.List {
	return &aol.Metadata
}

// The code below is used only to work around a known problem with third-party
// resources and ugorji. If/when these issues are resolved, the code below
// should no longer be required.

type AciListCopy AciList
type AciCopy Aci

func (ao *Aci) UnmarshalJSON(data []byte) error {
	tmp := AciCopy{}
	err := json.Unmarshal(data, &tmp)
	if err != nil {
		return err
	}
	tmp2 := Aci(tmp)
	*ao = tmp2
	return nil
}

func (ao *AciList) UnmarshalJSON(data []byte) error {
	tmp := AciListCopy{}
	err := json.Unmarshal(data, &tmp)
	if err != nil {
		return err
	}
	tmp2 := AciList(tmp)
	*ao = tmp2
	return nil
}
