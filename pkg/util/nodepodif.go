// Copyright 2021 Cisco Systems, Inc.
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

package util

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	nc "github.com/noironetworks/aci-containers/pkg/nodepodif/clientset/versioned"
)

// DeleteNodePodIfCR Deletes a NodePodIf CR
func DeleteNodePodIfCR(c nc.Clientset, name string) error {
	err := c.AciV1().NodePodIFs("kube-system").Delete(context.TODO(), name, metav1.DeleteOptions{})
	if err != nil {
		return err
	}
	return nil
}
