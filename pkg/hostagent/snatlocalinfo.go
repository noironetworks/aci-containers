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
	snatLocalInfov1 "github.com/noironetworks/aci-containers/pkg/snatlocalinfo/apis/aci.snat/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"reflect"
)

type SnatLocalInfo struct {
	snatIp         string
	destIps        []string
	snatpolicyName string
}

func (agent *HostAgent) UpdateLocalInfoCr() bool {
	env := agent.env.(*K8sEnvironment)
	snatLocalInfoClient := env.snatLocalInfoClient
	if snatLocalInfoClient == nil {
		agent.log.Debug("snatLocalInfo or Kube clients are not intialized")
		return false
	}
	agent.indexMutex.Lock()
	ginfos, ok := agent.opflexSnatGlobalInfos[agent.config.NodeName]
	if !ok {
		return false
		agent.indexMutex.Unlock()
	}

	snatLocalInfo := make(map[string]SnatLocalInfo)
	for _, ginfo := range ginfos {
		var localInfo SnatLocalInfo
		localInfo.snatIp = ginfo.SnatIp
		if _, ok := agent.snatPolicyCache[ginfo.SnatPolicyName]; ok {
			if len(agent.snatPolicyCache[ginfo.SnatPolicyName].Spec.DestIp) == 0 {
				localInfo.destIps = []string{"0.0.0.0/0"}
			} else {
				localInfo.destIps =
					agent.snatPolicyCache[ginfo.SnatPolicyName].Spec.DestIp
			}
		}
		localInfo.snatpolicyName = ginfo.SnatPolicyName
		snatLocalInfo[ginfo.SnatIpUid] = localInfo
	}
	localInfos := make(map[string]snatLocalInfov1.LocalInfo)
	for uid, v := range agent.opflexSnatLocalInfos {
		var localinfo snatLocalInfov1.LocalInfo
		localinfo.SnatIpToDests = make(map[string][]string)
		for _, plcyUid := range v.PlcyUuids {
			if linfo, ok := snatLocalInfo[plcyUid]; ok {
				localinfo.SnatIpToDests[linfo.snatIp] = linfo.destIps
				localinfo.SnatPolicyNames = append(localinfo.SnatPolicyNames, linfo.snatpolicyName)
			}
		}
		existing, ok := agent.opflexEps[uid]
		if ok {
			// @TODO need revisit this code how to copy the podName and Namespace
			for _, ep := range existing {
				localinfo.PodName = ep.Attributes["vm-name"]
				localinfo.PodNamespace = ep.Attributes["namespace"]
				break
			}
		}
		localInfos[uid] = localinfo
	}
	agent.indexMutex.Unlock()
	snatLocalInfoCr, err := snatLocalInfoClient.AciV1().SnatLocalInfos(agent.config.AciSnatNamespace).Get(context.TODO(), agent.config.NodeName, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			snatLocalInfoInstance := &snatLocalInfov1.SnatLocalInfo{
				ObjectMeta: metav1.ObjectMeta{
					Name:      agent.config.NodeName,
					Namespace: agent.config.AciSnatNamespace,
				},
				Spec: snatLocalInfov1.SnatLocalInfoSpec{
					LocalInfos: localInfos,
				},
			}
			_, err = snatLocalInfoClient.AciV1().SnatLocalInfos(agent.config.AciSnatNamespace).Create(context.TODO(), snatLocalInfoInstance, metav1.CreateOptions{})
		}
	} else {
		if !reflect.DeepEqual(snatLocalInfoCr.Spec.LocalInfos, localInfos) {
			snatLocalInfoCr.Spec.LocalInfos = localInfos
			_, err = snatLocalInfoClient.AciV1().SnatLocalInfos(agent.config.AciSnatNamespace).Update(context.TODO(), snatLocalInfoCr, metav1.UpdateOptions{})
		}
	}
	if err == nil {
		agent.log.Debug("SnatLocalInfo  Update Successful..")
		return false
	}
	return true
}
