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
	v1 "k8s.io/api/core/v1"
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
		agent.indexMutex.Unlock()
		return agent.deleteLocalInfoCr()
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
	var localInfos []snatLocalInfov1.LocalInfo
	for uid, v := range agent.opflexSnatLocalInfos {
		var localinfo snatLocalInfov1.LocalInfo
		var policies []snatLocalInfov1.SnatPolicy
		for _, plcyUid := range v.PlcyUuids {
			if linfo, ok := snatLocalInfo[plcyUid]; ok {
				var policy snatLocalInfov1.SnatPolicy
				policy.SnatIp = linfo.snatIp
				policy.DestIp = linfo.destIps
				policy.Name = linfo.snatpolicyName
				policies = append(policies, policy)
			}
		}
		epkey := agent.podUidToName[uid]
		podobj, exists, err := agent.podInformer.GetStore().GetByKey(epkey)
		if exists && err == nil {
			pod := podobj.(*v1.Pod)
			localinfo.PodName = pod.ObjectMeta.Name
			localinfo.PodNamespace = pod.ObjectMeta.Namespace
			agent.log.Debug("PodName:", localinfo.PodName)
		}
		localinfo.PodUid = uid
		localinfo.SnatPolicies = policies
		if len(policies) > 0 {
			localInfos = append(localInfos, localinfo)
		}
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
		Spec := snatLocalInfov1.SnatLocalInfoSpec{
			LocalInfos: localInfos,
		}
		if !reflect.DeepEqual(snatLocalInfoCr.Spec, Spec) {
			snatLocalInfoCr.Spec = Spec
			_, err = snatLocalInfoClient.AciV1().SnatLocalInfos(agent.config.AciSnatNamespace).Update(context.TODO(), snatLocalInfoCr, metav1.UpdateOptions{})
		}
	}
	if err == nil {
		agent.log.Debug("SnatLocalInfo  Update Successful..")
		return false
	}
	return true
}

func (agent *HostAgent) deleteLocalInfoCr() bool {
	env := agent.env.(*K8sEnvironment)
	snatLocalInfoClient := env.snatLocalInfoClient
	_, err := snatLocalInfoClient.AciV1().SnatLocalInfos(agent.config.AciSnatNamespace).Get(context.TODO(), agent.config.NodeName, metav1.GetOptions{})
	if err == nil {
		err = snatLocalInfoClient.AciV1().SnatLocalInfos(agent.config.AciSnatNamespace).Delete(context.TODO(), agent.config.NodeName, metav1.DeleteOptions{})
		if err != nil {
			agent.log.Debug("SnatLocalInfo failed to delete: ", err)
			return true
		}
	}
	return false
}
