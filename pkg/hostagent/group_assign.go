// Copyright 2018 Cisco Systems, Inc.
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
	"encoding/json"

	"github.com/Sirupsen/logrus"

	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	v1net "k8s.io/api/networking/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/noironetworks/aci-containers/pkg/index"
	"github.com/noironetworks/aci-containers/pkg/metadata"
	"github.com/noironetworks/aci-containers/pkg/util"
)

func addGroup(gset map[metadata.OpflexGroup]bool, g []metadata.OpflexGroup,
	tenant string, name string) []metadata.OpflexGroup {
	newg := metadata.OpflexGroup{
		PolicySpace: tenant,
		Name:        name,
	}
	if _, ok := gset[newg]; !ok {
		gset[newg] = true
		g = append(g, newg)
	}
	return g
}

func (agent *HostAgent) mergeNetPolSg(podkey string, pod *v1.Pod,
	namespace *v1.Namespace, sgval []metadata.OpflexGroup) ([]metadata.OpflexGroup, error) {
	gset := make(map[metadata.OpflexGroup]bool)
	var g []metadata.OpflexGroup
	ptypeset := make(map[v1net.PolicyType]bool)

	// Add network policies that directly select this pod
	for _, npkey := range agent.netPolPods.GetObjForPod(podkey) {
		g = addGroup(gset, g, agent.config.DefaultEg.PolicySpace,
			util.AciNameForKey(agent.config.AciPrefix, "np", npkey))
		for _, t := range util.GetNetPolPolicyTypes(agent.netPolInformer.GetIndexer(), npkey) {
			ptypeset[t] = true
		}
	}

	// When the pod is not selected by any network policy, don't apply
	// any extra security groups and return the existing value from
	// the user annotation
	if len(gset) == 0 {
		return sgval, nil
	}

	// Add security groups from the user annotation
	for _, og := range sgval {
		gset[og] = true
		g = append(g, og)
	}

	// Add network policy for accessing the pod's local node
	if pod.Spec.NodeName != "" {
		g = addGroup(gset, g, agent.config.DefaultEg.PolicySpace,
			util.AciNameForKey(agent.config.AciPrefix, "node", pod.Spec.NodeName))
	}

	// Add static-discovery network policy to allow ICMP/ARP
	g = addGroup(gset, g, agent.config.DefaultEg.PolicySpace,
		util.AciNameForKey(agent.config.AciPrefix, "np", "static-discovery"))

	if !ptypeset[v1net.PolicyTypeIngress] {
		// Add static-ingress since no policy applies to ingress
		g = addGroup(gset, g, agent.config.DefaultEg.PolicySpace,
			util.AciNameForKey(agent.config.AciPrefix, "np", "static-ingress"))
	}
	if !ptypeset[v1net.PolicyTypeEgress] {
		// Add static-egress since no policy applies to egress
		g = addGroup(gset, g, agent.config.DefaultEg.PolicySpace,
			util.AciNameForKey(agent.config.AciPrefix, "np", "static-egress"))
	}

	if len(g) == 0 {
		return sgval, nil
	}
	return g, nil
}

func decodeAnnotation(annStr string, into interface{}, logger *logrus.Entry, comment string) {
	logger.Infof("decodeAnnotation: %s -- [%s]", annStr, comment)
	if annStr != "" {
		err := json.Unmarshal([]byte(annStr), &into)
		if err != nil {
			logger.WithFields(logrus.Fields{
				"Annotation": annStr,
			}).Errorf("%s - could not decode annotation: %v", comment, err)
		}
	}
}

// Gets eg, sg annotations on associated deployment or rc
func (agent *HostAgent) getParentAnn(podKey string) (string, string, bool) {
	set := []struct {
		indexer  *index.PodSelectorIndex
		informer cache.SharedIndexInformer
	}{
		{agent.depPods, agent.depInformer},
		{agent.rcPods, agent.rcInformer},
	}
	for _, parent := range set {
		for _, pkey := range parent.indexer.GetObjForPod(podKey) {
			agent.log.Infof("deployment/rc found!")
			obj, exists, err :=
				parent.informer.GetIndexer().GetByKey(pkey)
			if err != nil {
				agent.log.Error("Could not lookup parent " +
					pkey + ": " + err.Error())
				continue
			}
			if exists && obj != nil {
				deployment, ok := obj.(*appsv1.Deployment)
				if ok {
					return deployment.ObjectMeta.Annotations[metadata.EgAnnotation],
						deployment.ObjectMeta.Annotations[metadata.SgAnnotation], true
				}

				rc, ok := obj.(*v1.ReplicationController)
				if ok {
					return rc.ObjectMeta.Annotations[metadata.EgAnnotation],
						rc.ObjectMeta.Annotations[metadata.SgAnnotation], true
				}

			}
		}
	}
	return "", "", false
}

// assignGroups assigns epg and security groups based on annotations on the
// namespace, deployment and pod.
func (agent *HostAgent) assignGroups(pod *v1.Pod) (metadata.OpflexGroup, []metadata.OpflexGroup, error) {
	var egval metadata.OpflexGroup
	var sgval []metadata.OpflexGroup

	logger := podLogger(agent.log, pod)

	podkey, err := cache.MetaNamespaceKeyFunc(pod)
	if err != nil {
		logger.Error("Could not create pod key: ", err)
		return egval, sgval, err
	}

	namespaceobj, exists, err :=
		agent.nsInformer.GetIndexer().GetByKey(pod.ObjectMeta.Namespace)
	if err != nil {
		agent.log.Error("Could not lookup namespace " +
			pod.ObjectMeta.Namespace + ": " + err.Error())
		return egval, sgval, err
	}

	// top-level default annotation
	egval = agent.config.DefaultEg
	sgval = agent.config.DefaultSg

	// configured namespace override has next-highest priority
	if nseg, ok := agent.config.NamespaceDefaultEg[pod.Namespace]; ok {
		egval = nseg
	}

	if nssgs, ok := agent.config.NamespaceDefaultSg[pod.Namespace]; ok {
		sgval = nssgs
	}

	// namespace annotation has next-highest priority
	var namespace *v1.Namespace
	if exists && namespaceobj != nil {
		namespace = namespaceobj.(*v1.Namespace)

		decodeAnnotation(namespace.ObjectMeta.Annotations[metadata.EgAnnotation], &egval, logger, "namespace[EpgAnnotation]")
		decodeAnnotation(namespace.ObjectMeta.Annotations[metadata.SgAnnotation], &sgval, logger, "namespace[SgAnnotation]")
	}

	// annotation on parent deployment or rc is next-highest priority
	egAnn, sgAnn, found := agent.getParentAnn(podkey)
	if found {
		decodeAnnotation(egAnn, &egval, logger, "deployment/rc[EpgAnnotation]")
		decodeAnnotation(sgAnn, &sgval, logger, "deployment/rc[SgAnnotation]")
	}

	// direct pod annotation is highest priority
	decodeAnnotation(pod.ObjectMeta.Annotations[metadata.EgAnnotation], &egval, logger, "pod[EpgAnnotation]")
	decodeAnnotation(pod.ObjectMeta.Annotations[metadata.SgAnnotation], &sgval, logger, "pod[SgAnnotation]")

	sgval, err = agent.mergeNetPolSg(podkey, pod, namespace, sgval)
	if err != nil {
		logger.Error("Could not generate network policy ",
			"security groups:", err)
	}

	return egval, sgval, nil
}
