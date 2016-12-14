// Copyright 2016 Cisco Systems, Inc.
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

// Handlers for pod updates.  Pods map to opflex endpoints

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/Sirupsen/logrus"

	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/apis/extensions"
	"k8s.io/kubernetes/pkg/client/cache"

	"github.com/noironetworks/aci-containers/cnimetadata"
)

type opflexGroup struct {
	PolicySpace string `json:"policy-space"`
	Name        string `json:"name"`
}

type opflexEndpoint struct {
	Uuid string `json:"uuid"`

	EgPolicySpace string        `json:"eg-policy-space,omitempty"`
	EndpointGroup string        `json:"endpoint-group-name,omitempty"`
	SecurityGroup []opflexGroup `json:"security-group,omitempty"`

	IpAddress  []string `json:"ip,omitempty"`
	MacAddress string   `json:"mac,omitempty"`

	AccessIface       string `json:"access-interface,omitempty"`
	AccessUplinkIface string `json:"access-uplink-interface,omitempty"`
	IfaceName         string `json:"interface-name,omitempty"`

	Attributes map[string]string `json:"attributes,omitempty"`
}

func getEp(epfile string) (*opflexEndpoint, error) {
	data := &opflexEndpoint{}

	raw, err := ioutil.ReadFile(epfile)
	if err != nil {
		return data, err
	}
	err = json.Unmarshal(raw, data)
	return data, err
}

func writeEp(epfile string, ep *opflexEndpoint) error {
	datacont, err := json.MarshalIndent(ep, "", "  ")
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(epfile, datacont, 0644)
	if err != nil {
		log.WithFields(
			logrus.Fields{"epfile": epfile, "uuid": ep.Uuid},
		).Error("Error writing EP file: " + err.Error())
	}
	return err
}

func podLogger(pod *api.Pod) *logrus.Entry {
	return log.WithFields(logrus.Fields{
		"namespace": pod.ObjectMeta.Namespace,
		"name":      pod.ObjectMeta.Name,
		"node":      pod.Spec.NodeName,
	})
}

func opflexEpLogger(ep *opflexEndpoint) *logrus.Entry {
	return log.WithFields(logrus.Fields{
		"Uuid": ep.Uuid,
		"name": ep.Attributes["vm-name"],
	})
}

func syncEps() {
	if !syncEnabled {
		return
	}

	files, err := ioutil.ReadDir(*endpointDir)
	if err != nil {
		log.WithFields(
			logrus.Fields{"endpointDir": endpointDir},
		).Error("Could not read directory " + err.Error())
		return
	}
	seen := make(map[string]bool)
	for _, f := range files {
		if !strings.HasSuffix(f.Name(), ".ep") {
			continue
		}

		epfile := filepath.Join(*endpointDir, f.Name())
		logger := log.WithFields(
			logrus.Fields{"epfile": epfile},
		)
		ep, err := getEp(epfile)
		if err != nil {
			logger.Error("Error reading EP file: " + err.Error())
			os.Remove(epfile)
		} else {
			existing, ok := opflexEps[ep.Uuid]
			if ok {
				if !reflect.DeepEqual(existing, ep) {
					opflexEpLogger(ep).Info("Updating endpoint")
					writeEp(epfile, existing)
				}
				seen[ep.Uuid] = true
			} else {
				opflexEpLogger(ep).Info("Removing endpoint")
				os.Remove(epfile)
			}
		}
	}

	for _, ep := range opflexEps {
		if seen[ep.Uuid] {
			continue
		}

		opflexEpLogger(ep).Info("Adding endpoint")
		writeEp(filepath.Join(*endpointDir, ep.Uuid+".ep"), ep)
	}
}

func podFilter(pod *api.Pod) bool {
	if pod.Status.HostIP != *nodename {
		return false
	} else if pod.Spec.SecurityContext != nil &&
		pod.Spec.SecurityContext.HostNetwork == true {
		return false
	}
	return true
}

func podUpdated(_ interface{}, obj interface{}) {
	podAdded(obj)
}

func podAdded(obj interface{}) {
	indexMutex.Lock()
	defer indexMutex.Unlock()

	podChangedLocked(obj)
}

func podChangedLocked(obj interface{}) {
	pod := obj.(*api.Pod)
	if !podFilter(pod) {
		podDeletedLocked(obj)
		return
	}
	logger := podLogger(pod)

	hasCont := false
	for _, s := range pod.Status.ContainerStatuses {
		if s.State.Running != nil {
			hasCont = true
			break
		}
	}
	if !hasCont {
		podDeletedLocked(obj)
		return
	}

	podkey, err := cache.MetaNamespaceKeyFunc(pod)
	if err != nil {
		logger.Error("Could not create pod key:" + err.Error())
		return
	}

	podobj, exists, err := podInformer.GetStore().GetByKey(podkey)
	if err != nil {
		log.Error("Could not lookup pod:" + err.Error())
		return
	}
	if !exists || podobj == nil {
		podDeletedLocked(pod)
	}

	id := fmt.Sprintf("%s_%s", pod.ObjectMeta.Namespace, pod.ObjectMeta.Name)
	metadata, err := cnimetadata.GetMetadata(*metadataDir, *network, id)
	if err != nil {
		logger.Error("Could not retrieve metadata: " + err.Error())
		podDeletedLocked(obj)
		return
	}

	patchIntName, patchAccessName :=
		cnimetadata.GetIfaceNames(metadata.HostVethName)

	ep := &opflexEndpoint{
		Uuid:              string(pod.ObjectMeta.UID),
		MacAddress:        metadata.MAC,
		IpAddress:         []string{pod.Status.PodIP},
		AccessIface:       metadata.HostVethName,
		AccessUplinkIface: patchAccessName,
		IfaceName:         patchIntName,
	}

	ep.Attributes = pod.ObjectMeta.Labels
	ep.Attributes["vm-name"] = id

	const EgAnnotation = "opflex.cisco.com/endpoint-group"
	const SgAnnotation = "opflex.cisco.com/security-group"

	// top-level default annotation
	egval := defaultEg
	sgval := defaultSg

	// namespace annotation has next-highest priority
	namespaceobj, exists, err :=
		namespaceInformer.GetStore().GetByKey(pod.ObjectMeta.Namespace)
	if err != nil {
		log.Error("Could not lookup namespace " +
			pod.ObjectMeta.Namespace + ": " + err.Error())
		return
	}
	if exists && namespaceobj != nil {
		namespace := namespaceobj.(*api.Namespace)

		if og, ok := namespace.ObjectMeta.Annotations[EgAnnotation]; ok {
			egval = &og
		}
		if og, ok := namespace.ObjectMeta.Annotations[SgAnnotation]; ok {
			sgval = &og
		}
	}

	// annotation on associated deployment is next-highest priority
	if _, ok := depPods[podkey]; !ok {
		if _, ok := pod.ObjectMeta.Annotations["kubernetes.io/created-by"]; ok {
			// we have no deployment for this pod but it was created
			// by something.  Update the index

			updateDeploymentsForPod(pod)
		}
	}
	if depkey, ok := depPods[podkey]; ok {
		deploymentobj, exists, err :=
			deploymentInformer.GetStore().GetByKey(depkey)
		if err != nil {
			log.Error("Could not lookup deployment " + depkey + ": " + err.Error())
			return
		}
		if exists && deploymentobj != nil {
			deployment := deploymentobj.(*extensions.Deployment)

			if og, ok := deployment.ObjectMeta.Annotations[EgAnnotation]; ok {
				egval = &og
			}
			if og, ok := deployment.ObjectMeta.Annotations[SgAnnotation]; ok {
				sgval = &og
			}
		}
	}

	// direct pod annotation is highest priority
	if og, ok := pod.ObjectMeta.Annotations[EgAnnotation]; ok {
		egval = &og
	}
	if og, ok := pod.ObjectMeta.Annotations[SgAnnotation]; ok {
		sgval = &og
	}

	logger.WithFields(logrus.Fields{
		"EgAnnotation": *egval,
		"SgAnnotation": *sgval,
	}).Debug("Computed pod annotations")

	if egval != nil && *egval != "" {
		g := &opflexGroup{}
		err := json.Unmarshal([]byte(*egval), g)
		if err != nil {
			logger.WithFields(logrus.Fields{
				"EgAnnotation": *egval,
			}).Error("Could not decode annotation: " + err.Error())
		} else {
			ep.EgPolicySpace = g.PolicySpace
			ep.EndpointGroup = g.Name
		}
	}
	if sgval != nil && *sgval != "" {
		g := make([]opflexGroup, 0)
		err := json.Unmarshal([]byte(*sgval), &g)
		if err != nil {
			logger.WithFields(logrus.Fields{
				"SgAnnotation": *sgval,
			}).Error("Could not decode annotation: " + err.Error())
		} else {
			ep.SecurityGroup = g
		}
	}

	existing, ok := opflexEps[ep.Uuid]
	if (ok && !reflect.DeepEqual(existing, ep)) || !ok {
		opflexEps[ep.Uuid] = ep
		syncEps()
	}
}

func podDeleted(obj interface{}) {
	indexMutex.Lock()
	defer indexMutex.Unlock()

	podDeletedLocked(obj)
}

func podDeletedLocked(obj interface{}) {
	pod := obj.(*api.Pod)
	if !podFilter(pod) {
		return
	}
	u := string(pod.ObjectMeta.UID)
	if _, ok := opflexEps[u]; ok {
		delete(opflexEps, u)
		syncEps()
	}
}
