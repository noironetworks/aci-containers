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
	"k8s.io/kubernetes/pkg/client/cache"
	clientset "k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset"
	"k8s.io/kubernetes/pkg/controller"
	"k8s.io/kubernetes/pkg/fields"
	"k8s.io/kubernetes/pkg/runtime"
	"k8s.io/kubernetes/pkg/util/wait"
	"k8s.io/kubernetes/pkg/watch"

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

func initPodInformer(kubeClient *clientset.Clientset) {
	podInformer = cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options api.ListOptions) (runtime.Object, error) {
				options.FieldSelector =
					fields.Set{"spec.nodeName": config.NodeName}.AsSelector()
				return kubeClient.Core().Pods(api.NamespaceAll).List(options)
			},
			WatchFunc: func(options api.ListOptions) (watch.Interface, error) {
				options.FieldSelector =
					fields.Set{"spec.nodeName": config.NodeName}.AsSelector()
				return kubeClient.Core().Pods(api.NamespaceAll).Watch(options)
			},
		},
		&api.Pod{},
		controller.NoResyncPeriodFunc(),
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    podAdded,
		UpdateFunc: podUpdated,
		DeleteFunc: podDeleted,
	})

	go podInformer.GetController().Run(wait.NeverStop)
	go podInformer.Run(wait.NeverStop)
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

	files, err := ioutil.ReadDir(config.OpFlexEndpointDir)
	if err != nil {
		log.WithFields(
			logrus.Fields{"endpointDir": config.OpFlexEndpointDir},
		).Error("Could not read directory " + err.Error())
		return
	}
	seen := make(map[string]bool)
	for _, f := range files {
		if !strings.HasSuffix(f.Name(), ".ep") {
			continue
		}

		epfile := filepath.Join(config.OpFlexEndpointDir, f.Name())
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
		writeEp(filepath.Join(config.OpFlexEndpointDir, ep.Uuid+".ep"), ep)
	}
}

func podFilter(pod *api.Pod) bool {
	if pod.Spec.NodeName != config.NodeName {
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

func podChanged(podkey *string) {
	podobj, exists, err := podInformer.GetStore().GetByKey(*podkey)
	if err != nil {
		log.Error("Could not lookup pod: ", err)
	}
	if !exists || podobj == nil {
		log.Info("Object doesn't exist yet ", *podkey)
		return
	}

	indexMutex.Lock()
	defer indexMutex.Unlock()
	podChangedLocked(podobj)
}

func podChangedLocked(podobj interface{}) {
	pod := podobj.(*api.Pod)
	logger := podLogger(pod)

	if !podFilter(pod) {
		delete(opflexEps, string(pod.ObjectMeta.UID))
		syncEps()
		return
	}

	id := fmt.Sprintf("%s_%s", pod.ObjectMeta.Namespace, pod.ObjectMeta.Name)
	metadata, ok := epMetadata[id]
	if !ok {
		logger.Debug("No metadata")
		delete(opflexEps, string(pod.ObjectMeta.UID))
		syncEps()
		return
	}

	patchIntName, patchAccessName :=
		cnimetadata.GetIfaceNames(metadata.HostVethName)
	ips := make([]string, 0)
	if metadata.NetConf.IP4 != nil {
		ips = append(ips, metadata.NetConf.IP4.IP.IP.String())
	}
	if metadata.NetConf.IP6 != nil {
		ips = append(ips, metadata.NetConf.IP6.IP.IP.String())
	}

	ep := &opflexEndpoint{
		Uuid:              string(pod.ObjectMeta.UID),
		MacAddress:        metadata.MAC,
		IpAddress:         ips,
		AccessIface:       metadata.HostVethName,
		AccessUplinkIface: patchAccessName,
		IfaceName:         patchIntName,
	}

	ep.Attributes = pod.ObjectMeta.Labels
	ep.Attributes["vm-name"] = id

	const CompEgAnnotation = "opflex.cisco.com/computed-endpoint-group"
	const CompSgAnnotation = "opflex.cisco.com/computed-security-group"

	if egval, ok := pod.ObjectMeta.Annotations[CompEgAnnotation]; ok {
		g := &opflexGroup{}
		err := json.Unmarshal([]byte(egval), g)
		if err != nil {
			logger.WithFields(logrus.Fields{
				"EgAnnotation": egval,
			}).Error("Could not decode annotation: " + err.Error())
		} else {
			ep.EgPolicySpace = g.PolicySpace
			ep.EndpointGroup = g.Name
		}
	}
	if sgval, ok := pod.ObjectMeta.Annotations[CompSgAnnotation]; ok {
		g := make([]opflexGroup, 0)
		err := json.Unmarshal([]byte(sgval), &g)
		if err != nil {
			logger.WithFields(logrus.Fields{
				"SgAnnotation": sgval,
			}).Error("Could not decode annotation: " + err.Error())
		} else {
			ep.SecurityGroup = g
		}
	}

	existing, ok := opflexEps[ep.Uuid]
	if (ok && !reflect.DeepEqual(existing, ep)) || !ok {
		logger.WithFields(logrus.Fields{
			"ep": ep,
		}).Debug("Updated endpoint")

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
	u := string(pod.ObjectMeta.UID)
	if _, ok := opflexEps[u]; ok {
		delete(opflexEps, u)
		syncEps()
	}
}
