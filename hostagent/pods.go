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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	v1 "k8s.io/client-go/pkg/api/v1"
	"k8s.io/client-go/tools/cache"

	"k8s.io/kubernetes/pkg/controller"

	"github.com/noironetworks/aci-containers/metadata"
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

func (agent *hostAgent) initPodInformer() {
	agent.podInformer = cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				options.FieldSelector =
					fields.Set{"spec.nodeName": agent.config.NodeName}.String()
				return agent.kubeClient.Core().Pods(metav1.NamespaceAll).List(options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				options.FieldSelector =
					fields.Set{"spec.nodeName": agent.config.NodeName}.String()
				return agent.kubeClient.Core().Pods(metav1.NamespaceAll).Watch(options)
			},
		},
		&v1.Pod{},
		controller.NoResyncPeriodFunc(),
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	agent.podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			agent.podUpdated(obj)
		},
		UpdateFunc: func(_ interface{}, obj interface{}) {
			agent.podUpdated(obj)
		},
		DeleteFunc: func(obj interface{}) {
			agent.podDeleted(obj)
		},
	})

	go agent.podInformer.GetController().Run(wait.NeverStop)
	go agent.podInformer.Run(wait.NeverStop)
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

func podLogger(pod *v1.Pod) *logrus.Entry {
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

func (agent *hostAgent) syncEps() {
	if !agent.syncEnabled {
		return
	}

	log.Debug("Syncing endpoints")
	files, err := ioutil.ReadDir(agent.config.OpFlexEndpointDir)
	if err != nil {
		log.WithFields(
			logrus.Fields{"endpointDir": agent.config.OpFlexEndpointDir},
		).Error("Could not read directory " + err.Error())
		return
	}
	seen := make(map[string]bool)
	for _, f := range files {
		if !strings.HasSuffix(f.Name(), ".ep") {
			continue
		}

		epfile := filepath.Join(agent.config.OpFlexEndpointDir, f.Name())
		logger := log.WithFields(
			logrus.Fields{"epfile": epfile},
		)
		ep, err := getEp(epfile)
		if err != nil {
			logger.Error("Error reading EP file: " + err.Error())
			os.Remove(epfile)
		} else {
			existing, ok := agent.opflexEps[ep.Uuid]
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

	for _, ep := range agent.opflexEps {
		if seen[ep.Uuid] {
			continue
		}

		opflexEpLogger(ep).Info("Adding endpoint")
		writeEp(filepath.Join(agent.config.OpFlexEndpointDir, ep.Uuid+".ep"), ep)
	}
	log.Debug("Finished endpoint sync")
}

func podFilter(pod *v1.Pod) bool {
	// XXX TODO there seems to be no way to get the value of the
	// HostNetwork field using the versioned API?
	//else if pod.Spec.SecurityContext != nil &&
	//	pod.Spec.SecurityContext.HostNetwork == true {
	//	return false
	//}
	return true
}

func (agent *hostAgent) podUpdated(obj interface{}) {
	agent.indexMutex.Lock()
	defer agent.indexMutex.Unlock()
	agent.podChangedLocked(obj)
}

func (agent *hostAgent) podChanged(podkey *string) {
	podobj, exists, err := agent.podInformer.GetStore().GetByKey(*podkey)
	if err != nil {
		log.Error("Could not lookup pod: ", err)
	}
	if !exists || podobj == nil {
		log.Info("Object doesn't exist yet ", *podkey)
		return
	}

	agent.indexMutex.Lock()
	defer agent.indexMutex.Unlock()
	agent.podChangedLocked(podobj)
}

func (agent *hostAgent) podChangedLocked(podobj interface{}) {
	pod := podobj.(*v1.Pod)
	logger := podLogger(pod)

	if !podFilter(pod) {
		delete(agent.opflexEps, string(pod.ObjectMeta.UID))
		agent.syncEps()
		return
	}

	id := fmt.Sprintf("%s_%s", pod.ObjectMeta.Namespace, pod.ObjectMeta.Name)
	epmetadata, ok := agent.epMetadata[id]
	if !ok {
		logger.Debug("No metadata")
		delete(agent.opflexEps, string(pod.ObjectMeta.UID))
		agent.syncEps()
		return
	}

	patchIntName, patchAccessName :=
		metadata.GetIfaceNames(epmetadata.HostVethName)
	ips := make([]string, 0)
	if epmetadata.NetConf.IP4 != nil {
		ips = append(ips, epmetadata.NetConf.IP4.IP.IP.String())
	}
	if epmetadata.NetConf.IP6 != nil {
		ips = append(ips, epmetadata.NetConf.IP6.IP.IP.String())
	}

	ep := &opflexEndpoint{
		Uuid:              string(pod.ObjectMeta.UID),
		MacAddress:        epmetadata.MAC,
		IpAddress:         ips,
		AccessIface:       epmetadata.HostVethName,
		AccessUplinkIface: patchAccessName,
		IfaceName:         patchIntName,
	}

	ep.Attributes = pod.ObjectMeta.Labels
	ep.Attributes["vm-name"] = id

	if egval, ok := pod.ObjectMeta.Annotations[metadata.CompEgAnnotation]; ok {
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
	if sgval, ok := pod.ObjectMeta.Annotations[metadata.CompSgAnnotation]; ok {
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

	existing, ok := agent.opflexEps[ep.Uuid]
	if (ok && !reflect.DeepEqual(existing, ep)) || !ok {
		logger.WithFields(logrus.Fields{
			"ep": ep,
		}).Debug("Updated endpoint")

		agent.opflexEps[ep.Uuid] = ep

		agent.syncEps()
	}
}

func (agent *hostAgent) podDeleted(obj interface{}) {
	agent.indexMutex.Lock()
	defer agent.indexMutex.Unlock()

	agent.podDeletedLocked(obj)
}

func (agent *hostAgent) podDeletedLocked(obj interface{}) {
	pod := obj.(*v1.Pod)
	u := string(pod.ObjectMeta.UID)
	if _, ok := agent.opflexEps[u]; ok {
		delete(agent.opflexEps, u)
		agent.syncEps()
	}
}
