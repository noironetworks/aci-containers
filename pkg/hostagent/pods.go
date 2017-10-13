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

package hostagent

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/Sirupsen/logrus"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"k8s.io/kubernetes/pkg/controller"

	"github.com/noironetworks/aci-containers/pkg/metadata"
)

type opflexEndpoint struct {
	Uuid string `json:"uuid"`

	EgPolicySpace string                 `json:"eg-policy-space,omitempty"`
	EndpointGroup string                 `json:"endpoint-group-name,omitempty"`
	SecurityGroup []metadata.OpflexGroup `json:"security-group,omitempty"`

	IpAddress  []string `json:"ip,omitempty"`
	MacAddress string   `json:"mac,omitempty"`

	AccessIface       string `json:"access-interface,omitempty"`
	AccessUplinkIface string `json:"access-uplink-interface,omitempty"`
	IfaceName         string `json:"interface-name,omitempty"`

	Attributes map[string]string `json:"attributes,omitempty"`
}

func (agent *HostAgent) initPodInformerFromClient(
	kubeClient *kubernetes.Clientset) {

	agent.initPodInformerBase(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				options.FieldSelector =
					fields.Set{"spec.nodeName": agent.config.NodeName}.String()
				return kubeClient.Core().Pods(metav1.NamespaceAll).List(options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				options.FieldSelector =
					fields.Set{"spec.nodeName": agent.config.NodeName}.String()
				return kubeClient.Core().Pods(metav1.NamespaceAll).Watch(options)
			},
		})
}

func (agent *HostAgent) initPodInformerBase(listWatch *cache.ListWatch) {
	agent.podInformer = cache.NewSharedIndexInformer(
		listWatch,
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
}

func getEp(epfile string) (string, error) {
	raw, err := ioutil.ReadFile(epfile)
	if err != nil {
		return "", err
	}
	return string(raw), err
}

func writeEp(epfile string, ep *opflexEndpoint) (bool, error) {
	newdata, err := json.MarshalIndent(ep, "", "  ")
	if err != nil {
		return true, err
	}
	existingdata, err := ioutil.ReadFile(epfile)
	if err == nil && reflect.DeepEqual(existingdata, newdata) {
		return false, nil
	}

	err = ioutil.WriteFile(epfile, newdata, 0644)
	return true, err
}

func podLogger(log *logrus.Logger, pod *v1.Pod) *logrus.Entry {
	return log.WithFields(logrus.Fields{
		"namespace": pod.ObjectMeta.Namespace,
		"name":      pod.ObjectMeta.Name,
		"node":      pod.Spec.NodeName,
	})
}

func opflexEpLogger(log *logrus.Logger, ep *opflexEndpoint) *logrus.Entry {
	return log.WithFields(logrus.Fields{
		"Uuid":      ep.Uuid,
		"name":      ep.Attributes["vm-name"],
		"namespace": ep.Attributes["namespace"],
	})
}

func (agent *HostAgent) syncEps() bool {
	if !agent.syncEnabled {
		return false
	}

	agent.log.Debug("Syncing endpoints")
	agent.indexMutex.Lock()
	opflexEps := make(map[string][]*opflexEndpoint)
	for k, v := range agent.opflexEps {
		opflexEps[k] = v
	}
	agent.indexMutex.Unlock()

	files, err := ioutil.ReadDir(agent.config.OpFlexEndpointDir)
	if err != nil {
		agent.log.WithFields(
			logrus.Fields{"endpointDir": agent.config.OpFlexEndpointDir},
		).Error("Could not read directory ", err)
		return true
	}
	seen := make(map[string]bool)
	for _, f := range files {
		if !strings.HasSuffix(f.Name(), ".ep") {
			continue
		}
		epfile := filepath.Join(agent.config.OpFlexEndpointDir, f.Name())
		epidstr := f.Name()
		epidstr = epidstr[:len(epidstr)-3]
		epid := strings.Split(epidstr, "_")

		if len(epid) < 3 {
			agent.log.Warn("Removing invalid endpoint:", f.Name())
			os.Remove(epfile)
			continue
		}
		poduuid := epid[0]
		contid := epid[1]
		contiface := epid[2]

		logger := agent.log.WithFields(
			logrus.Fields{
				"PodUuid":   poduuid,
				"ContId":    contid,
				"ContIFace": contiface,
			},
		)

		existing, ok := opflexEps[poduuid]
		if ok {
			ok = false
			for _, ep := range existing {
				if ep.Uuid != epidstr {
					continue
				}

				wrote, err := writeEp(epfile, ep)
				if err != nil {
					opflexEpLogger(agent.log, ep).
						Error("Error writing EP file: ", err)
				} else if wrote {
					opflexEpLogger(agent.log, ep).
						Info("Updated endpoint")
				}
				seen[epidstr] = true
				ok = true
			}
		}
		if !ok {
			logger.Info("Removing endpoint")
			os.Remove(epfile)
		}
	}

	for _, eps := range opflexEps {
		for _, ep := range eps {
			if seen[ep.Uuid] {
				continue
			}

			opflexEpLogger(agent.log, ep).Info("Adding endpoint")
			epfile := filepath.Join(agent.config.OpFlexEndpointDir,
				ep.Uuid+".ep")
			_, err = writeEp(epfile, ep)
			if err != nil {
				opflexEpLogger(agent.log, ep).
					Error("Error writing EP file: ", err)
			}
		}
	}
	agent.log.Debug("Finished endpoint sync")
	return false
}

func podFilter(pod *v1.Pod) bool {
	if pod.Spec.HostNetwork {
		return false
	}
	return true
}

func (agent *HostAgent) podUpdated(obj interface{}) {
	agent.indexMutex.Lock()
	defer agent.indexMutex.Unlock()
	agent.podChangedLocked(obj)
}

func (agent *HostAgent) podChanged(podkey *string) {
	podobj, exists, err := agent.podInformer.GetStore().GetByKey(*podkey)
	if err != nil {
		agent.log.Error("Could not lookup pod: ", err)
	}
	if !exists || podobj == nil {
		agent.log.Info("Object doesn't exist yet ", *podkey)
		return
	}

	agent.indexMutex.Lock()
	defer agent.indexMutex.Unlock()
	agent.podChangedLocked(podobj)
}

func (agent *HostAgent) podChangedLocked(podobj interface{}) {
	pod := podobj.(*v1.Pod)
	logger := podLogger(agent.log, pod)

	if !podFilter(pod) {
		delete(agent.opflexEps, string(pod.ObjectMeta.UID))
		agent.scheduleSyncEps()
		return
	}

	id := fmt.Sprintf("%s/%s", pod.ObjectMeta.Namespace, pod.ObjectMeta.Name)
	epmetadata, ok := agent.epMetadata[id]
	if !ok {
		logger.Debug("No metadata")
		delete(agent.opflexEps, string(pod.ObjectMeta.UID))
		agent.scheduleSyncEps()
		return
	}

	var neweps []*opflexEndpoint

	for _, epmeta := range epmetadata {
		for _, iface := range epmeta.Ifaces {
			patchIntName, patchAccessName :=
				metadata.GetIfaceNames(iface.HostVethName)

			ips := make([]string, 0)
			for _, ip := range iface.IPs {
				if ip.Address.IP == nil {
					continue
				}
				ips = append(ips, ip.Address.IP.String())
			}

			epidstr := string(pod.ObjectMeta.UID) + "_" +
				epmeta.Id.ContId + "_" + iface.HostVethName
			ep := &opflexEndpoint{
				Uuid:              epidstr,
				MacAddress:        iface.Mac,
				IpAddress:         ips,
				AccessIface:       iface.HostVethName,
				AccessUplinkIface: patchAccessName,
				IfaceName:         patchIntName,
			}

			ep.Attributes = pod.ObjectMeta.Labels
			if ep.Attributes == nil {
				ep.Attributes = make(map[string]string)
			}
			ep.Attributes["vm-name"] = pod.ObjectMeta.Name
			ep.Attributes["namespace"] = pod.ObjectMeta.Namespace
			ep.Attributes["interface-name"] = iface.HostVethName

			if egval, ok := pod.ObjectMeta.Annotations[metadata.CompEgAnnotation]; ok {
				g := &metadata.OpflexGroup{}
				err := json.Unmarshal([]byte(egval), g)
				if err != nil {
					logger.WithFields(logrus.Fields{
						"EgAnnotation": egval,
					}).Error("Could not decode annotation: ", err)
				} else {
					if g.Tenant != "" {
						ep.EgPolicySpace = g.Tenant
					} else {
						ep.EgPolicySpace = g.PolicySpace
					}
					if g.AppProfile != "" {
						ep.EndpointGroup = g.AppProfile + "|" + g.Name
					} else {
						ep.EndpointGroup = g.Name
					}
				}
			}
			if sgval, ok := pod.ObjectMeta.Annotations[metadata.CompSgAnnotation]; ok {
				g := make([]metadata.OpflexGroup, 0)
				err := json.Unmarshal([]byte(sgval), &g)
				if err != nil {
					logger.WithFields(logrus.Fields{
						"SgAnnotation": sgval,
					}).Error("Could not decode annotation: ", err)
				} else {
					ep.SecurityGroup = g
				}
			}

			neweps = append(neweps, ep)
		}
	}

	existing, ok := agent.opflexEps[string(pod.ObjectMeta.UID)]
	if (ok && !reflect.DeepEqual(existing, neweps)) || !ok {
		logger.WithFields(logrus.Fields{
			"id": id,
			"ep": neweps,
		}).Debug("Updated endpoints for pod")

		agent.opflexEps[string(pod.ObjectMeta.UID)] = neweps

		agent.scheduleSyncEps()
	}
}

func (agent *HostAgent) podDeleted(obj interface{}) {
	agent.indexMutex.Lock()
	defer agent.indexMutex.Unlock()

	agent.podDeletedLocked(obj)
}

func (agent *HostAgent) podDeletedLocked(obj interface{}) {
	pod := obj.(*v1.Pod)
	u := string(pod.ObjectMeta.UID)
	if _, ok := agent.opflexEps[u]; ok {
		delete(agent.opflexEps, u)
		agent.scheduleSyncEps()
	}
}
