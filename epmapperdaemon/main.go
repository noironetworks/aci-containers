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

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"

	"github.com/Sirupsen/logrus"

	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/client/cache"
	clientset "k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset"
	"k8s.io/kubernetes/pkg/client/restclient"
	"k8s.io/kubernetes/pkg/client/unversioned/clientcmd"
	"k8s.io/kubernetes/pkg/controller"
	"k8s.io/kubernetes/pkg/controller/informers"
	"k8s.io/kubernetes/pkg/util/wait"

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

var (
	log         = logrus.New()
	kubeconfig  = flag.String("kubeconfig", "", "absolute path to the kubeconfig file")
	nodeip      = flag.String("node", "", "IP of current node")
	metadataDir = flag.String("cnimetadatadir", "/var/lib/cni/opflex-networks", "Directory containing OpFlex CNI metadata")
	network     = flag.String("cninetwork", "opflex-k8s-network", "Name of CNI network")
	endpointDir = flag.String("endpointdir", "/var/lib/opflex-agent-ovs/endpoints/", "Directory for writing OpFlex endpoint metadata")

	opflexEps = make(map[string]*opflexEndpoint)
)

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

func syncEps() {
	// TODO only run once podInformer.GetController().HasSynced == true

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
		} else {
			existing, ok := opflexEps[ep.Uuid]
			if ok {
				if !reflect.DeepEqual(existing, ep) {
					writeEp(epfile, existing)
				}
				seen[ep.Uuid] = true
			} else {
				os.Remove(epfile)
			}
		}
	}

	for _, ep := range opflexEps {
		if seen[ep.Uuid] {
			continue
		}

		writeEp(filepath.Join(*endpointDir, ep.Uuid+".ep"), ep)
	}
}

func podFilter(pod *api.Pod) bool {
	if pod.Status.HostIP != *nodeip {
		return false
	} else if pod.Spec.SecurityContext != nil &&
		pod.Spec.SecurityContext.HostNetwork == true {
		return false
	}
	return true
}

func podLogger(pod *api.Pod) *logrus.Entry {
	return log.WithFields(logrus.Fields{
		"namespace": pod.ObjectMeta.Namespace,
		"name":      pod.ObjectMeta.Name,
		"node":      pod.Spec.NodeName,
	})
}

func podUpdated(_ interface{}, obj interface{}) {
	podAdded(obj)
}

func podAdded(obj interface{}) {
	pod := obj.(*api.Pod)
	if !podFilter(pod) {
		podDeleted(obj)
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
		podDeleted(obj)
		return
	}

	id := fmt.Sprintf("%s_%s", pod.ObjectMeta.Namespace, pod.ObjectMeta.Name)
	metadata, err := cnimetadata.GetMetadata(*metadataDir, *network, id)
	if err != nil {
		logger.Error("Could not retrieve metadata: " + err.Error())
		podDeleted(obj)
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

	if og, ok := pod.ObjectMeta.Annotations[EgAnnotation]; ok {
		g := &opflexGroup{}
		err := json.Unmarshal([]byte(og), g)
		if err != nil {
			logger.WithFields(logrus.Fields{
				"EgAnnotation": og,
			}).Error("Could not decode annotation: " + err.Error())
		} else {
			ep.EgPolicySpace = g.PolicySpace
			ep.EndpointGroup = g.Name
		}
	}
	if og, ok := pod.ObjectMeta.Annotations[SgAnnotation]; ok {
		g := make([]opflexGroup, 0)
		err := json.Unmarshal([]byte(og), &g)
		if err != nil {
			logger.WithFields(logrus.Fields{
				"SgAnnotation": og,
			}).Error("Could not decode annotation: " + err.Error())
		} else {
			ep.SecurityGroup = g
		}
	}

	logger.Info("Pod added/updated")
	opflexEps[ep.Uuid] = ep

	syncEps()
}

func podDeleted(obj interface{}) {
	pod := obj.(*api.Pod)
	if !podFilter(pod) {
		return
	}
	logger := podLogger(pod)
	u := string(pod.ObjectMeta.UID)
	if _, ok := opflexEps[u]; ok {
		logger.Info("Pod deleted")
		delete(opflexEps, u)
	}

	syncEps()
}

func main() {
	flag.Parse()

	if nodeip == nil || *nodeip == "" {
		err := errors.New("Node IP not specified")
		log.Error(err.Error())
		panic(err.Error())
	}

	var config *restclient.Config
	var err error
	if kubeconfig != nil {
		// use kubeconfig file from command line
		config, err = clientcmd.BuildConfigFromFlags("", *kubeconfig)
		if err != nil {
			panic(err.Error())
		}
	} else {
		// creates the in-cluster config
		config, err = restclient.InClusterConfig()
		if err != nil {
			panic(err.Error())
		}
	}

	// creates the client
	kubeClient, err := clientset.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}

	var wg sync.WaitGroup
	wg.Add(1)
	podInformer := informers.NewPodInformer(kubeClient,
		controller.NoResyncPeriodFunc())
	podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    podAdded,
		UpdateFunc: podUpdated,
		DeleteFunc: podDeleted,
	})

	go podInformer.GetController().Run(wait.NeverStop)
	go podInformer.Run(wait.NeverStop)
	wg.Wait()
}
