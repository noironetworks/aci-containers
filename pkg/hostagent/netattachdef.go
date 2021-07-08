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

package hostagent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	netpolicy "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	netClient "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/clientset/versioned"
	netattclient "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/clientset/versioned/typed/k8s.cni.cncf.io/v1"
	md "github.com/noironetworks/aci-containers/pkg/metadata"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
	podresourcesv1alpha1 "k8s.io/kubelet/pkg/apis/podresources/v1alpha1"
	"k8s.io/kubernetes/pkg/controller"
	"k8s.io/kubernetes/pkg/kubelet/apis/podresources"
)

const (
	defaultAnnot                  = "k8s.v1.cni.cncf.io/networks"
	resourceNameAnnot             = "k8s.v1.cni.cncf.io/resourceName"
	netAttachDefCRDName           = "network-attachment-definitions.k8s.cni.cncf.io"
	kubeletPodResourceDefaultPath = "/usr/local/var/lib/kubelet/pod-resources"
	podResourcesMaxSizeDefault    = 1024 * 1024 * 16 // 16 Mb
	timeout                       = 10 * time.Second
)

type NetworkAttachmentData struct {
	Name      string
	Namespace string
	Config    string
	Annot     string
}

type ClientInfo struct {
	NetClient netattclient.K8sCniCncfIoV1Interface
}

func (agent *HostAgent) initNetworkAttDefInformerFromClient(
	netClientSet *netClient.Clientset) {

	agent.initNetworkAttachmentDefinitionInformerBase(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				return netClientSet.K8sCniCncfIoV1().NetworkAttachmentDefinitions(metav1.NamespaceAll).List(context.TODO(), options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				return netClientSet.K8sCniCncfIoV1().NetworkAttachmentDefinitions(metav1.NamespaceAll).Watch(context.TODO(), options)
			},
		})
}

func (agent *HostAgent) initNetworkAttachmentDefinitionInformerBase(listWatch *cache.ListWatch) {
	agent.netAttDefInformer = cache.NewSharedIndexInformer(
		listWatch, &netpolicy.NetworkAttachmentDefinition{}, controller.NoResyncPeriodFunc(),
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	agent.netAttDefInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			agent.networkAttDefAdded(obj)
		},
		UpdateFunc: func(oldobj interface{}, newobj interface{}) {
			agent.networkAttDefUpdated(oldobj, newobj)
		},
		DeleteFunc: func(obj interface{}) {
			agent.networkAttDefDeleted(obj)
		},
	})
}

type Config struct {
	Name       string    `json:"name"`
	Plugins    []Plugins `json:"plugins"`
	CniVersion string    `json:"cniVersion"`
}

type Plugins struct {
	Type string `json:"type,omitempty"`
	IPAM IPAM   `json:"ipam,omitempty"`
}

type IPAM struct {
	Type string `json:"type,omitempty"`
}

func (agent *HostAgent) networkAttDefAdded(obj interface{}) {
	ntd := obj.(*netpolicy.NetworkAttachmentDefinition)
	agent.log.Infof("network atttachment definition added: %s", ntd.ObjectMeta.Name)
	agent.networkAttDefChanged(ntd)
}

func (agent *HostAgent) networkAttDefChanged(ntd *netpolicy.NetworkAttachmentDefinition) {
	netattdata := NetworkAttachmentData{
		Name:      ntd.ObjectMeta.Name,
		Namespace: ntd.ObjectMeta.Namespace,
		Config:    ntd.Spec.Config,
		Annot:     ntd.ObjectMeta.Annotations[resourceNameAnnot],
	}
	var config Config
	json.Unmarshal([]byte(ntd.Spec.Config), &config)

	for i := 0; i < len(config.Plugins); i++ {
		if config.Name == "k8s-pod-network" {
			if config.Plugins[i].Type == "opflex-agent-cni" && config.Plugins[i].IPAM.Type == "opflex-agent-cni-ipam" {
				if ntd.ObjectMeta.Annotations[resourceNameAnnot] != "" {
					if ntd.ObjectMeta.Name != "" {
						agent.indexMutex.Lock()
						agent.netattdefmap[ntd.ObjectMeta.Name] = &netattdata
						agent.indexMutex.Unlock()
						break
					}
				}
			} else {
				agent.log.Debug("network atttachment does not specify opflex-agent-cni and opflex-agent-cni-ipam")
			}
		}
	}
}

func (agent *HostAgent) networkAttDefUpdated(oldobj interface{}, newobj interface{}) {
	ntd := newobj.(*netpolicy.NetworkAttachmentDefinition)
	agent.log.Infof("network atttachment definition changed: %s", ntd.ObjectMeta.Name)
	agent.networkAttDefChanged(ntd)
}

func (agent *HostAgent) networkAttDefDeleted(obj interface{}) {
	ntd := obj.(*netpolicy.NetworkAttachmentDefinition)
	agent.log.Infof("network atttachment definition deleted: %s", ntd.ObjectMeta.Name)
	agent.indexMutex.Lock()
	delete(agent.netattdefmap, ntd.ObjectMeta.Name)
	agent.indexMutex.Unlock()
}

// KubeletPodResources is struct to hold resource allocation information
type kubeletPodResources struct {
	resp []*podresourcesv1alpha1.PodResources
}

type DeviceInfo struct {
	DeviceId     string
	ResourceName string
}

func (agent *HostAgent) getAlloccatedDeviceId(metadata *md.ContainerMetadata) error {
	err := agent.getPodResource(metadata)
	return err
}

func (agent *HostAgent) getPodResource(metadata *md.ContainerMetadata) error {
	var isAcicniNetwork bool
	agent.indexMutex.Lock()
	netList := agent.podToNetAttachDef[metadata.Id.Pod+"-"+metadata.Id.Namespace]
	agent.indexMutex.Unlock()
	for _, netAttName := range netList {
		if agent.netattdefmap[netAttName] != nil {
			isAcicniNetwork = true
		} else {
			return nil
		}
	}
	if isAcicniNetwork {
		podResourceSock := filepath.Join(kubeletPodResourceDefaultPath, podresources.Socket+".sock")
		if _, err := os.Stat(podResourceSock); os.IsNotExist(err) {
			return fmt.Errorf("Could not retreive the kubelet sock %v", err)
		}

		ctx, cancelFunc := context.WithTimeout(context.Background(), timeout)
		defer cancelFunc()

		podResourcesClient, podResourcesConn, err := podresources.GetV1alpha1Client(podResourceSock, timeout, podResourcesMaxSizeDefault)
		if err != nil {
			return fmt.Errorf("Could not retreive the pod resource client %v", err)
		}
		defer podResourcesConn.Close()

		resp, err := podResourcesClient.List(ctx, &podresourcesv1alpha1.ListPodResourcesRequest{})

		if err != nil {
			return fmt.Errorf("Could not get pod resource from the client %v", err)
		}
		if resp == nil {
			return fmt.Errorf("Not able to process PodResourcesResponse")
		}

		podResource := &kubeletPodResources{}
		podResource.resp = resp.PodResources
		podName := metadata.Id.Pod
		podNamespace := metadata.Id.Namespace
		for _, podResource := range podResource.resp {
			if podName == podResource.Name && podNamespace == podResource.Namespace {
				for _, container := range podResource.Containers {
					for _, devices := range container.Devices {
						DeviceList := devices.DeviceIds
						if len(DeviceList) != 1 {
							return fmt.Errorf("Virtual function allocation failed : Multiple device id found")
						} else {
							deviceInfo := &DeviceInfo{
								DeviceId:     strings.Join(DeviceList, " "),
								ResourceName: devices.ResourceName,
							}
							metadata.Id.DeviceId = deviceInfo.DeviceId
							return nil
						}
					}
				}
			}
		}

	}
	return nil
}
