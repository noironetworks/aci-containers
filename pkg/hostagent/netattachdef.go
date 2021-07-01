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
	"fmt"
	netpolicy "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	"time"
	//	v1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	netClient "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/clientset/versioned"
	netattclient "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/clientset/versioned/typed/k8s.cni.cncf.io/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	podresourcesv1 "k8s.io/kubelet/pkg/apis/podresources/v1"
	//"k8s.io/apimachinery/pkg/fields"
	//v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
	"k8s.io/kubernetes/pkg/controller"
	"k8s.io/kubernetes/pkg/kubelet/apis/podresources"
	"k8s.io/kubernetes/pkg/kubelet/util"
)

const (
	defaultAnnot                  = "aci-cni/default-network"
	netAttachDefCRDName           = "network-attachment-definitions.k8s.cni.cncf.io"
	kubeletPodResourceDefaultPath = "/var/lib/kubelet/pod-resources"
	defaultPodResourcesMaxSize    = 1024 * 1024 * 16 // 16 Mb
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

	agent.log.Debug("running initNetworkAttachmentDefinitionFromClient")
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
	agent.log.Debug("running initNetworkAttachmentDefinitionBase")
	agent.netAttDefInformer = cache.NewSharedIndexInformer(
		listWatch, &netpolicy.NetworkAttachmentDefinition{}, controller.NoResyncPeriodFunc(),
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	agent.netAttDefInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			agent.networkAttDefAdded(obj)
		},
		UpdateFunc: func(oldobj interface{}, newobj interface{}) {
			agent.networkAttDefChanged(oldobj, newobj)
		},
		DeleteFunc: func(obj interface{}) {
			agent.networkAttDefDeleted(obj)
		},
	})
}

func (agent *HostAgent) networkAttDefAdded(obj interface{}) {
	ntd := obj.(*netpolicy.NetworkAttachmentDefinition)
	agent.log.Infof("network atttachment Added: %s", ntd.ObjectMeta.Name)
	agent.indexMutex.Lock()
	netattdata := NetworkAttachmentData{
		Name:      ntd.ObjectMeta.Name,
		Namespace: ntd.ObjectMeta.Namespace,
		Config:    ntd.Spec.Config,
		//Annot:     ntd.Spec.Annotations[defaultAnnot],
	}
	agent.log.Debug("Name", netattdata.Name)
	agent.log.Debug("Namespace", netattdata.Namespace)
	agent.log.Debug("Config", netattdata.Config)
	//agent.log.Infof("Annotion", netattdata.Annot)

	ntdKey := agent.getnetattKey(ntd)
	agent.netattdefmap[ntdKey] = &netattdata
	agent.indexMutex.Unlock()
}

func (agent *HostAgent) getnetattKey(netdata *netpolicy.NetworkAttachmentDefinition) string {
	return netdata.ObjectMeta.Name
}

func (agent *HostAgent) networkAttDefChanged(oldobj interface{}, newobj interface{}) {
	ntd := newobj.(*netpolicy.NetworkAttachmentDefinition)
	agent.log.Infof("network atttachment Changed: %s", ntd.ObjectMeta.Name)
	agent.indexMutex.Lock()
	netattdata := NetworkAttachmentData{
		Name:      ntd.ObjectMeta.Name,
		Namespace: ntd.ObjectMeta.Namespace,
		Config:    ntd.Spec.Config,
		//Annot:     ntd.Spec.Annotations[defaultAnnot],
	}
	ntdKey := agent.getnetattKey(ntd)
	agent.netattdefmap[ntdKey] = &netattdata
	agent.indexMutex.Unlock()
}

func (agent *HostAgent) networkAttDefDeleted(obj interface{}) {
	ntd := obj.(*netpolicy.NetworkAttachmentDefinition)
	agent.log.Infof("network atttachment Deleted: %s", ntd.ObjectMeta.Name)
	agent.indexMutex.Lock()
	delete(agent.netattdefmap, agent.getnetattKey(ntd))
	agent.indexMutex.Unlock()
}

// ResourceInfo is struct to hold Pod device allocation information
type DeviceId struct {
	//	Index     int
	DeviceIDs []string
}

type kubeletPodResources struct {
	resp []*podresourcesv1.PodResources
}

func (agent *HostAgent) getNetAttachment() error {
	agent.log.Debug("inside network attachment method")
	socket, err := util.LocalEndpoint(kubeletPodResourceDefaultPath, podresources.Socket)
	agent.log.Debug("connecting to local endpoint")
	if err != nil {
		fmt.Errorf("Could not retreive the kubelet sock %v", err)
	}
	client, conn, err := podresources.GetV1Client(socket, 10*time.Second, defaultPodResourcesMaxSize)
	if err != nil {
		fmt.Errorf("Could not retreive the pod resource client %v", err)
	}
	defer conn.Close()

	podResource := &kubeletPodResources{}
	//	var temp []*podresourcesv1.PodResources
	err = podResource.getPodResourceList(client)

	if err != nil {
		fmt.Errorf("Could not get pod resource from the client %v", err)
		return err
	}

	//*kubeletpodresourcesv1.ListPodResourcesResponse

	//deviceIdMap := make(map[string][]string)
	// need to take care of overwriting,
	// multiple device ids extraction
	//	podName := pod.ObjectMeta.Name
	//	podNamespace := pod.ObjectMeta.Namespace
	//
	//	agent.log.Debug("podName ", podName)
	//	agent.log.Debug("podNamespace ", podNamespace)
	//	for _, podResource := range podResource.resp {
	//		agent.log.Debug("inside first for loop")
	//		if podName == podResource.Name && podNamespace == podResource.Namespace {
	//			for _, container := range podResource.Containers {
	//				agent.log.Debug("inside containes")
	//				for _, devices := range container.Devices {
	//					agent.log.Debug("inside container devices")
	//					deviceIdMap[devices.ResourceName] = devices.DeviceIds
	//					agent.log.Debug("device ids ", devices.DeviceIds)
	//				}
	//			}
	//		}
	//	}
	return nil

}

func (podResource *kubeletPodResources) getPodResourceList(client podresourcesv1.PodResourcesListerClient) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := client.List(ctx, &podresourcesv1.ListPodResourcesRequest{})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	if resp == nil {
		return nil
	}

	podResource.resp = resp.PodResources
	return nil
}
