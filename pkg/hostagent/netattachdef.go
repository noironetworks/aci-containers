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
	"bytes"
	"context"

	"encoding/json"

	"fmt"
	"io/fs"
	"io/ioutil"
	"os"
	"path"
	"strings"
	"time"

	netpolicy "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	netClient "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/clientset/versioned"
	netattclient "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/clientset/versioned/typed/k8s.cni.cncf.io/v1"
	sriovtypes "github.com/k8snetworkplumbingwg/sriov-network-device-plugin/pkg/types"
	"github.com/k8snetworkplumbingwg/sriovnet"
	fabattv1 "github.com/noironetworks/aci-containers/pkg/fabricattachment/apis/aci.fabricattachment/v1"
	md "github.com/noironetworks/aci-containers/pkg/metadata"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
	podresourcesv1alpha1 "k8s.io/kubelet/pkg/apis/podresources/v1alpha1"
	"k8s.io/kubernetes/pkg/controller"
	"k8s.io/kubernetes/pkg/kubelet/apis/podresources"
	"path/filepath"
)

const (
	fabNetAttDefNamespace         = "aci-containers-system"
	defaultAnnot                  = "k8s.v1.cni.cncf.io/networks"
	resourceNameAnnot             = "k8s.v1.cni.cncf.io/resourceName"
	netAttachDefCRDName           = "network-attachment-definitions.k8s.cni.cncf.io"
	kubeletPodResourceDefaultPath = "/usr/local/var/lib/kubelet/pod-resources"
	podResourcesMaxSizeDefault    = 1024 * 1024 * 16 // 16 Mb
	timeout                       = 10 * time.Second
)

type PrimaryCNIType string

const (
	PrimaryCNISRIOV   = "sriov"
	PrimaryCNIMACVLAN = "macvlan"
	PrimaryCNIUnk     = "nothandled"
)

type NetworkAttachmentData struct {
	Name                 string
	Namespace            string
	IsPrimaryNetwork     bool
	Config               string
	Annot                string
	PrimaryCNI           PrimaryCNIType
	ResourcePlugin       string
	ResourceName         string
	Ifaces               []string
	EncapVlan            string
	FabricAttachmentData map[string][]*FabricAttachmentData
	Pods                 map[string]map[string]fabattv1.PodAttachment
}

type ClientInfo struct {
	NetClient netattclient.K8sCniCncfIoV1Interface
}

func (agent *HostAgent) getNetDevFromVFPCI(pci string, pfName string) string {
	vfIndex, err := sriovnet.GetVfIndexByPciAddress(pci)
	if err != nil {
		agent.log.Errorf("GetPfIndexByVfPciAddress:%s err:%v", pci, err)
		return ""
	}
	agent.log.Debugf("VF index:%d", vfIndex)
	vsNetdevName := fmt.Sprintf("%sv%v", pfName, vfIndex)
	return vsNetdevName
}

func (agent *HostAgent) getPFFromVFPCI(vfPCI string) string {
	pfPCI, err := sriovnet.GetPfPciFromVfPci(vfPCI)
	if err != nil {
		agent.log.Errorf("GetPfPciFromVfPCI:%s err:%v", vfPCI, err)
		return ""
	}
	netDevList, err := sriovnet.GetNetDevicesFromPci(pfPCI)
	if err != nil {
		agent.log.Errorf("GetNetDevicesFromPci:%s err:%v", pfPCI, err)
		return ""
	}
	if len(netDevList) > 0 {
		return netDevList[0]
	}
	agent.log.Errorf("No netdevs for VFPCI:%s", vfPCI)
	return ""
}

func (agent *HostAgent) getIfacesFromSriovResource(resourcePlugin string, resourceName string) []string {
	var ifaces []string
	kubeClient := agent.env.(*K8sEnvironment).kubeClient
	var cfgMapNamespace string
	switch resourcePlugin {
	case "openshift.io":
		cfgMapNamespace = "openshift-sriov-network-operator"
	default:
		agent.log.Errorf("Unrecognized device-plugin:%s", resourcePlugin)
		cfgMapNamespace = "default"
	}
	devPlugin, err := kubeClient.CoreV1().ConfigMaps(cfgMapNamespace).Get(context.TODO(), "device-plugin-config", metav1.GetOptions{})
	if err != nil {
		agent.log.Errorf("Failed to fetch device plugin data")
	}
	if resourceData, ok := devPlugin.Data[agent.config.NodeName]; ok {
		buf := bytes.NewBufferString(resourceData)
		var resourceConf sriovtypes.ResourceConfList
		if err = json.Unmarshal(buf.Bytes(), &resourceConf); err != nil {
			agent.log.Errorf("Failed to unmarshal device-plugin-config :%v", err)
			return ifaces
		}
		for _, resource := range resourceConf.ResourceList {
			if resource.ResourceName != resourceName {
				continue
			}
			if resource.DeviceType == sriovtypes.NetDeviceType || resource.DeviceType == "" {
				var netDevSel sriovtypes.NetDeviceSelectors
				if err = json.Unmarshal(*resource.Selectors, &netDevSel); err != nil {
					agent.log.Errorf("Failed to unmarshal netdevice selector :%v", err)
				}
				for idx := range netDevSel.PfNames {
					pfData := netDevSel.PfNames[idx]
					pfParts := strings.Split(pfData, "#")
					ifaces = append(ifaces, pfParts[0])
				}
			}
		}
	}
	return ifaces
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
	Type   string `json:"type,omitempty"`
	IPAM   IPAM   `json:"ipam,omitempty"`
	Vlan   int    `json:"vlan,omitempty"`
	Master string `json:"master,omitempty"`
}

type IPAM struct {
	Type string `json:"type,omitempty"`
}

func (agent *HostAgent) LoadAdditionalNetworkMetadata() error {
	for _, netAttData := range agent.netattdefmap {
		fabNetAttName := netAttData.Namespace + "-" + netAttData.Name
		dir := filepath.Join(agent.config.CniMetadataDir, fabNetAttName)
		files, err := ioutil.ReadDir(dir)
		if err != nil {
			agent.log.Infof("No local pods for %s: %v", fabNetAttName, err)
			continue
		}
		for _, file := range files {
			metadata, err := md.GetMetadata(agent.config.CniMetadataDir, fabNetAttName, file.Name())
			if err == nil {
				podId := metadata.Id.Namespace + "/" + metadata.Id.Pod
				if _, ok := agent.podNetworkMetadata[podId]; !ok {
					agent.podNetworkMetadata[podId] = make(map[string]map[string]*md.ContainerMetadata)
				}
				if _, ok := agent.podNetworkMetadata[podId][netAttData.Name]; !ok {
					agent.podNetworkMetadata[podId][netAttData.Name] = make(map[string]*md.ContainerMetadata)
				}
				agent.podNetworkMetadata[podId][netAttData.Name][metadata.Id.ContId] = metadata
			} else {
				agent.log.Errorf("Skipping podnetworkmeta file: %v", err)
			}
		}
	}

	return nil
}

func (agent *HostAgent) DeleteNetworkMetadata(netAttData *NetworkAttachmentData) {
	fabNetAttName := netAttData.Namespace + "-" + netAttData.Name
	networkFile := filepath.Join(agent.config.CniNetworksDir, fabNetAttName)
	if err := os.Remove(networkFile); err != nil {
		agent.log.Errorf("Failed to remove NetworkMeta: %v", err)
	}
}

func (agent *HostAgent) RecordNetworkMetadata(netAttData *NetworkAttachmentData) error {
	if err := os.MkdirAll(agent.config.CniNetworksDir, 0755); err != nil {
		return err
	}
	fabNetAttName := netAttData.Namespace + "-" + netAttData.Name
	networkFile := filepath.Join(agent.config.CniNetworksDir, fabNetAttName)
	netCont, err := json.MarshalIndent(*netAttData, "", "  ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(networkFile, netCont, 0644)
}

func (agent *HostAgent) LoadCniNetworks() error {
	_, err := os.Stat(agent.config.CniNetworksDir)
	if err != nil {
		return err
	}
	networksWalkFn := func(path string, d fs.DirEntry, err error) error {
		agent.log.Debugf("Checking path: %s", path)
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if data, err2 := os.ReadFile(path); err2 == nil {
			var netAttData NetworkAttachmentData
			if err3 := json.Unmarshal(data, &netAttData); err3 != nil {
				agent.log.Errorf("Failed to unmarshal additional network file %s:%v", path, err3)
				return nil
			}
			if netAttData.IsPrimaryNetwork {
				agent.primaryNetworkName = netAttData.Name
				return nil
			}
			netAttKey := netAttData.Namespace + "/" + netAttData.Name
			agent.netattdefmap[netAttKey] = &netAttData
			for _, localIface := range netAttData.Ifaces {
				agent.netattdefifacemap[localIface] = &netAttData
			}

		} else {
			agent.log.Errorf("Failed to read additional network file %s:%v", path, err2)
			return nil
		}
		return nil
	}

	if err := filepath.WalkDir(agent.config.CniNetworksDir, networksWalkFn); err != nil {
		agent.log.Errorf("Error while reading CniNetworksDir : %v", err)
	}

	/*Read the primary CNI config file if never cached*/
	if agent.primaryNetworkName == "" {
		data, err := os.ReadFile(agent.config.PrimaryCniPath)
		if err != nil {
			agent.log.Errorf("PrimaryCNI read failed: %v", err)
			return nil
		}
		var config Config
		if err := json.Unmarshal(data, &config); err != nil {
			agent.log.Errorf("Failed to unmarshal primaryCNI configlist %s:%v", agent.config.PrimaryCniPath, err)
			return nil
		}
		agent.primaryNetworkName = config.Name
		netAttData := NetworkAttachmentData{
			Namespace:        "default",
			Name:             agent.primaryNetworkName,
			IsPrimaryNetwork: true,
		}
		agent.RecordNetworkMetadata(&netAttData)
	}
	return nil
}

func (agent *HostAgent) NotifyFabricAdjacency(iface string, fabAttData []*FabricAttachmentData) {
	agent.indexMutex.Lock()
	if netAttData, ok := agent.netattdefifacemap[iface]; ok {
		agent.log.Debugf("Update adjacency for %s", iface)
		fabNetAttName := agent.config.NodeName + "-" + netAttData.Namespace + "-" + netAttData.Name
		nbrList := []*FabricAttachmentData{}
		for nbr := range fabAttData {
			if fabAttData[nbr].StaticPath != "" {
				nbrList = append(nbrList, fabAttData[nbr])
			}
			netAttData.FabricAttachmentData[iface] = nbrList
		}
		fabNetAtt, err := agent.fabAttClient.NodeFabricNetworkAttachments(fabNetAttDefNamespace).Get(context.TODO(), fabNetAttName, metav1.GetOptions{})
		if err == nil {
			if fabNetAtt.Spec.AciTopology == nil {
				fabNetAtt.Spec.AciTopology = make(map[string]fabattv1.AciNodeLinkAdjacency)
			}
			staticPaths := []string{}
			for nbr := range netAttData.FabricAttachmentData[iface] {
				staticPaths = append(staticPaths, netAttData.FabricAttachmentData[iface][nbr].StaticPath)
			}
			if aciAdj, ok := fabNetAtt.Spec.AciTopology[iface]; ok {
				aciAdj.FabricLink = staticPaths
				fabNetAtt.Spec.AciTopology[iface] = aciAdj
			} else {
				pods := []fabattv1.PodAttachment{}
				for podKey := range netAttData.Pods[iface] {
					pods = append(pods, netAttData.Pods[iface][podKey])
				}
				fabNetAtt.Spec.AciTopology[iface] = fabattv1.AciNodeLinkAdjacency{
					FabricLink: staticPaths,
					Pods:       pods,
				}
			}
			fabNetAtt.TypeMeta = metav1.TypeMeta{
				Kind:       "NodeFabricNetworkAttachment",
				APIVersion: "aci.fabricattachment/v1",
			}
			_, err = agent.fabAttClient.NodeFabricNetworkAttachments(fabNetAttDefNamespace).Update(context.TODO(), fabNetAtt, metav1.UpdateOptions{})
			if err != nil {
				agent.log.Errorf("Failed to update adjacency:%v", err)
			}
		}
	}
	agent.indexMutex.Unlock()

}

func (agent *HostAgent) updateFabricPodNetworkAttachmentLocked(pod *fabattv1.PodAttachment, networkName string, podDeleted bool) error {
	var err error
	var podIface string
	adjFound := false
	podKey := pod.PodRef.Name + "-" + pod.PodRef.Namespace
	netAttDefName := pod.PodRef.Namespace + "/" + networkName
	if _, ok := agent.netattdefmap[netAttDefName]; ok {
		netattData := agent.netattdefmap[netAttDefName]
		if netattData.PrimaryCNI == "sriov" {
			for _, podNetMeta := range agent.podNetworkMetadata[pod.PodRef.Namespace+"/"+pod.PodRef.Name][networkName] {
				podIface = podNetMeta.Network.PFName
				if podIface != "" {
					break
				}
			}
		} else if netattData.PrimaryCNI == "macvlan" {
			podIface = netattData.ResourceName
		}
		if podIface != "" {
			if podDeleted {
				if _, ok := netattData.Pods[podIface][podKey]; ok {
					delete(netattData.Pods[podIface], podKey)
					agent.updateNodeFabricNetworkAttachmentLocked(netattData)
				}
				return nil
			}
			if _, ok := netattData.Pods[podIface]; !ok {
				netattData.Pods[podIface] = make(map[string]fabattv1.PodAttachment)
			}
			podIfaceMap := netattData.Pods[podIface]
			podIfaceMap[podKey] = *pod
			netattData.Pods[podIface] = podIfaceMap
			agent.updateNodeFabricNetworkAttachmentLocked(netattData)
			if nbrList, ok := netattData.FabricAttachmentData[podIface]; ok {
				for _, nbr := range nbrList {
					if nbr.StaticPath != "" {
						adjFound = true
						break
					}
				}
			}
		}
	}
	if !adjFound && !podDeleted {
		err = fmt.Errorf("LLDP adjacency with ACI fabric not found on interface %v", podIface)
	}
	return err
}

func (agent *HostAgent) updateNodeFabricNetworkAttachmentLocked(netAttData *NetworkAttachmentData) error {

	populateTopology := func(fabNetAtt *fabattv1.NodeFabricNetworkAttachment, netAttData *NetworkAttachmentData) {
		for iface := range netAttData.FabricAttachmentData {
			staticPaths := []string{}
			for nbr := range netAttData.FabricAttachmentData[iface] {
				staticPaths = append(staticPaths, netAttData.FabricAttachmentData[iface][nbr].StaticPath)
			}
			fabNetAtt.Spec.AciTopology[iface] = fabattv1.AciNodeLinkAdjacency{
				FabricLink: staticPaths,
				Pods:       []fabattv1.PodAttachment{},
			}
			aciNodeLink := fabNetAtt.Spec.AciTopology[iface]
			if attachedPods, ok := netAttData.Pods[iface]; ok {
				for podKey := range attachedPods {
					aciNodeLink.Pods = append(aciNodeLink.Pods, attachedPods[podKey])
				}
			}
			fabNetAtt.Spec.AciTopology[iface] = aciNodeLink
		}

	}
	fabNetAttName := agent.config.NodeName + "-" + netAttData.Namespace + "-" + netAttData.Name
	fabNetAtt, err := agent.fabAttClient.NodeFabricNetworkAttachments(fabNetAttDefNamespace).Get(context.TODO(), fabNetAttName, metav1.GetOptions{})
	if err == nil {
		fabNetAtt.TypeMeta = metav1.TypeMeta{
			Kind:       "NodeFabricNetworkAttachment",
			APIVersion: "aci.fabricattachment/v1",
		}
		fabNetAtt.Spec.EncapVlan = netAttData.EncapVlan
		fabNetAtt.Spec.AciTopology = make(map[string]fabattv1.AciNodeLinkAdjacency)
		populateTopology(fabNetAtt, netAttData)
		_, err = agent.fabAttClient.NodeFabricNetworkAttachments(fabNetAttDefNamespace).Update(context.TODO(), fabNetAtt, metav1.UpdateOptions{})
		agent.RecordNetworkMetadata(netAttData)

	} else if apierrors.IsNotFound(err) {
		fabNetAtt = &fabattv1.NodeFabricNetworkAttachment{
			TypeMeta: metav1.TypeMeta{
				Kind:       "NodeFabricNetworkAttachment",
				APIVersion: "aci.fabricattachment/v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      fabNetAttName,
				Namespace: fabNetAttDefNamespace,
			},
			Spec: fabattv1.NodeFabricNetworkAttachmentSpec{
				NetworkRef: fabattv1.ObjRef{
					Name:      netAttData.Name,
					Namespace: netAttData.Namespace,
				},
				EncapVlan:   netAttData.EncapVlan,
				NodeName:    agent.config.NodeName,
				AciTopology: make(map[string]fabattv1.AciNodeLinkAdjacency),
			},
		}
		populateTopology(fabNetAtt, netAttData)
		_, err = agent.fabAttClient.NodeFabricNetworkAttachments(fabNetAttDefNamespace).Create(context.TODO(), fabNetAtt, metav1.CreateOptions{})
		agent.RecordNetworkMetadata(netAttData)
	}
	return err

}

func (agent *HostAgent) deleteNodeFabricNetworkAttachment(netattData *NetworkAttachmentData) error {
	fabNetAttKey := agent.config.NodeName + "-" + netattData.Namespace + "-" + netattData.Name
	return agent.fabAttClient.NodeFabricNetworkAttachments(fabNetAttDefNamespace).Delete(context.TODO(), fabNetAttKey, metav1.DeleteOptions{})
}

func (agent *HostAgent) parseChainedPlugins(config Config, netattData *NetworkAttachmentData) bool {
	relevantChain := false
	for idx, plugin := range config.Plugins {
		if idx == 0 {
			if plugin.Type == "sriov" {
				netattData.PrimaryCNI = PrimaryCNISRIOV
				parts := strings.Split(netattData.Annot, "/")
				if len(parts) == 2 {
					netattData.ResourcePlugin = parts[0]
					netattData.ResourceName = parts[1]
				}
				if len(parts) == 1 {
					netattData.ResourceName = parts[0]
				}
				if len(parts) > 2 {
					agent.log.Errorf("resourcename %s unrecognized in  net-att-def %s/%s", netattData.Annot, netattData.Namespace, netattData.Name)
				}
				agent.log.Infof("Using resource %s", netattData.ResourceName)
				netattData.EncapVlan = fmt.Sprintf("%d", plugin.Vlan)

			} else if plugin.Type == "macvlan" {
				netattData.PrimaryCNI = PrimaryCNIMACVLAN
				parts := strings.Split(plugin.Master, ".")
				if len(parts) != 2 {
					agent.log.Errorf("master interface %s unrecognized in  net-att-def %s/%s", plugin.Master, netattData.Namespace, netattData.Name)
				} else {
					netattData.ResourceName = parts[0]
					netattData.EncapVlan = parts[1]
				}
			} else {
				netattData.PrimaryCNI = PrimaryCNIUnk
			}
		} else {
			if (plugin.Type == "opflex-agent-cni") || (plugin.Type == "netop-cni") {
				relevantChain = true
			}
		}

	}
	return relevantChain
}

func (agent *HostAgent) networkAttDefAdded(obj interface{}) {
	ntd := obj.(*netpolicy.NetworkAttachmentDefinition)
	agent.log.Infof("network atttachment definition added: %s", ntd.ObjectMeta.Name)
	agent.networkAttDefChanged(ntd)
}

func (agent *HostAgent) networkAttDefChanged(ntd *netpolicy.NetworkAttachmentDefinition) {
	netattdata := NetworkAttachmentData{
		Name:             ntd.ObjectMeta.Name,
		Namespace:        ntd.ObjectMeta.Namespace,
		Config:           ntd.Spec.Config,
		Annot:            ntd.ObjectMeta.Annotations[resourceNameAnnot],
		IsPrimaryNetwork: false,
	}
	var config Config

	if agent.config.ChainedMode {
		netAttDefKey := ntd.ObjectMeta.Namespace + "/" + ntd.ObjectMeta.Name
		netattdata.Pods = make(map[string]map[string]fabattv1.PodAttachment)
		netattdata.FabricAttachmentData = make(map[string][]*FabricAttachmentData)
		netattdata.Ifaces = []string{}
		primaryCniDir := filepath.Dir(agent.config.PrimaryCniPath)
		agent.log.Debugf("Checking netattdef in chained mode: %s", netAttDefKey)
		agent.log.Debugf("Primary CNI path: %s", primaryCniDir)
		relevantChain := false
		if ntd.Spec.Config == "" {
			// For a delegating plugin like Multus- it can use this method of
			// referring to a file for additional network definition
			cniWalkFn := func(path string, d fs.DirEntry, err error) error {
				agent.log.Debugf("Checking path: %s", path)
				if err != nil {
					return err
				}
				if d.IsDir() {
					return nil
				}
				if data, err2 := os.ReadFile(path); err2 == nil {
					// We only support being secondary plugin in chained mode
					if strings.HasSuffix(path, ".conflist") {
						if err3 := json.Unmarshal(data, &config); err3 != nil {
							agent.log.Errorf("Failed to read CNI configlist %s:%v", path, err3)
							return nil
						}
						if config.Name == ntd.ObjectMeta.Name {
							relevantChain = agent.parseChainedPlugins(config, &netattdata)
							return fs.SkipAll
						}
					} else {
						agent.log.Debugf("Ignoring individual cni in chained mode: %s", path)
					}
				}
				return nil
			}
			if err := filepath.WalkDir(primaryCniDir, cniWalkFn); err != nil {
				agent.log.Errorf("Error while reading CniDir : %v", err)
			}
		} else {
			// For a non-delegating plugin, both lists and individual cni are specified here
			json.Unmarshal([]byte(ntd.Spec.Config), &config)
			relevantChain = agent.parseChainedPlugins(config, &netattdata)
		}
		if relevantChain {
			agent.log.Infof("Valid netattdef in chained mode: %s", netAttDefKey)
			agent.indexMutex.Lock()
			nodeFabNetAttName := agent.config.NodeName + "-" + netattdata.Namespace + "-" + netattdata.Name
			if netattdata.PrimaryCNI == PrimaryCNIMACVLAN {
				agent.netattdefifacemap[netattdata.ResourceName] = &netattdata
				netattdata.Ifaces = append(netattdata.Ifaces, netattdata.ResourceName)
			} else if netattdata.PrimaryCNI == PrimaryCNISRIOV {
				netattdata.Ifaces = append(netattdata.Ifaces, agent.getIfacesFromSriovResource(netattdata.ResourcePlugin, netattdata.ResourceName)...)
			}
			agent.log.Infof("Physical ifaces for nodefabricnetworkattachment %s :%v", nodeFabNetAttName, netattdata.Ifaces)
			if prevnetattdata, ok := agent.netattdefmap[netAttDefKey]; ok {
				netattdata.Pods = prevnetattdata.Pods
				netattdata.FabricAttachmentData = prevnetattdata.FabricAttachmentData
			}
			agent.netattdefmap[netAttDefKey] = &netattdata
			for _, iface := range netattdata.Ifaces {
				agent.netattdefifacemap[iface] = &netattdata
				if fabAttData, err := agent.fabricDiscoveryAgent.GetNeighborData(iface); err == nil {
					if fabAttData != nil {
						netattdata.FabricAttachmentData[iface] = fabAttData
					}
				}
			}
			if err := agent.updateNodeFabricNetworkAttachmentLocked(&netattdata); err != nil {
				agent.log.Errorf("Failed to create/update nodefabricnetworkattachment %s :%v", nodeFabNetAttName, err)
			}
			agent.indexMutex.Unlock()
		}
		return
	}

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
				agent.log.Debug("Network Attachment Definition is not ACICNI specific")
			}
		}
	}
}

func (agent *HostAgent) networkAttDefUpdated(oldobj interface{}, newobj interface{}) {
	ntd := newobj.(*netpolicy.NetworkAttachmentDefinition)
	agent.log.Infof("network attachment definition changed: %s", ntd.ObjectMeta.Name)
	agent.networkAttDefChanged(ntd)
}

func (agent *HostAgent) networkAttDefDeleted(obj interface{}) {
	ntd, isNtd := obj.(*netpolicy.NetworkAttachmentDefinition)
	if !isNtd {
		deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			agent.log.Error("Received unexpected object: ", obj)
			return
		}
		ntd, ok = deletedState.Obj.(*netpolicy.NetworkAttachmentDefinition)
		if !ok {
			agent.log.Error("DeletedFinalStateUnknown contained non-NetworkAttachmentDefinition object: ", deletedState.Obj)
			return
		}
	}
	agent.log.Infof("network attachment definition deleted: %s", ntd.ObjectMeta.Name)
	var netAttDefKey string
	if agent.config.ChainedMode {
		netAttDefKey = ntd.ObjectMeta.Namespace + "/" + ntd.ObjectMeta.Name
	} else {
		netAttDefKey = ntd.ObjectMeta.Name
	}
	agent.indexMutex.Lock()
	if netattDef, ok := agent.netattdefmap[netAttDefKey]; ok {
		err := agent.deleteNodeFabricNetworkAttachment(netattDef)
		if err != nil {
			agent.log.Errorf("node fabric network attachment delete failed:%v", err)
		}
		if netattDef.PrimaryCNI == PrimaryCNIMACVLAN {
			delete(agent.netattdefifacemap, netattDef.ResourceName)
		} else if netattDef.PrimaryCNI == PrimaryCNISRIOV {
			for _, iface := range netattDef.Ifaces {
				delete(agent.netattdefifacemap, iface)
			}
		}
		agent.DeleteNetworkMetadata(netattDef)
	}
	delete(agent.netattdefmap, netAttDefKey)
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

func (agent *HostAgent) getAlloccatedDeviceId(metadata *md.ContainerMetadata, smartnicmode string) error {
	var err error
	var acicni bool
	if smartnicmode == "dpu" || smartnicmode == "chained" {
		err = agent.getPodResource(metadata)
	} else {
		acicni, err = agent.isAcicniNetwork(metadata)
		if acicni {
			err = agent.getPodResource(metadata)
		}
	}
	return err
}

func (agent *HostAgent) isAcicniNetwork(metadata *md.ContainerMetadata) (bool, error) {
	var isAcicniNetwork bool
	agent.indexMutex.Lock()
	netList := agent.podToNetAttachDef[metadata.Id.Pod+"-"+metadata.Id.Namespace]
	agent.indexMutex.Unlock()
	for _, netAttName := range netList {
		if agent.netattdefmap[netAttName] != nil {
			isAcicniNetwork = true
			return isAcicniNetwork, nil
		} else {
			return isAcicniNetwork, fmt.Errorf("Network Attachment Definition CR not applied: Must mention ACICNI plugin")
		}
	}
	return isAcicniNetwork, fmt.Errorf("No Network Attachment Definition CR found")
}

func (agent *HostAgent) getPodResource(metadata *md.ContainerMetadata) error {
	podResourceSock := path.Join(kubeletPodResourceDefaultPath, podresources.Socket+".sock")
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

	return nil
}
