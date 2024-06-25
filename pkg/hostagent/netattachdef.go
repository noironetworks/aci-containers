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
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"path/filepath"

	netpolicy "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	netClient "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/clientset/versioned"
	netattclient "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/clientset/versioned/typed/k8s.cni.cncf.io/v1"
	sriovtypes "github.com/k8snetworkplumbingwg/sriov-network-device-plugin/pkg/types"
	"github.com/k8snetworkplumbingwg/sriovnet"
	fabattv1 "github.com/noironetworks/aci-containers/pkg/fabricattachment/apis/aci.fabricattachment/v1"
	md "github.com/noironetworks/aci-containers/pkg/metadata"
	"github.com/noironetworks/aci-containers/pkg/util"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
	podresourcesv1alpha1 "k8s.io/kubelet/pkg/apis/podresources/v1alpha1"
	"k8s.io/kubernetes/pkg/controller"
	"k8s.io/kubernetes/pkg/kubelet/apis/podresources"
)

const (
	fabNetAttDefNamespace         = "aci-containers-system"
	defaultAnnot                  = "k8s.v1.cni.cncf.io/networks"
	resourceNameAnnot             = "k8s.v1.cni.cncf.io/resourceName"
	vlanAnnot                     = "netop-cni.cisco.com/vlans"
	netAttachDefCRDName           = "network-attachment-definitions.k8s.cni.cncf.io"
	kubeletPodResourceDefaultPath = "/usr/local/var/lib/kubelet/pod-resources"
	podResourcesMaxSizeDefault    = 1024 * 1024 * 16 // 16 Mb
	timeout                       = 10 * time.Second
)

var (
	ErrLLDPAdjacency             = errors.New("LLDP adjacency with ACI fabric not found")
	ErrNoAllocatableVlan         = errors.New("No encap specified/derivable for network-attachment-definition")
	ErrNoAllocatableVlanUntagged = errors.New("Invalid Encap for untagged network-attachment-definition")
	ErrMultipleEncapUntagged     = errors.New("Multiple encap specified/derivable for untagged network-attachment-definition")
)

type PrimaryCNIType string

const (
	PrimaryCNISRIOV           = "sriov"
	PrimaryCNIMACVLAN         = "macvlan"
	PrimaryCNIBridge          = "bridge"
	PrimaryCNIOpenShiftBridge = "cnv-bridge"
	PrimaryCNIIPVLAN          = "ipvlan"
	PrimaryCNIOVS             = "ovs"
	PrimaryCNIUnk             = "nothandled"
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
	KnownAnnots          map[string]string
	EncapKey             string
	PluginVlan           string
	EncapMode            util.EncapMode
	PluginTrunk          []TrunkConfig
	Programmed           bool
	PluginAllowUntagged  bool
	Status               string
}

type ClientInfo struct {
	NetClient netattclient.K8sCniCncfIoV1Interface
}

func (agent *HostAgent) setNodeFabNetAttStatusLocked(netAttData *NetworkAttachmentData) {
	if netAttData.PrimaryCNI == PrimaryCNIUnk {
		netAttData.Status = fmt.Sprintf("Primary CNI on this network is not supported")
		return
	}
	if netAttData.EncapVlan == "" {
		if netAttData.EncapKey != "" {
			netAttData.Status = "NadVlanMap is a match but vlan is not present in Fabricvlanpool"
			return
		}
		netAttData.Status = "No allocatable vlan: specify using fabricvlanpool and annotation/nad/nadvlanmap"
		return
	}
	if netAttData.EncapMode == util.EncapModeUntagged {
		vlans, _, _, err2 := util.ParseVlanList([]string{netAttData.EncapVlan})
		if err2 != nil {
			netAttData.Status = "vlan format incorrect"
			return
		} else if len(vlans) > 1 {
			netAttData.Status = "Ensure only one implicit uplink vlan for ipvlan network"
			return
		}
	}
	netAttData.Status = "Complete"
}

func (agent *HostAgent) getNetDevFromVFPCI(pci, pfName string) string {
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

func (agent *HostAgent) getIfacesFromSriovResource(resourcePlugin, resourceName string) []string {
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

type TrunkConfig struct {
	Id    int `json:"id,omitempty"`
	MinID int `json:"minID,omitempty"`
	MaxID int `json:"maxID,omitempty"`
}

type Plugins struct {
	Type             string        `json:"type,omitempty"`
	IPAM             IPAM          `json:"ipam,omitempty"`
	Vlan             int           `json:"vlan,omitempty"`
	IsDefaultGateway bool          `json:"isDefaultGateway,omitempty"`
	Trunk            []TrunkConfig `json:"vlanTrunk,omitempty"`
	Master           string        `json:"master,omitempty"`
	Bridge           string        `json:"bridge,omitempty"`
}

type IPAM struct {
	Type string `json:"type,omitempty"`
}

func (agent *HostAgent) LoadAdditionalNetworkMetadata() error {
	for _, netAttData := range agent.netattdefmap {
		fabNetAttName := netAttData.Namespace + "-" + netAttData.Name
		dir := filepath.Join(agent.config.CniMetadataDir, fabNetAttName)
		files, err := os.ReadDir(dir)
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
	return os.WriteFile(networkFile, netCont, 0644)
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
	defer agent.indexMutex.Unlock()
	if netAttData, ok := agent.netattdefifacemap[iface]; ok {
		agent.log.Debugf("Update adjacency for %s", iface)
		nbrList := []*FabricAttachmentData{}
		for nbr := range fabAttData {
			if fabAttData[nbr].StaticPath != "" {
				nbrList = append(nbrList, fabAttData[nbr])
				agent.log.Debugf("Adjacency: %s", fabAttData[nbr].StaticPath)
			}
			netAttData.FabricAttachmentData[iface] = nbrList
		}
		agent.updateNodeFabricNetworkAttachmentLocked(netAttData)
	}
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
		} else {
			podIface = netattData.ResourceName
		}
		if podIface != "" {
			if podDeleted {
				if _, ok := netattData.Pods[podIface][podKey]; ok {
					delete(netattData.Pods[podIface], podKey)
					if len(netattData.Pods[podIface]) == 0 {
						delete(netattData.Pods, podIface)
					}
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
		if (netattData.EncapVlan == "" || netattData.EncapVlan == "[]") && !podDeleted {
			err = fmt.Errorf("%w %s/%s. Specify fabricvlanpool at the least or specific vlan to use", ErrNoAllocatableVlan, netattData.Namespace, netattData.Name)
		} else if (netattData.PrimaryCNI == PrimaryCNIIPVLAN) && !podDeleted {
			if netattData.EncapMode == util.EncapModeUntagged {
				vlans, _, _, err2 := util.ParseVlanList([]string{netattData.EncapVlan})
				if err2 != nil {
					err = fmt.Errorf("%w %s/%s", ErrNoAllocatableVlanUntagged, netattData.Namespace, netattData.Name)
				} else if len(vlans) > 1 {
					err = fmt.Errorf("%w %s/%s. Ensure only one implicit uplink vlan for ipvlan network", ErrMultipleEncapUntagged, netattData.Namespace, netattData.Name)
				}
			}
		}
	}
	if !adjFound && !podDeleted {
		err = fmt.Errorf("%w on interface %v", ErrLLDPAdjacency, podIface)
	}
	agent.log.Debug(err)
	return err
}

func (agent *HostAgent) updateNodeFabricNetworkAttachmentEncap(fabNetAtt *fabattv1.NodeFabricNetworkAttachment, netAttData *NetworkAttachmentData) {
	fabNetAtt.Spec.EncapVlan = fabattv1.EncapSource{
		VlanList: netAttData.EncapVlan,
		Mode:     netAttData.EncapMode.ToFabAttEncapMode(),
	}
	if netAttData.EncapKey != "" {
		fabNetAtt.Spec.EncapVlan.EncapRef = fabattv1.EncapRef{
			NadVlanMapRef: "aci-containers-system/nad-vlan-map",
			Key:           netAttData.EncapKey,
		}
	}
	agent.setNodeFabNetAttStatusLocked(netAttData)
	fabNetAtt.Status.State = fabattv1.FabricAttachmentState(netAttData.Status)
}

func (agent *HostAgent) updateNodeFabricNetworkAttachmentForEncapChangeLocked(nadKey, encapKey, vlanList string, isDelete bool) {
	netAttData, ok := agent.netattdefmap[nadKey]
	if !ok {
		agent.log.Debugf("NAD not found %s", nadKey)
		return
	}
	if !isDelete {
		vlanList = agent.getAllowedVlansLocked(vlanList, netAttData.Namespace)
		netAttData.EncapVlan = vlanList
		netAttData.EncapKey = encapKey
		agent.log.Debugf("Using nadVlanMap allowed list : %s", vlanList)
	} else {
		agent.handlePluginVlan(netAttData)
	}
	fabNetAttName := agent.config.NodeName + "-" + netAttData.Namespace + "-" + netAttData.Name
	fabNetAtt, err := agent.fabAttClient.NodeFabricNetworkAttachments(fabNetAttDefNamespace).Get(context.TODO(), fabNetAttName, metav1.GetOptions{})
	if err == nil {
		fabNetAtt.TypeMeta = metav1.TypeMeta{
			Kind:       "NodeFabricNetworkAttachment",
			APIVersion: "aci.fabricattachment/v1",
		}
		agent.updateNodeFabricNetworkAttachmentEncap(fabNetAtt, netAttData)
		_, err = agent.fabAttClient.NodeFabricNetworkAttachments(fabNetAttDefNamespace).Update(context.TODO(), fabNetAtt, metav1.UpdateOptions{})
		agent.RecordNetworkMetadata(netAttData)
		if err != nil {
			agent.log.Errorf("Failed to update nfna %s for encap change: %v", fabNetAttName, err)
		}
	}
}

func (agent *HostAgent) updateNodeFabricNetworkAttachmentForFabricVlanPoolLocked() {
	for _, netAttData := range agent.netattdefmap {
		agent.handlePluginVlan(netAttData)
		fabNetAttName := agent.config.NodeName + "-" + netAttData.Namespace + "-" + netAttData.Name
		fabNetAtt, err := agent.fabAttClient.NodeFabricNetworkAttachments(fabNetAttDefNamespace).Get(context.TODO(), fabNetAttName, metav1.GetOptions{})
		if err == nil {
			fabNetAtt.TypeMeta = metav1.TypeMeta{
				Kind:       "NodeFabricNetworkAttachment",
				APIVersion: "aci.fabricattachment/v1",
			}
			agent.updateNodeFabricNetworkAttachmentEncap(fabNetAtt, netAttData)
			_, err = agent.fabAttClient.NodeFabricNetworkAttachments(fabNetAttDefNamespace).Update(context.TODO(), fabNetAtt, metav1.UpdateOptions{})
			agent.RecordNetworkMetadata(netAttData)
			if err != nil {
				agent.log.Errorf("Failed to update nfna %s for pool change: %v", fabNetAttName, err)
			}
		}
	}
}

func (netAttData *NetworkAttachmentData) isProgrammable() bool {
	if len(netAttData.FabricAttachmentData) == 0 {
		return false
	}
	return true
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
	agent.RecordNetworkMetadata(netAttData)
	fabNetAttName := agent.config.NodeName + "-" + netAttData.Namespace + "-" + netAttData.Name
	fabNetAtt, err := agent.fabAttClient.NodeFabricNetworkAttachments(fabNetAttDefNamespace).Get(context.TODO(), fabNetAttName, metav1.GetOptions{})
	if err == nil {
		if !netAttData.isProgrammable() {
			agent.deleteNodeFabricNetworkAttachment(netAttData)
			netAttData.Programmed = false
			agent.log.Infof("Skip programming for %s", netAttData.Namespace+"/"+netAttData.Name)
			return nil
		}
		fabNetAtt.TypeMeta = metav1.TypeMeta{
			Kind:       "NodeFabricNetworkAttachment",
			APIVersion: "aci.fabricattachment/v1",
		}
		agent.updateNodeFabricNetworkAttachmentEncap(fabNetAtt, netAttData)
		fabNetAtt.Spec.AciTopology = make(map[string]fabattv1.AciNodeLinkAdjacency)
		populateTopology(fabNetAtt, netAttData)
		_, err = agent.fabAttClient.NodeFabricNetworkAttachments(fabNetAttDefNamespace).Update(context.TODO(), fabNetAtt, metav1.UpdateOptions{})
		netAttData.Programmed = true
	} else if apierrors.IsNotFound(err) {
		if !netAttData.isProgrammable() {
			agent.log.Infof("Skip programming for %s", netAttData.Namespace+"/"+netAttData.Name)
			return nil
		}
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
				NodeName:    agent.config.NodeName,
				PrimaryCNI:  string(netAttData.PrimaryCNI),
				AciTopology: make(map[string]fabattv1.AciNodeLinkAdjacency),
			},
		}
		agent.updateNodeFabricNetworkAttachmentEncap(fabNetAtt, netAttData)
		populateTopology(fabNetAtt, netAttData)
		_, err = agent.fabAttClient.NodeFabricNetworkAttachments(fabNetAttDefNamespace).Create(context.TODO(), fabNetAtt, metav1.CreateOptions{})
		netAttData.Programmed = true
	}
	return err
}

func (agent *HostAgent) deleteNodeFabricNetworkAttachment(netattData *NetworkAttachmentData) error {
	fabNetAttKey := agent.config.NodeName + "-" + netattData.Namespace + "-" + netattData.Name
	return agent.fabAttClient.NodeFabricNetworkAttachments(fabNetAttDefNamespace).Delete(context.TODO(), fabNetAttKey, metav1.DeleteOptions{})
}

func validateVlanAnnotation(vlanStr string) (string, error) {
	vlanStr = strings.TrimSpace(vlanStr)
	firstStageStr := vlanStr
	_, after, found := strings.Cut(vlanStr, "[")
	if found {
		var found2 bool
		firstStageStr, _, found2 = strings.Cut(after, "]")
		if !found2 {
			return "", fmt.Errorf("Mismatched brackets")
		}
	}
	resultStr := "["
	vlanElemStr := ""
	vlans := strings.Split(firstStageStr, ",")
	firstInst := true
	for _, vlan := range vlans {
		vlanTrimmed := strings.TrimSpace(vlan)
		vlanRange := strings.Split(vlanTrimmed, "-")
		if len(vlanRange) > 2 {
			return "", fmt.Errorf("Incorrect vlan range %s", vlanTrimmed)
		}
		if len(vlanRange) == 2 {
			vlanFrom, err1 := strconv.Atoi(vlanRange[0])
			vlanTo, err2 := strconv.Atoi(vlanRange[1])
			if (err1 != nil) || (err2 != nil) || (vlanFrom > vlanTo) {
				return "", fmt.Errorf("Incorrect vlan range %s", vlanTrimmed)
			}
			vlanElemStr = fmt.Sprintf("%d-%d", vlanFrom, vlanTo)
		} else if len(vlanRange) == 1 {
			singleVlan, err3 := strconv.Atoi(vlanRange[0])
			if err3 != nil {
				return "", fmt.Errorf("Incorrect vlan range %s", vlanTrimmed)
			}
			vlanElemStr = fmt.Sprintf("%d", singleVlan)
		} else {
			return "", fmt.Errorf("Incorrect vlan %s", vlanTrimmed)
		}
		if !firstInst {
			resultStr += ","
		}
		resultStr += vlanElemStr
		firstInst = false
	}
	if firstInst {
		return "", fmt.Errorf("No vlan in the annotation:%v", firstStageStr)
	}
	resultStr += "]"
	return resultStr, nil
}

func (agent *HostAgent) getAllowedVlansLocked(encapStr string, namespace string) (allowedStr string) {
	poolStr := agent.getFabricVlanPool(namespace, true)
	poolVlans, _, _, err := util.ParseVlanList([]string{poolStr})
	if err != nil {
		return ""
	}
	vlans, _, _, err := util.ParseVlanList([]string{encapStr})
	if err != nil {
		return ""
	}
	vlanMap := make(map[int]bool)
	for _, elem := range vlans {
		vlanMap[elem] = false
	}
	for _, elem := range poolVlans {
		if _, ok := vlanMap[elem]; ok {
			if allowedStr == "" {
				allowedStr = fmt.Sprintf("[%d", elem)
				continue
			}
			allowedStr += fmt.Sprintf(",%d", elem)
		}
	}
	if len(allowedStr) != 0 {
		allowedStr += "]"
	}
	return allowedStr
}

func (agent *HostAgent) handlePluginVlan(netAttData *NetworkAttachmentData) {
	nadKey := netAttData.Namespace + "/" + netAttData.Name
	if netAttData.PluginVlan == "0" {
		netAttData.EncapMode = util.EncapModeTrunk
		if (netAttData.PrimaryCNI == PrimaryCNIBridge) ||
			(netAttData.PrimaryCNI == PrimaryCNIOpenShiftBridge) ||
			(netAttData.PrimaryCNI == PrimaryCNIOVS) {
			vlanStr := ""
			for _, trunkElem := range netAttData.PluginTrunk {
				vlan := ""
				if trunkElem.Id != 0 {
					vlan = fmt.Sprintf("%d", trunkElem.Id)
				} else if trunkElem.MaxID > trunkElem.MinID {
					vlan = fmt.Sprintf("%d-%d", trunkElem.MinID, trunkElem.MaxID)
				} else {
					continue
				}
				if vlanStr == "" {
					vlanStr += "[" + vlan
					continue
				}
				vlanStr += "," + vlan
			}
			if vlanStr != "" {
				vlanStr += "]"
			}
			netAttData.EncapVlan = vlanStr
			netAttData.EncapKey = ""
			if vlanStr != "" {
				agent.log.Debugf("Using trunk config: %s", vlanStr)
				return
			} else if (netAttData.PluginAllowUntagged) && ((netAttData.PrimaryCNI == PrimaryCNIBridge) ||
				(netAttData.PrimaryCNI == PrimaryCNIOpenShiftBridge)) {
				netAttData.EncapMode = util.EncapModeUntagged
				agent.log.Debugf("Using untagged mode for bridge")
			}
		} else if netAttData.PrimaryCNI == PrimaryCNIIPVLAN {
			netAttData.EncapMode = util.EncapModeUntagged
		}
		if val, ok := netAttData.KnownAnnots[vlanAnnot]; ok {
			if vlanStr, err := validateVlanAnnotation(val); err == nil {
				vlanStr = agent.getAllowedVlansLocked(vlanStr, netAttData.Namespace)
				agent.log.Debugf("Using annotation: %s", vlanStr)
				netAttData.EncapVlan = vlanStr
				netAttData.EncapKey = ""
				return
			} else {
				agent.log.Errorf("Failed to parse vlan annotation:%v", err)
			}
		}
		matchingKey, vlanList, match := agent.getNadVlanMapMatchLocked(nadKey)
		if match {
			vlanList = agent.getAllowedVlansLocked(vlanList, netAttData.Namespace)
			agent.log.Debugf("Using nadVlanMap: %s", vlanList)
			netAttData.EncapVlan = vlanList
			netAttData.EncapKey = matchingKey
			return
		}
		vlanStr := agent.getFabricVlanPool(netAttData.Namespace, true)
		agent.log.Debugf("Using vlan pool: %s", vlanStr)
		netAttData.EncapVlan = vlanStr
		netAttData.EncapKey = ""
		return
	}
	vlanStr := agent.getAllowedVlansLocked(netAttData.PluginVlan, netAttData.Namespace)
	agent.log.Debugf("Using vlan in NAD: %s", vlanStr)
	netAttData.EncapVlan = vlanStr
	netAttData.EncapKey = ""
	return
}

func (agent *HostAgent) parseChainedPlugins(config Config, netattData *NetworkAttachmentData) bool {
	relevantChain := false
	for idx, plugin := range config.Plugins {
		if idx == 0 {
			if netattData.Annot != "" {
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

			}
			switch plugin.Type {
			case "sriov":
				{
					netattData.PrimaryCNI = PrimaryCNISRIOV
					agent.log.Infof("Using resource %s", netattData.ResourceName)
					netattData.PluginVlan = fmt.Sprintf("%d", plugin.Vlan)
					agent.handlePluginVlan(netattData)
				}
			case "macvlan", "ipvlan":
				{
					netattData.PrimaryCNI = PrimaryCNIMACVLAN
					if plugin.Type == "ipvlan" {
						netattData.PrimaryCNI = PrimaryCNIIPVLAN
					}
					parts := strings.Split(plugin.Master, ".")
					netattData.ResourceName = parts[0]
					if len(parts) != 2 {
						netattData.PluginVlan = "0"
						agent.handlePluginVlan(netattData)
						if len(parts) != 1 {
							agent.log.Errorf("master interface encap not parseable %s in net-att-def %s/%s", plugin.Master, netattData.Namespace, netattData.Name)
						}
					} else {
						netattData.PluginVlan = parts[1]
						_, err := strconv.Atoi(parts[1])
						if err != nil {
							agent.log.Errorf("master interface encap not parseable %s in net-att-def %s/%s", plugin.Master, netattData.Namespace, netattData.Name)
							netattData.PluginVlan = "0"
						}
						agent.handlePluginVlan(netattData)
					}
				}
			case "bridge", "ovs", "cnv-bridge":
				{
					netattData.PrimaryCNI = PrimaryCNIBridge
					if plugin.Type == "ovs" {
						netattData.PrimaryCNI = PrimaryCNIOVS
					}
					if plugin.Type == "cnv-bridge" {
						netattData.PrimaryCNI = PrimaryCNIOpenShiftBridge
					}
					netattData.PluginVlan = fmt.Sprintf("%d", plugin.Vlan)
					netattData.PluginTrunk = plugin.Trunk
					if plugin.IsDefaultGateway && ((plugin.Type == "bridge") || (plugin.Type == "cnv-bridge")) {
						netattData.PluginAllowUntagged = true
					}
					agent.handlePluginVlan(netattData)
					if (netattData.ResourceName != "") && (netattData.ResourceName != plugin.Bridge) {
						agent.log.Errorf("resourcename annotation %s does not match bridgename %s", netattData.ResourceName, plugin.Bridge)
					}
					netattData.ResourceName = plugin.Bridge
				}
			default:
				{
					netattData.PrimaryCNI = PrimaryCNIUnk
				}
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
		KnownAnnots:      make(map[string]string),
		IsPrimaryNetwork: false,
	}
	/* Add new annotations here for backward compatibilty with ep file */
	for _, annot := range []string{vlanAnnot} {
		if val, ok := ntd.ObjectMeta.Annotations[annot]; ok {
			netattdata.KnownAnnots[annot] = val
		}
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
		agent.indexMutex.Lock()
		defer agent.indexMutex.Unlock()
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
			if !agent.config.EnableChainedSecondary {
				agent.log.Infof("Secondary chaining disabled while in chained mode")
				return
			}
			agent.log.Infof("Valid netattdef in chained mode: %s", netAttDefKey)
			nodeFabNetAttName := agent.config.NodeName + "-" + netattdata.Namespace + "-" + netattdata.Name
			if netattdata.PrimaryCNI == PrimaryCNISRIOV {
				netattdata.Ifaces = append(netattdata.Ifaces, agent.getIfacesFromSriovResource(netattdata.ResourcePlugin, netattdata.ResourceName)...)
			} else {
				agent.netattdefifacemap[netattdata.ResourceName] = &netattdata
				netattdata.Ifaces = append(netattdata.Ifaces, netattdata.ResourceName)
			}
			agent.log.Infof("Physical ifaces for nodefabricnetworkattachment %s :%v", nodeFabNetAttName, netattdata.Ifaces)
			if prevnetattdata, ok := agent.netattdefmap[netAttDefKey]; ok {
				netattdata.Pods = prevnetattdata.Pods
				netattdata.FabricAttachmentData = prevnetattdata.FabricAttachmentData
			}
			agent.netattdefmap[netAttDefKey] = &netattdata
			for _, iface := range netattdata.Ifaces {
				agent.netattdefifacemap[iface] = &netattdata
				if fabAttData, err := agent.GetFabricDiscoveryNeighborDataLocked(iface); err == nil {
					if fabAttData != nil {
						netattdata.FabricAttachmentData[iface] = fabAttData
					}
				}
			}
			if err := agent.updateNodeFabricNetworkAttachmentLocked(&netattdata); err != nil {
				agent.log.Errorf("Failed to create/update nodefabricnetworkattachment %s :%v", nodeFabNetAttName, err)
			}
		}
		return
	}

	json.Unmarshal([]byte(ntd.Spec.Config), &config)
	veth_mode := os.Getenv("GENERIC_VETH_MODE")
	config_name := ""
	// Check if the environment variable is set
	if veth_mode != "True" {
		config_name = "k8s-pod-network"
	} else {
		config_name = "generic-veth"
	}
	for i := 0; i < len(config.Plugins); i++ {
		if config.Name == config_name {
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

func (agent *HostAgent) networkAttDefUpdated(oldobj, newobj interface{}) {
	ntd := newobj.(*netpolicy.NetworkAttachmentDefinition)
	agent.log.Infof("network attachment definition changed: %s", ntd.ObjectMeta.Name)
	agent.networkAttDefChanged(ntd)
}

func (agent *HostAgent) networkAttDefDeleteByKeyLocked(netAttDefKey string) {
	if netattDef, ok := agent.netattdefmap[netAttDefKey]; ok {
		if netattDef.Programmed {
			err := agent.deleteNodeFabricNetworkAttachment(netattDef)
			if err != nil {
				agent.log.Errorf("node fabric network attachment delete failed:%v", err)
			}
		}
		if netattDef.PrimaryCNI == PrimaryCNISRIOV {
			for _, iface := range netattDef.Ifaces {
				delete(agent.netattdefifacemap, iface)
			}
		} else {
			delete(agent.netattdefifacemap, netattDef.ResourceName)
		}
		agent.DeleteNetworkMetadata(netattDef)
	}
	delete(agent.netattdefmap, netAttDefKey)
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
	agent.networkAttDefDeleteByKeyLocked(netAttDefKey)
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

func (agent *HostAgent) getAlloccatedDeviceId(metadata *md.ContainerMetadata, smartnicmode, resourceName string) error {
	var err error
	var acicni bool
	if smartnicmode == "dpu" || smartnicmode == "chained" {
		err = agent.getPodResource(metadata, resourceName)
	} else {
		acicni, err = agent.isAcicniNetwork(metadata)
		if acicni {
			err = agent.getPodResource(metadata, "")
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

func (agent *HostAgent) getPodResource(metadata *md.ContainerMetadata, resourceName string) error {
	podResourceSock := path.Join(kubeletPodResourceDefaultPath, podresources.Socket+".sock")
	if _, err := os.Stat(podResourceSock); os.IsNotExist(err) {
		return fmt.Errorf("Could not retreive the kubelet sock %w", err)
	}

	ctx, cancelFunc := context.WithTimeout(context.Background(), timeout)
	defer cancelFunc()

	podResourcesClient, podResourcesConn, err := podresources.GetV1alpha1Client(podResourceSock, timeout, podResourcesMaxSizeDefault)
	if err != nil {
		return fmt.Errorf("Could not retreive the pod resource client %w", err)
	}
	defer podResourcesConn.Close()

	resp, err := podResourcesClient.List(ctx, &podresourcesv1alpha1.ListPodResourcesRequest{})

	if err != nil {
		return fmt.Errorf("Could not get pod resource from the client %w", err)
	}
	if resp == nil {
		return errors.New("Not able to process PodResourcesResponse")
	}

	podid := metadata.Id.Namespace + "/" + metadata.Id.Pod
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
						return errors.New("Virtual function allocation failed : Multiple device id found")
					} else {
						agent.log.Debugf("devices.ResourceName:%s", devices.ResourceName)
						if resourceName != "" && resourceName != devices.ResourceName {
							continue
						}
						deviceInfo := &DeviceInfo{
							DeviceId:     strings.Join(DeviceList, " "),
							ResourceName: devices.ResourceName,
						}
						/*In case 2 SRIOV NADs share the same resource and this pod is on both,
						  SRIOV CNI will allocate a new VF per network . To handle this case,
						  check if this pod is on another network using the same resource*/
						skipDev := false
						if pNwData, ok := agent.podNetworkMetadata[podid]; ok {
							for nw, cntMap := range pNwData {
								if nw != metadata.Network.NetworkName {
									if mdata, ok := cntMap[metadata.Id.ContId]; ok {
										if mdata.Id.DeviceId == deviceInfo.DeviceId {
											skipDev = true
											break
										}
									}
								}
							}
							if skipDev {
								continue
							}
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
