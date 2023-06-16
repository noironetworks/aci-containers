// Copyright 2017 Cisco Systems, Inc.
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

// Handlers for node updates.

package controller

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"

	v1 "k8s.io/api/core/v1"
	kubeerr "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"github.com/sirupsen/logrus"

	"github.com/noironetworks/aci-containers/pkg/apicapi"
	crdv1 "github.com/noironetworks/aci-containers/pkg/gbpcrd/apis/acipolicy/v1"
	"github.com/noironetworks/aci-containers/pkg/gbpserver/watchers"
	"github.com/noironetworks/aci-containers/pkg/ipam"
	"github.com/noironetworks/aci-containers/pkg/metadata"
	nodePodIf "github.com/noironetworks/aci-containers/pkg/nodepodif/apis/acipolicy/v1"
	"github.com/noironetworks/aci-containers/pkg/util"
)

const (
	tunnelIDIncr = 2
)

type tunnelState struct {
	stateDriver  *watchers.K8sStateDriver
	nodeToTunnel map[string]int64
	nextID       int64
}

func (cont *AciController) initNodeInformerFromClient(
	kubeClient *kubernetes.Clientset) {

	cont.initNodeInformerBase(
		cache.NewListWatchFromClient(
			kubeClient.CoreV1().RESTClient(), "nodes",
			metav1.NamespaceAll, fields.Everything()))
}

func (cont *AciController) initNodeInformerBase(listWatch *cache.ListWatch) {
	cont.nodeIndexer, cont.nodeInformer = cache.NewIndexerInformer(
		listWatch, &v1.Node{}, 0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				cont.syncPodNet(obj) // update cache
				cont.nodeChanged(obj)
			},
			UpdateFunc: func(_ interface{}, obj interface{}) {
				cont.nodeChanged(obj)
			},
			DeleteFunc: func(obj interface{}) {
				cont.nodeDeleted(obj)
			},
		},
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
}

func apicNodeNetPol(name string, tenantName string,
	nodeIps map[string]bool) apicapi.ApicObject {

	hpp := apicapi.NewHostprotPol(tenantName, name)
	hppDn := hpp.GetDn()
	nodeSubj := apicapi.NewHostprotSubj(hppDn, "local-node")
	if len(nodeIps) > 0 {
		nodeSubjDn := nodeSubj.GetDn()
		outbound := apicapi.NewHostprotRule(nodeSubjDn, "allow-all-egress")
		outbound.SetAttr("direction", "egress")
		outbound.SetAttr("ethertype", "ipv4")
		outbound.SetAttr("connTrack", "normal")

		inbound := apicapi.NewHostprotRule(nodeSubjDn, "allow-all-ingress")
		inbound.SetAttr("direction", "ingress")
		inbound.SetAttr("ethertype", "ipv4")
		inbound.SetAttr("connTrack", "normal")

		for ip := range nodeIps {
			outbound.AddChild(apicapi.NewHostprotRemoteIp(outbound.GetDn(), ip))
			inbound.AddChild(apicapi.NewHostprotRemoteIp(inbound.GetDn(), ip))
		}

		nodeSubj.AddChild(inbound)
		nodeSubj.AddChild(outbound)
	}
	hpp.AddChild(nodeSubj)
	return hpp
}

func (cont *AciController) createNetPolForNode(node *v1.Node) {
	nodeIps := make(map[string]bool)
	for _, a := range node.Status.Addresses {
		if a.Address != "" &&
			(a.Type == "InternalIP" || a.Type == "ExternalIP") {
			nodeIps[a.Address] = true
		}
	}

	sgName := cont.aciNameForKey("node", node.Name)
	cont.apicConn.WriteApicObjects(sgName,
		apicapi.ApicSlice{
			apicNodeNetPol(sgName, cont.config.AciPolicyTenant, nodeIps),
		})
}

func (cont *AciController) createServiceEndpoint(existing *metadata.ServiceEndpoint, ep *metadata.ServiceEndpoint, deviceMac string, nodeName string) error {

	_, err := net.ParseMAC(deviceMac)
	if err == nil && deviceMac != "00:00:00:00:00:00" {
		ep.Mac = deviceMac
	} else {
		_, err := net.ParseMAC(existing.Mac)
		if err == nil {
			ep.Mac = existing.Mac
		} else {
			var mac net.HardwareAddr = make([]byte, 6)
			_, err := rand.Read(mac)
			if err != nil {
				return err
			}

			mac[0] = (mac[0] & 254) | 2
			ep.Mac = mac.String()
		}
	}

	if ep.Ipv4 == nil && existing.Ipv4 != nil &&
		cont.nodeServiceIps.V4.RemoveIp(existing.Ipv4) {
		ep.Ipv4 = existing.Ipv4
	}

	if ep.Ipv4 == nil {
		ipv4, err := cont.nodeServiceIps.V4.GetIp()
		if err == nil {
			ep.Ipv4 = ipv4
		} else {
			ep.Ipv4 = nil
		}
	}

	if ep.Ipv6 == nil && existing.Ipv6 != nil &&
		cont.nodeServiceIps.V6.RemoveIp(existing.Ipv6) {
		ep.Ipv6 = existing.Ipv6
	}

	if ep.Ipv6 == nil {
		ipv6, err := cont.nodeServiceIps.V6.GetIp()
		if err == nil {
			ep.Ipv6 = ipv6
		} else {
			ep.Ipv6 = nil
		}
	}

	if ep.Ipv4 == nil && ep.Ipv6 == nil {
		return errors.New("No IP addresses available for service endpoint")
	}

	if (ep.HealthGroupDn == "") && (cont.config.AciServiceMonitorInterval > 0) {
		name := cont.aciNameForKey("svc", nodeName)
		healthGroupObj := apicapi.NewVnsRedirectHealthGroup(cont.config.AciVrfTenant, name)
		ep.HealthGroupDn = healthGroupObj.GetDn()
		cont.apicConn.WriteApicObjects(name, apicapi.ApicSlice{healthGroupObj})
	}

	return nil
}

func (cont *AciController) nodeFullSync() {
	cache.ListAll(cont.nodeIndexer, labels.Everything(),
		func(nodeobj interface{}) {
			cont.syncPodNet(nodeobj) // update the cache
			cont.nodeChanged(nodeobj)
		})
}

// syncPodNet syncs in the podnets from the node object's annotation
func (cont *AciController) syncPodNet(obj interface{}) {
	cont.indexMutex.Lock()
	defer cont.indexMutex.Unlock()

	node := obj.(*v1.Node)
	logger := cont.log.WithFields(logrus.Fields{
		"Node": node.ObjectMeta.Name,
	})

	if node.ObjectMeta.Annotations == nil {
		return // nothing to sync
	}

	netval, ok := node.ObjectMeta.Annotations[metadata.PodNetworkRangeAnnotation]
	if !ok {
		return // nothing to sync
	}

	nodePodNet := newNodePodNetMeta()
	cont.mergePodNet(nodePodNet, netval, logger)
	cont.nodePodNetCache[node.ObjectMeta.Name] = nodePodNet
}

func maxof(x1, x2 int64) int64 {
	if x1 > x2 {
		return x1
	}

	return x2
}

func (cont *AciController) getTunnelID(node *v1.Node) int64 {
	if cont.config.LBType == lbTypeAci {
		return 0
	}

	nodeIP := getNodeIP(node, v1.NodeInternalIP)
	if nodeIP == "" {
		cont.log.Errorf("Can't get IP for node %s", node.Name)
		return 0
	}

	if cont.tunnelGetter == nil {
		tunnelGetter := &tunnelState{}
		tunnelGetter.stateDriver = &watchers.K8sStateDriver{}
		err := tunnelGetter.stateDriver.Init(watchers.FieldTunnelID)
		if err != nil {
			cont.log.Warnf("Can't get tunnelID for %s", node.Name)
			return 0
		}

		gbps, err := tunnelGetter.stateDriver.Get()
		if err != nil {
			cont.log.Warnf("Can't get tunnelID for %s", node.Name)
			return 0
		}

		cont.tunnelGetter = tunnelGetter
		if gbps.Status.TunnelIDs == nil {
			cont.log.Infof("Initializing tunnelIDs")
			tunnelGetter.nodeToTunnel = make(map[string]int64)
			cont.tunnelGetter.nextID = 0
		} else {
			tunnelGetter.nodeToTunnel = gbps.Status.TunnelIDs
			for _, val := range tunnelGetter.nodeToTunnel {
				cont.tunnelGetter.nextID = maxof(cont.tunnelGetter.nextID, val)
			}

			cont.tunnelGetter.nextID = cont.tunnelGetter.nextID + tunnelIDIncr
		}
	}

	id, found := cont.tunnelGetter.nodeToTunnel[nodeIP]
	if found {
		return id + int64(cont.config.CSRTunnelIDBase)
	}

	id = cont.tunnelGetter.nextID
	if id >= int64(cont.config.MaxCSRTunnels*tunnelIDIncr) {
		cont.log.Infof("Max tunnels %d reached", cont.config.MaxCSRTunnels)
		return 0
	}

	// each allocated id packs two tunnels.
	cont.tunnelGetter.nodeToTunnel[nodeIP] = id
	cont.tunnelGetter.nextID = id + tunnelIDIncr
	state := &crdv1.GBPSState{}
	state.Status.TunnelIDs = cont.tunnelGetter.nodeToTunnel
	cont.tunnelGetter.stateDriver.Update(state)
	return id + int64(cont.config.CSRTunnelIDBase)
}

func (cont *AciController) writeApicNode(node *v1.Node) {
	tunnelID := cont.getTunnelID(node)
	//cont.log.Infof("=>  Node: %s, tunnelID: %v", node.Name, tunnelID)
	key := cont.aciNameForKey("node-vmm", node.Name)
	aobj := apicapi.NewVmmInjectedHost(cont.vmmDomainProvider(),
		cont.config.AciVmmDomain, cont.config.AciVmmController,
		node.Name)
	aobj.SetAttr("mgmtIp", getNodeIP(node, v1.NodeInternalIP))
	aobj.SetAttr("os", node.Status.NodeInfo.OSImage)
	aobj.SetAttr("kernelVer", node.Status.NodeInfo.KernelVersion)
	if apicapi.ApicVersion >= "5.0" {
		aobj.SetAttr("id", fmt.Sprintf("%v", tunnelID))
	}
	cont.apicConn.WriteApicObjects(key, apicapi.ApicSlice{aobj})
}

func getNodeIP(node *v1.Node, aType v1.NodeAddressType) string {
	for _, a := range node.Status.Addresses {
		if a.Type == aType {
			return a.Address
		}

	}

	return ""
}

func (cont *AciController) nodeChangedByName(nodeName string) {
	node, exists, err := cont.nodeIndexer.GetByKey(nodeName)
	if err != nil {
		cont.log.Error("Could not lookup node: ", err)
		return
	}
	if exists && node != nil {
		cont.nodeChanged(node)
	}
}

func (cont *AciController) nodeChanged(obj interface{}) {
	cont.indexMutex.Lock()

	node := obj.(*v1.Node)
	logger := cont.log.WithFields(logrus.Fields{
		"Node": node.ObjectMeta.Name,
	})

	nodeUpdated := false
	if node.ObjectMeta.Annotations == nil {
		node.ObjectMeta.Annotations = make(map[string]string)
	}

	nodeMeta, metaok := cont.nodeServiceMetaCache[node.ObjectMeta.Name]
	epval, epok := node.ObjectMeta.Annotations[metadata.ServiceEpAnnotation]
	deviceMac, hasDevice := cont.deviceMacForNode(node.ObjectMeta.Name)

	if cont.nodeSyncEnabled && hasDevice {
		if !metaok {
			nodeMeta = &nodeServiceMeta{}
			cont.nodeServiceMetaCache[node.ObjectMeta.Name] = nodeMeta
		}

		existing := &metadata.ServiceEndpoint{}
		if epok {
			err := json.Unmarshal([]byte(epval), existing)
			if err != nil {
				logger.WithFields(logrus.Fields{
					"epval": epval,
				}).Warn("Could not parse existing node ",
					"service endpoint annotation: ", err)
			}
		}

		cont.createServiceEndpoint(existing, &nodeMeta.serviceEp, deviceMac, node.ObjectMeta.Name)
		raw, err := json.Marshal(&nodeMeta.serviceEp)
		if err != nil {
			logger.Error("Could not create node service endpoint annotation", err)
		} else {
			serviceEpAnnotation := string(raw)
			if !epok || serviceEpAnnotation != epval {
				node.ObjectMeta.Annotations[metadata.ServiceEpAnnotation] =
					serviceEpAnnotation
				nodeUpdated = true
				cont.updateServicesForNode(node.ObjectMeta.Name)
				cont.snatFullSync()
			}
		}
	}

	nodePodNet, ok := cont.nodePodNetCache[node.ObjectMeta.Name]
	if !ok {
		nodePodNet = newNodePodNetMeta()
		cont.nodePodNetCache[node.ObjectMeta.Name] = nodePodNet
	}

	netval := node.ObjectMeta.Annotations[metadata.PodNetworkRangeAnnotation]
	if cont.nodeSyncEnabled {
		cont.checkNodePodNet(node.ObjectMeta.Name)
		if netval != nodePodNet.podNetIpsAnnotation {
			logger.Debug("Overwriting existing pod network: ", netval)
			node.ObjectMeta.Annotations[metadata.PodNetworkRangeAnnotation] =
				nodePodNet.podNetIpsAnnotation
			nodeUpdated = true
		}
	}

	if cont.config.AciMultipod {
		nodeAciPod := cont.nodeACIPod[node.ObjectMeta.Name]
		aciPodAnn := node.ObjectMeta.Annotations[metadata.AciPodAnnotation]
		if cont.nodeSyncEnabled {
			if aciPodAnn != nodeAciPod && nodeAciPod != "" {
				node.ObjectMeta.Annotations[metadata.AciPodAnnotation] = nodeAciPod
				nodeUpdated = true
			}
		}
	}
	cont.indexMutex.Unlock()

	cont.createNetPolForNode(node)
	cont.writeApicNode(node)

	if nodeUpdated {
		_, err := cont.updateNode(node)
		if err != nil {
			if serr, ok := err.(*kubeerr.StatusError); ok {
				if serr.ErrStatus.Code == http.StatusConflict {
					logger.Debug("Conflict updating node; ",
						"will retry on next update")
					return
				}
			}
			logger.Error("Failed to update node: ", err)
		} else {
			logger.WithFields(logrus.Fields{
				"ServiceEpAnnotation": node.
					ObjectMeta.Annotations[metadata.ServiceEpAnnotation],
				"PodNetworkRangeAnnotation": node.
					ObjectMeta.Annotations[metadata.PodNetworkRangeAnnotation],
			}).Info("Updated node annotations")
		}
	}
}

func (cont *AciController) nodeDeleted(obj interface{}) {
	node, isNode := obj.(*v1.Node)
	if !isNode {
		deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			cont.log.Error("Received unexpected object: ", obj)
			return
		}
		node, ok = deletedState.Obj.(*v1.Node)
		if !ok {
			cont.log.Error("DeletedFinalStateUnknown contained non-Node object: ", deletedState.Obj)
			return
		}
	}
	cont.apicConn.ClearApicObjects(cont.aciNameForKey("node", node.Name))
	cont.apicConn.ClearApicObjects(cont.aciNameForKey("node-vmm", node.Name))
	cont.log.Infof("Node deleted: %s", node.ObjectMeta.Name)

	cont.indexMutex.Lock()
	defer cont.indexMutex.Unlock()

	if existing, ok := cont.nodeServiceMetaCache[node.ObjectMeta.Name]; ok {
		if existing.serviceEp.Ipv4 != nil {
			cont.nodeServiceIps.V4.AddIp(existing.serviceEp.Ipv4)
		}
		if existing.serviceEp.Ipv6 != nil {
			cont.nodeServiceIps.V6.AddIp(existing.serviceEp.Ipv6)
		}
	}
	delete(cont.nodeServiceMetaCache, node.ObjectMeta.Name)
	cont.updateServicesForNode(node.ObjectMeta.Name)
	cont.snatFullSync()
	if _, ok := cont.snatNodeInfoCache[node.ObjectMeta.Name]; ok {
		env := cont.env.(*K8sEnvironment)
		nodeinfocl := env.nodeInfoClient
		//TODO Add reconcile here on failure
		if nodeinfocl != nil {
			err := util.DeleteNodeInfoCR(*nodeinfocl, node.ObjectMeta.Name)
			if err != nil {
				cont.log.Error("Could not delete the NodeInfo", node.ObjectMeta.Name)
				return
			}
			cont.log.Debug("Successfully Deleted NodeInfoCR for node: ", node.ObjectMeta.Name)
		}
		nodeinfo := cont.snatNodeInfoCache[node.ObjectMeta.Name]
		delete(cont.snatNodeInfoCache, node.ObjectMeta.Name)
		cont.log.Debug("Node deleted from snatNodeInfoCache: ", node.ObjectMeta.Name)
		nodeinfokey, _ := cache.MetaNamespaceKeyFunc(nodeinfo)
		cont.queueNodeInfoUpdateByKey(nodeinfokey)
	}
	np, ok := obj.(*nodePodIf.NodePodIF)
	if !ok {
		deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			cont.log.Error("Received unexpected object: ", obj)
			return
		}
		np, ok = deletedState.Obj.(*nodePodIf.NodePodIF)
		if !ok {
			cont.log.Error("DeletedFinalStateUnknown contained non-NodePodIF object: ", deletedState.Obj)
			return
		}
	}
	env := cont.env.(*K8sEnvironment)
	nodepodifc1 := env.nodePodifClient
	if nodepodifc1 != nil {
		err := util.DeleteNodePodIfCR(*nodepodifc1, np.ObjectMeta.Name)
		if err != nil {
			cont.log.Error("Could not delete the NodePodIF", np.ObjectMeta.Name)
			return
		}
	}
}

// must have index lock
func (cont *AciController) addPodToNode(nodename string, key string) {
	existing, ok := cont.nodePodNetCache[nodename]
	if !ok {
		existing = newNodePodNetMeta()
		cont.nodePodNetCache[nodename] = existing
	}
	if _, ok = existing.nodePods[key]; !ok {
		existing.nodePods[key] = true
		cont.checkNodePodNet(nodename)
	}
}

// must have index lock
func (cont *AciController) removePodFromNode(nodename string, key string) {
	if existing, ok := cont.nodePodNetCache[nodename]; ok {
		delete(existing.nodePods, key)
		cont.checkNodePodNet(nodename)
	}
}

func (cont *AciController) recomputePodNetAnnotation(podnet *nodePodNetMeta) {
	raw, err := json.Marshal(&podnet.podNetIps)
	if err != nil {
		cont.log.Error("Could not create node pod network ",
			"annotation", err)
	}
	podnet.podNetIpsAnnotation = string(raw)
}

// must have index lock
func (cont *AciController) mergePodNet(podnet *nodePodNetMeta, existingAnnotation string, logger *logrus.Entry) {
	existing := &metadata.NetIps{}
	err := json.Unmarshal([]byte(existingAnnotation), existing)
	if err != nil {
		cont.log.Error("Could not parse existing pod network ",
			"annotation", err)
		return
	}

	logger.Debug("Merging existing pod network: ", existingAnnotation)

	{
		v4 := ipam.NewFromRanges(podnet.podNetIps.V4)
		v4.AddRanges(existing.V4)
		annSize := v4.GetSize()

		// validate existing against configured range
		v4 = v4.Intersect(cont.configuredPodNetworkIps.V4)
		if v4.GetSize() != annSize {
			logger.Warnf("intersect: %+v, config: %+v", v4, cont.configuredPodNetworkIps.V4)
			logger.Warn("Existing annotation outside configured",
				"range", existingAnnotation)
		}

		// mark the existing as allocated
		prevSize := cont.podNetworkIps.V4.GetSize()
		cont.podNetworkIps.V4.RemoveRanges(existing.V4)

		// verify allocation was successful
		newSize := cont.podNetworkIps.V4.GetSize()
		if (newSize + annSize) != prevSize {
			logger.Warn("Existing annotation failed allocation: ",
				existingAnnotation)
		}

		if len(v4.FreeList) > 0 {
			podnet.podNetIps.V4 = v4.FreeList
		} else {
			podnet.podNetIps.V4 = nil
		}
	}

	{
		v6 := ipam.NewFromRanges(podnet.podNetIps.V6)
		v6.AddRanges(existing.V6)
		v6 = v6.Intersect(cont.configuredPodNetworkIps.V6)
		cont.podNetworkIps.V6.RemoveRanges(existing.V6)
		if len(v6.FreeList) > 0 {
			podnet.podNetIps.V6 = v6.FreeList
		} else {
			podnet.podNetIps.V6 = nil
		}
	}

	cont.recomputePodNetAnnotation(podnet)
}

func (cont *AciController) allocateIpChunk(podnet *nodePodNetMeta, v4 bool) bool {
	var podnetipam, ipa *ipam.IpAlloc
	changed := false
	if v4 {
		podnetipam = ipam.NewFromRanges(podnet.podNetIps.V4)
		ipa = cont.podNetworkIps.V4
	} else {
		podnetipam = ipam.NewFromRanges(podnet.podNetIps.V6)
		ipa = cont.podNetworkIps.V6
	}
	size := podnetipam.GetSize()
	if int64(len(podnet.nodePods)) >
		size-int64(cont.config.PodIpPoolChunkSize)/2 {
		// we have half a chunk left or less; allocate a new chunk
		r, err := ipa.GetIpChunk(int64(cont.config.PodIpPoolChunkSize))
		if err != nil {
			cont.log.Error("Could not allocate address chunk: ", err)
		} else {
			podnetipam.AddRanges(r)
			if v4 {
				podnet.podNetIps.V4 = podnetipam.FreeList
			} else {
				podnet.podNetIps.V6 = podnetipam.FreeList
			}
			cont.recomputePodNetAnnotation(podnet)
			changed = true
		}
	}
	return changed
}

// must have index lock
func (cont *AciController) checkNodePodNet(nodename string) {
	v4changed, v6changed := false, false
	if podnet, ok := cont.nodePodNetCache[nodename]; ok {
		if !cont.configuredPodNetworkIps.V4.Empty() {
			v4changed = cont.allocateIpChunk(podnet, true)
		}
		if !cont.configuredPodNetworkIps.V6.Empty() {
			v6changed = cont.allocateIpChunk(podnet, false)
		}
	}
	if v4changed || v6changed {
		go cont.env.NodePodNetworkChanged(nodename)
	}

}
