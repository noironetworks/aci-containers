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
	"net"
	"net/http"

	kubeerr "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	v1 "k8s.io/client-go/pkg/api/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/kubernetes/pkg/controller"

	"github.com/Sirupsen/logrus"

	"github.com/noironetworks/aci-containers/pkg/apicapi"
	"github.com/noironetworks/aci-containers/pkg/ipam"
	"github.com/noironetworks/aci-containers/pkg/metadata"
)

func (cont *AciController) initNodeInformerFromClient(
	kubeClient *kubernetes.Clientset) {

	cont.initNodeInformerBase(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				return kubeClient.Core().Nodes().List(options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				return kubeClient.Core().Nodes().Watch(options)
			},
		})
}

func (cont *AciController) initNodeInformerBase(listWatch *cache.ListWatch) {
	cont.nodeInformer = cache.NewSharedIndexInformer(
		listWatch,
		&v1.Node{},
		controller.NoResyncPeriodFunc(),
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	cont.nodeInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			cont.nodeChanged(obj)
		},
		UpdateFunc: func(_ interface{}, obj interface{}) {
			cont.nodeChanged(obj)
		},
		DeleteFunc: func(obj interface{}) {
			cont.nodeDeleted(obj)
		},
	})

}

func apicNodeNetPol(name string, tenantName string,
	nodeIps []string) apicapi.ApicObject {

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

		for _, ip := range nodeIps {
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
	var nodeIps []string
	for _, a := range node.Status.Addresses {
		if a.Address != "" &&
			(a.Type == "InternalIP" || a.Type == "ExternalIP") {
			nodeIps = append(nodeIps, a.Address)
		}
	}

	sgName := cont.aciNameForKey("node", node.Name)
	cont.apicConn.WriteApicObjects(sgName,
		apicapi.ApicSlice{
			apicNodeNetPol(sgName, cont.config.AciPolicyTenant, nodeIps),
		})
}

func (cont *AciController) createServiceEndpoint(ep *metadata.ServiceEndpoint) error {
	_, err := net.ParseMAC(ep.Mac)
	if err != nil {
		var mac net.HardwareAddr
		mac = make([]byte, 6)
		_, err := rand.Read(mac)
		if err != nil {
			return err
		}

		mac[0] = (mac[0] & 254) | 2
		ep.Mac = mac.String()
	}

	if ep.Ipv4 == nil || !cont.nodeServiceIps.V4.RemoveIp(ep.Ipv4) {
		ipv4, err := cont.nodeServiceIps.V4.GetIp()
		if err == nil {
			ep.Ipv4 = ipv4
		} else {
			ep.Ipv4 = nil
		}
	}
	if ep.Ipv6 == nil || !cont.nodeServiceIps.V6.RemoveIp(ep.Ipv6) {
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

	return nil
}

func (cont *AciController) nodeFullSync() {
	cache.ListAll(cont.nodeInformer.GetIndexer(), labels.Everything(),
		func(nodeobj interface{}) {
			cont.nodeChanged(nodeobj)
		})
}

func (cont *AciController) nodeChanged(obj interface{}) {
	cont.indexMutex.Lock()

	node := obj.(*v1.Node)
	logger := cont.log.WithFields(logrus.Fields{
		"Node": node.ObjectMeta.Name,
	})

	nodeUpdated := false
	epval, epok := node.ObjectMeta.Annotations[metadata.ServiceEpAnnotation]

	if existing, ok := cont.nodeServiceMetaCache[node.ObjectMeta.Name]; ok {
		if !epok || existing.serviceEpAnnotation != epval {
			node.ObjectMeta.Annotations[metadata.ServiceEpAnnotation] =
				existing.serviceEpAnnotation
			nodeUpdated = true
		}
	} else if cont.nodeSyncEnabled {
		nodeMeta := &nodeServiceMeta{}

		if epok {
			err := json.Unmarshal([]byte(epval), &nodeMeta.serviceEp)
			if err != nil {
				logger.WithFields(logrus.Fields{
					"epval": epval,
				}).Warn("Could not parse existing node ",
					"service endpoint annotation: ", err)
			}
		}

		cont.createServiceEndpoint(&nodeMeta.serviceEp)
		raw, err := json.Marshal(&nodeMeta.serviceEp)
		if err != nil {
			logger.Error("Could not create node service endpoint annotation", err)
		} else {
			nodeMeta.serviceEpAnnotation = string(raw)
			if !epok || nodeMeta.serviceEpAnnotation != epval {
				node.ObjectMeta.Annotations[metadata.ServiceEpAnnotation] =
					nodeMeta.serviceEpAnnotation
				nodeUpdated = true
			}
			cont.nodeServiceMetaCache[node.ObjectMeta.Name] = nodeMeta
			cont.updateServicesForNode(node.ObjectMeta.Name)
		}
	}

	nodePodNet, ok := cont.nodePodNetCache[node.ObjectMeta.Name]
	if !ok {
		nodePodNet = newNodePodNetMeta()
		cont.nodePodNetCache[node.ObjectMeta.Name] = nodePodNet
	}

	netval, netok :=
		node.ObjectMeta.Annotations[metadata.PodNetworkRangeAnnotation]
	if netok {
		if netval != nodePodNet.podNetIpsAnnotation {
			cont.mergePodNet(nodePodNet, netval, logger)
		}
	}
	if cont.nodeSyncEnabled {
		cont.checkNodePodNet(node.ObjectMeta.Name)
		if netval != nodePodNet.podNetIpsAnnotation {
			node.ObjectMeta.Annotations[metadata.PodNetworkRangeAnnotation] =
				nodePodNet.podNetIpsAnnotation
			nodeUpdated = true
		}
	}
	cont.indexMutex.Unlock()

	cont.createNetPolForNode(node)

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
	node := obj.(*v1.Node)
	cont.apicConn.ClearApicObjects("node" + node.Name)

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
		v4 = v4.Intersect(cont.configuredPodNetworkIps.V4)
		cont.podNetworkIps.V4.RemoveRanges(existing.V4)
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

// must have index lock
func (cont *AciController) checkNodePodNet(nodename string) {
	changed := false
	if podnet, ok := cont.nodePodNetCache[nodename]; ok {
		podnetipam := ipam.NewFromRanges(podnet.podNetIps.V4)
		size := podnetipam.GetSize()
		if int64(len(podnet.nodePods)) >
			size-int64(cont.config.PodIpPoolChunkSize)/2 {
			// we have half a chunk left or less; allocate a new chunk
			r, err := cont.podNetworkIps.V4.
				GetIpChunk(int64(cont.config.PodIpPoolChunkSize))
			if err != nil {
				cont.log.Error("Could not allocate IPv4 address chunk: ", err)
			} else {
				podnetipam.AddRanges(r)
				podnet.podNetIps.V4 = podnetipam.FreeList
				cont.recomputePodNetAnnotation(podnet)
				changed = true
			}
		}
	}

	if changed {
		go func() {
			node, exists, err :=
				cont.nodeInformer.GetStore().GetByKey(nodename)
			if err != nil {
				cont.log.Error("Could not lookup node: ", err)
				return
			}
			if exists && node != nil {
				cont.nodeChanged(node)
			}
		}()
	}

}
