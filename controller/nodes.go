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

package main

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"net"

	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/client/cache"
	"k8s.io/kubernetes/pkg/controller"
	"k8s.io/kubernetes/pkg/runtime"
	"k8s.io/kubernetes/pkg/util/wait"
	"k8s.io/kubernetes/pkg/watch"

	"github.com/Sirupsen/logrus"

	"github.com/noironetworks/aci-containers/ipam"
	"github.com/noironetworks/aci-containers/metadata"
)

type nodeServiceMeta struct {
	serviceEp           metadata.ServiceEndpoint
	serviceEpAnnotation string
}

type nodePodNetMeta struct {
	nodePods            map[string]bool
	podNetIps           metadata.NetIps
	podNetIpsAnnotation string
}

func newNodePodNetMeta() *nodePodNetMeta {
	return &nodePodNetMeta{
		nodePods: make(map[string]bool),
	}
}

var (
	nodeServiceMetaCache = make(map[string]*nodeServiceMeta)
	nodePodNetCache      = make(map[string]*nodePodNetMeta)
	nodequeue            = make(chan string)
)

func initNodeInformer() {
	nodeInformer = cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options api.ListOptions) (runtime.Object, error) {
				return kubeClient.Core().Nodes().List(options)
			},
			WatchFunc: func(options api.ListOptions) (watch.Interface, error) {
				return kubeClient.Core().Nodes().Watch(options)
			},
		},
		&api.Node{},
		controller.NoResyncPeriodFunc(),
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	nodeInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    nodeChanged,
		UpdateFunc: nodeUpdated,
		DeleteFunc: nodeDeleted,
	})

	go nodeInformer.GetController().Run(wait.NeverStop)
	go nodeInformer.Run(wait.NeverStop)
	go func() {
		for nodename := range nodequeue {
			indexMutex.Lock()
			changed := checkNodePodNet(nodename)
			indexMutex.Unlock()

			if changed {
				node, exists, err := nodeInformer.GetStore().GetByKey(nodename)
				if err != nil {
					log.Error("Could not lookup node: ", err)
					continue
				}
				if exists && node != nil {
					nodeChanged(node)
				}
			}
		}
	}()
}

func nodeUpdated(_ interface{}, obj interface{}) {
	nodeChanged(obj)
}

func createServiceEndpoint(ep *metadata.ServiceEndpoint) error {
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

	if ep.Ipv4 == nil || !nodeServiceIps.V4.RemoveIp(ep.Ipv4) {
		ipv4, err := nodeServiceIps.V4.GetIp()
		if err == nil {
			ep.Ipv4 = ipv4
		} else {
			ep.Ipv4 = nil
		}
	}
	if ep.Ipv6 == nil || !nodeServiceIps.V6.RemoveIp(ep.Ipv6) {
		ipv6, err := nodeServiceIps.V6.GetIp()
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

func nodeChanged(obj interface{}) {
	indexMutex.Lock()
	defer indexMutex.Unlock()

	node := obj.(*api.Node)
	logger := log.WithFields(logrus.Fields{
		"Node": node.ObjectMeta.Name,
	})

	nodeUpdated := false
	epval, epok := node.ObjectMeta.Annotations[metadata.ServiceEpAnnotation]

	if existing, ok := nodeServiceMetaCache[node.ObjectMeta.Name]; ok {
		if !epok || existing.serviceEpAnnotation != epval {
			node.ObjectMeta.Annotations[metadata.ServiceEpAnnotation] =
				existing.serviceEpAnnotation
			nodeUpdated = true
		}
	} else {
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

		createServiceEndpoint(&nodeMeta.serviceEp)
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
			nodeServiceMetaCache[node.ObjectMeta.Name] = nodeMeta
		}
	}

	nodePodNet, ok := nodePodNetCache[node.ObjectMeta.Name]
	if !ok {
		nodePodNet = newNodePodNetMeta()
		nodePodNetCache[node.ObjectMeta.Name] = nodePodNet
	}

	netval, netok :=
		node.ObjectMeta.Annotations[metadata.PodNetworkRangeAnnotation]
	if netok {
		mergePodNet(nodePodNet, netval)
	}
	checkNodePodNet(node.ObjectMeta.Name)
	if netval != nodePodNet.podNetIpsAnnotation {
		node.ObjectMeta.Annotations[metadata.PodNetworkRangeAnnotation] =
			nodePodNet.podNetIpsAnnotation
		nodeUpdated = true
	}

	if nodeUpdated {
		_, err := kubeClient.Core().Nodes().Update(node)
		if err != nil {
			logger.Error("Failed to update node: " + err.Error())
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

func nodeDeleted(obj interface{}) {
	indexMutex.Lock()
	defer indexMutex.Unlock()

	node := obj.(*api.Node)

	if existing, ok := nodeServiceMetaCache[node.ObjectMeta.Name]; ok {
		if existing.serviceEp.Ipv4 != nil {
			nodeServiceIps.V4.AddIp(existing.serviceEp.Ipv4)
		}
		if existing.serviceEp.Ipv6 != nil {
			nodeServiceIps.V6.AddIp(existing.serviceEp.Ipv6)
		}
	}
	delete(nodeServiceMetaCache, node.ObjectMeta.Name)
}

func addPodToNode(nodename string, key string) {
	indexMutex.Lock()
	defer indexMutex.Unlock()

	existing, ok := nodePodNetCache[nodename]
	if !ok {
		existing = newNodePodNetMeta()
		nodePodNetCache[nodename] = existing
	}
	existing.nodePods[key] = true
}

func removePodFromNode(nodename string, key string) {
	indexMutex.Lock()
	defer indexMutex.Unlock()

	if existing, ok := nodePodNetCache[nodename]; ok {
		delete(existing.nodePods, key)
	}
}

// must have index lock
func recomputePodNetAnnotation(podnet *nodePodNetMeta) {
	raw, err := json.Marshal(&podnet.podNetIps)
	if err != nil {
		log.Error("Could not create node pod network ",
			"annotation", err)
	}
	podnet.podNetIpsAnnotation = string(raw)
}

// must have index lock
func mergePodNet(podnet *nodePodNetMeta, existingAnnotation string) {
	existing := &metadata.NetIps{}
	err := json.Unmarshal([]byte(existingAnnotation), existing)
	if err != nil {
		log.Error("Could not parse existing pod network ",
			"annotation", err)
		return
	}

	v4 := ipam.NewFromRanges(podnet.podNetIps.V4)
	// TODO: intersect with configured IP ranges so ranges can be removed
	v4.AddRanges(existing.V4)
	podNetworkIps.V4.RemoveRanges(existing.V4)
	podnet.podNetIps.V4 = v4.FreeList
	recomputePodNetAnnotation(podnet)
}

// must have index lock
func checkNodePodNet(nodename string) bool {
	if podnet, ok := nodePodNetCache[nodename]; ok {
		podnetipam := ipam.NewFromRanges(podnet.podNetIps.V4)
		size := podnetipam.GetSize()
		if int64(len(podnet.nodePods)) > size-128 {
			// we have half a chunk left or less; allocate a new chunk
			r, err := podNetworkIps.V4.GetIpChunk(256)
			if err != nil {
				log.Error("Could not allocate IPv4 address chunk: ", err)
			} else {
				podnetipam.AddRanges(r)
				podnet.podNetIps.V4 = podnetipam.FreeList
				recomputePodNetAnnotation(podnet)
				return true
			}
		}
	}
	return false
}
