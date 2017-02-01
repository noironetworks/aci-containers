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

type nodeMetadata struct {
	serviceEp           metadata.ServiceEndpoint
	serviceEpAnnotation string
	podIps              []ipam.IpRange
}

var (
	nodeMetaCache = make(map[string]*nodeMetadata)
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

	if ep.Ipv4 == nil || !nodeServiceIpsV4.RemoveIp(ep.Ipv4) {
		ipv4, err := nodeServiceIpsV4.GetIp()
		if err == nil {
			ep.Ipv4 = ipv4
		} else {
			ep.Ipv4 = nil
		}
	}
	if ep.Ipv6 == nil || !nodeServiceIpsV6.RemoveIp(ep.Ipv6) {
		ipv6, err := nodeServiceIpsV6.GetIp()
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

	if existing, ok := nodeMetaCache[node.ObjectMeta.Name]; ok {
		if !epok || existing.serviceEpAnnotation != epval {
			node.ObjectMeta.Annotations[metadata.ServiceEpAnnotation] =
				existing.serviceEpAnnotation
			nodeUpdated = true
		}
	} else {
		nodeMeta := &nodeMetadata{}

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
			return
		}
		nodeMeta.serviceEpAnnotation = string(raw)
		if !epok || nodeMeta.serviceEpAnnotation != epval {
			node.ObjectMeta.Annotations[metadata.ServiceEpAnnotation] =
				nodeMeta.serviceEpAnnotation
			nodeUpdated = true
		}
		nodeMetaCache[node.ObjectMeta.Name] = nodeMeta
	}

	if nodeUpdated {
		_, err := kubeClient.Core().Nodes().Update(node)
		if err != nil {
			logger.Error("Failed to update node: " + err.Error())
		} else {
			logger.WithFields(logrus.Fields{
				"ServiceEpAnnotation": node.
					ObjectMeta.Annotations[metadata.ServiceEpAnnotation],
			}).Info("Updated node service annotations")
		}
	}
}

func nodeDeleted(obj interface{}) {
	indexMutex.Lock()
	defer indexMutex.Unlock()

	node := obj.(*api.Node)

	if existing, ok := nodeMetaCache[node.ObjectMeta.Name]; ok {
		if existing.serviceEp.Ipv4 != nil {
			nodeServiceIpsV4.AddIp(existing.serviceEp.Ipv4)
		}
		if existing.serviceEp.Ipv6 != nil {
			nodeServiceIpsV6.AddIp(existing.serviceEp.Ipv6)
		}
	}
	delete(nodeMetaCache, node.ObjectMeta.Name)
}
