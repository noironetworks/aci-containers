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

package hostagent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/kubernetes/pkg/controller"

	"context"

	"github.com/noironetworks/aci-containers/pkg/metadata"
)

const (
	hostVethEP   = "veth_host_ac.ep"
	hostVethName = "veth_host"
)

func (agent *HostAgent) initNodeInformerFromClient(
	kubeClient *kubernetes.Clientset) {
	agent.initNodeInformerBase(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				options.FieldSelector =
					fields.Set{"metadata.name": agent.config.NodeName}.String()
				obj, err := kubeClient.CoreV1().Nodes().List(context.TODO(), options)
				if err != nil {
					agent.log.Fatalf("Failed to list Nodes during initialization of NodeInformer: %s", err)
				}
				return obj, err
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				options.FieldSelector =
					fields.Set{"metadata.name": agent.config.NodeName}.String()
				obj, err := kubeClient.CoreV1().Nodes().Watch(context.TODO(), options)
				if err != nil {
					agent.log.Fatalf("Failed to watch Nodes during initialization of NodeInformer: %s", err)
				}
				return obj, err
			},
		})
}

func (agent *HostAgent) initNodeInformerBase(listWatch *cache.ListWatch) {
	agent.nodeInformer = cache.NewSharedIndexInformer(
		listWatch,
		&v1.Node{},
		controller.NoResyncPeriodFunc(),
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	agent.nodeInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			agent.nodeChanged(obj)
		},
		UpdateFunc: func(oldobj interface{}, newobj interface{}) {
			agent.nodeChanged(oldobj, newobj)
		},
		DeleteFunc: func(obj interface{}) {
			agent.nodeDeleted(obj)
		},
	})
}

func (agent *HostAgent) nodeChanged(obj ...interface{}) {
	updateServices := false
	var node *v1.Node
	if len(obj) == 2 {
		oldnode := obj[0].(*v1.Node)
		node = obj[1].(*v1.Node)
		if !reflect.DeepEqual(node.ObjectMeta.Labels, oldnode.ObjectMeta.Labels) {
			updateServices = true
			agent.log.Infof("Node label changed for: %s, Updating services", node.ObjectMeta.Name)
		}
	} else {
		node = obj[0].(*v1.Node)
	}
	if node.ObjectMeta.Name != agent.config.NodeName {
		agent.log.Error("Got incorrect node update for ", node.ObjectMeta.Name)
		return
	}

	agent.indexMutex.Lock()

	if agent.config.EnableOpflexAgentReconnect {
		nodeAciPod, acipodok := node.ObjectMeta.Annotations[metadata.NodeAciPodAnnotation]
		if acipodok {
			if agent.nodeAciPodAnnotation != nodeAciPod && nodeAciPod == "none" {
				// Inform opflex-agent that the vm is migrated by updating the reset.conf file
				err := agent.updateResetConfFile()
				if err != nil {
					agent.log.Error("Failed to inform opflex-agent about opflexOdev disconnect ", err)
				} else {
					agent.log.Info("Informed opflex-agent about opflexOdev disconnect")
				}
			}
			agent.nodeAciPodAnnotation = nodeAciPod
		}
	}

	if agent.config.AciMultipod {
		aciPod, acipodok := node.ObjectMeta.Annotations[metadata.AciPodAnnotation]
		if acipodok {
			if agent.aciPodAnnotation != aciPod {
				agent.doDhcpRenew(aciPod)
			}
			agent.aciPodAnnotation = aciPod
		}
	}

	pnet, ok := node.ObjectMeta.Annotations[metadata.PodNetworkRangeAnnotation]
	if ok {
		agent.updateIpamAnnotation(pnet)
	}

	{
		var newServiceEp metadata.ServiceEndpoint
		epval, ok := node.ObjectMeta.Annotations[metadata.ServiceEpAnnotation]
		if ok {
			err := json.Unmarshal([]byte(epval), &newServiceEp)
			if err != nil {
				agent.log.WithFields(logrus.Fields{
					"epval": epval,
				}).Warn("Could not parse node ",
					"service endpoint annotation: ", err)
			}
		}
		if !reflect.DeepEqual(newServiceEp, agent.serviceEp) {
			agent.log.WithFields(logrus.Fields{
				"epval": epval,
			}).Info("Updated service endpoint")
			agent.serviceEp = newServiceEp
			// this case can be posible when there is a default snatpolicy present
			// And nodeinfo service EP is not annotated
			if _, ok := agent.opflexServices[SnatService]; ok {
				agent.opflexServices[SnatService].InterfaceIp = agent.serviceEp.Ipv4.String()
				agent.log.Infof("Updated Snat service-ext file: %s", agent.serviceEp.Ipv4.String())
			}
			updateServices = true
		}
	}

	gotVtep := false
	if agent.vtepIP == "" {
		for _, a := range node.Status.Addresses {
			if a.Type == v1.NodeInternalIP {
				agent.vtepIP = a.Address
				agent.log.Infof("vtepIP: %s", agent.vtepIP)
				gotVtep = true
			}
		}
	}

	agent.indexMutex.Unlock()
	if gotVtep {
		agent.routeInit()
		if agent.crdClient != nil {
			agent.registerHostVeth()
		}
	}

	if updateServices {
		agent.updateAllServices()
	}
}

func (agent *HostAgent) registerHostVeth() {
	go func() {
		for {
			ep := &opflexEndpoint{}
			epfile := filepath.Join(agent.config.OpFlexEndpointDir, hostVethEP)
			datacont, err := os.ReadFile(epfile)
			if err != nil {
				agent.log.Errorf("Unable to read %s - %v", epfile, err)
				return
			}

			err = json.Unmarshal(datacont, ep)
			if err != nil {
				agent.log.Errorf("Unable to read %s - %v", epfile, err)
				return
			}

			vmName := ep.Attributes["vm-name"]
			if !strings.Contains(vmName, agent.vtepIP) {
				vmName = fmt.Sprintf("%s.%s", vmName, agent.vtepIP)
				ep.Attributes["vm-name"] = vmName
			}
			agent.log.Infof("-- Adding %+v to registry", ep)
			agent.EPRegAdd(ep)
			if ep.registered {
				return
			}
			time.Sleep(5 * time.Second)
		}
	}()
}

func (agent *HostAgent) nodeDeleted(obj interface{}) {
	agent.indexMutex.Lock()
	defer agent.indexMutex.Unlock()
}

func (agent *HostAgent) routeInit() {
	for _, nc := range agent.config.NetConfig {
		err := addPodRoute(nc.Subnet, hostVethName, agent.vtepIP)
		if err != nil {
			agent.log.Errorf("### Could not add route for subnet %+v reason: %s", nc.Subnet, err)
			continue
		}
		agent.log.Infof("VtepIP: %s, subnet: %+v, interface: %s", agent.vtepIP, nc.Subnet, hostVethName)
	}
}

func (agent *HostAgent) isNodeExists(name string) bool {
	_, exists, err := agent.nodeInformer.GetStore().GetByKey(name)
	if err == nil && exists {
		return true
	}
	return false
}
