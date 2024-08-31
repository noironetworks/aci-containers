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

package controller

import (
	"strconv"

	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	v1net "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	framework "k8s.io/client-go/tools/cache/testing"

	"github.com/sirupsen/logrus"
	"github.com/yl2chen/cidranger"

	"github.com/noironetworks/aci-containers/pkg/hpp/clientset/versioned/fake"
	"github.com/noironetworks/aci-containers/pkg/metadata"
	discovery "k8s.io/api/discovery/v1"
)

type testAciController struct {
	AciController
	stopCh chan struct{}

	fakeNamespaceSource       *framework.FakeControllerSource
	fakePodSource             *framework.FakeControllerSource
	fakeEndpointsSource       *framework.FakeControllerSource
	fakeEndpointSliceSource   *framework.FakeControllerSource
	fakeServiceSource         *framework.FakeControllerSource
	fakeNodeSource            *framework.FakeControllerSource
	fakeReplicaSetSource      *framework.FakeControllerSource
	fakeDeploymentSource      *framework.FakeControllerSource
	fakeNetworkPolicySource   *framework.FakeControllerSource
	fakeSnatPolicySource      *framework.FakeControllerSource
	fakeRdConfigSource        *framework.FakeControllerSource
	fakeQosPolicySource       *framework.FakeControllerSource
	fakeNetflowPolicySource   *framework.FakeControllerSource
	fakeErspanPolicySource    *framework.FakeControllerSource
	fakeNodePodIFSource       *framework.FakeControllerSource
	fakeNodeInfoSource        *framework.FakeControllerSource
	fakeIstioSource           *framework.FakeControllerSource
	fakeSnatCfgSource         *framework.FakeControllerSource
	fakeCRDSource             *framework.FakeControllerSource
	fakeFabricVlanPoolsSource *framework.FakeControllerSource
	fakeOobPolicySource       *framework.FakeControllerSource
	podUpdates                []*v1.Pod
	nodeUpdates               []*v1.Node
	serviceUpdates            []*v1.Service
}

func (cont *testAciController) InitController() {
	cont.env.(*K8sEnvironment).cont = &cont.AciController
	cont.env.(*K8sEnvironment).hppClient = fake.NewSimpleClientset()
	cont.serviceEndPoints = &serviceEndpoint{}
	cont.serviceEndPoints.(*serviceEndpoint).cont = &cont.AciController
	cont.fakeNamespaceSource = framework.NewFakeControllerSource()
	cont.initNamespaceInformerBase(
		&cache.ListWatch{
			ListFunc:  cont.fakeNamespaceSource.List,
			WatchFunc: cont.fakeNamespaceSource.Watch,
		})

	cont.fakePodSource = framework.NewFakeControllerSource()
	cont.initPodInformerBase(
		&cache.ListWatch{
			ListFunc:  cont.fakePodSource.List,
			WatchFunc: cont.fakePodSource.Watch,
		})

	cont.fakeEndpointsSource = framework.NewFakeControllerSource()
	cont.initEndpointsInformerBase(
		&cache.ListWatch{
			ListFunc:  cont.fakeEndpointsSource.List,
			WatchFunc: cont.fakeEndpointsSource.Watch,
		})
	cont.fakeEndpointSliceSource = framework.NewFakeControllerSource()
	cont.initEndpointSliceInformerBase(
		&cache.ListWatch{
			ListFunc:  cont.fakeEndpointSliceSource.List,
			WatchFunc: cont.fakeEndpointSliceSource.Watch,
		})
	cont.fakeServiceSource = framework.NewFakeControllerSource()
	cont.initServiceInformerBase(
		&cache.ListWatch{
			ListFunc:  cont.fakeServiceSource.List,
			WatchFunc: cont.fakeServiceSource.Watch,
		})

	cont.fakeNodeSource = framework.NewFakeControllerSource()
	cont.initNodeInformerBase(
		&cache.ListWatch{
			ListFunc:  cont.fakeNodeSource.List,
			WatchFunc: cont.fakeNodeSource.Watch,
		})

	cont.fakeReplicaSetSource = framework.NewFakeControllerSource()
	cont.initReplicaSetInformerBase(
		&cache.ListWatch{
			ListFunc:  cont.fakeReplicaSetSource.List,
			WatchFunc: cont.fakeReplicaSetSource.Watch,
		})

	cont.fakeDeploymentSource = framework.NewFakeControllerSource()
	cont.initDeploymentInformerBase(
		&cache.ListWatch{
			ListFunc:  cont.fakeDeploymentSource.List,
			WatchFunc: cont.fakeDeploymentSource.Watch,
		})

	cont.fakeNetworkPolicySource = framework.NewFakeControllerSource()
	cont.initNetworkPolicyInformerBase(
		&cache.ListWatch{
			ListFunc:  cont.fakeNetworkPolicySource.List,
			WatchFunc: cont.fakeNetworkPolicySource.Watch,
		})

	cont.fakeSnatPolicySource = framework.NewFakeControllerSource()
	cont.initSnatInformerBase(
		&cache.ListWatch{
			ListFunc:  cont.fakeSnatPolicySource.List,
			WatchFunc: cont.fakeSnatPolicySource.Watch,
		})

	cont.fakeRdConfigSource = framework.NewFakeControllerSource()
	cont.initRdConfigInformerBase(
		&cache.ListWatch{
			ListFunc:  cont.fakeRdConfigSource.List,
			WatchFunc: cont.fakeRdConfigSource.Watch,
		})

	cont.fakeQosPolicySource = framework.NewFakeControllerSource()
	cont.initQosInformerBase(
		&cache.ListWatch{
			ListFunc:  cont.fakeQosPolicySource.List,
			WatchFunc: cont.fakeQosPolicySource.Watch,
		})

	cont.fakeNetflowPolicySource = framework.NewFakeControllerSource()
	cont.initNetflowInformerBase(
		&cache.ListWatch{
			ListFunc:  cont.fakeNetflowPolicySource.List,
			WatchFunc: cont.fakeNetflowPolicySource.Watch,
		})

	cont.fakeErspanPolicySource = framework.NewFakeControllerSource()
	cont.initErspanInformerBase(
		&cache.ListWatch{
			ListFunc:  cont.fakeErspanPolicySource.List,
			WatchFunc: cont.fakeErspanPolicySource.Watch,
		})

	cont.fakeNodePodIFSource = framework.NewFakeControllerSource()
	cont.initNodePodIfInformerBase(
		&cache.ListWatch{
			ListFunc:  cont.fakeNodePodIFSource.List,
			WatchFunc: cont.fakeNodePodIFSource.Watch,
		})

	cont.fakeNodeInfoSource = framework.NewFakeControllerSource()
	cont.initSnatNodeInformerBase(
		&cache.ListWatch{
			ListFunc:  cont.fakeNodeInfoSource.List,
			WatchFunc: cont.fakeNodeInfoSource.Watch,
		})

	cont.fakeIstioSource = framework.NewFakeControllerSource()
	/* Commenting code to remove dependency from istio.io/istio package.
	           Vulnerabilties were detected by quay.io security scan of aci-containers-controller
	           and aci-containers-operator images for istio.io/istio package

		cont.initIstioInformerBase(
			&cache.ListWatch{
				ListFunc:  cont.fakeIstioSource.List,
				WatchFunc: cont.fakeIstioSource.Watch,
			})
	*/

	cont.fakeSnatCfgSource = framework.NewFakeControllerSource()
	cont.initSnatCfgInformerBase(
		&cache.ListWatch{
			ListFunc:  cont.fakeSnatCfgSource.List,
			WatchFunc: cont.fakeSnatCfgSource.Watch,
		})

	cont.fakeCRDSource = framework.NewFakeControllerSource()
	cont.initCRDInformerBase(
		&cache.ListWatch{
			ListFunc:  cont.fakeCRDSource.List,
			WatchFunc: cont.fakeCRDSource.Watch,
		})

	cont.fakeFabricVlanPoolsSource = framework.NewFakeControllerSource()
	cont.initFabricVlanPoolInformerBase(
		&cache.ListWatch{
			ListFunc:  cont.fakeFabricVlanPoolsSource.List,
			WatchFunc: cont.fakeFabricVlanPoolsSource.Watch,
		})

	cont.fakeOobPolicySource = framework.NewFakeControllerSource()
	cont.initOOBPolicyInformerBase(
		&cache.ListWatch{
			ListFunc:  cont.fakeOobPolicySource.List,
			WatchFunc: cont.fakeOobPolicySource.Watch,
		})

	cont.updatePod = func(pod *v1.Pod) (*v1.Pod, error) {
		cont.podUpdates = append(cont.podUpdates, pod)
		return pod, nil
	}
	cont.updateNode = func(node *v1.Node) (*v1.Node, error) {
		cont.nodeUpdates = append(cont.nodeUpdates, node)
		return node, nil
	}
	cont.updateServiceStatus = func(service *v1.Service) (*v1.Service, error) {
		cont.serviceUpdates = append(cont.serviceUpdates, service)
		return service, nil
	}
	cont.listNetworkPolicies = func(ns string) (*v1net.NetworkPolicyList, error) {
		return &v1net.NetworkPolicyList{}, nil
	}
	cont.listNamespaces = func() (*v1.NamespaceList, error) {
		return &v1.NamespaceList{}, nil
	}

	cont.initDepPodIndex()
	cont.initNetPolPodIndex()
	cont.initErspanPolPodIndex()
	cont.endpointsIpIndex = cidranger.NewPCTrieRanger()
	cont.targetPortIndex = make(map[string]*portIndexEntry)
	cont.netPolSubnetIndex = cidranger.NewPCTrieRanger()

}

func testController() *testAciController {
	log := logrus.New()
	log.Level = logrus.DebugLevel
	log.Formatter = &logrus.TextFormatter{
		DisableColors: true,
	}

	cont := &testAciController{
		AciController: *NewController(NewConfig(), &K8sEnvironment{}, log, true),
	}
	cont.InitController()
	return cont
}

func testChainedController(aciPrefix string, aciUseGlobalScopeVlan bool, additionalVlans string) *testAciController {
	log := logrus.New()
	log.Level = logrus.DebugLevel
	log.Formatter = &logrus.TextFormatter{
		DisableColors: true,
	}

	cont := &testAciController{
		AciController: *NewController(&ControllerConfig{
			AciPolicyTenant:       "kubernetes",
			AciPrefix:             aciPrefix,
			AciVrf:                "kube-vrf",
			AciVrfTenant:          "common",
			ChainedMode:           true,
			AciPhysDom:            "first-physdom",
			AciAdditionalAep:      "second-aep",
			AciUseGlobalScopeVlan: aciUseGlobalScopeVlan,
		},
			&K8sEnvironment{}, log, true),
	}
	cont.InitController()
	// Hardcode lldpIfMOs
	cont.lldpIfCache["topology/pod-1/node-101/pathep-[eth1/34]"] = "topology/pod-1/protpaths-101-102/pathep-[test-bond1]"
	cont.lldpIfCache["topology/pod-1/node-102/pathep-[eth1/34]"] = "topology/pod-1/protpaths-101-102/pathep-[test-bond1]"
	cont.lldpIfCache["topology/pod-1/node-101/pathep-[eth1/31]"] = "topology/pod-1/protpaths-101-102/pathep-[test-bond2]"
	cont.lldpIfCache["topology/pod-1/node-102/pathep-[eth1/31]"] = "topology/pod-1/protpaths-101-102/pathep-[test-bond2]"
	return cont
}

func (cont *testAciController) run() {
	cont.stopCh = make(chan struct{})
	cont.AciController.Run(cont.stopCh)
}

func (cont *testAciController) stop() {
	close(cont.stopCh)
}

func node(name string) *v1.Node {
	return &v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Annotations: map[string]string{},
		},
	}
}

func namespaceLabel(name string, labels map[string]string) *v1.Namespace {
	return &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: labels,
		},
	}
}

func namespace(name, egAnnot, sgAnnot string) *v1.Namespace {
	return &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Annotations: map[string]string{
				metadata.EgAnnotation: egAnnot,
				metadata.SgAnnotation: sgAnnot,
			},
		},
	}
}

func podOnNode(namespace, name, nodeName string) *v1.Pod {
	return &v1.Pod{
		Spec: v1.PodSpec{
			NodeName: nodeName,
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   namespace,
			Name:        name,
			Annotations: map[string]string{},
		},
	}
}

func podLabel(namespace, name string, labels map[string]string) *v1.Pod {
	return &v1.Pod{
		Spec: v1.PodSpec{
			NodeName: "test-node",
			Containers: []v1.Container{
				{
					Ports: []v1.ContainerPort{
						{
							Name:          "serve-80",
							ContainerPort: int32(80),
						},
					},
				},
			},
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
			Labels:    labels,
		},
	}
}

func pod(namespace, name, egAnnot, sgAnnot string) *v1.Pod {
	pod := podLabel(namespace, name, map[string]string{
		"app":  "sample-app",
		"tier": "sample-tier",
	})
	pod.ObjectMeta.Annotations = map[string]string{
		"kubernetes.io/created-by": "something",
		metadata.EgAnnotation:      egAnnot,
		metadata.SgAnnotation:      sgAnnot,
	}
	return pod
}

func deployment(namespace, name, egAnnot, sgAnnot string) *appsv1.Deployment {
	return &appsv1.Deployment{
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app":  "sample-app",
					"tier": "sample-tier",
				},
			},
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
			Annotations: map[string]string{
				metadata.EgAnnotation: egAnnot,
				metadata.SgAnnotation: sgAnnot,
			},
		},
	}
}

func service(namespace, name, lbIP string) *v1.Service {
	return &v1.Service{
		Spec: v1.ServiceSpec{
			Type:           v1.ServiceTypeLoadBalancer,
			ClusterIP:      "10.0.0.1",
			LoadBalancerIP: lbIP,
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   namespace,
			Name:        name,
			Annotations: map[string]string{},
		},
	}
}

func v6service(namespace, name, lbIP string) *v1.Service {
	return &v1.Service{
		Spec: v1.ServiceSpec{
			Type:           v1.ServiceTypeLoadBalancer,
			ClusterIP:      "2001::f",
			LoadBalancerIP: lbIP,
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   namespace,
			Name:        name,
			Annotations: map[string]string{},
		},
	}
}

// nodes ands addrs must have same length if present, but are
// optional.
func endpoints(namespace, name string,
	nodes, addrs []string, ports []v1.EndpointPort) *v1.Endpoints {
	var eaddrs []v1.EndpointAddress
	if len(nodes) == 0 {
		for i := 0; i < len(addrs); i++ {
			nodes = append(nodes, "node"+strconv.Itoa(i))
		}
	}
	for i, n := range nodes {
		ncopy := n
		ip := "42.42.42.42"
		if addrs != nil {
			ip = addrs[i]
		}
		eaddrs = append(eaddrs, v1.EndpointAddress{
			IP:       ip,
			NodeName: &ncopy,
		})
	}

	return &v1.Endpoints{
		Subsets: []v1.EndpointSubset{
			{
				Addresses: eaddrs,
				Ports:     ports,
			},
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   namespace,
			Name:        name,
			Annotations: map[string]string{},
		},
	}
}

// endpointslice.
func endpointslice(namespace, name string, endpoints []discovery.Endpoint,
	servicename string) *discovery.EndpointSlice {
	return &discovery.EndpointSlice{
		AddressType: discovery.AddressTypeIPv4,
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   namespace,
			Labels:      map[string]string{discovery.LabelServiceName: servicename},
			Annotations: map[string]string{},
		},
		Endpoints: endpoints,
	}
}
