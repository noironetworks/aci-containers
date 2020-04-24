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

package hostagent

import (
	"github.com/sirupsen/logrus"
	cnitypes "github.com/containernetworking/cni/pkg/types"
	"github.com/noironetworks/aci-containers/pkg/metadata"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	v1net "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	framework "k8s.io/client-go/tools/cache/testing"
	"net"
        record "k8s.io/client-go/tools/record"
        "time"
)

const nodename = "test-node"

type testHostAgent struct {
	*HostAgent
	stopCh chan struct{}

	fakeNodeSource          *framework.FakeControllerSource
	fakePodSource           *framework.FakeControllerSource
	fakeEndpointsSource     *framework.FakeControllerSource
	fakeServiceSource       *framework.FakeControllerSource
	fakeNamespaceSource     *framework.FakeControllerSource
	fakeDeploymentSource    *framework.FakeControllerSource
	fakeRCSource            *framework.FakeControllerSource
	fakeNetworkPolicySource *framework.FakeControllerSource
	fakeSnatPolicySource    *framework.FakeControllerSource
	fakeSnatGlobalSource    *framework.FakeControllerSource
	fakeRdConfigSource      *framework.FakeControllerSource
}

func testAgent() *testHostAgent {
	ncf := cniNetConfig{Subnet: cnitypes.IPNet{IP: net.ParseIP("10.128.2.0"), Mask: net.CIDRMask(24, 32)}}
	hcf := &HostAgentConfig{
		NodeName:  nodename,
		NetConfig: []cniNetConfig{ncf},
                GroupDefaults: GroupDefaults{DefaultEg: metadata.OpflexGroup{Name: "aci-containers-test|aci-contianers-default"}},
	}
	return testAgentWithConf(hcf)
}
func testAgentWithConf(hcf *HostAgentConfig) *testHostAgent {
	log := logrus.New()
	log.Level = logrus.InfoLevel

	agent := &testHostAgent{
		HostAgent: NewHostAgent(hcf, &K8sEnvironment{}, log),
	}

	agent.env.(*K8sEnvironment).agent = agent.HostAgent

	agent.fakeNodeSource = framework.NewFakeControllerSource()
	agent.initNodeInformerBase(
		&cache.ListWatch{
			ListFunc:  agent.fakeNodeSource.List,
			WatchFunc: agent.fakeNodeSource.Watch,
		})

	agent.fakePodSource = framework.NewFakeControllerSource()
	agent.initPodInformerBase(
		&cache.ListWatch{
			ListFunc:  agent.fakePodSource.List,
			WatchFunc: agent.fakePodSource.Watch,
		})

	agent.initControllerInformerBase(
		&cache.ListWatch{
			ListFunc:  agent.fakePodSource.List,
			WatchFunc: agent.fakePodSource.Watch,
		})

	agent.fakeEndpointsSource = framework.NewFakeControllerSource()
	agent.initEndpointsInformerBase(
		&cache.ListWatch{
			ListFunc:  agent.fakeEndpointsSource.List,
			WatchFunc: agent.fakeEndpointsSource.Watch,
		})

	agent.fakeServiceSource = framework.NewFakeControllerSource()
	agent.initServiceInformerBase(
		&cache.ListWatch{
			ListFunc:  agent.fakeServiceSource.List,
			WatchFunc: agent.fakeServiceSource.Watch,
		})
	agent.usedIPs = make(map[string]bool)

	agent.fakeNamespaceSource = framework.NewFakeControllerSource()
	agent.initNamespaceInformerBase(
		&cache.ListWatch{
			ListFunc:  agent.fakeNamespaceSource.List,
			WatchFunc: agent.fakeNamespaceSource.Watch,
		})

	agent.fakeDeploymentSource = framework.NewFakeControllerSource()
	agent.initDeploymentInformerBase(
		&cache.ListWatch{
			ListFunc:  agent.fakeDeploymentSource.List,
			WatchFunc: agent.fakeDeploymentSource.Watch,
		})

	agent.fakeRCSource = framework.NewFakeControllerSource()
	agent.initRCInformerBase(
		&cache.ListWatch{
			ListFunc:  agent.fakeRCSource.List,
			WatchFunc: agent.fakeRCSource.Watch,
		})

	agent.fakeNetworkPolicySource = framework.NewFakeControllerSource()
	agent.initNetworkPolicyInformerBase(
		&cache.ListWatch{
			ListFunc:  agent.fakeNetworkPolicySource.List,
			WatchFunc: agent.fakeNetworkPolicySource.Watch,
		})
	agent.fakeSnatPolicySource = framework.NewFakeControllerSource()
	agent.initSnatPolicyInformerBase(
		&cache.ListWatch{
			ListFunc:  agent.fakeSnatPolicySource.List,
			WatchFunc: agent.fakeSnatPolicySource.Watch,
		})
	agent.fakeSnatGlobalSource = framework.NewFakeControllerSource()
	agent.initSnatGlobalInformerBase(
		&cache.ListWatch{
			ListFunc:  agent.fakeSnatGlobalSource.List,
			WatchFunc: agent.fakeSnatGlobalSource.Watch,
		})
	agent.fakeRdConfigSource = framework.NewFakeControllerSource()
	agent.initRdConfigInformerBase(
		&cache.ListWatch{
			ListFunc:  agent.fakeRdConfigSource.List,
			WatchFunc: agent.fakeRdConfigSource.Watch,
		})
	agent.poster = &EventPoster{
		recorder:           record.NewFakeRecorder(100),
		eventSubmitTimeMap: make(map[string]time.Time),
        }
	agent.initNetPolPodIndex()
	agent.initNetPolPodIndex()
	agent.initDepPodIndex()
	agent.initRCPodIndex()

	return agent
}

func (agent *testHostAgent) run() {
	agent.stopCh = make(chan struct{})
	agent.HostAgent.Run(agent.stopCh)
}

func (agent *testHostAgent) stop() {
	close(agent.stopCh)
}

func namespaceLabel(name string, labels map[string]string) *v1.Namespace {
	return &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: labels,
		},
	}
}

func mkNamespace(name string, egAnnot string, sgAnnot string) *v1.Namespace {
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

func podLabel(namespace string, name string, labels map[string]string) *v1.Pod {
	return &v1.Pod{
		Spec: v1.PodSpec{
			NodeName: "test-node",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
			Labels:    labels,
		},
	}
}

func mkDeployment(namespace string, name string, egAnnot string, sgAnnot string) *appsv1.Deployment {
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

func mkRC(namespace string, name string, egAnnot string, sgAnnot string) *v1.ReplicationController {
	return &v1.ReplicationController{
		Spec: v1.ReplicationControllerSpec{
			Template: &v1.PodTemplateSpec{},
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

func mkNetPol(namespace string, name string, podSelector *metav1.LabelSelector,
	irules []v1net.NetworkPolicyIngressRule,
	erules []v1net.NetworkPolicyEgressRule,
	ptypes []v1net.PolicyType) *v1net.NetworkPolicy {
	return &v1net.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: v1net.NetworkPolicySpec{
			PolicyTypes: ptypes,
			PodSelector: *podSelector,
			Ingress:     irules,
			Egress:      erules,
		},
	}
}
