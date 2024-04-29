// Copyright 2019 Cisco Systems, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRATIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Handlers for snat updates.

package hostagent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	hppv1 "github.com/noironetworks/aci-containers/pkg/hpp/apis/aci.hpp/v1"
	hppclset "github.com/noironetworks/aci-containers/pkg/hpp/clientset/versioned"

	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
	"k8s.io/kubernetes/pkg/controller"
)

func (agent *HostAgent) initHppInformerFromClient(
	hppClient *hppclset.Clientset) {
	agent.initHppInformerBase(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				return hppClient.AciV1().HostprotPols(metav1.NamespaceAll).List(context.TODO(), options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				return hppClient.AciV1().HostprotPols(metav1.NamespaceAll).Watch(context.TODO(), options)
			},
		})
}

func (agent *HostAgent) initHostprotRemoteIpContainerInformerFromClient(
	hppClient *hppclset.Clientset) {
	agent.initHostprotRemoteIpContainerBase(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				return hppClient.AciV1().HostprotRemoteIpContainers(metav1.NamespaceAll).List(context.TODO(), options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				return hppClient.AciV1().HostprotRemoteIpContainers(metav1.NamespaceAll).Watch(context.TODO(), options)
			},
		})
}

func HppLogger(log *logrus.Logger, hpp *hppv1.HostprotPol) *logrus.Entry {
	return log.WithFields(logrus.Fields{
		"namespace": hpp.ObjectMeta.Namespace,
		"name":      hpp.ObjectMeta.Name,
		"spec":      hpp.Spec,
	})
}

func HostprotRemoteIpContainerLogger(log *logrus.Logger, hpp *hppv1.HostprotRemoteIpContainer) *logrus.Entry {
	return log.WithFields(logrus.Fields{
		"namespace": hpp.ObjectMeta.Namespace,
		"name":      hpp.ObjectMeta.Name,
		"spec":      hpp.Spec,
	})
}

func (agent *HostAgent) initHppInformerBase(listWatch *cache.ListWatch) {
	agent.hppInformer = cache.NewSharedIndexInformer(
		listWatch,
		&hppv1.HostprotPol{},
		controller.NoResyncPeriodFunc(),
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	agent.hppInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			agent.hppAdded(obj)
		},
		UpdateFunc: func(oldobj interface{}, newobj interface{}) {
			agent.hppUpdate(oldobj, newobj)
		},
		DeleteFunc: func(obj interface{}) {
			agent.hppDelete(obj)
		},
	})
}

func (agent *HostAgent) initHostprotRemoteIpContainerBase(listWatch *cache.ListWatch) {
	agent.hppRemoteIpInformer = cache.NewSharedIndexInformer(
		listWatch,
		&hppv1.HostprotRemoteIpContainer{},
		controller.NoResyncPeriodFunc(),
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	agent.hppRemoteIpInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			agent.hppRemoteIPUpdate(obj)
		},
		UpdateFunc: func(_ interface{}, obj interface{}) {
			agent.hppRemoteIPUpdate(obj)
		},
		DeleteFunc: func(obj interface{}) {
			agent.hppRemoteIPDelete(obj)
		},
	})
}

func (agent *HostAgent) matchesFilter(label hppv1.HppEpLabel, filter hppv1.HostprotFilter) bool {
	switch filter.Operator {
	case "In":
		for _, value := range filter.Values {
			if label.Key == filter.Key && label.Value == value {
				return true
			}
		}
		return false
	case "NotIn":
		for _, value := range filter.Values {
			if label.Key == filter.Key && label.Value == value {
				return false
			}
		}
		return true
	case "Exists":
		return label.Key == filter.Key
	case "DoesNotExist":
		return label.Key != filter.Key
	case "Equals":
		if len(filter.Values) == 0 || len(filter.Values) > 1 {
			return false
		}
		return label.Key == filter.Key && label.Value == filter.Values[0]
	default:
		return false
	}
}

func (agent *HostAgent) matchesAllFilters(labels []hppv1.HppEpLabel, filters []hppv1.HostprotFilter) bool {
	for _, filter := range filters {
		matchFound := false
		for _, label := range labels {
			if agent.matchesFilter(label, filter) {
				matchFound = true
				break
			}
		}
		if !matchFound {
			return false
		}
	}
	return true
}

func (agent *HostAgent) filterHostProtRemoteIps(remoteIps []hppv1.HostprotRemoteIp, filters []hppv1.HostprotFilter) []string {
	var matchedAddrs []string
	for _, remoteIp := range remoteIps {
		if agent.matchesAllFilters(remoteIp.HppEpLabel, filters) {
			matchedAddrs = append(matchedAddrs, remoteIp.Addr)
		}
	}
	return matchedAddrs
}

func (agent *HostAgent) getHostprotRemoteIpContainer(name, ns string) (*hppv1.HostprotRemoteIpContainer, error) {
	env := agent.env.(*K8sEnvironment)
	hppcl := env.hppClient
	if hppcl == nil {
		return nil, fmt.Errorf("hpp client not found")
	}

	hpp, err := hppcl.AciV1().HostprotRemoteIpContainers(ns).Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		agent.log.Error("Error getting HostprotRemoteIpContainers CR: ", err)
		return nil, err
	}
	agent.log.Debug("HostprotRemoteIpContainers CR found: ", hpp)
	return hpp, nil
}

func (agent *HostAgent) updateLocalHpp(obj interface{}) {
	agent.indexMutex.Lock()
	defer agent.indexMutex.Unlock()
	hpp := obj.(*hppv1.HostprotPol)
	logger := HppLogger(agent.log, hpp)
	agent.initGbpConfig()
	ns := agent.config.AciHppObjsNamespace
	np := &NetworkPolicy{
		HostprotPol: Hpp{
			Attributes: map[string]string{},
			Children:   []map[string]*HpSubj{},
		},
	}

	for _, subj := range hpp.Spec.HostprotSubj {
		hpSubj := &HpSubj{
			Attributes: map[string]string{
				propName: subj.Name,
			},
			Children: []map[string]HpSubjChild{},
		}
		for _, rule := range subj.HostprotRule {
			hpRule := &HpSubjChild{
				Attributes: map[string]string{
					propName:    rule.Name,
					"direction": rule.Direction,
					"protocol":  rule.Protocol,
					"fromPort":  rule.FromPort,
					"toPort":    rule.ToPort,
					"connTrack": rule.ConnTrack,
					"ethertype": rule.Ethertype,
				},
				Children: []map[string]HpSubjGrandchild{},
			}

			hostprotServiceRemoteIps := rule.HostprotServiceRemoteIps

			if strings.HasPrefix(rule.Name, "service_") && len(hostprotServiceRemoteIps) > 0 {
				for _, remoteIp := range hostprotServiceRemoteIps {
					hpSubnet := &HpSubjGrandchild{
						Attributes: map[string]string{
							"addr": remoteIp,
						},
					}
					hpRule.Children = append(hpRule.Children, map[string]HpSubjGrandchild{"hostprotRemoteIp": *hpSubnet})
				}
			} else {
				rsRemoteIpContainer := rule.RsRemoteIpContainer
				hostprotFilters := rule.HostprotFilterContainer.HostprotFilter

				for _, remoteIpContainerName := range rsRemoteIpContainer {
					remoteIpCont, err := agent.getHostprotRemoteIpContainer(remoteIpContainerName, ns)
					if err != nil {
						logger.Error("Error getting HostprotRemoteIpContainers")
						return
					}
					hostprotRemoteIps := remoteIpCont.Spec.HostprotRemoteIp
					matchedAddrs := agent.filterHostProtRemoteIps(hostprotRemoteIps, hostprotFilters)
					for _, matchedAddr := range matchedAddrs {
						hpSubnet := &HpSubjGrandchild{
							Attributes: map[string]string{
								"addr": matchedAddr,
							},
						}
						hpRule.Children = append(hpRule.Children, map[string]HpSubjGrandchild{"hostprotRemoteIp": *hpSubnet})
					}
				}
			}

			hpSubj.Children = append(hpSubj.Children, map[string]HpSubjChild{"hostprotRule": *hpRule})
		}
		np.HostprotPol.Children = append(np.HostprotPol.Children, map[string]*HpSubj{"hostprotSubj": hpSubj})
	}

	np.HostprotPol.Attributes[propName] = hpp.Spec.Name

	err := np.Make()
	if err != nil {
		agent.log.Errorf("network policy -- %v", err)
		return
	}
	modb := getMoDB()
	policyDBJson, err := json.MarshalIndent(modb, "", "  ")
	if err != nil {
		agent.log.Fatalf("Failed to marshal policyDB: %v", err)
		return
	}
	filePath := filepath.Join(agent.config.OpFlexNetPolDir, fmt.Sprintf("%s.netpol", hpp.Spec.Name))
	err = os.WriteFile(filePath, policyDBJson, 0644)
	if err != nil {
		agent.log.Fatalf("Failed to write netpol to file: %v", err)
		return
	} else {
		agent.log.Infof("HPP %s updated", hpp.Spec.Name)
	}
}

func (agent *HostAgent) hppAdded(obj interface{}) {
	agent.updateLocalHpp(obj)
}

func (agent *HostAgent) hppUpdate(old_obj interface{}, obj interface{}) {
	agent.hppDelete(old_obj)
	agent.updateLocalHpp(obj)
}

func (agent *HostAgent) hppDelete(obj interface{}) {
	hpp := obj.(*hppv1.HostprotPol)
	filePath := filepath.Join(agent.config.OpFlexNetPolDir, fmt.Sprintf("%s.netpol", hpp.Spec.Name))
	err := os.Remove(filePath)
	if err != nil {
		agent.log.Errorf("Failed to delete file: %v", err)
	}
}

func (agent *HostAgent) listHostprotPol(ns string) (*hppv1.HostprotPolList, error) {
	env := agent.env.(*K8sEnvironment)
	hppcl := env.hppClient
	if hppcl == nil {
		return nil, fmt.Errorf("hpp client not found")
	}

	hpps, err := hppcl.AciV1().HostprotPols(ns).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		agent.log.Error("Error listing HPP CR: ", err)
		return nil, err
	}
	return hpps, nil
}

func (agent *HostAgent) hppRemoteIPUpdate(obj interface{}) {
	hppRemoteIpCont := obj.(*hppv1.HostprotRemoteIpContainer)
	ns := agent.config.AciHppObjsNamespace
	hpps, err := agent.listHostprotPol(ns)
	if err != nil {
		return
	}
	for _, hpp := range hpps.Items {
		hppUpdated := false
		for _, subj := range hpp.Spec.HostprotSubj {
			if hppUpdated {
				break
			}
			for _, rule := range subj.HostprotRule {
				if hppUpdated {
					break
				}
				for _, remoteIpContainerName := range rule.RsRemoteIpContainer {
					if remoteIpContainerName == hppRemoteIpCont.Name {
						agent.updateLocalHpp(&hpp)
						hppUpdated = true
						break
					}
				}
			}
		}
	}
}

func (agent *HostAgent) hppRemoteIPDelete(obj interface{}) {
	agent.hppRemoteIPUpdate(obj)
}
