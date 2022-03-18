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
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package util

import (
	"context"
	nodeinfo "github.com/noironetworks/aci-containers/pkg/nodeinfo/apis/aci.snat/v1"
	nodeinfoclset "github.com/noironetworks/aci-containers/pkg/nodeinfo/clientset/versioned"
	snatglobal "github.com/noironetworks/aci-containers/pkg/snatglobalinfo/apis/aci.snat/v1"
	snatglobalclset "github.com/noironetworks/aci-containers/pkg/snatglobalinfo/clientset/versioned"
	snatpolicy "github.com/noironetworks/aci-containers/pkg/snatpolicy/apis/aci.snat/v1"
	snatpolicyclset "github.com/noironetworks/aci-containers/pkg/snatpolicy/clientset/versioned"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"os"
	"sort"
	"strconv"
)

type StartSorter []snatglobal.PortRange

func (a StartSorter) Len() int           { return len(a) }
func (a StartSorter) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a StartSorter) Less(i, j int) bool { return a[i].Start < a[j].Start }

const PORTPERNODES = 3000
const MIN_PORT = 5000
const MAX_PORT = 65000

// Given generic list of start and end of each port range,
// return sorted array(based on start of the range) of portranges based on number of per node
func ExpandPortRanges(currPortRange []snatglobal.PortRange, step int) []snatglobal.PortRange {

	expandedPortRange := []snatglobal.PortRange{}
	for _, item := range currPortRange {
		temp := item.Start
		for temp < item.End-1 {
			if temp+step-1 <= item.End-1 {
				expandedPortRange = append(expandedPortRange, snatglobal.PortRange{Start: temp, End: temp + step - 1})
			}
			temp = temp + step
		}
	}

	// Sort based on `Start` field
	sort.Sort(StartSorter(expandedPortRange))

	return expandedPortRange
}

// createSnatGlobalInfoCR Creates a SnatGlobalInfo CR
func CreateSnatGlobalInfoCR(c snatglobalclset.Clientset,
	globalInfoSpec snatglobal.SnatGlobalInfoSpec) error {
	ns := os.Getenv("ACI_SNAT_NAMESPACE")
	obj := &snatglobal.SnatGlobalInfo{
		ObjectMeta: metav1.ObjectMeta{
			Name:      os.Getenv("ACI_SNAGLOBALINFO_NAME"),
			Namespace: ns,
		},
		Spec: globalInfoSpec,
	}
	_, err := c.AciV1().SnatGlobalInfos(ns).Create(context.TODO(), obj, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	return nil
}

// UpdateSnatGlobalInfoCR Updates a SnatGlobalInfo CR
func UpdateGlobalInfoCR(c snatglobalclset.Clientset, globalInfo snatglobal.SnatGlobalInfo) error {
	ns := os.Getenv("ACI_SNAT_NAMESPACE")
	_, err := c.AciV1().SnatGlobalInfos(ns).Update(context.TODO(), &globalInfo, metav1.UpdateOptions{})
	if err != nil {
		return err
	}
	return nil
}

func GetGlobalInfoCR(c snatglobalclset.Clientset) (snatglobal.SnatGlobalInfo, error) {
	ns := os.Getenv("ACI_SNAT_NAMESPACE")
	globalinfo, err := c.AciV1().SnatGlobalInfos(ns).Get(context.TODO(), os.Getenv("ACI_SNAGLOBALINFO_NAME"), metav1.GetOptions{})
	if err != nil {
		return snatglobal.SnatGlobalInfo{}, err
	}
	return *globalinfo, nil
}

// CreateNodeInfoCR Creates a NodeInfo CR
func CreateNodeInfoCR(c nodeinfoclset.Clientset,
	nodeInfoSpec nodeinfo.NodeInfoSpec, nodename string) error {
	ns := os.Getenv("ACI_SNAT_NAMESPACE")
	obj := &nodeinfo.NodeInfo{
		ObjectMeta: metav1.ObjectMeta{
			Name:      nodename,
			Namespace: ns,
		},
		Spec: nodeInfoSpec,
	}
	_, err := c.AciV1().NodeInfos(ns).Create(context.TODO(), obj, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	return nil
}

// UpdateNodeInfoCR Updates a UpdateNodeInfoInfo CR
func UpdateNodeInfoCR(c nodeinfoclset.Clientset, nodeinfo nodeinfo.NodeInfo) error {
	ns := os.Getenv("ACI_SNAT_NAMESPACE")
	_, err := c.AciV1().NodeInfos(ns).Update(context.TODO(), &nodeinfo, metav1.UpdateOptions{})
	if err != nil {
		return err
	}
	return nil
}

// UpdateNodeInfoCR Updates a UpdateNodeInfoInfo CR
func DeleteNodeInfoCR(c nodeinfoclset.Clientset, name string) error {
	ns := os.Getenv("ACI_SNAT_NAMESPACE")
	err := c.AciV1().NodeInfos(ns).Delete(context.TODO(), name, metav1.DeleteOptions{})
	if err != nil {
		return err
	}
	return nil
}

func GetPortRangeFromConfigMap(c *kubernetes.Clientset) (snatglobal.PortRange, int) {
	cMap, err := c.CoreV1().ConfigMaps("aci-containers-system").Get(context.TODO(), "snat-operator-config", metav1.GetOptions{})
	var resultPortRange snatglobal.PortRange
	resultPortRange.Start = MIN_PORT
	resultPortRange.End = MAX_PORT
	if err != nil {
		return resultPortRange, PORTPERNODES
	}
	data := cMap.Data
	start, err1 := strconv.Atoi(data["start"])
	end, err2 := strconv.Atoi(data["end"])
	portsPerNode, err3 := strconv.Atoi(data["ports-per-node"])
	if err1 != nil || err2 != nil || err3 != nil ||
		start < 5000 || end > 65000 || start > end || portsPerNode > end-start+1 {
		return resultPortRange, PORTPERNODES
	}
	resultPortRange.Start = start
	resultPortRange.End = end
	return resultPortRange, portsPerNode
}

func MatchLabels(policylabels map[string]string, reslabels map[string]string) bool {
	if len(policylabels) == 0 {
		return true
	}
	for key, value := range policylabels {
		if _, ok := reslabels[key]; ok {
			if value != reslabels[key] {
				return false
			}
		} else {
			return false
		}
	}
	return true
}

func GetServicesByOneOfLabels(indexer cache.Indexer, ns string, reslabels map[string]string) []*v1.Service {
	var services []*v1.Service
	for key, value := range reslabels {
		label := make(map[string]string)
		label[key] = value
		cache.ListAllByNamespace(indexer, ns, labels.SelectorFromSet(label),
			func(servobj interface{}) {
				services = append(services, servobj.(*v1.Service))
			})
	}
	return services
}

// UpdateSnatPolicy Updates a UpdateSnatPolicy CR
func UpdateSnatPolicyCR(c snatpolicyclset.Clientset, policy *snatpolicy.SnatPolicy) error {
	_, err := c.AciV1().SnatPolicies().UpdateStatus(context.TODO(), policy, metav1.UpdateOptions{})
	if err != nil {
		return err
	}
	return nil
}
