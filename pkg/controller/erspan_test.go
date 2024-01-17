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
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package controller

import (
	"fmt"
	"net"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/noironetworks/aci-containers/pkg/apicapi"
	erspanpolicy "github.com/noironetworks/aci-containers/pkg/erspanpolicy/apis/aci.erspan/v1alpha"
	"github.com/noironetworks/aci-containers/pkg/ipam"
	nodePodIf "github.com/noironetworks/aci-containers/pkg/nodepodif/apis/acipolicy/v1"
	tu "github.com/noironetworks/aci-containers/pkg/testutil"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

type erspanTest struct {
	erspanPol *erspanpolicy.ErspanPolicy
	desc      string
}

func erspanpol(name string, namespace string, dest erspanpolicy.ErspanDestType,
	source erspanpolicy.ErspanSourceType, labels map[string]string) *erspanpolicy.ErspanPolicy {
	policy := &erspanpolicy.ErspanPolicy{
		Spec: erspanpolicy.ErspanPolicySpec{
			Dest:   dest,
			Source: source,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Status: erspanpolicy.ErspanPolicyStatus{
			State: erspanpolicy.Ready,
		},
	}
	var podSelector erspanpolicy.PodSelector
	podSelector.Namespace = namespace
	podSelector.Labels = labels
	policy.Spec.Selector = podSelector
	return policy
}

func buildSpanObjs(name string, dstIP string, flowID int, adminSt string,
	dir string, macs []string, vpcs []string) apicapi.ApicSlice {
	srcGrp := apicapi.NewSpanVSrcGrp(name)
	srcGrp.SetAttr("adminSt", adminSt)
	apicSlice := apicapi.ApicSlice{srcGrp}
	for _, mac := range macs {
		fvCEpDn := fmt.Sprintf("uni/tn-%s/ap-%s/epg-%s/cep-%s",
			"consul", "test-ap", "default", mac)
		srcName := name + "_Src"
		src := apicapi.NewSpanVSrc(srcGrp.GetDn(), srcName)
		src.SetAttr("dir", dir)
		srcGrp.AddChild(src)
		srcCEp := apicapi.NewSpanRsSrcToVPort(src.GetDn(), fvCEpDn)
		src.AddChild(srcCEp)
	}
	lbl := apicapi.NewSpanSpanLbl(srcGrp.GetDn(), name)
	srcGrp.AddChild(lbl)

	destGrp := apicapi.NewSpanVDestGrp(name)
	destName := name + "_Dest"
	dest := apicapi.NewSpanVDest(destGrp.GetDn(), destName)
	destGrp.AddChild(dest)
	destSummary := apicapi.NewSpanVEpgSummary(dest.GetDn())
	destSummary.SetAttr("dstIp", dstIP)
	destSummary.SetAttr("flowId", strconv.Itoa(flowID))
	dest.AddChild(destSummary)
	apicSlice = append(apicSlice, destGrp)
	for _, vpc := range vpcs {
		accBndlGrp := apicapi.NewInfraAccBndlGrp(vpc)
		infraRsSpanVSrcGrp := apicapi.NewInfraRsSpanVSrcGrp(vpc, name)
		accBndlGrp.AddChild(infraRsSpanVSrcGrp)
		apicSlice = append(apicSlice, infraRsSpanVSrcGrp)
		infraRsSpanVDstGrp := apicapi.NewInfraRsSpanVDestGrp(vpc, name)
		accBndlGrp.AddChild(infraRsSpanVDstGrp)
		apicSlice = append(apicSlice, infraRsSpanVDstGrp)
	}
	return apicSlice
}

func checkDeleteErspan(t *testing.T, spanTest erspanTest, cont *testAciController) {
	tu.WaitFor(t, "delete", 500*time.Millisecond,
		func(last bool) (bool, error) {
			key, _ := cache.MetaNamespaceKeyFunc(spanTest.erspanPol)
			labelKey := cont.aciNameForKey("span", key)
			if !tu.WaitEqual(t, last, 0,
				len(cont.apicConn.GetDesiredState(labelKey)), "delete") {
				return false, nil
			}
			return true, nil
		})
}

func TestErspanPolicy(t *testing.T) {
	labels := map[string]string{"lab_key1": "lab_value1"}

	var dest0 erspanpolicy.ErspanDestType
	dest0.DestIP = "172.51.1.2"
	dest0.FlowID = 10

	var dest1 erspanpolicy.ErspanDestType
	dest1.DestIP = "172.51.1.2"

	var src0 erspanpolicy.ErspanSourceType
	src0.AdminState = "start"
	src0.Direction = "out"

	var src1 erspanpolicy.ErspanSourceType
	src1.AdminState = ""
	src1.Direction = ""

	var spanTests = []erspanTest{
		{erspanpol("test", "testns", dest0, src0, labels), "test1"},
		{erspanpol("test", "testns", dest0, src1, labels), "test2"},
		{erspanpol("test", "testns", dest1, src1, labels), "test3"},
	}
	initCont := func() *testAciController {
		cont := testController()
		cont.config.NodeServiceIpPool = []ipam.IpRange{
			{Start: net.ParseIP("10.1.1.2"), End: net.ParseIP("10.1.1.3")},
		}
		cont.config.PodIpPool = []ipam.IpRange{
			{Start: net.ParseIP("10.1.1.2"), End: net.ParseIP("10.1.255.254")},
		}
		cont.AciController.initIpam()

		cont.fakeNamespaceSource.Add(namespaceLabel("testns",
			map[string]string{"test": "testv"}))
		cont.fakeNamespaceSource.Add(namespaceLabel("ns1",
			map[string]string{"nl": "nv"}))
		cont.fakeNamespaceSource.Add(namespaceLabel("ns2",
			map[string]string{"nl": "nv"}))

		pod := &v1.Pod{
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
				Namespace: "testns",
				Name:      "pod-1",
				Labels:    labels,
			},
		}
		cont.fakePodSource.Add(pod)

		cont.config.AciVmmDomain = "kube"
		cont.config.AciVmmController = "kube"

		return cont
	}

	// Function to check if erspan object is present in the apic connection at a specific key
	erspanObject := func(t *testing.T, desc string, cont *testAciController,
		key string, isexpected string, present bool) {
		tu.WaitFor(t, desc, 500*time.Millisecond,
			func(last bool) (bool, error) {
				cont.indexMutex.Lock()
				defer cont.indexMutex.Unlock()
				var ok bool
				ds := cont.apicConn.GetDesiredState(key)
				for _, v := range ds {
					if _, ok = v[isexpected]; ok {
						break
					}
				}
				if ok == present {
					return true, nil
				}
				return false, nil
			})
		cont.log.Info("Finished waiting for ", desc)
	}

	for _, spanTest := range spanTests {
		cont := initCont()
		cont.run()
		go cont.erspanInformer.Run(cont.stopCh)
		go cont.nodePodIfInformer.Run(cont.stopCh)

		nodepodifinfo := &nodePodIf.NodePodIF{
			Spec: nodePodIf.NodePodIFSpec{
				PodIFs: []nodePodIf.PodIF{
					{
						MacAddr: "C2-85-53-A1-85-61",
						EPG:     "test-epg1",
						PodNS:   "testns",
						PodName: "pod-1",
					},
				},
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test",
				Namespace: "testns",
			},
		}

		cont.fakeNodePodIFSource.Add(nodepodifinfo)

		time.Sleep(100 * time.Millisecond)

		go cont.processQueue(cont.erspanQueue, cont.erspanIndexer,
			func(obj interface{}) bool {
				return cont.handleErspanUpdate(obj.(*erspanpolicy.ErspanPolicy))
			}, nil, nil, cont.stopCh)
		key, _ := cache.MetaNamespaceKeyFunc(spanTest.erspanPol)
		labelKey := cont.aciNameForKey("span", key)

		opflexDevice1 := apicapi.EmptyApicObject("opflexODev", "dev1")
		opflexDevice1.SetAttr("hostName", "node1")
		opflexDevice1.SetAttr("fabricPathDn",
			"topology/pod-1/protpaths-301/pathep-[eth1/33]")
		opflexDevice1.SetAttr("devType", "k8s")
		opflexDevice1.SetAttr("domName", "kube")
		opflexDevice1.SetAttr("ctrlrName", "kube")
		opflexDevice1.SetAttr("state", "connected")

		cont.opflexDeviceChanged(opflexDevice1)
		time.Sleep(500 * time.Millisecond)

		cont.log.Info("Testing erspan Add ", spanTest.desc)
		cont.fakeErspanPolicySource.Add(spanTest.erspanPol)
		erspanObject(t, "object absent check", cont, labelKey, "spanVSrcGrp", true)
		erspanObject(t, "object absent check", cont, labelKey, "spanVDestGrp", true)

		cont.log.Info("Testing erspan delete", spanTest.desc)
		cont.fakeErspanPolicySource.Delete(spanTest.erspanPol)
		checkDeleteErspan(t, spanTest, cont)

		opflexDevice2 := apicapi.EmptyApicObject("opflexODev", "dev1")
		opflexDevice2.SetAttr("hostName", "node1")
		opflexDevice2.SetAttr("fabricPathDn",
			"topology/pod-1/paths-301/pathep-[eth1/34]")
		opflexDevice2.SetAttr("devType", "k8s")
		opflexDevice2.SetAttr("domName", "kube")
		opflexDevice2.SetAttr("ctrlrName", "kube")
		opflexDevice2.SetAttr("state", "connected")

		cont.opflexDeviceChanged(opflexDevice2)
		time.Sleep(500 * time.Millisecond)

		cont.log.Info("Testing erspan update", spanTest.desc)
		cont.fakeErspanPolicySource.Modify(spanTest.erspanPol)
		erspanObject(t, "object absent check", cont, labelKey, "spanVSrcGrp", true)
		erspanObject(t, "object absent check", cont, labelKey, "spanVDestGrp", true)

		cont.log.Info("Testing erspan delete", spanTest.desc)
		cont.fakeErspanPolicySource.Delete(spanTest.erspanPol)
		checkDeleteErspan(t, spanTest, cont)

		erspanPol := erspanpol("test-erspanpol", "test-namespace", dest0, src0, labels)
		key, _ = cache.MetaNamespaceKeyFunc(erspanPol)
		labelKey = cont.aciNameForKey("span", key)
		cont.fakeErspanPolicySource.Add(erspanPol)
		time.Sleep(500 * time.Millisecond)
		type test struct {
			metav1.ObjectMeta
		}

		fakeErspanPol := &test{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "test-namespace",
				Name:      "test-erspanpol",
			},
		}
		cont.erspanPolicyDeleted(fakeErspanPol)
		time.Sleep(500 * time.Millisecond)
		if len(cont.apicConn.GetDesiredState(labelKey)) == 0 {
			t.Error("erspan policy should not be deleted")
		}

		fakeErspanPol2 := cache.DeletedFinalStateUnknown{
			Key: key,
			Obj: labelKey,
		}

		cont.erspanPolicyDeleted(fakeErspanPol2)
		time.Sleep(500 * time.Millisecond)
		if len(cont.apicConn.GetDesiredState(labelKey)) == 0 {
			t.Error("erspan policy should not be deleted")
		}

		cont.fakeErspanPolicySource.Delete(erspanPol)

		cont.stop()
	}
}

func TestMisc(t *testing.T) {
	cont := testController()
	opflexDevice1 := apicapi.EmptyApicObject("opflexODev", "dev1")
	opflexDevice1.SetAttr("hostName", "node1")
	opflexDevice1.SetAttr("fabricPathDn",
		"topology/pod-1/protpaths-301/pathep-[eth1/33]")
	opflexDevice1.SetAttr("devType", "k8s")
	opflexDevice1.SetAttr("domName", "kube")
	opflexDevice1.SetAttr("ctrlrName", "kube")
	opflexDevice1.SetAttr("state", "connected")

	opflexDevice2 := apicapi.EmptyApicObject("opflexODev", "dev1")
	opflexDevice2.SetAttr("hostName", "node1")
	opflexDevice2.SetAttr("fabricPathDn",
		"topology/pod-1/paths-301/pathep-[eth1/34]")
	opflexDevice2.SetAttr("devType", "k8s")
	opflexDevice2.SetAttr("domName", "kube")
	opflexDevice2.SetAttr("ctrlrName", "kube")
	opflexDevice2.SetAttr("state", "connected")

	cont.config.AciVmmDomain = "kube"
	cont.config.AciVmmController = "kube"
	cont.run()
	defer cont.stop()
	cont.opflexDeviceChanged(opflexDevice1)
	time.Sleep(500 * time.Millisecond)
	// Test getFabricPaths
	expected := []string{"topology/pod-1/protpaths-301/pathep-[eth1/33]"}
	if !reflect.DeepEqual(expected, cont.getFabricPaths()) {
		t.Error("Expected ", expected, " got ", cont.getFabricPaths())
	}

	// Test getVpcs
	expected = []string{"eth1/33"}
	if !reflect.DeepEqual(expected, cont.getVpcs()) {
		t.Error("Expected ", expected, " got ", cont.getVpcs())
	}

	cont.opflexDeviceChanged(opflexDevice2)

	// Test getAccLeafPorts
	expected = []string{"eth1/34"}
	if !reflect.DeepEqual(expected, cont.getAccLeafPorts()) {
		t.Error("Expected ", expected, " got ", cont.getAccLeafPorts())
	}

	// Test transformMac
	mac := "00:50:56:8c:5a:aa"
	expectedMac := "00-50-56-8c-5a-aa"
	if expectedMac != transformMac(mac) {
		t.Error("Expected ", expected, " got ", transformMac(mac))
	}

}
