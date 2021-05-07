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
	"strconv"
	"testing"
	"time"

	"github.com/noironetworks/aci-containers/pkg/apicapi"
	erspanpolicy "github.com/noironetworks/aci-containers/pkg/erspanpolicy/apis/aci.erspan/v1alpha"
	"github.com/noironetworks/aci-containers/pkg/ipam"
	tu "github.com/noironetworks/aci-containers/pkg/testutil"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type erspanTest struct {
	erspanPol   *erspanpolicy.ErspanPolicy
	writeToApic bool
	desc        string
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
	dir string, macs []string, vpcs []string) bool {

	srcGrp := apicapi.NewSpanVSrcGrp(name)
	srcGrp.SetAttr("adminSt", adminSt)
	apicSlice := apicapi.ApicSlice{srcGrp}
	srcName := name + "_Src"
	src := apicapi.NewSpanVSrc(srcGrp.GetDn(), srcName)
	src.SetAttr("dir", dir)
	srcGrp.AddChild(src)
	for _, mac := range macs {
		fvCEpDn := fmt.Sprintf("uni/tn-%s/ap-%s/epg-%s/cep-%s",
			"consul", "test-ap", "default", mac)
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
	return false

}

func checkDeleteErspan(t *testing.T, spanTest erspanTest, cont *testAciController) {
	tu.WaitFor(t, "delete", 500*time.Millisecond,
		func(last bool) (bool, error) {
			//span := spanTests[0]
			key := cont.aciNameForKey("span",
				spanTest.erspanPol.Namespace+"_"+spanTest.erspanPol.Name)
			if !tu.WaitEqual(t, last, 0,
				len(cont.apicConn.GetDesiredState(key)), "delete") {
				return false, nil
			}
			return true, nil
		})
}

func TestErspanPolicy(t *testing.T) {
	name := "kube_span_test"
	labels := map[string]string{"lab_key1": "lab_value1"}
	macs := []string{"C2-85-53-A1-85-60", "E4-81-80-40-26-CD"}
	vpcs := []string{"test-vpc1", "test-vpc2"}

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
		{erspanpol("test", "testns", dest0, src0, labels),
			buildSpanObjs(name, "172.51.1.2", 10, "start", "out", macs, vpcs), "test1"},
		{erspanpol("test", "testns", dest0, src1, labels),
			buildSpanObjs(name, "172.51.1.2", 10, "start", "both", macs, vpcs), "test2"},
		{erspanpol("test", "testns", dest1, src1, labels),
			buildSpanObjs(name, "172.51.1.2", 1, "start", "both", macs, vpcs), "test3"},
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

		return cont
	}

	//Function to check if erspan object is present in the apic connection at a specific key
	erspanObject := func(t *testing.T, desc string, cont *testAciController,
		key string, expected string, present bool) {

		tu.WaitFor(t, desc, 500*time.Millisecond,
			func(last bool) (bool, error) {
				cont.indexMutex.Lock()
				defer cont.indexMutex.Unlock()
				var ok bool
				ds := cont.apicConn.GetDesiredState(key)
				for _, v := range ds {
					if _, ok = v[expected]; ok {
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
		cont.log.Info("Testing erspan post to APIC ", spanTest.desc)
		cont.run()
		cont.fakeErspanPolicySource.Modify(spanTest.erspanPol)
		erspanObject(t, "object absent check", cont, name, "spanVSrcGrp", false)
		erspanObject(t, "object absent check", cont, name, "spanVDestGrp", false)
		actualPost := spanTest.writeToApic
		expectedPost := cont.handleErspanUpdate(spanTest.erspanPol)
		assert.Equal(t, actualPost, expectedPost)

		cont.log.Info("Testing erspan delete", spanTest.desc)
		cont.fakeNetflowPolicySource.Delete(spanTest.erspanPol)
		checkDeleteErspan(t, spanTests[0], cont)
		cont.stop()
	}

}
