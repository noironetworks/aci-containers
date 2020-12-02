// Copyright 2020 Cisco Systems, Inc.
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
	"net"
	"strconv"
	"testing"
	"time"

	v1 "k8s.io/api/core/v1"

	netflowpolicy "github.com/noironetworks/aci-containers/pkg/netflowpolicy/apis/aci.netflow/v1alpha"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/noironetworks/aci-containers/pkg/apicapi"
	"github.com/noironetworks/aci-containers/pkg/ipam"
	tu "github.com/noironetworks/aci-containers/pkg/testutil"
	"github.com/stretchr/testify/assert"
	"k8s.io/client-go/tools/cache"
)

func staticNetflowReqKey() string {
	return "kube_nf_static"
}

type nfTestAugment struct {
	endpoints []*v1.Endpoints
	services  []*v1.Service
}

type nfTest struct {
	netflowPol *netflowpolicy.NetflowPolicy
	aciObj     apicapi.ApicObject
	augment    *nfTestAugment
	desc       string
}

func addNetflowServices(cont *testAciController, augment *nfTestAugment) {
	if augment == nil {
		return
	}
	for _, s := range augment.services {
		cont.fakeServiceSource.Add(s)
	}
	for _, e := range augment.endpoints {
		cont.fakeEndpointsSource.Add(e)
	}
}

func makeNf(flowSamplingPolicy apicapi.ApicSlice, name string, dstAddr string, dstPort int, ver string,
	activeFlowTimeOut int, idleFlowTimeOut int, samplingRate int) apicapi.ApicObject {

	nf1 := apicapi.NewNetflowVmmExporterPol(name)

	nf1.SetAttr("dstAddr", dstAddr)
	nf1.SetAttr("dstPort", strconv.Itoa(dstPort))
	nf1.SetAttr("ver", ver)

	nf1VmmVSwitch :=
		apicapi.NewVmmVSwitchPolicyCont("Kubernetes", "k8s")
	nf1RsVmmVSwitch :=
		apicapi.NewVmmRsVswitchExporterPol("Kubernetes", "k8s", nf1.GetDn())
	nf1VmmVSwitch.AddChild(nf1RsVmmVSwitch)
	nf1RsVmmVSwitch.SetAttr("activeFlowTimeOut", strconv.Itoa(activeFlowTimeOut))
	nf1RsVmmVSwitch.SetAttr("idleFlowTimeOut", strconv.Itoa(idleFlowTimeOut))
	nf1RsVmmVSwitch.SetAttr("samplingRate", strconv.Itoa(samplingRate))
	return nf1
}

func checkNf(t *testing.T, nt *nfTest, category string, cont *testAciController) {
	tu.WaitFor(t, category+"/"+nt.desc, 500*time.Millisecond,
		func(last bool) (bool, error) {
			slice := apicapi.ApicSlice{nt.aciObj}
			key := cont.aciNameForKey("nf",
				nt.netflowPol.Namespace+"_"+nt.netflowPol.Name)
			apicapi.PrepareApicSlice(slice, "kube", key)

			if !tu.WaitEqual(t, last, slice,
				cont.apicConn.GetDesiredState(key), nt.desc, key) {
				return false, nil
			}
			return true, nil
		})
}

func checkDeleteNf(t *testing.T, nt nfTest, cont *testAciController) {
	tu.WaitFor(t, "delete", 500*time.Millisecond,
		func(last bool) (bool, error) {
			//qr := qrTests[0]
			key := cont.aciNameForKey("nf",
				nt.netflowPol.Namespace+"_"+nt.netflowPol.Name)
			if !tu.WaitEqual(t, last, 0,
				len(cont.apicConn.GetDesiredState(key)), "delete") {
				return false, nil
			}
			return true, nil
		})
}

func (cont *AciController) netflowPolUpdate(nfp *netflowpolicy.NetflowPolicy) apicapi.ApicObject {
	key, err := cache.MetaNamespaceKeyFunc(nfp)
	logger := NetflowPolicyLogger(cont.log, nfp)
	if err != nil {
		logger.Error("Could not create netflow policy key: ", err)
		return nil
	}
	labelKey := cont.aciNameForKey("nfp", key)
	nf := apicapi.NewNetflowVmmExporterPol(labelKey)
	nfDn := nf.GetDn()
	nf.SetAttr("dstAddr", nfp.Spec.FlowSamplingPolicy.DstAddr)
	if nfp.Spec.FlowSamplingPolicy.Version == "netflow" {
		nf.SetAttr("ver", "v5")
	} else if nfp.Spec.FlowSamplingPolicy.Version == "ipfix" {
		nf.SetAttr("ver", "v9")
	} else {
		nf.SetAttr("ver", "v5")
	}
	if nfp.Spec.FlowSamplingPolicy.DstPort != 0 {
		nf.SetAttr("dstPort", strconv.Itoa(nfp.Spec.FlowSamplingPolicy.DstPort))
	} else {
		nf.SetAttr("dstPort", "unspecified")
	}

	VmmVSwitch := apicapi.NewVmmVSwitchPolicyCont(cont.vmmDomainProvider(), cont.config.AciVmmDomain)
	RsVmmVSwitch := apicapi.NewVmmRsVswitchExporterPol(cont.vmmDomainProvider(), cont.config.AciVmmDomain, nfDn)
	VmmVSwitch.AddChild(RsVmmVSwitch)
	if nfp.Spec.FlowSamplingPolicy.ActiveFlowTimeOut != 0 {
		RsVmmVSwitch.SetAttr("activeFlowTimeOut", strconv.Itoa(nfp.Spec.FlowSamplingPolicy.ActiveFlowTimeOut))
	} else {
		RsVmmVSwitch.SetAttr("activeFlowTimeOut", "60")
	}
	if nfp.Spec.FlowSamplingPolicy.IdleFlowTimeOut != 0 {
		RsVmmVSwitch.SetAttr("idleFlowTimeOut", strconv.Itoa(nfp.Spec.FlowSamplingPolicy.IdleFlowTimeOut))
	} else {
		RsVmmVSwitch.SetAttr("idleFlowTimeOut", "15")
	}
	if nfp.Spec.FlowSamplingPolicy.SamplingRate != 0 {
		RsVmmVSwitch.SetAttr("samplingRate", strconv.Itoa(nfp.Spec.FlowSamplingPolicy.SamplingRate))
	} else {
		RsVmmVSwitch.SetAttr("samplingRate", "0")
	}

	return nf
}

func testnetflowpolicy(name string, namespace string, flowSamplingPolicy netflowpolicy.NetflowType) *netflowpolicy.NetflowPolicy {
	policy := &netflowpolicy.NetflowPolicy{
		Spec: netflowpolicy.NetflowPolicySpec{
			FlowSamplingPolicy: flowSamplingPolicy,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Status: netflowpolicy.NetflowPolicyStatus{
			State: netflowpolicy.Ready,
		},
	}

	return policy
}

func TestNetflowPolicy(t *testing.T) {
	var flowSamplingPolicy0 netflowpolicy.NetflowType
	flowSamplingPolicy0.DstAddr = "172.51.1.2"
	flowSamplingPolicy0.DstPort = 2055
	flowSamplingPolicy0.Version = "netflow"
	flowSamplingPolicy0.ActiveFlowTimeOut = 5
	flowSamplingPolicy0.IdleFlowTimeOut = 5
	flowSamplingPolicy0.SamplingRate = 400

	var flowSamplingPolicy1 netflowpolicy.NetflowType
	flowSamplingPolicy1.DstAddr = "172.51.1.2"
	flowSamplingPolicy1.DstPort = 2055
	flowSamplingPolicy1.Version = "netflow"
	flowSamplingPolicy1.ActiveFlowTimeOut = 0
	flowSamplingPolicy1.IdleFlowTimeOut = 0
	flowSamplingPolicy1.SamplingRate = 0

	var flowSamplingPolicy2 netflowpolicy.NetflowType
	flowSamplingPolicy2.DstAddr = "172.51.1.2"
	flowSamplingPolicy2.DstPort = 2056
	flowSamplingPolicy2.Version = ""
	flowSamplingPolicy2.ActiveFlowTimeOut = 60
	flowSamplingPolicy2.IdleFlowTimeOut = 15
	flowSamplingPolicy2.SamplingRate = 0

	name := "kube_nfp_testns"

	rule0_0 := apicapi.NewNetflowVmmExporterPol("test")
	rule0_1 := apicapi.NewVmmVSwitchPolicyCont("Kubernetes", "k8s")
	rule0_1.AddChild(apicapi.NewVmmRsVswitchExporterPol("Kubernetes", "k8s", rule0_0.GetDn()))

	rule1_0 := apicapi.NewNetflowVmmExporterPol("test")
	rule1_1 := apicapi.NewVmmVSwitchPolicyCont("Kubernetes", "k8s")
	rule1_1.AddChild(apicapi.NewVmmRsVswitchExporterPol("Kubernetes", "k8s", rule1_0.GetDn()))

	rule2_0 := apicapi.NewNetflowVmmExporterPol("test")
	rule2_1 := apicapi.NewVmmVSwitchPolicyCont("Kubernetes", "k8s")
	rule2_1.AddChild(apicapi.NewVmmRsVswitchExporterPol("Kubernetes", "k8s", rule2_0.GetDn()))

	var nfTests = []nfTest{
		{testnetflowpolicy("testns", "nf1", flowSamplingPolicy0),
			makeNf(apicapi.ApicSlice{rule0_0}, name, "172.51.1.2", 2055, "v5", 5, 5, 400), nil, ""},
		{testnetflowpolicy("testns", "nf1", flowSamplingPolicy1),
			makeNf(apicapi.ApicSlice{rule1_0}, name, "172.51.1.2", 2055, "v5", 0, 0, 0), nil, ""},
		{testnetflowpolicy("testns", "nf1", flowSamplingPolicy2),
			makeNf(apicapi.ApicSlice{rule2_0}, name, "172.51.1.2", 2056, "v5", 60, 15, 0), nil, ""},
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

		cont.fakeNamespaceSource.Add(namespaceLabel("testns_netflow",
			map[string]string{"test": "testv"}))
		cont.fakeNamespaceSource.Add(namespaceLabel("ns1_netflow",
			map[string]string{"nl_netflow": "nv_netflow"}))
		cont.fakeNamespaceSource.Add(namespaceLabel("ns2_netflow",
			map[string]string{"nl_netflow": "nv_netflow"}))

		return cont
	}
	ips := []string{
		"1.1.1.1", "1.1.1.2", "1.1.1.3", "1.1.1.4", "1.1.1.5", "",
	}

	for _, nt := range nfTests {
		cont := initCont()
		cont.log.Info("Starting podsfirst ", nt.desc)
		addPods(cont, true, ips, true)
		addNetflowServices(cont, nt.augment)
		cont.run()
		cont.fakeNetflowPolicySource.Add(nt.netflowPol)
		actual := nt.aciObj
		expected := cont.netflowPolUpdate(nt.netflowPol)
		assert.Equal(t, actual, expected)

		cont.log.Info("Starting delete ", nt.desc)
		cont.fakeNetflowPolicySource.Delete(nt.netflowPol)
		checkDeleteNf(t, nfTests[0], cont)
		cont.stop()
	}
}
