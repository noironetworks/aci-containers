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

	netflowpolicy "github.com/noironetworks/aci-containers/pkg/netflowpolicy/apis/aci.netflow/v1alpha"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/noironetworks/aci-containers/pkg/apicapi"
	"github.com/noironetworks/aci-containers/pkg/ipam"
	tu "github.com/noironetworks/aci-containers/pkg/testutil"
	"github.com/stretchr/testify/assert"
)

func staticNetflowPolKey() string {
	return "consul_netflow-policy"
}

type nfTest struct {
	netflowPol  *netflowpolicy.NetflowPolicy
	aciObjSlice apicapi.ApicSlice
	aciObj      apicapi.ApicObject
	desc        string
	writeToApic bool
	nfDelete    bool
}

func makeNf(name string, dstAddr string, dstPort int,
	ver string, activeFlowTimeOut int, idleFlowTimeOut int, samplingRate int) apicapi.ApicSlice {

	nf1 := apicapi.NewNetflowVmmExporterPol(name)
	apicSlice := apicapi.ApicSlice{nf1}
	nf1.SetAttr("dstAddr", dstAddr)
	nf1.SetAttr("dstPort", strconv.Itoa(dstPort))
	nf1.SetAttr("ver", ver)
	nf1VmmVSwitch :=
		apicapi.NewVmmVSwitchPolicyCont("Kubernetes", "")
	nf1RsVmmVSwitch :=
		apicapi.NewVmmRsVswitchExporterPol(nf1VmmVSwitch.GetDn(), nf1.GetDn())
	nf1VmmVSwitch.AddChild(nf1RsVmmVSwitch)
	nf1RsVmmVSwitch.SetAttr("activeFlowTimeOut", strconv.Itoa(activeFlowTimeOut))
	nf1RsVmmVSwitch.SetAttr("idleFlowTimeOut", strconv.Itoa(idleFlowTimeOut))
	nf1RsVmmVSwitch.SetAttr("samplingRate", strconv.Itoa(samplingRate))

	apicSlice = append(apicSlice, nf1VmmVSwitch)

	return apicSlice
}

func checkNf(t *testing.T, nt *nfTest, category string, cont *testAciController) {
	tu.WaitFor(t, nt.desc, 500*time.Millisecond,
		func(last bool) (bool, error) {
			slice := apicapi.ApicSlice{nt.aciObj}
			key := cont.aciNameForKey("nf", nt.netflowPol.Name)
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
			//nf := nfTests[0]
			key := cont.aciNameForKey("nf", nt.netflowPol.Name)
			if !tu.WaitEqual(t, last, 0,
				len(cont.apicConn.GetDesiredState(key)), "delete") {
				return false, nil
			}
			return true, nil
		})
}

func testnetflowpolicy(name string, flowSamplingPolicy netflowpolicy.NetflowType) *netflowpolicy.NetflowPolicy {
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
	name := "kube_nfp_testnf"

	var flowSamplingPolicy0 netflowpolicy.NetflowType
	flowSamplingPolicy0.DstAddr = "172.51.1.2"
	flowSamplingPolicy0.DstPort = 2055
	flowSamplingPolicy0.FlowType = "netflow"
	flowSamplingPolicy0.ActiveFlowTimeOut = 5
	flowSamplingPolicy0.IdleFlowTimeOut = 5
	flowSamplingPolicy0.SamplingRate = 400

	var flowSamplingPolicy1 netflowpolicy.NetflowType
	flowSamplingPolicy1.DstAddr = "172.51.1.2"
	flowSamplingPolicy1.FlowType = "ipfix"

	var flowSamplingPolicy2 netflowpolicy.NetflowType
	flowSamplingPolicy2.DstAddr = "172.51.1.2"
	flowSamplingPolicy2.DstPort = 2056
	flowSamplingPolicy2.FlowType = ""
	flowSamplingPolicy2.ActiveFlowTimeOut = 60
	flowSamplingPolicy2.IdleFlowTimeOut = 15
	flowSamplingPolicy2.SamplingRate = 0

	var nfTests = []nfTest{
		{testnetflowpolicy("testnf", flowSamplingPolicy0),
			makeNf(name, "172.51.1.2", 2055, "v5", 5, 5, 400), nil, "test1", false, true},
		{testnetflowpolicy("testnf", flowSamplingPolicy1),
			makeNf(name, "172.51.1.2", 0, "v9", 0, 0, 0), nil, "test2", false, true},
		{testnetflowpolicy("testnf", flowSamplingPolicy2),
			makeNf(name, "172.51.1.2", 2056, "v5", 60, 15, 0), nil, "test3", false, true},
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

		return cont
	}

	for _, nt := range nfTests {
		cont := initCont()
		cont.log.Info("Testing netflow update for ", nt.desc)
		cont.run()
		cont.fakeNetflowPolicySource.Add(nt.netflowPol)
		actual := nt.aciObjSlice
		expected := cont.netflowPolObjs(nt.netflowPol)
		assert.Equal(t, actual, expected)

		cont.log.Info("Testing netflow post to APIC ", nt.desc)
		actualPost := nt.writeToApic
		expectedPost := cont.handleNetflowPolUpdate(nt.netflowPol)
		assert.Equal(t, actualPost, expectedPost)

		cont.log.Info("Testing netflow delete for ", nt.desc)
		cont.fakeNetflowPolicySource.Delete(nt.netflowPol)
		checkDeleteNf(t, nfTests[0], cont)
		actualDel := nt.nfDelete
		expectedDel := cont.netflowPolicyDelete(nt.netflowPol)
		assert.Equal(t, actualDel, expectedDel)
		cont.stop()
	}
}
