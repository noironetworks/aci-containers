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
	"fmt"
	"net"
	"strconv"
	"testing"
	"time"

	v1 "k8s.io/api/core/v1"

	qospolicy "github.com/noironetworks/aci-containers/pkg/qospolicy/apis/aci.qos/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/noironetworks/aci-containers/pkg/apicapi"
	"github.com/noironetworks/aci-containers/pkg/ipam"
	tu "github.com/noironetworks/aci-containers/pkg/testutil"
	"github.com/stretchr/testify/assert"
	"k8s.io/client-go/tools/cache"
)

func staticQosReqKey() string {
	return "kube_qr_static"
}

type qrTestAugment struct {
	endpoints []*v1.Endpoints
	services  []*v1.Service
}

type qrTest struct {
	qosPol  *qospolicy.QosPolicy
	aciObj  apicapi.ApicObject
	augment *qrTestAugment
	desc    string
}

func addQosServices(cont *testAciController, augment *qrTestAugment) {
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

func makeQr(ingress apicapi.ApicSlice, egress apicapi.ApicSlice, name string, policingRateI int,
	policingBurstI int, policingRateE int, policingBurstE int, dscpMark int) apicapi.ApicObject {

	qr1 := apicapi.NewQosRequirement("test-tenant_qos", name)
	qEpDscpMarking := apicapi.NewQosEpDscpMarking(qr1.GetDn(), "EpDscpMarking")
	qEpDscpMarking.SetAttr("mark", strconv.Itoa(dscpMark))
	qr1.AddChild(qEpDscpMarking)

	if ingress != nil {
		qr1dpppI :=
			apicapi.NewQosDppPol("test-tenant_qos", "ingress")
		qr1dpppI.SetAttr("rate", strconv.Itoa(policingRateI))
		qr1dpppI.SetAttr("burst", strconv.Itoa(policingBurstI))
		qr1rsdpppI :=
			apicapi.NewRsIngressDppPol(qr1.GetDn(), qr1dpppI.GetDn())
		qr1.AddChild(qr1rsdpppI)
	}
	if egress != nil {
		qr1dpppE :=
			apicapi.NewQosDppPol("test-tenant_qos", "egress")
		qr1dpppE.SetAttr("rate", policingRateE)
		qr1dpppE.SetAttr("burst", policingBurstE)
		qr1rsdpppE :=
			apicapi.NewRsEgressDppPol(qr1.GetDn(), qr1dpppE.GetDn())
		qr1.AddChild(qr1rsdpppE)
	}
	return qr1
}

func checkQr(t *testing.T, qt *qrTest, category string, cont *testAciController) {
	tu.WaitFor(t, category+"/"+qt.desc, 500*time.Millisecond,
		func(last bool) (bool, error) {
			slice := apicapi.ApicSlice{qt.aciObj}
			key := cont.aciNameForKey("qr",
				qt.qosPol.Namespace+"_"+qt.qosPol.Name)
			apicapi.PrepareApicSlice(slice, "kube", key)

			if !tu.WaitEqual(t, last, slice,
				cont.apicConn.GetDesiredState(key), qt.desc, key) {
				return false, nil
			}
			return true, nil
		})
}

func checkDeleteQr(t *testing.T, qt qrTest, cont *testAciController) {
	tu.WaitFor(t, "delete", 500*time.Millisecond,
		func(last bool) (bool, error) {
			//qr := qrTests[0]
			key := cont.aciNameForKey("qr",
				qt.qosPol.Namespace+"_"+qt.qosPol.Name)
			if !tu.WaitEqual(t, last, 0,
				len(cont.apicConn.GetDesiredState(key)), "delete") {
				return false, nil
			}
			return true, nil
		})
}

func (cont *AciController) qosPolUpdate(qp *qospolicy.QosPolicy) apicapi.ApicObject {
	key, err := cache.MetaNamespaceKeyFunc(qp)
	logger := QosPolicyLogger(cont.log, qp)
	if err != nil {
		logger.Error("Could not create qos policy key: ", err)
		return nil
	}
	labelKey := cont.aciNameForKey("qp", key)
	qr := apicapi.NewQosRequirement(cont.config.AciPolicyTenant, labelKey)
	qrDn := qr.GetDn()

	// Pushing EpDscpMarking Mo if dscp_mark not equal to 0
	if qp.Spec.Mark != 0 {
		DscpMarking := apicapi.NewQosEpDscpMarking(qrDn, "EpDscpMarking")
		DscpMarking.SetAttr("mark", strconv.Itoa(qp.Spec.Mark))
		qr.AddChild(DscpMarking)
	}

	// Generate ingress policies
	if qp.Spec.Ingress.PolicingRate != 0 && qp.Spec.Ingress.PolicingBurst != 0 {

		DppPolIngress := apicapi.NewQosDppPol(cont.config.AciPolicyTenant, "ingress")
		DppPolIngress.SetAttr("rate", strconv.Itoa(qp.Spec.Ingress.PolicingRate))
		DppPolIngress.SetAttr("burst", strconv.Itoa(qp.Spec.Ingress.PolicingBurst))

		DppPolIngressDn := DppPolIngress.GetDn()
		RsIngressDppPol := apicapi.NewRsIngressDppPol(qrDn, DppPolIngressDn)
		qr.AddChild(RsIngressDppPol)
	}

	// Generate egress policies
	if qp.Spec.Egress.PolicingRate != 0 && qp.Spec.Egress.PolicingBurst != 0 {

		DppPolEgress := apicapi.NewQosDppPol(cont.config.AciPolicyTenant, "egress")
		DppPolEgress.SetAttr("rate", strconv.Itoa(qp.Spec.Egress.PolicingRate))
		DppPolEgress.SetAttr("burst", strconv.Itoa(qp.Spec.Egress.PolicingBurst))

		DppPolEgressDn := DppPolEgress.GetDn()
		RsEgressDppPol := apicapi.NewRsEgressDppPol(qrDn, DppPolEgressDn)
		qr.AddChild(RsEgressDppPol)
	}

	return qr
}

func testqospolicy(name string, namespace string, ingress qospolicy.PolicingType,
	egress qospolicy.PolicingType, mark int, labels map[string]string) *qospolicy.QosPolicy {
	policy := &qospolicy.QosPolicy{
		Spec: qospolicy.QosPolicySpec{
			Ingress: ingress, Egress: egress, Mark: mark,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Status: qospolicy.QosPolicyStatus{
			State: qospolicy.Ready,
		},
	}
	var podSelector qospolicy.PodSelector
	podSelector.Namespace = namespace
	podSelector.Labels = labels
	policy.Spec.Selector = podSelector

	return policy
}

func TestQosPolicy(t *testing.T) {
	dscpmark := 1

	var ingress0 qospolicy.PolicingType
	ingress0.PolicingRate = 1000
	ingress0.PolicingBurst = 1000

	var egress0 qospolicy.PolicingType
	egress0.PolicingRate = 0
	egress0.PolicingBurst = 0

	var ingress1 qospolicy.PolicingType
	ingress1.PolicingRate = 0
	ingress1.PolicingBurst = 0

	var egress1 qospolicy.PolicingType
	egress1.PolicingRate = 1000
	egress1.PolicingBurst = 1000

	var ingress2 qospolicy.PolicingType
	ingress2.PolicingRate = 1000
	ingress2.PolicingBurst = 1000

	var egress2 qospolicy.PolicingType
	egress2.PolicingRate = 1000
	egress2.PolicingBurst = 1000

	var ingress3 qospolicy.PolicingType
	ingress3.PolicingRate = 0
	ingress3.PolicingBurst = 0

	var egress3 qospolicy.PolicingType
	egress3.PolicingRate = 0
	egress3.PolicingBurst = 0

	name := "kube_qp_testns"
	baseDn := makeQr(nil, nil, name, 1000, 1000, 0, 0, 0).GetDn()
	qr1SDnI := fmt.Sprintf("%s/qosreq-qp_default_qos-policy1 ", baseDn)

	rule_0_0 := apicapi.NewQosRequirement(qr1SDnI, "0")
	rule_0_1 := apicapi.NewQosDppPol(rule_0_0.GetDn(), "ingress")
	rule_0_0.AddChild(apicapi.NewRsIngressDppPol(rule_0_0.GetDn(), rule_0_1.GetDn()))
	rule_0_0.AddChild(apicapi.NewQosEpDscpMarking(rule_0_0.GetDn(), "EpDscpMarking"))

	baseDn = makeQr(nil, nil, name, 0, 0, 1000, 1000, 0).GetDn()
	qr1SDnE := fmt.Sprintf("%s/qosreq-qp_default_qos-policy1", baseDn)

	rule_1_0 := apicapi.NewQosRequirement(qr1SDnE, "0")
	rule_1_1 := apicapi.NewQosDppPol(rule_1_0.GetDn(), "egress")
	rule_1_0.AddChild(apicapi.NewRsEgressDppPol(rule_1_0.GetDn(), rule_1_1.GetDn()))
	rule_1_0.AddChild(apicapi.NewQosEpDscpMarking(rule_1_0.GetDn(), "EpDscpMarking"))

	baseDn = makeQr(nil, nil, name, 1000, 1000, 1000, 1000, 0).GetDn()
	qr1SDnIE := fmt.Sprintf("%s/qosreq-qp_default_qos-policy1", baseDn)
	rule_2_0 := apicapi.NewQosRequirement(qr1SDnIE, "0")
	rule_2_1 := apicapi.NewQosDppPol(rule_2_0.GetDn(), "ingress")
	rule_2_2 := apicapi.NewQosDppPol(rule_2_0.GetDn(), "egress")
	rule_2_0.AddChild(apicapi.NewRsIngressDppPol(rule_2_0.GetDn(), rule_2_1.GetDn()))
	rule_2_0.AddChild(apicapi.NewRsEgressDppPol(rule_2_0.GetDn(), rule_2_2.GetDn()))
	rule_2_0.AddChild(apicapi.NewQosEpDscpMarking(rule_2_0.GetDn(), "EpDscpMarking"))

	labels := map[string]string{
		"lab_key1": "lab_value1"}

	var qrTests = []qrTest{
		{testqospolicy("testns", "qr1",
			ingress0, egress0, dscpmark, labels),
			makeQr(apicapi.ApicSlice{rule_0_0}, nil, name, 1000, 1000, 0, 0, 1),
			nil, ""},
		{testqospolicy("testns", "qr1",
			ingress1, egress1, dscpmark, labels),
			makeQr(nil, apicapi.ApicSlice{rule_1_0}, name, 0, 0, 1000, 1000, 1),
			nil, ""},
		{testqospolicy("testns", "qr1",
			ingress2, egress2, dscpmark, labels),
			makeQr(apicapi.ApicSlice{rule_2_0}, apicapi.ApicSlice{rule_2_0},
				name, 1000, 1000, 1000, 1000, 1), nil, ""},
		{testqospolicy("testns", "qr1",
			ingress3, egress3, dscpmark, labels),
			makeQr(nil, nil, name, 0, 0, 0, 0, 1), nil, ""},
	}
	initCont := func() *testAciController {
		cont := testController()
		cont.config.AciPolicyTenant = "test-tenant_qos"
		cont.config.NodeServiceIpPool = []ipam.IpRange{
			{Start: net.ParseIP("10.1.1.2"), End: net.ParseIP("10.1.1.3")},
		}
		cont.config.PodIpPool = []ipam.IpRange{
			{Start: net.ParseIP("10.1.1.2"), End: net.ParseIP("10.1.255.254")},
		}
		cont.AciController.initIpam()

		cont.fakeNamespaceSource.Add(namespaceLabel("testns_qos",
			map[string]string{"test": "testv"}))
		cont.fakeNamespaceSource.Add(namespaceLabel("ns1_qos",
			map[string]string{"nl_qos": "nv_qos"}))
		cont.fakeNamespaceSource.Add(namespaceLabel("ns2_qos",
			map[string]string{"nl_qos": "nv_qos"}))

		return cont
	}
	ips := []string{
		"1.1.1.1", "1.1.1.2", "1.1.1.3", "1.1.1.4", "1.1.1.5", "",
	}

	for _, qt := range qrTests {
		cont := initCont()
		cont.log.Info("Starting podsfirst ", qt.desc)
		addPods(cont, true, ips, true)
		addQosServices(cont, qt.augment)
		cont.run()
		cont.fakeQosPolicySource.Add(qt.qosPol)
		actual := qt.aciObj
		expected := cont.qosPolUpdate(qt.qosPol)
		assert.Equal(t, actual, expected)

		cont.log.Info("Starting delete ", qt.desc)
		cont.fakeQosPolicySource.Delete(qt.qosPol)
		checkDeleteQr(t, qrTests[0], cont)
		cont.stop()
	}
}
