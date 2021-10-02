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
	"strconv"

	"github.com/sirupsen/logrus"

	qospolicy "github.com/noironetworks/aci-containers/pkg/qospolicy/apis/aci.qos/v1"
	qosclientset "github.com/noironetworks/aci-containers/pkg/qospolicy/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/tools/cache"

	"github.com/noironetworks/aci-containers/pkg/apicapi"
)

func QosPolicyLogger(log *logrus.Logger, qos *qospolicy.QosPolicy) *logrus.Entry {
	return log.WithFields(logrus.Fields{
		"namespace": qos.ObjectMeta.Namespace,
		"name":      qos.ObjectMeta.Name,
		"spec":      qos.Spec,
	})
}

func qosInit(cont *AciController, stopCh <-chan struct{}) {
	cont.log.Debug("Initializing qos client")
	restconfig := cont.env.RESTConfig()
	qosClient, err := qosclientset.NewForConfig(restconfig)
	if err != nil {
		cont.log.Errorf("Failed to intialize qos client")
		return
	}
	cont.initQosInformerFromClient(qosClient)
	go cont.qosInformer.Run(stopCh)
	go cont.processQueue(cont.qosQueue, cont.qosIndexer,
		func(obj interface{}) bool {
			return cont.handleQosPolUpdate(obj)
		}, nil, stopCh)
	cache.WaitForCacheSync(stopCh, cont.qosInformer.HasSynced)
}

func (cont *AciController) initQosInformerFromClient(
	qosClient *qosclientset.Clientset) {
	cont.initQosInformerBase(
		cache.NewListWatchFromClient(
			qosClient.AciV1().RESTClient(), "qospolicies",
			metav1.NamespaceAll, fields.Everything()))
}

func (cont *AciController) initQosInformerBase(listWatch *cache.ListWatch) {
	cont.qosIndexer, cont.qosInformer = cache.NewIndexerInformer(
		listWatch,
		&qospolicy.QosPolicy{}, 0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				cont.qosPolicyUpdated(obj)
			},
			UpdateFunc: func(_, obj interface{}) {
				cont.qosPolicyUpdated(obj)
			},
			DeleteFunc: func(obj interface{}) {
				cont.qosPolicyDeleted(obj)
			},
		},
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	cont.log.Debug("Initializing Qos Policy Informers")

}

func (cont *AciController) qosPolicyUpdated(obj interface{}) {
	qosPolicy, ok := obj.(*qospolicy.QosPolicy)
	if !ok {
		cont.log.Error("qosPolicyUpdated: Bad object type")
		return
	}
	key, err := cache.MetaNamespaceKeyFunc(qosPolicy)
	if err != nil {
		QosPolicyLogger(cont.log, qosPolicy).
			Error("Could not create key:" + err.Error())
		return
	}
	cont.queueQosUpdateByKey(key)
	cont.log.Infof("qos policy updated: %s", qosPolicy.ObjectMeta.Name)

}

func (cont *AciController) queueQosUpdateByKey(key string) {
	cont.qosQueue.Add(key)
}

func (cont *AciController) qosPolicyDeleted(qosobj interface{}) {
	qr, isQr := qosobj.(*qospolicy.QosPolicy)
	if !isQr {
		deletedState, ok := qosobj.(cache.DeletedFinalStateUnknown)
		if !ok {
			QosPolicyLogger(cont.log, qr).
				Error("Received unexpected object: ", qosobj)
			return
		}
		qr, ok = deletedState.Obj.(*qospolicy.QosPolicy)
		if !ok {
			QosPolicyLogger(cont.log, qr).
				Error("DeletedFinalStateUnknown contained non-qos object: ", deletedState.Obj)
			return
		}
	}
	qrkey, err := cache.MetaNamespaceKeyFunc(qr)
	if err != nil {
		QosPolicyLogger(cont.log, qr).
			Error("Could not create qos policy key: ", err)
		return
	}

	cont.apicConn.ClearApicObjects(cont.aciNameForKey("qp", qrkey))

}

func (cont *AciController) handleQosPolUpdate(obj interface{}) bool {

	// Ability to configure Qos Policy is available only in APIC versions >= 5.1(x).
	if apicapi.ApicVersion < "5.1" {
		cont.log.Error("Cannot create Qos Policy in APIC versions < 5.1(x). Actual APIC version: ",
			apicapi.ApicVersion)
		return false
	}

	qp, ok := obj.(*qospolicy.QosPolicy)
	if !ok {
		cont.log.Error("handleQosPolUpdate: Bad object type")
		return false
	}
	logger := QosPolicyLogger(cont.log, qp)
	key, err := cache.MetaNamespaceKeyFunc(qp)
	if err != nil {
		logger.Error("Could not create qos policy key: ", err)
		return false
	}
	labelKey := cont.aciNameForKey("qp", key)
	cont.log.Infof("Creating qos policy: %s", qp.ObjectMeta.Name)
	qr := apicapi.NewQosRequirement(cont.config.AciPolicyTenant, labelKey)
	qrDn := qr.GetDn()
	apicSlice := apicapi.ApicSlice{qr}

	DscpMarking := apicapi.NewQosEpDscpMarking(qrDn, "EpDscpMarking")
	DscpMarking.SetAttr("mark", strconv.Itoa(qp.Spec.Mark))
	qr.AddChild(DscpMarking)

	// Generate ingress policies
	if qp.Spec.Ingress.PolicingRate != 0 && qp.Spec.Ingress.PolicingBurst != 0 {

		DppPolIngressName := labelKey + "_ingress"
		DppPolIngress := apicapi.NewQosDppPol(cont.config.AciPolicyTenant, DppPolIngressName)
		DppPolIngress.SetAttr("rate", strconv.Itoa(qp.Spec.Ingress.PolicingRate))
		DppPolIngress.SetAttr("rateUnit", "kilo")
		DppPolIngress.SetAttr("burst", strconv.Itoa(qp.Spec.Ingress.PolicingBurst))
		DppPolIngress.SetAttr("burstUnit", "kilo")

		RsIngressDppPol := apicapi.NewRsIngressDppPol(qrDn, DppPolIngressName)
		qr.AddChild(RsIngressDppPol)
		apicSlice = append(apicSlice, DppPolIngress)
	}

	// Generate egress policies
	if qp.Spec.Egress.PolicingRate != 0 && qp.Spec.Egress.PolicingBurst != 0 {

		DppPolEgressName := labelKey + "_egress"
		DppPolEgress := apicapi.NewQosDppPol(cont.config.AciPolicyTenant, DppPolEgressName)
		DppPolEgress.SetAttr("rate", strconv.Itoa(qp.Spec.Egress.PolicingRate))
		DppPolEgress.SetAttr("rateUnit", "kilo")
		DppPolEgress.SetAttr("burst", strconv.Itoa(qp.Spec.Egress.PolicingBurst))
		DppPolEgress.SetAttr("burstUnit", "kilo")

		RsEgressDppPol := apicapi.NewRsEgressDppPol(qrDn, DppPolEgressName)
		qr.AddChild(RsEgressDppPol)
		apicSlice = append(apicSlice, DppPolEgress)
	}
	cont.log.Info("qos APIC slice: ", apicSlice)
	cont.apicConn.WriteApicObjects(labelKey, apicSlice)

	return false

}
