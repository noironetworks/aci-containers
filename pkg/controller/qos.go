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

type ContPolicingType struct {
	PolicingRate int      `json:"policing_rate"`
        PolicingBurst int     `json:"policing_burst"`
}


type ContQosPolicy struct {
        Selector          ContPodSelector
        Ingress           ContPolicingType
        Egress            ContPolicingType
}

func QosPolicyLogger(log *logrus.Logger, qos *qospolicy.QosPolicy) *logrus.Entry {
        return log.WithFields(logrus.Fields{
                "namespace": qos.ObjectMeta.Namespace,
                "name":      qos.ObjectMeta.Name,
                "spec":      qos.Spec,
        })
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
                                cont.qosPolicyDelete(obj)
                        },
                },
                cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
        )
        cont.log.Debug("Initializing Qos Policy Informers")

}

func (cont *AciController) qosPolicyUpdated(obj interface{}) {
	qosPolicy := obj.(*qospolicy.QosPolicy)
        key, err := cache.MetaNamespaceKeyFunc(qosPolicy)
        if err != nil {
                QosPolicyLogger(cont.log, qosPolicy).
                        Error("Could not create key:" + err.Error())
                return
        }
        cont.queueQosUpdateByKey(key)

}

func (cont *AciController) queueQosUpdateByKey(key string) {
        cont.qosQueue.Add(key)
}

func (cont *AciController) qosPolicyDelete(qosobj interface{}) {
	qr := qosobj.(*qospolicy.QosPolicy)
        qrkey, err := cache.MetaNamespaceKeyFunc(qr)

	if err != nil {
                QosPolicyLogger(cont.log, qr).
                        Error("Could not create qos policy key: ", err)
                return
        }

	cont.apicConn.ClearApicObjects(cont.aciNameForKey("qp", qrkey))

}

func (cont *AciController) handleQosPolUpdate(qp *qospolicy.QosPolicy) bool {
	key, err := cache.MetaNamespaceKeyFunc(qp)
        logger := QosPolicyLogger(cont.log, qp)
        if err != nil {
                logger.Error("Could not create qos policy key: ", err)
		return false
        }
        labelKey := cont.aciNameForKey("qp", key)
        qr := apicapi.NewQosRequirement(cont.config.AciPolicyTenant, labelKey)
	qrDn := qr.GetDn()
	apicSlice:= apicapi.ApicSlice{qr}

        // Generate ingress policies
        if qp.Spec.Ingress.PolicingRate != 0 && qp.Spec.Ingress.PolicingBurst != 0 {

		DppPolIngress:= apicapi.NewQosDppPol(cont.config.AciPolicyTenant, "ingress")
		DppPolIngress.SetAttr("rate", strconv.Itoa(qp.Spec.Ingress.PolicingRate))
                DppPolIngress.SetAttr("burst", strconv.Itoa(qp.Spec.Ingress.PolicingBurst))

		DppPolIngressDn := DppPolIngress.GetDn()
		RsIngressDppPol := apicapi.NewRsIngressDppPol(qrDn, DppPolIngressDn)
		qr.AddChild(RsIngressDppPol)
		apicSlice = append(apicSlice, DppPolIngress)
        }

	// Generate egress policies
	if qp.Spec.Egress.PolicingRate != 0 && qp.Spec.Egress.PolicingBurst != 0 {

	        DppPolEgress:= apicapi.NewQosDppPol(cont.config.AciPolicyTenant, "egress")
		DppPolEgress.SetAttr("rate", strconv.Itoa(qp.Spec.Egress.PolicingRate))
	        DppPolEgress.SetAttr("burst", strconv.Itoa(qp.Spec.Egress.PolicingBurst))

		DppPolEgressDn := DppPolEgress.GetDn()
		RsEgressDppPol := apicapi.NewRsEgressDppPol(qrDn, DppPolEgressDn)
                qr.AddChild(RsEgressDppPol)
		apicSlice = append(apicSlice, DppPolEgress)
	}

	cont.apicConn.WriteApicObjects(labelKey, apicSlice)

	return false

}
