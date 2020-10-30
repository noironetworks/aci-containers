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
	"github.com/sirupsen/logrus"

	metricspolicy "github.com/noironetworks/aci-containers/pkg/metricspolicy/apis/aci.metrics/v1alpha"
	metricsclientset "github.com/noironetworks/aci-containers/pkg/metricspolicy/clientset/versioned"
	"github.com/noironetworks/metrics-poc/metrics"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/tools/cache"
)

const (
	metricsCRDName = "metricspolicies.aci.metrics"
)

// MetricsPolicyLogger Log MetricsPolicy using logrus
func MetricsPolicyLogger(log *logrus.Logger, metrics *metricspolicy.MetricsPolicy) *logrus.Entry {
	return log.WithFields(logrus.Fields{
		"namespace": metrics.ObjectMeta.Namespace,
		"name":      metrics.ObjectMeta.Name,
		"spec":      metrics.Spec,
	})
}

func metricsInit(cont *AciController, stopCh <-chan struct{}) {
	cont.log.Debug("Initializing metrics client")
	restconfig := cont.env.RESTConfig()
	metricsClient, err := metricsclientset.NewForConfig(restconfig)
	if err != nil {
		cont.log.Errorf("Failed to intialize metrics client")
		return
	}
	cont.initMetricsInformerFromClient(metricsClient)
	cont.metricsInformer.Run(stopCh)
}

func (cont *AciController) initMetricsInformerFromClient(
	metricsClient *metricsclientset.Clientset) {
	cont.initMetricsInformerBase(
		cache.NewListWatchFromClient(
			metricsClient.AciV1alpha().RESTClient(), "metricspolicies",
			metav1.NamespaceAll, fields.Everything()))
}

func (cont *AciController) initMetricsInformerBase(listWatch *cache.ListWatch) {
	cont.metricsIndexer, cont.metricsInformer = cache.NewIndexerInformer(
		listWatch,
		&metricspolicy.MetricsPolicy{}, 0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				cont.metricsPolicyUpdated(obj)
			},
			UpdateFunc: func(_, obj interface{}) {
				cont.metricsPolicyUpdated(obj)
			},
			DeleteFunc: func(obj interface{}) {
				cont.metricsPolicyDelete(obj)
			},
		},
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	cont.log.Debug("Initializing Metrics Policy Informers")

}

func (cont *AciController) metricsPolicyUpdated(obj interface{}) {
	mp := obj.(*metricspolicy.MetricsPolicy)
	cont.queueMetricsUpdate(mp)
}

func (cont *AciController) queueMetricsUpdate(metricspolicy *metricspolicy.MetricsPolicy) {
	key, err := cache.MetaNamespaceKeyFunc(metricspolicy)
	if err != nil {
		MetricsPolicyLogger(cont.log, metricspolicy).
			Error("Could not create key:" + err.Error())
		return
	}
	cont.metricsQueue.Add(key)
}

func (cont *AciController) metricsPolicyDelete(obj interface{}) {
	mp, isMP := obj.(*metricspolicy.MetricsPolicy)
	if !isMP {
		deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			MetricsPolicyLogger(cont.log, mp).
				Errorln("Received unexpected object: ", obj)
			return
		}
		mp, ok = deletedState.Obj.(*metricspolicy.MetricsPolicy)
		if !ok {
			MetricsPolicyLogger(cont.log, mp).
				Errorln("DeletedFinalStateUnknown contained non-metrics object: ", deletedState.Obj)
			return
		}
	}
	logger := MetricsPolicyLogger(cont.log, mp)
	logger.Infoln("Received metricspolicy delete")

	// Stop metrics package since MetricsPolicy is deleted
	metrics.Update([]string{}, "", 0)
}

func (cont *AciController) handleMetricsPolUpdate(obj interface{}) bool {
	mp, ok := obj.(*metricspolicy.MetricsPolicy)
	if !ok {
		cont.log.Error("handleMetricsPolUpdate: Bad object type")
		return false
	}
	logger := MetricsPolicyLogger(cont.log, mp)
	logger.Infoln("Received metrics policy")

	brokers := mp.Spec.MetricsPolicy.KafkaBrokerAddr
	exporter := mp.Spec.MetricsPolicy.PromServerAddr
	interval := mp.Spec.MetricsPolicy.ScrapeInterval

	cont.log.Debugf("received metricspolicy  brokers: %v prom: %v interval: %v\n", brokers, exporter, interval)
	metrics.Update(brokers, exporter, int16(interval))
	return false

}
