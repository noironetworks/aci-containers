/***
Copyright 2019 Cisco Systems Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
// Prometheus exporter

package metrics

import (
	"fmt"
	"net/http"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	ingressDir  = "ingress"
	egressDir   = "egress"
	destKey     = "to"
	destTypeKey = "destType"
	srcTypeKey  = "srcType"
	srcKey      = "from"
)

var podStatsDesc = prometheus.NewDesc("cluster_nw_stats", "k8s network stats", []string{"namespace", "deployment", "service", "cidr"}, nil)

func InitPromExporter(pso *PodStatsObj, mPort string) {
	reg := prometheus.NewRegistry()
	reg.MustRegister(pso)
	http.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	log.Fatal(http.ListenAndServe(mPort, nil))
}

func (pso *PodStatsObj) Describe(ch chan<- *prometheus.Desc) {
	ch <- podStatsDesc
}

func (pso *PodStatsObj) Collect(ch chan<- prometheus.Metric) {
	pso.Lock()
	defer pso.Unlock()
	for _, ps := range pso.PS {
		dirList := []string{ingressDir, egressDir}
		for _, dir := range dirList {
			pso.exportStats(dir, ps, ch)
		}
	}
}

func (pso *PodStatsObj) exportStats(dir string, stats *PodStatsType, ch chan<- prometheus.Metric) {
	var s map[Tuple][]StatsRec

	if dir == "ingress" {
		s = stats.Ingress
	} else {
		s = stats.Egress
	}

	for tuple, statsList := range s {
		labels := pso.getLabels(stats, tuple, dir)
		for _, stat := range statsList {
			items := []struct {
				value float64
				name  string
			}{
				{float64(stat.connections), "connections"},
				{float64(stat.packets), "packets"},
				{float64(stat.bytes), "bytes"},
			}
			for _, sItem := range items {
				desc := prometheus.NewDesc(fmt.Sprintf("%s_%s", dir, sItem.name), "", nil, labels)
				m, err := prometheus.NewConstMetric(desc, prometheus.GaugeValue, sItem.value)
				if err != nil {
					log.Errorf("NewConstMetric: %v", err)
					continue
				}
				ch <- prometheus.NewMetricWithTimestamp(stat.timestamp, m)
			}
		}
	}
}

func (pso *PodStatsObj) getLabels(stats *PodStatsType, tuple Tuple, dir string) map[string]string {
	l := make(map[string]string)
	for k, v := range stats.Labels {
		l[k] = v
	}

	if dir == egressDir {
		svc, ok := pso.ipToSvc[tuple.destIP]
		if ok {
			l[destKey] = svc
			l[destTypeKey] = "service"
		} else {
			l[destKey] = fmt.Sprintf("%s:%s", tuple.destIP, tuple.destPort)
			l[destTypeKey] = "cidr"
		}
	} else {
		svc, ok := pso.svcEPToSvc[tuple.srcIP]
		if ok {
			svcList := []string{}
			for sn := range svc {
				svcList = append(svcList, sn)
			}
			l[srcKey] = strings.Join(svcList, "|")
			l[srcTypeKey] = "service"
		} else {
			l[srcKey] = fmt.Sprintf("%s", tuple.srcIP)
			l[srcTypeKey] = "cidr"
		}
	}

	return l
}
