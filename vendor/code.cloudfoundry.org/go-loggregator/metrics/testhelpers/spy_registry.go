package testhelpers

import (
	"fmt"
	"sort"
	"sync"

	"code.cloudfoundry.org/go-loggregator/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

type SpyMetricsRegistry struct {
	mu      sync.Mutex
	Metrics map[string]*SpyMetric
}

func NewMetricsRegistry() *SpyMetricsRegistry {
	return &SpyMetricsRegistry{
		Metrics: make(map[string]*SpyMetric),
	}
}

func (s *SpyMetricsRegistry) NewCounter(name string, opts ...metrics.MetricOption) metrics.Counter {
	s.mu.Lock()
	defer s.mu.Unlock()

	m := newSpyMetric(name, opts)
	m = s.addMetric(m)

	return m
}

func (s *SpyMetricsRegistry) NewGauge(name string, opts ...metrics.MetricOption) metrics.Gauge {
	s.mu.Lock()
	defer s.mu.Unlock()

	m := newSpyMetric(name, opts)
	m = s.addMetric(m)

	return m
}

func (s *SpyMetricsRegistry) addMetric(sm *SpyMetric) *SpyMetric {
	n := getMetricName(sm.name, sm.Opts.ConstLabels)

	_, ok := s.Metrics[n]
	if !ok {
		s.Metrics[n] = sm
	}

	return s.Metrics[n]
}

func (s *SpyMetricsRegistry) GetMetric(name string, tags map[string]string) *SpyMetric {
	s.mu.Lock()
	defer s.mu.Unlock()

	n := getMetricName(name, tags)

	if m, ok := s.Metrics[n]; ok {
		return m
	}

	panic(fmt.Sprintf("unknown metric: %s", name))
}

// Returns -1 to signify no metric
func (s *SpyMetricsRegistry) GetMetricValue(name string, tags map[string]string) float64 {
	s.mu.Lock()
	defer s.mu.Unlock()

	n := getMetricName(name, tags)

	if m, ok := s.Metrics[n]; ok {
		return m.Value()
	}

	return -1
}

func (s *SpyMetricsRegistry) HasMetric(name string, tags map[string]string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	n := getMetricName(name, tags)
	_, ok := s.Metrics[n]
	return ok
}

func newSpyMetric(name string, opts []metrics.MetricOption) *SpyMetric {
	sm := &SpyMetric{
		name: name,
		Opts: &prometheus.Opts{
			ConstLabels: make(prometheus.Labels),
		},
	}

	for _, o := range opts {
		o(sm.Opts)
	}

	for k, _ := range sm.Opts.ConstLabels {
		sm.keys = append(sm.keys, k)
	}
	sort.Strings(sm.keys)

	return sm
}

type SpyMetric struct {
	mu    sync.Mutex
	value float64
	name  string

	keys []string
	Opts *prometheus.Opts
}

func (s *SpyMetric) Set(c float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.value = c
}

func (s *SpyMetric) Add(c float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.value += c
}

func (s *SpyMetric) Value() float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.value
}

func getMetricName(name string, tags map[string]string) string {
	n := name

	k := make([]string, len(tags))
	for t := range tags {
		k = append(k, t)
	}
	sort.Strings(k)

	for _, key := range k {
		n += fmt.Sprintf("%s_%s", key, tags[key])
	}

	return n
}
