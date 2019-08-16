package metrics_test

import (
	"bytes"
	"code.cloudfoundry.org/go-loggregator/metrics"
	"fmt"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/prometheus/common/expfmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/gogo/protobuf/proto"
	dto "github.com/prometheus/client_model/go"
)

var _ = Describe("PrometheusMetrics", func() {

	var (
		l *log.Logger
	)

	BeforeEach(func() {
		l = log.New(GinkgoWriter, "", log.LstdFlags)

		// This is needed because the prom registry will register
		// the /metrics route with the default http mux which is
		// global
		http.DefaultServeMux = new(http.ServeMux)
	})

	It("serves metrics on a prometheus endpoint", func() {
		r := metrics.NewRegistry(l, metrics.WithServer(0))

		c := r.NewCounter(
			"test_counter",
			metrics.WithMetricTags(map[string]string{"foo": "bar"}),
			metrics.WithHelpText("a counter help text for test_counter"),
		)

		g := r.NewGauge(
			"test_gauge",
			metrics.WithHelpText("a gauge help text for test_gauge"),
			metrics.WithMetricTags(map[string]string{"bar": "baz"}),
		)

		c.Add(10)
		g.Set(10)
		g.Add(1)

		Eventually(func() string { return getMetrics(r.Port()) }).Should(ContainSubstring(`test_counter{foo="bar"} 10`))
		Eventually(func() string { return getMetrics(r.Port()) }).Should(ContainSubstring("a counter help text for test_counter"))
		Eventually(func() string { return getMetrics(r.Port()) }).Should(ContainSubstring(`test_gauge{bar="baz"} 11`))
		Eventually(func() string { return getMetrics(r.Port()) }).Should(ContainSubstring("a gauge help text for test_gauge"))
	})

	It("accepts custom default tags", func() {
		ct := map[string]string{
			"tag": "custom",
		}

		r := metrics.NewRegistry(l, metrics.WithDefaultTags(ct), metrics.WithServer(0))

		r.NewCounter(
			"test_counter",
			metrics.WithHelpText("a counter help text for test_counter"),
		)

		r.NewGauge(
			"test_gauge",
			metrics.WithHelpText("a gauge help text for test_gauge"),
		)

		Eventually(func() string { return getMetrics(r.Port()) }).Should(And(
			ContainSubstring("test_counter"),
			ContainSubstring("test_gauge"),
		))

		metrics := getMetrics(r.Port())
		metricFamilies, err := new(expfmt.TextParser).TextToMetricFamilies(bytes.NewReader([]byte(metrics)))
		Expect(err).ToNot(HaveOccurred())

		for _, family := range metricFamilies {
			for _, metric := range family.GetMetric() {
				Expect(metric.Label).To(ContainElement(
					&dto.LabelPair{Name: proto.String("tag"), Value: proto.String("custom")},
				), fmt.Sprintf("family %s contained a metric without default tags", family.GetName()))
			}
		}
	})

	It("returns the metric when duplicate is created", func() {
		r := metrics.NewRegistry(l, metrics.WithServer(0))

		c := r.NewCounter("test_counter")
		c2 := r.NewCounter("test_counter")

		c.Add(1)
		c2.Add(2)

		Eventually(func() string {
			return getMetrics(r.Port())
		}).Should(ContainSubstring(`test_counter 3`))

		g := r.NewGauge("test_gauge")
		g2 := r.NewGauge("test_gauge")

		g.Add(1)
		g2.Add(2)

		Eventually(func() string {
			return getMetrics(r.Port())
		}).Should(ContainSubstring(`test_gauge 3`))
	})

	It("panics if the metric is invalid", func() {
		r := metrics.NewRegistry(l)

		Expect(func() {
			r.NewCounter("test-counter")
		}).To(Panic())

		Expect(func() {
			r.NewGauge("test-counter")
		}).To(Panic())
	})
})

func getMetrics(port string) string {
	addr := fmt.Sprintf("http://127.0.0.1:%s/metrics", port)
	resp, err := http.Get(addr)
	if err != nil {
		return ""
	}

	respBytes, err := ioutil.ReadAll(resp.Body)
	Expect(err).ToNot(HaveOccurred())

	return string(respBytes)
}
