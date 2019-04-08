package metrics_test

import (
	"time"

	"code.cloudfoundry.org/bbs/db/sqldb/helpers/helpersfakes"
	"code.cloudfoundry.org/bbs/db/sqldb/helpers/monitor/monitorfakes"
	"code.cloudfoundry.org/clock/fakeclock"
	mfakes "code.cloudfoundry.org/diego-logging-client/testhelpers"
	loggregator "code.cloudfoundry.org/go-loggregator"
	"code.cloudfoundry.org/lager/lagertest"
	"code.cloudfoundry.org/locket/metrics"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/tedsuo/ifrit"
	"github.com/tedsuo/ifrit/ginkgomon"
)

var _ = Describe("DBMetrics", func() {
	type FakeGauge struct {
		Name  string
		Value int
	}

	var (
		runner           ifrit.Runner
		process          ifrit.Process
		fakeMetronClient *mfakes.FakeIngressClient
		logger           *lagertest.TestLogger
		fakeClock        *fakeclock.FakeClock
		metricsInterval  time.Duration
		lockDB           *helpersfakes.FakeQueryableDB
		fakeMonitor      *monitorfakes.FakeMonitor
		metricsChan      chan FakeGauge
	)

	metricsChan = make(chan FakeGauge, 100)

	BeforeEach(func() {
		logger = lagertest.NewTestLogger("metrics")
		fakeMetronClient = new(mfakes.FakeIngressClient)
		fakeClock = fakeclock.NewFakeClock(time.Now())
		metricsInterval = 10 * time.Second

		lockDB = new(helpersfakes.FakeQueryableDB)
		fakeMonitor = new(monitorfakes.FakeMonitor)

		fakeMetronClient.SendMetricStub = func(name string, value int, opts ...loggregator.EmitGaugeOption) error {
			defer GinkgoRecover()

			Eventually(metricsChan).Should(BeSent(FakeGauge{name, value}))
			return nil
		}
		fakeMetronClient.SendDurationStub = func(name string, value time.Duration, opts ...loggregator.EmitGaugeOption) error {
			defer GinkgoRecover()

			Eventually(metricsChan).Should(BeSent(FakeGauge{name, int(value)}))
			return nil
		}

		lockDB.OpenConnectionsReturns(100)
		fakeMonitor.TotalReturns(105)
		fakeMonitor.SucceededReturns(90)
		fakeMonitor.FailedReturns(10)
		fakeMonitor.ReadAndResetInFlightMaxReturns(5)
		fakeMonitor.ReadAndResetDurationMaxReturns(time.Second)
	})

	JustBeforeEach(func() {
		runner = metrics.NewDBMetricsNotifier(
			logger,
			fakeClock,
			fakeMetronClient,
			metricsInterval,
			lockDB,
			fakeMonitor,
		)
		process = ifrit.Background(runner)
		Eventually(process.Ready()).Should(BeClosed())
		fakeClock.Increment(metricsInterval)
	})

	AfterEach(func() {
		ginkgomon.Interrupt(process)
	})

	It("emits a metric for the number of open database connections", func() {
		Eventually(metricsChan).Should(Receive(Equal(FakeGauge{"DBOpenConnections", 100})))
		fakeClock.Increment(metricsInterval)
		Eventually(metricsChan).Should(Receive(Equal(FakeGauge{"DBOpenConnections", 100})))
	})

	It("emits a metric for the number of total queries against the database", func() {
		Eventually(metricsChan).Should(Receive(Equal(FakeGauge{"DBQueriesTotal", 105})))
		fakeClock.Increment(metricsInterval)
		Eventually(metricsChan).Should(Receive(Equal(FakeGauge{"DBQueriesTotal", 105})))
	})

	It("emits a metric for the number of queries succeeded against the database", func() {
		Eventually(metricsChan).Should(Receive(Equal(FakeGauge{"DBQueriesSucceeded", 90})))
		fakeClock.Increment(metricsInterval)
		Eventually(metricsChan).Should(Receive(Equal(FakeGauge{"DBQueriesSucceeded", 90})))
	})

	It("emits a metric for the number of queries failed against the database", func() {
		Eventually(metricsChan).Should(Receive(Equal(FakeGauge{"DBQueriesFailed", 10})))
		fakeClock.Increment(metricsInterval)
		Eventually(metricsChan).Should(Receive(Equal(FakeGauge{"DBQueriesFailed", 10})))
	})

	It("emits a metric for the max number of queries in flight against the database", func() {
		Eventually(metricsChan).Should(Receive(Equal(FakeGauge{"DBQueriesInFlight", 5})))
		fakeClock.Increment(metricsInterval)
		Eventually(metricsChan).Should(Receive(Equal(FakeGauge{"DBQueriesInFlight", 5})))
	})

	It("emits a metric for the max duration of queries", func() {
		Eventually(metricsChan).Should(Receive(Equal(FakeGauge{"DBQueryDurationMax", int(time.Second)})))
		fakeClock.Increment(metricsInterval)
		Eventually(metricsChan).Should(Receive(Equal(FakeGauge{"DBQueryDurationMax", int(time.Second)})))
	})
})
