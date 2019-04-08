package metrics_test

import (
	"errors"
	"time"

	"code.cloudfoundry.org/clock/fakeclock"
	mfakes "code.cloudfoundry.org/diego-logging-client/testhelpers"
	loggregator "code.cloudfoundry.org/go-loggregator"
	"code.cloudfoundry.org/lager"
	"code.cloudfoundry.org/lager/lagertest"
	"code.cloudfoundry.org/locket/db/dbfakes"
	"code.cloudfoundry.org/locket/metrics"
	"code.cloudfoundry.org/locket/models"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/tedsuo/ifrit"
	"github.com/tedsuo/ifrit/ginkgomon"
)

var _ = Describe("LockMetrics", func() {
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
		lockDB           *dbfakes.FakeLockDB
		metricsChan      chan FakeGauge
	)

	BeforeEach(func() {
		logger = lagertest.NewTestLogger("metrics")
		fakeMetronClient = new(mfakes.FakeIngressClient)
		fakeClock = fakeclock.NewFakeClock(time.Now())
		metricsInterval = 10 * time.Second

		lockDB = &dbfakes.FakeLockDB{}

		lockDB.CountStub = func(l lager.Logger, lockType string) (int, error) {
			switch {
			case lockType == models.LockType:
				return 3, nil
			case lockType == models.PresenceType:
				return 2, nil
			default:
				return 0, errors.New("unknown type")
			}
		}

		metricsChan = make(chan FakeGauge, 100)

		ch := metricsChan
		fakeMetronClient.SendMetricStub = func(name string, value int, opts ...loggregator.EmitGaugeOption) error {
			defer GinkgoRecover()

			Eventually(ch).Should(BeSent(FakeGauge{name, value}))
			return nil
		}
	})

	JustBeforeEach(func() {
		runner = metrics.NewLockMetricsNotifier(
			logger,
			fakeClock,
			fakeMetronClient,
			metricsInterval,
			lockDB,
		)
		process = ifrit.Background(runner)
		Eventually(process.Ready()).Should(BeClosed())
	})

	AfterEach(func() {
		ginkgomon.Interrupt(process)
	})

	Context("when there are no errors retrieving counts from database", func() {

		JustBeforeEach(func() {
			fakeClock.Increment(metricsInterval)
		})

		It("emits a metric for the number of active locks", func() {
			Eventually(metricsChan).Should(Receive(Equal(FakeGauge{"ActiveLocks", 3})))
			fakeClock.Increment(metricsInterval)
			Eventually(metricsChan).Should(Receive(Equal(FakeGauge{"ActiveLocks", 3})))
		})

		It("emits a metric for the number of active presences", func() {
			Eventually(metricsChan).Should(Receive(Equal(FakeGauge{"ActivePresences", 2})))
			fakeClock.Increment(metricsInterval)
			Eventually(metricsChan).Should(Receive(Equal(FakeGauge{"ActivePresences", 2})))
		})
	})

	Context("when there are errors retrieving counts from database", func() {
		BeforeEach(func() {
			lockDB.CountReturns(1, errors.New("DB error"))
		})

		JustBeforeEach(func() {
			fakeClock.Increment(metricsInterval)
		})

		It("does not emit any metrics", func() {
			Consistently(metricsChan).ShouldNot(Receive())
			fakeClock.Increment(metricsInterval)
			Consistently(metricsChan).ShouldNot(Receive())
		})
	})
})
