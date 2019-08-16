package lockheldmetrics_test

import (
	"os"
	"time"

	"code.cloudfoundry.org/clock/fakeclock"
	mfakes "code.cloudfoundry.org/diego-logging-client/testhelpers"
	loggregator "code.cloudfoundry.org/go-loggregator"
	"code.cloudfoundry.org/lager/lagertest"
	"code.cloudfoundry.org/locket/lockheldmetrics"
	"github.com/tedsuo/ifrit"
	"github.com/tedsuo/ifrit/ginkgomon"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("PeriodicLockHeldNotifier", func() {
	type metric struct {
		name  string
		value int
	}

	var (
		fakeMetronClient *mfakes.FakeIngressClient
		metricsCh        chan metric

		reportInterval time.Duration
		fakeClock      *fakeclock.FakeClock

		mn  *lockheldmetrics.LockHeldMetronNotifier
		mnp ifrit.Process
	)

	BeforeEach(func() {
		metricsCh = make(chan metric, 10)
		fakeMetronClient = new(mfakes.FakeIngressClient)
		fakeMetronClient.SendMetricStub = func(name string, value int, opts ...loggregator.EmitGaugeOption) error {
			metricsCh <- metric{name, value}
			return nil
		}

		reportInterval = 100 * time.Millisecond

		fakeClock = fakeclock.NewFakeClock(time.Unix(123, 456))
	})

	JustBeforeEach(func() {
		ticker := fakeClock.NewTicker(reportInterval)
		mn = lockheldmetrics.NewLockHeldMetronNotifier(lagertest.NewTestLogger("test"), ticker, fakeMetronClient)
		mnp = ifrit.Invoke(mn)
	})

	AfterEach(func() {
		mnp.Signal(os.Interrupt)
		Eventually(mnp.Wait(), 2*time.Second).Should(Receive())
	})

	It("should emit a lock held gauge periodically", func() {
		mn.SetLock()
		fakeClock.WaitForWatcherAndIncrement(reportInterval)

		Eventually(metricsCh).Should(Receive(Equal(metric{"LockHeld", 1})))

		mn.UnsetLock()
		fakeClock.WaitForWatcherAndIncrement(reportInterval)

		Eventually(metricsCh).Should(Receive(Equal(metric{"LockHeld", 0})))
	})

	Describe("SetLockHeldRunner", func() {
		var setLockProcess ifrit.Process
		var setLockRunner ifrit.Runner

		JustBeforeEach(func() {
			setLockRunner = lockheldmetrics.SetLockHeldRunner(lagertest.NewTestLogger("test-set-lock-held-runner"), *mn)
		})

		AfterEach(func() {
			ginkgomon.Interrupt(setLockProcess)
		})

		It("returns an ifrit runner that sets the lock", func() {
			fakeClock.WaitForWatcherAndIncrement(reportInterval)
			Eventually(metricsCh).Should(Receive(Equal(metric{"LockHeld", 0})))

			setLockProcess = ifrit.Invoke(setLockRunner)
			fakeClock.WaitForWatcherAndIncrement(reportInterval)

			Eventually(metricsCh).Should(Receive(Equal(metric{"LockHeld", 1})))
		})
	})
})
