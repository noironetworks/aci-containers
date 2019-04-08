package jointlock_test

import (
	"errors"
	"os"
	"time"

	"code.cloudfoundry.org/clock/fakeclock"
	"code.cloudfoundry.org/locket/jointlock"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/tedsuo/ifrit"
	"github.com/tedsuo/ifrit/fake_runner"
	"github.com/tedsuo/ifrit/ginkgomon"
	"github.com/tedsuo/ifrit/grouper"
)

var _ = Describe("TimeoutRunner", func() {
	var (
		fakeClock      *fakeclock.FakeClock
		testRunner     *fake_runner.TestRunner
		timeout        time.Duration
		timeoutProcess ifrit.Process
		timeoutRunner  ifrit.Runner
	)

	BeforeEach(func() {
		fakeClock = fakeclock.NewFakeClock(time.Now())
		timeout = 10 * time.Second
		testRunner = fake_runner.NewTestRunner()
		timeoutRunner = jointlock.NewTimeoutRunner(
			fakeClock,
			timeout,
			grouper.Member{"test", testRunner},
		)
	})

	JustBeforeEach(func() {
		timeoutProcess = ifrit.Background(timeoutRunner)
	})

	AfterEach(func() {
		testRunner.EnsureExit()
		ginkgomon.Interrupt(timeoutProcess)
	})

	It("starts the runner", func() {
		Consistently(timeoutProcess.Ready()).ShouldNot(BeClosed())
		testRunner.TriggerReady()
		Eventually(timeoutProcess.Ready()).Should(BeClosed())
		Expect(testRunner.RunCallCount()).To(Equal(1))
	})

	It("waits for the runner to exit", func() {
		testRunner.TriggerReady()
		Eventually(timeoutProcess.Ready()).Should(BeClosed())
		Consistently(timeoutProcess.Wait()).ShouldNot(Receive())
	})

	Context("when the runner takes longer than the timeout to be ready", func() {
		It("returns an error", func() {
			Consistently(timeoutProcess.Ready()).ShouldNot(BeClosed())
			fakeClock.WaitForWatcherAndIncrement(timeout)
			Eventually(timeoutProcess.Wait()).Should(Receive(MatchError("test: failed to start in time")))
		})
	})

	Context("when the runner errors after becoming ready", func() {
		It("propagates the error", func() {
			testRunner.TriggerReady()
			Eventually(timeoutProcess.Ready()).Should(BeClosed())
			Consistently(timeoutProcess.Wait()).ShouldNot(Receive())
			expectedErr := errors.New("boom")
			testRunner.TriggerExit(expectedErr)
			Eventually(timeoutProcess.Wait()).Should(Receive(Equal(expectedErr)))
		})
	})

	Context("when the runner errors before becoming ready", func() {
		It("propagates the error", func() {
			Consistently(timeoutProcess.Wait()).ShouldNot(Receive())
			expectedErr := errors.New("boom")
			testRunner.TriggerExit(expectedErr)
			Eventually(timeoutProcess.Wait()).Should(Receive(Equal(expectedErr)))
		})
	})

	Context("when signalled before the runner is ready", func() {
		It("propagates the signal and continues waiting on the runner", func() {
			Eventually(testRunner.RunCallCount).Should(Equal(1))
			signals, _ := testRunner.RunArgsForCall(0)
			timeoutProcess.Signal(os.Kill)
			Eventually(signals).Should(Receive(Equal(os.Kill)))
		})

		It("continues to respect the timeout", func() {
			timeoutProcess.Signal(os.Kill)
			fakeClock.WaitForWatcherAndIncrement(timeout)
			Eventually(timeoutProcess.Wait()).Should(Receive(MatchError("test: failed to start in time")))
		})
	})

	Context("when the process is signalled", func() {
		It("propagates the signal to the runner and waits for it to exit", func() {
			testRunner.TriggerReady()
			Eventually(timeoutProcess.Ready()).Should(BeClosed())
			Consistently(timeoutProcess.Wait()).ShouldNot(Receive())

			Eventually(testRunner.RunCallCount).Should(Equal(1))
			signals, _ := testRunner.RunArgsForCall(0)
			timeoutProcess.Signal(os.Kill)
			Eventually(signals).Should(Receive(Equal(os.Kill)))
		})
	})

	Context("when the process exits successfuly before becoming ready", func() {
		It("exits", func() {
			Consistently(timeoutProcess.Wait()).ShouldNot(Receive())
			testRunner.TriggerExit(nil)
			Eventually(timeoutProcess.Wait()).Should(Receive(BeNil()))
		})
	})
})
