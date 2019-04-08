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

var _ = Describe("Jointlock", func() {
	var (
		jointLock                ifrit.Runner
		jointLockProcess         ifrit.Process
		timeout                  time.Duration
		fakeClock                *fakeclock.FakeClock
		testRunner1, testRunner2 *fake_runner.TestRunner
	)

	BeforeEach(func() {
		timeout = 5 * time.Second
		fakeClock = fakeclock.NewFakeClock(time.Now())
		testRunner1 = fake_runner.NewTestRunner()
		testRunner2 = fake_runner.NewTestRunner()
	})

	JustBeforeEach(func() {
		jointLock = jointlock.NewJointLock(
			fakeClock,
			timeout,
			grouper.Member{"test1", testRunner1},
			grouper.Member{"test2", testRunner2},
		)
		jointLockProcess = ifrit.Background(jointLock)
	})

	AfterEach(func() {
		Eventually(testRunner1.RunCallCount).Should(Equal(1))
		testRunner1.EnsureExit()
		testRunner2.EnsureExit()
		ginkgomon.Interrupt(jointLockProcess)
	})

	It("starts both runners in serial", func() {
		Consistently(jointLockProcess.Ready()).ShouldNot(BeClosed())
		testRunner1.TriggerReady()
		Consistently(jointLockProcess.Ready()).ShouldNot(BeClosed())
		testRunner2.TriggerReady()
		Eventually(jointLockProcess.Ready()).Should(BeClosed())
		Consistently(jointLockProcess.Wait()).ShouldNot(Receive())

		Expect(testRunner1.RunCallCount()).To(Equal(1))
		Expect(testRunner2.RunCallCount()).To(Equal(1))
	})

	Context("when there are no runners", func() {
		It("blocks waiting for signal", func() {
			jointLock := jointlock.NewJointLock(fakeClock, timeout)
			process := ifrit.Background(jointLock)
			Eventually(process.Ready()).Should(BeClosed())
		})
	})

	Context("when the first runner fails to start", func() {
		It("propagates the error", func() {
			testRunner1.TriggerExit(errors.New("boom"))
			Eventually(jointLockProcess.Wait()).Should(Receive(HaveOccurred()))
		})
	})

	Context("when the second runner fails to start", func() {
		It("propagates the error", func() {
			Eventually(testRunner1.RunCallCount).Should(Equal(1))
			signals, _ := testRunner1.RunArgsForCall(0)
			testRunner1.TriggerReady()
			testRunner2.TriggerExit(errors.New("boom"))
			Eventually(signals).Should(Receive(Equal(os.Interrupt)))
			testRunner1.EnsureExit()
			Eventually(jointLockProcess.Wait()).Should(Receive(HaveOccurred()))
		})
	})

	Context("when the first runner takes longer than the timeout to be ready", func() {
		AfterEach(func() {
			testRunner1.TriggerReady()
			testRunner2.TriggerReady()
		})

		It("waits until the first runner is ready", func() {
			Consistently(jointLockProcess.Wait()).ShouldNot(Receive())
			fakeClock.Increment(timeout)
			Consistently(jointLockProcess.Wait()).ShouldNot(Receive())
		})
	})

	Context("when the second runner never becomes ready", func() {
		It("eventually times out and exits", func() {
			Eventually(testRunner1.RunCallCount).Should(Equal(1))
			signals, _ := testRunner1.RunArgsForCall(0)
			testRunner1.TriggerReady()
			Consistently(jointLockProcess.Wait()).ShouldNot(Receive())
			fakeClock.Increment(timeout)
			Eventually(signals).Should(Receive(Equal(os.Interrupt)))
			testRunner1.EnsureExit()
			Eventually(jointLockProcess.Wait()).Should(Receive(HaveOccurred()))
		})
	})
})
