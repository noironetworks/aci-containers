package expiration_test

import (
	"errors"
	"time"

	"code.cloudfoundry.org/clock/fakeclock"
	mfakes "code.cloudfoundry.org/diego-logging-client/testhelpers"
	"code.cloudfoundry.org/lager/lagertest"
	"code.cloudfoundry.org/locket/db"
	"code.cloudfoundry.org/locket/db/dbfakes"
	"code.cloudfoundry.org/locket/expiration"
	"code.cloudfoundry.org/locket/expiration/expirationfakes"
	"code.cloudfoundry.org/locket/models"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
	"github.com/tedsuo/ifrit"
	"github.com/tedsuo/ifrit/ginkgomon"
)

var _ = Describe("Burglar", func() {
	var (
		runner  ifrit.Runner
		process ifrit.Process

		fakeLockDB   *dbfakes.FakeLockDB
		fakeLockPick *expirationfakes.FakeLockPick
		fakeClock    *fakeclock.FakeClock
		logger       *lagertest.TestLogger

		expectedLock1, expectedLock2 *db.Lock
		checkInterval                time.Duration
		fakeMetronClient             *mfakes.FakeIngressClient
	)

	BeforeEach(func() {
		fakeLockDB = &dbfakes.FakeLockDB{}
		fakeLockPick = &expirationfakes.FakeLockPick{}
		fakeClock = fakeclock.NewFakeClock(time.Now())
		logger = lagertest.NewTestLogger("expiration")

		expectedLock1 = &db.Lock{
			Resource: &models.Resource{
				Key:      "funky",
				Owner:    "town",
				Value:    "won't you take me to",
				Type:     "lock",
				TypeCode: models.LOCK,
			},
			TtlInSeconds:  25,
			ModifiedIndex: 3587584357348,
		}

		expectedLock2 = &db.Lock{
			Resource: &models.Resource{
				Key:      "clif",
				Owner:    "bar",
				Value:    "chocolate chip",
				Type:     "presence",
				TypeCode: models.PRESENCE,
			},
			TtlInSeconds:  437,
			ModifiedIndex: 2346,
		}

		checkInterval = 5 * time.Second

		fakeLockDB.FetchAllReturns([]*db.Lock{expectedLock1, expectedLock2}, nil)
		fakeMetronClient = new(mfakes.FakeIngressClient)
	})

	JustBeforeEach(func() {
		runner = expiration.NewBurglar(logger, fakeLockDB, fakeLockPick, fakeClock, checkInterval, fakeMetronClient)
		process = ifrit.Background(runner)
	})

	AfterEach(func() {
		ginkgomon.Interrupt(process)
	})

	It("fetches the list of locks and registers them with the lock pick", func() {
		Eventually(fakeLockDB.FetchAllCallCount).Should(Equal(1))
		_, lockType := fakeLockDB.FetchAllArgsForCall(0)
		Expect(lockType).To(Equal(""))

		Eventually(fakeLockPick.RegisterTTLCallCount).Should(Equal(2))
		_, lock := fakeLockPick.RegisterTTLArgsForCall(0)
		Expect(lock).To(Equal(expectedLock1))

		_, lock = fakeLockPick.RegisterTTLArgsForCall(1)
		Expect(lock).To(Equal(expectedLock2))

		Eventually(process.Ready()).Should(BeClosed())
	})

	It("continues to fetch locks and register them on an interval", func() {
		Eventually(fakeLockDB.FetchAllCallCount).Should(Equal(1))
		_, lockType := fakeLockDB.FetchAllArgsForCall(0)
		Expect(lockType).To(Equal(""))

		Eventually(fakeLockPick.RegisterTTLCallCount).Should(Equal(2))

		initialFetchAllCallCount := fakeLockDB.FetchAllCallCount()
		initialRegisterTTLCallCount := fakeLockPick.RegisterTTLCallCount()

		Eventually(process.Ready()).Should(BeClosed())

		fakeClock.Increment(checkInterval)
		Eventually(fakeLockDB.FetchAllCallCount).Should(Equal(initialFetchAllCallCount + 1))
		_, lockType = fakeLockDB.FetchAllArgsForCall(initialFetchAllCallCount + 1 - 1)
		Expect(lockType).To(Equal(""))
		Eventually(fakeLockPick.RegisterTTLCallCount).Should(Equal(initialRegisterTTLCallCount + 2))
	})

	It("periodically emits a counter metric showing the lock and presence haven't expired", func() {
		counter := 0
		fakeLockPick.ExpirationCountsStub = func() (uint32, uint32) {
			counter++
			return uint32(counter), uint32(counter)
		}

		for i := 0; i < 4; i++ {
			fakeClock.WaitForNWatchersAndIncrement(60*time.Second, 2)

			Eventually(fakeMetronClient.SendMetricCallCount).Should(BeEquivalentTo(2 * (i + 1)))
			metric, value, _ := fakeMetronClient.SendMetricArgsForCall(i * 2)
			Expect(metric).To(BeEquivalentTo("LocksExpired"))
			Expect(value).To(BeEquivalentTo(i + 1))

			metric, value, _ = fakeMetronClient.SendMetricArgsForCall(i*2 + 1)
			Expect(metric).To(BeEquivalentTo("PresenceExpired"))
			Expect(value).To(BeEquivalentTo(i + 1))

			// make sure the other case statement is executed
			Eventually(fakeLockDB.FetchAllCallCount).Should(Equal(i + 2))
		}
	})

	Context("when fetching the locks fails", func() {
		BeforeEach(func() {
			fakeLockDB.FetchAllReturns(nil, errors.New("we got the funk"))
		})

		It("logs the error and continues", func() {
			Eventually(fakeLockDB.FetchAllCallCount).Should(Equal(1))
			_, lockType := fakeLockDB.FetchAllArgsForCall(0)
			Expect(lockType).To(Equal(""))
			Eventually(process.Ready()).Should(BeClosed())
			Eventually(logger).Should(gbytes.Say("failed-fetching-locks"))

			fakeClock.Increment(checkInterval)
			Eventually(fakeLockDB.FetchAllCallCount).Should(Equal(2))
			_, lockType = fakeLockDB.FetchAllArgsForCall(1)
			Expect(lockType).To(Equal(""))
			Eventually(logger).Should(gbytes.Say("failed-fetching-locks"))
		})
	})
})
