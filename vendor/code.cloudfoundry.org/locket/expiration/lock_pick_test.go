package expiration_test

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	"code.cloudfoundry.org/clock/fakeclock"
	mfakes "code.cloudfoundry.org/diego-logging-client/testhelpers"
	"code.cloudfoundry.org/lager"
	"code.cloudfoundry.org/lager/lagertest"
	"code.cloudfoundry.org/locket/db"
	"code.cloudfoundry.org/locket/db/dbfakes"
	"code.cloudfoundry.org/locket/expiration"
	"code.cloudfoundry.org/locket/models"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
)

var _ = Describe("LockPick", func() {
	var (
		lockPick expiration.LockPick

		logger           *lagertest.TestLogger
		fakeLockDB       *dbfakes.FakeLockDB
		fakeClock        *fakeclock.FakeClock
		fakeMetronClient *mfakes.FakeIngressClient

		ttl time.Duration

		lock, presence *db.Lock
	)

	BeforeEach(func() {
		lock = &db.Lock{
			Resource: &models.Resource{
				Key:   "funky",
				Owner: "town",
				Value: "won't you take me to",
				Type:  models.LockType,
			},
			TtlInSeconds:  25,
			ModifiedIndex: 6,
			ModifiedId:    "guid",
		}

		presence = &db.Lock{
			Resource: &models.Resource{
				Key:   "funky-presence",
				Owner: "town-presence",
				Value: "please dont take me",
				Type:  models.PresenceType,
			},
			TtlInSeconds:  25,
			ModifiedIndex: 6,
			ModifiedId:    "guid",
		}

		ttl = time.Duration(lock.TtlInSeconds) * time.Second

		fakeClock = fakeclock.NewFakeClock(time.Now())
		logger = lagertest.NewTestLogger("lock-pick")
		fakeLockDB = &dbfakes.FakeLockDB{}
		fakeMetronClient = new(mfakes.FakeIngressClient)

		lockPick = expiration.NewLockPick(fakeLockDB, fakeClock, fakeMetronClient)
	})

	Context("RegisterTTL", func() {
		BeforeEach(func() {
			fakeLockDB.FetchAndReleaseReturns(true, nil)
		})

		It("checks that the lock expires after the ttl", func() {
			lockPick.RegisterTTL(logger, lock)

			fakeClock.WaitForWatcherAndIncrement(ttl)

			Eventually(fakeLockDB.FetchAndReleaseCallCount).Should(Equal(1))
			_, _, oldLock := fakeLockDB.FetchAndReleaseArgsForCall(0)
			Expect(lock).To(Equal(oldLock))
		})

		It("increments the count for lock expiration", func() {
			lockPick.RegisterTTL(logger, lock)
			fakeClock.WaitForNWatchersAndIncrement(ttl, 1)

			Eventually(func() uint32 {
				locksExpired, _ := lockPick.ExpirationCounts()
				return locksExpired
			}).Should(BeEquivalentTo(1))
		})

		It("increments the count for presence expiration", func() {
			lockPick.RegisterTTL(logger, presence)
			fakeClock.WaitForNWatchersAndIncrement(ttl, 1)

			Eventually(func() uint32 {
				_, presencesExpired := lockPick.ExpirationCounts()
				return presencesExpired
			}).Should(BeEquivalentTo(1))
		})

		It("logs the type of the lock", func() {
			lockPick.RegisterTTL(logger, lock)
			Eventually(logger.Buffer()).Should(gbytes.Say("\"type\":\"lock\""))
		})

		It("logs the type of the presence", func() {
			lockPick.RegisterTTL(logger, presence)
			Eventually(logger.Buffer()).Should(gbytes.Say("\"type\":\"presence\""))
		})

		Context("when comparing and releasing the lock fails", func() {
			BeforeEach(func() {
				fakeLockDB.FetchAndReleaseReturns(false, errors.New("failed-to-fetch-lock"))
			})

			It("logs the error", func() {
				lockPick.RegisterTTL(logger, lock)

				fakeClock.WaitForWatcherAndIncrement(ttl)

				Eventually(fakeLockDB.FetchAndReleaseCallCount).Should(Equal(1))
				Eventually(logger.Buffer()).Should(gbytes.Say("failed-compare-and-release"))
			})
		})

		Context("when there is already a check process running", func() {
			BeforeEach(func() {
				lockPick.RegisterTTL(logger, lock)
				Eventually(fakeClock.WatcherCount).Should(Equal(1))
			})

			Context("and the lock id is the same", func() {
				Context("and the lock index is incremented", func() {
					var returnedLock *db.Lock
					BeforeEach(func() {
						returnedLock = &db.Lock{
							Resource: &models.Resource{
								Key:   "funky",
								Owner: "town",
								Value: "won't you take me to",
							},
							TtlInSeconds:  lock.TtlInSeconds,
							ModifiedIndex: 7,
							ModifiedId:    "guid",
						}
					})

					It("cancels the existing check and adds a new one", func() {
						lockPick.RegisterTTL(logger, returnedLock)

						Eventually(fakeClock.WatcherCount).Should(Equal(2))
						Consistently(fakeClock.WatcherCount).Should(Equal(2))
						fakeClock.WaitForWatcherAndIncrement(ttl)

						Eventually(logger).Should(gbytes.Say("cancelling-old-check"))

						Eventually(fakeLockDB.FetchAndReleaseCallCount).Should(Equal(1))
						Consistently(fakeLockDB.FetchAndReleaseCallCount).Should(Equal(1))
						_, _, lock := fakeLockDB.FetchAndReleaseArgsForCall(0)
						Expect(lock).To(Equal(returnedLock))
					})
				})

				Context("and competes with a newer lock on checking expiry", func() {
					var thirdLock db.Lock
					var trigger uint32

					BeforeEach(func() {
						newLock := *lock
						newLock.ModifiedIndex += 1

						thirdLock = newLock
						thirdLock.ModifiedIndex += 1

						trigger = 1
						fakeLockDB.FetchAndReleaseStub = func(ctx context.Context, logger lager.Logger, lock *db.Lock) (bool, error) {
							if atomic.LoadUint32(&trigger) != 0 {
								// second expiry goroutine
								lockPick.RegisterTTL(logger, &newLock)
							}
							atomic.StoreUint32(&trigger, 0)

							return true, nil
						}
					})

					It("checks the expiration of the lock twice", func() {
						// first expiry goroutine proceeds into timer case statement
						fakeClock.WaitForWatcherAndIncrement(ttl)
						Eventually(fakeLockDB.FetchAndReleaseCallCount).Should(Equal(1))
						Eventually(func() uint32 {
							return atomic.LoadUint32(&trigger)
						}).Should(BeEquivalentTo(0))

						// third expiry goroutine, cancels the second expiry goroutine
						lockPick.RegisterTTL(logger, &thirdLock)

						Eventually(fakeClock.WatcherCount).Should(Equal(2))
						fakeClock.WaitForWatcherAndIncrement(ttl)

						Eventually(fakeLockDB.FetchAndReleaseCallCount).Should(Equal(2))
						Consistently(fakeLockDB.FetchAndReleaseCallCount).Should(Equal(2))
					})
				})

				Context("when registering same lock", func() {
					It("does nothing", func() {
						lockPick.RegisterTTL(logger, lock)
						Eventually(logger).Should(gbytes.Say("found-expiration-goroutine"))
					})
				})

				Context("when registering an older lock", func() {
					var oldLock db.Lock

					BeforeEach(func() {
						oldLock = *lock
						oldLock.ModifiedIndex -= 1
					})

					It("does nothing", func() {
						l := oldLock
						lockPick.RegisterTTL(logger, &l)
						Eventually(logger).Should(gbytes.Say("found-expiration-goroutine"))
					})

					Context("and the previous lock has already expired", func() {
						BeforeEach(func() {
							fakeClock.WaitForWatcherAndIncrement(ttl)
							Eventually(fakeLockDB.FetchAndReleaseCallCount).Should(Equal(1))
						})

						It("checks the expiration of the lock", func() {
							l := oldLock
							lockPick.RegisterTTL(logger, &l)
							Eventually(fakeClock.WatcherCount).Should(Equal(1))
							fakeClock.WaitForWatcherAndIncrement(ttl)

							Eventually(fakeLockDB.FetchAndReleaseCallCount).Should(Equal(2))
							_, _, lock := fakeLockDB.FetchAndReleaseArgsForCall(1)
							Expect(lock).To(Equal(&l))
						})
					})
				})
			})

			Context("when the same lock is registered with a different id", func() {
				var newLock db.Lock

				BeforeEach(func() {
					newLock = *lock
					newLock.ModifiedId = "new-guid"
				})

				It("does not effect the other check goroutines", func() {
					lockPick.RegisterTTL(logger, &newLock)

					Eventually(fakeClock.WatcherCount).Should(Equal(2))
					Consistently(fakeClock.WatcherCount).Should(Equal(2))

					fakeClock.WaitForWatcherAndIncrement(ttl)

					Eventually(fakeLockDB.FetchAndReleaseCallCount).Should(Equal(2))
				})
			})

			Context("when another lock is registered", func() {
				var anotherLock, newLock db.Lock
				BeforeEach(func() {
					anotherLock = db.Lock{
						Resource: &models.Resource{
							Key:   "another",
							Owner: "myself",
							Value: "hi",
						},
						TtlInSeconds:  lock.TtlInSeconds,
						ModifiedIndex: 9,
					}

					newLock = *lock
					newLock.ModifiedIndex += 1
				})

				It("does not effect the other check goroutines", func() {
					lockPick.RegisterTTL(logger, &anotherLock)

					Eventually(fakeClock.WatcherCount).Should(Equal(2))
					Consistently(fakeClock.WatcherCount).Should(Equal(2))

					lockPick.RegisterTTL(logger, &newLock)

					Eventually(fakeClock.WatcherCount).Should(Equal(3))
					fakeClock.WaitForWatcherAndIncrement(ttl)

					Eventually(fakeLockDB.FetchAndReleaseCallCount).Should(Equal(2))
					_, _, lock1 := fakeLockDB.FetchAndReleaseArgsForCall(0)
					_, _, lock2 := fakeLockDB.FetchAndReleaseArgsForCall(1)
					Expect([]*db.Lock{lock1, lock2}).To(ContainElement(&newLock))
					Expect([]*db.Lock{lock1, lock2}).To(ContainElement(&anotherLock))

					Consistently(fakeLockDB.FetchAndReleaseCallCount).Should(Equal(2))
				})
			})

			Context("and the check process finishes", func() {
				BeforeEach(func() {
					fakeClock.WaitForWatcherAndIncrement(ttl)

					Eventually(fakeLockDB.FetchAndReleaseCallCount).Should(Equal(1))
					Consistently(fakeLockDB.FetchAndReleaseCallCount).Should(Equal(1))
					_, _, l := fakeLockDB.FetchAndReleaseArgsForCall(0)
					Expect(l).To(Equal(lock))
				})

				It("performs the expiration check", func() {
					lockPick.RegisterTTL(logger, lock)

					Eventually(fakeClock.WatcherCount).Should(Equal(1))
					fakeClock.WaitForWatcherAndIncrement(ttl)

					Eventually(fakeLockDB.FetchAndReleaseCallCount).Should(Equal(2))
					Consistently(fakeLockDB.FetchAndReleaseCallCount).Should(Equal(2))
					_, _, l := fakeLockDB.FetchAndReleaseArgsForCall(1)
					Expect(l).To(Equal(lock))
				})
			})
		})
	})
})
