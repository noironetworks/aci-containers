package lock_test

import (
	"errors"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"

	"code.cloudfoundry.org/clock/fakeclock"
	"code.cloudfoundry.org/lager/lagertest"
	"code.cloudfoundry.org/locket"
	"code.cloudfoundry.org/locket/lock"
	"code.cloudfoundry.org/locket/models"
	"code.cloudfoundry.org/locket/models/modelsfakes"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
	"github.com/tedsuo/ifrit"
	"github.com/tedsuo/ifrit/ginkgomon"
	"golang.org/x/net/context"
)

var _ = Describe("Lock", func() {
	var (
		logger *lagertest.TestLogger

		fakeLocker *modelsfakes.FakeLocketClient
		fakeClock  *fakeclock.FakeClock

		expectedLock      *models.Resource
		expectedTTL       int64
		lockRetryInterval time.Duration

		lockRunner  ifrit.Runner
		lockProcess ifrit.Process
	)

	BeforeEach(func() {
		logger = lagertest.NewTestLogger("lock")

		fakeLocker = &modelsfakes.FakeLocketClient{}
		fakeClock = fakeclock.NewFakeClock(time.Now())

		lockRetryInterval = locket.RetryInterval
		expectedLock = &models.Resource{Key: "test", Owner: "jim", Value: "is pretty sweet."}
		expectedTTL = 5
	})

	Context("NewLockRunner", func() {
		BeforeEach(func() {
			lockRunner = lock.NewLockRunner(
				logger,
				fakeLocker,
				expectedLock,
				expectedTTL,
				fakeClock,
				lockRetryInterval,
			)
		})

		JustBeforeEach(func() {
			lockProcess = ifrit.Background(lockRunner)
		})

		AfterEach(func() {
			ginkgomon.Kill(lockProcess)
		})

		It("locks the key", func() {
			Eventually(lockProcess.Ready()).Should(BeClosed())
			Eventually(fakeLocker.LockCallCount).Should(Equal(1))
			_, lockReq, _ := fakeLocker.LockArgsForCall(0)
			Expect(lockReq.Resource).To(Equal(expectedLock))
			Expect(lockReq.TtlInSeconds).To(Equal(expectedTTL))
		})

		It("sets the request guid metadata", func() {
			Eventually(fakeLocker.LockCallCount).Should(Equal(1))
			ctx, _, _ := fakeLocker.LockArgsForCall(0)
			md, _ := metadata.FromOutgoingContext(ctx)
			Expect(md).To(HaveKey("uuid"))
		})

		Context("when the lock cannot be acquired", func() {
			BeforeEach(func() {
				fakeLocker.LockReturns(nil, errors.New("no-lock-for-you"))
				fakeLocker.FetchReturns(&models.FetchResponse{Resource: &models.Resource{Owner: "joe"}}, nil)
			})

			JustBeforeEach(func() {
				Eventually(fakeLocker.LockCallCount).Should(Equal(1))
				_, lockReq, _ := fakeLocker.LockArgsForCall(0)
				Expect(lockReq.Resource).To(Equal(expectedLock))
				Expect(lockReq.TtlInSeconds).To(Equal(expectedTTL))
			})

			It("logs the request uuid", func() {
				Eventually(logger).Should(gbytes.Say("request-uuid"))
			})

			It("logs the initial error", func() {
				Eventually(logger).Should(gbytes.Say("no-lock-for-you"))
			})

			Context("and the retry interval elapses", func() {
				JustBeforeEach(func() {
					Eventually(logger).Should(gbytes.Say("no-lock-for-you"))
					fakeClock.WaitForWatcherAndIncrement(lockRetryInterval)
				})

				It("logs subsequent errors", func() {
					Eventually(fakeLocker.LockCallCount).Should(Equal(2))
					Eventually(logger).Should(gbytes.Say("no-lock-for-you"))
				})

				It("logs the request uuid", func() {
					Eventually(fakeLocker.LockCallCount).Should(Equal(2))
					Eventually(logger).Should(gbytes.Say("request-uuid"))
				})

				It("sets the request guid metadata", func() {
					Eventually(fakeLocker.LockCallCount).Should(Equal(2))
					ctx, _, _ := fakeLocker.LockArgsForCall(1)
					md, _ := metadata.FromOutgoingContext(ctx)
					Expect(md).To(HaveKey("uuid"))
				})

				It("retries locking after the lock retry interval", func() {
					Eventually(fakeLocker.LockCallCount).Should(Equal(2))
					ctx, lockReq, options := fakeLocker.LockArgsForCall(1)
					Expect(lockReq.Resource).To(Equal(expectedLock))
					Expect(lockReq.TtlInSeconds).To(Equal(expectedTTL))
					_, ok := ctx.Deadline()
					Expect(ok).To(BeTrue(), "no deadline set")
					Expect(options).To(HaveLen(1))

					Consistently(lockProcess.Ready()).ShouldNot(BeClosed())
				})
			})

			Context("when there is a lock collision", func() {
				BeforeEach(func() {
					// do not use models.ErrLockCollision because in practice from the wire that
					// variable instance cannot be returned
					fakeLocker.LockReturns(nil, grpc.Errorf(codes.AlreadyExists, "lock-collision"))

					fakeLocker.FetchReturns(&models.FetchResponse{Resource: &models.Resource{Owner: "joe"}}, nil)
				})

				It("logs the initial error", func() {
					Eventually(logger).Should(gbytes.Say("lock-collision"))
				})

				It("logs the owner of the lock", func() {
					Eventually(logger).Should(gbytes.Say("lock-owner"))
					Eventually(logger).Should(gbytes.Say("joe"))
				})

				Context("when fetching the owner of the lock fails", func() {
					BeforeEach(func() {
						fakeLocker.FetchReturns(nil, errors.New("no-fetch-for-you"))
					})

					It("logs that the fetch failed", func() {
						Eventually(logger).Should(gbytes.Say("no-fetch-for-you"))
					})
				})

				Context("and the retry interval elapses", func() {
					JustBeforeEach(func() {
						Eventually(logger).Should(gbytes.Say("lock-collision"))
						fakeClock.WaitForWatcherAndIncrement(lockRetryInterval)
					})

					It("does not log subsequent errors", func() {
						Eventually(fakeLocker.LockCallCount).Should(Equal(2))
						Consistently(logger).ShouldNot(gbytes.Say("lock-collision"))
					})
				})
			})

			Context("and the lock becomes available", func() {
				var done chan struct{}

				BeforeEach(func() {
					done = make(chan struct{})

					fakeLocker.LockStub = func(ctx context.Context, res *models.LockRequest, opts ...grpc.CallOption) (*models.LockResponse, error) {
						select {
						case <-done:
							return nil, nil
						default:
							return nil, errors.New("no-lock-for-you")
						}
					}
				})

				It("grabs the lock and the continues to heartbeat", func() {
					Consistently(lockProcess.Ready()).ShouldNot(BeClosed())

					close(done)
					fakeClock.WaitForWatcherAndIncrement(lockRetryInterval)

					Eventually(lockProcess.Ready()).Should(BeClosed())
					Eventually(fakeLocker.LockCallCount).Should(Equal(2))
					_, lockReq, _ := fakeLocker.LockArgsForCall(1)
					Expect(lockReq.Resource).To(Equal(expectedLock))
					Expect(lockReq.TtlInSeconds).To(Equal(expectedTTL))

					fakeClock.WaitForWatcherAndIncrement(lockRetryInterval)
					Eventually(fakeLocker.LockCallCount).Should(Equal(3))
				})
			})
		})

		Context("when the lock can be acquired", func() {
			It("grabs the lock and then continues to heartbeat", func() {
				Eventually(lockProcess.Ready()).Should(BeClosed())
				Eventually(fakeLocker.LockCallCount).Should(Equal(1))
				_, lockReq, _ := fakeLocker.LockArgsForCall(0)
				Expect(lockReq.Resource).To(Equal(expectedLock))
				Expect(lockReq.TtlInSeconds).To(Equal(expectedTTL))

				fakeClock.WaitForWatcherAndIncrement(lockRetryInterval)
				Eventually(fakeLocker.LockCallCount).Should(Equal(2))
				_, lockReq, _ = fakeLocker.LockArgsForCall(1)
				Expect(lockReq.Resource).To(Equal(expectedLock))
				Expect(lockReq.TtlInSeconds).To(Equal(expectedTTL))

				Eventually(fakeClock.WatcherCount).Should(Equal(1))
				fakeClock.WaitForWatcherAndIncrement(lockRetryInterval)
				Eventually(fakeLocker.LockCallCount).Should(Equal(3))
				_, lockReq, _ = fakeLocker.LockArgsForCall(2)
				Expect(lockReq.Resource).To(Equal(expectedLock))
				Expect(lockReq.TtlInSeconds).To(Equal(expectedTTL))
			})

			Context("and then the lock becomes unavailable", func() {
				var done chan struct{}

				BeforeEach(func() {
					done = make(chan struct{})

					fakeLocker.LockStub = func(ctx context.Context, res *models.LockRequest, opts ...grpc.CallOption) (*models.LockResponse, error) {
						select {
						case <-done:
							return nil, errors.New("no-lock-for-you")
						default:
							return nil, nil
						}
					}
				})

				JustBeforeEach(func() {
					Eventually(lockProcess.Ready()).Should(BeClosed())
					Eventually(fakeLocker.LockCallCount).Should(Equal(1))
					close(done)

					fakeClock.WaitForWatcherAndIncrement(lockRetryInterval)
				})

				It("logs the error", func() {
					Eventually(fakeLocker.LockCallCount).Should(Equal(2))
					Eventually(logger).Should(gbytes.Say("lost-lock.*no-lock-for-you"))
				})

				It("logs the request uuid", func() {
					Eventually(fakeLocker.LockCallCount).Should(Equal(2))
					Eventually(logger).Should(gbytes.Say("request-uuid"))
				})

				It("exits with an error", func() {
					Eventually(fakeLocker.LockCallCount).Should(Equal(2))
					Eventually(lockProcess.Wait()).Should(Receive())
				})
			})
		})

		Context("when the lock process receives a signal", func() {
			It("releases the lock", func() {
				ginkgomon.Interrupt(lockProcess)
				Eventually(fakeLocker.ReleaseCallCount).Should(Equal(1))
				_, releaseReq, _ := fakeLocker.ReleaseArgsForCall(0)
				Expect(releaseReq.Resource).To(Equal(expectedLock))
			})
		})
	})

	Context("NewPresenceRunner", func() {
		BeforeEach(func() {
			lockRunner = lock.NewPresenceRunner(
				logger,
				fakeLocker,
				expectedLock,
				expectedTTL,
				fakeClock,
				lockRetryInterval,
			)
		})

		JustBeforeEach(func() {
			lockProcess = ifrit.Background(lockRunner)
		})

		AfterEach(func() {
			ginkgomon.Kill(lockProcess)
		})

		Context("when the lock can be acquired", func() {
			It("grabs the lock and then continues to heartbeat", func() {
				Eventually(lockProcess.Ready()).Should(BeClosed())
				Eventually(fakeLocker.LockCallCount).Should(Equal(1))
				_, lockReq, _ := fakeLocker.LockArgsForCall(0)
				Expect(lockReq.Resource).To(Equal(expectedLock))
				Expect(lockReq.TtlInSeconds).To(Equal(expectedTTL))

				fakeClock.WaitForWatcherAndIncrement(lockRetryInterval)
				Eventually(fakeLocker.LockCallCount).Should(Equal(2))
				_, lockReq, _ = fakeLocker.LockArgsForCall(1)
				Expect(lockReq.Resource).To(Equal(expectedLock))
				Expect(lockReq.TtlInSeconds).To(Equal(expectedTTL))

				Eventually(fakeClock.WatcherCount).Should(Equal(1))
				fakeClock.WaitForWatcherAndIncrement(lockRetryInterval)
				Eventually(fakeLocker.LockCallCount).Should(Equal(3))
				_, lockReq, _ = fakeLocker.LockArgsForCall(2)
				Expect(lockReq.Resource).To(Equal(expectedLock))
				Expect(lockReq.TtlInSeconds).To(Equal(expectedTTL))
			})

			Context("and then the lock becomes unavailable", func() {
				var lockResult chan bool

				BeforeEach(func() {
					lockResult = make(chan bool, 1)

					fakeLocker.LockStub = func(ctx context.Context, res *models.LockRequest, opts ...grpc.CallOption) (*models.LockResponse, error) {
						defer GinkgoRecover()
						var shouldError bool
						Eventually(lockResult).Should(Receive(&shouldError))
						if shouldError {
							return nil, errors.New("boom!")
						} else {
							return nil, nil
						}
					}
				})

				It("continues to retry grabbing the lock", func() {
					Eventually(lockResult).Should(BeSent(false))

					Eventually(lockProcess.Ready()).Should(BeClosed())
					Eventually(fakeLocker.LockCallCount).Should(Equal(1))
					_, lockReq, _ := fakeLocker.LockArgsForCall(0)
					Expect(lockReq.Resource).To(Equal(expectedLock))
					Expect(lockReq.TtlInSeconds).To(Equal(expectedTTL))

					Eventually(lockResult).Should(BeSent(true))
					fakeClock.WaitForWatcherAndIncrement(lockRetryInterval)

					Eventually(fakeLocker.LockCallCount).Should(Equal(2))
					Consistently(lockProcess.Wait()).ShouldNot(Receive())

					Eventually(lockResult).Should(BeSent(false))
					fakeClock.WaitForWatcherAndIncrement(lockRetryInterval)

					Eventually(fakeLocker.LockCallCount).Should(Equal(3))
					_, lockReq, _ = fakeLocker.LockArgsForCall(2)
					Expect(lockReq.Resource).To(Equal(expectedLock))
					Expect(lockReq.TtlInSeconds).To(Equal(expectedTTL))
					Consistently(lockProcess.Wait()).ShouldNot(Receive())
				})
			})
		})
	})
})
