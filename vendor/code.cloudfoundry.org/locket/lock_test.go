package locket_test

import (
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	cfhttp "code.cloudfoundry.org/cfhttp/v2"
	"code.cloudfoundry.org/consuladapter"
	loggregator "code.cloudfoundry.org/go-loggregator"
	"code.cloudfoundry.org/locket"
	"github.com/hashicorp/consul/api"

	"code.cloudfoundry.org/clock/fakeclock"
	mfakes "code.cloudfoundry.org/diego-logging-client/testhelpers"
	"code.cloudfoundry.org/lager"
	"code.cloudfoundry.org/lager/lagertest"
	"github.com/tedsuo/ifrit"
	"github.com/tedsuo/ifrit/ginkgomon"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gbytes"
)

var _ = Describe("Lock", func() {

	type durationMetric struct {
		name  string
		value time.Duration
	}
	type intMetric struct {
		name  string
		value int
	}
	var (
		fakeMetronClient     *mfakes.FakeIngressClient
		lockKey              string
		lockHeldMetricName   string
		lockUptimeMetricName string
		lockValue            []byte
		fakeMetricChan       chan intMetric
		fakeDurationChan     chan durationMetric

		consulClient consuladapter.Client

		lockRunner    ifrit.Runner
		lockProcess   ifrit.Process
		retryInterval time.Duration
		lockTTL       time.Duration
		logger        lager.Logger

		clock *fakeclock.FakeClock
	)

	getLockValue := func() ([]byte, error) {
		kvPair, _, err := consulClient.KV().Get(lockKey, nil)
		if err != nil {
			return nil, err
		}

		if kvPair == nil || kvPair.Session == "" {
			return nil, consuladapter.NewKeyNotFoundError(lockKey)
		}

		return kvPair.Value, nil
	}

	BeforeEach(func() {
		consulClient = consulRunner.NewClient()

		lockKey = locket.LockSchemaPath("some-key")
		lockKeyMetric := strings.Replace(lockKey, "/", "-", -1)
		lockHeldMetricName = "LockHeld." + lockKeyMetric
		lockUptimeMetricName = "LockHeldDuration." + lockKeyMetric
		lockValue = []byte("some-value")

		retryInterval = 500 * time.Millisecond
		lockTTL = 5 * time.Second
		logger = lagertest.NewTestLogger("locket")

		fakeMetricChan = make(chan intMetric, 5)
		fakeDurationChan = make(chan durationMetric, 5)

		fakeMetronClient = new(mfakes.FakeIngressClient)
		fakeMetronClient.SendMetricStub = func(name string, value int, opts ...loggregator.EmitGaugeOption) error {
			fakeMetricChan <- intMetric{name: name, value: value}
			return nil
		}
		fakeMetronClient.SendDurationStub = func(name string, value time.Duration, opts ...loggregator.EmitGaugeOption) error {
			fakeDurationChan <- durationMetric{name: name, value: value}
			return nil
		}
	})

	JustBeforeEach(func() {
		clock = fakeclock.NewFakeClock(time.Now())
		lockRunner = locket.NewLock(logger, consulClient, lockKey, lockValue, clock, retryInterval, lockTTL, locket.WithMetronClient(fakeMetronClient))
	})

	AfterEach(func() {
		ginkgomon.Interrupt(lockProcess)
	})

	var shouldEventuallyHaveNumSessions = func(numSessions int) {
		Eventually(func() int {
			sessions, _, err := consulClient.Session().List(nil)
			Expect(err).NotTo(HaveOccurred())
			return len(sessions)
		}).Should(Equal(numSessions))
	}

	Context("When consul is running", func() {
		Context("an error occurs while acquiring the lock", func() {
			BeforeEach(func() {
				lockKey = ""
				lockKeyMetric := strings.Replace(lockKey, "/", "-", -1)
				lockHeldMetricName = "LockHeld." + lockKeyMetric
			})

			It("continues to retry", func() {
				lockProcess = ifrit.Background(lockRunner)
				shouldEventuallyHaveNumSessions(1)
				Consistently(lockProcess.Ready()).ShouldNot(BeClosed())
				Consistently(lockProcess.Wait()).ShouldNot(Receive())

				clock.WaitForWatcherAndIncrement(retryInterval)
				Eventually(logger).Should(Say("acquire-lock-failed"))
				Eventually(logger).Should(Say("retrying-acquiring-lock"))
				Eventually(fakeMetricChan).Should(Receive(Equal(intMetric{
					name:  "LockHeld.",
					value: 0,
				})))
			})
		})

		Context("and the lock is available", func() {
			It("acquires the lock", func() {
				lockProcess = ifrit.Background(lockRunner)
				Eventually(lockProcess.Ready()).Should(BeClosed())
				Eventually(fakeDurationChan).Should(Receive(Equal(durationMetric{
					name:  lockUptimeMetricName,
					value: 0 * time.Second,
				})))
				Expect(getLockValue()).To(Equal(lockValue))
				Eventually(fakeMetricChan).Should(Receive(Equal(intMetric{
					name:  lockHeldMetricName,
					value: 1,
				})))
			})

			Context("and we have acquired the lock", func() {
				JustBeforeEach(func() {
					lockProcess = ifrit.Background(lockRunner)
					Eventually(lockProcess.Ready()).Should(BeClosed())
				})

				It("continues to emit lock metric", func() {
					clock.WaitForWatcherAndIncrement(30 * time.Second)
					Eventually(fakeDurationChan).Should(Receive(Equal(durationMetric{
						name:  lockUptimeMetricName,
						value: 30 * time.Second,
					})))

					clock.WaitForWatcherAndIncrement(30 * time.Second)
					Eventually(fakeDurationChan).Should(Receive(Equal(durationMetric{
						name:  lockUptimeMetricName,
						value: 60 * time.Second,
					})))

					clock.WaitForWatcherAndIncrement(30 * time.Second)
					Eventually(fakeDurationChan).Should(Receive(Equal(durationMetric{
						name:  lockUptimeMetricName,
						value: 90 * time.Second,
					})))

				})

				Context("when consul shuts down", func() {
					JustBeforeEach(func() {
						consulRunner.Stop()
					})

					AfterEach(func() {
						consulRunner.Start()
						consulRunner.WaitUntilReady()
					})

					It("loses the lock and exits", func() {
						var err error
						Eventually(lockProcess.Wait()).Should(Receive(&err))
						Expect(err).To(Equal(locket.ErrLockLost))
						Eventually(fakeMetricChan).Should(Receive(Equal(intMetric{
							name:  lockHeldMetricName,
							value: 0,
						})))
					})
				})

				Context("and the process is shutting down", func() {
					It("releases the lock and exits", func() {
						ginkgomon.Interrupt(lockProcess)
						Eventually(lockProcess.Wait()).Should(Receive(BeNil()))
						_, err := getLockValue()
						Expect(err).To(Equal(consuladapter.NewKeyNotFoundError(lockKey)))
					})
				})

				Context("and consul goes through a period of instability", func() {
					var serveFiveHundreds chan bool
					var fakeConsul *httptest.Server

					BeforeEach(func() {
						serveFiveHundreds = make(chan bool, 4)

						consulClusterURL, err := url.Parse(consulRunner.URL())
						Expect(err).NotTo(HaveOccurred())
						proxy := httputil.NewSingleHostReverseProxy(consulClusterURL)
						fakeConsul = httptest.NewServer(
							http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
								// We only want to return 500's on the lock monitor query which is of the form /v1/kv/some-key?consistent=
								_, hasConsistent := r.URL.Query()["consistent"]
								if !hasConsistent {
									By(time.Now().String() + ": forwarding request to " + r.URL.String())
									proxy.ServeHTTP(w, r)
									return
								}

								if <-serveFiveHundreds {
									By(time.Now().String() + ": returning 500 to " + r.URL.String())
									w.WriteHeader(http.StatusInternalServerError)
								} else {
									By(time.Now().String() + ": forwarding request to " + r.URL.String())
									proxy.ServeHTTP(w, r)
								}
							}),
						)

						fakeConsulURL, err := url.Parse(fakeConsul.URL)
						Expect(err).NotTo(HaveOccurred())

						client, err := api.NewClient(&api.Config{
							Address:    fakeConsulURL.Host,
							Scheme:     fakeConsulURL.Scheme,
							HttpClient: cfhttp.NewClient(cfhttp.WithStreamingDefaults()),
						})
						Expect(err).NotTo(HaveOccurred())

						consulClient = consuladapter.NewConsulClient(client)
						lockTTL = 6 * time.Second
					})

					Context("for longer than the MonitorRetries * MonitorRetryTime", func() {
						It("loses lock", func() {
							Eventually(fakeDurationChan).Should(Receive(Equal(durationMetric{
								name:  lockUptimeMetricName,
								value: 0 * time.Second,
							})))
							Expect(getLockValue()).To(Equal(lockValue))
							Eventually(fakeMetricChan).Should(Receive(Equal(intMetric{
								name:  lockHeldMetricName,
								value: 1,
							})))

							// Serve 500's to simulate a leader election. We know that we need
							// to serve more than lockTTL / 2 500's to lose the lock.
							for i := 0; i < 4; i++ {
								Eventually(serveFiveHundreds).Should(BeSent(true))
							}

							close(serveFiveHundreds)

							Eventually(lockProcess.Wait(), 7*time.Second).Should(Receive())
						})
					})

					Context("for less than the MonitorRetries * MonitorRetryTime", func() {
						It("does not lose the lock", func() {
							Eventually(fakeDurationChan).Should(Receive(Equal(durationMetric{
								name:  lockUptimeMetricName,
								value: 0 * time.Second,
							})))
							Expect(getLockValue()).To(Equal(lockValue))
							Eventually(fakeMetricChan).Should(Receive(Equal(intMetric{
								name:  lockHeldMetricName,
								value: 1,
							})))

							// Serve 500's to simulate a leader election. We know that if we
							// serve less than lockTTL / 2 500's, we will not lose the lock.
							for i := 0; i < 2; i++ {
								Eventually(serveFiveHundreds).Should(BeSent(true))
							}

							close(serveFiveHundreds)

							Consistently(lockProcess.Wait(), 7*time.Second).ShouldNot(Receive())
						})
					})
				})
			})
		})

		Context("and the lock is unavailable", func() {
			var (
				otherProcess ifrit.Process
				otherValue   []byte
			)

			BeforeEach(func() {
				otherValue = []byte("doppel-value")
				otherClock := fakeclock.NewFakeClock(time.Now())

				otherRunner := locket.NewLock(logger, consulClient, lockKey, otherValue, otherClock, retryInterval, 5*time.Second, locket.WithMetronClient(fakeMetronClient))
				otherProcess = ifrit.Background(otherRunner)

				Eventually(otherProcess.Ready()).Should(BeClosed())
				Expect(getLockValue()).To(Equal(otherValue))
			})

			AfterEach(func() {
				ginkgomon.Interrupt(otherProcess)
			})

			It("waits for the lock to become available", func() {
				lockProcess = ifrit.Background(lockRunner)
				Consistently(lockProcess.Ready()).ShouldNot(BeClosed())
				Expect(getLockValue()).To(Equal(otherValue))
			})

			Context("when consul shuts down", func() {
				JustBeforeEach(func() {
					lockProcess = ifrit.Background(lockRunner)
					shouldEventuallyHaveNumSessions(1)

					consulRunner.Stop()
				})

				AfterEach(func() {
					consulRunner.Start()
					consulRunner.WaitUntilReady()
				})

				It("continues to wait for the lock", func() {
					Consistently(lockProcess.Ready()).ShouldNot(BeClosed())
					Consistently(lockProcess.Wait()).ShouldNot(Receive())

					Eventually(logger).Should(Say("acquire-lock-failed"))
					clock.WaitForWatcherAndIncrement(retryInterval)
					Eventually(logger).Should(Say("retrying-acquiring-lock"))
					Eventually(fakeMetricChan).Should(Receive(Equal(intMetric{
						name:  lockHeldMetricName,
						value: 0,
					})))
				})
			})

			Context("and the session is destroyed", func() {
				It("should recreate the session and continue to retry", func() {
					lockProcess = ifrit.Background(lockRunner)

					shouldEventuallyHaveNumSessions(2)

					sessions, _, err := consulClient.Session().List(nil)
					Expect(err).NotTo(HaveOccurred())
					var mostRecentSession *api.SessionEntry
					for _, session := range sessions {
						if mostRecentSession == nil {
							mostRecentSession = session
						} else if session.CreateIndex > mostRecentSession.CreateIndex {
							mostRecentSession = session
						}
					}

					_, err = consulClient.Session().Destroy(mostRecentSession.ID, nil)
					Expect(err).NotTo(HaveOccurred())

					Eventually(logger, 10*time.Second).Should(Say("consul-error"))
					Eventually(logger, 15*time.Second).Should(Say("acquire-lock-failed"))
					clock.WaitForWatcherAndIncrement(retryInterval)
					Eventually(logger).Should(Say("retrying-acquiring-lock"))
					shouldEventuallyHaveNumSessions(2)
				})
			})

			Context("and the process is shutting down", func() {
				It("exits", func() {
					lockProcess = ifrit.Background(lockRunner)
					shouldEventuallyHaveNumSessions(2)

					ginkgomon.Interrupt(lockProcess)
					Eventually(lockProcess.Wait()).Should(Receive(BeNil()))
				})
			})

			Context("and the lock is released", func() {
				It("acquires the lock", func() {
					lockProcess = ifrit.Background(lockRunner)
					Consistently(lockProcess.Ready()).ShouldNot(BeClosed())
					Expect(getLockValue()).To(Equal(otherValue))

					ginkgomon.Interrupt(otherProcess)

					Eventually(lockProcess.Ready(), 6*time.Second).Should(BeClosed())
					Expect(getLockValue()).To(Equal(lockValue))
				})
			})
		})
	})

	Context("When consul is down", func() {
		BeforeEach(func() {
			consulRunner.Stop()
		})

		AfterEach(func() {
			consulRunner.Start()
			consulRunner.WaitUntilReady()
		})

		It("continues to retry acquiring the lock", func() {
			lockProcess = ifrit.Background(lockRunner)

			Consistently(lockProcess.Ready()).ShouldNot(BeClosed())
			Consistently(lockProcess.Wait()).ShouldNot(Receive())

			Eventually(logger).Should(Say("acquire-lock-failed"))
			clock.WaitForWatcherAndIncrement(retryInterval)
			Eventually(logger).Should(Say("retrying-acquiring-lock"))
			clock.WaitForWatcherAndIncrement(retryInterval)
			Eventually(logger).Should(Say("retrying-acquiring-lock"))
		})

		Context("when consul starts up", func() {
			It("acquires the lock", func() {
				lockProcess = ifrit.Background(lockRunner)

				Eventually(logger).Should(Say("acquire-lock-failed"))
				clock.WaitForWatcherAndIncrement(retryInterval)
				Eventually(logger).Should(Say("retrying-acquiring-lock"))
				Consistently(lockProcess.Ready()).ShouldNot(BeClosed())
				Consistently(lockProcess.Wait()).ShouldNot(Receive())

				consulRunner.Start()
				consulRunner.WaitUntilReady()

				clock.WaitForWatcherAndIncrement(retryInterval)
				Eventually(lockProcess.Ready()).Should(BeClosed())
				Expect(getLockValue()).To(Equal(lockValue))
			})
		})
	})
})
