package main_test

import (
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"sync"
	"time"

	"code.cloudfoundry.org/diego-logging-client/testhelpers"
	"code.cloudfoundry.org/durationjson"
	"code.cloudfoundry.org/go-loggregator/rpc/loggregator_v2"
	"code.cloudfoundry.org/lager/lagertest"
	"code.cloudfoundry.org/locket"
	"code.cloudfoundry.org/locket/cmd/locket/config"
	"code.cloudfoundry.org/locket/cmd/locket/testrunner"
	"code.cloudfoundry.org/locket/models"
	"google.golang.org/grpc/metadata"

	"github.com/hashicorp/consul/api"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
	"github.com/onsi/gomega/gexec"
	"github.com/tedsuo/ifrit"
	"github.com/tedsuo/ifrit/ginkgomon"
)

var _ = Describe("Locket", func() {
	var (
		locketAddress string
		locketClient  models.LocketClient
		locketProcess ifrit.Process
		locketPort    uint16
		locketRunner  *ginkgomon.Runner

		logger *lagertest.TestLogger

		configOverrides []func(*config.LocketConfig)
	)

	BeforeEach(func() {
		var err error

		locketPort, err = portAllocator.ClaimPorts(1)
		Expect(err).NotTo(HaveOccurred())

		locketAddress = fmt.Sprintf("127.0.0.1:%d", locketPort)

		logger = lagertest.NewTestLogger("locket")

		configOverrides = []func(cfg *config.LocketConfig){
			func(cfg *config.LocketConfig) {
				cfg.ListenAddress = locketAddress
				cfg.ConsulCluster = consulRunner.ConsulCluster()
				cfg.DatabaseDriver = sqlRunner.DriverName()
				cfg.DatabaseConnectionString = sqlRunner.ConnectionString()
				cfg.ReportInterval = durationjson.Duration(time.Second)
			},
		}
	})

	JustBeforeEach(func() {
		locketRunner = testrunner.NewLocketRunner(locketBinPath, configOverrides...)
	})

	Context("when the configuration is invalid", func() {
		Context("when the loggregator configuration isn't valid or the agent isn't up", func() {
			BeforeEach(func() {
				port, err := portAllocator.ClaimPorts(1)
				Expect(err).NotTo(HaveOccurred())
				configOverrides = append(configOverrides, func(cfg *config.LocketConfig) {
					cfg.LoggregatorConfig.UseV2API = true
					cfg.LoggregatorConfig.APIPort = int(port)
					cfg.LoggregatorConfig.CACertPath = "fixtures/metron/CA.crt"
					cfg.LoggregatorConfig.KeyPath = "fixtures/metron/client.key"
					cfg.LoggregatorConfig.CertPath = "fixtures/metron/client.crt"
				})
			})

			It("exit with non-zero status code", func() {
				locketProcess = ifrit.Invoke(locketRunner)
				Eventually(locketProcess.Wait()).Should(Receive(HaveOccurred()))
			})
		})

		Context("when an invalid config is passed", func() {
			var (
				configFile string
			)

			BeforeEach(func() {
				locketConfigFilePath, err := ioutil.TempFile(os.TempDir(), "locket-config")
				Expect(err).NotTo(HaveOccurred())
				_, err = locketConfigFilePath.Write([]byte(`{"foo":`))
				Expect(err).NotTo(HaveOccurred())
				Expect(locketConfigFilePath.Close()).To(Succeed())
				configFile = locketConfigFilePath.Name()
			})

			It("prints a meaningfull error to the user", func() {
				session, err := gexec.Start(exec.Command(locketBinPath, "-config="+configFile), GinkgoWriter, GinkgoWriter)
				Expect(err).NotTo(HaveOccurred())
				Eventually(session.Exited).Should(BeClosed())
				Expect(session.ExitCode()).To(Equal(2))
				Expect(session.Err).To(gbytes.Say("invalid-config-file"))
			})
		})
	})

	Context("when the configuration is valid", func() {
		JustBeforeEach(func() {
			locketProcess = ginkgomon.Invoke(locketRunner)

			config := testrunner.ClientLocketConfig()
			config.LocketAddress = locketAddress

			var err error
			locketClient, err = locket.NewClient(logger, config)
			Expect(err).NotTo(HaveOccurred())
		})

		AfterEach(func() {
			ginkgomon.Interrupt(locketProcess)
			sqlRunner.ResetTables(TruncateTableList)
		})

		Context("metrics", func() {

			var (
				testIngressServer *testhelpers.TestIngressServer
				testMetricsChan   chan *loggregator_v2.Envelope
				testMetricsPort   int
				signalMetricsChan chan struct{}
			)

			BeforeEach(func() {
				var err error
				testIngressServer, err = testhelpers.NewTestIngressServer(
					"fixtures/metron/metron.crt",
					"fixtures/metron/metron.key",
					"fixtures/metron/CA.crt",
				)
				Expect(err).NotTo(HaveOccurred())
				receiversChan := testIngressServer.Receivers()
				Expect(testIngressServer.Start()).To(Succeed())
				testMetricsPort, err = testIngressServer.Port()
				Expect(err).NotTo(HaveOccurred())

				testMetricsChan, signalMetricsChan = testhelpers.TestMetricChan(receiversChan)
			})

			AfterEach(func() {
				testIngressServer.Stop()
				close(signalMetricsChan)
			})

			Context("when using the v2 api", func() {
				BeforeEach(func() {
					configOverrides = append(configOverrides, func(cfg *config.LocketConfig) {
						cfg.LoggregatorConfig.UseV2API = true
						cfg.LoggregatorConfig.APIPort = testMetricsPort
						cfg.LoggregatorConfig.CACertPath = "fixtures/metron/CA.crt"
						cfg.LoggregatorConfig.KeyPath = "fixtures/metron/client.key"
						cfg.LoggregatorConfig.CertPath = "fixtures/metron/client.crt"
					})
				})

				It("emits metrics", func() {
					Eventually(testMetricsChan).Should(Receive())
				})

				Context("when a lock is acquired", func() {
					JustBeforeEach(func() {
						requestedResource := &models.Resource{Key: "test", Value: "test-data", Owner: "jim", Type: "lock"}
						_, err := locketClient.Lock(context.Background(), &models.LockRequest{
							Resource:     requestedResource,
							TtlInSeconds: 10,
						})
						Expect(err).NotTo(HaveOccurred())
					})

					It("emits DBQueriesTotal metric", func() {
						metricName := "DBQueriesTotal"
						Eventually(testMetricsChan).Should(Receive(
							SatisfyAll(
								testhelpers.MatchV2Metric(testhelpers.MetricAndValue{Name: metricName}),
								WithTransform(func(source *loggregator_v2.Envelope) float64 {
									return source.GetGauge().GetMetrics()[metricName].Value
								}, BeNumerically(">", 0)),
							),
						))
					})

					It("increases the RequestsSucceeded metric", func() {
						metricName := "RequestsSucceeded"
						Eventually(testMetricsChan).Should(Receive(
							SatisfyAll(
								testhelpers.MatchV2Metric(testhelpers.MetricAndValue{Name: metricName}),
								WithTransform(func(source *loggregator_v2.Envelope) float64 {
									return source.GetGauge().GetMetrics()[metricName].Value
								}, BeNumerically(">", 0)),
							),
						))
					})
				})

				Context("when the locket server is encountering a high load", func() {
					BeforeEach(func() {
						configOverrides = append(configOverrides, func(cfg *config.LocketConfig) {
							cfg.MaxOpenDatabaseConnections = 100
							cfg.MaxDatabaseConnectionLifetime = 0
						})
					})

					JustBeforeEach(func() {
						var wg sync.WaitGroup
						wg.Add(10)
						for i := 0; i < 10; i++ {
							key := fmt.Sprintf("test%d", i)
							requestedResource := &models.Resource{Key: key, Value: "test-data", Owner: key, Type: "lock"}
							go func() {
								defer GinkgoRecover()
								defer wg.Done()
								var err error
								for j := 0; j < 3; j++ {
									_, err := locketClient.Lock(context.Background(), &models.LockRequest{
										Resource:     requestedResource,
										TtlInSeconds: 10,
									})
									if err == nil {
										break
									}
								}
								Expect(err).NotTo(HaveOccurred())
							}()
						}
						wg.Wait()
					})

					It("increases the DBOpenConnections metric", func() {
						metricName := "DBOpenConnections"
						openConnections := make(chan float64, 10)
						go func() {
							for {
								metric := <-testMetricsChan
								gauge := metric.GetGauge()
								if gauge != nil {
									metrics := gauge.GetMetrics()
									if m, found := metrics[metricName]; found {
										openConnections <- m.Value
									}
								}
							}
						}()
						Eventually(openConnections).Should(Receive(BeNumerically(">", 5)))
						Consistently(func() float64 { return <-openConnections }, 10*time.Second).Should(BeNumerically(">", 5))
					})

					Context("when the max database connection lifetime is set", func() {
						BeforeEach(func() {
							configOverrides = append(configOverrides, func(cfg *config.LocketConfig) {
								cfg.MaxDatabaseConnectionLifetime = durationjson.Duration(5 * time.Second)
							})
						})

						It("eventually decreases the DBOpenConnections metric", func() {
							metricName := "DBOpenConnections"
							openConnections := make(chan float64, 10)
							go func() {
								for {
									metric := <-testMetricsChan
									gauge := metric.GetGauge()
									if gauge != nil {
										metrics := gauge.GetMetrics()
										if m, found := metrics[metricName]; found {
											openConnections <- m.Value
										}
									}
								}
							}()
							Eventually(openConnections).Should(Receive(BeNumerically(">", 5)))
							Eventually(openConnections).Should(Receive(BeNumerically("<", 5)))
						})
					})
				})
			})

			Context("when not using the v2 api", func() {
				BeforeEach(func() {
					configOverrides = append(configOverrides, func(cfg *config.LocketConfig) {
						cfg.LoggregatorConfig.UseV2API = false
						cfg.LoggregatorConfig.APIPort = testMetricsPort
						cfg.LoggregatorConfig.CACertPath = "fixtures/metron/CA.crt"
						cfg.LoggregatorConfig.KeyPath = "fixtures/metron/client.key"
						cfg.LoggregatorConfig.CertPath = "fixtures/metron/client.crt"
					})
				})

				It("does not emit metrics", func() {
					Consistently(testMetricsChan).ShouldNot(Receive())
				})
			})
		})

		Context("debug address", func() {
			var debugAddress string

			BeforeEach(func() {
				port, err := portAllocator.ClaimPorts(1)
				Expect(err).NotTo(HaveOccurred())

				debugAddress = fmt.Sprintf("127.0.0.1:%d", port)
				configOverrides = append(configOverrides, func(cfg *config.LocketConfig) {
					cfg.DebugAddress = debugAddress
				})
			})

			It("listens on the debug address specified", func() {
				_, err := net.Dial("tcp", debugAddress)
				Expect(err).NotTo(HaveOccurred())
			})
		})

		Context("ServiceRegistration", func() {
			Context("with EnableConsulServiceRegistration set to false", func() {
				BeforeEach(func() {
					configOverrides = append(configOverrides, func(cfg *config.LocketConfig) {
						cfg.EnableConsulServiceRegistration = false
					})
				})

				It("does not register itself with consul", func() {
					consulClient := consulRunner.NewClient()
					services, err := consulClient.Agent().Services()
					Expect(err).ToNot(HaveOccurred())

					Expect(services).NotTo(HaveKey("locket"))
				})
			})

			Context("with EnableConsulServiceRegistration set to true", func() {
				BeforeEach(func() {
					configOverrides = append(configOverrides, func(cfg *config.LocketConfig) {
						cfg.EnableConsulServiceRegistration = true
					})
				})

				It("registers itself with consul", func() {
					consulClient := consulRunner.NewClient()
					services, err := consulClient.Agent().Services()
					Expect(err).ToNot(HaveOccurred())

					Expect(services).To(HaveKeyWithValue("locket",
						&api.AgentService{
							Service: "locket",
							ID:      "locket",
							Port:    int(locketPort),
						}))
				})

				It("registers a TTL healthcheck", func() {
					consulClient := consulRunner.NewClient()
					checks, err := consulClient.Agent().Checks()
					Expect(err).ToNot(HaveOccurred())

					Expect(checks).To(HaveKeyWithValue("service:locket",
						&api.AgentCheck{
							Node:        "0",
							CheckID:     "service:locket",
							Name:        "Service 'locket' check",
							Status:      "passing",
							ServiceID:   "locket",
							ServiceName: "locket",
						}))
				})
			})
		})

		Context("Lock", func() {
			Context("if the table disappears", func() {
				AfterEach(func() {
					sqlRunner.DB().Close()
					sqlProcess = ginkgomon.Invoke(sqlRunner)
				})

				JustBeforeEach(func() {
					_, err := sqlRunner.DB().Exec("DROP TABLE locks")
					Expect(err).NotTo(HaveOccurred())
					requestedResource := &models.Resource{Key: "test", Value: "test-data", Owner: "jim", Type: "lock"}
					_, err = locketClient.Lock(context.Background(), &models.LockRequest{
						Resource:     requestedResource,
						TtlInSeconds: 10,
					})
					Expect(err).To(HaveOccurred())
				})

				It("exits", func() {
					Eventually(locketRunner).Should(gbytes.Say("unrecoverable-error"))
					Eventually(locketProcess.Wait()).Should(Receive())
				})
			})

			It("locks the key with the corresponding value", func() {
				requestedResource := &models.Resource{Key: "test", Value: "test-data", Owner: "jim", Type: "lock"}
				expectedResource := &models.Resource{Key: "test", Value: "test-data", Owner: "jim", Type: "lock", TypeCode: models.LOCK}
				_, err := locketClient.Lock(context.Background(), &models.LockRequest{
					Resource:     requestedResource,
					TtlInSeconds: 10,
				})
				Expect(err).NotTo(HaveOccurred())

				resp, err := locketClient.Fetch(context.Background(), &models.FetchRequest{Key: "test"})
				Expect(err).NotTo(HaveOccurred())
				Expect(resp.Resource).To(BeEquivalentTo(expectedResource))

				requestedResource = &models.Resource{Key: "test", Value: "test-data", Owner: "nima", Type: "lock"}
				_, err = locketClient.Lock(context.Background(), &models.LockRequest{
					Resource:     requestedResource,
					TtlInSeconds: 10,
				})
				Expect(err).To(HaveOccurred())
			})

			It("logs the uuid of the request", func() {
				requestedResource := &models.Resource{Key: "test", Value: "test-data", Owner: "jim", Type: "lock"}
				ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("uuid", "some-uuid"))
				_, err := locketClient.Lock(ctx, &models.LockRequest{
					Resource:     requestedResource,
					TtlInSeconds: 10,
				})
				Expect(err).NotTo(HaveOccurred())

				Eventually(locketRunner).Should(gbytes.Say("some-uuid"))
			})

			It("expires after a ttl", func() {
				requestedResource := &models.Resource{Key: "test", Value: "test-data", Owner: "jim", Type: "lock"}
				_, err := locketClient.Lock(context.Background(), &models.LockRequest{
					Resource:     requestedResource,
					TtlInSeconds: 6,
				})
				Expect(err).NotTo(HaveOccurred())

				Eventually(func() error {
					_, err := locketClient.Fetch(context.Background(), &models.FetchRequest{Key: "test"})
					return err
				}, 10*time.Second).Should(HaveOccurred())
			})

			Context("when the lock server disappears unexpectedly", func() {
				It("still disappears after ~ the ttl", func() {
					requestedResource := &models.Resource{Key: "test", Value: "test-data", Owner: "jim", Type: "lock"}
					_, err := locketClient.Lock(context.Background(), &models.LockRequest{
						Resource:     requestedResource,
						TtlInSeconds: 3,
					})
					Expect(err).NotTo(HaveOccurred())

					ginkgomon.Kill(locketProcess)

					// cannot reuse the runner otherwise a `exec: already started` error will occur
					locketRunner = testrunner.NewLocketRunner(locketBinPath, configOverrides...)
					locketProcess = ginkgomon.Invoke(locketRunner)

					Eventually(func() error {
						_, err := locketClient.Fetch(context.Background(), &models.FetchRequest{Key: "test"})
						return err
					}, 6*time.Second).Should(HaveOccurred())
				})
			})
		})

		Context("Release", func() {
			var requestedResource *models.Resource

			Context("when the lock does not exist", func() {
				It("does not throw an error releasing the lock", func() {
					requestedResource = &models.Resource{Key: "test", Value: "test-data", Owner: "jim", Type: "lock"}
					_, err := locketClient.Release(context.Background(), &models.ReleaseRequest{Resource: requestedResource})
					Expect(err).NotTo(HaveOccurred())
				})
			})

			Context("when the lock exists", func() {
				JustBeforeEach(func() {
					requestedResource = &models.Resource{Key: "test", Value: "test-data", Owner: "jim", Type: "lock", TypeCode: models.LOCK}
					_, err := locketClient.Lock(context.Background(), &models.LockRequest{Resource: requestedResource, TtlInSeconds: 10})
					Expect(err).NotTo(HaveOccurred())

					resp, err := locketClient.Fetch(context.Background(), &models.FetchRequest{Key: "test"})
					Expect(err).NotTo(HaveOccurred())
					Expect(resp.Resource).To(BeEquivalentTo(requestedResource))
				})

				It("releases the lock", func() {
					_, err := locketClient.Release(context.Background(), &models.ReleaseRequest{Resource: requestedResource})
					Expect(err).NotTo(HaveOccurred())

					_, err = locketClient.Fetch(context.Background(), &models.FetchRequest{Key: "test"})
					Expect(err).To(HaveOccurred())
				})

				Context("when another process is the lock owner", func() {
					It("throws an error", func() {
						requestedResource = &models.Resource{Key: "test", Value: "test-data", Owner: "nima", Type: "lock"}
						_, err := locketClient.Release(context.Background(), &models.ReleaseRequest{Resource: requestedResource})
						Expect(err).To(HaveOccurred())
					})
				})
			})
		})

		Context("FetchAll", func() {
			var (
				resource1, resource2, resource3, resource4 *models.Resource
			)

			JustBeforeEach(func() {
				_, err := locketClient.Lock(context.Background(), &models.LockRequest{
					Resource:     resource1,
					TtlInSeconds: 10,
				})
				Expect(err).NotTo(HaveOccurred())

				_, err = locketClient.Lock(context.Background(), &models.LockRequest{
					Resource:     resource2,
					TtlInSeconds: 10,
				})
				Expect(err).NotTo(HaveOccurred())

				_, err = locketClient.Lock(context.Background(), &models.LockRequest{
					Resource:     resource3,
					TtlInSeconds: 10,
				})
				Expect(err).NotTo(HaveOccurred())

				_, err = locketClient.Lock(context.Background(), &models.LockRequest{
					Resource:     resource4,
					TtlInSeconds: 10,
				})
				Expect(err).NotTo(HaveOccurred())
			})

			Context("when using type strings", func() {
				BeforeEach(func() {
					resource1 = &models.Resource{Key: "test-lock1", Value: "test-data", Owner: "jim", Type: "lock", TypeCode: models.LOCK}
					resource2 = &models.Resource{Key: "test-lock2", Value: "test-data", Owner: "jim", Type: "lock", TypeCode: models.LOCK}
					resource3 = &models.Resource{Key: "test-presence1", Value: "test-data", Owner: "jim", Type: "presence", TypeCode: models.PRESENCE}
					resource4 = &models.Resource{Key: "test-presence2", Value: "test-data", Owner: "jim", Type: "presence", TypeCode: models.PRESENCE}
				})

				It("fetches all the locks corresponding to type code", func() {
					_, err := locketClient.FetchAll(context.Background(), &models.FetchAllRequest{})
					Expect(err).To(HaveOccurred())
				})

				It("fetches all the locks corresponding to type code", func() {
					response, err := locketClient.FetchAll(context.Background(), &models.FetchAllRequest{Type: models.LockType})
					Expect(err).NotTo(HaveOccurred())
					Expect(response.Resources).To(ConsistOf(resource1, resource2))
				})

				It("fetches all the presences corresponding to type", func() {
					response, err := locketClient.FetchAll(context.Background(), &models.FetchAllRequest{Type: models.PresenceType})
					Expect(err).NotTo(HaveOccurred())
					Expect(response.Resources).To(ConsistOf(resource3, resource4))
				})
			})

			Context("when using type code", func() {
				var expectedResource1, expectedResource2, expectedResource3, expectedResource4 *models.Resource

				BeforeEach(func() {
					resource1 = &models.Resource{Key: "test-lock1", Value: "test-data", Owner: "jim", TypeCode: models.LOCK}
					resource2 = &models.Resource{Key: "test-lock2", Value: "test-data", Owner: "jim", TypeCode: models.LOCK}
					resource3 = &models.Resource{Key: "test-presence1", Value: "test-data", Owner: "jim", TypeCode: models.PRESENCE}
					resource4 = &models.Resource{Key: "test-presence2", Value: "test-data", Owner: "jim", TypeCode: models.PRESENCE}

					expectedResource1 = &models.Resource{Key: "test-lock1", Value: "test-data", Owner: "jim", TypeCode: models.LOCK, Type: models.LockType}
					expectedResource2 = &models.Resource{Key: "test-lock2", Value: "test-data", Owner: "jim", TypeCode: models.LOCK, Type: models.LockType}
					expectedResource3 = &models.Resource{Key: "test-presence1", Value: "test-data", Owner: "jim", TypeCode: models.PRESENCE, Type: models.PresenceType}
					expectedResource4 = &models.Resource{Key: "test-presence2", Value: "test-data", Owner: "jim", TypeCode: models.PRESENCE, Type: models.PresenceType}
				})

				It("fetches all the locks corresponding to type code", func() {
					response, err := locketClient.FetchAll(context.Background(), &models.FetchAllRequest{TypeCode: models.LOCK})
					Expect(err).NotTo(HaveOccurred())
					Expect(response.Resources).To(ConsistOf(expectedResource1, expectedResource2))
				})

				It("fetches all the presences corresponding to type", func() {
					response, err := locketClient.FetchAll(context.Background(), &models.FetchAllRequest{TypeCode: models.PRESENCE})
					Expect(err).NotTo(HaveOccurred())
					Expect(response.Resources).To(ConsistOf(expectedResource3, expectedResource4))
				})
			})

			Context("if the table disappears", func() {
				BeforeEach(func() {
					resource1 = &models.Resource{Key: "test-lock1", Value: "test-data", Owner: "jim", TypeCode: models.LOCK}
					resource2 = &models.Resource{Key: "test-lock2", Value: "test-data", Owner: "jim", TypeCode: models.LOCK}
					resource3 = &models.Resource{Key: "test-presence1", Value: "test-data", Owner: "jim", TypeCode: models.PRESENCE}
					resource4 = &models.Resource{Key: "test-presence2", Value: "test-data", Owner: "jim", TypeCode: models.PRESENCE}
				})

				JustBeforeEach(func() {
					_, err := sqlRunner.DB().Exec("DROP TABLE locks")
					Expect(err).NotTo(HaveOccurred())
					_, err = locketClient.FetchAll(context.Background(), &models.FetchAllRequest{Type: models.LockType})
					Expect(err).To(HaveOccurred())
				})

				AfterEach(func() {
					sqlRunner.DB().Close()
					sqlProcess = ginkgomon.Invoke(sqlRunner)
				})

				It("exits", func() {
					Eventually(locketRunner).Should(gbytes.Say("unrecoverable-error"))
					Eventually(locketProcess.Wait()).Should(Receive())
				})
			})
		})
	})
})
