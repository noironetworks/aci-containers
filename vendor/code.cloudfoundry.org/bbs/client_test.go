package bbs_test

import (
	"net/http"
	"os"
	"path"
	"time"

	"code.cloudfoundry.org/bbs"
	"code.cloudfoundry.org/bbs/models"
	"code.cloudfoundry.org/lager"
	"code.cloudfoundry.org/lager/lagertest"
	"code.cloudfoundry.org/tlsconfig"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/ghttp"
)

var _ = Describe("Client", func() {
	var (
		bbsServer *ghttp.Server
		client    bbs.Client
		cfg       bbs.ClientConfig
		logger    lager.Logger
	)

	BeforeEach(func() {
		bbsServer = ghttp.NewServer()
		cfg = bbs.ClientConfig{
			URL:     bbsServer.URL(),
			Retries: 1,
		}

		logger = lagertest.NewTestLogger("bbs-client")
	})

	AfterEach(func() {
		bbsServer.CloseClientConnections()
		bbsServer.Close()
	})

	JustBeforeEach(func() {
		var err error
		client, err = bbs.NewClientWithConfig(cfg)
		Expect(err).ToNot(HaveOccurred())
	})

	Context("when the request timeout is explicitly set", func() {
		Context("when the client is not configured to use TLS", func() {
			BeforeEach(func() {
				cfg.RequestTimeout = 2 * time.Second

				bbsServer.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest("POST", "/v1/actual_lrp_groups/list"),
						func(w http.ResponseWriter, req *http.Request) {
							time.Sleep(cfg.RequestTimeout * 2)
						},
						ghttp.RespondWith(418, nil),
					),
				)
			})

			It("respects the request timeout", func() {
				_, err := client.ActualLRPGroups(logger, models.ActualLRPFilter{})
				Expect(err.Error()).To(ContainSubstring("request canceled"))
			})
		})

		Context("when the client is configured to use TLS", func() {
			var tlsServer *ghttp.Server

			BeforeEach(func() {
				basePath := path.Join(os.Getenv("GOPATH"), "src/code.cloudfoundry.org/bbs/cmd/bbs/fixtures")
				caFile := path.Join(basePath, "green-certs", "server-ca.crt")

				cfg.IsTLS = true
				cfg.CAFile = caFile
				cfg.CertFile = path.Join(basePath, "green-certs", "client.crt")
				cfg.KeyFile = path.Join(basePath, "green-certs", "client.key")
				cfg.RequestTimeout = 2 * time.Second

				tlsServer = ghttp.NewUnstartedServer()

				tlsConfig, err := tlsconfig.Build(
					tlsconfig.WithInternalServiceDefaults(),
					tlsconfig.WithIdentityFromFile(
						path.Join(basePath, "green-certs", "server.crt"),
						path.Join(basePath, "green-certs", "server.key"),
					),
				).Server(tlsconfig.WithClientAuthenticationFromFile(caFile))
				Expect(err).NotTo(HaveOccurred())

				tlsServer.HTTPTestServer.TLS = tlsConfig
				tlsServer.HTTPTestServer.StartTLS()
				cfg.URL = tlsServer.URL()

				tlsServer.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest("POST", "/v1/actual_lrp_groups/list"),
						func(w http.ResponseWriter, req *http.Request) {
							time.Sleep(cfg.RequestTimeout * 2)
						},
						ghttp.RespondWith(418, nil),
					),
				)
			})

			AfterEach(func() {
				tlsServer.CloseClientConnections()
				tlsServer.Close()
			})

			It("respects the request timeout", func() {
				_, err := client.ActualLRPGroups(logger, models.ActualLRPFilter{})
				Expect(err.Error()).To(ContainSubstring("request canceled"))
			})
		})
	})

	Context("when the server responds successfully after some time", func() {
		var (
			serverTimeout time.Duration
			blockCh       chan struct{}
		)

		BeforeEach(func() {
			serverTimeout = 30 * time.Millisecond
			blockCh = make(chan struct{}, 1)
		})

		AfterEach(func() {
			close(blockCh)
		})

		JustBeforeEach(func() {
			bbsServer.AppendHandlers(
				ghttp.CombineHandlers(
					ghttp.VerifyRequest("POST", "/v1/actual_lrp_groups/list"),
					func(w http.ResponseWriter, req *http.Request) {
						<-blockCh
					},
					ghttp.RespondWithProto(200, &models.ActualLRPGroupsResponse{
						ActualLrpGroups: []*models.ActualLRPGroup{
							{
								Instance: &models.ActualLRP{
									State: "running",
								},
							},
						},
					}),
				),
			)
		})

		It("returns the successful response", func() {
			go func() {
				defer GinkgoRecover()

				time.Sleep(serverTimeout)
				Eventually(blockCh).Should(BeSent(struct{}{}))
			}()

			lrps, err := client.ActualLRPGroups(logger, models.ActualLRPFilter{})
			Expect(err).ToNot(HaveOccurred())
			Expect(lrps).To(ConsistOf(&models.ActualLRPGroup{
				Instance: &models.ActualLRP{
					State: "running",
				},
			}))
		})

		Context("when the client is configured with a small timeout", func() {
			BeforeEach(func() {
				cfg.RequestTimeout = 20 * time.Millisecond
			})

			It("fails the request with a timeout error", func() {
				_, err := client.ActualLRPGroups(logger, models.ActualLRPFilter{})
				var apiError *models.Error
				Expect(err).To(HaveOccurred())
				Expect(err).To(BeAssignableToTypeOf(apiError))
				apiError = err.(*models.Error)
				Expect(apiError.Type).To(Equal(models.Error_Timeout))
			})
		})
	})

	Context("when the server responds with a 500", func() {
		JustBeforeEach(func() {
			bbsServer.AppendHandlers(
				ghttp.CombineHandlers(
					ghttp.VerifyRequest("POST", "/v1/actual_lrp_groups/list"),
					ghttp.RespondWith(500, nil),
				),
			)
		})

		It("returns the error", func() {
			_, err := client.ActualLRPGroups(logger, models.ActualLRPFilter{})
			Expect(err).To(HaveOccurred())
			responseError := err.(*models.Error)
			Expect(responseError.Type).To(Equal(models.Error_InvalidResponse))
		})
	})

	Context("when an http URL is provided to the secure client", func() {
		It("creating the client returns an error", func() {
			_, err := bbs.NewClient(bbsServer.URL(), "", "", "", 1, 1)
			Expect(err).To(MatchError("Expected https URL"))
		})
	})
})
