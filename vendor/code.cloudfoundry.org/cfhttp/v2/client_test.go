package cfhttp_test

import (
	"crypto/tls"
	"net/http"
	"time"

	"code.cloudfoundry.org/cfhttp/v2"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/ghttp"
)

var _ = Describe("NewClient", func() {
	var server *ghttp.Server

	BeforeEach(func() {
		server = ghttp.NewServer()
		server.AppendHandlers(
			ghttp.RespondWith(http.StatusOK, nil),
		)
	})

	AfterEach(func() {
		server.Close()
	})

	It("returns an HTTP client with default settings", func() {
		client := cfhttp.NewClient()
		transport := client.Transport.(*http.Transport)
		Expect(transport.DialContext).NotTo(BeNil())
		Expect(transport.IdleConnTimeout).To(Equal(90 * time.Second))
		Expect(transport.DisableKeepAlives).To(BeFalse())
	})

	It("returns an HTTP client that works on an HTTP Client", func() {
		client := cfhttp.NewClient()
		resp, err := client.Get(server.URL())
		Expect(err).NotTo(HaveOccurred())
		Expect(resp.StatusCode).To(Equal(http.StatusOK))
	})

	Describe(`with the "WithStreaming" option`, func() {
		It("returns an HTTP client with streaming default settings", func() {
			client := cfhttp.NewClient(cfhttp.WithStreamingDefaults())
			transport := client.Transport.(*http.Transport)
			Expect(transport.DialContext).NotTo(BeNil())
			Expect(transport.IdleConnTimeout).To(Equal(90 * time.Second))
			Expect(transport.DisableKeepAlives).To(BeFalse())
		})
	})

	Describe(`with the "WithRequestTimeout" option`, func() {
		It("returns an HTTP client with a custom request timeout", func() {
			client := cfhttp.NewClient(cfhttp.WithRequestTimeout(1 * time.Nanosecond))
			Expect(client.Timeout).To(Equal(1 * time.Nanosecond))
		})
	})

	Describe(`with the "WithDialTimeout" option`, func() {
		It("returns an HTTP client with a custom DialTimeout", func() {
			client := cfhttp.NewClient(cfhttp.WithDialTimeout(1 * time.Nanosecond))
			_, err := client.Get("https://google.com")
			Expect(err).To(HaveOccurred())
		})
	})

	Describe(`with the "WithTCPKeepAliveTimeout" option`, func() {
		It("returns an HTTP client with a custom TCP keepalive timeout", func() {
			// I don't think there's an easy way to test this behavior
			client := cfhttp.NewClient(
				cfhttp.WithStreamingDefaults(),
				cfhttp.WithTCPKeepAliveTimeout(10*time.Second),
			)
			transport := client.Transport.(*http.Transport)
			Expect(transport.DialContext).NotTo(BeNil())
		})
	})

	Describe(`with the "WithIdleConnTimeout" option`, func() {
		It("returns an HTTP client with a custom IdleConnTimeout", func() {
			client := cfhttp.NewClient(cfhttp.WithIdleConnTimeout(10 * time.Second))
			transport := client.Transport.(*http.Transport)
			Expect(transport.IdleConnTimeout).To(Equal(10 * time.Second))
			Expect(transport.DisableKeepAlives).To(BeFalse())
		})
	})

	Describe(`with the "WithDisableKeepAlives" option`, func() {
		It("returns an HTTP client with HTTP keepalives disabled", func() {
			client := cfhttp.NewClient(cfhttp.WithDisableKeepAlives())
			transport := client.Transport.(*http.Transport)
			Expect(transport.DisableKeepAlives).To(BeTrue())
		})
	})

	Describe(`with the "WithTLSConfig" option`, func() {
		It("returns a transport with the TLS config set", func() {
			t := &tls.Config{
				ServerName: "test-server.com",
			}
			client := cfhttp.NewClient(cfhttp.WithTLSConfig(t))
			transport := client.Transport.(*http.Transport)
			Expect(transport.TLSClientConfig).To(Equal(t))
		})
	})

	Describe(`with the "WithMaxIdleConnsPerHost" option`, func() {
		It("returns a transport with the MaxIdleConnsPerHost set", func() {
			client := cfhttp.NewClient(cfhttp.WithMaxIdleConnsPerHost(100))
			transport := client.Transport.(*http.Transport)
			Expect(transport.MaxIdleConnsPerHost).To(Equal(100))
		})
	})
})
