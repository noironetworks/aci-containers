package tlsconfig_test

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"code.cloudfoundry.org/tlsconfig"
	"code.cloudfoundry.org/tlsconfig/certtest"
)

type buildResult struct {
	name string
	err  error

	expectedErrPrefix string
}

func TestE2E(t *testing.T) {
	t.Parallel()

	ca, err := certtest.BuildCA("tlsconfig")
	if err != nil {
		t.Fatalf("failed to build CA: %v", err)
	}

	pool, err := ca.CertPool()
	if err != nil {
		t.Fatalf("failed to get CA cert pool: %v", err)
	}

	serverCrt, err := ca.BuildSignedCertificate("server")
	if err != nil {
		t.Fatalf("failed to make server certificate: %v", err)
	}
	serverTLSCrt, err := serverCrt.TLSCertificate()
	if err != nil {
		t.Fatalf("failed to get tls server certificate: %v", err)
	}

	clientCrt, err := ca.BuildSignedCertificate("client")
	if err != nil {
		t.Fatalf("failed to make client certificate: %v", err)
	}
	clientTLSCrt, err := clientCrt.TLSCertificate()
	if err != nil {
		t.Fatalf("failed to get tls client certificate: %v", err)
	}

	// Typically we would share a base configuration but here we're pretending
	// to be two different services.
	serverConf, err := tlsconfig.Build(
		tlsconfig.WithIdentity(serverTLSCrt),
	).Server(
		tlsconfig.WithClientAuthentication(pool),
	)
	if err != nil {
		t.Fatalf("failed to build server config: %v", err)
	}

	if serverConf.NameToCertificate == nil {
		t.Error("tls.Config.NameToCertificate should not be nil")
	}

	clientConf, err := tlsconfig.Build(
		tlsconfig.WithIdentity(clientTLSCrt),
	).Client(
		tlsconfig.WithAuthority(pool),
	)
	if err != nil {
		t.Fatalf("failed to build client config: %v", err)
	}

	if clientConf.NameToCertificate == nil {
		t.Error("tls.Config.NameToCertificate should not be nil")
	}

	testClientServerTLSConnection(t, clientConf, serverConf)
}

func TestE2EFromFile(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "")
	if err != nil {
		t.Fatalf("failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	ca, err := certtest.BuildCA("tlsconfig")
	if err != nil {
		t.Fatalf("failed to build CA: %v", err)
	}
	caFile, err := writeCAToTempFile(tempDir, ca)
	if err != nil {
		t.Fatalf("failed to write CA file: %v", err)
	}

	serverCertFile, serverKeyFile, err := generateKeypairToTempFilesFromCA(tempDir, ca, false)
	if err != nil {
		t.Fatalf("failed to generate certificate keypair: %v", err)
	}

	clientCertFile, clientKeyFile, err := generateKeypairToTempFilesFromCA(tempDir, ca, false)
	if err != nil {
		t.Fatalf("failed to generate certificate keypair: %v", err)
	}

	t.Parallel()

	// Typically we would share a base configuration but here we're pretending
	// to be two different services.
	serverConf, err := tlsconfig.Build(
		tlsconfig.WithIdentityFromFile(serverCertFile, serverKeyFile),
	).Server(
		tlsconfig.WithClientAuthenticationFromFile(caFile),
	)
	if err != nil {
		t.Fatalf("failed to build server config: %v", err)
	}

	clientConf, err := tlsconfig.Build(
		tlsconfig.WithIdentityFromFile(clientCertFile, clientKeyFile),
	).Client(
		tlsconfig.WithAuthorityFromFile(caFile),
	)
	if err != nil {
		t.Fatalf("failed to build client config: %v", err)
	}

	testClientServerTLSConnection(t, clientConf, serverConf)
}

func TestServerName(t *testing.T) {
	t.Parallel()

	ca, err := certtest.BuildCA("tlsconfig")
	if err != nil {
		t.Fatalf("failed to build CA: %v", err)
	}

	pool, err := ca.CertPool()
	if err != nil {
		t.Fatalf("failed to get CA cert pool: %v", err)
	}

	serverName := "oddservername"
	serverCrt, err := ca.BuildSignedCertificate("server", certtest.WithDomains(serverName))
	if err != nil {
		t.Fatalf("failed to make server certificate: %v", err)
	}
	serverTLSCrt, err := serverCrt.TLSCertificate()
	if err != nil {
		t.Fatalf("failed to get tls server certificate: %v", err)
	}

	clientCrt, err := ca.BuildSignedCertificate("client")
	if err != nil {
		t.Fatalf("failed to make client certificate: %v", err)
	}
	clientTLSCrt, err := clientCrt.TLSCertificate()
	if err != nil {
		t.Fatalf("failed to get tls client certificate: %v", err)
	}

	// Typically we would share a base configuration but here we're pretending
	// to be two different services.
	serverConf, err := tlsconfig.Build(
		tlsconfig.WithIdentity(serverTLSCrt),
	).Server(
		tlsconfig.WithClientAuthentication(pool),
	)
	if err != nil {
		t.Fatalf("failed to build server config: %v", err)
	}

	goodClientConf, err := tlsconfig.Build(
		tlsconfig.WithIdentity(clientTLSCrt),
	).Client(
		tlsconfig.WithAuthority(pool),
		tlsconfig.WithServerName(serverName),
	)
	if err != nil {
		t.Fatalf("failed to build client config: %v", err)
	}

	// works with correct server name
	testClientServerTLSConnection(t, goodClientConf, serverConf)

	// does not work without server name
	badClientConf, err := tlsconfig.Build(
		tlsconfig.WithIdentity(clientTLSCrt),
	).Client(
		tlsconfig.WithAuthority(pool),
		tlsconfig.WithServerName("badServerName"),
	)
	if err != nil {
		t.Fatalf("failed to build client config: %v", err)
	}
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "hello, world!")
	}))
	s.TLS = serverConf
	s.StartTLS()
	defer s.Close()

	transport := &http.Transport{TLSClientConfig: badClientConf}
	client := &http.Client{Transport: transport}

	_, err = client.Get(s.URL)
	if err == nil {
		t.Fatalf("expected to fail with invalid server name")
	}
}

func TestInternalDefaults(t *testing.T) {
	log.SetOutput(ioutil.Discard)
	t.Parallel()

	clientConfig, err := tlsconfig.Build(tlsconfig.WithInternalServiceDefaults()).Client()
	if err != nil {
		t.Fatalf("failed to build client config: %v", err)
	}
	serverConfig, err := tlsconfig.Build(tlsconfig.WithInternalServiceDefaults()).Server()
	if err != nil {
		t.Fatalf("failed to build server config: %v", err)
	}

	var tcs = []struct {
		name   string
		config *tls.Config
	}{
		{
			name:   "internal (client)",
			config: clientConfig,
		},
		{
			name:   "internal (server)",
			config: serverConfig,
		},
	}

	for _, tc := range tcs {
		tc := tc // capture variable
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			config := tc.config

			if have, want := config.PreferServerCipherSuites, true; have != want {
				t.Errorf("expected server cipher suites to be preferred; have: %t", have)
			}

			if have, want := config.MinVersion, uint16(tls.VersionTLS12); have != want {
				t.Errorf("expected TLS 1.2 to be the minimum version; want: %v, have: %v", want, have)
			}

			if have, want := config.MaxVersion, uint16(tls.VersionTLS12); have != want {
				t.Errorf("expected TLS 1.2 to be the maximum version; want: %v, have: %v", want, have)
			}

			wantSuites := []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			}
			if have, want := config.CipherSuites, wantSuites; !reflect.DeepEqual(have, want) {
				t.Errorf("expected a different set of ciphersuites; want: %v, have: %v", want, have)
			}

			h2Ciphersuite := tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
			if !contains(config.CipherSuites, h2Ciphersuite) {
				// https://http2.github.io/http2-spec/#rfc.section.9.2.2
				t.Errorf("expected the http2 required ciphersuite (%v) to be present; have: %v", h2Ciphersuite, config.CipherSuites)
			}
		})
	}
}

func TestExternalDefaults(t *testing.T) {
	log.SetOutput(ioutil.Discard)
	t.Parallel()

	clientConfig, err := tlsconfig.Build(tlsconfig.WithExternalServiceDefaults()).Client()
	if err != nil {
		t.Fatalf("failed to build client config: %v", err)
	}
	serverConfig, err := tlsconfig.Build(tlsconfig.WithExternalServiceDefaults()).Server()
	if err != nil {
		t.Fatalf("failed to build server config: %v", err)
	}

	var tcs = []struct {
		name   string
		config *tls.Config
	}{
		{
			name:   "external (client)",
			config: clientConfig,
		},
		{
			name:   "external (server)",
			config: serverConfig,
		},
	}

	for _, tc := range tcs {
		tc := tc // capture variable
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			config := tc.config

			if have, want := config.PreferServerCipherSuites, false; have != want {
				t.Errorf("expected server cipher suites not to be preferred; have: %t", have)
			}

			if have, want := config.MinVersion, uint16(tls.VersionTLS12); have != want {
				t.Errorf("expected TLS 1.2 to be the minimum version; want: %v, have: %v", want, have)
			}

			if have, want := config.MaxVersion, uint16(tls.VersionTLS12); have != want {
				t.Errorf("expected TLS 1.2 to be the maximum version; want: %v, have: %v", want, have)
			}

			wantSuites := []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			}
			if have, want := config.CipherSuites, wantSuites; !reflect.DeepEqual(have, want) {
				t.Errorf("expected a different set of ciphersuites; want: %v, have: %v", want, have)
			}

			h2Ciphersuite := tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
			if !contains(config.CipherSuites, h2Ciphersuite) {
				// https://http2.github.io/http2-spec/#rfc.section.9.2.2
				t.Errorf("expected the http2 required ciphersuite (%v) to be present; have: %v", h2Ciphersuite, config.CipherSuites)
			}
		})
	}
}

func TestLoadKeypairFails(t *testing.T) {
	t.Parallel()

	tempDir, err := ioutil.TempDir("", "")
	if err != nil {
		t.Fatalf("failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	ca, err := certtest.BuildCA("tlsconfig")
	if err != nil {
		t.Fatalf("failed to build CA: %v", err)
	}

	certFile, keyFile, err := generateKeypairToTempFilesFromCA(tempDir, ca, false)
	if err != nil {
		t.Fatalf("failed to generate certificate keypair: %v", err)
	}

	// generate file invalid for use as cert or key
	invalidFile, err := ioutil.TempFile(tempDir, "invalid")
	if err != nil {
		t.Fatalf("failed to create temp invalid-key: %v", err)
	}
	defer invalidFile.Close()

	if err := ioutil.WriteFile(invalidFile.Name(), []byte("invalid"), 0666); err != nil {
		t.Fatalf("failed to write invalid file: %v", err)
	}

	expiredCertFile, expiredKeyFile, err := generateKeypairToTempFilesFromCA(tempDir, ca, true)
	if err != nil {
		t.Fatalf("failed to generate expired certificate keypair: %v", err)
	}

	keypairs := []struct {
		name      string
		certFile  string
		keyFile   string
		errPrefix string
	}{
		{name: "cert file missing", certFile: "does not exist", keyFile: keyFile, errPrefix: "failed to load keypair"},
		{name: "cert file invalid", certFile: invalidFile.Name(), keyFile: keyFile, errPrefix: "failed to load keypair"},
		{name: "key file missing", certFile: certFile, keyFile: "does not exist", errPrefix: "failed to load keypair"},
		{name: "key file invalid", certFile: certFile, keyFile: invalidFile.Name(), errPrefix: "failed to load keypair"},
		{
			name:      "cert expired",
			certFile:  expiredCertFile,
			keyFile:   expiredKeyFile,
			errPrefix: "failed to load keypair: certificate has expired",
		},
	}

	var buildResults []buildResult
	for _, keypair := range keypairs {
		_, err := tlsconfig.Build(tlsconfig.WithIdentityFromFile(keypair.certFile, keypair.keyFile)).Client()
		buildResults = append(buildResults, buildResult{
			name: keypair.name + " (client)",
			err:  err,

			expectedErrPrefix: keypair.errPrefix,
		})
		_, err = tlsconfig.Build(tlsconfig.WithIdentityFromFile(keypair.certFile, keypair.keyFile)).Server()
		buildResults = append(buildResults, buildResult{
			name: keypair.name + " (server)",
			err:  err,

			expectedErrPrefix: keypair.errPrefix,
		})
	}

	for _, br := range buildResults {
		br := br // capture variable
		t.Run(br.name, func(t *testing.T) {
			t.Parallel()

			if br.err == nil {
				t.Fatal("building config should have errored")
			}
			if !strings.HasPrefix(br.err.Error(), br.expectedErrPrefix) {
				t.Fatalf("unexpected error prefix returned; have: %q, want: %q", br.err, br.expectedErrPrefix)
			}
		})
	}
}

func TestLoadCAFails(t *testing.T) {
	t.Parallel()

	_, clientCAErr := tlsconfig.Build().Client(tlsconfig.WithAuthorityFromFile("does not exist"))
	_, serverCAErr := tlsconfig.Build().Server(tlsconfig.WithClientAuthenticationFromFile("does not exist"))

	buildResults := []buildResult{
		{name: "CA cert file missing (client)", err: clientCAErr},
		{name: "CA cert file missing (server)", err: serverCAErr},
	}

	errStr := "failed to read certificate(s) at path"
	for _, br := range buildResults {
		br := br // capture variable
		t.Run(br.name, func(t *testing.T) {
			t.Parallel()

			if br.err == nil {
				t.Fatal("building config should have errored")
			}
			if !strings.HasPrefix(br.err.Error(), errStr) {
				t.Fatalf("unexpected error prefix returned; have: %v, want: '%s'", br.err, errStr)
			}
		})
	}
}

func TestCAInvalidFails(t *testing.T) {
	t.Parallel()

	invalidCAFile, err := ioutil.TempFile("", "invalid-CA")
	if err != nil {
		t.Fatalf("failed to create temp invalid-CA: %v", err)
	}
	defer invalidCAFile.Close()

	if err := ioutil.WriteFile(invalidCAFile.Name(), []byte("invalid"), 0666); err != nil {
		t.Fatalf("failed to write invalid-CA file: %v", err)
	}
	defer os.Remove(invalidCAFile.Name())

	_, clientCAErr := tlsconfig.Build().Client(
		tlsconfig.WithAuthorityBuilder(
			tlsconfig.FromEmptyPool(
				tlsconfig.WithCertsFromFile(invalidCAFile.Name()),
			),
		),
	)
	_, serverCAErr := tlsconfig.Build().Server(
		tlsconfig.WithClientAuthenticationBuilder(
			tlsconfig.FromEmptyPool(
				tlsconfig.WithCertsFromFile(invalidCAFile.Name()),
			),
		),
	)

	buildResults := []buildResult{
		{name: "CA cert file invalid (client)", err: clientCAErr},
		{name: "CA cert file invalid (server)", err: serverCAErr},
	}

	errStr := "no valid certificates read from file"
	for _, br := range buildResults {
		br := br // capture variable
		t.Run(br.name, func(t *testing.T) {
			t.Parallel()

			if br.err == nil {
				t.Fatal("building config should have errored")
			}
			if !strings.HasPrefix(br.err.Error(), errStr) {
				t.Fatalf("unexpected error prefix returned; have: %v, want: '%s'", br.err, errStr)
			}
		})
	}
}

func testClientServerTLSConnection(t *testing.T, clientConf, serverConf *tls.Config) {
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "hello, world!")
	}))
	s.TLS = serverConf
	s.StartTLS()
	defer s.Close()

	transport := &http.Transport{TLSClientConfig: clientConf}
	client := &http.Client{Transport: transport}

	res, err := client.Get(s.URL)
	if err != nil {
		t.Fatalf("failed to make request: %v", err)
	}
	bs, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("failed to read body: %v", err)
	}
	res.Body.Close()

	if have, want := bs, []byte("hello, world!"); !bytes.Equal(have, want) {
		t.Errorf("unexpected body returned; have: %q, want: %q", have, want)
	}
}

func writeCAToTempFile(tempDir string, ca *certtest.Authority) (string, error) {
	caBytes, err := ca.CertificatePEM()
	if err != nil {
		return "", fmt.Errorf("failed to get CA PEM encoding: %s", err)
	}

	caFile, err := ioutil.TempFile(tempDir, "CA")
	if err != nil {
		return "", fmt.Errorf("failed to create temp CA file: %s", err)
	}
	defer caFile.Close()

	if err := ioutil.WriteFile(caFile.Name(), caBytes, 0666); err != nil {
		return "", fmt.Errorf("failed to write CA file: %s", err)
	}

	return caFile.Name(), nil
}

func generateKeypairToTempFilesFromCA(tempDir string, ca *certtest.Authority, expired bool) (string, string, error) {
	var (
		cert *certtest.Certificate
		err  error
	)
	if expired {
		cert, err = ca.BuildSignedCertificateWithExpiry("cert", time.Now().Add(-10000))
	} else {
		cert, err = ca.BuildSignedCertificate("cert")
	}
	if err != nil {
		return "", "", fmt.Errorf("failed to make certificate keypair: %s", err)
	}

	certBytes, keyBytes, err := cert.CertificatePEMAndPrivateKey()
	if err != nil {
		return "", "", fmt.Errorf("failed to get cert and key bytes: %s", err)
	}

	keyFile, err := ioutil.TempFile(tempDir, "key")
	if err != nil {
		return "", "", fmt.Errorf("failed to create temp key file: %s", err)
	}
	defer keyFile.Close()

	if err := ioutil.WriteFile(keyFile.Name(), keyBytes, 0666); err != nil {
		return "", "", fmt.Errorf("failed to write key file: %s", err)
	}

	certFile, err := ioutil.TempFile(tempDir, "cert")
	if err != nil {
		return "", "", fmt.Errorf("failed to create temp cert file: %s", err)
	}
	defer certFile.Close()

	if err := ioutil.WriteFile(certFile.Name(), certBytes, 0666); err != nil {
		return "", "", fmt.Errorf("failed to write cert file: %s", err)
	}

	return certFile.Name(), keyFile.Name(), nil
}

func contains(haystack []uint16, needle uint16) bool {
	for _, e := range haystack {
		if e == needle {
			return true
		}
	}

	return false
}
