package tlsconfig

import (
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"code.cloudfoundry.org/tlsconfig/certtest"
)

func TestEmptyPool(t *testing.T) {
	t.Parallel()
	pool, err := FromEmptyPool().Build()
	if err != nil {
		t.Fatalf("unexpected error when building empty pool: %q", err)
	}

	if size := len(pool.Subjects()); size != 0 {
		t.Errorf("expected pool to be empty but it had %d certificates", size)
	}
}

func TestSystemPool(t *testing.T) {
	t.Parallel()
	pool, err := FromSystemPool().Build()
	if err != nil {
		t.Fatalf("unexpected error when building system pool: %q", err)
	}

	if size := len(pool.Subjects()); size == 0 {
		t.Error("expected pool to contain something but it did not")
	}
}

func TestWithCert(t *testing.T) {
	t.Parallel()

	auth, err := certtest.BuildCA("theauthority")
	if err != nil {
		t.Fatalf("failed to create CA: %s", err)
	}

	cert, err := auth.Certificate()
	if err != nil {
		t.Fatalf("failed to create certificate: %s", err)
	}

	pool, err := FromEmptyPool(
		WithCert(cert),
	).Build()
	if err != nil {
		t.Fatalf("unexpected error when building pool: %q", err)
	}

	if want, have := 1, len(pool.Subjects()); have != want {
		t.Errorf("expected pool to have size %d but it had %d certificates", want, have)
	}

	if s, subj := "theauthority", string(pool.Subjects()[0]); !strings.Contains(subj, s) {
		t.Errorf("pool should have contained cert with subject %q but it was acutally %q", s, subj)
	}
}

func TestLoadCertsFromFile(t *testing.T) {
	t.Parallel()

	auth, err := certtest.BuildCA("authority")
	if err != nil {
		t.Fatalf("failed to create CA: %s", err)
	}

	cert1, err := auth.BuildSignedCertificate("cert1")
	if err != nil {
		t.Fatalf("failed to create certificate: %s", err)
	}

	cert1Pem, _, err := cert1.CertificatePEMAndPrivateKey()
	if err != nil {
		t.Fatalf("failed to PEM-encode certificate: %s", err)
	}

	cert2, err := auth.BuildSignedCertificate("cert2")
	if err != nil {
		t.Fatalf("failed to create certificate: %s", err)
	}

	cert2Pem, _, err := cert2.CertificatePEMAndPrivateKey()
	if err != nil {
		t.Fatalf("failed to PEM-encode certificate: %s", err)
	}

	f, err := ioutil.TempFile("", "tlsconfig_authority")
	if err != nil {
		t.Fatalf("failed to create temporary certificate file: %s", err)
	}

	if _, err := f.Write(cert1Pem); err != nil {
		t.Fatalf("failed to write PEM to file: %s", err)
	}

	if _, err := f.Write(cert2Pem); err != nil {
		t.Fatalf("failed to write PEM to file: %s", err)
	}

	if err := f.Close(); err != nil {
		t.Fatalf("failed to close certificate file: %s", err)
	}
	defer os.Remove(f.Name())

	pool, err := FromEmptyPool(
		WithCertsFromFile(f.Name()),
	).Build()
	if err != nil {
		t.Fatalf("unexpected error when building pool: %q", err)
	}

	// We add 2 certificates to the pool from the file.
	if want, have := 2, len(pool.Subjects()); have != want {
		t.Errorf("expected pool to have size %d but it had %d certificates", want, have)
	}

	if s, subj := "cert1", string(pool.Subjects()[0]); !strings.Contains(subj, s) {
		t.Errorf("pool should have contained cert with subject %q but it was acutally %q", s, subj)
	}

	if s, subj := "cert2", string(pool.Subjects()[1]); !strings.Contains(subj, s) {
		t.Errorf("pool should have contained cert with subject %q but it was acutally %q", s, subj)
	}
}
