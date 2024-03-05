// Copyright 2017 Cisco Systems, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package apicapi

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHash(t *testing.T) {
	method := "GET"
	url := "/api/resource"
	body := []byte("request body")

	expectedHash := sha256.Sum256([]byte(method + url + string(body)))

	result := hash(method, url, body)

	assert.Equal(t, expectedHash[:], result)
}

func TestSign(t *testing.T) {
	method := "POST"
	url := "/api/resource"
	body := []byte("request body")

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	s := &signer{key: key}

	expectedHash := sha256.Sum256([]byte(method + url + string(body)))
	expectedSig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, expectedHash[:])
	if err != nil {
		t.Fatalf("Failed to calculate expected signature: %v", err)
	}
	expectedSigStr := base64.StdEncoding.EncodeToString(expectedSig)

	sig, err := s.sign(method, url, body)
	if err != nil {
		t.Fatalf("Failed to sign request: %v", err)
	}

	assert.Equal(t, expectedSigStr, sig)

	type test struct {
		name string
	}
	t_type := &test{name: "test"}
	s = &signer{key: t_type}
	_, err = s.sign(method, url, body)
	assert.Equal(t, "Unsupported key type", err.Error())
}

func generatePrivateKeyPEM() ([]byte, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	privateKeyBytes, _ := x509.MarshalPKCS8PrivateKey(privateKey)
	pemBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	return pem.EncodeToMemory(pemBlock), nil
}

func generatePKCS1PrivateKeyPEM() ([]byte, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	return pem.EncodeToMemory(pemBlock), nil
}

func generateInvalidKeyTypePEM() ([]byte, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	privateKeyBytes, _ := x509.MarshalPKCS8PrivateKey(privateKey)
	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: privateKeyBytes,
	}

	return pem.EncodeToMemory(pemBlock), nil
}

func generateUnsupportedPrivateKeyPEM() ([]byte, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	privateKeyBytes, _ := x509.MarshalPKCS8PrivateKey(privateKey)
	pemBlock := &pem.Block{
		Type:  "ECDSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	return pem.EncodeToMemory(pemBlock), nil
}

func TestNewSigner(t *testing.T) {
	t.Run("Valid PKCS8 Private Key", func(t *testing.T) {
		validPKCS8PrivateKey, _ := generatePrivateKeyPEM()
		result, err := newSigner(validPKCS8PrivateKey)
		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}
		assert.Equal(t, &signer{key: result.key}, result)
	})

	t.Run("Valid PKCS1 Private Key (RSA)", func(t *testing.T) {
		validPKCS1PrivateKey, _ := generatePKCS1PrivateKeyPEM()
		result, err := newSigner(validPKCS1PrivateKey)
		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}
		assert.Equal(t, &signer{key: result.key}, result)
	})

	t.Run("Invalid Private Key (Not Decodable)", func(t *testing.T) {
		invalidPrivateKey := []byte(`-----BEGIN PRIVATE KEY-----
			InvalidKeyData
			-----END PRIVATE KEY-----`)
		result, err := newSigner(invalidPrivateKey)
		if err == nil || !strings.Contains(err.Error(), "Could not decode PEM file") {
			t.Errorf("Expected decoding error, got %v", err)
		}
		assert.Nil(t, result)
	})

	t.Run("Invalid Key Type in PEM", func(t *testing.T) {
		invalidKeyType, _ := generateInvalidKeyTypePEM()
		result, err := newSigner(invalidKeyType)
		if err == nil || !strings.Contains(err.Error(), "PEM file does not contain private key") {
			t.Errorf("Expected unsupported key type error, got %v", err)
		}
		assert.Nil(t, result)
	})

	t.Run("Empty PEM", func(t *testing.T) {
		emptyPEM := []byte(``)
		result, err := newSigner(emptyPEM)
		if err == nil || !strings.Contains(err.Error(), "Could not decode PEM file") {
			t.Errorf("Expected decoding error, got %v", err)
		}
		assert.Nil(t, result)
	})

	t.Run("No PEM Block", func(t *testing.T) {
		noPEMBlock := []byte(`Not a PEM block`)
		result, err := newSigner(noPEMBlock)
		if err == nil || !strings.Contains(err.Error(), "Could not decode PEM file") {
			t.Errorf("Expected decoding error, got %v", err)
		}
		assert.Nil(t, result)
	})

	t.Run("Unsupported key type", func(t *testing.T) {
		unsupportedKey, _ := generateUnsupportedPrivateKeyPEM()
		result, err := newSigner(unsupportedKey)
		if err == nil || !strings.Contains(err.Error(), "Unsupported key type") {
			t.Errorf("Expected decoding error, got %v", err)
		}
		assert.Nil(t, result)
	})
}
