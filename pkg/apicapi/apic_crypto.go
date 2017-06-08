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
	"errors"
	"strings"
)

type signer struct {
	key interface{}
}

func hash(method string, url string, body []byte) []byte {
	h := sha256.New()
	h.Write([]byte(method))
	h.Write([]byte(url))
	if body != nil {
		h.Write(body)
	}
	return h.Sum(nil)
}

func (s *signer) sign(method string, url string,
	body []byte) (sig string, err error) {
	h := hash(method, url, body)

	var raw []byte
	switch k := s.key.(type) {
	case *rsa.PrivateKey:
		raw, err = rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, h)
		if err != nil {
			return
		}
	default:
		err = errors.New("Unsupported key type")
		return
	}

	//fmt.Println("s ", method, " ", url, " ",
	//	base64.StdEncoding.EncodeToString(h))

	sig = base64.StdEncoding.EncodeToString(raw)
	return
}

func newSigner(privKey []byte) (*signer, error) {
	block, _ := pem.Decode(privKey)
	if block == nil {
		return nil, errors.New("Could not decode PEM file")
	}
	if !strings.HasSuffix(block.Type, "PRIVATE KEY") {
		return nil, errors.New("PEM file does not contain private key")
	}
	s := &signer{}
	switch block.Type {
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		s.key = key
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		s.key = key
	default:
		return nil, errors.New("Unsupported key type: " + block.Type)
	}
	return s, nil
}
