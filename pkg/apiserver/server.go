/***
Copyright 2018 Cisco Systems Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package apiserver

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	log "github.com/Sirupsen/logrus"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"github.com/noironetworks/aci-containers/pkg/objdb"
	"github.com/noironetworks/aci-containers/pkg/apicapi"
)

const (
	root       = "/aci/objdb"
	ListenPort = "8899"
	defToken   = "api-server-token"
)

var DefETCD = []string{"127.0.0.1:2379"}

type PostResp struct {
	URI string
}

type ListResp struct {
	URIs []string
}

type Server struct {
	objapi   objdb.API
	upgrader websocket.Upgrader
}

type loginHandler struct {
}

func (l *loginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	class := "aaaLogin"
	if r.Method == http.MethodGet {
		class = "webtokenSession"
	}
	result := map[string]interface{}{
		"imdata": []interface{}{
			map[string]interface{}{
				class: map[string]interface{}{
					"attributes": map[string]interface{}{
						"token": defToken,
					},
				},
			},
		},
	}
	json.NewEncoder(w).Encode(result)
}

type refreshSucc struct{}

func (h *refreshSucc) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	result := map[string]interface{}{}
	json.NewEncoder(w).Encode(result)
}

type socketHandler struct {
	srv *Server
}

func (h *socketHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c, err := h.srv.upgrader.Upgrade(w, r, nil)

	if err != nil {
		return
	}

	go func() {
		defer c.Close()

		for {
			_, _, err := c.ReadMessage()
			if _, k := err.(*websocket.CloseError); k {
				break
			}
		}
	}()
}

var LocalhostCert = []byte(`-----BEGIN CERTIFICATE-----
MIICEzCCAXygAwIBAgIQMIMChMLGrR+QvmQvpwAU6zANBgkqhkiG9w0BAQsFADAS
MRAwDgYDVQQKEwdBY21lIENvMCAXDTcwMDEwMTAwMDAwMFoYDzIwODQwMTI5MTYw
MDAwWjASMRAwDgYDVQQKEwdBY21lIENvMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCB
iQKBgQDuLnQAI3mDgey3VBzWnB2L39JUU4txjeVE6myuDqkM/uGlfjb9SjY1bIw4
iA5sBBZzHi3z0h1YV8QPuxEbi4nW91IJm2gsvvZhIrCHS3l6afab4pZBl2+XsDul
rKBxKKtD1rGxlG4LjncdabFn9gvLZad2bSysqz/qTAUStTvqJQIDAQABo2gwZjAO
BgNVHQ8BAf8EBAMCAqQwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDwYDVR0TAQH/BAUw
AwEB/zAuBgNVHREEJzAlggtleGFtcGxlLmNvbYcEfwAAAYcQAAAAAAAAAAAAAAAA
AAAAATANBgkqhkiG9w0BAQsFAAOBgQCEcetwO59EWk7WiJsG4x8SY+UIAA+flUI9
tyC4lNhbcF2Idq9greZwbYCqTTTr2XiRNSMLCOjKyI7ukPoPjo16ocHj+P3vZGfs
h1fIw3cSS2OolhloGw/XM6RWPWtPAlGykKLciQrBru5NAPvCMsb/I1DAceTiotQM
fblo6RBxUQ==
-----END CERTIFICATE-----`)

var LocalhostKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDuLnQAI3mDgey3VBzWnB2L39JUU4txjeVE6myuDqkM/uGlfjb9
SjY1bIw4iA5sBBZzHi3z0h1YV8QPuxEbi4nW91IJm2gsvvZhIrCHS3l6afab4pZB
l2+XsDulrKBxKKtD1rGxlG4LjncdabFn9gvLZad2bSysqz/qTAUStTvqJQIDAQAB
AoGAGRzwwir7XvBOAy5tM/uV6e+Zf6anZzus1s1Y1ClbjbE6HXbnWWF/wbZGOpet
3Zm4vD6MXc7jpTLryzTQIvVdfQbRc6+MUVeLKwZatTXtdZrhu+Jk7hx0nTPy8Jcb
uJqFk541aEw+mMogY/xEcfbWd6IOkp+4xqjlFLBEDytgbIECQQDvH/E6nk+hgN4H
qzzVtxxr397vWrjrIgPbJpQvBsafG7b0dA4AFjwVbFLmQcj2PprIMmPcQrooz8vp
jy4SHEg1AkEA/v13/5M47K9vCxmb8QeD/asydfsgS5TeuNi8DoUBEmiSJwma7FXY
fFUtxuvL7XvjwjN5B30pNEbc6Iuyt7y4MQJBAIt21su4b3sjXNueLKH85Q+phy2U
fQtuUE9txblTu14q3N7gHRZB4ZMhFYyDy8CKrN2cPg/Fvyt0Xlp/DoCzjA0CQQDU
y2ptGsuSmgUtWj3NM9xuwYPm+Z/F84K6+ARYiZ6PYj013sovGKUFfYAqVXVlxtIX
qyUBnu3X9ps8ZfjLZO7BAkEAlT4R5Yl6cGhaJQYZHOde3JEMhNRcVFMO8dJDaFeo
f9Oeos0UUothgiDktdQHxdNEwLjQf7lJJBzV+5OtwswCWA==
-----END RSA PRIVATE KEY-----`)

func getTLSCfg() (*tls.Config, error) {
	cfg := new(tls.Config)
	cert, err := tls.X509KeyPair(LocalhostCert, LocalhostKey)
	if err != nil {
		return nil, err
	}

	if cfg.NextProtos == nil {
		cfg.NextProtos = []string{"http/1.1"}
	}
	cfg.Certificates = []tls.Certificate{cert}
	return cfg, nil
}

type nfh struct {
}

func (n *nfh) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Errorf("+++ Request: %+v", r)
}
func StartNewServer(etcdURLs []string, listenPort string) ([]byte, error) {
	// create an etcd client

	log.Infof("=> Creating new client ..")
	ec, err := objdb.NewClient(etcdURLs, root)
	if err != nil {
		return nil, err
	}

	log.Infof("=> New client created..")
	s := &Server{objapi: ec}
	wHandler := func(w http.ResponseWriter, r *http.Request) {
		s.handleWrite(w, r)
	}
	rHandler := func(w http.ResponseWriter, r *http.Request) {
		s.handleRead(w, r)
	}

	r := mux.NewRouter()

	// add websocket handlers
	r.Handle("/api/webtokenSession.json", &loginHandler{})
	r.Handle("/api/aaaLogin.json", &loginHandler{})
	r.Handle("/api/aaaRefresh.json", &refreshSucc{})
	r.Handle(fmt.Sprintf("/socket%s", defToken), &socketHandler{srv: s})
	//r.PathPrefix("/api/node").HandlerFunc(wHandler)

	t := r.Headers("Content-Type", "application/json").Methods("POST").Subrouter()
	// gbp rest handlers
	addGBPPost(t)

	// api/mo handlers (apic stub)
	t.PathPrefix("/api/mo").HandlerFunc(wHandler)
	// Routes consist of a path and a handler function.
	delR := r.Methods("DELETE").Subrouter()
	addGBPDelete(delR)
	getR := r.Methods("GET").Subrouter()
	addGBPGet(getR)
	getR.PathPrefix("/api/mo").HandlerFunc(rHandler)
	getR.PathPrefix("/api/node").HandlerFunc(rHandler)
	getR.PathPrefix("/api/class").HandlerFunc(rHandler)
	r.Methods("POST").Subrouter().PathPrefix("/api/node").HandlerFunc(wHandler)
	r.NotFoundHandler = &nfh{}
	tlsCfg, err := getTLSCfg()
	if err != nil {
		return nil, err
	}
	//	tlsCfg.BuildNameToCertificate()

	go func() {
		log.Infof("=> Listening at %s", listenPort)
		tlsSrv := http.Server{Addr: listenPort, Handler: r, TLSConfig: tlsCfg}
		// Bind to a port and pass our router in
		log.Fatal(tlsSrv.ListenAndServeTLS("", ""))
	}()
	return tlsCfg.Certificates[0].Certificate[0], nil
}

func (s *Server) handleWrite(w http.ResponseWriter, r *http.Request) {
	uri := r.URL.RequestURI()
	log.Infof("handleWrite: %s", uri)
	content, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = s.objapi.SetRaw(uri, content)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleRead(w http.ResponseWriter, r *http.Request) {
	uri := r.URL.RequestURI()

	log.Infof("handleRead: %s", uri)
	content, err := s.objapi.GetRaw(uri)
	if err != nil {
	//	http.Error(w, err.Error(), http.StatusInternalServerError)
	//	return
		nullResp := &apicapi.ApicResponse{
                SubscriptionId: "4-3-3",
        	}
		content, _ = json.Marshal(nullResp)
	}

	w.Header().Set("Content-Type", "application/json")

	// write the HTTP status code
	w.WriteHeader(http.StatusOK)
	w.Write(content)
}

func addGBPPost(mr *mux.Router) {
	mr.PathPrefix("/gbp/contracts").HandlerFunc(MakeHTTPHandler(postContract))
	mr.PathPrefix("/gbp/epgs").HandlerFunc(MakeHTTPHandler(postEpg))
	mr.PathPrefix("/gbp/endpoints").HandlerFunc(MakeHTTPHandler(postEndpoint))
}

func addGBPGet(mr *mux.Router) {
	//	mr.PathPrefix("/gbp/contracts/").HandlerFunc(MakeHTTPHandler(listContracts))
	//	mr.PathPrefix("/gbp/contracts/{key}").HandlerFunc(MakeHTTPHandler(getContract))
	mr.Path("/gbp/epgs/").HandlerFunc(MakeHTTPHandler(listEpgs))
	mr.Path("/gbp/epg/").HandlerFunc(MakeHTTPHandler(getEpg))
	mr.Path("/gbp/endpoints/").HandlerFunc(MakeHTTPHandler(listEndpoints))
	mr.Path("/gbp/endpoint/").HandlerFunc(MakeHTTPHandler(getEndpoint))
}

func addGBPDelete(mr *mux.Router) {
	mr.Path("/gbp/contract/").HandlerFunc(MakeHTTPHandler(deleteObject))
	mr.Path("/gbp/epg/").HandlerFunc(MakeHTTPHandler(deleteObject))
	mr.Path("/gbp/endpoint/").HandlerFunc(MakeHTTPHandler(deleteEndpoint))
}
