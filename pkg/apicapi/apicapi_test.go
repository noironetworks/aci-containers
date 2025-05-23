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
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	tu "github.com/noironetworks/aci-containers/pkg/testutil"
)

type testServer struct {
	mux    *http.ServeMux
	server *httptest.Server

	sh *socketHandler
}

func newTestServer() *testServer {
	mux := http.NewServeMux()
	server := httptest.NewTLSServer(mux)

	ts := &testServer{
		mux:    mux,
		server: server,
	}
	ts.sh = &socketHandler{
		ts: ts,
	}
	return ts
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

type certHandler struct {
	pubKey  interface{}
	handler http.Handler
}

func (h *certHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	var raw []byte
	if req.Method == "POST" {
		raw, _ := io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewBuffer(raw))
	}
	sh := h.handler

	var sig []byte
	for _, c := range req.Cookies() {
		if c.Name == "APIC-Request-Signature" {
			s, err := base64.StdEncoding.DecodeString(c.Value)
			if err != nil {
				sh = &errorHandler{code: "401", status: 401, text: err.Error()}
				break
			}
			sig = s
		}
	}

	if sig == nil {
		sh = &errorHandler{code: "401", status: 401, text: "Signature missing"}
	} else {
		hash := hash(req.Method, req.URL.Path, raw)
		if k, ok := h.pubKey.(*rsa.PublicKey); ok {
			err := rsa.VerifyPKCS1v15(k, crypto.SHA256, hash, sig)
			if err != nil {
				sh = &errorHandler{code: "401", status: 401, text: err.Error()}
			}
		}
	}
	sh.ServeHTTP(w, req)
}

type loginSucc struct {
	cert bool
}

func (h *loginSucc) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	class := "aaaLogin"
	if h.cert {
		class = "webtokenSession"
	}
	result := map[string]interface{}{
		"imdata": []interface{}{
			map[string]interface{}{
				class: map[string]interface{}{
					"attributes": map[string]interface{}{
						"token": "testtoken",
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
	ts         *testServer
	socketConn *websocket.Conn
	err        error
}

func (h *socketHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	c, err := upgrader.Upgrade(w, req, nil)

	if err != nil {
		h.err = err
		return
	}

	go func() {
		defer c.Close()

		for {
			_, _, err := c.ReadMessage()
			var closeError *websocket.CloseError
			if errors.As(err, &closeError) {
				break
			}
		}
	}()

	h.socketConn, h.err = c, err
}

func (server *testServer) testConn(key []byte) (*ApicConnection, error) {
	u, _ := url.Parse(server.server.URL)
	apic := fmt.Sprintf("%s:%s", u.Hostname(), u.Port())

	log := logrus.New()
	log.Level = logrus.DebugLevel
	log.Formatter = &logrus.TextFormatter{
		DisableColors: true,
	}

	cert := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: server.server.TLS.Certificates[0].Certificate[0],
	})

	n, err := New(log, []string{apic}, "admin", "noir0123", key, cert, "kube",
		60, 5, 5, "common", nil)
	if err != nil {
		return nil, err
	}
	n.ReconnectInterval = 5 * time.Millisecond
	return n, nil
}

type errorHandler struct {
	code   string
	text   string
	status int
}

func (h *errorHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	result := map[string]interface{}{
		"imdata": []interface{}{
			map[string]interface{}{
				"error": map[string]interface{}{
					"attributes": map[string]interface{}{
						"code": h.code,
						"text": h.text,
					},
				},
			},
		},
	}
	w.WriteHeader(h.status)
	json.NewEncoder(w).Encode(result)
}

func newErrorHandler(code, text string, status int) *errorHandler {
	return &errorHandler{
		code:   code,
		text:   text,
		status: status,
	}
}

type retryHandler struct {
	cur         int
	max         int
	errHandler  http.Handler
	succHandler http.Handler
}

func (h *retryHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	h.cur += 1
	if h.cur > h.max {
		h.succHandler.ServeHTTP(w, req)
	} else {
		h.errHandler.ServeHTTP(w, req)
	}
}

func TestGetSetTag(t *testing.T) {
	bd := NewFvBD("common", "testbd1")
	bd.SetTag("tagTest")
	assert.Equal(t, "tagTest", bd.GetTag())

	bd = NewFvBD("common", "testbd3")
	bd.AddChild(NewFvSubnet(bd.GetDn(), "1.1.1.1/16"))
	bd.AddChild(NewTagAnnotation(bd.GetDn(), aciContainersAnnotKey).
		SetAttr("value", "anotherTest"))
	assert.Equal(t, "anotherTest", bd.GetTag())
}

func TestIsSyncTag(t *testing.T) {
	server := newTestServer()
	defer server.server.Close()
	conn, err := server.testConn(nil)
	assert.Nil(t, err)
	assert.True(t, conn.isSyncTag("kube-135cf888d314a2ca48f11a1d6ef95c67"))
	assert.False(t, conn.isSyncTag("kub-135cf888d314a2ca48f11a1d6ef95c67"))
	assert.False(t, conn.isSyncTag("kuber-135cf888d314a2ca48f11a1d6ef95c67"))
	assert.False(t, conn.isSyncTag("kube-35cf888d314a2ca48f11a1d6ef95c67"))
}

func TestTagFromKey(t *testing.T) {
	assert.Equal(t, "kube-2c70e12b7a0646f92279f427c7b38e73",
		getTagFromKey("kube", "key"))
}

func TestLoginSuccess(t *testing.T) {
	server := newTestServer()
	defer server.server.Close()
	server.mux.Handle("/api/aaaLogin.json", &loginSucc{})
	server.mux.Handle("/sockettesttoken", server.sh)

	conn, err := server.testConn(nil)
	assert.Nil(t, err)

	stopCh := make(chan struct{})
	go conn.Run(stopCh)

	tu.WaitFor(t, "login", 500*time.Millisecond,
		func(last bool) (bool, error) {
			return tu.WaitNotNil(t, last, server.sh.socketConn,
				"socket connection"), nil
		})

	close(stopCh)
}

func TestLoginRetry(t *testing.T) {
	server := newTestServer()
	defer server.server.Close()
	server.mux.Handle("/api/aaaLogin.json",
		&retryHandler{
			max: 2,
			errHandler: newErrorHandler("401", "Unauthorized",
				http.StatusUnauthorized),
			succHandler: &loginSucc{},
		})
	server.mux.Handle("/sockettesttoken", server.sh)

	conn, err := server.testConn(nil)
	assert.Nil(t, err)

	stopCh := make(chan struct{})
	go conn.Run(stopCh)

	tu.WaitFor(t, "login", 500*time.Millisecond,
		func(last bool) (bool, error) {
			return tu.WaitNotNil(t, last, server.sh.socketConn,
				"socket connection"), nil
		})

	close(stopCh)
}

func TestCertLogin(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.Nil(t, err)

	server := newTestServer()
	defer server.server.Close()
	server.mux.Handle("/api/webtokenSession.json",
		&certHandler{
			pubKey:  priv.Public(),
			handler: &loginSucc{cert: true},
		})
	server.mux.Handle("/sockettesttoken",
		&certHandler{
			pubKey:  priv.Public(),
			handler: server.sh,
		})

	key := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})

	conn, err := server.testConn(key)
	assert.Nil(t, err)
	if err != nil {
		return
	}

	stopCh := make(chan struct{})
	go conn.Run(stopCh)

	tu.WaitFor(t, "login", 500*time.Millisecond,
		func(last bool) (bool, error) {
			return tu.WaitNotNil(t, last, server.sh.socketConn,
				"socket connection"), nil
		})

	close(stopCh)
}

func TestReconnect(t *testing.T) {
	server := newTestServer()
	defer server.server.Close()
	server.mux.Handle("/api/aaaLogin.json", &loginSucc{})
	server.mux.Handle("/sockettesttoken", server.sh)
	server.mux.Handle("/api/aaaRefresh.json",
		&retryHandler{
			max: 1,
			errHandler: newErrorHandler("400", "Internal Error",
				http.StatusBadRequest),
			succHandler: &refreshSucc{},
		},
	)
	server.mux.Handle("/api/subscriptionRefresh.json",
		&retryHandler{
			max: 1,
			errHandler: newErrorHandler("400", "Internal Error",
				http.StatusBadRequest),
			succHandler: &refreshSucc{},
		})
	server.mux.Handle("/api/mo/uni/tn-common.json", &subHandler{})

	conn, err := server.testConn(nil)
	assert.Nil(t, err)

	stopCh := make(chan struct{})
	conn.RefreshInterval = 5 * time.Millisecond
	conn.RefreshTickerAdjust = 1 * time.Millisecond
	conn.AddSubscriptionDn("uni/tn-common", []string{"fvBD"})
	go conn.Run(stopCh)

	tu.WaitFor(t, "login", 500*time.Millisecond,
		func(last bool) (bool, error) {
			return tu.WaitNotNil(t, last, server.sh.socketConn,
				"socket connection"), nil
		})

	server.sh.socketConn = nil
	tu.WaitFor(t, "login", 5000*time.Millisecond,
		func(last bool) (bool, error) {
			return tu.WaitNotNil(t, last, server.sh.socketConn,
				"socket connection"), nil
		})

	server.sh.socketConn = nil
	tu.WaitFor(t, "login", 5000*time.Millisecond,
		func(last bool) (bool, error) {
			return tu.WaitNotNil(t, last, server.sh.socketConn,
				"socket connection"), nil
		})

	close(stopCh)
}

type subHandler struct {
	id       string
	response ApicSlice
}

func (h *subHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	result := map[string]interface{}{
		"subscriptionId": h.id,
		"imdata":         h.response,
	}
	json.NewEncoder(w).Encode(result)
}

func TestSubscription(t *testing.T) {
	server := newTestServer()
	defer server.server.Close()
	server.mux.Handle("/api/aaaLogin.json", &loginSucc{})
	server.mux.Handle("/sockettesttoken", server.sh)
	server.mux.Handle("/api/mo/uni/tn-common.json", &subHandler{id: "42"})

	odev := EmptyApicObject("opflexODev", "some/dn")
	server.mux.Handle("/api/class/opflexODev.json",
		&subHandler{
			id:       "43",
			response: ApicSlice{odev},
		})

	conn, err := server.testConn(nil)
	assert.Nil(t, err)

	dn := "uni/tn-common"
	conn.AddSubscriptionDn(dn, []string{"fvBD"})
	class := "opflexODev"
	conn.AddSubscriptionClass(class, []string{"opflexODev"},
		"eq(opflexODev.ctrlrName,\"controller\")")

	changed := make(map[string]bool)
	deleted := make(map[string]bool)
	conn.SetSubscriptionHooks("opflexODev",
		func(obj ApicObject) bool {
			changed[obj.GetDn()] = true
			return true
		},
		func(dn string) {
			deleted[dn] = true
		})

	stopCh := make(chan struct{})
	go conn.Run(stopCh)

	tu.WaitFor(t, "subscription", 500*time.Millisecond,
		func(last bool) (bool, error) {
			if !tu.WaitEqual(t, last, "42",
				conn.subscriptions.subs[dn].id, "subscription id dn") {
				return false, nil
			}
			if !tu.WaitEqual(t, last, "43",
				conn.subscriptions.subs[class].id, "subscription id class") {
				return false, nil
			}
			return true, nil
		})

	tu.WaitFor(t, "subscription", 500*time.Millisecond,
		func(last bool) (bool, error) {
			return tu.WaitEqual(t, last, map[string]bool{"some/dn": true},
				changed, "sub hook change"), nil
		})

	odev.SetAttr("status", "deleted")
	server.sh.socketConn.WriteJSON(ApicResponse{
		SubscriptionId: []string{"43"},
		Imdata:         []ApicObject{odev},
	})

	tu.WaitFor(t, "subscription", 500*time.Millisecond,
		func(last bool) (bool, error) {
			return tu.WaitEqual(t, last, map[string]bool{"some/dn": true},
				deleted, "sub hook delete"), nil
		})

	close(stopCh)
}

func existingState() ApicSlice {
	bd := NewFvBD("common", "testbd1")
	subnet := NewFvSubnet(bd.GetDn(), "10.42.10.1/16")
	subnet2 := NewFvSubnet(bd.GetDn(), "10.43.10.1/16")
	bd.AddChild(subnet)
	bd.AddChild(subnet2)

	bd2 := NewFvBD("common", "testbd2")
	bd0 := NewFvBD("common", "testbd0")

	s := ApicSlice{bd0, bd, bd2}

	return s
}

type request struct {
	method string
	uri    string
	body   ApicObject
}

type methodMux struct {
	methods map[string]http.Handler
}

func (h *methodMux) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if h, ok := h.methods[req.Method]; ok {
		h.ServeHTTP(w, req)
	}
}

type recorder struct {
	requests []request
}

func (h *recorder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	var reqBody ApicObject
	json.NewDecoder(req.Body).Decode(&reqBody)
	fmt.Println(req.Method, req.URL)
	h.requests = append(h.requests, request{
		method: req.Method,
		uri:    req.URL.RequestURI(),
		body:   reqBody,
	})
}

type syncTest struct {
	desiredState   map[string]ApicSlice
	containerState map[string]ApicSlice
	existing       ApicSlice
	expected       []request
	desc           string
}

func TestFullSync(t *testing.T) {
	bd0 := NewFvBD("common", "testbd0")
	bd4 := NewFvBD("common", "testbd4")
	ns := NewVmmInjectedNs("v", "d", "c", "n")
	depl := NewVmmInjectedDepl("v", "d", "c", "n", "d")

	syncTests := []syncTest{
		{
			desc:     "deletes",
			existing: PrepareApicSlice(existingState(), "kube", "kube-key1"),
			expected: []request{
				{
					method: "DELETE",
					uri:    "/api/mo/uni/tn-common/BD-testbd0.json",
				},
				{
					method: "DELETE",
					uri:    "/api/mo/uni/tn-common/BD-testbd1/subnet-[10.43.10.1/16].json",
				},
				{
					method: "DELETE",
					uri:    "/api/mo/uni/tn-common/BD-testbd2.json",
				},
			},
			desiredState: func() map[string]ApicSlice {
				bd := NewFvBD("common", "testbd1")
				subnet := NewFvSubnet(bd.GetDn(), "10.42.10.1/16")
				bd.AddChild(subnet)
				return map[string]ApicSlice{"kube-key1": {bd}}
			}(),
		},
		{
			desc:     "adds",
			existing: PrepareApicSlice(existingState(), "kube", "kube-key1"),
			expected: []request{
				{
					method: "POST",
					uri:    "/api/mo/uni/tn-common/BD-testbd0.json",
					body:   bd0,
				},
				{
					method: "POST",
					uri:    "/api/mo/uni/tn-common/BD-testbd4.json",
					body:   bd4,
				},
			},
			desiredState: func() map[string]ApicSlice {
				bd := NewFvBD("common", "testbd1")
				subnet := NewFvSubnet(bd.GetDn(), "10.42.10.1/16")
				subnet2 := NewFvSubnet(bd.GetDn(), "10.43.10.1/16")
				bd.AddChild(subnet)
				bd.AddChild(subnet2)

				bd2 := NewFvBD("common", "testbd2")

				subnet3 := NewFvSubnet(bd0.GetDn(), "10.44.10.1/16")
				bd0.AddChild(subnet3)

				s := ApicSlice{bd0, bd, bd2, bd4}
				return map[string]ApicSlice{"kube-key1": s}
			}(),
		},
		{
			desc:     "container",
			existing: PrepareApicSlice(existingState(), "kube", "kube-key1"),
			expected: []request{
				{
					method: "POST",
					uri:    fmt.Sprintf("/api/mo/%s.json", ns.GetDn()),
					body:   ns,
				},
				{
					method: "POST",
					uri:    fmt.Sprintf("/api/mo/%s.json", depl.GetDn()),
					body:   depl,
				},
			},
			desiredState: func() map[string]ApicSlice {
				return map[string]ApicSlice{
					"kube-key1": existingState(),
					"d-vmm-1":   {depl},
				}
			}(),
			containerState: func() map[string]ApicSlice {
				return map[string]ApicSlice{
					"ns-vmm": {ns},
				}
			}(),
		}}

	for _, test := range syncTests {
		server := newTestServer()
		defer server.server.Close()
		server.mux.Handle("/api/aaaLogin.json", &loginSucc{})
		server.mux.Handle("/sockettesttoken", server.sh)
		server.mux.Handle("/api/mo/uni/tn-common.json",
			&subHandler{
				response: test.existing,
			})
		rec := &recorder{}
		server.mux.Handle("/api/mo/uni/tn-common/", rec)
		server.mux.Handle("/api/mo/comp/", rec)

		conn, err := server.testConn(nil)
		assert.Nil(t, err)

		dn := "uni/tn-common"
		conn.AddSubscriptionDn(dn, []string{"fvBD"})

		for key, value := range test.containerState {
			conn.WriteApicContainer(key, value)
		}
		for key, value := range test.desiredState {
			conn.WriteApicObjects(key, value)
		}

		stopCh := make(chan struct{})
		go conn.Run(stopCh)

		tu.WaitFor(t, "sync", 500*time.Millisecond,
			func(last bool) (bool, error) {
				return tu.WaitEqual(t, last, test.expected, rec.requests,
					test.desc), nil
			})

		close(stopCh)
	}
}

type reconcileTest struct {
	desiredState map[string]ApicSlice
	existing     ApicSlice
	updateResp   map[string]ApicSlice
	deleteBody   map[string]ApicSlice
	updates      []string
	deletes      []string
	expected     map[string][]request
	desc         string
}

func TestReconcile(t *testing.T) {
	bd1exp := NewFvBD("common", "testbd1")
	subnetexp := NewFvSubnet(bd1exp.GetDn(), "10.42.10.1/16")
	subnetexp_copy := NewFvSubnet(bd1exp.GetDn(), "10.42.10.1/16")
	{
		subnet2 := NewFvSubnet(bd1exp.GetDn(), "10.43.10.1/16")
		bd1exp.AddChild(subnetexp)
		bd1exp.AddChild(subnet2)
	}
	bdExtra := NewFvBD("common", "testbd_extra")
	bdExtra2 := NewFvBD("common", "testbd_extra2")
	// note don't prepare bdExtra2
	PrepareApicSlice(ApicSlice{bd1exp, bdExtra}, "kube", "kube-key1")

	bd1 := NewFvBD("common", "testbd1")
	{
		bd1.SetAttr("arpFlood", "yes")
		subnet := NewFvSubnet(bd1.GetDn(), "10.42.10.1/16")
		subnet2 := NewFvSubnet(bd1.GetDn(), "10.43.10.1/16")
		bd1.AddChild(subnet)
		bd1.AddChild(subnet2)
	}

	subnet_mod := NewFvSubnet(bd1.GetDn(), "10.42.10.1/16")
	subnet_mod.SetAttr("virtual", "yes")

	reconcileTests := []reconcileTest{
		{
			desc:     "modify parent",
			existing: PrepareApicSlice(existingState(), "kube", "kube-key1"),
			desiredState: map[string]ApicSlice{
				"kube-key1": existingState(),
			},
			updateResp: func() map[string]ApicSlice {
				return map[string]ApicSlice{
					bd1.GetDn(): {bd1},
				}
			}(),
			updates: []string{bd1.GetDn()},
			expected: map[string][]request{
				bd1.GetDn(): {{
					method: "POST",
					uri:    fmt.Sprintf("/api/mo/%s.json", bd1.GetDn()),
					body:   bd1exp,
				}},
			},
		},
		{
			desc:     "modify child",
			existing: PrepareApicSlice(existingState(), "kube", "kube-key1"),
			desiredState: map[string]ApicSlice{
				"kube-key1": existingState(),
			},
			updateResp: func() map[string]ApicSlice {
				return map[string]ApicSlice{
					subnet_mod.GetDn(): {subnet_mod},
				}
			}(),
			updates: []string{subnet_mod.GetDn()},
			expected: map[string][]request{
				subnetexp.GetDn(): {{
					method: "POST",
					uri:    fmt.Sprintf("/api/mo/%s.json", subnetexp.GetDn()),
					body:   subnetexp,
				}},
			},
		},
		{
			desc:     "delete parent",
			existing: PrepareApicSlice(existingState(), "kube", "kube-key1"),
			desiredState: map[string]ApicSlice{
				"kube-key1": existingState(),
			},
			deleteBody: func() map[string]ApicSlice {
				return map[string]ApicSlice{
					bd1.GetDn(): {bd1},
				}
			}(),
			deletes: []string{bd1.GetDn()},
			expected: map[string][]request{
				bd1.GetDn(): {{
					method: "POST",
					uri:    fmt.Sprintf("/api/mo/%s.json", bd1.GetDn()),
					body:   bd1exp,
				}},
			},
		},
		{
			desc:     "delete child",
			existing: PrepareApicSlice(existingState(), "kube", "kube-key1"),
			desiredState: map[string]ApicSlice{
				"kube-key1": existingState(),
			},
			deleteBody: func() map[string]ApicSlice {
				return map[string]ApicSlice{
					subnetexp.GetDn(): {subnetexp_copy},
				}
			}(),
			deletes: []string{subnetexp.GetDn()},
			expected: map[string][]request{
				subnetexp.GetDn(): {{
					method: "POST",
					uri:    fmt.Sprintf("/api/mo/%s.json", subnetexp.GetDn()),
					body:   subnetexp,
				}},
			},
		},
		{
			desc:     "update for extra object",
			existing: PrepareApicSlice(existingState(), "kube", "kube-key1"),
			desiredState: map[string]ApicSlice{
				"kube-key1": existingState(),
			},
			updateResp: func() map[string]ApicSlice {
				return map[string]ApicSlice{
					bdExtra.GetDn():  {bdExtra},
					bdExtra2.GetDn(): {bdExtra2},
				}
			}(),
			updates: []string{bdExtra2.GetDn(), bdExtra.GetDn()},
			expected: map[string][]request{
				bdExtra.GetDn(): {{
					method: "DELETE",
					uri:    fmt.Sprintf("/api/mo/%s.json", bdExtra.GetDn()),
				}},
				bdExtra2.GetDn(): nil,
			},
		},
	}

	for _, test := range reconcileTests {
		server := newTestServer()
		defer server.server.Close()
		server.mux.Handle("/api/aaaLogin.json", &loginSucc{})
		server.mux.Handle("/sockettesttoken", server.sh)
		server.mux.Handle("/api/mo/uni/tn-common.json",
			&subHandler{
				id:       "42",
				response: test.existing,
			})
		recorders := make(map[string]*recorder)
		for dn, obj := range test.updateResp {
			r := &recorder{}
			recorders[dn] = r
			server.mux.Handle(fmt.Sprintf("/api/mo/%s.json", dn),
				&methodMux{
					methods: map[string]http.Handler{
						"GET": &subHandler{
							response: obj,
						},
						"POST":   r,
						"DELETE": r,
					},
				})
		}
		for dn := range test.expected {
			if _, ok := test.updateResp[dn]; ok {
				continue
			}
			r := &recorder{}
			recorders[dn] = r
			server.mux.Handle(fmt.Sprintf("/api/mo/%s.json", dn),
				&methodMux{
					methods: map[string]http.Handler{
						"GET":    r,
						"POST":   r,
						"DELETE": r,
					},
				})
		}

		conn, err := server.testConn(nil)
		assert.Nil(t, err)

		dn := "uni/tn-common"
		conn.AddSubscriptionDn(dn, []string{"fvBD"})

		time.Sleep(1 * time.Second)
		for key, value := range test.desiredState {
			conn.WriteApicObjects(key, value)
		}

		stopCh := make(chan struct{})
		go conn.Run(stopCh)
		tu.WaitFor(t, "login", 500*time.Millisecond,
			func(last bool) (bool, error) {
				return tu.WaitNotNil(t, last, server.sh.socketConn,
					"socket connection"), nil
			})

		time.Sleep(1 * time.Second)
		for _, updateDn := range test.updates {
			update := test.updateResp[updateDn]
			for _, u := range update {
				u.SetAttr("status", "updated")
			}
			data := map[string]interface{}{
				"subscriptionId": []string{"42"},
				"imdata":         update,
			}
			server.sh.socketConn.WriteJSON(data)
		}

		for _, deleteDn := range test.deletes {
			deleteMo := test.deleteBody[deleteDn]
			for _, d := range deleteMo {
				d.SetAttr("status", "deleted")
			}
			data := map[string]interface{}{
				"subscriptionId": []string{"42"},
				"imdata":         deleteMo,
			}
			server.sh.socketConn.WriteJSON(data)
		}

		tu.WaitFor(t, "sync", 500*time.Millisecond,
			func(last bool) (bool, error) {
				for dn, rec := range recorders {
					if !tu.WaitEqual(t, last, test.expected[dn], rec.requests,
						test.desc, dn) {
						return false, nil
					}
				}
				return true, nil
			})
		close(stopCh)
	}
}

type recorderMuxer struct {
	requests []request
	id       string
	response ApicSlice
	ns       ApicObject
	depl     ApicObject
	replSet  ApicObject
}

func (h *recorderMuxer) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	var reqBody ApicObject
	json.NewDecoder(req.Body).Decode(&reqBody)
	fmt.Println(req.Method, req.URL)
	h.requests = append(h.requests, request{
		method: req.Method,
		uri:    req.URL.RequestURI(),
		body:   reqBody,
	})
	switch {
	case strings.Contains(req.URL.RequestURI(), "vmmInjectedNs"):
		h.response = PrepareApicSlice(ApicSlice{h.ns}, "kube", "kube-key1")
	case strings.Contains(req.URL.RequestURI(), "vmmInjectedDepl"):
		h.response = PrepareApicSlice(ApicSlice{h.depl}, "kube", "kube-key1")
	case strings.Contains(req.URL.RequestURI(), "vmmInjectedReplSet"):
		h.response = PrepareApicSlice(ApicSlice{h.replSet}, "kube", "kube-key1")
	default:
		h.response = ApicSlice{}
	}
	result := map[string]interface{}{
		"subscriptionId": h.id,
		"imdata":         h.response,
	}
	json.NewEncoder(w).Encode(result)
	currId, _ := strconv.Atoi(h.id)
	currId++
	h.id = strconv.Itoa(currId)
}

func TestSplitSubscribe(t *testing.T) {
	nsName := "test1"
	ns := NewVmmInjectedNs("v", "d", "c", nsName)
	depl := NewVmmInjectedDepl("v", "d", "c", nsName, "depl1")
	replSet := NewVmmInjectedReplSet("v", "d", "c", nsName, "repl1")
	server := newTestServer()
	defer server.server.Close()
	server.mux.Handle("/api/aaaLogin.json", &loginSucc{})
	server.mux.Handle("/sockettesttoken", server.sh)
	desiredState := map[string]ApicSlice{
		"kube-key1": {ns, depl, replSet},
	}
	expectedSubscribe := []string{
		`/api/mo/comp/prov-v/ctrlr-[d]-c/injcont.json?subscription=yes&refresh-timeout=60&query-target=subtree&rsp-subtree=children&target-subtree-class=vmmInjectedHost&rsp-subtree-class=tagAnnotation`,
		`/api/mo/comp/prov-v/ctrlr-[d]-c/injcont.json?subscription=yes&refresh-timeout=60&query-target=subtree&rsp-subtree=children&target-subtree-class=vmmInjectedContGrp&rsp-subtree-class=tagAnnotation`,
		`/api/mo/comp/prov-v/ctrlr-[d]-c/injcont.json?subscription=yes&refresh-timeout=60&query-target=subtree&rsp-subtree=children&target-subtree-class=vmmInjectedSvc&rsp-subtree-class=tagAnnotation`,
		`/api/mo/comp/prov-v/ctrlr-[d]-c/injcont.json?subscription=yes&refresh-timeout=60&query-target=subtree&rsp-subtree=children&target-subtree-class=vmmInjectedSvcEp&rsp-subtree-class=tagAnnotation`,
		`/api/mo/comp/prov-v/ctrlr-[d]-c/injcont.json?subscription=yes&refresh-timeout=60&query-target=subtree&rsp-subtree=children&target-subtree-class=vmmInjectedSvcPort&rsp-subtree-class=tagAnnotation`,
		`/api/mo/comp/prov-v/ctrlr-[d]-c/injcont.json?subscription=yes&refresh-timeout=60&query-target=subtree&rsp-subtree=children&target-subtree-class=vmmInjectedDepl&rsp-subtree-class=tagAnnotation`,
		`/api/mo/comp/prov-v/ctrlr-[d]-c/injcont.json?subscription=yes&refresh-timeout=60&query-target=subtree&rsp-subtree=children&target-subtree-class=vmmInjectedReplSet&rsp-subtree-class=tagAnnotation`,
		`/api/mo/comp/prov-v/ctrlr-[d]-c/injcont.json?subscription=yes&refresh-timeout=60&query-target=subtree&rsp-subtree=children&target-subtree-class=vmmInjectedNs&rsp-subtree-class=tagAnnotation`,
	}
	sort.Strings(expectedSubscribe)
	rMux := recorderMuxer{
		id:      "45",
		ns:      NewVmmInjectedNs("v", "d", "c", nsName),
		depl:    depl,
		replSet: replSet,
	}
	server.mux.Handle(
		"/api/mo/comp/prov-v/ctrlr-[d]-c/injcont.json",
		&rMux,
	)
	conn, err := server.testConn(nil)
	assert.Nil(t, err)

	dn := "comp/prov-v/ctrlr-[d]-c/injcont"
	conn.AddSubscriptionDn(dn, []string{"vmmInjectedHost", "vmmInjectedNs"})
	for key, value := range desiredState {
		conn.WriteApicObjects(key, value)
	}
	stopCh := make(chan struct{})
	go conn.Run(stopCh)

	tu.WaitFor(t, "login", 500*time.Millisecond,
		func(last bool) (bool, error) {
			return tu.WaitNotNil(t, last, server.sh.socketConn,
				"socket connection"), nil
		})
	tu.WaitFor(t, "subscribe", 500*time.Millisecond,
		func(last bool) (bool, error) {
			var s []string
			for i := range rMux.requests {
				s = append(s, rMux.requests[i].uri)
			}
			sort.Strings(s)
			return tu.WaitEqual(t, last, expectedSubscribe, s,
				"split subscription requests"), nil
		})
	close(stopCh)
}
func TestGetRootDn(t *testing.T) {
	tests := []struct {
		dn         string
		rootClass  string
		expectedDn string
	}{
		{
			dn:         "uni/tn-common/cloudepg/ap-testbd/teststr",
			rootClass:  "cloudEPg",
			expectedDn: "uni/tn-common/cloudepg/ap-testbd",
		},
		{
			dn:         "uni/tn-common/ap-testepg/teststr1/teststr2",
			rootClass:  "vzBrCP",
			expectedDn: "uni/tn-common/ap-testepg",
		},
	}

	for _, test := range tests {
		actualDn := getRootDn(test.dn, test.rootClass)
		if actualDn != test.expectedDn {
			t.Errorf("getRootDn(%s, %s) = %s, expected %s", test.dn, test.rootClass, actualDn, test.expectedDn)
		}
	}
}
func TestGetApicResponse(t *testing.T) {
	server := newTestServer()
	defer server.server.Close()
	server.mux.HandleFunc("/api/test", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(ApicResponse{
			Imdata: []ApicObject{
				{
					"class": &ApicObjectBody{
						Attributes: map[string]interface{}{
							"attr2": "value2",
							"dn":    "dn2",
						},
					},
				},
			},
		})
	})

	conn, err := server.testConn(nil)
	assert.Nil(t, err)

	uri := "/api/test"
	resp, err := conn.GetApicResponse(uri)
	assert.Nil(t, err)
	assert.NotNil(t, resp)
	expectedRespData := ApicObject{
		"class": &ApicObjectBody{
			Attributes: map[string]interface{}{
				"attr2": "value2",
				"dn":    "dn2",
			},
		},
	}
	assert.Equal(t, expectedRespData, resp.Imdata[0])
}

func TestAddSubscriptionTree(t *testing.T) {
	server := newTestServer()
	defer server.server.Close()
	conn, err := server.testConn(nil)
	assert.Nil(t, err)

	conn.subscriptions.subs = make(map[string]*subscription)
	conn.indexMutex = sync.Mutex{}

	class := "hostprotPol"
	targetClasses := []string{"cloudEPg", "vzBrCP"}
	targetFilter := "vzFilter"

	conn.AddSubscriptionTree(class, targetClasses, targetFilter)

	sub, ok := conn.subscriptions.subs[class]
	if !ok {
		t.Errorf("Expected subscription for class %s, but not found", class)
	}

	if sub.kind != apicSubTree {
		t.Errorf("Expected subscription kind to be apicSubTree, got %d", sub.kind)
	}

	if len(sub.childSubs) != 0 {
		t.Errorf("Expected childSubs to be empty, got %d", len(sub.childSubs))
	}

	if !reflect.DeepEqual(sub.targetClasses, targetClasses) {
		t.Errorf("Expected targetClasses to be %v, got %v", targetClasses, sub.targetClasses)
	}

	if sub.targetFilter != targetFilter {
		t.Errorf("Expected targetFilter to be %s, got %s", targetFilter, sub.targetFilter)
	}
}

/*
// commented out - DeleteDnInline function no longer in use
func TestDeleteDnInline(t *testing.T) {
	server := newTestServer()
	defer server.server.Close()
	conn, err := server.testConn(nil)
	assert.Nil(t, err)

	conn.Apic = []string{"apic1", "apic2"}

	dn := "uni/tn-common"

	err = conn.DeleteDnInline(dn)
	// No HTTPS server running, so we expect an error
	assert.Error(t, err, "Could not delete dn")
}
*/

func TestGetVersion(t *testing.T) {

	server := newTestServer()
	defer server.server.Close()
	conn, err := server.testConn(nil)
	assert.Nil(t, err)

	conn.Apic = []string{"127.0.0.1"}
	conn.log = logrus.New().WithField("test", "test")

	version, err := conn.GetVersion()
	assert.Nil(t, err)
	assert.Equal(t, "4.2(4i)", version)
}
