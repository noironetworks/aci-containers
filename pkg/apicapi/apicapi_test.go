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
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/gorilla/websocket"
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

type loginSucc struct{}

func (h *loginSucc) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	result := map[string]interface{}{
		"imdata": []interface{}{
			map[string]interface{}{
				"aaaLogin": map[string]interface{}{
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
			if _, k := err.(*websocket.CloseError); k {
				break
			}
		}
	}()

	h.socketConn, h.err = c, err
}

func (server *testServer) testConn() (*ApicConnection, error) {
	u, _ := url.Parse(server.server.URL)
	apic := fmt.Sprintf("%s:%s", u.Hostname(), u.Port())

	log := logrus.New()
	log.Level = logrus.DebugLevel
	log.Formatter = &logrus.TextFormatter{
		DisableColors: true,
	}

	tls := &tls.Config{InsecureSkipVerify: true}
	dialer := &websocket.Dialer{
		TLSClientConfig: tls,
	}

	n, err := New(dialer, log, []string{apic}, "admin", "noir0123", "kube")
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

func newErrorHandler(code string, text string, status int) *errorHandler {
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

func TestLoginSuccess(t *testing.T) {
	server := newTestServer()
	defer server.server.Close()
	server.mux.Handle("/api/aaaLogin.json", &loginSucc{})
	server.mux.Handle("/sockettesttoken", server.sh)

	conn, err := server.testConn()
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

	conn, err := server.testConn()
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

	conn, err := server.testConn()
	assert.Nil(t, err)

	stopCh := make(chan struct{})
	conn.RefreshInterval = 5 * time.Millisecond
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
	server.mux.Handle("/api/class/opflexODev.json", &subHandler{id: "43"})

	conn, err := server.testConn()
	assert.Nil(t, err)

	dn := "uni/tn-common"
	conn.AddSubscriptionDn(dn, []string{"fvBD"})
	class := "opflexODev"
	conn.AddSubscriptionClass(class, []string{"opflexODev"},
		"eq(opflexODev.ctrlrName,\"controller\")")

	stopCh := make(chan struct{})
	go conn.Run(stopCh)

	tu.WaitFor(t, "subscription", 500*time.Millisecond,
		func(last bool) (bool, error) {
			if !tu.WaitEqual(t, last, "42",
				conn.subscriptions.subs[dn].id, "subscription id") {
				return false, nil
			}
			return tu.WaitEqual(t, last, "43",
				conn.subscriptions.subs[class].id, "subscription id"), nil
		})

	close(stopCh)
}

func existingState() ApicSlice {
	bd := NewBridgeDomain("common", "testbd1")
	subnet := NewSubnet(bd.GetDn(), "10.42.10.1/16")
	subnet2 := NewSubnet(bd.GetDn(), "10.43.10.1/16")
	bd.AddChild(subnet)
	bd.AddChild(subnet2)

	bd2 := NewBridgeDomain("common", "testbd2")
	bd0 := NewBridgeDomain("common", "testbd0")

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
	desiredState map[string]ApicSlice
	existing     ApicSlice
	expected     []request
	desc         string
}

func TestFullSync(t *testing.T) {

	bd0 := NewBridgeDomain("common", "testbd0")
	bd4 := NewBridgeDomain("common", "testbd4")

	syncTests := []syncTest{
		syncTest{
			desc:     "deletes",
			existing: PrepareApicSlice(existingState(), "kube-key1"),
			expected: []request{
				request{
					method: "DELETE",
					uri:    "/api/mo/uni/tn-common/BD-testbd0.json",
				},
				request{
					method: "DELETE",
					uri:    "/api/mo/uni/tn-common/BD-testbd1/subnet-[10.43.10.1/16].json",
				},
				request{
					method: "DELETE",
					uri:    "/api/mo/uni/tn-common/BD-testbd2.json",
				},
			},
			desiredState: func() map[string]ApicSlice {
				bd := NewBridgeDomain("common", "testbd1")
				subnet := NewSubnet(bd.GetDn(), "10.42.10.1/16")
				bd.AddChild(subnet)
				return map[string]ApicSlice{"kube-key1": {bd}}
			}(),
		},
		syncTest{
			desc:     "adds",
			existing: PrepareApicSlice(existingState(), "kube-key1"),
			expected: []request{
				request{
					method: "POST",
					uri:    "/api/mo/uni/tn-common/BD-testbd0.json",
					body:   bd0,
				},
				request{
					method: "POST",
					uri:    "/api/mo/uni/tn-common/BD-testbd4.json",
					body:   bd4,
				},
			},
			desiredState: func() map[string]ApicSlice {
				bd := NewBridgeDomain("common", "testbd1")
				subnet := NewSubnet(bd.GetDn(), "10.42.10.1/16")
				subnet2 := NewSubnet(bd.GetDn(), "10.43.10.1/16")
				bd.AddChild(subnet)
				bd.AddChild(subnet2)

				bd2 := NewBridgeDomain("common", "testbd2")

				subnet3 := NewSubnet(bd0.GetDn(), "10.44.10.1/16")
				bd0.AddChild(subnet3)

				s := ApicSlice{bd0, bd, bd2, bd4}
				return map[string]ApicSlice{"kube-key1": s}
			}(),
		},
	}

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

		conn, err := server.testConn()
		assert.Nil(t, err)

		dn := "uni/tn-common"
		conn.AddSubscriptionDn(dn, []string{"fvBD"})

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
	bd1exp := NewBridgeDomain("common", "testbd1")
	subnetexp := NewSubnet(bd1exp.GetDn(), "10.42.10.1/16")
	{
		subnet2 := NewSubnet(bd1exp.GetDn(), "10.43.10.1/16")
		bd1exp.AddChild(subnetexp)
		bd1exp.AddChild(subnet2)
	}
	bdExtra := NewBridgeDomain("common", "testbd_extra")
	bdExtra2 := NewBridgeDomain("common", "testbd_extra2")
	// note don't prepare bdExtra2
	PrepareApicSlice(ApicSlice{bd1exp, bdExtra}, "kube-key1")

	bd1 := NewBridgeDomain("common", "testbd1")
	{
		bd1.SetAttr("arpFlood", "yes")
		subnet := NewSubnet(bd1.GetDn(), "10.42.10.1/16")
		subnet2 := NewSubnet(bd1.GetDn(), "10.43.10.1/16")
		bd1.AddChild(subnet)
		bd1.AddChild(subnet2)

	}

	subnet_mod := NewSubnet(bd1.GetDn(), "10.42.10.1/16")
	subnet_mod.SetAttr("virtual", "yes")

	reconcileTests := []reconcileTest{
		reconcileTest{
			desc:     "modify parent",
			existing: PrepareApicSlice(existingState(), "kube-key1"),
			desiredState: map[string]ApicSlice{
				"kube-key1": existingState(),
			},
			updateResp: func() map[string]ApicSlice {
				return map[string]ApicSlice{
					bd1.GetDn(): ApicSlice{bd1},
				}
			}(),
			updates: []string{bd1.GetDn()},
			expected: map[string][]request{
				bd1.GetDn(): []request{request{
					method: "POST",
					uri:    fmt.Sprintf("/api/mo/%s.json", bd1.GetDn()),
					body:   bd1exp,
				}},
			},
		},
		reconcileTest{
			desc:     "modify child",
			existing: PrepareApicSlice(existingState(), "kube-key1"),
			desiredState: map[string]ApicSlice{
				"kube-key1": existingState(),
			},
			updateResp: func() map[string]ApicSlice {
				return map[string]ApicSlice{
					subnet_mod.GetDn(): ApicSlice{subnet_mod},
				}
			}(),
			updates: []string{subnet_mod.GetDn()},
			expected: map[string][]request{
				subnetexp.GetDn(): []request{request{
					method: "POST",
					uri:    fmt.Sprintf("/api/mo/%s.json", subnetexp.GetDn()),
					body:   subnetexp,
				}},
			},
		},
		reconcileTest{
			desc:     "delete parent",
			existing: PrepareApicSlice(existingState(), "kube-key1"),
			desiredState: map[string]ApicSlice{
				"kube-key1": existingState(),
			},
			deleteBody: func() map[string]ApicSlice {
				return map[string]ApicSlice{
					bd1.GetDn(): ApicSlice{bd1},
				}
			}(),
			deletes: []string{bd1.GetDn()},
			expected: map[string][]request{
				bd1.GetDn(): []request{request{
					method: "POST",
					uri:    fmt.Sprintf("/api/mo/%s.json", bd1.GetDn()),
					body:   bd1exp,
				}},
			},
		},
		reconcileTest{
			desc:     "delete child",
			existing: PrepareApicSlice(existingState(), "kube-key1"),
			desiredState: map[string]ApicSlice{
				"kube-key1": existingState(),
			},
			deleteBody: func() map[string]ApicSlice {
				return map[string]ApicSlice{
					subnetexp.GetDn(): ApicSlice{subnetexp},
				}
			}(),
			deletes: []string{subnetexp.GetDn()},
			expected: map[string][]request{
				subnetexp.GetDn(): []request{request{
					method: "POST",
					uri:    fmt.Sprintf("/api/mo/%s.json", subnetexp.GetDn()),
					body:   subnetexp,
				}},
			},
		},
		reconcileTest{
			desc:     "update for extra object",
			existing: PrepareApicSlice(existingState(), "kube-key1"),
			desiredState: map[string]ApicSlice{
				"kube-key1": existingState(),
			},
			updateResp: func() map[string]ApicSlice {
				return map[string]ApicSlice{
					bdExtra.GetDn():  ApicSlice{bdExtra},
					bdExtra2.GetDn(): ApicSlice{bdExtra2},
				}
			}(),
			updates: []string{bdExtra2.GetDn(), bdExtra.GetDn()},
			expected: map[string][]request{
				bdExtra.GetDn(): []request{request{
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

		conn, err := server.testConn()
		assert.Nil(t, err)

		dn := "uni/tn-common"
		conn.AddSubscriptionDn(dn, []string{"fvBD"})

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
			delete := test.deleteBody[deleteDn]
			for _, d := range delete {
				d.SetAttr("status", "deleted")
			}
			data := map[string]interface{}{
				"subscriptionId": []string{"42"},
				"imdata":         delete,
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
