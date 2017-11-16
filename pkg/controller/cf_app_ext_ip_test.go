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

package controller

import (
	"database/sql"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/noironetworks/aci-containers/pkg/cfapi"
	//	tu "github.com/noironetworks/aci-containers/pkg/testutil"
)

func TestCfAppExtIpDbOps(t *testing.T) {
	env := testCfEnvironment(t)
	ipdb := AppExtIpDb{}

	// set v4 & v6
	ip1 := ExtIpAlloc{"1.2.3.4", false, "p1"}
	ip2 := ExtIpAlloc{"2.3.4.4", true, "p2"}
	ip3 := ExtIpAlloc{"::fe80", false, "p1"}

	txn(env.db, func(txn *sql.Tx) {
		err := ipdb.Set(txn, "1", []ExtIpAlloc{ip1, ip2, ip3})
		assert.Nil(t, err)
	})

	// verify
	txn(env.db, func(txn *sql.Tx) {
		ips, err := ipdb.Get(txn, "1")
		assert.Nil(t, err)
		assert.Equal(t, []ExtIpAlloc{ip1, ip2, ip3}, ips)
	})

	// list
	txn(env.db, func(txn *sql.Tx) {
		val, err := ipdb.List(txn)
		assert.Nil(t, err)
		assert.Equal(t, 3, len(val))
		assert.Equal(t, "1", val[0].Guid)
		assert.Equal(t, "1", val[1].Guid)
		assert.Equal(t, "1", val[2].Guid)
	})

	// reset
	txn(env.db, func(txn *sql.Tx) {
		err := ipdb.Set(txn, "1", nil)
		assert.Nil(t, err)
	})

	// verify
	txn(env.db, func(txn *sql.Tx) {
		ips, err := ipdb.Get(txn, "1")
		assert.Nil(t, err)
		assert.Nil(t, ips)
	})

	// set only v4
	txn(env.db, func(txn *sql.Tx) {
		err := ipdb.Set(txn, "1", []ExtIpAlloc{ip1, ip2})
		assert.Nil(t, err)
	})

	// verify
	txn(env.db, func(txn *sql.Tx) {
		ips, err := ipdb.Get(txn, "1")
		assert.Nil(t, err)
		assert.Equal(t, []ExtIpAlloc{ip1, ip2}, ips)
	})

	// delete
	txn(env.db, func(txn *sql.Tx) {
		err := ipdb.Delete(txn, "1")
		assert.Nil(t, err)
	})
	// verify
	txn(env.db, func(txn *sql.Tx) {
		ips, err := ipdb.Get(txn, "1")
		assert.Nil(t, err)
		assert.Nil(t, ips)
	})

	// delete again
	txn(env.db, func(txn *sql.Tx) {
		err := ipdb.Delete(txn, "1")
		assert.Nil(t, err)
	})
}

func TestCfAppExtIpDbList(t *testing.T) {
	env := testCfEnvironment(t)
	ipdb := AppExtIpDb{}

	a := make([][]ExtIpAlloc, 0)
	aa := make([]ExtIpAllocApp, 0)
	ids := []string{"1", "2", "3", "4"}
	for _, id := range ids {
		ip1 := ExtIpAlloc{id + ".2.3.4", false, "p1"}
		ip2 := ExtIpAlloc{id + ".3.3.4", true, "p2"}
		ip3 := ExtIpAlloc{"::fe80" + id, false, "p1"}
		a = append(a, []ExtIpAlloc{ip1, ip2, ip3})
		aa = append(aa, ExtIpAllocApp{id, ip1}, ExtIpAllocApp{id, ip2}, ExtIpAllocApp{id, ip3})
	}
	txn(env.db, func(txn *sql.Tx) {
		assert.Nil(t, ipdb.Set(txn, ids[0], a[0]))
		assert.Nil(t, ipdb.Set(txn, ids[1], a[1]))
		assert.Nil(t, ipdb.Set(txn, ids[2], a[2]))
		assert.Nil(t, ipdb.Set(txn, ids[3], a[3]))
	})
	txn(env.db, func(txn *sql.Tx) {
		res, err := ipdb.List(txn)
		assert.Nil(t, err)
		assert.Equal(t, aa, res)
	})
}

func TestCfAppExtIpHttpHandler(t *testing.T) {
	env := testCfEnvironment(t)
	handler := &AppExtIpHttpHandler{env: env}

	doHttpOp := func(verb, id string, ips []string) (int, []string) {
		var rdr io.Reader
		if ips != nil {
			str, err := json.Marshal(AppExtIpPutMessageBody{IP: ips})
			assert.Nil(t, err)
			rdr = strings.NewReader(string(str))
		}
		req := httptest.NewRequest(verb, "http://localhost/networking-aci/app_ext_ip/"+id, rdr)
		req.Header.Add("Authorization", "Bearer testtoken")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		resp := w.Result()
		var msg AppExtIpGetMessageBody
		if resp.StatusCode == 200 {
			assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
			body, _ := ioutil.ReadAll(resp.Body)
			assert.Nil(t, json.Unmarshal(body, &msg))
			assert.Equal(t, id, msg.Guid)
		}
		return resp.StatusCode, msg.IP
	}

	var code int
	var ips []string
	obj := "app-1"
	cont_to_check := []interface{}{"c-1", "c-2"}

	// get non-existent
	code, ips = doHttpOp("GET", obj, nil)
	assert.Equal(t, http.StatusNotFound, code)
	assert.Nil(t, ips)

	// add
	code, ips = doHttpOp("PUT", obj, []string{"1.2.3.4", "::2fee"})
	assert.Equal(t, http.StatusNoContent, code)
	assert.Nil(t, ips)

	// get
	code, ips = doHttpOp("GET", obj, nil)
	assert.Equal(t, http.StatusOK, code)
	assert.Equal(t, []string{"1.2.3.4", "::2fee"}, ips)

	assert.Equal(t, []string{"1.2.3.4", "::2fee"}, env.appIdx[obj].ExternalIp)
	waitForGet(t, env.appUpdateQ, 500*time.Millisecond, "app-1")
	waitForGetList(t, env.containerUpdateQ, 1000*time.Millisecond, cont_to_check)

	// update
	code, ips = doHttpOp("PUT", obj, []string{"1.2.3.5"})
	assert.Equal(t, http.StatusNoContent, code)
	assert.Nil(t, ips)

	// get
	code, ips = doHttpOp("GET", obj, nil)
	assert.Equal(t, http.StatusOK, code)
	assert.Equal(t, []string{"1.2.3.5"}, ips)

	assert.Equal(t, []string{"1.2.3.5"}, env.appIdx[obj].ExternalIp)
	waitForGet(t, env.appUpdateQ, 500*time.Millisecond, "app-1")
	waitForGetList(t, env.containerUpdateQ, 1000*time.Millisecond, cont_to_check)

	// delete
	code, ips = doHttpOp("DELETE", obj, nil)
	assert.Equal(t, http.StatusNoContent, code)
	assert.Nil(t, ips)

	// get
	code, ips = doHttpOp("GET", obj, nil)
	assert.Equal(t, http.StatusNotFound, code)
	assert.Nil(t, ips)

	assert.Equal(t, 0, len(env.appIdx[obj].ExternalIp))
	waitForGet(t, env.appUpdateQ, 500*time.Millisecond, "app-1")
	waitForGetList(t, env.containerUpdateQ, 1000*time.Millisecond, cont_to_check)

	// delete non-existent
	code, ips = doHttpOp("DELETE", obj, nil)
	assert.Equal(t, http.StatusNoContent, code)
	assert.Nil(t, ips)
}

func TestCfAppExtIpHttpInvalidPath(t *testing.T) {
	env := testCfEnvironment(t)
	handler := &AppExtIpHttpHandler{env: env}
	paths := map[string]int{
		"foo": http.StatusInternalServerError,
		"networking-aci/app_ext_ip/":         http.StatusNotFound,
		"networking-aci/app_ext_ip/foo/1234": http.StatusNotFound,
	}
	for p, c := range paths {
		req := httptest.NewRequest("GET", "http://localhost/"+p, nil)
		req.Header.Add("Authorization", "Bearer testtoken")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, c, resp.StatusCode)
	}
}

func TestCfAppExtIpHttpInvalidMethod(t *testing.T) {
	env := testCfEnvironment(t)
	handler := &AppExtIpHttpHandler{env: env}

	for _, v := range []string{"POST", "HEAD", "PATCH"} {
		req := httptest.NewRequest(v, "http://localhost/networking-aci/app_ext_ip/1234", nil)
		req.Header.Add("Authorization", "Bearer testtoken")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusMethodNotAllowed, w.Result().StatusCode)
	}
}

func TestCfAppExtIpHttpAuth(t *testing.T) {
	env := testCfEnvironment(t)
	cc := env.fakeCcClient()
	ri := cfapi.NewUserRoleInfo("some")
	ri.Spaces["space-one"] = struct{}{}
	ri.AuditedSpaces["space-two"] = struct{}{}
	ri.ManagedSpaces["space-three"] = struct{}{}
	cc.On("GetUserRoleInfo", "some").Return(ri, nil)

	auth := env.fakeCfAuthClient()
	auth.On("FetchTokenInfo", "testtoken-some").Return(
		&cfapi.TokenInfo{Scope: []string{}, UserId: "some", UserName: "someone"},
		nil)

	handler := &AppExtIpHttpHandler{env: env}

	doHttpOp := func(verb, id string) int {
		req := httptest.NewRequest(verb, "http://localhost/networking-aci/app_ext_ip/"+id, nil)
		req.Header.Add("Authorization", "Bearer testtoken-some")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w.Result().StatusCode
	}

	var code int

	cc.On("GetAppSpace", "zero").Return("space-zero", nil)
	code = doHttpOp("GET", "zero")
	assert.Equal(t, http.StatusForbidden, code)

	code = doHttpOp("PUT", "zero")
	assert.Equal(t, http.StatusForbidden, code)

	code = doHttpOp("DELETE", "zero")
	assert.Equal(t, http.StatusForbidden, code)

	cc.On("GetAppSpace", "one").Return("space-one", nil)
	code = doHttpOp("GET", "one")
	assert.Equal(t, http.StatusNotFound, code)

	code = doHttpOp("PUT", "one")
	assert.Equal(t, http.StatusForbidden, code)

	code = doHttpOp("DELETE", "one")
	assert.Equal(t, http.StatusForbidden, code)

	cc.On("GetAppSpace", "two").Return("space-two", nil)
	code = doHttpOp("GET", "two")
	assert.Equal(t, http.StatusNotFound, code)

	code = doHttpOp("PUT", "two")
	assert.Equal(t, http.StatusForbidden, code)

	code = doHttpOp("DELETE", "two")
	assert.Equal(t, http.StatusForbidden, code)

	cc.On("GetAppSpace", "three").Return("space-three", nil)
	code = doHttpOp("PUT", "three")
	assert.Equal(t, http.StatusBadRequest, code)

	code = doHttpOp("GET", "three")
	assert.Equal(t, http.StatusNotFound, code)

	code = doHttpOp("DELETE", "three")
	assert.Equal(t, http.StatusNoContent, code)
}
