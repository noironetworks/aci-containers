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
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/noironetworks/aci-containers/pkg/cfapi"
)

func TestCfAppVipDbOps(t *testing.T) {
	env := testCfEnvironment(t)
	ipdb := AppVipDb{}

	// set v4 & v6
	txn(env.db, func(txn *sql.Tx) {
		err := ipdb.Set(txn, "1", "1.2.3.4", "::fe80")
		assert.Nil(t, err)
	})

	// verify
	txn(env.db, func(txn *sql.Tx) {
		v4, v6, err := ipdb.Get(txn, "1")
		assert.Nil(t, err)
		assert.Equal(t, "1.2.3.4", v4)
		assert.Equal(t, "::fe80", v6)
	})

	// list
	txn(env.db, func(txn *sql.Tx) {
		val, err := ipdb.List(txn)
		assert.Nil(t, err)
		assert.Equal(t, 1, len(val))
		assert.Equal(t, "1", val[0].Guid)
	})

	// reset
	txn(env.db, func(txn *sql.Tx) {
		err := ipdb.Set(txn, "1", "", "")
		assert.Nil(t, err)
	})

	// verify
	txn(env.db, func(txn *sql.Tx) {
		v4, v6, err := ipdb.Get(txn, "1")
		assert.Nil(t, err)
		assert.Equal(t, "", v4)
		assert.Equal(t, "", v6)
	})

	// set only v4
	txn(env.db, func(txn *sql.Tx) {
		err := ipdb.Set(txn, "1", "1.2.3.4", "")
		assert.Nil(t, err)
	})

	// verify
	txn(env.db, func(txn *sql.Tx) {
		v4, v6, err := ipdb.Get(txn, "1")
		assert.Nil(t, err)
		assert.Equal(t, "1.2.3.4", v4)
		assert.Equal(t, "", v6)
	})

	// delete
	txn(env.db, func(txn *sql.Tx) {
		err := ipdb.Delete(txn, "1")
		assert.Nil(t, err)
	})
	// verify
	txn(env.db, func(txn *sql.Tx) {
		v4, v6, err := ipdb.Get(txn, "1")
		assert.Nil(t, err)
		assert.Equal(t, "", v4)
		assert.Equal(t, "", v6)
	})

	// delete again
	txn(env.db, func(txn *sql.Tx) {
		err := ipdb.Delete(txn, "1")
		assert.Nil(t, err)
	})
}

func TestCfAppVipHttpHandler(t *testing.T) {
	env := testCfEnvironment(t)
	handler := &AppVipHttpHandler{env: env}

	doHttpGet := func(id string) (int, []string) {
		req := httptest.NewRequest("GET", "http://localhost/networking-aci/app_vip/"+id, nil)
		req.Header.Add("Authorization", "Bearer testtoken")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		resp := w.Result()
		var msg AppVipGetMessageBody
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
	code, ips = doHttpGet("app-1")
	assert.Equal(t, http.StatusNotFound, code)
	assert.Nil(t, ips)

	ipdb := AppVipDb{}
	txn(env.db, func(txn *sql.Tx) {
		err := ipdb.Set(txn, "app-1", "1.2.3.4", "")
		assert.Nil(t, err)
	})
	code, ips = doHttpGet("app-1")
	assert.Equal(t, http.StatusOK, code)
	assert.Equal(t, []string{"1.2.3.4"}, ips)

	txn(env.db, func(txn *sql.Tx) {
		err := ipdb.Set(txn, "app-1", "1.2.3.4", "::fe80")
		assert.Nil(t, err)
	})
	code, ips = doHttpGet("app-1")
	assert.Equal(t, http.StatusOK, code)
	assert.Equal(t, []string{"1.2.3.4", "::fe80"}, ips)
}

func TestCfAppVipHttpInvalidPath(t *testing.T) {
	env := testCfEnvironment(t)
	handler := &AppVipHttpHandler{env: env}
	paths := map[string]int{
		"foo": http.StatusInternalServerError,
		"networking-aci/app_vip/":         http.StatusNotFound,
		"networking-aci/app_vip/foo/1234": http.StatusNotFound,
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

func TestCfAppVipHttpInvalidMethod(t *testing.T) {
	env := testCfEnvironment(t)
	handler := &AppVipHttpHandler{env: env}

	for _, v := range []string{"PUT", "POST", "HEAD", "PATCH", "DELETE"} {
		req := httptest.NewRequest(v, "http://localhost/networking-aci/app_vip/1234", nil)
		req.Header.Add("Authorization", "Bearer testtoken")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusMethodNotAllowed, w.Result().StatusCode)
	}
}

func TestCfAppVipHttpAuth(t *testing.T) {
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

	handler := &AppVipHttpHandler{env: env}
	ipdb := AppVipDb{}

	doHttpGet := func(id string) int {
		req := httptest.NewRequest("GET", "http://localhost/networking-aci/app_vip/"+id, nil)
		req.Header.Add("Authorization", "Bearer testtoken-some")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w.Result().StatusCode
	}

	txn(env.db, func(txn *sql.Tx) {
		err := ipdb.Set(txn, "zero", "1.2.3.3", "::fe7f")
		assert.Nil(t, err)
		err = ipdb.Set(txn, "one", "1.2.3.4", "::fe80")
		assert.Nil(t, err)
		err = ipdb.Set(txn, "two", "1.2.3.5", "::fe81")
		assert.Nil(t, err)
		err = ipdb.Set(txn, "three", "1.2.3.6", "::fe82")
		assert.Nil(t, err)
	})
	var code int

	cc.On("GetAppSpace", "zero").Return("space-zero", nil)
	code = doHttpGet("zero")
	assert.Equal(t, http.StatusForbidden, code)

	cc.On("GetAppSpace", "one").Return("space-one", nil)
	code = doHttpGet("one")
	assert.Equal(t, http.StatusOK, code)

	cc.On("GetAppSpace", "two").Return("space-one", nil)
	code = doHttpGet("two")
	assert.Equal(t, http.StatusOK, code)

	cc.On("GetAppSpace", "three").Return("space-three", nil)
	code = doHttpGet("three")
	assert.Equal(t, http.StatusOK, code)
}
