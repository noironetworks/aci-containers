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
)

func doTestAnnoDBForKind(t *testing.T, kind int) {
	env := testCfEnvironment(t)
	ea_db := EpgAnnotationDb{}

	// add
	txn(env.db, func(txn *sql.Tx) {
		err := ea_db.UpdateAnnotation(txn, "1", kind, "add")
		assert.Nil(t, err)
	})

	// verify
	txn(env.db, func(txn *sql.Tx) {
		val, err := ea_db.GetAnnotation(txn, "1", kind)
		assert.Nil(t, err)
		assert.Equal(t, "add", val)
	})

	// list by kind
	txn(env.db, func(txn *sql.Tx) {
		val, err := ea_db.List(txn, kind)
		assert.Nil(t, err)
		assert.Equal(t, 1, len(val))
		assert.Equal(t, "1", val[0].Guid)
	})

	// list without kind
	txn(env.db, func(txn *sql.Tx) {
		val, err := ea_db.List(txn, CF_OBJ_LAST)
		assert.Nil(t, err)
		assert.Equal(t, 1, len(val))
		assert.Equal(t, "1", val[0].Guid)
		assert.Equal(t, kind, val[0].Kind)
	})

	// update
	txn(env.db, func(txn *sql.Tx) {
		err := ea_db.UpdateAnnotation(txn, "1", kind, "update")
		assert.Nil(t, err)
	})

	// verify
	txn(env.db, func(txn *sql.Tx) {
		val, err := ea_db.GetAnnotation(txn, "1", kind)
		assert.Nil(t, err)
		assert.Equal(t, "update", val)
	})

	// delete
	txn(env.db, func(txn *sql.Tx) {
		err := ea_db.DeleteAnnotation(txn, "1", kind)
		assert.Nil(t, err)
	})

	// verify
	txn(env.db, func(txn *sql.Tx) {
		val, err := ea_db.GetAnnotation(txn, "1", kind)
		assert.Nil(t, err)
		assert.Equal(t, "", val)
	})

	// delete again
	txn(env.db, func(txn *sql.Tx) {
		err := ea_db.DeleteAnnotation(txn, "1", kind)
		assert.Nil(t, err)
	})
}

func TestCfAnnotationDbOrgLifecycle(t *testing.T) {
	doTestAnnoDBForKind(t, CF_OBJ_ORG)
}

func TestCfAnnotationDbSpaceLifecycle(t *testing.T) {
	doTestAnnoDBForKind(t, CF_OBJ_SPACE)
}

func TestCfAnnotationDbAppLifecycle(t *testing.T) {
	doTestAnnoDBForKind(t, CF_OBJ_APP)
}

func TestCfAnnotationDbInvalidKind(t *testing.T) {
	env := testCfEnvironment(t)
	ea_db := EpgAnnotationDb{}
	kind := CF_OBJ_LAST

	txn, _ := env.db.Begin()
	err := ea_db.UpdateAnnotation(txn, "1", kind, "add")
	assert.NotNil(t, err)

	err = ea_db.DeleteAnnotation(txn, "1", kind)
	assert.NotNil(t, err)

	_, err = ea_db.GetAnnotation(txn, "1", kind)
	assert.NotNil(t, err)

	txn.Commit()
}

func TestCfAnnotationDbResolve(t *testing.T) {
	env := testCfEnvironment(t)
	ea_db := EpgAnnotationDb{}

	// resolve -> nothing
	txn(env.db, func(txn *sql.Tx) {
		val, err := ea_db.ResolveAnnotation(txn, "1", "2", "3")
		assert.Nil(t, err)
		assert.Equal(t, "", val)
	})

	// add org annotation
	txn(env.db, func(txn *sql.Tx) {
		err := ea_db.UpdateAnnotation(txn, "3", CF_OBJ_ORG, "org")
		assert.Nil(t, err)
	})

	// resolve and verify
	txn(env.db, func(txn *sql.Tx) {
		val, err := ea_db.ResolveAnnotation(txn, "1", "2", "3")
		assert.Nil(t, err)
		assert.Equal(t, "org", val)
	})

	// add space annotation
	txn(env.db, func(txn *sql.Tx) {
		err := ea_db.UpdateAnnotation(txn, "2", CF_OBJ_SPACE, "space")
		assert.Nil(t, err)
	})

	// resolve and verify
	txn(env.db, func(txn *sql.Tx) {
		val, err := ea_db.ResolveAnnotation(txn, "1", "2", "3")
		assert.Nil(t, err)
		assert.Equal(t, "space", val)
	})

	// add app annotation
	txn(env.db, func(txn *sql.Tx) {
		err := ea_db.UpdateAnnotation(txn, "1", CF_OBJ_APP, "app")
		assert.Nil(t, err)
	})

	// resolve and verify
	txn(env.db, func(txn *sql.Tx) {
		val, err := ea_db.ResolveAnnotation(txn, "1", "2", "3")
		assert.Nil(t, err)
		assert.Equal(t, "app", val)
	})
}

func TestCfAnnotationHttpPathPrefix(t *testing.T) {
	env := testCfEnvironment(t)
	h := EpgAnnotationHttpHandler{env: env}
	assert.Equal(t, "/networking-aci/epg/", h.Path())
}

func doHttp(t *testing.T, handler *EpgAnnotationHttpHandler, verb, kind, id, data string) (int, string) {
	var rdr io.Reader
	if data != "" {
		str, err := json.Marshal(EpgAnnotationPutMessageBody{Value: data})
		assert.Nil(t, err)
		rdr = strings.NewReader(string(str))
	}
	req := httptest.NewRequest(verb, "http://localhost/networking-aci/epg/"+kind+"/"+id, rdr)
	req.Header.Add("Authorization", "Bearer testtoken")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	resp := w.Result()
	var msg EpgAnnotationGetMessageBody
	if resp.StatusCode == 200 {
		assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
		body, _ := ioutil.ReadAll(resp.Body)
		assert.Nil(t, json.Unmarshal(body, &msg))
		assert.Equal(t, id, msg.Guid)
		assert.Equal(t, kind, msg.Kind)
	}
	return resp.StatusCode, msg.Value
}

func doTestAnnoHttpHandlerForKind(t *testing.T, kind string) {
	env := testCfEnvironment(t)
	h := &EpgAnnotationHttpHandler{env: env}
	cont_to_check := []interface{}{"c-1", "c-2"}
	if kind == "space" {
		cont_to_check = append(cont_to_check, "c-3")
	}
	if kind == "org" {
		cont_to_check = append(cont_to_check, "c-3", "c-4")
	}

	var code int
	var value string
	obj := kind + "-1"

	// get non-existent
	code, value = doHttp(t, h, "GET", kind, obj, "")
	assert.Equal(t, http.StatusNotFound, code)
	assert.Equal(t, "", value)

	// add
	code, value = doHttp(t, h, "PUT", kind, obj, "add")
	assert.Equal(t, http.StatusNoContent, code)
	assert.Equal(t, "", value)

	// get
	code, value = doHttp(t, h, "GET", kind, obj, "")
	assert.Equal(t, http.StatusOK, code)
	assert.Equal(t, "add", value)

	waitForGetList(t, env.containerUpdateQ, 1000*time.Millisecond, cont_to_check)

	// update
	code, value = doHttp(t, h, "PUT", kind, obj, "update")
	assert.Equal(t, http.StatusNoContent, code)
	assert.Equal(t, "", value)

	// get
	code, value = doHttp(t, h, "GET", kind, obj, "")
	assert.Equal(t, http.StatusOK, code)
	assert.Equal(t, "update", value)

	waitForGetList(t, env.containerUpdateQ, 1000*time.Millisecond, cont_to_check)

	// delete
	code, value = doHttp(t, h, "DELETE", kind, obj, "")
	assert.Equal(t, http.StatusNoContent, code)
	assert.Equal(t, "", value)

	// get
	code, value = doHttp(t, h, "GET", kind, obj, "")
	assert.Equal(t, http.StatusNotFound, code)
	assert.Equal(t, "", value)

	waitForGetList(t, env.containerUpdateQ, 1000*time.Millisecond, cont_to_check)

	// delete non-existent
	code, value = doHttp(t, h, "DELETE", kind, obj, "")
	assert.Equal(t, http.StatusNoContent, code)
	assert.Equal(t, "", value)
}

func TestCfAnnotationHttpOrgLifecycle(t *testing.T) {
	doTestAnnoHttpHandlerForKind(t, "org")
}

func TestCfAnnotationHttpSpaceLifecycle(t *testing.T) {
	doTestAnnoHttpHandlerForKind(t, "space")
}

func TestCfAnnotationHttpAppLifecycle(t *testing.T) {
	doTestAnnoHttpHandlerForKind(t, "app")
}

func TestCfAnnotationHttpInvalidKind(t *testing.T) {
	env := testCfEnvironment(t)
	h := &EpgAnnotationHttpHandler{env: env}
	kind := "foo"

	code, _ := doHttp(t, h, "GET", kind, "some-obj", "")
	assert.Equal(t, http.StatusNotFound, code)

	code, _ = doHttp(t, h, "PUT", kind, "some-obj", "")
	assert.Equal(t, http.StatusNotFound, code)

	code, _ = doHttp(t, h, "DELETE", kind, "some-obj", "")
	assert.Equal(t, http.StatusNotFound, code)
}

func TestCfAnnotationHttpInvalidPath(t *testing.T) {
	env := testCfEnvironment(t)
	handler := EpgAnnotationHttpHandler{env: env}
	paths := map[string]int{
		"foo": http.StatusInternalServerError,
		"networking-aci/epg/":            http.StatusNotFound,
		"networking-aci/epg/app":         http.StatusNotFound,
		"networking-aci/epg/org/foo/bar": http.StatusNotFound,
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

func TestCfAnnotationHttpInvalidMethod(t *testing.T) {
	env := testCfEnvironment(t)
	h := &EpgAnnotationHttpHandler{env: env}

	for _, v := range []string{"POST", "HEAD", "PATCH"} {
		code, _ := doHttp(t, h, v, "org", "some-obj", "")
		assert.Equal(t, http.StatusMethodNotAllowed, code)
	}
}

func TestCfAnnotationHttpInvalidPutBody(t *testing.T) {
	env := testCfEnvironment(t)
	handler := EpgAnnotationHttpHandler{env: env}

	for _, kind := range []string{"org", "space", "app"} {
		for _, body := range []string{"{\"value\": \"\"}", "{", "{\"foo\": 123}"} {
			req := httptest.NewRequest(
				"PUT", "http://localhost/networking-aci/epg/"+kind+"/"+kind+"-1",
				strings.NewReader(body))
			req.Header.Add("Authorization", "Bearer testtoken")
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			resp := w.Result()
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		}
	}
}

func doTestAnnoHttpHandlerAuthForKind(t *testing.T, kind string) {
	env := testCfEnvironment(t)
	cc := env.fakeCcClient()
	ri := cfapi.NewUserRoleInfo("some")
	ri.Spaces["space-one"] = struct{}{}
	ri.AuditedSpaces["space-two"] = struct{}{}
	ri.ManagedSpaces["space-three"] = struct{}{}
	ri.Organizations["org-one"] = struct{}{}
	ri.AuditedOrganizations["org-two"] = struct{}{}
	ri.ManagedOrganizations["org-three"] = struct{}{}
	cc.On("GetUserRoleInfo", "some").Return(ri, nil)

	auth := env.fakeCfAuthClient()
	auth.On("FetchTokenInfo", "testtoken-some").Return(
		&cfapi.TokenInfo{Scope: []string{}, UserId: "some", UserName: "someone"},
		nil)

	h := &EpgAnnotationHttpHandler{env: env}
	doHttpOp := func(verb, kind, id string) int {
		var rdr io.Reader
		if verb == "PUT" {
			str, err := json.Marshal(EpgAnnotationPutMessageBody{Value: "epg42"})
			assert.Nil(t, err)
			rdr = strings.NewReader(string(str))
		}
		req := httptest.NewRequest(verb, "http://localhost/networking-aci/epg/"+kind+"/"+id, rdr)
		req.Header.Add("Authorization", "Bearer testtoken-some")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w.Result().StatusCode
	}

	var code int

	cc.On("GetAppSpace", "zero").Return("space-zero", nil)
	code = doHttpOp("GET", kind, "zero")
	assert.Equal(t, http.StatusForbidden, code)

	code = doHttpOp("PUT", kind, "zero")
	assert.Equal(t, http.StatusForbidden, code)

	code = doHttpOp("DELETE", kind, "zero")
	assert.Equal(t, http.StatusForbidden, code)

	cc.On("GetAppSpace", kind+"-one").Return("space-one", nil)
	code = doHttpOp("GET", kind, kind+"-one")
	assert.Equal(t, http.StatusNotFound, code)

	code = doHttpOp("PUT", kind, kind+"-one")
	assert.Equal(t, http.StatusForbidden, code)

	code = doHttpOp("DELETE", kind, kind+"-one")
	assert.Equal(t, http.StatusForbidden, code)

	cc.On("GetAppSpace", kind+"-two").Return("space-two", nil)
	code = doHttpOp("GET", kind, kind+"-two")
	assert.Equal(t, http.StatusNotFound, code)

	code = doHttpOp("PUT", kind, kind+"-two")
	assert.Equal(t, http.StatusForbidden, code)

	code = doHttpOp("DELETE", kind, kind+"-two")
	assert.Equal(t, http.StatusForbidden, code)

	cc.On("GetAppSpace", kind+"-three").Return("space-three", nil)
	code = doHttpOp("PUT", kind, kind+"-three")
	assert.Equal(t, http.StatusNoContent, code)

	code = doHttpOp("GET", kind, kind+"-three")
	assert.Equal(t, http.StatusOK, code)

	code = doHttpOp("DELETE", kind, kind+"-three")
	assert.Equal(t, http.StatusNoContent, code)
}

func TestCfAnnotationHttpAuthOrg(t *testing.T) {
	doTestAnnoHttpHandlerAuthForKind(t, "org")
}

func TestCfAnnotationHttpAuthSpace(t *testing.T) {
	doTestAnnoHttpHandlerAuthForKind(t, "space")
}

func TestCfAnnotationHttpAuthApp(t *testing.T) {
	doTestAnnoHttpHandlerAuthForKind(t, "app")
}
