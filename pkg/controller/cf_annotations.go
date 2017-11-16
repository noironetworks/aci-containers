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
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/noironetworks/aci-containers/pkg/cfapi"
)

type EpgAnnotationDb struct {
}

const (
	CF_OBJ_APP = iota
	CF_OBJ_SPACE
	CF_OBJ_ORG
	CF_OBJ_LAST
)

func (db *EpgAnnotationDb) UpdateAnnotation(txn *sql.Tx, objId string, objKind int, ann string) error {
	if objKind < 0 || objKind >= CF_OBJ_LAST {
		return fmt.Errorf("Invalid object kind %d", objKind)
	}
	res, err := txn.Exec("UPDATE aci_epg_annotations SET value=? WHERE guid=? AND kind=?",
		ann, objId, objKind)
	if err != nil {
		return err
	}
	nrows, _ := res.RowsAffected()
	if nrows == 0 {
		_, err = txn.Exec("INSERT INTO aci_epg_annotations(guid, kind, value) VALUES(?, ?, ?)",
			objId, objKind, ann)
	}
	return err
}

func (db *EpgAnnotationDb) DeleteAnnotation(txn *sql.Tx, objId string, objKind int) error {
	if objKind < 0 || objKind >= CF_OBJ_LAST {
		return fmt.Errorf("Invalid object kind %d", objKind)
	}
	q := "DELETE FROM aci_epg_annotations WHERE guid=? AND kind=?"
	_, err := txn.Exec(q, objId, objKind)
	return err
}

func (db *EpgAnnotationDb) GetAnnotation(txn *sql.Tx, objId string, objKind int) (string, error) {
	if objKind < 0 || objKind >= CF_OBJ_LAST {
		return "", fmt.Errorf("Invalid object kind %d", objKind)
	}
	var v string
	err := txn.QueryRow("SELECT value FROM aci_epg_annotations WHERE guid=? AND kind=?",
		objId, objKind).Scan(&v)
	if err == nil {
		return v, nil
	} else if err == sql.ErrNoRows {
		return "", nil
	}
	return "", err
}

type AnnotationObject struct {
	Guid  string
	Value string
	Kind  int
}

func (db *EpgAnnotationDb) List(txn *sql.Tx, kind int) ([]AnnotationObject, error) {
	var objs []AnnotationObject
	var rows *sql.Rows
	var err error
	if kind == CF_OBJ_LAST {
		rows, err = txn.Query("SELECT guid, value, kind FROM aci_epg_annotations ORDER BY guid ASC")
	} else {
		rows, err = txn.Query("SELECT guid, value, kind FROM aci_epg_annotations WHERE kind=? ORDER BY guid ASC",
			kind)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var guid, value string
		var knd int
		if err := rows.Scan(&guid, &value, &knd); err == nil {
			objs = append(objs, AnnotationObject{guid, value, knd})
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return objs, nil
}

func (db *EpgAnnotationDb) ResolveAnnotation(txn *sql.Tx, appId string, spaceId string,
	orgId string) (string, error) {
	var v string
	var k int
	err := txn.QueryRow("SELECT kind, value FROM aci_epg_annotations WHERE (guid=? AND kind=?) "+
		"OR (guid=? AND kind=?) OR (guid=? AND kind=?) "+
		"ORDER BY kind ASC",
		appId, CF_OBJ_APP, spaceId, CF_OBJ_SPACE, orgId, CF_OBJ_ORG).Scan(&k, &v)
	if err == nil {
		return v, nil
	} else if err == sql.ErrNoRows {
		return "", nil
	}
	return "", err
}

type EpgAnnotationHttpHandler struct {
	env *CfEnvironment
}

type EpgAnnotationPutMessageBody struct {
	Value string `json:"value, omitempty"`
}

type EpgAnnotationGetMessageBody struct {
	Guid  string `json:"guid, omitempty"`
	Kind  string `json:"kind, omitempty"`
	Value string `json:"value, omitempty"`
}

func (h *EpgAnnotationHttpHandler) Path() string {
	return h.env.cfconfig.ApiPathPrefix + "/epg/"
}

func (h *EpgAnnotationHttpHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	path := req.URL.Path
	if !strings.HasPrefix(path, h.Path()) {
		h.env.log.Warning("Asked to handle unknown path: ", path)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if req.Method != http.MethodGet && req.Method != http.MethodPut && req.Method != http.MethodDelete {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	// expect paths of the form <org|space|app>/<id>
	parts := strings.Split(path[len(h.Path()):], "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	var updateFunc func(string)
	var kind int = CF_OBJ_LAST
	switch parts[0] {
	case "org":
		kind = CF_OBJ_ORG
		updateFunc = h.env.scheduleOrgContainersUpdateLocked
	case "space":
		kind = CF_OBJ_SPACE
		updateFunc = h.env.scheduleSpaceContainersUpdateLocked
	case "app":
		kind = CF_OBJ_APP
		updateFunc = h.env.scheduleAppContainersUpdateLocked
	default:
		w.WriteHeader(http.StatusNotFound)
		return
	}

	access := "read"
	if req.Method != http.MethodGet {
		access = "write"
	}
	ok, err := cfapi.HasAccess(h.env.ccClient, h.env.cfAuthClient, req, parts[0], parts[1], access)
	if err != nil {
		h.env.log.Warning("Failed to verify authorized access: ", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if !ok {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	doUpdate := false
	defer func() {
		if doUpdate {
			h.env.indexLock.Lock()
			defer h.env.indexLock.Unlock()
			h.env.lookupOrCreate(parts[1], kind)
			updateFunc(parts[1])
		}
	}()

	ea_db := EpgAnnotationDb{}
	txn, err := h.env.db.Begin()
	if err != nil {
		h.env.log.Warning("Failed to start DB transaction: ", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer txn.Commit()

	status := 0
	switch req.Method {
	case http.MethodGet:
		var val string
		val, err = ea_db.GetAnnotation(txn, parts[1], kind)
		if err == nil {
			if val == "" {
				w.WriteHeader(http.StatusNotFound)
			} else {
				w.Header().Set("Content-Type", "application/json")
				m := EpgAnnotationGetMessageBody{Guid: parts[1], Kind: parts[0], Value: val}
				json.NewEncoder(w).Encode(m)
			}
		}
	case http.MethodDelete:
		err = ea_db.DeleteAnnotation(txn, parts[1], kind)
		if err == nil {
			w.WriteHeader(http.StatusNoContent)
			doUpdate = true
		}
	case http.MethodPut:
		var body []byte
		body, err = ioutil.ReadAll(req.Body)
		if err != nil {
			h.env.log.Warning("Failed to read request body: ", err)
			break
		}
		var msg EpgAnnotationPutMessageBody
		err = json.Unmarshal(body, &msg)
		if err != nil || msg.Value == "" {
			if err == nil {
				err = fmt.Errorf("Missing data")
			}
			status = http.StatusBadRequest
			break
		}
		err = ea_db.UpdateAnnotation(txn, parts[1], kind, msg.Value)
		if err == nil {
			w.WriteHeader(http.StatusNoContent)
			doUpdate = true
		}
	}
	if err != nil {
		if status == 0 {
			h.env.log.Warning("Failed to update DB for EPG annotation: ", err)
			status = http.StatusInternalServerError
		}
		w.WriteHeader(status)
	}
}
