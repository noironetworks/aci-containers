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
	"net/http"
	"strings"

	"github.com/noironetworks/aci-containers/pkg/cfapi"
)

type AppVipDb struct {
}

func (db *AppVipDb) Get(txn *sql.Tx, appId string) (string, string, error) {
	var v4, v6 string
	err := txn.QueryRow("SELECT ip_v4, ip_v6 FROM aci_app_vip WHERE guid=?",
		appId).Scan(&v4, &v6)
	if err == nil {
		return v4, v6, nil
	} else if err == sql.ErrNoRows {
		return "", "", nil
	}
	return "", "", err
}

func (db *AppVipDb) Set(txn *sql.Tx, appId, v4, v6 string) error {
	res, err := txn.Exec("UPDATE aci_app_vip SET ip_v4=?, ip_v6=? WHERE guid=?",
		v4, v6, appId)
	if err != nil {
		return err
	}
	nrows, _ := res.RowsAffected()
	if nrows == 0 {
		_, err = txn.Exec("INSERT INTO aci_app_vip(guid, ip_v4, ip_v6) VALUES(?, ?, ?)",
			appId, v4, v6)
	}
	return err
}

func (db *AppVipDb) Delete(txn *sql.Tx, appId string) error {
	q := "DELETE FROM aci_app_vip WHERE guid=?"
	_, err := txn.Exec(q, appId)
	return err
}

type VipAllocApp struct {
	Guid string
	IPv4 string
	IPv6 string
}

func (db *AppVipDb) List(txn *sql.Tx) ([]VipAllocApp, error) {
	var ips []VipAllocApp
	rows, err := txn.Query("SELECT guid, ip_v4, ip_v6 FROM aci_app_vip ORDER BY guid ASC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var guid, ip_v4, ip_v6 string
		if err := rows.Scan(&guid, &ip_v4, &ip_v6); err == nil {
			ips = append(ips, VipAllocApp{guid, ip_v4, ip_v6})
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return ips, nil
}

type AppVipHttpHandler struct {
	env *CfEnvironment
}

type AppVipGetMessageBody struct {
	Guid string   `json:"guid, omitempty"`
	IP   []string `json:"ip, omitempty"`
}

func (h *AppVipHttpHandler) Path() string {
	return h.env.cfconfig.ApiPathPrefix + "/app_vip/"
}

func (h *AppVipHttpHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	path := req.URL.Path
	if !strings.HasPrefix(path, h.Path()) {
		h.env.log.Warning("Asked to handle unknown path: ", path)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if req.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	// expect paths of the form <prefix>/<id>
	parts := strings.Split(path[len(h.Path()):], "/")
	if len(parts) != 1 || parts[0] == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	ok, err := cfapi.HasAccess(h.env.ccClient, h.env.cfAuthClient, req, "app", parts[0], "read")
	if err != nil {
		h.env.log.Warning("Failed to verify authorized access: ", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if !ok {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	ipdb := AppVipDb{}
	txn, err := h.env.db.Begin()
	if err != nil {
		h.env.log.Warning("Failed to start DB transaction: ", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer txn.Commit()

	v4, v6, err := ipdb.Get(txn, parts[0])
	if err == nil {
		m := AppVipGetMessageBody{Guid: parts[0]}
		if v4 != "" {
			m.IP = append(m.IP, v4)
		}
		if v6 != "" {
			m.IP = append(m.IP, v6)
		}
		if len(m.IP) == 0 {
			w.WriteHeader(http.StatusNotFound)
		} else {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(m)
		}
	} else {
		h.env.log.Warning("Failed to get app virtual ip: ", err)
		w.WriteHeader(http.StatusInternalServerError)
	}
}
