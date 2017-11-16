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

type AppExtIpDb struct {
}

type ExtIpAlloc struct {
	IP      string
	Dynamic bool
	Pool    string
}

type ExtIpAllocApp struct {
	Guid string
	ExtIpAlloc
}

func (db *AppExtIpDb) Get(txn *sql.Tx, appId string) ([]ExtIpAlloc, error) {
	var ips []ExtIpAlloc
	rows, err := txn.Query("SELECT ip, dynamic, pool FROM aci_app_ext_ip WHERE guid=? ORDER BY ip ASC", appId)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var ip, pool string
		var dynamic int
		if err := rows.Scan(&ip, &dynamic, &pool); err == nil {
			ips = append(ips, ExtIpAlloc{ip, dynamic != 0, pool})
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return ips, nil
}

func (db *AppExtIpDb) List(txn *sql.Tx) ([]ExtIpAllocApp, error) {
	var ips []ExtIpAllocApp
	rows, err := txn.Query("SELECT guid, ip, dynamic, pool FROM aci_app_ext_ip ORDER BY guid, ip ASC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var guid, ip, pool string
		var dynamic int
		if err := rows.Scan(&guid, &ip, &dynamic, &pool); err == nil {
			ips = append(ips, ExtIpAllocApp{guid, ExtIpAlloc{ip, dynamic != 0, pool}})
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return ips, nil
}

func (db *AppExtIpDb) Set(txn *sql.Tx, appId string, ips []ExtIpAlloc) error {
	err := db.Delete(txn, appId)
	if err != nil {
		return fmt.Errorf("Error deleting old rows - %s", err.Error())
	}
	for _, ip := range ips {
		dyn := 0
		if ip.Dynamic {
			dyn = 1
		}
		_, err = txn.Exec("INSERT INTO aci_app_ext_ip(guid, ip, dynamic, pool) VALUES(?, ?, ?, ?)",
			appId, ip.IP, dyn, ip.Pool)
		if err != nil {
			return err
		}
	}
	return nil
}

func (db *AppExtIpDb) Delete(txn *sql.Tx, appId string) error {
	q := "DELETE FROM aci_app_ext_ip WHERE guid=?"
	_, err := txn.Exec(q, appId)
	return err
}

type AppExtIpHttpHandler struct {
	env *CfEnvironment
}

type AppExtIpGetMessageBody struct {
	Guid string   `json:"guid, omitempty"`
	IP   []string `json:"ip, omitempty"`
}

type AppExtIpPutMessageBody struct {
	IP []string `json:"ip, omitempty"`
}

func (h *AppExtIpHttpHandler) Path() string {
	return h.env.cfconfig.ApiPathPrefix + "/app_ext_ip/"
}

func (h *AppExtIpHttpHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
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
	// expect paths of the form <prefix>/<id>
	parts := strings.Split(path[len(h.Path()):], "/")
	if len(parts) != 1 || parts[0] == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	appId := parts[0]
	access := "read"
	if req.Method != http.MethodGet {
		access = "write"
	}
	ok, err := cfapi.HasAccess(h.env.ccClient, h.env.cfAuthClient, req, "app", appId, access)
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
	var new_ips []ExtIpAlloc
	defer func() {
		if doUpdate {
			// update the index
			var new_ext []string
			for _, i := range new_ips {
				new_ext = append(new_ext, i.IP)
			}
			h.env.indexLock.Lock()
			defer h.env.indexLock.Unlock()
			appInfo := h.env.appIdx[appId]
			if appInfo == nil {
				appInfo = NewAppInfo(appId)
			}
			appInfo.ExternalIp = new_ext
			h.env.appIdx[appId] = appInfo
			// notify change
			h.env.appUpdateQ.Add(appId)
			h.env.scheduleAppContainersUpdateLocked(appId)
		}
	}()

	aei_db := AppExtIpDb{}
	txn, err := h.env.db.Begin()
	if err != nil {
		h.env.log.Warning("Failed to start DB transaction: ", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer func() {
		if err == nil {
			txn.Commit()
		} else {
			txn.Rollback()
		}
	}()

	status := 0
	switch req.Method {
	case http.MethodGet:
		var ips []ExtIpAlloc
		ips, err = aei_db.Get(txn, appId)
		if err == nil {
			if ips == nil {
				w.WriteHeader(http.StatusNotFound)
			} else {
				w.Header().Set("Content-Type", "application/json")
				ips_only := make([]string, 0, len(ips))
				for _, i := range ips {
					ips_only = append(ips_only, i.IP)
				}
				m := AppExtIpGetMessageBody{Guid: appId, IP: ips_only}
				json.NewEncoder(w).Encode(m)
			}
		}
	case http.MethodDelete:
		var ips []ExtIpAlloc
		ips, err = aei_db.Get(txn, appId)
		if err != nil {
			h.env.log.Warn("Failed to read app external IPs: ", err)
		}
		err = aei_db.Delete(txn, appId)
		if err == nil {
			_, err1 := h.env.ManageAppExtIp(ips, nil, false)
			if err1 != nil {
				h.env.log.Warning("Failed to unmanage ext ip: ", err1)
			}
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
		var msg AppExtIpPutMessageBody
		dynamic := false
		err = json.Unmarshal(body, &msg)
		if err != nil {
			status = http.StatusBadRequest
			break
		}
		if len(msg.IP) == 0 && dynamic == false {
			err = fmt.Errorf("Missing data")
			status = http.StatusBadRequest
			break
		}
		if len(msg.IP) > 0 && dynamic == true {
			err = fmt.Errorf("Both static and dynamic address cannot be requested")
			status = http.StatusBadRequest
			break
		}
		ips := make([]ExtIpAlloc, 0, len(msg.IP))
		for _, i := range msg.IP {
			ips = append(ips, ExtIpAlloc{IP: i, Dynamic: false, Pool: ""})
		}
		var current_ips []ExtIpAlloc
		current_ips, err = aei_db.Get(txn, appId)
		if err != nil {
			h.env.log.Warn("Failed to read app external IPs: ", err)
			break
		}
		new_ips, err = h.env.ManageAppExtIp(current_ips, ips, dynamic)
		if err == nil {
			err = aei_db.Set(txn, appId, new_ips)
		} else {
			h.env.log.Error("Updating external IPs failed: ", err)
			status = http.StatusBadRequest
		}
		if err == nil {
			w.WriteHeader(http.StatusNoContent)
			doUpdate = true
		}
	}
	if err != nil {
		if status == 0 {
			h.env.log.Warning("Failed to update DB for app ext ip: ", err)
			status = http.StatusInternalServerError
		} else {
			h.env.log.Debug("Request failed: ", err)
		}
		w.WriteHeader(status)
	}
}
