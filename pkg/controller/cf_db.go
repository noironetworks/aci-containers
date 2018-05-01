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
	_ "github.com/go-sql-driver/mysql"
)

type migration struct {
	version    string
	statements []string
}

func getV0Migration(db *sql.DB, txn *sql.Tx) *migration {
	m := migration{version: "0",
		statements: []string{
			`CREATE TABLE IF NOT EXISTS aci_epg_annotations (
					guid VARCHAR(255) NOT NULL,
					kind INTEGER,
					value VARCHAR(255),
					PRIMARY KEY (guid, kind)
					);`,
			`CREATE TABLE IF NOT EXISTS aci_app_vip (
					guid VARCHAR(255) NOT NULL,
					ip_v4 VARCHAR(16),
					ip_v6 VARCHAR(64),
					PRIMARY KEY (guid)
					);`,
			`CREATE TABLE IF NOT EXISTS aci_app_ext_ip (
					guid VARCHAR(255) NOT NULL,
					ip VARCHAR(64),
					dynamic INTEGER,
					pool VARCHAR(255),
					PRIMARY KEY (guid, ip)
					);`,
		},
	}
	return &m
}

func getV1Migration(db *sql.DB, txn *sql.Tx) *migration {
	m := migration{version: "1",
		statements: []string{
			`CREATE TABLE IF NOT EXISTS aci_cell_pod_networks (
					guid VARCHAR(255) NOT NULL,
					start VARCHAR(64),
					end VARCHAR(64),
					PRIMARY KEY (guid, start, end)
					);`,
			`CREATE TABLE IF NOT EXISTS aci_cell_service_ep (
					guid VARCHAR(255) NOT NULL,
					mac VARCHAR(24),
					ip_v4 VARCHAR(16),
					ip_v6 VARCHAR(64),
					PRIMARY KEY (guid)
					);`,
		},
	}
	return &m
}

func (env *CfEnvironment) RunDbMigration() error {
	txn, err := env.db.Begin()
	if err != nil {
		return err
	}

	var stmts []*migration
	stmts = append(stmts,
		getV0Migration(env.db, txn),
		getV1Migration(env.db, txn))

	// TODO inspect the current version in the DB
	for _, m := range stmts {
		for _, s := range m.statements {
			_, err = txn.Exec(s)
			if err != nil {
				txn.Rollback()
				return err
			}
		}
	}
	err = txn.Commit()
	return err
}
