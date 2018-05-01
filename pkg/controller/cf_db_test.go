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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCfDbMigration(t *testing.T) {
	env := testCfEnvironmentNoMigration(t)
	err := env.RunDbMigration()
	assert.Nil(t, err)

	{
		rows, err := env.db.Query("SELECT guid, kind, value from aci_epg_annotations")
		cts, err := rows.ColumnTypes()
		rows.Close()
		assert.Nil(t, err)

		assert.Equal(t, 3, len(cts))
		assert.Equal(t, "guid", cts[0].Name())
		assert.Equal(t, "VARCHAR(255)", cts[0].DatabaseTypeName())

		assert.Equal(t, "kind", cts[1].Name())
		assert.Equal(t, "INTEGER", cts[1].DatabaseTypeName())

		assert.Equal(t, "value", cts[2].Name())
		assert.Equal(t, "VARCHAR(255)", cts[2].DatabaseTypeName())
	}

	{
		rows, err := env.db.Query("SELECT guid, ip_v4, ip_v6 from aci_app_vip")
		cts, err := rows.ColumnTypes()
		rows.Close()
		assert.Nil(t, err)

		assert.Equal(t, 3, len(cts))
		assert.Equal(t, "guid", cts[0].Name())
		assert.Equal(t, "VARCHAR(255)", cts[0].DatabaseTypeName())

		assert.Equal(t, "ip_v4", cts[1].Name())
		assert.Equal(t, "VARCHAR(16)", cts[1].DatabaseTypeName())

		assert.Equal(t, "ip_v6", cts[2].Name())
		assert.Equal(t, "VARCHAR(64)", cts[2].DatabaseTypeName())
	}

	{
		rows, err := env.db.Query("SELECT guid, ip, dynamic, pool from aci_app_ext_ip")
		cts, err := rows.ColumnTypes()
		rows.Close()
		assert.Nil(t, err)

		assert.Equal(t, 4, len(cts))
		assert.Equal(t, "guid", cts[0].Name())
		assert.Equal(t, "VARCHAR(255)", cts[0].DatabaseTypeName())

		assert.Equal(t, "ip", cts[1].Name())
		assert.Equal(t, "VARCHAR(64)", cts[1].DatabaseTypeName())

		assert.Equal(t, "dynamic", cts[2].Name())
		assert.Equal(t, "INTEGER", cts[2].DatabaseTypeName())

		assert.Equal(t, "pool", cts[3].Name())
		assert.Equal(t, "VARCHAR(255)", cts[3].DatabaseTypeName())
	}

	{
		rows, err := env.db.Query(
			"SELECT guid, start, end from aci_cell_pod_networks")
		cts, err := rows.ColumnTypes()
		rows.Close()
		assert.Nil(t, err)

		assert.Equal(t, 3, len(cts))
		assert.Equal(t, "guid", cts[0].Name())
		assert.Equal(t, "VARCHAR(255)", cts[0].DatabaseTypeName())

		assert.Equal(t, "start", cts[1].Name())
		assert.Equal(t, "VARCHAR(64)", cts[1].DatabaseTypeName())

		assert.Equal(t, "end", cts[2].Name())
		assert.Equal(t, "VARCHAR(64)", cts[2].DatabaseTypeName())
	}

	{
		rows, err := env.db.Query(
			"SELECT guid, mac, ip_v4, ip_v6 from aci_cell_service_ep")
		cts, err := rows.ColumnTypes()
		rows.Close()
		assert.Nil(t, err)

		assert.Equal(t, 4, len(cts))
		assert.Equal(t, "guid", cts[0].Name())
		assert.Equal(t, "VARCHAR(255)", cts[0].DatabaseTypeName())

		assert.Equal(t, "mac", cts[1].Name())
		assert.Equal(t, "VARCHAR(24)", cts[1].DatabaseTypeName())

		assert.Equal(t, "ip_v4", cts[2].Name())
		assert.Equal(t, "VARCHAR(16)", cts[2].DatabaseTypeName())

		assert.Equal(t, "ip_v6", cts[3].Name())
		assert.Equal(t, "VARCHAR(64)", cts[3].DatabaseTypeName())
	}
}

func TestCfDbMigrationIdempotent(t *testing.T) {
	env := testCfEnvironment(t)
	err := env.RunDbMigration()
	assert.Nil(t, err)
}
