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
	"testing"

	"code.cloudfoundry.org/bbs/models"
	"github.com/stretchr/testify/assert"

	etcd "github.com/noironetworks/aci-containers/pkg/cf_etcd"
)

func TestCfContainerUpdateDelete(t *testing.T) {
	env := testCfEnvironment(t)

	env.handleContainerUpdate("c-1")
	assert.Equal(t, getExpectedEpInfo(), env.GetEpInfo("cell-1", "c-1"))

	cinfo := env.contIdx["c-1"]
	delete(env.contIdx, "c-1")
	env.handleContainerDelete(cinfo)
	assert.Nil(t, env.GetEpInfo("cell-1", "c-1"))
}

func TestCfContainerUpdateStaging(t *testing.T) {
	env := testCfEnvironment(t)

	env.contIdx["c-1"].InstanceIndex = -1
	exp_ep := getExpectedEpInfo()
	exp_ep.InstanceIndex = -1
	exp_ep.SecurityGroups[2].Group = "cf_asg_ASG_S1"

	env.handleContainerUpdate("c-1")
	assert.Equal(t, exp_ep, env.GetEpInfo("cell-1", "c-1"))
}

func TestCfContainerUpdateTask(t *testing.T) {
	env := testCfEnvironment(t)

	env.contIdx["c-1"].InstanceIndex = -2
	env.contIdx["c-1"].TaskName = "task 123"
	exp_ep := getExpectedEpInfo()
	exp_ep.InstanceIndex = -2
	exp_ep.TaskName = "task 123"

	env.handleContainerUpdate("c-1")
	assert.Equal(t, exp_ep, env.GetEpInfo("cell-1", "c-1"))
}

func TestCfContainerUpdateIsolationSegment(t *testing.T) {
	env := testCfEnvironment(t)

	env.spaceIdx["space-1"].IsolationSegment = "is1"
	exp_ep := getExpectedEpInfo()
	exp_ep.Epg = "auto|isolate1"

	env.handleContainerUpdate("c-1")
	assert.Equal(t, exp_ep, env.GetEpInfo("cell-1", "c-1"))
}

func TestCfContainerUpdateEpgAnnotation(t *testing.T) {
	env := testCfEnvironment(t)
	ea_db := EpgAnnotationDb{}
	exp_ep := getExpectedEpInfo()

	for _, prefix := range []string{"", "anno|"} {
		app_prof := "auto|"
		if prefix != "" {
			app_prof = prefix
		}
		// add org annotation
		txn(env.db, func(txn *sql.Tx) {
			err := ea_db.UpdateAnnotation(txn, "org-1", CF_OBJ_ORG, prefix+"epg-org")
			assert.Nil(t, err)
		})
		exp_ep.Epg = app_prof + "epg-org"
		env.handleContainerUpdate("c-1")
		assert.Equal(t, exp_ep, env.GetEpInfo("cell-1", "c-1"))

		// add space annotation
		txn(env.db, func(txn *sql.Tx) {
			err := ea_db.UpdateAnnotation(txn, "space-1", CF_OBJ_SPACE, prefix+"epg-space")
			assert.Nil(t, err)
		})
		exp_ep.Epg = app_prof + "epg-space"
		env.handleContainerUpdate("c-1")
		assert.Equal(t, exp_ep, env.GetEpInfo("cell-1", "c-1"))

		// add app annotation
		txn(env.db, func(txn *sql.Tx) {
			err := ea_db.UpdateAnnotation(txn, "app-1", CF_OBJ_APP, prefix+"epg-app")
			assert.Nil(t, err)
		})
		exp_ep.Epg = app_prof + "epg-app"
		env.handleContainerUpdate("c-1")
		assert.Equal(t, exp_ep, env.GetEpInfo("cell-1", "c-1"))

		// cleanup for next loop
		txn(env.db, func(txn *sql.Tx) {
			ea_db.DeleteAnnotation(txn, "org-1", CF_OBJ_ORG)
			ea_db.DeleteAnnotation(txn, "space-1", CF_OBJ_SPACE)
			ea_db.DeleteAnnotation(txn, "app-1", CF_OBJ_APP)
		})
	}
}

func TestCfContainerUpdateAdditionalPorts(t *testing.T) {
	env := testCfEnvironment(t)

	env.contIdx["c-1"].Ports = append(env.contIdx["c-1"].Ports,
		&models.PortMapping{ContainerPort: 7777, HostPort: 32},
		&models.PortMapping{ContainerPort: 8888, HostPort: 33})
	exp_ep := getExpectedEpInfo()
	exp_ep.PortMapping = append(exp_ep.PortMapping,
		etcd.PortMap{ContainerPort: 7777, HostPort: 32},
		etcd.PortMap{ContainerPort: 8888, HostPort: 33})
	exp_ep.SecurityGroups = append(exp_ep.SecurityGroups,
		etcd.GroupInfo{Tenant: "cf", Group: "cf_hpp_app-port:app-1"})

	env.handleContainerUpdate("c-1")
	assert.Equal(t, exp_ep, env.GetEpInfo("cell-1", "c-1"))
}

func TestCfAppUpdateDelete(t *testing.T) {
	env := testCfEnvironment(t)

	// give a container additional ports
	env.contIdx["c-1"].Ports = append(env.contIdx["c-1"].Ports,
		&models.PortMapping{ContainerPort: 7777, HostPort: 32},
		&models.PortMapping{ContainerPort: 8888, HostPort: 33})

	// include staging & task containers in the app
	env.contIdx["c-5"] = &ContainerInfo{ContainerId: "c-5", CellId: "cell-5",
		IpAddress: "1.2.3.8", AppId: "app-1", InstanceIndex: -1}
	env.contIdx["c-6"] = &ContainerInfo{ContainerId: "c-6", CellId: "cell-6",
		IpAddress: "1.2.3.9", AppId: "app-1", InstanceIndex: -2}
	env.appIdx["app-1"].ContainerIps["c-5"] = "1.2.3.8"
	env.appIdx["app-1"].ContainerIps["c-6"] = "1.2.3.9"

	exp_app := getExpectedAppInfo()

	env.handleAppUpdate("app-1")
	assert.Equal(t, exp_app, env.GetAppInfo("app-1"))
	assert.NotNil(t, env.cont.apicConn.GetDesiredState("app_ext_ip:app-1"))
	assert.NotNil(t, env.cont.apicConn.GetDesiredState("app-port:app-1"))
	assert.NotNil(t, env.cont.apicConn.GetDesiredState("np:app-101"))
	assert.NotNil(t, env.cont.apicConn.GetDesiredState("np:app-102"))

	ainfo := env.appIdx["app-1"]
	delete(env.appIdx, "app-1")
	env.handleAppDelete(ainfo)
	assert.Nil(t, env.GetAppInfo("app-1"))
	assert.Nil(t, env.cont.apicConn.GetDesiredState("app_ext_ip:app-1"))
	assert.Nil(t, env.cont.apicConn.GetDesiredState("app-port:app-1"))
}

func TestCfCleanupEpgAnnotation(t *testing.T) {
	env := testCfEnvironment(t)
	ea_db := EpgAnnotationDb{}

	txn(env.db, func(txn *sql.Tx) {
		err := ea_db.UpdateAnnotation(txn, "org-1", CF_OBJ_ORG, "epg-org")
		assert.Nil(t, err)
		err = ea_db.UpdateAnnotation(txn, "space-1", CF_OBJ_SPACE, "epg-space")
		assert.Nil(t, err)
		err = ea_db.UpdateAnnotation(txn, "app-1", CF_OBJ_APP, "epg-app")
		assert.Nil(t, err)
	})

	env.handleAppDelete(env.appIdx["app-1"])
	env.handleSpaceDelete(env.spaceIdx["space-1"])
	env.handleOrgDelete(env.orgIdx["org-1"])

	txn(env.db, func(txn *sql.Tx) {
		val, err := ea_db.List(txn, CF_OBJ_ORG)
		assert.Nil(t, err)
		assert.Nil(t, val)
		val, err = ea_db.List(txn, CF_OBJ_SPACE)
		assert.Nil(t, err)
		assert.Nil(t, val)
		val, err = ea_db.List(txn, CF_OBJ_APP)
		assert.Nil(t, err)
		assert.Nil(t, val)
	})
}

func TestCfAsgUpdateDelete(t *testing.T) {
	env := testCfEnvironment(t)

	env.handleAsgUpdate("ASG_R1")
	env.handleAsgUpdate("ASG_S1")
	env.handleAsgUpdate("ASG_PUB")
	assert.NotNil(t, env.cont.apicConn.GetDesiredState("asg:ASG_R1"))
	assert.NotNil(t, env.cont.apicConn.GetDesiredState("asg:ASG_S1"))
	assert.NotNil(t, env.cont.apicConn.GetDesiredState("asg:ASG_PUB"))

	pub_info := env.asgIdx["ASG_PUB"]
	r1_info := env.asgIdx["ASG_R1"]
	s1_info := env.asgIdx["ASG_S1"]
	delete(env.asgIdx, "ASG_PUB")
	delete(env.asgIdx, "ASG_R1")
	delete(env.asgIdx, "ASG_S1")
	env.handleAsgDelete(r1_info)
	env.handleAsgDelete(s1_info)
	env.handleAsgDelete(pub_info)
	assert.Nil(t, env.cont.apicConn.GetDesiredState("asg:ASG_R1"))
	assert.Nil(t, env.cont.apicConn.GetDesiredState("asg:ASG_S1"))
	assert.Nil(t, env.cont.apicConn.GetDesiredState("asg:ASG_PUB"))
}
