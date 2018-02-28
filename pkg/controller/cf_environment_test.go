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
	"encoding/json"
	"fmt"
	"net"
	"testing"
	"time"

	"code.cloudfoundry.org/bbs/models"
	locketmodels "code.cloudfoundry.org/locket/models"
	locketfakes "code.cloudfoundry.org/locket/models/modelsfakes"
	etcdclient "github.com/coreos/etcd/client"
	"github.com/stretchr/testify/assert"
	"golang.org/x/net/context"

	etcd "github.com/noironetworks/aci-containers/pkg/cf_etcd"
	"github.com/noironetworks/aci-containers/pkg/ipam"
	"github.com/noironetworks/aci-containers/pkg/metadata"

	tu "github.com/noironetworks/aci-containers/pkg/testutil"
)

func TestCfLoadCellNetworkInfo(t *testing.T) {
	env := testCfEnvironment(t)
	k := env.fakeEtcdKeysApi()
	cellId := "cell-1"
	key := etcd.CELL_KEY_BASE + "/" + cellId + "/network"
	ctx := context.Background()

	env.LoadCellNetworkInfo(cellId)
	_, ok := env.cont.nodePodNetCache[cellId]
	assert.False(t, ok)

	nodeMeta := newNodePodNetMeta()
	nodeMeta.podNetIps.V4 = append(nodeMeta.podNetIps.V4,
		ipam.IpRange{Start: net.ParseIP("10.10.0.1"), End: net.ParseIP("10.10.0.24")})
	nodeMeta.podNetIps.V6 = append(nodeMeta.podNetIps.V6,
		ipam.IpRange{Start: net.ParseIP("::fe80"), End: net.ParseIP("::fe90")})
	env.cont.recomputePodNetAnnotation(nodeMeta)

	k.Set(ctx, key, nodeMeta.podNetIpsAnnotation, nil)
	env.LoadCellNetworkInfo(cellId)
	r, ok := env.cont.nodePodNetCache[cellId]
	assert.True(t, ok)
	assert.Equal(t, nodeMeta.podNetIpsAnnotation, r.podNetIpsAnnotation)

	k.Delete(ctx, key, nil)
	env.LoadCellNetworkInfo(cellId)
	r, ok = env.cont.nodePodNetCache[cellId]
	assert.True(t, ok)
	assert.Equal(t, nodeMeta.podNetIpsAnnotation, r.podNetIpsAnnotation)
}

func TestCfLoadCellServiceInfo(t *testing.T) {
	env := testCfEnvironment(t)
	k := env.fakeEtcdKeysApi()
	cellId := "cell-1"
	nodename := "diego-cell-" + cellId
	key := etcd.CELL_KEY_BASE + "/" + cellId + "/service"
	ctx := context.Background()

	// cleanup initial state
	delete(env.cont.nodeServiceMetaCache, nodename)

	env.LoadCellServiceInfo(cellId)
	r, ok := env.cont.nodeServiceMetaCache[nodename]
	assert.True(t, ok)
	assert.NotEqual(t, "", r.serviceEp.Mac)
	assert.NotNil(t, r.serviceEp.Ipv4)
	assert.NotNil(t, r.serviceEp.Ipv6)

	svcEpStr, _ := json.Marshal(r.serviceEp)
	v, _ := k.Get(ctx, key, nil)
	assert.Equal(t, string(svcEpStr), v.Node.Value)

	delete(env.cont.nodeServiceMetaCache, nodename)
	svcEP := metadata.ServiceEndpoint{Mac: "aa:bb:cc:dd:ee:ff",
		Ipv4: net.ParseIP("1.0.0.10"),
		Ipv6: net.ParseIP("a1::1a"),
	}
	svcEpStr, _ = json.Marshal(&svcEP)
	k.Set(ctx, key, string(svcEpStr), nil)
	env.LoadCellServiceInfo(cellId)
	r, ok = env.cont.nodeServiceMetaCache[nodename]
	assert.True(t, ok)
	assert.Equal(t, "aa:bb:cc:dd:ee:ff", r.serviceEp.Mac)
	assert.Equal(t, net.ParseIP("1.0.0.10"), r.serviceEp.Ipv4)
	assert.Equal(t, net.ParseIP("a1::1a"), r.serviceEp.Ipv6)
	v, _ = k.Get(ctx, key, nil)
	assert.Equal(t, string(svcEpStr), v.Node.Value)

	k.Delete(ctx, key, nil)
	env.LoadCellServiceInfo(cellId)
	r, ok = env.cont.nodeServiceMetaCache[nodename]
	assert.True(t, ok)
	assert.Equal(t, "aa:bb:cc:dd:ee:ff", r.serviceEp.Mac)
	assert.Equal(t, net.ParseIP("1.0.0.10"), r.serviceEp.Ipv4)
	assert.Equal(t, net.ParseIP("a1::1a"), r.serviceEp.Ipv6)
}

func TestCfEtcdStaleCleanup(t *testing.T) {
	env := testCfEnvironment(t)
	k := env.fakeEtcdKeysApi()
	ctx := context.Background()

	k.Set(ctx, "/aci", "", nil)
	keys := []string{"/aci/cells/cell-1/containers/c-stale",
		"/aci/cells/cell-10/containers/c-1",
		"/aci/apps/app-stale"}
	for _, ky := range keys {
		k.Set(ctx, ky, "", nil)
	}

	env.cleanupEtcdContainers()
	err := etcdclient.Error{Code: etcdclient.ErrorCodeKeyNotFound}
	for _, ky := range keys {
		resp, e := k.Get(ctx, ky, nil)
		assert.Nil(t, resp)
		assert.Equal(t, err, e)
	}
}

func TestCfInitStaticAciObjects(t *testing.T) {
	env := testCfEnvironment(t)
	env.cont.config.PodSubnets = []string{"10.10.0.1/16"}
	env.cfconfig.AppVipSubnet = []string{"10.250.4.1/24", "aa::2e00/120"}
	env.InitStaticAciObjects()
	assert.NotNil(t, env.cont.apicConn.GetDesiredState("cf_asg_static"))
	assert.NotNil(t, env.cont.apicConn.GetDesiredState("cf_service_static"))
}

func TestCfUpdateHppForCfComponents(t *testing.T) {
	env := testCfEnvironment(t)
	env.cfconfig.GoRouterAddress = "96.97.98.99"
	env.cfconfig.TcpRouterAddress = "75.57.55.77"
	env.contIdx["c-1"].Ports = append(env.contIdx["c-1"].Ports,
		&models.PortMapping{ContainerPort: 7777, HostPort: 32},
		&models.PortMapping{ContainerPort: 8888, HostPort: 33})
	env.contIdx["c-3"].Ports = append(env.contIdx["c-3"].Ports,
		&models.PortMapping{ContainerPort: 7777, HostPort: 32},
		&models.PortMapping{ContainerPort: 8888, HostPort: 33})

	env.UpdateHppForCfComponents()
	assert.NotNil(t, env.cont.apicConn.GetDesiredState("cf_hpp_cf_comp"))
	waitForGetList(t, env.appUpdateQ, 500*time.Millisecond, []interface{}{"app-1", "app-2"})
}

func TestCfNodePodNetworkChanged(t *testing.T) {
	env := testCfEnvironment(t)
	env.cont.nodePodNetCache["cell-10"] = &nodePodNetMeta{podNetIpsAnnotation: "some-annotation"}

	env.NodePodNetworkChanged("cell-10")
	v, _ := env.fakeEtcdKeysApi().Get(context.Background(), "/aci/cells/cell-10/network", nil)
	assert.Equal(t, "some-annotation", v.Node.Value)
}

func TestCfNodeServiceChanged(t *testing.T) {
	env := testCfEnvironment(t)
	env.NodeServiceChanged("diego-cell-cell-1")
	waitForGetList(t, env.appUpdateQ, 500*time.Millisecond, []interface{}{"app-1", "app-2", "app-3"})
}

func TestCfHaMaster(t *testing.T) {
	env := testCfEnvironment(t)
	fakeLocket := locketfakes.FakeLocketClient{}
	env.locketClient = &fakeLocket
	retry := 50 * time.Millisecond

	lockLost := false
	lostFunc := func() {
		lockLost = true
	}

	fakeLocket.LockReturnsOnCall(0, &locketmodels.LockResponse{}, nil)
	fakeLocket.LockReturnsOnCall(1, &locketmodels.LockResponse{}, nil)
	fakeLocket.LockReturns(&locketmodels.LockResponse{},
		fmt.Errorf("Lock not available"))

	// become master
	assert.Nil(t, env.waitToBecomeMaster(make(chan struct{}), retry, lostFunc))

	// stay master
	tu.WaitFor(t, "HA master lock renew", 500*time.Millisecond,
		func(last bool) (bool, error) {
			return (fakeLocket.LockCallCount() == 2), nil
		})
	assert.False(t, lockLost)

	// become slave
	tu.WaitFor(t, "HA master lock lost", 500*time.Millisecond,
		func(last bool) (bool, error) {
			return lockLost, nil
		})
	assert.Equal(t, 3, fakeLocket.LockCallCount())
}

func TestCfHaSlaveToMaster(t *testing.T) {
	env := testCfEnvironment(t)
	fakeLocket := locketfakes.FakeLocketClient{}
	env.locketClient = &fakeLocket
	retry := 50 * time.Millisecond

	fakeLocket.LockReturnsOnCall(0, &locketmodels.LockResponse{},
		fmt.Errorf("Lock not available"))
	fakeLocket.LockReturnsOnCall(1, &locketmodels.LockResponse{},
		fmt.Errorf("Lock not available"))
	fakeLocket.LockReturns(&locketmodels.LockResponse{}, nil)

	assert.Nil(t,
		env.waitToBecomeMaster(make(chan struct{}), retry, func() {}))
	assert.Equal(t, 3, fakeLocket.LockCallCount())
}

func TestCfHaStop(t *testing.T) {
	env := testCfEnvironment(t)
	fakeLocket := locketfakes.FakeLocketClient{}
	env.locketClient = &fakeLocket
	retry := 50 * time.Millisecond

	fakeLocket.LockReturns(&locketmodels.LockResponse{},
		fmt.Errorf("Lock not available"))

	stopCh := make(chan struct{})
	lockLost := false
	lostFunc := func() {
		lockLost = true
	}

	ret := fmt.Errorf("dummy")
	go func() {
		ret = env.waitToBecomeMaster(stopCh, retry, lostFunc)
	}()

	tu.WaitFor(t, "HA stop - setup", 500*time.Millisecond,
		func(last bool) (bool, error) {
			return (fakeLocket.LockCallCount() == 2), nil
		})
	close(stopCh)
	tu.WaitFor(t, "HA stop - exited", 500*time.Millisecond,
		func(last bool) (bool, error) {
			return (ret == nil), nil
		})
	assert.Equal(t, 1, fakeLocket.ReleaseCallCount())
	assert.False(t, lockLost)
}
