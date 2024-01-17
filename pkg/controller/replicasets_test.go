// Copyright 2019 Cisco Systems, Inc.
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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	apicapi "github.com/noironetworks/aci-containers/pkg/apicapi"
	tu "github.com/noironetworks/aci-containers/pkg/testutil"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

func testReplicaSet() *appsv1.ReplicaSet {
	var replicas int32 = 1
	rs := &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "test-namespace",
			Name:      "test-replicaset",
		},
		Spec: appsv1.ReplicaSetSpec{
			Replicas: &replicas,
		},
		Status: appsv1.ReplicaSetStatus{
			Replicas: 3,
		},
	}

	return rs
}

func rsWait(t *testing.T, desc string, cont *testAciController, expected map[string]apicapi.ApicSlice) {
	tu.WaitFor(t, desc, 500*time.Millisecond,
		func(last bool) (bool, error) {
			cont.indexMutex.Lock()
			defer cont.indexMutex.Unlock()

			for key, slice := range expected {
				ds := cont.apicConn.GetDesiredState(key)
				if !tu.WaitEqual(t, last, slice, ds, desc, key) {
					for i := range slice {
						if last &&
							assert.Equal(t, len(slice[i]), len(ds[i])) {
							assert.Equal(t, slice[i], ds[i])
						} else {
							return false, nil
						}
					}
				}
			}
			return true, nil
		})
	cont.log.Info("Finished waiting for ", desc)
}
func TestReplicaSetLogger(t *testing.T) {
	rs := testReplicaSet()

	log := &logrus.Logger{
		Out:       nil,
		Formatter: nil,
		Hooks:     nil,
		Level:     logrus.DebugLevel,
	}

	logger := replicaSetLogger(log, rs)

	if logger.Data["namespace"] != "test-namespace" {
		t.Errorf("Expected namespace to be test-namespace, got %s", logger.Data["namespace"])
	}

	if logger.Data["name"] != "test-replicaset" {
		t.Errorf("Expected name to be test-replicaset, got %s", logger.Data["name"])
	}
}

func TestReplicaSetAddedChainedMode(t *testing.T) {
	cont := testController()
	cont.config.ChainedMode = true
	cont.run()
	rs := testReplicaSet()
	cont.fakeReplicaSetSource.Add(rs)
	time.Sleep(1 * time.Second)
	if len(cont.apicConn.GetDesiredState("kube_replicaSet_test-namespace_test-replicaset")) != 0 {
		t.Error("Expected no replicaSet objects")
	}
	cont.stop()
}

func TestReplicaSetAdded(t *testing.T) {
	cont := testController()
	cont.config.ChainedMode = false
	cont.run()
	rs := testReplicaSet()
	cont.fakeReplicaSetSource.Add(rs)

	rskey, _ := cache.MetaNamespaceKeyFunc(rs)
	key := cont.aciNameForKey("replicaSet", rskey)

	aobj := apicapi.NewVmmInjectedReplSet(cont.vmmDomainProvider(), cont.config.AciVmmDomain, cont.config.AciVmmController, rs.Namespace, rs.Name)

	aobj.SetAttr("annotation", "orchestrator:aci-containers-controller")

	hash := sha256.Sum256([]byte(key))
	tag := fmt.Sprintf("%s-%s", "kube", hex.EncodeToString(hash[:16]))

	aobj.AddChild(apicapi.NewTagAnnotation(aobj.GetDn(), "aci-containers-controller-tag"))
	aobj.SetTag(tag)
	expected := map[string]apicapi.ApicSlice{
		key: {aobj},
	}
	rsWait(t, "Replicaset added", cont, expected)
	cont.stop()
}

func TestReplicaSetAddedWithLabels(t *testing.T) {
	cont := testController()
	cont.config.ChainedMode = false
	cont.config.EnableVmmInjectedLabels = true
	apicapi.ApicVersion = "5.0"

	cont.run()
	rs := testReplicaSet()
	rs.ObjectMeta.Labels = map[string]string{
		"test-label": "test-value",
	}
	cont.fakeReplicaSetSource.Add(rs)

	rskey, _ := cache.MetaNamespaceKeyFunc(rs)
	key := cont.aciNameForKey("replicaSet", rskey)

	aobj := apicapi.NewVmmInjectedReplSet(cont.vmmDomainProvider(), cont.config.AciVmmDomain, cont.config.AciVmmController, rs.Namespace, rs.Name)

	aobj.SetAttr("annotation", "orchestrator:aci-containers-controller")

	hash := sha256.Sum256([]byte(key))
	tag := fmt.Sprintf("%s-%s", "kube", hex.EncodeToString(hash[:16]))

	aobj.AddChild(apicapi.NewTagAnnotation(aobj.GetDn(), "aci-containers-controller-tag"))
	aobj.SetTag(tag)
	for key, val := range rs.ObjectMeta.Labels {
		newLabelKey := cont.aciNameForKey("label", key)
		label := apicapi.NewVmmInjectedLabel(aobj.GetDn(),
			newLabelKey, val)
		label.SetAttr("annotation", "orchestrator:aci-containers-controller")
		label.AddChild(apicapi.NewTagAnnotation(label.GetDn(), "aci-containers-controller-tag"))
		label.SetTag(tag)
		aobj.AddChild(label)
	}
	expected := map[string]apicapi.ApicSlice{
		key: {aobj},
	}
	rsWait(t, "Replicaset added", cont, expected)
	cont.stop()
}

func TestReplicaSetAddedWithOwnerReference(t *testing.T) {
	cont := testController()
	cont.config.ChainedMode = false
	cont.run()
	rs := testReplicaSet()
	rs.OwnerReferences = []metav1.OwnerReference{
		{
			Kind: "Deployment",
			Name: "test-deployment",
		},
	}
	cont.fakeReplicaSetSource.Add(rs)

	rskey, _ := cache.MetaNamespaceKeyFunc(rs)
	key := cont.aciNameForKey("replicaSet", rskey)

	aobj := apicapi.NewVmmInjectedReplSet(cont.vmmDomainProvider(), cont.config.AciVmmDomain, cont.config.AciVmmController, rs.Namespace, rs.Name)

	aobj.SetAttr("annotation", "orchestrator:aci-containers-controller")

	hash := sha256.Sum256([]byte(key))
	tag := fmt.Sprintf("%s-%s", "kube", hex.EncodeToString(hash[:16]))

	aobj.AddChild(apicapi.NewTagAnnotation(aobj.GetDn(), "aci-containers-controller-tag"))
	aobj.SetTag(tag)
	aobj.SetAttr("deploymentName", "test-deployment")
	expected := map[string]apicapi.ApicSlice{
		key: {aobj},
	}
	rsWait(t, "Replicaset added", cont, expected)
	cont.stop()
}

func TestReplicaSetChanged(t *testing.T) {
	cont := testController()
	cont.config.ChainedMode = false
	cont.run()
	rs := testReplicaSet()
	cont.fakeReplicaSetSource.Add(rs)
	time.Sleep(1 * time.Second)
	rs.OwnerReferences = []metav1.OwnerReference{
		{
			Kind: "Deployment",
			Name: "test-deployment",
		},
	}
	cont.fakeReplicaSetSource.Modify(rs)

	rskey, _ := cache.MetaNamespaceKeyFunc(rs)
	key := cont.aciNameForKey("replicaSet", rskey)

	aobj := apicapi.NewVmmInjectedReplSet(cont.vmmDomainProvider(), cont.config.AciVmmDomain, cont.config.AciVmmController, rs.Namespace, rs.Name)

	aobj.SetAttr("annotation", "orchestrator:aci-containers-controller")

	hash := sha256.Sum256([]byte(key))
	tag := fmt.Sprintf("%s-%s", "kube", hex.EncodeToString(hash[:16]))

	aobj.AddChild(apicapi.NewTagAnnotation(aobj.GetDn(), "aci-containers-controller-tag"))
	aobj.SetTag(tag)
	aobj.SetAttr("deploymentName", "test-deployment")
	expected := map[string]apicapi.ApicSlice{
		key: {aobj},
	}
	rsWait(t, "Replicaset updated", cont, expected)
	cont.stop()
}

func TestReplicaSetDeleted(t *testing.T) {
	cont := testController()
	cont.config.ChainedMode = false
	cont.run()
	rs := testReplicaSet()
	cont.fakeReplicaSetSource.Add(rs)

	rskey, _ := cache.MetaNamespaceKeyFunc(rs)
	key := cont.aciNameForKey("replicaSet", rskey)

	aobj := apicapi.NewVmmInjectedReplSet(cont.vmmDomainProvider(), cont.config.AciVmmDomain, cont.config.AciVmmController, rs.Namespace, rs.Name)

	aobj.SetAttr("annotation", "orchestrator:aci-containers-controller")

	hash := sha256.Sum256([]byte(key))
	tag := fmt.Sprintf("%s-%s", "kube", hex.EncodeToString(hash[:16]))

	aobj.AddChild(apicapi.NewTagAnnotation(aobj.GetDn(), "aci-containers-controller-tag"))
	aobj.SetTag(tag)
	aobj.SetAttr("deploymentName", "")
	expected := map[string]apicapi.ApicSlice{
		key: {aobj},
	}
	rsWait(t, "RS added", cont, expected)

	cont.fakeReplicaSetSource.Delete(rs)
	time.Sleep(1 * time.Second)
	expected = map[string]apicapi.ApicSlice{
		key: {},
	}
	rsWait(t, "RS deleted", cont, expected)
	if len(cont.apicConn.GetDesiredState(key)) != 0 {
		t.Error("Expected no replicaSet objects")
	}
	cont.stop()
}

func TestReplicaSetDeleteFail(t *testing.T) {
	cont := testController()
	cont.config.ChainedMode = false
	cont.run()
	rs := testReplicaSet()
	cont.fakeReplicaSetSource.Add(rs)

	rskey, _ := cache.MetaNamespaceKeyFunc(rs)
	key := cont.aciNameForKey("replicaSet", rskey)

	aobj := apicapi.NewVmmInjectedReplSet(cont.vmmDomainProvider(), cont.config.AciVmmDomain, cont.config.AciVmmController, rs.Namespace, rs.Name)

	aobj.SetAttr("annotation", "orchestrator:aci-containers-controller")

	hash := sha256.Sum256([]byte(key))
	tag := fmt.Sprintf("%s-%s", "kube", hex.EncodeToString(hash[:16]))

	aobj.AddChild(apicapi.NewTagAnnotation(aobj.GetDn(), "aci-containers-controller-tag"))
	aobj.SetTag(tag)
	aobj.SetAttr("deploymentName", "")
	expected := map[string]apicapi.ApicSlice{
		key: {aobj},
	}
	rsWait(t, "RS added", cont, expected)
	type test struct {
		metav1.ObjectMeta
	}

	rs1 := &test{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "test-namespace",
			Name:      "test-replicaset",
		},
	}
	cont.replicaSetDeleted(rs1)
	time.Sleep(1 * time.Second)
	expected = map[string]apicapi.ApicSlice{
		key: {aobj},
	}
	rsWait(t, "RS not deleted", cont, expected)
	cont.stop()
}

func TestReplicaSetDeleteStateUnknown(t *testing.T) {
	cont := testController()
	cont.config.ChainedMode = false
	cont.run()
	rs := testReplicaSet()
	cont.fakeReplicaSetSource.Add(rs)

	rskey, _ := cache.MetaNamespaceKeyFunc(rs)
	key := cont.aciNameForKey("replicaSet", rskey)

	aobj := apicapi.NewVmmInjectedReplSet(cont.vmmDomainProvider(), cont.config.AciVmmDomain, cont.config.AciVmmController, rs.Namespace, rs.Name)

	aobj.SetAttr("annotation", "orchestrator:aci-containers-controller")

	hash := sha256.Sum256([]byte(key))
	tag := fmt.Sprintf("%s-%s", "kube", hex.EncodeToString(hash[:16]))

	aobj.AddChild(apicapi.NewTagAnnotation(aobj.GetDn(), "aci-containers-controller-tag"))
	aobj.SetTag(tag)
	aobj.SetAttr("deploymentName", "")
	expected := map[string]apicapi.ApicSlice{
		key: {aobj},
	}
	rsWait(t, "RS added", cont, expected)

	rs1 := cache.DeletedFinalStateUnknown{
		Key: key,
		Obj: rs,
	}
	cont.replicaSetDeleted(rs1)
	time.Sleep(1 * time.Second)
	expected = map[string]apicapi.ApicSlice{
		key: {},
	}
	rsWait(t, "RS not deleted", cont, expected)
	cont.stop()
}

func TestReplicaSetDeleteStateUnknownFail(t *testing.T) {
	cont := testController()
	cont.config.ChainedMode = false
	cont.run()
	rs := testReplicaSet()
	cont.fakeReplicaSetSource.Add(rs)

	rskey, _ := cache.MetaNamespaceKeyFunc(rs)
	key := cont.aciNameForKey("replicaSet", rskey)

	aobj := apicapi.NewVmmInjectedReplSet(cont.vmmDomainProvider(), cont.config.AciVmmDomain, cont.config.AciVmmController, rs.Namespace, rs.Name)

	aobj.SetAttr("annotation", "orchestrator:aci-containers-controller")

	hash := sha256.Sum256([]byte(key))
	tag := fmt.Sprintf("%s-%s", "kube", hex.EncodeToString(hash[:16]))

	aobj.AddChild(apicapi.NewTagAnnotation(aobj.GetDn(), "aci-containers-controller-tag"))
	aobj.SetTag(tag)
	aobj.SetAttr("deploymentName", "")
	expected := map[string]apicapi.ApicSlice{
		key: {aobj},
	}
	rsWait(t, "RS added", cont, expected)

	type test struct {
		metav1.ObjectMeta
	}

	rs1 := &test{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "test-namespace",
			Name:      "test-replicaset",
		},
	}

	rs2 := cache.DeletedFinalStateUnknown{
		Key: key,
		Obj: rs1,
	}
	cont.replicaSetDeleted(rs2)
	time.Sleep(1 * time.Second)
	expected = map[string]apicapi.ApicSlice{
		key: {aobj},
	}
	rsWait(t, "RS not deleted", cont, expected)
	cont.stop()
}
