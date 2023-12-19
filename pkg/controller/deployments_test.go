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

func testDeployment() *appsv1.Deployment {
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "test-namespace",
			Name:      "test-deployment",
		},
		Spec:   appsv1.DeploymentSpec{},
		Status: appsv1.DeploymentStatus{},
	}

	return dep
}

func depWait(t *testing.T, desc string, cont *testAciController, expected map[string]apicapi.ApicSlice) {
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

func TestDeploymentLogger(t *testing.T) {
	dep := testDeployment()

	log := &logrus.Logger{
		Out:       nil,
		Formatter: nil,
		Hooks:     nil,
		Level:     logrus.DebugLevel,
	}

	logger := deploymentLogger(log, dep)

	if logger.Data["namespace"] != "test-namespace" {
		t.Errorf("Expected namespace to be test-namespace, got %s", logger.Data["namespace"])
	}

	if logger.Data["name"] != "test-deployment" {
		t.Errorf("Expected name to be test-deployment, got %s", logger.Data["name"])
	}
}

func TestDeploymentChainedMode(t *testing.T) {
	cont := testController()
	cont.config.ChainedMode = true
	cont.run()
	dep := testDeployment()
	depkey, _ := cache.MetaNamespaceKeyFunc(dep)
	key := cont.aciNameForKey("deployment", depkey)
	cont.fakeDeploymentSource.Add(dep)
	time.Sleep(1 * time.Second)
	if len(cont.apicConn.GetDesiredState(key)) != 0 {
		t.Error("Expected no replicaSet objects")
	}
	cont.stop()
}

func TestDeploymentAdded(t *testing.T) {
	cont := testController()
	cont.config.ChainedMode = false
	cont.run()
	dep := testDeployment()
	depkey, _ := cache.MetaNamespaceKeyFunc(dep)
	key := cont.aciNameForKey("deployment", depkey)
	cont.fakeDeploymentSource.Add(dep)
	aobj := apicapi.NewVmmInjectedDepl(cont.vmmDomainProvider(),
		cont.config.AciVmmDomain, cont.config.AciVmmController,
		dep.Namespace, dep.Name)
	aobj.SetAttr("annotation", "orchestrator:aci-containers-controller")
	aobj.SetAttr("replicas", "1")
	hash := sha256.Sum256([]byte(key))
	tag := fmt.Sprintf("%s-%s", "kube", hex.EncodeToString(hash[:16]))

	aobj.AddChild(apicapi.NewTagAnnotation(aobj.GetDn(), "aci-containers-controller-tag"))
	aobj.SetTag(tag)
	expected := map[string]apicapi.ApicSlice{
		key: {aobj},
	}
	depWait(t, "deployment added", cont, expected)
	cont.stop()
}

func TestDeploymentAddedWithReplicas(t *testing.T) {
	cont := testController()
	cont.config.ChainedMode = false
	cont.run()
	dep := testDeployment()
	replicas := int32(3)
	dep.Spec.Replicas = &replicas
	depkey, _ := cache.MetaNamespaceKeyFunc(dep)
	key := cont.aciNameForKey("deployment", depkey)
	cont.fakeDeploymentSource.Add(dep)
	aobj := apicapi.NewVmmInjectedDepl(cont.vmmDomainProvider(),
		cont.config.AciVmmDomain, cont.config.AciVmmController,
		dep.Namespace, dep.Name)
	aobj.SetAttr("annotation", "orchestrator:aci-containers-controller")
	aobj.SetAttr("replicas", "3")
	hash := sha256.Sum256([]byte(key))
	tag := fmt.Sprintf("%s-%s", "kube", hex.EncodeToString(hash[:16]))

	aobj.AddChild(apicapi.NewTagAnnotation(aobj.GetDn(), "aci-containers-controller-tag"))
	aobj.SetTag(tag)
	expected := map[string]apicapi.ApicSlice{
		key: {aobj},
	}
	depWait(t, "deployment added", cont, expected)
	cont.stop()
}

func TestDeploymentAddedWithLabels(t *testing.T) {
	cont := testController()
	cont.config.ChainedMode = false
	cont.config.EnableVmmInjectedLabels = true
	apicapi.ApicVersion = "5.0"
	cont.run()
	dep := testDeployment()
	dep.ObjectMeta.Labels = map[string]string{
		"test-label": "test-value",
	}
	depkey, _ := cache.MetaNamespaceKeyFunc(dep)
	key := cont.aciNameForKey("deployment", depkey)
	cont.fakeDeploymentSource.Add(dep)
	aobj := apicapi.NewVmmInjectedDepl(cont.vmmDomainProvider(),
		cont.config.AciVmmDomain, cont.config.AciVmmController,
		dep.Namespace, dep.Name)
	aobj.SetAttr("annotation", "orchestrator:aci-containers-controller")
	aobj.SetAttr("replicas", "1")
	hash := sha256.Sum256([]byte(key))
	tag := fmt.Sprintf("%s-%s", "kube", hex.EncodeToString(hash[:16]))

	aobj.AddChild(apicapi.NewTagAnnotation(aobj.GetDn(), "aci-containers-controller-tag"))
	aobj.SetTag(tag)
	for key, val := range dep.ObjectMeta.Labels {
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
	depWait(t, "deployment added", cont, expected)
	cont.stop()
}

func TestDeploymentChanged(t *testing.T) {
	cont := testController()
	cont.config.ChainedMode = false
	cont.run()
	dep := testDeployment()
	depkey, _ := cache.MetaNamespaceKeyFunc(dep)
	key := cont.aciNameForKey("deployment", depkey)
	cont.fakeDeploymentSource.Add(dep)
	aobj := apicapi.NewVmmInjectedDepl(cont.vmmDomainProvider(),
		cont.config.AciVmmDomain, cont.config.AciVmmController,
		dep.Namespace, dep.Name)
	aobj.SetAttr("annotation", "orchestrator:aci-containers-controller")
	aobj.SetAttr("replicas", "1")
	hash := sha256.Sum256([]byte(key))
	tag := fmt.Sprintf("%s-%s", "kube", hex.EncodeToString(hash[:16]))

	aobj.AddChild(apicapi.NewTagAnnotation(aobj.GetDn(), "aci-containers-controller-tag"))
	aobj.SetTag(tag)
	expected := map[string]apicapi.ApicSlice{
		key: {aobj},
	}
	depWait(t, "deployment added", cont, expected)
	replicas := int32(3)
	dep.Spec.Replicas = &replicas
	cont.fakeDeploymentSource.Modify(dep)
	aobj.SetAttr("replicas", "3")
	time.Sleep(200 * time.Millisecond)
	expected = map[string]apicapi.ApicSlice{
		key: {aobj},
	}
	depWait(t, "deployment updated", cont, expected)
	cont.stop()
}

func TestDeploymentDeleted(t *testing.T) {
	cont := testController()
	cont.config.ChainedMode = false
	cont.run()
	dep := testDeployment()
	depkey, _ := cache.MetaNamespaceKeyFunc(dep)
	key := cont.aciNameForKey("deployment", depkey)
	cont.fakeDeploymentSource.Add(dep)
	aobj := apicapi.NewVmmInjectedDepl(cont.vmmDomainProvider(),
		cont.config.AciVmmDomain, cont.config.AciVmmController,
		dep.Namespace, dep.Name)
	aobj.SetAttr("annotation", "orchestrator:aci-containers-controller")
	aobj.SetAttr("replicas", "1")
	hash := sha256.Sum256([]byte(key))
	tag := fmt.Sprintf("%s-%s", "kube", hex.EncodeToString(hash[:16]))

	aobj.AddChild(apicapi.NewTagAnnotation(aobj.GetDn(), "aci-containers-controller-tag"))
	aobj.SetTag(tag)
	expected := map[string]apicapi.ApicSlice{
		key: {aobj},
	}
	depWait(t, "deployment added", cont, expected)
	cont.fakeDeploymentSource.Delete(dep)
	time.Sleep(1 * time.Second)
	expected = map[string]apicapi.ApicSlice{
		key: {},
	}
	depWait(t, "deployment deleted", cont, expected)
	if len(cont.apicConn.GetDesiredState(key)) != 0 {
		t.Error("Expected no deployment objects")
	}
	cont.stop()
}

func TestDeploymentDeleteFail(t *testing.T) {
	cont := testController()
	cont.config.ChainedMode = false
	cont.run()
	dep := testDeployment()
	depkey, _ := cache.MetaNamespaceKeyFunc(dep)
	key := cont.aciNameForKey("deployment", depkey)
	cont.fakeDeploymentSource.Add(dep)
	aobj := apicapi.NewVmmInjectedDepl(cont.vmmDomainProvider(),
		cont.config.AciVmmDomain, cont.config.AciVmmController,
		dep.Namespace, dep.Name)
	aobj.SetAttr("annotation", "orchestrator:aci-containers-controller")
	aobj.SetAttr("replicas", "1")
	hash := sha256.Sum256([]byte(key))
	tag := fmt.Sprintf("%s-%s", "kube", hex.EncodeToString(hash[:16]))

	aobj.AddChild(apicapi.NewTagAnnotation(aobj.GetDn(), "aci-containers-controller-tag"))
	aobj.SetTag(tag)
	expected := map[string]apicapi.ApicSlice{
		key: {aobj},
	}
	depWait(t, "deployment added", cont, expected)
	type test struct {
		metav1.ObjectMeta
	}

	dep1 := &test{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "test-namespace",
			Name:      "test-deployment",
		},
	}
	cont.deploymentDeleted(dep1)
	time.Sleep(1 * time.Second)
	expected = map[string]apicapi.ApicSlice{
		key: {aobj},
	}
	depWait(t, "Deployment should not be deleted", cont, expected)
	cont.stop()
}

func TestDeploymentDeleteDeletedFinalStateUnknown(t *testing.T) {
	cont := testController()
	cont.config.ChainedMode = false
	cont.run()
	dep := testDeployment()
	depkey, _ := cache.MetaNamespaceKeyFunc(dep)
	key := cont.aciNameForKey("deployment", depkey)
	cont.fakeDeploymentSource.Add(dep)
	aobj := apicapi.NewVmmInjectedDepl(cont.vmmDomainProvider(),
		cont.config.AciVmmDomain, cont.config.AciVmmController,
		dep.Namespace, dep.Name)
	aobj.SetAttr("annotation", "orchestrator:aci-containers-controller")
	aobj.SetAttr("replicas", "1")
	hash := sha256.Sum256([]byte(key))
	tag := fmt.Sprintf("%s-%s", "kube", hex.EncodeToString(hash[:16]))

	aobj.AddChild(apicapi.NewTagAnnotation(aobj.GetDn(), "aci-containers-controller-tag"))
	aobj.SetTag(tag)
	expected := map[string]apicapi.ApicSlice{
		key: {aobj},
	}
	depWait(t, "deployment added", cont, expected)
	dep1 := cache.DeletedFinalStateUnknown{
		Key: key,
		Obj: dep,
	}
	cont.deploymentDeleted(dep1)
	time.Sleep(1 * time.Second)
	expected = map[string]apicapi.ApicSlice{
		key: {},
	}
	depWait(t, "Deployment should be deleted", cont, expected)
	if len(cont.apicConn.GetDesiredState(key)) != 0 {
		t.Error("Expected no deployment objects")
	}
	cont.stop()
}

func TestDeploymentDeleteDeletedFinalStateUnknownFail(t *testing.T) {
	cont := testController()
	cont.config.ChainedMode = false
	cont.run()
	dep := testDeployment()
	depkey, _ := cache.MetaNamespaceKeyFunc(dep)
	key := cont.aciNameForKey("deployment", depkey)
	cont.fakeDeploymentSource.Add(dep)
	aobj := apicapi.NewVmmInjectedDepl(cont.vmmDomainProvider(),
		cont.config.AciVmmDomain, cont.config.AciVmmController,
		dep.Namespace, dep.Name)
	aobj.SetAttr("annotation", "orchestrator:aci-containers-controller")
	aobj.SetAttr("replicas", "1")
	hash := sha256.Sum256([]byte(key))
	tag := fmt.Sprintf("%s-%s", "kube", hex.EncodeToString(hash[:16]))

	aobj.AddChild(apicapi.NewTagAnnotation(aobj.GetDn(), "aci-containers-controller-tag"))
	aobj.SetTag(tag)
	expected := map[string]apicapi.ApicSlice{
		key: {aobj},
	}
	depWait(t, "deployment added", cont, expected)

	type test struct {
		metav1.ObjectMeta
	}

	testObj := &test{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "test-namespace",
			Name:      "test-deployment",
		},
	}

	dep1 := cache.DeletedFinalStateUnknown{
		Key: key,
		Obj: testObj,
	}
	cont.deploymentDeleted(dep1)
	time.Sleep(1 * time.Second)
	expected = map[string]apicapi.ApicSlice{
		key: {aobj},
	}
	depWait(t, "Deployment should not be deleted", cont, expected)
	cont.stop()
}

func TestDeploymentChangedAnnot(t *testing.T) {
	cont := testController()
	cont.config.ChainedMode = false
	cont.run()
	dep := testDeployment()
	depkey, _ := cache.MetaNamespaceKeyFunc(dep)
	key := cont.aciNameForKey("deployment", depkey)
	cont.fakeDeploymentSource.Add(dep)
	aobj := apicapi.NewVmmInjectedDepl(cont.vmmDomainProvider(),
		cont.config.AciVmmDomain, cont.config.AciVmmController,
		dep.Namespace, dep.Name)
	aobj.SetAttr("annotation", "orchestrator:aci-containers-controller")
	aobj.SetAttr("replicas", "1")
	hash := sha256.Sum256([]byte(key))
	tag := fmt.Sprintf("%s-%s", "kube", hex.EncodeToString(hash[:16]))

	aobj.AddChild(apicapi.NewTagAnnotation(aobj.GetDn(), "aci-containers-controller-tag"))
	aobj.SetTag(tag)
	expected := map[string]apicapi.ApicSlice{
		key: {aobj},
	}
	depWait(t, "deployment added", cont, expected)
	replicas := int32(3)
	dep.Spec.Replicas = &replicas
	dep.ObjectMeta.Annotations = map[string]string{
		"test-annotation": "test-value",
	}
	cont.fakeDeploymentSource.Modify(dep)
	aobj.SetAttr("replicas", "3")
	time.Sleep(200 * time.Millisecond)
	expected = map[string]apicapi.ApicSlice{
		key: {aobj},
	}
	depWait(t, "deployment updated", cont, expected)
	cont.stop()
}
