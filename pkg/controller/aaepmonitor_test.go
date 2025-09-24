// Copyright 2025 Cisco Systems, Inc.
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
	"time"

	amv1 "github.com/noironetworks/aci-containers/pkg/aaepmonitor/apis/aci.attachmentmonitor/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestQueueAaepMonitorConfigByKey(t *testing.T) {
	cont := testController()
	cont.stopCh = make(chan struct{})
	defer cont.stop()

	key := "test-namespace/test-aaepmonitor"
	cont.queueAaepMonitorConfigByKey(key)

	// Wait for the item to be added to the queue
	time.Sleep(10 * time.Millisecond)

	if cont.aaepMonitorConfigQueue.Len() != 1 {
		t.Errorf("Expected queue length 1, got %d", cont.aaepMonitorConfigQueue.Len())
	}

	// Get the item from the queue to verify it's correct
	item, _ := cont.aaepMonitorConfigQueue.Get()
	if item != key {
		t.Errorf("Expected queue item %s, got %v", key, item)
	}
	cont.aaepMonitorConfigQueue.Done(item)
}

func TestAaepMonitorConfAdded(t *testing.T) {
	cont := testController()
	cont.stopCh = make(chan struct{})
	defer cont.stop()

	// Create a test AaepMonitor object
	aaepMonitor := &amv1.AaepMonitor{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-aaepmonitor",
			Namespace: "test-namespace",
		},
		Spec: amv1.AaepMonitorSpec{
			Aaeps: []string{"uni/infra/attentp-test"},
		},
	}

	cont.aaepMonitorConfAdded(aaepMonitor)

	// Verify the object was queued
	time.Sleep(10 * time.Millisecond)
	if cont.aaepMonitorConfigQueue.Len() == 0 {
		t.Error("Expected item to be queued after aaepMonitorConfAdded")
	}
}

func TestAaepMonitorConfUpdate(t *testing.T) {
	cont := testController()
	cont.stopCh = make(chan struct{})
	defer cont.stop()

	oldMonitor := &amv1.AaepMonitor{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-aaepmonitor",
			Namespace: "test-namespace",
		},
		Spec: amv1.AaepMonitorSpec{
			Aaeps: []string{"uni/infra/attentp-old"},
		},
	}

	newMonitor := &amv1.AaepMonitor{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-aaepmonitor",
			Namespace: "test-namespace",
		},
		Spec: amv1.AaepMonitorSpec{
			Aaeps: []string{"uni/infra/attentp-new"},
		},
	}

	cont.aaepMonitorConfUpdate(oldMonitor, newMonitor)

	// Verify the object was queued
	time.Sleep(10 * time.Millisecond)
	if cont.aaepMonitorConfigQueue.Len() == 0 {
		t.Error("Expected item to be queued after aaepMonitorConfUpdate")
	}
}

func TestAaepMonitorConfDelete(t *testing.T) {
	cont := testController()
	cont.stopCh = make(chan struct{})
	defer cont.stop()

	aaepMonitor := &amv1.AaepMonitor{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-aaepmonitor",
			Namespace: "test-namespace",
		},
		Spec: amv1.AaepMonitorSpec{
			Aaeps: []string{"uni/infra/attentp-test"},
		},
	}

	cont.aaepMonitorConfDelete(aaepMonitor)

	// Verify the object was queued for deletion handling
	time.Sleep(10 * time.Millisecond)
	if cont.aaepMonitorConfigQueue.Len() == 0 {
		t.Error("Expected item to be queued after aaepMonitorConfDelete")
	}
}
