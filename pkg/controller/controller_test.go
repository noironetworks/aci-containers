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
	"time"

	"github.com/stretchr/testify/assert"
)

type getAciNameTest struct {
	prefix string
	ktype  string
	name   string
	result string
}

func TestAciName(t *testing.T) {
	tests := []getAciNameTest{
		{"kube", "svc", "name", "kube_svc_name"},
		{"kube", "svc", "name/test", "kube_svc_name_test"},
		{"k8", "svc", "name/test", "k8_svc_name_test"},
		{"thisisaverylongprefixnamewhydothis", "svc",
			"thisisaverylongnamethisisbad", "3aa990528b114e15b4e9fa647382a40c"},
		{"shortprefix", "svc",
			"thisisaveryespeciallylongnamethisisbadwowthisisreallylong",
			"shortprefix_svc_0cb7bb9174a15c285a8454a5adb0e995"},
		{"thisislongbutnotthatlongenough", "svc",
			"thisisaveryespeciallylongnamethisisbadwowthisisreallylong",
			"thisislongbutnotthatlongenough_589a86701bdf648d54de8c519e0a906b"},
	}

	for _, tc := range tests {
		cont := AciController{
			config: &ControllerConfig{
				AciPrefix: tc.prefix,
			},
		}
		name := cont.aciNameForKey(tc.ktype, tc.name)
		assert.Equal(t, tc.result, name)
		assert.True(t, len(name) < 64)
	}
}

func TestProcessRemIpContQueue(t *testing.T) {
	cont := NewController(nil, nil, nil, false)
	queue := createQueue("remIpContQueue")
	stopCh := make(chan struct{})

	queue.Add("test1")

	go func() {
		time.Sleep(1 * time.Second)
		close(stopCh)
	}()

	fake_chan := make(chan string)
	fake_del_chan := make(chan string)
	fake_handler := func(s interface{}) bool {
		fake_chan <- "fake_handler_called"
		return false
	}

	fake_del_handler := func() bool {
		fake_del_chan <- "fake_del_handler_called"
		return false
	}

	cont.processRemIpContQueue(queue, fake_handler, fake_del_handler, stopCh)

	fake_handler_called := false
	fake_del_handler_called := false

waitHandler:
	for {
		select {
		case n := <-fake_chan:
			if n == "fake_handler_called" {
				fake_handler_called = true
			}
		case m := <-fake_del_chan:
			if m == "fake_del_handler_called" {
				fake_del_handler_called = true
			}
		case <-time.After(1 * time.Second):
			assert.True(t, false, "Timeout waiting for handler")
		}

		if fake_handler_called && fake_del_handler_called {
			break waitHandler
		}
	}

	assert.True(t, fake_handler_called, "fake_handler not called")
	assert.True(t, fake_del_handler_called, "fake_del_handler not called")
}
