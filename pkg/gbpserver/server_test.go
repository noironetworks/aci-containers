/***
Copyright 2018 Cisco Systems Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package gbpserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	reflect "reflect"
	"testing"
	"time"

	"github.com/noironetworks/aci-containers/pkg/gbpserver/kafkac"
)

func TestLoginHandlerServeHTTP(t *testing.T) {
	handler := &loginHandler{}

	req, err := http.NewRequest(http.MethodGet, "/", nil)
	if err != nil {
		t.Fatalf("Failed to create HTTP request: %v", err)
	}

	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, recorder.Code)
	}
}
func TestVersionRespServeHTTP(t *testing.T) {
	handler := &versionResp{}

	req, err := http.NewRequest(http.MethodGet, "/", nil)
	if err != nil {
		t.Fatalf("Failed to create HTTP request: %v", err)
	}

	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, recorder.Code)
	}

	expectedResult := map[string]interface{}{
		"imdata": []interface{}{
			map[string]interface{}{
				"firmwareCtrlrRunning": map[string]interface{}{
					"attributes": map[string]interface{}{
						"version": versionStr,
					},
				},
			},
		},
	}

	var actualResult map[string]interface{}
	err = json.NewDecoder(recorder.Body).Decode(&actualResult)
	if err != nil {
		t.Fatalf("Failed to decode response body: %v", err)
	}

	if !reflect.DeepEqual(actualResult, expectedResult) {
		t.Errorf("Expected response body %v, got %v", expectedResult, actualResult)
	}
}
func TestNfhServeHTTP(t *testing.T) {
	n := &nfh{}

	req, err := http.NewRequest(http.MethodGet, "/", nil)
	if err != nil {
		t.Fatalf("Failed to create HTTP request: %v", err)
	}

	recorder := httptest.NewRecorder()

	n.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, recorder.Code)
	}
}
func TestUTReadMsg(t *testing.T) {
	s := &Server{
		rxCh: make(chan *inputMsg),
	}

	op, data, err := s.UTReadMsg(time.Second)
	if err == nil {
		t.Errorf("Expected error, got nil")
	}
	if err.Error() != "timeout" {
		t.Errorf("Expected error 'timeout', got '%v'", err)
	}
	if op != 0 {
		t.Errorf("Expected op 0, got %d", op)
	}
	if data != nil {
		t.Errorf("Expected data nil, got %v", data)
	}
}
func TestAddNetPol(t *testing.T) {
	s := &Server{
		rxCh: make(chan *inputMsg),
	}

	np := NetworkPolicy{}

	expectedMsg := &inputMsg{
		op:   OpaddNetPol,
		data: &np,
	}

	go s.AddNetPol(np)

	select {
	case msg := <-s.rxCh:
		if !reflect.DeepEqual(msg, expectedMsg) {
			t.Errorf("Expected message %v, got %v", expectedMsg, msg)
		}
	case <-time.After(time.Second):
		t.Errorf("Timeout waiting for message")
	}
}
func TestDelEPServeHTTP(t *testing.T) {
	s := &Server{
		rxCh: make(chan *inputMsg),
	}

	ep := Endpoint{}

	expectedMsg := &inputMsg{
		op:   OpdelEP,
		data: &ep,
	}

	go s.DelEP(ep)

	select {
	case msg := <-s.rxCh:
		if !reflect.DeepEqual(msg, expectedMsg) {
			t.Errorf("Expected message %v, got %v", expectedMsg, msg)
		}
	case <-time.After(time.Second):
		t.Errorf("Timeout waiting for message")
	}
}
func TestUpdateTunnels(t *testing.T) {
	s := &Server{
		rxCh: make(chan *inputMsg),
	}

	tunnels := map[string]int64{
		"tunnel1": 123,
		"tunnel2": 456,
	}

	expectedMsg := &inputMsg{
		op:   OpUpdTunnels,
		data: tunnels,
	}

	go s.UpdateTunnels(tunnels)

	select {
	case msg := <-s.rxCh:
		if !reflect.DeepEqual(msg, expectedMsg) {
			t.Errorf("Expected message %v, got %v", expectedMsg, msg)
		}
	case <-time.After(time.Second):
		t.Errorf("Timeout waiting for message")
	}
}
func TestUuidToCid(t *testing.T) {
	tests := []struct {
		name     string
		uuid     string
		expected string
	}{
		{
			name:     "Test case 1",
			uuid:     "abc.def.ghi",
			expected: "ghi",
		},
		{
			name:     "Test case 2",
			uuid:     "123.456.789",
			expected: "789",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := UuidToCid(tt.uuid)
			if actual != tt.expected {
				t.Errorf("Expected result: %s, got: %s", tt.expected, actual)
			}
		})
	}
}

func TestKafkaEPDel(t *testing.T) {
	s := &Server{
		kc: nil,
	}

	s.kafkaEPDel(&Endpoint{})

	s.kc = &kafkac.KafkaClient{}

	s.kafkaEPDel(&Endpoint{})
}
