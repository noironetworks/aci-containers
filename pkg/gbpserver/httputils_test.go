/***
Copyright 2019 Cisco Systems Inc. All rights reserved.

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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMakeHTTPHandler(t *testing.T) {
	mockHandler := func(w http.ResponseWriter, r *http.Request, vars map[string]string) (interface{}, error) {
		return map[string]string{"message": "Hello, World!"}, nil
	}

	req, err := http.NewRequest("GET", "/test", http.NoBody)
	if err != nil {
		t.Fatalf("Failed to create test request: %v", err)
	}

	recorder := httptest.NewRecorder()

	handler := MakeHTTPHandler(mockHandler)

	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, recorder.Code)
	}

	expectedBody := `{"message":"Hello, World!"}`
	if strings.TrimSpace(recorder.Body.String()) != strings.TrimSpace(expectedBody) {
		t.Errorf("Expected response body %q, got %q", expectedBody, recorder.Body.String())
	}
}
