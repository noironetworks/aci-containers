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
	"encoding/json"
	"net/http"

	log "github.com/sirupsen/logrus"
	"github.com/gorilla/mux"
)

type httpAPIFunc func(w http.ResponseWriter, r *http.Request, vars map[string]string) (interface{}, error)

// MakeHTTPHandler is a simple Wrapper for http handlers
func MakeHTTPHandler(handlerFunc httpAPIFunc) http.HandlerFunc {
	// Create a closure and return an anonymous function
	return func(w http.ResponseWriter, r *http.Request) {
		// Call the handler
		resp, err := handlerFunc(w, r, mux.Vars(r))
		if err != nil {
			// Log error
			log.Errorf("Handler for %s %s returned error: %s", r.Method, r.URL, err)

			if resp == nil {
				// Send HTTP response
				http.Error(w, err.Error(), http.StatusInternalServerError)
			} else {
				// Send HTTP response as Json
				content, err := json.Marshal(resp)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}

				w.WriteHeader(http.StatusInternalServerError)
				w.Write(content)
			}
		} else {
			// Send HTTP response as Json
			err = writeJSON(w, http.StatusOK, resp)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
	}
}

// writeJSON: writes the value v to the http response stream as json with standard
// json encoding.
func writeJSON(w http.ResponseWriter, code int, v interface{}) error {
	// Set content type as json
	w.Header().Set("Content-Type", "application/json")

	// write the HTTP status code
	w.WriteHeader(code)

	// Write the Json output
	return json.NewEncoder(w).Encode(v)
}
