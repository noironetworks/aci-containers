/***
Copyright 2020 Cisco Systems Inc. All rights reserved.

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
// GBP Mo hooks

package gbpserver

import (
	log "github.com/sirupsen/logrus"
)

// CRDMo acts as the interface between a CRD and the corresponding MO.
// Implement this interface in the CRD watcher
type CRDMo interface {
	Subject() string
	URI() string
	Properties() map[string]interface{}
	ParentSub() string
	ParentURI() string
	Children() []string
}

// GetTenantURI helper for watchers to get the tenant uri
func (s *Server) GetTenantURI() string {
	return getTenantUri()
}

// AddCRDMo access utility for crd watcher to add an MO
func (s *Server) AddCRDMo(crd CRDMo) {
	m := &inputMsg{
		op:   OpaddCRDMo,
		data: crd,
	}

	s.rxCh <- m
}

// DelCRDMo access utility for crd watcher to delete an MO
func (s *Server) DelCRDMo(crd CRDMo) {
	m := &inputMsg{
		op:   OpdelCRDMo,
		data: crd,
	}

	s.rxCh <- m
}

func (s *Server) processAddCRDMoLocked(crd CRDMo) {
	mo := &gbpBaseMo{}
	mo.Subject = crd.Subject()
	mo.Uri = crd.URI()
	if crd.ParentSub() != "" {
		mo.SetParent(crd.ParentSub(), crd.Subject(), crd.ParentURI())
		for p, val := range crd.Properties() {
			mo.AddProperty(p, val)
		}
	}

	for _, c := range crd.Children() {
		mo.AddChild(c)
	}

	mo.save()
	for _, fn := range s.listeners {
		fn(GBPOperation_REPLACE, []string{mo.Uri})
	}
}

func (s *Server) processDelCRDMoLocked(crd CRDMo) {
	key := crd.URI()
	log.Debugf("delete object: %s", key)
	for _, fn := range s.listeners {
		fn(GBPOperation_DELETE, []string{key})
	}
	moDB := getMoDB()
	mo := moDB[key]
	if mo != nil {
		mo.delRecursive()
	}

}
