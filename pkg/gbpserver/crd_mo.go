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

// GBPCustomMo acts as the interface between a CRD and the corresponding MO.
// Implement this interface in the CRD watcher
type GBPCustomMo interface {
	Subject() string
	URI(s *Server) string
	Properties() map[string]interface{}
	ParentSub() string
	ParentURI(s *Server) string
	Children() []string
}

// GetTenantURI helper for watchers to get the tenant uri
func (s *Server) GetTenantURI() string {
	return getTenantUri()
}

// GetPlatformURI helper for watchers to get the platform uri
func (s *Server) GetPlatformURI() string {
	return getPlatformUri(s)
}

// GetURIBySubject helper for watchers to get a parent URI
func (s *Server) GetURIBySubject(sub string) string {
	gMutex.Lock()
	defer gMutex.Unlock()
	moDB := getMoDB()
	for uri, mo := range moDB {
		if mo.Subject == sub {
			return uri
		}
	}
	return ""
}

// AddGBPCustomMo access utility for crd watcher to add an MO
func (s *Server) AddGBPCustomMo(crd GBPCustomMo) {
	m := &inputMsg{
		op:   OpaddGBPCustomMo,
		data: crd,
	}

	s.rxCh <- m
}

// DelGBPCustomMo access utility for crd watcher to delete an MO
func (s *Server) DelGBPCustomMo(crd GBPCustomMo) {
	m := &inputMsg{
		op:   OpdelGBPCustomMo,
		data: crd,
	}

	s.rxCh <- m
}

func (s *Server) processAddGBPCustomMoLocked(crd GBPCustomMo) {
	mo := &gbpBaseMo{}
	mo.Subject = crd.Subject()
	mo.Uri = crd.URI(s)
	if crd.ParentSub() != "" {
		mo.SetParent(crd.ParentSub(), crd.Subject(), crd.ParentURI(s))
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

func (s *Server) processDelGBPCustomMoLocked(crd GBPCustomMo) {
	key := crd.URI(s)
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
