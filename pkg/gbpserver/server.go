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
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	NoContainer = "NC"
	defToken    = "api-server-token"
	maxAttempts = 4096
	noOp        = iota
	OpaddEPG
	OpdelEPG
	OpaddContract
	OpdelContract
	OpaddEP
	OpdelEP
	OpaddNetPol
	OpdelNetPol
	OpaddGBPCustomMo
	OpdelGBPCustomMo
)

type PostResp struct {
	URI string
}

type ListResp struct {
	URIs []string
}

type Server struct {
	config *GBPServerConfig
	rxCh   chan *inputMsg
	// policy Mos
	policyDB map[string]*gbpBaseMo
	// inventory -- ep's organized per vtep
	invDB map[string]map[string]*gbpInvMo
	// listener callbacks for DB updates
	listeners map[string]func(op GBPOperation_OpCode, url []string)
	// grpc server
	gw *gbpWatch
	// tls rest server
	tlsSrv *http.Server
	// insecure rest server
	insSrv        *http.Server
	usedClassIDs  map[uint]bool
	instToClassID map[string]uint
	tunnels       map[string]int64
	bounceList    []string
	stopped       bool
}

// message from one of the watchers
type inputMsg struct {
	op   int
	data interface{}
}

type loginHandler struct {
}

func (l *loginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	class := "aaaLogin"
	if r.Method == http.MethodGet {
		class = "webtokenSession"
	}
	result := map[string]interface{}{
		"imdata": []interface{}{
			map[string]interface{}{
				class: map[string]interface{}{
					"attributes": map[string]interface{}{
						"token": defToken,
					},
				},
			},
		},
	}
	json.NewEncoder(w).Encode(result)
}

type nfh struct {
}

func (n *nfh) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Errorf("+++ Request: %+v", r)
}

func StartNewServer(config *GBPServerConfig) (*Server, error) {
	s := NewServer(config)
	s.InitDB()
	go s.handleMsgs()

	grpcPort := fmt.Sprintf(":%d", config.GRPCPort)
	gw, err := StartGRPC(grpcPort, s)
	s.gw = gw
	return s, err
}

func NewServer(config *GBPServerConfig) *Server {
	return &Server{
		config:        config,
		rxCh:          make(chan *inputMsg, 128),
		listeners:     make(map[string]func(op GBPOperation_OpCode, urls []string)),
		usedClassIDs:  make(map[uint]bool),
		instToClassID: make(map[string]uint),
	}
}

func (s *Server) getEncapClass(instURL string) (uint, uint) {
	if class, ok := s.instToClassID[instURL]; ok {
		log.Debugf("Found existing classID %v for epg %s", class, instURL)
		return encapFromClass(class), class
	}

	// allocate a classID
	for i := 0; i < maxAttempts; i++ {
		class := uint(rand.Intn(numClassIDs) + firstClassID)
		if !s.usedClassIDs[class] {
			s.usedClassIDs[class] = true
			s.instToClassID[instURL] = class
			return encapFromClass(class), class
		}
	}

	log.Fatalf("Failed to allocate classID after %d attempts", maxAttempts)
	return 0, 0
}

func (s *Server) freeEncapClass(instURL string) {
	class := s.instToClassID[instURL]
	log.Debugf("Freeing class: %v, uri: %s", class, instURL)
	delete(s.instToClassID, instURL)
	delete(s.usedClassIDs, class)
}

func (s *Server) Config() *GBPServerConfig {
	cfg := *s.config
	return &cfg
}

func (s *Server) Stop() {
	s.stopped = true
	s.gw.Stop()
	if s.tlsSrv != nil {
		s.tlsSrv.Close()
	}
	if s.insSrv != nil {
		s.insSrv.Close()
	}
}

func (s *Server) UTReadMsg(to time.Duration) (int, interface{}, error) {
	select {
	case m, ok := <-s.rxCh:
		if ok {
			return m.op, m.data, nil
		}

		return 0, nil, fmt.Errorf("channel closed")

	case <-time.After(to):
		return 0, nil, fmt.Errorf("timeout")
	}
}

func (s *Server) RegisterCallBack(id string, fn func(op GBPOperation_OpCode, urls []string)) {
	s.listeners[id] = fn
}

func (s *Server) RemoveCallBack(id string) {
	delete(s.listeners, id)
}

func (s *Server) AddNetPol(np NetworkPolicy) {
	m := &inputMsg{
		op:   OpaddNetPol,
		data: &np,
	}

	s.rxCh <- m
}

func (s *Server) DelNetPol(dn string) {
	m := &inputMsg{
		op:   OpdelNetPol,
		data: &dn,
	}

	s.rxCh <- m
}

func (s *Server) AddEPG(e EPG) {
	m := &inputMsg{
		op:   OpaddEPG,
		data: &e,
	}

	s.rxCh <- m
}

func (s *Server) DelEPG(e EPG) {
	m := &inputMsg{
		op:   OpdelEPG,
		data: &e,
	}

	s.rxCh <- m
}

func (s *Server) AddContract(c Contract) {
	m := &inputMsg{
		op:   OpaddContract,
		data: &c,
	}

	s.rxCh <- m
}

func (s *Server) DelContract(c Contract) {
	m := &inputMsg{
		op:   OpdelContract,
		data: &c,
	}

	s.rxCh <- m
}

func (s *Server) AddEP(ep Endpoint) {
	m := &inputMsg{
		op:   OpaddEP,
		data: &ep,
	}

	s.rxCh <- m
}

func (s *Server) DelEP(ep Endpoint) {
	m := &inputMsg{
		op:   OpdelEP,
		data: &ep,
	}

	s.rxCh <- m
}

func (s *Server) handleMsgs() {
	moDB := getMoDB()
	gMutex.Lock()
	for {
		gMutex.Unlock()
		m, ok := <-s.rxCh
		if !ok {
			log.Infof("Exiting handleMsgs")
			return
		}
		gMutex.Lock()

		switch m.op {
		case OpaddEP:
			ep, ok := m.data.(*Endpoint)
			if !ok {
				log.Errorf("Bad OpaddEP msg")
				continue
			}

			log.Debugf("OpaddEP: %+v", ep)
			if ep.IPAddr[0] != "" {
				ep.Add()
				for _, fn := range s.listeners {
					fn(GBPOperation_REPLACE, []string{ep.getURI()})
				}
			}

		case OpdelEP:
			ep, ok := m.data.(*Endpoint)
			if !ok {
				log.Errorf("Bad OpdelEP msg")
				continue
			}

			for _, fn := range s.listeners {
				fn(GBPOperation_DELETE, []string{ep.getURI()})
			}

			ep.Delete()
		case OpaddEPG:
			epg, ok := m.data.(*EPG)
			if !ok {
				log.Errorf("Bad OpaddEPG msg")
				continue
			}

			log.Debugf("Got epg: %+v", epg)
			epg.Make()
			for _, fn := range s.listeners {
				fn(GBPOperation_REPLACE, []string{epg.getURI()})
			}
		case OpdelEPG:
			epg, ok := m.data.(*EPG)
			if !ok {
				log.Errorf("Bad OpdelEPG msg")
				continue
			}

			key := epg.getURI()
			for _, fn := range s.listeners {
				fn(GBPOperation_DELETE, []string{key})
			}
			epg.Delete()
		case OpaddContract:
			c, ok := m.data.(*Contract)
			if !ok {
				log.Errorf("Bad OpaddContract msg")
				continue
			}

			c.Make()
			for _, fn := range s.listeners {
				fn(GBPOperation_REPLACE, c.getAllURIs())
			}
		case OpdelContract:
			c, ok := m.data.(*Contract)
			if !ok {
				log.Errorf("Bad OpdelContract msg")
				continue
			}

			key := c.getURI()
			log.Debugf("delete contract: %s", key)
			for _, fn := range s.listeners {
				fn(GBPOperation_DELETE, []string{key})
			}
			cmo := moDB[key]
			if cmo != nil {
				cmo.delRecursive()
			}
		case OpaddNetPol:
			np, ok := m.data.(*NetworkPolicy)
			if !ok {
				log.Errorf("Bad OpaddNetPol msg")
				continue
			}

			err := np.Make()
			if err != nil {
				log.Errorf("Network policy -- %v", err)
				continue
			}

			name := np.HostprotPol.Attributes[propName]
			if !strings.Contains(name, "np_static") {
				for _, fn := range theServer.listeners {
					fn(GBPOperation_REPLACE, np.getAllURIs())
				}
			}
		case OpdelNetPol:
			dn, ok := m.data.(*string)
			if !ok {
				log.Errorf("Bad OpdelNetPol msg")
				continue
			}
			npName := npNameFromDn(*dn)

			key := fmt.Sprintf("/PolicyUniverse/PolicySpace/%s/%s/%s/", getTenantName(), subjSecGroup, npName)
			npMo := moDB[key]
			if npMo == nil {
				log.Errorf("%s not found", key)
				continue
			}
			for _, fn := range theServer.listeners {
				fn(GBPOperation_DELETE, []string{key})
			}
			npMo.delRecursive()
		case OpaddGBPCustomMo:
			s.processAddGBPCustomMoLocked(m.data.(GBPCustomMo))
		case OpdelGBPCustomMo:
			s.processDelGBPCustomMoLocked(m.data.(GBPCustomMo))
		default:
			log.Errorf("Unknown msg type: %d", m.op)
			continue
		}
	}
}
