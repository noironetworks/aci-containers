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
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"github.com/noironetworks/aci-containers/pkg/apicapi"
	crdv1 "github.com/noironetworks/aci-containers/pkg/gbpcrd/apis/acipolicy/v1"
	"github.com/noironetworks/aci-containers/pkg/gbpserver/kafkac"
	"github.com/noironetworks/aci-containers/pkg/objdb"
)

const (
	NoContainer = "NC"
	root        = "/aci/objdb"
	ListenPort  = "8899"
	defToken    = "api-server-token"
	versionPath = "/api/node/class/firmwareCtrlrRunning.json"
	versionStr  = "3.2(5d)"
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
)

var DefETCD = []string{"127.0.0.1:2379"}

type PostResp struct {
	URI string
}

type ListResp struct {
	URIs []string
}

type Server struct {
	config   *GBPServerConfig
	driver   StateDriver
	rxCh     chan *inputMsg
	objapi   objdb.API
	upgrader websocket.Upgrader
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
	insSrv *http.Server
	// kafka client
	kc            *kafkac.KafkaClient
	usedClassIDs  map[uint]bool
	instToClassID map[string]uint
	stopped       bool
}

type StateDriver interface {
	Init(int) error
	Get() (*crdv1.GBPSState, error)
	Update(*crdv1.GBPSState) error
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

type versionResp struct {
}

func (v *versionResp) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	result := map[string]interface{}{
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
	json.NewEncoder(w).Encode(result)
}

type refreshSucc struct{}

func (h *refreshSucc) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	result := map[string]interface{}{}
	json.NewEncoder(w).Encode(result)
}

type socketHandler struct {
	srv *Server
}

func (h *socketHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c, err := h.srv.upgrader.Upgrade(w, r, nil)

	if err != nil {
		return
	}

	go func() {
		defer c.Close()

		for {
			_, _, err := c.ReadMessage()
			if _, k := err.(*websocket.CloseError); k {
				break
			}
		}
	}()
}

var LocalhostCert = []byte(`-----BEGIN CERTIFICATE-----
MIICEzCCAXygAwIBAgIQMIMChMLGrR+QvmQvpwAU6zANBgkqhkiG9w0BAQsFADAS
MRAwDgYDVQQKEwdBY21lIENvMCAXDTcwMDEwMTAwMDAwMFoYDzIwODQwMTI5MTYw
MDAwWjASMRAwDgYDVQQKEwdBY21lIENvMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCB
iQKBgQDuLnQAI3mDgey3VBzWnB2L39JUU4txjeVE6myuDqkM/uGlfjb9SjY1bIw4
iA5sBBZzHi3z0h1YV8QPuxEbi4nW91IJm2gsvvZhIrCHS3l6afab4pZBl2+XsDul
rKBxKKtD1rGxlG4LjncdabFn9gvLZad2bSysqz/qTAUStTvqJQIDAQABo2gwZjAO
BgNVHQ8BAf8EBAMCAqQwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDwYDVR0TAQH/BAUw
AwEB/zAuBgNVHREEJzAlggtleGFtcGxlLmNvbYcEfwAAAYcQAAAAAAAAAAAAAAAA
AAAAATANBgkqhkiG9w0BAQsFAAOBgQCEcetwO59EWk7WiJsG4x8SY+UIAA+flUI9
tyC4lNhbcF2Idq9greZwbYCqTTTr2XiRNSMLCOjKyI7ukPoPjo16ocHj+P3vZGfs
h1fIw3cSS2OolhloGw/XM6RWPWtPAlGykKLciQrBru5NAPvCMsb/I1DAceTiotQM
fblo6RBxUQ==
-----END CERTIFICATE-----`)

var LocalhostKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDuLnQAI3mDgey3VBzWnB2L39JUU4txjeVE6myuDqkM/uGlfjb9
SjY1bIw4iA5sBBZzHi3z0h1YV8QPuxEbi4nW91IJm2gsvvZhIrCHS3l6afab4pZB
l2+XsDulrKBxKKtD1rGxlG4LjncdabFn9gvLZad2bSysqz/qTAUStTvqJQIDAQAB
AoGAGRzwwir7XvBOAy5tM/uV6e+Zf6anZzus1s1Y1ClbjbE6HXbnWWF/wbZGOpet
3Zm4vD6MXc7jpTLryzTQIvVdfQbRc6+MUVeLKwZatTXtdZrhu+Jk7hx0nTPy8Jcb
uJqFk541aEw+mMogY/xEcfbWd6IOkp+4xqjlFLBEDytgbIECQQDvH/E6nk+hgN4H
qzzVtxxr397vWrjrIgPbJpQvBsafG7b0dA4AFjwVbFLmQcj2PprIMmPcQrooz8vp
jy4SHEg1AkEA/v13/5M47K9vCxmb8QeD/asydfsgS5TeuNi8DoUBEmiSJwma7FXY
fFUtxuvL7XvjwjN5B30pNEbc6Iuyt7y4MQJBAIt21su4b3sjXNueLKH85Q+phy2U
fQtuUE9txblTu14q3N7gHRZB4ZMhFYyDy8CKrN2cPg/Fvyt0Xlp/DoCzjA0CQQDU
y2ptGsuSmgUtWj3NM9xuwYPm+Z/F84K6+ARYiZ6PYj013sovGKUFfYAqVXVlxtIX
qyUBnu3X9ps8ZfjLZO7BAkEAlT4R5Yl6cGhaJQYZHOde3JEMhNRcVFMO8dJDaFeo
f9Oeos0UUothgiDktdQHxdNEwLjQf7lJJBzV+5OtwswCWA==
-----END RSA PRIVATE KEY-----`)

func getTLSCfg() (*tls.Config, error) {
	cfg := new(tls.Config)
	cert, err := tls.X509KeyPair(LocalhostCert, LocalhostKey)
	if err != nil {
		return nil, err
	}

	if cfg.NextProtos == nil {
		cfg.NextProtos = []string{"http/1.1"}
	}
	cfg.Certificates = []tls.Certificate{cert}
	return cfg, nil
}

type nfh struct {
}

func (n *nfh) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Errorf("+++ Request: %+v", r)
}

func StartNewServer(config *GBPServerConfig, sd StateDriver, etcdURLs []string) (*Server, error) {
	// create an etcd client
	log.Debugf("=> Creating new client ..")
	ec, err := objdb.NewClient(etcdURLs, root)
	if err != nil {
		return nil, err
	}

	log.Debugf("=> New client created..")
	s := NewServer(config)
	s.InitState(sd)
	s.InitDB()
	s.objapi = ec
	wHandler := func(w http.ResponseWriter, r *http.Request) {
		s.handleWrite(w, r)
	}
	rHandler := func(w http.ResponseWriter, r *http.Request) {
		s.handleRead(w, r)
	}

	r := mux.NewRouter()

	// add websocket handlers
	r.Handle("/api/webtokenSession.json", &loginHandler{})
	r.Handle("/api/aaaLogin.json", &loginHandler{})
	r.Handle("/api/aaaRefresh.json", &refreshSucc{})
	r.Handle(fmt.Sprintf("/socket%s", defToken), &socketHandler{srv: s})
	//r.PathPrefix("/api/node").HandlerFunc(wHandler)

	t := r.Headers("Content-Type", "application/json").Methods("POST").Subrouter()
	// gbp rest handlers
	addGBPPost(t)

	npPath := fmt.Sprintf("/api/mo/uni/tn-%s/pol-", config.AciPolicyTenant)
	t.PathPrefix(npPath).HandlerFunc(MakeHTTPHandler(postNP))
	t.PathPrefix("/api/mo").HandlerFunc(wHandler)
	// api/mo handlers (apic stub)
	t.PathPrefix("/api/mo").HandlerFunc(wHandler)
	// Routes consist of a path and a handler function.
	delR := r.Methods("DELETE").Subrouter()
	addGBPDelete(delR)
	delR.PathPrefix(npPath).HandlerFunc(MakeHTTPHandler(deleteNP))
	getR := r.Methods("GET").Subrouter()
	addGBPGet(getR)
	getR.PathPrefix("/api/mo").HandlerFunc(rHandler)
	getR.PathPrefix("/api/node").HandlerFunc(rHandler)
	getR.PathPrefix("/api/class").HandlerFunc(rHandler)
	r.Methods("POST").Subrouter().PathPrefix("/api/node").HandlerFunc(wHandler)
	r.NotFoundHandler = &nfh{}
	tlsCfg, err := getTLSCfg()
	if err != nil {
		return nil, err
	}
	//	tlsCfg.BuildNameToCertificate()

	listenPort := fmt.Sprintf(":%d", config.ProxyListenPort)
	go func() {
		log.Infof("=> Listening at %s", listenPort)
		tlsSrv := http.Server{Addr: listenPort, Handler: r, TLSConfig: tlsCfg}
		s.tlsSrv = &tlsSrv
		// Bind to a port and pass our router in
		err := tlsSrv.ListenAndServeTLS("", "")
		if !s.stopped {
			log.Fatal(err)
		}
	}()

	/*
		if insecurePort != "" {
			go func() {
				srv := &http.Server{
					Handler: r,
					Addr:    insecurePort,
					// Good practice: enforce timeouts for servers you create!
					WriteTimeout: 15 * time.Second,
					ReadTimeout:  15 * time.Second,
				}

				s.insSrv = srv
				err := srv.ListenAndServe()
				if !s.stopped {
					log.Fatal(err)
				}
			}()
		}
	*/

	go s.handleMsgs()
	if config.Apic != nil && config.Apic.Kafka != nil {
		kc, err := kafkac.InitKafkaClient(config.Apic.Kafka, config.Apic.Cloud)
		if err != nil {
			return nil, err
		}

		s.kc = kc
	}

	grpcPort := fmt.Sprintf(":%d", config.GRPCPort)
	s.gw, err = StartGRPC(grpcPort, s)
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

func (s *Server) InitState(sd StateDriver) error {
	s.driver = sd
	state, err := s.driver.Get()
	if err != nil {
		return err
	}

	// populate classID maps based on the state
	for epg, classID := range state.Status.ClassIDs {
		s.instToClassID[epg] = classID
		s.usedClassIDs[classID] = true
	}

	return nil
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
			s.writeState()
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
	s.writeState()
}

func (s *Server) writeState() {
	state := &crdv1.GBPSState{}
	state.Status.ClassIDs = make(map[string]uint, len(s.instToClassID))
	for uri, class := range s.instToClassID {
		state.Status.ClassIDs[uri] = class
	}

	s.driver.Update(state)
}

func (s *Server) Config() *GBPServerConfig {
	cfg := *s.config
	return &cfg
}

func (s *Server) Stop() {
	s.stopped = true
	s.gw.Stop()
	s.tlsSrv.Close()
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

			s.kafkaEPAdd(ep)

		case OpdelEP:
			ep, ok := m.data.(*Endpoint)
			if !ok {
				log.Errorf("Bad OpdelEP msg")
				continue
			}

			for _, fn := range s.listeners {
				fn(GBPOperation_DELETE, []string{ep.getURI()})
			}

			s.kafkaEPDel(ep)
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
			if s.kc != nil {
				s.kc.UpdateEpgDN(epg.Name, epg.ApicDN)
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
		default:
			log.Errorf("Unknown msg type: %d", m.op)
			continue
		}

		DoAll()
	}
}

func (s *Server) kafkaEPAdd(ep *Endpoint) {
	if s.kc == nil {
		return
	}

	cid := UuidToCid(ep.Uuid)
	if cid == NoContainer { // not a real pod, don't report to kafka
		return
	}

	ps := &crdv1.PodIFStatus{
		PodName:     ep.PodName,
		PodNS:       ep.Namespace,
		IFName:      ep.IFName,
		EPG:         ep.EPG,
		IPAddr:      ep.IPAddr[0],
		ContainerID: UuidToCid(ep.Uuid),
	}

	err := s.kc.AddEP(ps)
	if err != nil {
		log.Errorf("Error: %v adding EP: %+v", err, ps)
	}
}

func UuidToCid(uuid string) string {
	s := strings.Split(uuid, ".")
	return s[len(s)-1]
}

func (s *Server) kafkaEPDel(ep *Endpoint) {
	if s.kc == nil {
		return
	}

	if ep.PodName == "" { // not a real pod, don't report to kafka
		return
	}

	ps := &crdv1.PodIFStatus{
		PodName: ep.PodName,
		PodNS:   ep.Namespace,
		IFName:  ep.IFName,
		EPG:     ep.EPG,
		IPAddr:  ep.IPAddr[0],
	}
	s.kc.DeleteEP(ps)
}

func (s *Server) handleWrite(w http.ResponseWriter, r *http.Request) {
	uri := r.URL.RequestURI()
	log.Debugf("handleWrite: %s", uri)
	content, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = s.objapi.SetRaw(uri, content)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleRead(w http.ResponseWriter, r *http.Request) {
	uri := r.URL.RequestURI()

	log.Debugf("handleRead: %s", uri)
	if strings.Contains(uri, versionPath) {
		vR := &versionResp{}
		vR.ServeHTTP(w, r)
		return
	}
	content, err := s.objapi.GetRaw(uri)
	if err != nil {
		//	http.Error(w, err.Error(), http.StatusInternalServerError)
		//	return
		nullResp := &apicapi.ApicResponse{
			SubscriptionId: "4-3-3",
		}
		content, _ = json.Marshal(nullResp)
	}

	w.Header().Set("Content-Type", "application/json")

	// write the HTTP status code
	w.WriteHeader(http.StatusOK)
	w.Write(content)
}

func addGBPPost(mr *mux.Router) {
	mr.PathPrefix("/gbp/contracts").HandlerFunc(MakeHTTPHandler(postContract))
	mr.PathPrefix("/gbp/epgs").HandlerFunc(MakeHTTPHandler(postEpg))
	mr.PathPrefix("/gbp/endpoints").HandlerFunc(MakeHTTPHandler(postEndpoint))
}

func addGBPGet(mr *mux.Router) {
	mr.Path("/gbp/contracts/").HandlerFunc(MakeHTTPHandler(listContracts))
	mr.Path("/gbp/contract/").HandlerFunc(MakeHTTPHandler(getContract))
	mr.Path("/gbp/epgs/").HandlerFunc(MakeHTTPHandler(listEpgs))
	mr.Path("/gbp/epg/").HandlerFunc(MakeHTTPHandler(getEpg))
	mr.Path("/gbp/endpoints/").HandlerFunc(MakeHTTPHandler(listEndpoints))
	mr.Path("/gbp/endpoint/").HandlerFunc(MakeHTTPHandler(getEndpoint))
}

func addGBPDelete(mr *mux.Router) {
	mr.Path("/gbp/contract/").HandlerFunc(MakeHTTPHandler(deleteObject))
	mr.Path("/gbp/epg/").HandlerFunc(MakeHTTPHandler(deleteObject))
	mr.Path("/gbp/endpoint/").HandlerFunc(MakeHTTPHandler(deleteEndpoint))
}
