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

// Interface for connecting to APIC REST API using websockets
package apicapi

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/workqueue"

	"github.com/sirupsen/logrus"
	"github.com/gorilla/websocket"
	"golang.org/x/time/rate"
)

// defaultConnectionRefresh is used as connection refresh interval if
// RefreshInterval is set to 0
const defaultConnectionRefresh = 30 * time.Second

// ApicVersion - This global variable to be used when dealing with version-
// dependencies during APIC interaction. It gets filled with actual version
// as part of runConn()
var (
	ApicVersion = 3.1
)

func complete(resp *http.Response) {
	if resp.StatusCode != http.StatusOK {
		rBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			logrus.Errorf("ReadAll :% v", err)
		} else {
			logrus.Infof("Resp: %s", rBody)
		}

	}
	resp.Body.Close()
}

// Yes, this is really stupid, but this is really how this works
func (conn *ApicConnection) sign(req *http.Request, uri string, body []byte) {
	if conn.signer == nil {
		return
	}

	sig, err := conn.signer.sign(req.Method, uri, body)
	if err != nil {
		conn.log.Error("Failed to sign request: ", err)
		return
	}

	req.Header.Set("Cookie", conn.apicSigCookie(sig, conn.token))
}

func (conn *ApicConnection) apicSigCookie(sig string, token string) string {
	tokc := ""
	if token != "" {
		tokc = "; APIC-WebSocket-Session=" + token
	}
	return fmt.Sprintf("APIC-Request-Signature=%s; "+
		"APIC-Certificate-Algorithm=v1.0; "+
		"APIC-Certificate-DN=uni/userext/user-%s/usercert-%s.crt; "+
		"APIC-Certificate-Fingerprint=fingerprint%s",
		sig, conn.user, conn.user, tokc)
}

func (conn *ApicConnection) login() (string, error) {
	var path string
	var method string

	if conn.signer == nil {
		path = "aaaLogin"
		method = "POST"
	} else {
		path = "webtokenSession"
		method = "GET"
	}
	uri := fmt.Sprintf("/api/%s.json", path)
	url := fmt.Sprintf("https://%s%s", conn.apic[conn.apicIndex], uri)

	var reqBody io.Reader
	var raw []byte
	var err error
	if conn.signer == nil {
		login := &ApicObject{
			"aaaUser": &ApicObjectBody{
				Attributes: map[string]interface{}{
					"name": conn.user,
					"pwd":  conn.password,
				},
			},
		}
		raw, err = json.Marshal(login)
		if err != nil {
			return "", err
		}
		reqBody = bytes.NewBuffer(raw)
	}
	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		return "", err
	}
	conn.log.Infof("Req: %+v", req)
	conn.sign(req, uri, raw)
	req.Header.Set("Content-Type", "application/json")
	resp, err := conn.client.Do(req)
	if err != nil {
		return "", err
	}
	defer complete(resp)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		conn.logErrorResp("Error while logging into APIC", resp)
		return "", errors.New("Server returned error status")
	}

	var apicresp ApicResponse
	err = json.NewDecoder(resp.Body).Decode(&apicresp)
	if err != nil {
		return "", err
	}

	for _, obj := range apicresp.Imdata {
		lresp, ok := obj["aaaLogin"]
		if !ok {
			lresp, ok = obj["webtokenSession"]
			if !ok {
				continue
			}
		}

		token, ok := lresp.Attributes["token"]
		if !ok {
			return "", errors.New("Token not found in login response")
		}
		switch token := token.(type) {
		default:
			return "", errors.New("Token is not a string")
		case string:
			return token, nil
		}
	}
	return "", errors.New("Login response not found")
}

func configureTls(cert []byte) (*tls.Config, error) {
	if cert == nil {
		return &tls.Config{InsecureSkipVerify: true}, nil
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(cert) {
		return nil, errors.New("Could not load CA certificates")
	}
	return &tls.Config{RootCAs: pool}, nil
}

func New(log *logrus.Logger, apic []string, user string,
	password string, privKey []byte, cert []byte,
	prefix string, refresh int, refreshTickerAdjust int) (*ApicConnection, error) {
	tls, err := configureTls(cert)
	if err != nil {
		return nil, err
	}

	var signer *signer
	if privKey != nil {
		signer, err = newSigner(privKey)
		if err != nil {
			return nil, err
		}
	}

	dialer := &websocket.Dialer{
		TLSClientConfig: tls,
	}
	tr := &http.Transport{
		Proxy:           http.ProxyFromEnvironment,
		TLSClientConfig: dialer.TLSClientConfig,
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{
		Transport: tr,
		Jar:       jar,
		Timeout:   5 * time.Minute,
	}

	conn := &ApicConnection{
		ReconnectInterval:   time.Duration(5) * time.Second,
		RefreshInterval:     time.Duration(refresh) * time.Second,
		RefreshTickerAdjust: time.Duration(refreshTickerAdjust) * time.Second,
		signer:              signer,
		dialer:              dialer,
		logger:              log,
		log:                 log.WithField("mod", "APICAPI"),
		apic:                apic,
		user:                user,
		password:            password,
		prefix:              prefix,
		client:              client,
		subscriptions: subIndex{
			subs: make(map[string]*subscription),
			ids:  make(map[string]string),
		},
		desiredState:       make(map[string]ApicSlice),
		desiredStateDn:     make(map[string]ApicObject),
		keyHashes:          make(map[string]string),
		containerDns:       make(map[string]bool),
		cachedState:        make(map[string]ApicSlice),
		cacheDnSubIds:      make(map[string]map[string]bool),
		pendingSubDnUpdate: make(map[string]pendingChange),
		CachedSubnetDns:    make(map[string]string),
	}
	return conn, nil
}

func (conn *ApicConnection) handleSocketUpdate(apicresp *ApicResponse) {
	var subIds []string
	switch ids := apicresp.SubscriptionId.(type) {
	case string:
		subIds = append(subIds, ids)
	case []interface{}:
		for _, id := range ids {
			subIds = append(subIds, id.(string))
		}
	}

	for _, obj := range apicresp.Imdata {
		for _, body := range obj {
			switch dn := body.Attributes["dn"].(type) {
			case string:
				switch status := body.Attributes["status"].(type) {
				case string:
					var pendingKind int
					if status == "deleted" {
						pendingKind = pendingChangeDelete
					} else {
						pendingKind = pendingChangeUpdate
					}
					conn.indexMutex.Lock()

					conn.logger.WithFields(logrus.Fields{
						"mod": "APICAPI",
						"dn":  obj.GetDn(),
						"obj": obj,
					}).Debug("Processing websocket notification for:")

					conn.pendingSubDnUpdate[dn] = pendingChange{
						kind:    pendingKind,
						subIds:  subIds,
						isDirty: false,
					}
					if conn.deltaQueue != nil {
						conn.deltaQueue.Add(dn)
					}
					conn.indexMutex.Unlock()
				}
			}
		}
	}
}

func (conn *ApicConnection) restart() {
	conn.indexMutex.Lock()
	if conn.restartCh != nil {
		conn.log.Debug("Restarting connection")
		close(conn.restartCh)
		conn.restartCh = nil
	}
	conn.indexMutex.Unlock()
}

func (conn *ApicConnection) handleQueuedDn(dn string) bool {
	var respClasses []string
	var updateHandlers []ApicObjectHandler
	var deleteHandlers []ApicDnHandler
	var rootDn string

	handleId := func(id string) {
		conn.indexMutex.Lock()
		if value, ok := conn.subscriptions.ids[id]; ok {
			if sub, ok := conn.subscriptions.subs[value]; ok {
				respClasses =
					append(respClasses, sub.respClasses...)
				if sub.updateHook != nil {
					updateHandlers = append(updateHandlers, sub.updateHook)
				}
				if sub.deleteHook != nil {
					deleteHandlers = append(deleteHandlers, sub.deleteHook)
				}

				if sub.kind == apicSubTree {
					rootDn = getRootDn(dn, value)
				}
			}
		} else {
			conn.log.Warning("Unexpected subscription: ", id)
		}
		conn.indexMutex.Unlock()
	}

	var requeue bool
	conn.indexMutex.Lock()
	pending, hasPendingChange := conn.pendingSubDnUpdate[dn]
	conn.pendingSubDnUpdate[dn] = pendingChange{isDirty: true}
	obj, hasDesiredState := conn.desiredStateDn[dn]
	conn.indexMutex.Unlock()

	if hasPendingChange {
		for _, id := range pending.subIds {
			handleId(id)
		}
	}

	if rootDn == "" {
		rootDn = dn
	}

	if hasDesiredState {
		if hasPendingChange {
			if pending.kind == pendingChangeDelete {
				conn.logger.WithFields(logrus.Fields{"mod": "APICAPI", "DN": dn}).
					Warning("Restoring unexpectedly deleted" +
						" ACI object")
				requeue = conn.postDn(dn, obj)
			} else {
				conn.log.Debug("getSubtreeDn for:", rootDn)
				conn.getSubtreeDn(rootDn, respClasses, updateHandlers)
			}
		} else {
			requeue = conn.postDn(dn, obj)
		}
	} else {
		if hasPendingChange {
			if pending.kind == pendingChangeDelete {
				for _, handler := range deleteHandlers {
					handler(dn)
				}
			}

			if (pending.kind != pendingChangeDelete) || (dn != rootDn) {
				conn.log.Debug("getSubtreeDn for:", rootDn)
				conn.getSubtreeDn(rootDn, respClasses, updateHandlers)
			}
		} else {
			requeue = conn.deleteDn(dn)
		}
	}

	return requeue
}

func (conn *ApicConnection) processQueue(queue workqueue.RateLimitingInterface,
	queueStop <-chan struct{}) {

	go wait.Until(func() {
		for {
			dn, quit := queue.Get()
			if quit {
				break
			}
			var requeue bool
			switch dn := dn.(type) {
			case string:
				requeue = conn.handleQueuedDn(dn)
			}
			if requeue {
				queue.AddRateLimited(dn)
			} else {
				conn.indexMutex.Lock()
				if conn.pendingSubDnUpdate[dn.(string)].isDirty {
					delete(conn.pendingSubDnUpdate, dn.(string))
				}
				conn.indexMutex.Unlock()
				queue.Forget(dn)
			}
			queue.Done(dn)
		}
	}, time.Second, queueStop)
	<-queueStop
	queue.ShutDown()
}

type fullSync struct{}

func (conn *ApicConnection) runConn(stopCh <-chan struct{}) {
	done := make(chan struct{})
	restart := make(chan struct{})
	queueStop := make(chan struct{})
	syncHook := make(chan fullSync, 1)
	conn.restartCh = restart

	go func() {
		defer conn.connection.Close()
		defer close(done)

		for {
			var apicresp ApicResponse
			err := conn.connection.ReadJSON(&apicresp)
			if c, k := err.(*websocket.CloseError); k {
				conn.log.Info("Websocket connection closed: ", c.Code)
				conn.restart()
				break
			} else if err != nil {
				conn.log.Error("Could not read web socket message:", err)
				conn.restart()
				break
			} else {
				conn.handleSocketUpdate(&apicresp)
			}
		}
	}()

	conn.indexMutex.Lock()
	oldState := conn.cacheDnSubIds
	conn.cachedState = make(map[string]ApicSlice)
	conn.cacheDnSubIds = make(map[string]map[string]bool)
	conn.deltaQueue = workqueue.NewNamedRateLimitingQueue(
		workqueue.NewMaxOfRateLimiter(
			workqueue.NewItemExponentialFailureRateLimiter(5*time.Millisecond,
				10*time.Second),
			&workqueue.BucketRateLimiter{
				Limiter: rate.NewLimiter(rate.Limit(10), int(100)),
			},
		),
		"delta")
	go conn.processQueue(conn.deltaQueue, queueStop)
	conn.indexMutex.Unlock()

	var hasErr bool
	for value, subscription := range conn.subscriptions.subs {
		if !(conn.subscribe(value, subscription)) {
			hasErr = true
			conn.restart()
			break
		}
	}
	if !hasErr {
		conn.checkDeletes(oldState)
		go func() {
			if conn.FullSyncHook != nil {
				conn.FullSyncHook()
			}
			syncHook <- fullSync{}
		}()
	}

	// Get APIC version if connection restarts
	// Unsupported scenario: Exit if APIC downgrades from >=3.2 to <=3.1
	if conn.version == 0 && conn.checkVersion {
		go func() {
			version, err := conn.GetVersion()
			if err != nil {
				conn.log.Error("Error while getting APIC version: ", err)
			} else {
				conn.log.Debug("Cached version:", conn.CachedVersion, " New version:", version)
				ApicVersion = version
				if version <= 3.1 && conn.CachedVersion >= 3.2 {
					conn.log.Debug("APIC is downgraded from >=3.2 to a lower version, Exiting ")
					os.Exit(1) //K8S shall restart the container and fallback to tagInst
				}
			}
		}()
	}

	refreshInterval := conn.RefreshInterval
	if refreshInterval == 0 {
		refreshInterval = defaultConnectionRefresh
	}
	// Adjust refreshTickerInterval.
	// To refresh the subscriptions early than actual refresh timeout value
	refreshTickerInterval := refreshInterval - conn.RefreshTickerAdjust
	refreshTicker := time.NewTicker(refreshTickerInterval)
	defer refreshTicker.Stop()

	closeConn := func(stop bool) {
		close(queueStop)

		conn.indexMutex.Lock()
		conn.deltaQueue = nil
		conn.stopped = stop
		conn.syncEnabled = false
		conn.subscriptions.ids = make(map[string]string)
		conn.version = 0
		conn.indexMutex.Unlock()

		conn.log.Debug("Shutting down web socket")
		err := conn.connection.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
		if err != nil {
			conn.log.Error("Error while closing socket: ", err)
		} else {
			select {
			case <-done:
			case <-time.After(time.Second):
			}
		}
		conn.connection.Close()
	}

loop:
	for {
		select {
		case <-syncHook:
			conn.fullSync()
		case <-refreshTicker.C:
			conn.refresh()
		case <-restart:
			closeConn(false)
			break loop
		case <-stopCh:
			closeConn(true)
			break loop
		}
	}

	conn.log.Debug("Exiting websocket handler")
}

func (conn *ApicConnection) GetVersion() (float64, error) {
	versionMo := "firmwareCtrlrRunning"

	if len(conn.apic) == 0 {
		return 0, errors.New("No APIC configuration")
	}

	conn.checkVersion = true // enable version check on websocket reconnect
	// To Handle unit-tests
	if strings.Contains(conn.apic[conn.apicIndex], "127.0.0.1") {
		conn.version = 3.2
		conn.log.Debug("Returning APIC version 3.2 for test server")
		return conn.version, nil
	}

	uri := fmt.Sprintf("/api/node/class/%s.json?&", versionMo)
	url := fmt.Sprintf("https://%s%s", conn.apic[conn.apicIndex], uri)

	conn.logger.WithFields(logrus.Fields{
		"mod":  "APICAPI",
		"host": conn.apic[conn.apicIndex],
	}).Info("Connecting to APIC to determine the Version")

	for conn.version == 0 {
		// Wait before Retry.
		time.Sleep(conn.ReconnectInterval)

		token, err := conn.login()
		if err != nil {
			conn.log.Error("Failed to log into APIC: ", err)
			continue
		}
		conn.token = token

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			conn.log.Error("Could not create request:", err)
			continue
		}
		conn.sign(req, uri, nil)
		resp, err := conn.client.Do(req)
		if err != nil {
			conn.log.Error("Could not get response for ", versionMo, ": ", err)
			continue
		}
		defer complete(resp)
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			conn.logErrorResp("Could not get response for "+versionMo, resp)
			conn.log.Debug("Request:", req)
			continue
		}

		var apicresp ApicResponse
		err = json.NewDecoder(resp.Body).Decode(&apicresp)
		if err != nil {
			conn.log.Error("Could not parse APIC response: ", err)
			continue
		}
		for _, obj := range apicresp.Imdata {
			vresp, ok := obj["firmwareCtrlrRunning"]
			version, ok := vresp.Attributes["version"]
			if !ok {
				conn.log.Debug("No version attribute in the response??!")
				conn.logger.WithFields(logrus.Fields{
					"mod":                            "APICAPI",
					"firmwareCtrlrRunning":           vresp,
					"firmwareCtrlRunning Attributes": vresp.Attributes,
				}).Debug("Response:")
			} else {
				switch version := version.(type) {
				default:
				case string:
					version_split := strings.Split(version, "(")
					version_number, err := strconv.ParseFloat(version_split[0], 64)
					conn.log.Debug("Actual APIC version:", version, " Stripped out version:", version_number)
					if err == nil {
						conn.version = version_number
					}
				}
			}
		}
	}
	return conn.version, nil
}

func (conn *ApicConnection) Run(stopCh <-chan struct{}) {
	if len(conn.apic) == 0 {
		conn.log.Warning("APIC connection not configured")
		return
	}

	for !conn.stopped {
		func() {
			defer func() {
				conn.apicIndex = (conn.apicIndex + 1) % len(conn.apic)
				time.Sleep(conn.ReconnectInterval)

			}()

			conn.logger.WithFields(logrus.Fields{
				"mod":  "APICAPI",
				"host": conn.apic[conn.apicIndex],
			}).Info("Connecting to APIC")

			conn.subscriptions.ids = make(map[string]string)

			token, err := conn.login()
			if err != nil {
				conn.log.Error("Failed to log into APIC: ", err)
				return
			}
			conn.token = token

			uri := fmt.Sprintf("/socket%s", token)
			url := fmt.Sprintf("wss://%s%s",
				conn.apic[conn.apicIndex], uri)
			header := make(http.Header)
			if conn.signer != nil {
				sig, err := conn.signer.sign("GET", uri, nil)
				if err != nil {
					conn.log.Error("Failed to sign request: ", err)
					return
				}
				header.Set("Cookie", conn.apicSigCookie(sig, token))
			}

			conn.connection, _, err = conn.dialer.Dial(url, header)
			if err != nil {
				conn.log.Error("Failed to open APIC websocket: ", err)
				return
			} else {
				conn.log.Info("Websocket connected!")
			}

			conn.runConn(stopCh)
		}()
	}
}

func (conn *ApicConnection) refresh() {
	if conn.signer == nil {
		url := fmt.Sprintf("https://%s/api/aaaRefresh.json",
			conn.apic[conn.apicIndex])
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			conn.log.Error("Could not create request: ", err)
			return
		}
		resp, err := conn.client.Do(req)
		if err != nil {
			conn.log.Error("Failed to refresh APIC session: ", err)
			conn.restart()
			return
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			conn.logErrorResp("Error while refreshing login", resp)
			complete(resp)
			conn.restart()
			return
		}
		complete(resp)
		conn.log.Debugf("Refresh: url %v", url)
	}

	for _, sub := range conn.subscriptions.subs {
		uri := fmt.Sprintf("/api/subscriptionRefresh.json?id=%s", sub.id)
		url := fmt.Sprintf("https://%s%s", conn.apic[conn.apicIndex], uri)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			conn.log.Error("Could not create request: ", err)
			return
		}
		conn.sign(req, uri, nil)
		resp, err := conn.client.Do(req)
		if err != nil {
			conn.log.Error("Failed to refresh APIC subscription: ", err)
			conn.restart()
			return
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			conn.logErrorResp("Error while refreshing subscription", resp)
			complete(resp)
			conn.restart()
			return
		}
		complete(resp)
		conn.log.Debugf("Refresh sub: url %v", url)
	}
}

func (conn *ApicConnection) logErrorResp(message string, resp *http.Response) {
	var apicresp ApicResponse
	err := json.NewDecoder(resp.Body).Decode(&apicresp)
	if err != nil {
		conn.log.Error("Could not parse APIC error response: ", err)
	} else {
		code := 0
		text := ""
		for _, o := range apicresp.Imdata {
			if ob, ok := o["error"]; ok {
				if ob.Attributes != nil {
					switch t := ob.Attributes["text"].(type) {
					case string:
						text = t
					}
					switch c := ob.Attributes["code"].(type) {
					case int:
						code = c
					}
				}
			}
		}
		conn.logger.WithFields(logrus.Fields{
			"mod":    "APICAPI",
			"text":   text,
			"code":   code,
			"url":    resp.Request.URL,
			"status": resp.StatusCode,
		}).Error(message)
	}
}

// To make sure cluster's POD/NodeBDs and L3OUT are all mapped
// to same and correct VRF.
func (conn *ApicConnection) ValidateAciVrfAssociation(acivrfdn string, expectedVrfRelations []string) error {
	var aciVrfBdL3OuttDns []string
	args := []string{
		"query-target=subtree",
		"target-subtree-class=fvRtCtx,fvRtEctx",
	}

	uri := fmt.Sprintf("/api/mo/%s.json?%s", acivrfdn, strings.Join(args, "&"))
	url := fmt.Sprintf("https://%s%s", conn.apic[conn.apicIndex], uri)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		conn.log.Error("Could not create request: ", err)
		return err
	}
	conn.sign(req, uri, nil)
	resp, err := conn.client.Do(req)
	if err != nil {
		conn.log.Error("Could not get subtree for ", acivrfdn, ": ", err)
		return err
	}
	defer complete(resp)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		conn.logErrorResp("Could not get subtree for "+acivrfdn, resp)
		return err
	}

	var apicresp ApicResponse
	err = json.NewDecoder(resp.Body).Decode(&apicresp)
	if err != nil {
		conn.log.Error("Could not parse APIC response: ", err)
		return err
	}

	for _, obj := range apicresp.Imdata {
		for _, body := range obj {
			tDn, ok := body.Attributes["tDn"].(string)
			if !ok {
				continue
			}
			aciVrfBdL3OuttDns = append(aciVrfBdL3OuttDns, tDn)
		}
	}
	sort.Strings(aciVrfBdL3OuttDns)
	conn.log.Debug("aciVrfBdL3OuttDns:", aciVrfBdL3OuttDns)
	for _, expectedDn := range expectedVrfRelations {
		i := sort.SearchStrings(aciVrfBdL3OuttDns, expectedDn)
		if !(i < len(aciVrfBdL3OuttDns) && aciVrfBdL3OuttDns[i] == expectedDn) {
			conn.log.Debug("Missing (or) Incorrect Vrf association: ", expectedDn)
			return errors.New("Incorrect Pod/NodeBD/L3OUT VRF association")
		}
	}
	return nil
}

func (conn *ApicConnection) getSubtreeDn(dn string, respClasses []string,
	updateHandlers []ApicObjectHandler) {

	args := []string{
		"rsp-subtree=full",
	}

	if len(respClasses) > 0 {
		args = append(args, "rsp-subtree-class="+strings.Join(respClasses, ","))
	}
	// properly encoding the URI query parameters breaks APIC
	uri := fmt.Sprintf("/api/mo/%s.json?%s", dn, strings.Join(args, "&"))
	url := fmt.Sprintf("https://%s%s", conn.apic[conn.apicIndex], uri)
	conn.log.Debugf("URL: %v", url)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		conn.log.Error("Could not create request: ", err)
		return
	}
	conn.sign(req, uri, nil)
	resp, err := conn.client.Do(req)
	if err != nil {
		conn.log.Error("Could not get subtree for ", dn, ": ", err)
		conn.restart()
		return
	}
	defer complete(resp)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		conn.logErrorResp("Could not get subtree for "+dn, resp)
		conn.restart()
		return
	}

	var apicresp ApicResponse
	err = json.NewDecoder(resp.Body).Decode(&apicresp)
	if err != nil {
		conn.log.Error("Could not parse APIC response: ", err)
		return
	}
	if len(apicresp.Imdata) == 0 {
		conn.log.Debugf("No subtree found for dn %s", dn)
	}

	for _, obj := range apicresp.Imdata {
		conn.logger.WithFields(logrus.Fields{
			"mod": "APICAPI",
			"dn":  obj.GetDn(),
			"obj": obj,
		}).Debug("Object updated on APIC")

		prepareApicCache("", obj)

		handled := false
		for _, handler := range updateHandlers {
			if handler(obj) {
				handled = true
				break
			}
		}
		if handled {
			continue
		}
		conn.reconcileApicObject(obj)
	}
}

func (conn *ApicConnection) queueDn(dn string) {
	conn.indexMutex.Lock()
	if conn.deltaQueue != nil {
		conn.deltaQueue.Add(dn)
	}
	conn.indexMutex.Unlock()
}

func (conn *ApicConnection) ForceRelogin() {
	conn.token = ""
}

func (conn *ApicConnection) PostTestAPI(data interface{}) error {
	if conn.token == "" {
		token, err := conn.login()
		if err != nil {
			conn.log.Errorf("Login: %v", err)
			return err
		}
		conn.token = token
	}
	uri := "/testapi/cloudpe/mo/.json"
	url := fmt.Sprintf("https://%s%s", conn.apic[conn.apicIndex], uri)
	raw, err := json.Marshal(data)
	if err != nil {
		conn.log.Errorf("Could not serialize object for testapi %v", err)
		return err
	}
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(raw))
	if err != nil {
		conn.log.Error("Could not create request: ", err)
		return err
	}
	conn.sign(req, uri, raw)
	req.Header.Set("Content-Type", "application/json")
	conn.log.Infof("Post: %+v", req)
	resp, err := conn.client.Do(req)
	if err != nil {
		conn.log.Errorf("Could not update dn %v", err)
		return err
	}

	complete(resp)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Staus: %v", resp.StatusCode)
	}
	return nil
}

func (conn *ApicConnection) PostDnInline(dn string, obj ApicObject) error {
	if conn.token == "" {
		token, err := conn.login()
		if err != nil {
			conn.log.Errorf("Login: %v", err)
			return err
		}
		conn.token = token
	}
	uri := fmt.Sprintf("/api/mo/%s.json", dn)
	url := fmt.Sprintf("https://%s%s", conn.apic[conn.apicIndex], uri)
	raw, err := json.Marshal(obj)
	if err != nil {
		conn.log.Error("Could not serialize object for dn ", dn, ": ", err)
		return err
	}
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(raw))
	if err != nil {
		conn.log.Error("Could not create request: ", err)
		return err
	}
	conn.sign(req, uri, raw)
	req.Header.Set("Content-Type", "application/json")
	conn.log.Infof("Post: %+v", req)
	resp, err := conn.client.Do(req)
	if err != nil {
		conn.log.Error("Could not update dn ", dn, ": ", err)
		return err
	}

	complete(resp)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Staus: %v", resp.StatusCode)
	}
	return nil
}

func (conn *ApicConnection) DeleteDnInline(dn string) error {
	uri := fmt.Sprintf("/api/mo/%s.json", dn)
	url := fmt.Sprintf("https://%s%s", conn.apic[conn.apicIndex], uri)
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		conn.log.Error("Could not create delete request: ", err)
		return err
	}
	conn.sign(req, uri, nil)
	resp, err := conn.client.Do(req)
	if err != nil {
		conn.log.Error("Could not delete dn ", dn, ": ", err)
		return err
	}
	defer complete(resp)
	return nil
}

func (conn *ApicConnection) postDn(dn string, obj ApicObject) bool {
	conn.logger.WithFields(logrus.Fields{
		"mod": "APICAPI",
		"dn":  dn,
		//"obj": obj,
	}).Debug("Posting update")

	uri := fmt.Sprintf("/api/mo/%s.json", dn)
	url := fmt.Sprintf("https://%s%s", conn.apic[conn.apicIndex], uri)
	raw, err := json.Marshal(obj)
	if err != nil {
		conn.log.Error("Could not serialize object for dn ", dn, ": ", err)
	}
	//conn.log.Debug(string(raw))
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(raw))
	if err != nil {
		conn.log.Error("Could not create request: ", err)
		conn.restart()
		return false
	}
	conn.sign(req, uri, raw)
	req.Header.Set("Content-Type", "application/json")
	resp, err := conn.client.Do(req)
	if err != nil {
		conn.log.Error("Could not update dn ", dn, ": ", err)
		conn.restart()
		return false
	}
	defer complete(resp)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		conn.logErrorResp("Could not update dn "+dn, resp)
		if resp.StatusCode == 400 {
			return true
		} else {
			conn.restart()
		}
	}
	return false
}

func (conn *ApicConnection) deleteDn(dn string) bool {
	conn.log.Debug("Deleting ", dn)
	uri := fmt.Sprintf("/api/mo/%s.json", dn)
	url := fmt.Sprintf("https://%s%s", conn.apic[conn.apicIndex], uri)
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		conn.log.Error("Could not create delete request: ", err)
		conn.restart()
		return false
	}
	conn.sign(req, uri, nil)
	resp, err := conn.client.Do(req)
	if err != nil {
		conn.log.Error("Could not delete dn ", dn, ": ", err)
		conn.restart()
		return false
	}
	defer complete(resp)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		conn.logErrorResp("Could not delete dn "+dn, resp)
		conn.restart()
	}
	return false
}

func doComputeRespClasses(targetClasses []string,
	visited map[string]bool) {

	for _, class := range targetClasses {
		if visited[class] {
			continue
		}
		visited[class] = true
		if md, ok := metadata[class]; ok {
			doComputeRespClasses(md.children, visited)
		}
	}

}

func computeRespClasses(targetClasses []string,
	useAPICInstTag bool) []string {

	visited := make(map[string]bool)
	doComputeRespClasses(targetClasses, visited)

	var respClasses []string
	for class := range visited {
		respClasses = append(respClasses, class)
	}
	respClasses = append(respClasses, "tagInst")
	if !useAPICInstTag {
		respClasses = append(respClasses, "tagAnnotation")
	}
	return respClasses
}

// AddSubscriptionTree subscribe at a subtree level. class specifies
// the root. Changes will cause entire subtree of the rootdn to be fetched
func (conn *ApicConnection) AddSubscriptionTree(class string,
	targetClasses []string, targetFilter string) {

	if _, ok := classDepth[class]; !ok {
		errStr := fmt.Sprintf("classDepth not for class %s", class)
		panic(errStr)
	}

	conn.indexMutex.Lock()
	conn.subscriptions.subs[class] = &subscription{
		kind:          apicSubTree,
		targetClasses: targetClasses,
		targetFilter:  targetFilter,
	}
	conn.indexMutex.Unlock()
}

func (conn *ApicConnection) AddSubscriptionClass(class string,
	targetClasses []string, targetFilter string) {

	conn.indexMutex.Lock()
	conn.subscriptions.subs[class] = &subscription{
		kind:          apicSubClass,
		targetClasses: targetClasses,
		respClasses:   computeRespClasses(targetClasses, conn.UseAPICInstTag),
		targetFilter:  targetFilter,
	}
	conn.indexMutex.Unlock()
}

func (conn *ApicConnection) AddSubscriptionDn(dn string,
	targetClasses []string) {

	conn.indexMutex.Lock()
	conn.subscriptions.subs[dn] = &subscription{
		kind:          apicSubDn,
		targetClasses: targetClasses,
		respClasses:   computeRespClasses(targetClasses, conn.UseAPICInstTag),
	}
	conn.indexMutex.Unlock()
}

func (conn *ApicConnection) SetSubscriptionHooks(value string,
	updateHook ApicObjectHandler, deleteHook ApicDnHandler) {

	conn.indexMutex.Lock()
	if s, ok := conn.subscriptions.subs[value]; ok {
		s.updateHook = updateHook
		s.deleteHook = deleteHook
	}
	conn.indexMutex.Unlock()
}

func (conn *ApicConnection) GetApicResponse(uri string) (ApicResponse, error) {
	conn.log.Debug("apicIndex: ", conn.apic[conn.apicIndex], " uri: ", uri)
	url := fmt.Sprintf("https://%s%s", conn.apic[conn.apicIndex], uri)
	var apicresp ApicResponse
	conn.log.Debug("Apic Get url: ", url)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		conn.log.Error("Could not create request: ", err)
		return apicresp, err
	}
	conn.sign(req, uri, nil)
	resp, err := conn.client.Do(req)
	if err != nil {
		conn.log.Error("Could not get response for ", url, ": ", err)
		return apicresp, err
	}
	defer complete(resp)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		conn.logErrorResp("Could not get subtree for "+url, resp)
		return apicresp, err
	}
	err = json.NewDecoder(resp.Body).Decode(&apicresp)
	if err != nil {
		conn.log.Error("Could not parse APIC response: ", err)
		return apicresp, err
	}
	return apicresp, nil
}

func (conn *ApicConnection) subscribe(value string, sub *subscription) bool {
	args := []string{
		"query-target=subtree",
		"rsp-subtree=full",
		"target-subtree-class=" + strings.Join(sub.targetClasses, ","),
	}
	if sub.respClasses != nil {
		args = append(args, "rsp-subtree-class="+strings.Join(sub.respClasses, ","))
	}
	if sub.targetFilter != "" {
		args = append(args, "query-target-filter="+sub.targetFilter)
	}

	kind := "mo"
	if sub.kind == apicSubClass || sub.kind == apicSubTree {
		kind = "class"
	}

	refresh_interval := ""
	if conn.RefreshInterval != 0 {
		refresh_interval = fmt.Sprintf("refresh-timeout=%v&",
			conn.RefreshInterval.Seconds())
	}

	// properly encoding the URI query parameters breaks APIC
	uri := fmt.Sprintf("/api/%s/%s.json?subscription=yes&%s%s",
		kind, value, refresh_interval, strings.Join(args, "&"))
	url := fmt.Sprintf("https://%s%s", conn.apic[conn.apicIndex], uri)
	conn.log.Info("APIC connection URL: ", url)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		conn.log.Error("Could not create request: ", err)
		return false
	}
	conn.sign(req, uri, nil)
	resp, err := conn.client.Do(req)
	if err != nil {
		conn.log.Error("Failed to subscribe to ", value, ": ", err)
		return false
	}
	defer complete(resp)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		conn.logErrorResp("Could not subscribe to "+value, resp)
		return false
	}

	var apicresp ApicResponse
	err = json.NewDecoder(resp.Body).Decode(&apicresp)
	if err != nil {
		conn.log.Error("Could not decode APIC response", err)
		return false
	}

	var subId string
	switch id := apicresp.SubscriptionId.(type) {
	default:
		conn.log.Error("Subscription ID is not a string")
		return false
	case string:
		subId = id
	}

	conn.logger.WithFields(logrus.Fields{
		"mod":   "APICAPI",
		"value": value,
		"kind":  kind,
		"id":    subId,
		"args":  args,
	}).Debug("Subscribed")

	conn.indexMutex.Lock()
	conn.subscriptions.subs[value].id = subId
	conn.subscriptions.ids[subId] = value
	conn.indexMutex.Unlock()

	for _, obj := range apicresp.Imdata {

		dn := obj.GetDn()
		if dn == "" {
			continue
		}
		conn.indexMutex.Lock()
		subIds, found := conn.cacheDnSubIds[dn]
		if !found {
			subIds = make(map[string]bool)
			conn.cacheDnSubIds[dn] = subIds
		}
		subIds[subId] = true
		conn.indexMutex.Unlock()

		if sub.updateHook != nil && sub.updateHook(obj) {
			continue
		}

		tag := obj.GetTag()
		if !conn.isSyncTag(tag) {
			continue
		}

		conn.logger.WithFields(logrus.Fields{
			"mod": "APICAPI",
			"dn":  dn,
			"tag": tag,
			//"obj": obj,
		}).Debug("Caching")

		prepareApicCache("", obj)
		conn.indexMutex.Lock()
		conn.cachedState[tag] = append(conn.cachedState[tag], obj)
		conn.indexMutex.Unlock()
	}

	return true
}

var tagRegexp = regexp.MustCompile(`[a-zA-Z0-9_]{1,31}-[a-f0-9]{32}`)

func (conn *ApicConnection) isSyncTag(tag string) bool {
	return tagRegexp.MatchString(tag) &&
		strings.HasPrefix(tag, conn.prefix+"-")
}

func getRootDn(dn, rootClass string) string {
	depth := classDepth[rootClass]
	parts := strings.Split(dn, "/")
	parts = parts[:depth]
	return strings.Join(parts, "/")
}
