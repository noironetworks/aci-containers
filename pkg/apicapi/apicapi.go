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
	"net/http"
	"net/http/cookiejar"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/workqueue"

	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
)

// defaultConnectionRefresh is used as connection refresh interval if
// RefreshInterval is set to 0
const defaultConnectionRefresh = 30 * time.Second

// ApicVersion - This global variable to be used when dealing with version-
// dependencies during APIC interaction. It gets filled with actual version
// as part of runConn()
var (
	ApicVersion = "3.1"
)

func complete(resp *http.Response) {
	if resp.StatusCode != http.StatusOK {
		rBody, err := io.ReadAll(resp.Body)
		if err != nil {
			logrus.Errorf("ReadAll :%v", err)
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

func (conn *ApicConnection) apicSigCookie(sig, token string) string {
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
	url := fmt.Sprintf("https://%s%s", conn.Apic[conn.ApicIndex], uri)

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
		stoken, isStr := token.(string)
		if !isStr {
			return "", errors.New("Token is not a string")
		}
		return stoken, nil
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
	prefix string, refresh int, refreshTickerAdjust int,
	subscriptionDelay int, vrfTenant string) (*ApicConnection, error) {
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
		ReconnectRetryLimit: 5,
		RefreshInterval:     time.Duration(refresh) * time.Second,
		RefreshTickerAdjust: time.Duration(refreshTickerAdjust) * time.Second,
		SubscriptionDelay:   time.Duration(subscriptionDelay) * time.Millisecond,
		SyncDone:            false,
		signer:              signer,
		dialer:              dialer,
		logger:              log,
		log:                 log.WithField("mod", "APICAPI"),
		Apic:                apic,
		user:                user,
		password:            password,
		prefix:              prefix,
		client:              client,
		vrfTenant:           vrfTenant,
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

	nameAttrClass := map[string]bool{"vnsLDevVip": true, "vnsAbsGraph": true, "vzFilter": true, "vzBrCP": true, "l3extInstP": true, "vnsSvcRedirectPol": true, "vnsRedirectHealthGroup": true, "fvIPSLAMonitoringPol": true}

	for _, obj := range apicresp.Imdata {
		for key, body := range obj {
			if dn, ok := body.Attributes["dn"].(string); ok {
				if status, isStr := body.Attributes["status"].(string); isStr {
					dnSlice := strings.Split(dn, "/")
					if len(dnSlice) > 1 && strings.Contains(dnSlice[1], conn.vrfTenant) {
						var attr string
						if nameAttrClass[key] {
							_, ok := body.Attributes["name"]
							if ok {
								attr = body.Attributes["name"].(string)
							}
						} else if key == "tagAnnotation" {
							_, ok := body.Attributes["value"]
							if ok {
								attr = body.Attributes["value"].(string)
							}
						}
						if attr != "" && !strings.Contains(attr, conn.prefix) {
							conn.log.Debug("Skipping websocket notification for :", dn)
							continue
						}
					}
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
					if key == "opflexODev" && conn.odevQueue != nil {
						conn.log.Debug("Adding dn to odevQueue: ", dn)
						conn.odevQueue.Add(dn)
					} else if isPriorityObject(dn) {
						conn.log.Debug("Adding dn to priorityQueue: ", dn)
						conn.priorityQueue.Add(dn)
					} else {
						if conn.deltaQueue != nil {
							conn.deltaQueue.Add(dn)
						}
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
				if subComp, ok := sub.childSubs[id]; ok {
					respClasses =
						append(respClasses, subComp.respClasses...)
				} else {
					respClasses =
						append(respClasses, sub.respClasses...)
				}
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
			requeue = conn.Delete(dn)
		}
	}

	return requeue
}

func (conn *ApicConnection) processQueue(queue workqueue.RateLimitingInterface,
	queueStop <-chan struct{}, name string) {
	go wait.Until(func() {
		conn.log.Debug("Running processQueue for queue ", name)
		for {
			dn, quit := queue.Get()
			if quit {
				break
			}
			conn.log.Debug("Processing queue for:", dn)
			var requeue bool
			if dn, ok := dn.(string); ok {
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
	odevQueueStop := make(chan struct{})
	priorityQueueStop := make(chan struct{})
	syncHook := make(chan fullSync, 1)
	conn.restartCh = restart

	go func() {
		defer conn.connection.Close()
		defer close(done)

		for {
			var apicresp ApicResponse
			err := conn.connection.ReadJSON(&apicresp)
			var closeErr *websocket.CloseError
			if errors.As(err, &closeErr) {
				conn.log.Info("Websocket connection closed: ", closeErr.Code)
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
	go conn.processQueue(conn.deltaQueue, queueStop, "delta")
	conn.odevQueue = workqueue.NewNamedRateLimitingQueue(
		workqueue.NewMaxOfRateLimiter(
			workqueue.NewItemExponentialFailureRateLimiter(5*time.Millisecond,
				10*time.Second),
			&workqueue.BucketRateLimiter{
				Limiter: rate.NewLimiter(rate.Limit(10), int(100)),
			},
		),
		"odev")
	go conn.processQueue(conn.odevQueue, odevQueueStop, "odev")
	conn.priorityQueue = workqueue.NewNamedRateLimitingQueue(
		workqueue.NewMaxOfRateLimiter(
			workqueue.NewItemExponentialFailureRateLimiter(5*time.Millisecond,
				10*time.Second),
			&workqueue.BucketRateLimiter{
				Limiter: rate.NewLimiter(rate.Limit(10), int(100)),
			},
		),
		"priority")
	go conn.processQueue(conn.priorityQueue, priorityQueueStop, "priority")
	conn.indexMutex.Unlock()

	refreshInterval := conn.RefreshInterval
	if refreshInterval == 0 {
		refreshInterval = defaultConnectionRefresh
	}
	// Adjust refreshTickerInterval.
	// To refresh the subscriptions early than actual refresh timeout value
	refreshTickerInterval := refreshInterval - conn.RefreshTickerAdjust
	refreshTicker := time.NewTicker(refreshTickerInterval)
	defer refreshTicker.Stop()

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
	if conn.version == "" && conn.checkVersion {
		go func() {
			version, err := conn.GetVersion()
			if err != nil {
				conn.log.Error("Error while getting APIC version: ", err, " Restarting connection...")
				conn.restart()
			} else {
				conn.log.Debug("Cached version:", conn.CachedVersion, " New version:", version)
				if ApicVersion != version {
					ApicVersion = version
					if ApicVersion >= "6.0(4c)" {
						metadata["fvBD"].attributes["serviceBdRoutingDisable"] = "no"
					} else {
						delete(metadata["fvBD"].attributes, "serviceBdRoutingDisable")
					}
					conn.VersionUpdateHook()
				}
				conn.CachedVersion = version
			}
		}()
	}

	closeConn := func(stop bool) {
		close(queueStop)
		close(odevQueueStop)

		conn.indexMutex.Lock()
		conn.deltaQueue = nil
		conn.odevQueue = nil
		conn.priorityQueue = nil
		conn.stopped = stop
		conn.syncEnabled = false
		conn.subscriptions.ids = make(map[string]string)
		conn.version = ""
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

// This function should only to be called before we make the first connection to APIC.
// Use the cached Apic version when determining the version elsewhere. This can lead to inconsistent tokens.
func (conn *ApicConnection) GetVersion() (string, error) {
	versionMo := "firmwareCtrlrRunning"

	if len(conn.Apic) == 0 {
		return "", errors.New("No APIC configuration")
	}

	conn.checkVersion = true // enable version check on websocket reconnect
	// To Handle unit-tests
	if strings.Contains(conn.Apic[conn.ApicIndex], "127.0.0.1") {
		conn.version = "4.2(4i)"
		conn.SnatPbrFltrChain = true
		conn.log.Debug("Returning APIC version 4.2(4i) for test server")
		return conn.version, nil
	}

	uri := fmt.Sprintf("/api/node/class/%s.json?&", versionMo)
	url := fmt.Sprintf("https://%s%s", conn.Apic[conn.ApicIndex], uri)

	retries := 0
	for conn.version == "" {
		if retries <= conn.ReconnectRetryLimit {
			// Wait before Retry.
			time.Sleep(conn.ReconnectInterval)
			retries++
		} else {
			return "", fmt.Errorf("Failed to get APIC version after %d retries", retries)
		}

		token, err := conn.login()
		if err != nil {
			conn.log.Error("Failed to log into APIC: ", err)
			continue
		}
		conn.token = token

		req, err := http.NewRequest("GET", url, http.NoBody)
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
			vresp := obj["firmwareCtrlrRunning"]
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
					conn.log.Info("Actual APIC version:", version, " Stripped out version:", version_number)
					if err == nil {
						conn.version = version //return the actual version
					}
				}
			}
		}
	}
	return conn.version, nil
}

func (conn *ApicConnection) Run(stopCh <-chan struct{}) {
	if len(conn.Apic) == 0 {
		conn.log.Warning("APIC connection not configured")
		return
	}

	if conn.version >= "6.0(4c)" {
		metadata["fvBD"].attributes["serviceBdRoutingDisable"] = "no"
	}

	for !conn.stopped {
		func() {
			defer func() {
				conn.ApicIndex = (conn.ApicIndex + 1) % len(conn.Apic)
				time.Sleep(conn.ReconnectInterval)
			}()

			conn.logger.WithFields(logrus.Fields{
				"mod":  "APICAPI",
				"host": conn.Apic[conn.ApicIndex],
			}).Info("Connecting to APIC")

			for dn := range conn.subscriptions.subs {
				conn.subscriptions.subs[dn].childSubs = make(map[string]subComponent)
			}
			conn.subscriptions.ids = make(map[string]string)

			token, err := conn.login()
			if err != nil {
				conn.log.Error("Failed to log into APIC: ", err)
				return
			}
			conn.token = token

			uri := fmt.Sprintf("/socket%s", token)
			url := fmt.Sprintf("wss://%s%s",
				conn.Apic[conn.ApicIndex], uri)
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
			}
			conn.log.Info("Websocket connected!")
			conn.runConn(stopCh)
		}()
	}
}

func (conn *ApicConnection) refresh() {
	if conn.signer == nil {
		url := fmt.Sprintf("https://%s/api/aaaRefresh.json",
			conn.Apic[conn.ApicIndex])
		req, err := http.NewRequest("GET", url, http.NoBody)
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
		refreshId := func(id string) {
			uri := fmt.Sprintf("/api/subscriptionRefresh.json?id=%s", id)
			url := fmt.Sprintf("https://%s%s", conn.Apic[conn.ApicIndex], uri)
			req, err := http.NewRequest("GET", url, http.NoBody)
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
			time.Sleep(conn.SubscriptionDelay)
		}
		if len(sub.childSubs) > 0 {
			for id := range sub.childSubs {
				refreshId(id)
			}
		} else {
			refreshId(sub.id)
		}
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
					if t, isStr := ob.Attributes["text"].(string); isStr {
						text = t
					}
					if c, isInt := ob.Attributes["code"].(int); isInt {
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
	url := fmt.Sprintf("https://%s%s", conn.Apic[conn.ApicIndex], uri)
	req, err := http.NewRequest("GET", url, http.NoBody)
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
	url := fmt.Sprintf("https://%s%s", conn.Apic[conn.ApicIndex], uri)
	conn.log.Debugf("URL: %v", url)
	req, err := http.NewRequest("GET", url, http.NoBody)
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
		var count int
		prepareApicCache("", obj, &count)

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

func (conn *ApicConnection) queuePriorityDn(dn string) {
	conn.indexMutex.Lock()
	if conn.priorityQueue != nil {
		conn.priorityQueue.Add(dn)
	}
	conn.indexMutex.Unlock()
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
	url := fmt.Sprintf("https://%s%s", conn.Apic[conn.ApicIndex], uri)
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
		return fmt.Errorf("Status: %v", resp.StatusCode)
	}
	return nil
}

func (conn *ApicConnection) PostDnInline(dn string, obj ApicObject) error {
	conn.logger.WithFields(logrus.Fields{
		"mod": "APICAPI",
		"dn":  dn,
		"obj": obj,
	}).Debug("Posting Dn Inline")
	if conn.token == "" {
		token, err := conn.login()
		if err != nil {
			conn.log.Errorf("Login: %v", err)
			return err
		}
		conn.token = token
	}
	uri := fmt.Sprintf("/api/mo/%s.json", dn)
	url := fmt.Sprintf("https://%s%s", conn.Apic[conn.ApicIndex], uri)
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
		return fmt.Errorf("Status: %v", resp.StatusCode)
	}
	return nil
}

func (conn *ApicConnection) DeleteDnInline(dn string) error {
	conn.logger.WithFields(logrus.Fields{
		"mod": "APICAPI",
		"dn":  dn,
	}).Debug("Deleting Dn Inline")
	uri := fmt.Sprintf("/api/mo/%s.json", dn)
	url := fmt.Sprintf("https://%s%s", conn.Apic[conn.ApicIndex], uri)
	req, err := http.NewRequest("DELETE", url, http.NoBody)
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
		"obj": obj,
	}).Debug("Posting Dn")

	uri := fmt.Sprintf("/api/mo/%s.json", dn)
	url := fmt.Sprintf("https://%s%s", conn.Apic[conn.ApicIndex], uri)
	raw, err := json.Marshal(obj)
	if err != nil {
		conn.log.Error("Could not serialize object for dn ", dn, ": ", err)
	}
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
		}
		conn.restart()
	}
	return false
}

func (conn *ApicConnection) Delete(dn string) bool {
	if dn == "" {
		conn.log.Debug("Skip delete for empty Dn: ")
		return false
	}
	dnSlice := strings.Split(dn, "/")
	identifier := dnSlice[len(dnSlice)-1]
	iSlice := strings.SplitN(identifier, "-", 2)
	if len(iSlice) == 2 {
		if iSlice[0] == "ip" {
			addr := strings.Trim(iSlice[1], "[]")
			obj := NewDeleteHostprotRemoteIp(addr)
			conn.log.Debug("Posting delete of dn ", dn)
			return conn.postDn(dn, obj)
		} else if iSlice[0] == "odev" {
			conn.log.Debug("Skipping delete of opflexODev : ", dn)
			return false
		}
	}
	return conn.DeleteDn(dn)
}

func (conn *ApicConnection) DeleteDn(dn string) bool {
	if dn == "" {
		conn.log.Debug("Skip delete for empty Dn: ")
		return false
	}
	conn.logger.WithFields(logrus.Fields{
		"mod": "APICAPI",
		"dn":  dn,
	}).Debug("Deleting Dn")
	uri := fmt.Sprintf("/api/mo/%s.json", dn)
	url := fmt.Sprintf("https://%s%s", conn.Apic[conn.ApicIndex], uri)
	req, err := http.NewRequest("DELETE", url, http.NoBody)
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

func computeRespClasses(targetClasses []string) []string {
	visited := make(map[string]bool)
	doComputeRespClasses(targetClasses, visited)

	// Don't include targetclasses in rsp-subtree
	// because they are implicitly included
	for i := range targetClasses {
		delete(visited, targetClasses[i])
	}

	var respClasses []string
	for class := range visited {
		respClasses = append(respClasses, class)
	}
	respClasses = append(respClasses, "tagAnnotation")
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
		childSubs:     make(map[string]subComponent),
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
		childSubs:     make(map[string]subComponent),
		targetClasses: targetClasses,
		respClasses:   computeRespClasses(targetClasses),
		targetFilter:  targetFilter,
	}
	conn.indexMutex.Unlock()
}

func (conn *ApicConnection) AddSubscriptionDn(dn string,
	targetClasses []string) {
	conn.logger.WithFields(logrus.Fields{
		"mod": "APICAPI",
		"dn":  dn,
	}).Debug("Adding Subscription for Dn")

	conn.indexMutex.Lock()
	conn.subscriptions.subs[dn] = &subscription{
		kind:          apicSubDn,
		childSubs:     make(map[string]subComponent),
		targetClasses: targetClasses,
		respClasses:   computeRespClasses(targetClasses),
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
	conn.log.Debug("apicIndex: ", conn.Apic[conn.ApicIndex], " uri: ", uri)
	url := fmt.Sprintf("https://%s%s", conn.Apic[conn.ApicIndex], uri)
	var apicresp ApicResponse
	conn.log.Debug("Apic Get url: ", url)
	req, err := http.NewRequest("GET", url, http.NoBody)
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

func (conn *ApicConnection) doSubscribe(args []string,
	kind, value, refresh_interval string, apicresp *ApicResponse) bool {
	// properly encoding the URI query parameters breaks APIC
	uri := fmt.Sprintf("/api/%s/%s.json?subscription=yes&%s%s",
		kind, value, refresh_interval, strings.Join(args, "&"))
	url := fmt.Sprintf("https://%s%s", conn.Apic[conn.ApicIndex], uri)
	conn.log.Info("APIC connection URL: ", url)

	req, err := http.NewRequest("GET", url, http.NoBody)
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

	err = json.NewDecoder(resp.Body).Decode(apicresp)
	if err != nil {
		conn.log.Error("Could not decode APIC response", err)
		return false
	}
	time.Sleep(conn.SubscriptionDelay)
	return true
}

func (conn *ApicConnection) subscribe(value string, sub *subscription) bool {
	baseArgs := []string{
		"query-target=subtree",
		"rsp-subtree=full",
		"target-subtree-class=" + strings.Join(sub.targetClasses, ","),
	}

	const defaultArgs = 1
	var argCount = defaultArgs
	var combinableSubClasses, separableSubClasses []string
	var splitTargetClasses [][]string
	var splitRespClasses [][]string
	var argSet [][]string
	argSet = make([][]string, defaultArgs)
	argSet[defaultArgs-1] = make([]string, len(baseArgs))
	copy(argSet[defaultArgs-1], baseArgs)
	if sub.respClasses != nil {
		separateClasses := func(classes []string, combClasses, sepClasses *[]string) {
			for i := range classes {
				if classMeta, ok := metadata[classes[i]]; ok {
					if classes[i] == "tagAnnotation" {
						continue
					}
					if classMeta.hints != nil && classMeta.hints["cardinality"] == "high" {
						*sepClasses = append(*sepClasses, classes[i])
						continue
					}
					*combClasses = append(*combClasses, classes[i])
				}
			}
		}
		separateClasses(sub.respClasses, &combinableSubClasses, &separableSubClasses)

		// In case there are high cardinality children, we register for all the classes individually.
		// The concept of target-subtree and rsp-subtree class cannot be used because of the tagAnnotation object
		// vmmInjectedLabel is added for every object, so getting it separately will not be scalable
		if len(separableSubClasses) > 0 {
			separateClasses(sub.targetClasses, &combinableSubClasses, &separableSubClasses)
			separableSubClasses = append(separableSubClasses, combinableSubClasses...)
			baseArgs = []string{
				"query-target=subtree",
				"rsp-subtree=children",
			}
			subscribingClasses := make(map[string]bool)
			argSet = make([][]string, len(separableSubClasses))
			splitTargetClasses = make([][]string, len(separableSubClasses))
			splitRespClasses = make([][]string, len(separableSubClasses))

			argCount = 0
			for i := range separableSubClasses {
				// Eliminate duplicates
				if _, ok := subscribingClasses[separableSubClasses[i]]; ok {
					continue
				}
				subscribingClasses[separableSubClasses[i]] = true
				argSet[argCount] = make([]string, len(baseArgs))
				copy(argSet[argCount], baseArgs)
				argSet[argCount] = append(argSet[argCount], "target-subtree-class="+separableSubClasses[i], "rsp-subtree-class=tagAnnotation")
				splitTargetClasses[argCount] = append(splitTargetClasses[argCount], separableSubClasses[i])
				splitRespClasses[argCount] = computeRespClasses([]string{separableSubClasses[i]})
				argCount++
			}
		} else {
			argSet[defaultArgs-1] = append(argSet[defaultArgs-1], "rsp-subtree-class="+strings.Join(combinableSubClasses, ",")+",tagAnnotation")
		}
	}
	if sub.targetFilter != "" {
		targetFilterArgs := "query-target-filter=" + sub.targetFilter
		if len(separableSubClasses) == 0 {
			argSet[defaultArgs-1] = append(argSet[defaultArgs-1], targetFilterArgs)
		} else {
			for i := 0; i < argCount; i++ {
				argSet[i] = append(argSet[i], targetFilterArgs)
			}
		}
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
	for i := 0; i < argCount; i++ {
		var apicresp ApicResponse
		if !conn.doSubscribe(argSet[i], kind, value, refresh_interval, &apicresp) {
			return false
		}
		subId, ok := apicresp.SubscriptionId.(string)
		if !ok {
			conn.log.Error("Subscription ID is not a string")
			return false
		}

		conn.logger.WithFields(logrus.Fields{
			"mod":   "APICAPI",
			"value": value,
			"kind":  kind,
			"id":    subId,
			"args":  argSet[i],
		}).Debug("Subscribed")

		conn.indexMutex.Lock()
		if argCount > defaultArgs {
			sub.childSubs[subId] = subComponent{
				targetClasses: splitTargetClasses[i],
				respClasses:   splitRespClasses[i],
			}
		} else {
			conn.subscriptions.subs[value].id = subId
		}
		conn.subscriptions.ids[subId] = value
		conn.indexMutex.Unlock()
		var respObjCount int
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
				"obj": obj,
			}).Debug("Caching")
			var count int
			prepareApicCache("", obj, &count)
			respObjCount += count
			conn.indexMutex.Lock()
			conn.cachedState[tag] = append(conn.cachedState[tag], obj)
			conn.indexMutex.Unlock()
		}
		if respObjCount >= ApicSubscriptionResponseMoMaxCount/10 {
			conn.logger.WithFields(logrus.Fields{
				"args":       argSet[i],
				"moCount":    respObjCount,
				"maxAllowed": ApicSubscriptionResponseMoMaxCount,
			}).Warning("Subscription response is significantly large. Each new object will add 2 Mos atleast and twice the number of labels on the object")
		} else {
			conn.logger.WithFields(logrus.Fields{
				"moCount": respObjCount,
			}).Debug("ResponseObjCount")
		}
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

func (conn *ApicConnection) PostApicObjects(uri string, payload ApicSlice) error {
	conn.log.Debug("apicIndex: ", conn.Apic[conn.ApicIndex], " uri: ", uri)
	url := fmt.Sprintf("https://%s%s", conn.Apic[conn.ApicIndex], uri)
	conn.log.Debug("Apic POST url: ", url)

	if conn.token == "" {
		token, err := conn.login()
		if err != nil {
			conn.log.Errorf("Login: %v", err)
			return err
		}
		conn.token = token
	}

	raw, err := json.Marshal(payload)
	if err != nil {
		conn.log.Error("Could not serialize object: ", err)
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
		conn.log.Error("Could not update  ", url, ": ", err)
		return err
	}

	complete(resp)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Status: %v", resp.StatusCode)
	}

	return nil
}
