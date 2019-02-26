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
	"regexp"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/workqueue"

	"github.com/Sirupsen/logrus"
	"github.com/gorilla/websocket"
	"github.com/juju/ratelimit"
)

// defaultConnectionRefresh is used as connection refresh interval if
// RefreshInterval is set to 0
const defaultConnectionRefresh = 30 * time.Second

func complete(resp *http.Response) {
	io.Copy(ioutil.Discard, resp.Body)
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
	prefix string, refresh int) (*ApicConnection, error) {
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
		ReconnectInterval: time.Second,
		RefreshInterval:   time.Duration(refresh) * time.Second,
		signer:            signer,
		dialer:            dialer,
		log:               log,
		apic:              apic,
		user:              user,
		password:          password,
		prefix:            prefix,
		client:            client,
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
					conn.pendingSubDnUpdate[dn] = pendingChange{
						kind:   pendingKind,
						subIds: subIds,
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
			}
		} else {
			conn.log.Warning("Unexpected subscription: ", id)
		}
		conn.indexMutex.Unlock()
	}

	var requeue bool
	conn.indexMutex.Lock()
	pending, hasPendingChange := conn.pendingSubDnUpdate[dn]
	delete(conn.pendingSubDnUpdate, dn)
	obj, hasDesiredState := conn.desiredStateDn[dn]
	conn.indexMutex.Unlock()

	if hasPendingChange {
		for _, id := range pending.subIds {
			handleId(id)
		}
	}

	if hasDesiredState {
		if hasPendingChange {
			if pending.kind == pendingChangeDelete {
				conn.log.WithFields(logrus.Fields{"DN": dn}).
					Warning("Restoring unexpectedly deleted" +
						" ACI object")
				requeue = conn.postDn(dn, obj)
			} else if len(respClasses) > 0 {
				conn.getSubtreeDn(dn, respClasses, updateHandlers)
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
			} else if len(respClasses) > 0 {
				conn.getSubtreeDn(dn, respClasses, updateHandlers)
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
	conn.pendingSubDnUpdate = make(map[string]pendingChange)
	conn.deltaQueue = workqueue.NewNamedRateLimitingQueue(
		workqueue.NewMaxOfRateLimiter(
			workqueue.NewItemExponentialFailureRateLimiter(5*time.Millisecond,
				10*time.Second),
			&workqueue.BucketRateLimiter{
				Bucket: ratelimit.NewBucketWithRate(float64(10), int64(100)),
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

	refreshInterval := conn.RefreshInterval
	if refreshInterval == 0 {
		refreshInterval = defaultConnectionRefresh
	}
	refreshTicker := time.NewTicker(refreshInterval)
	defer refreshTicker.Stop()

	closeConn := func(stop bool) {
		close(queueStop)

		conn.indexMutex.Lock()
		conn.deltaQueue = nil
		conn.stopped = stop
		conn.syncEnabled = false
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

			conn.log.WithFields(logrus.Fields{
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
		conn.log.WithFields(logrus.Fields{
			"text":   text,
			"code":   code,
			"url":    resp.Request.URL,
			"status": resp.StatusCode,
		}).Error(message)
	}
}

func (conn *ApicConnection) getSubtreeDn(dn string, respClasses []string,
	updateHandlers []ApicObjectHandler) {

	args := []string{
		"rsp-subtree=full",
		"rsp-subtree-class=" + strings.Join(respClasses, ","),
	}
	// properly encoding the URI query parameters breaks APIC
	uri := fmt.Sprintf("/api/mo/%s.json?%s", dn, strings.Join(args, "&"))
	url := fmt.Sprintf("https://%s%s", conn.apic[conn.apicIndex], uri)
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
	for _, obj := range apicresp.Imdata {
		//conn.log.WithFields(logrus.Fields{
		//	"dn":  obj.GetDn(),
		//	"obj": obj,
		//}).Debug("Object updated on APIC")

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

func (conn *ApicConnection) postDn(dn string, obj ApicObject) bool {
	conn.log.WithFields(logrus.Fields{
		"dn": dn,
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

func (conn *ApicConnection) subscribe(value string, sub *subscription) bool {
	args := []string{
		"query-target=subtree",
		"rsp-subtree=full",
		"target-subtree-class=" + strings.Join(sub.targetClasses, ","),
		"rsp-subtree-class=" + strings.Join(sub.respClasses, ","),
	}
	if sub.targetFilter != "" {
		args = append(args, "query-target-filter="+sub.targetFilter)
	}

	kind := "mo"
	if sub.kind == apicSubClass {
		kind = "class"
	}

	refresh_interval := ""
	if conn.RefreshInterval != 0 {
		refresh_interval = fmt.Sprintf("refresh-timeout=%s&",
			conn.RefreshInterval)
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

	conn.log.WithFields(logrus.Fields{
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

		conn.log.WithFields(logrus.Fields{
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
