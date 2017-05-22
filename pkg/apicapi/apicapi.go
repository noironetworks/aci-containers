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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/gorilla/websocket"
)

func (conn *ApicConnection) login() (string, error) {
	url := fmt.Sprintf("https://%s/api/aaaLogin.json",
		conn.apic[conn.apicIndex])
	login := &ApicObject{
		"aaaUser": &ApicObjectBody{
			Attributes: map[string]interface{}{
				"name": conn.user,
				"pwd":  conn.password,
			},
		},
	}
	raw, err := json.Marshal(login)
	if err != nil {
		return "", err
	}
	resp, err := conn.client.Post(url,
		"application/json", bytes.NewBuffer(raw))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

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
		aaaLogin, ok := obj["aaaLogin"]
		if !ok {
			continue
		}

		token, ok := aaaLogin.Attributes["token"]
		if !ok {
			return "", errors.New("Token not found in aaaLogin response")
		}
		switch token := token.(type) {
		default:
			return "", errors.New("Token is not a string")
		case string:
			return token, nil
		}
	}
	return "", errors.New("aaaLogin not found in login response")
}

func New(dialer *websocket.Dialer, log *logrus.Logger,
	apic []string, user string, password string,
	prefix string) (*ApicConnection, error) {

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
	}
	conn := &ApicConnection{
		ReconnectInterval: time.Second,
		RefreshInterval:   30 * time.Second,
		RetryInterval:     5 * time.Second,
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
		desiredState:   make(map[string]ApicSlice),
		desiredStateDn: make(map[string]ApicObject),
		cachedState:    make(map[string]ApicSlice),
		cacheDnSubIds:  make(map[string][]string),
		errorUpdates:   make(map[string]ApicObject),
	}
	return conn, nil
}

func (conn *ApicConnection) handleSocketUpdate(apicresp *ApicResponse) {
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
	switch ids := apicresp.SubscriptionId.(type) {
	case string:
		handleId(ids)
	case []interface{}:
		for _, id := range ids {
			handleId(id.(string))
		}
	}
	if len(respClasses) == 0 {
		return
	}
	for _, obj := range apicresp.Imdata {
		for _, body := range obj {
			prepareApicCache("", obj)
			switch dn := body.Attributes["dn"].(type) {
			case string:
				switch status := body.Attributes["status"].(type) {
				case string:
					if status == "deleted" {
						for _, handler := range deleteHandlers {
							handler(dn)
						}
						conn.reconcileApicDelete(dn)
					} else {
						conn.getSubtreeDn(dn, respClasses, updateHandlers)
					}
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

func (conn *ApicConnection) runConn(stopCh <-chan struct{}) {
	done := make(chan struct{})
	restart := make(chan struct{})
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
	conn.cacheDnSubIds = make(map[string][]string)
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
		if conn.FullSyncHook != nil {
			conn.FullSyncHook()
		}
		conn.fullSync()
	}

	refreshTicker := time.NewTicker(conn.RefreshInterval)
	defer refreshTicker.Stop()
	retryTicker := time.NewTicker(conn.RetryInterval)
	defer retryTicker.Stop()

	closeConn := func(stop bool) {
		conn.indexMutex.Lock()
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
		case <-refreshTicker.C:
			conn.refresh()
		case <-retryTicker.C:
			conn.retry()
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

			url := fmt.Sprintf("wss://%s/socket%s",
				conn.apic[conn.apicIndex], token)
			conn.connection, _, err = conn.dialer.Dial(url, nil)
			if err != nil {
				conn.log.Error("Failed to open APIC websocket: ", err)
				return
			}

			conn.runConn(stopCh)
		}()
	}
}

func (conn *ApicConnection) refresh() {
	url := fmt.Sprintf("https://%s/api/aaaRefresh.json",
		conn.apic[conn.apicIndex])
	resp, err := conn.client.Get(url)
	if err != nil {
		conn.log.Error("Failed to refresh APIC session: ", err)
		conn.restart()
		return
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		defer resp.Body.Close()
		conn.logErrorResp("Error while refreshing login", resp)
		resp.Body.Close()
		conn.restart()
		return
	}

	for _, sub := range conn.subscriptions.subs {
		url := fmt.Sprintf("https://%s/api/subscriptionRefresh.json?id=%s",
			conn.apic[conn.apicIndex], sub.id)
		resp, err := conn.client.Get(url)
		if err != nil {
			conn.log.Error("Failed to refresh APIC subscription: ", err)
			conn.restart()
			return
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			conn.logErrorResp("Error while refreshing subscription", resp)
			resp.Body.Close()
			conn.restart()
			return
		}
		resp.Body.Close()
	}
}

func (conn *ApicConnection) retry() {
	conn.indexMutex.Lock()
	updates := conn.errorUpdates
	conn.errorUpdates = make(map[string]ApicObject)
	conn.indexMutex.Unlock()

	for dn, obj := range updates {
		conn.log.Info("Retrying update for ", dn)
		conn.postDn(dn, obj)
	}
}

func (conn *ApicConnection) logErrorResp(message string, resp *http.Response) {
	var apicresp ApicResponse
	conn.log.Error(resp.Request.URL)
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
			"status": resp.StatusCode,
		}).Error(message)
	}
}

func (conn *ApicConnection) getSubtreeDn(dn string, respClasses []string,
	updateHandlers []ApicObjectHandler) {

	args := url.Values{
		"rsp-subtree":       []string{"full"},
		"rsp-subtree-class": []string{strings.Join(respClasses, ",")},
	}
	url := fmt.Sprintf("https://%s/api/mo/%s.json?%s",
		conn.apic[conn.apicIndex], dn, args.Encode())
	resp, err := conn.client.Get(url)
	if err != nil {
		conn.log.Error("Could not get subtree for ", dn, ": ", err)
		conn.restart()
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		conn.logErrorResp("Could not get subtree for "+dn, resp)
		conn.restart()
	}

	var apicresp ApicResponse
	err = json.NewDecoder(resp.Body).Decode(&apicresp)
	if err != nil {
		conn.log.Error("Could not parse APIC response: ", err)
		return
	}
	for _, obj := range apicresp.Imdata {
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

func (conn *ApicConnection) postDn(dn string, obj ApicObject) {
	conn.indexMutex.Lock()
	conn.indexMutex.Unlock()

	url := fmt.Sprintf("https://%s/api/mo/%s.json",
		conn.apic[conn.apicIndex], dn)
	raw, err := json.Marshal(obj)
	if err != nil {
		conn.log.Error("Could not serialize object for dn ", dn, ": ", err)
	}
	//conn.log.Debug(string(raw))
	resp, err := conn.client.Post(url,
		"application/json", bytes.NewBuffer(raw))
	if err != nil {
		conn.log.Error("Could not update dn ", dn, ": ", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		conn.logErrorResp("Could not update dn "+dn, resp)
		if resp.StatusCode == 400 {
			conn.indexMutex.Lock()
			conn.errorUpdates[dn] = obj
			conn.indexMutex.Unlock()
		} else {
			conn.restart()
		}
	}
}

func (conn *ApicConnection) deleteDn(dn string) {
	url := fmt.Sprintf("https://%s/api/mo/%s.json",
		conn.apic[conn.apicIndex], dn)
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		conn.log.Error("Could not create delete request: ", err)
		return
	}
	resp, err := conn.client.Do(req)
	if err != nil {
		conn.log.Error("Could not delete dn ", dn, ": ", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		conn.logErrorResp("Could not delete dn "+dn, resp)
		conn.restart()
		return
	}
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

	var respClasses []string
	for class := range visited {
		respClasses = append(respClasses, class)
	}
	respClasses = append(respClasses, "tagInst")
	return respClasses
}

func (conn *ApicConnection) AddSubscriptionClass(class string,
	targetClasses []string, targetFilter string) {

	conn.indexMutex.Lock()
	conn.subscriptions.subs[class] = &subscription{
		kind:          apicSubClass,
		targetClasses: targetClasses,
		respClasses:   computeRespClasses(targetClasses),
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

func (conn *ApicConnection) subscribe(value string, sub *subscription) bool {
	args := url.Values{
		"query-target":         []string{"subtree"},
		"target-subtree-class": []string{strings.Join(sub.targetClasses, ",")},
		"rsp-subtree":          []string{"full"},
		"rsp-subtree-class":    []string{strings.Join(sub.respClasses, ",")},
	}
	if sub.targetFilter != "" {
		args["query-target-filter"] = []string{sub.targetFilter}
	}
	kind := "mo"
	if sub.kind == apicSubClass {
		kind = "class"
	}

	url := fmt.Sprintf("https://%s/api/%s/%s.json?subscription=yes&%s",
		conn.apic[conn.apicIndex], kind, value, args.Encode())
	resp, err := conn.client.Get(url)
	if err != nil {
		conn.log.Error("Failed to subscribe to ", value, ": ", err)
		return false
	}
	defer resp.Body.Close()
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
		conn.cacheDnSubIds[dn] = append(conn.cacheDnSubIds[dn], subId)
		conn.indexMutex.Unlock()

		if sub.updateHook != nil && sub.updateHook(obj) {
			continue
		}

		tag := obj.GetTag()
		if !conn.isSyncTag(tag) {
			continue
		}

		//conn.log.WithFields(logrus.Fields{
		//	"dn":  dn,
		//	"tag": tag,
		//	//"obj": obj,
		//}).Debug("Caching")

		prepareApicCache("", obj)
		conn.indexMutex.Lock()
		conn.cachedState[tag] = append(conn.cachedState[tag], obj)
		conn.indexMutex.Unlock()
	}

	return true
}

func (conn *ApicConnection) isSyncTag(tag string) bool {
	return tag != "" && strings.HasPrefix(tag, conn.prefix)
}
