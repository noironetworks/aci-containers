// Copyright 2018 Cisco Systems, Inc.
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

package keyvalueservice

import (
	"errors"
	"sync"
)

type KvItem struct {
	Key     string
	Value   interface{}
	Version uint64
}

const (
	OP_SET = iota
	OP_DELETE
)

type KvAction struct {
	Action uint
	Item   KvItem
}

var KvErrorInternal = errors.New("KvError: Internal Error")
var KvErrorVersionTooOld = errors.New("KvError: Requested version is too old")
var KvErrorNotFound = errors.New("KvError: Key or namespace not found")

type KvManager struct {
	lock       sync.Locker
	namespaces map[string]*kvNamespace

	servingWatch bool
	watchReqChan chan *watchReq
	changedChan  chan string
	pending      map[string][]*watchReq
	maxRetained  int
}

func NewKvManager() *KvManager {
	return &KvManager{
		lock:         &sync.Mutex{},
		namespaces:   make(map[string]*kvNamespace),
		servingWatch: false,
		watchReqChan: make(chan *watchReq),
		changedChan:  make(chan string),
		pending:      make(map[string][]*watchReq),
		maxRetained:  50}
}

func (m *KvManager) List(namespace string) (uint64, []KvItem) {
	ns := m.getNamespace(namespace)
	if ns != nil {
		return ns.GetAll()
	}
	return 0, nil
}

func (m *KvManager) Watch(namespace string, version uint64) (uint64,
	[]KvAction, error) {

	ch, err := m.watchAsync(namespace, version)
	if err != nil {
		return version, nil, err
	}
	res, ok := <-ch
	if ok {
		return res.Version, res.Actions, res.Error
	}
	// TODO: return an error here?
	return version, nil, nil
}

func (m *KvManager) watchAsync(namespace string, version uint64) (
	chan *watchRes, error) {
	if !m.servingWatch {
		return nil, KvErrorInternal
	}
	ns := m.getOrCreateNamespace(namespace)

	r := &watchReq{Namespace: ns,
		Version: version,
		ResChan: make(chan *watchRes, 1)}
	m.watchReqChan <- r
	return r.ResChan, nil
}

func (m *KvManager) Get(namespace, key string) (KvItem, error) {
	ns := m.getNamespace(namespace)
	if ns != nil {
		return ns.Get(key)
	}
	return KvItem{}, KvErrorNotFound
}

func (m *KvManager) Set(namespace, key string, value interface{}) error {
	ns := m.getOrCreateNamespace(namespace)
	ns.Set(key, value)
	if m.servingWatch {
		m.changedChan <- namespace
	}
	return nil
}

func (m *KvManager) Delete(namespace, key string) error {
	ns := m.getNamespace(namespace)
	if ns != nil {
		if deleted, _, _ := ns.Delete(key); deleted && m.servingWatch {
			m.changedChan <- namespace
		}
	}
	return nil
}

func (m *KvManager) ServeWatch(stopCh <-chan struct{}) {
	m.servingWatch = true

	// TODO: should we timeout watches if there are no updates?
	for {
		select {
		case req := <-m.watchReqChan:
			// Handle watch req
			if !req.Process() {
				m.pending[req.Namespace.Name] = append(
					m.pending[req.Namespace.Name], req)
			}
		case ns := <-m.changedChan:
			// Handle changes
			reqs, found := m.pending[ns]
			if !found {
				continue
			}
			new_pending := make([]*watchReq, 0)
			for _, r := range reqs {
				if !r.Process() {
					new_pending = append(new_pending, r)
				}
			}
			if len(new_pending) > 0 {
				m.pending[ns] = new_pending
			} else {
				delete(m.pending, ns)
			}
		case <-stopCh:
			m.servingWatch = false
			// Abort all watch requests
			for _, reqs := range m.pending {
				for _, r := range reqs {
					r.Abort()
				}
			}
			m.pending = make(map[string][]*watchReq)
			return
		}
	}
}

func (m *KvManager) getNamespace(namespace string) *kvNamespace {
	m.lock.Lock()
	defer m.lock.Unlock()
	return m.namespaces[namespace]
}

func (m *KvManager) getOrCreateNamespace(namespace string) *kvNamespace {
	m.lock.Lock()
	defer m.lock.Unlock()
	ns, ok := m.namespaces[namespace]
	if !ok {
		ns = newKvNamespace(namespace, m.maxRetained)
		m.namespaces[namespace] = ns
	}
	return ns
}

type watchReq struct {
	Namespace *kvNamespace
	Version   uint64
	ResChan   chan *watchRes
}

type watchRes struct {
	Actions []KvAction
	Version uint64
	Error   error
}

func (r *watchReq) Process() bool {
	last, acts, err := r.Namespace.FindUpdatedAfter(r.Version)
	if err != nil || len(acts) > 0 {
		r.ResChan <- &watchRes{Actions: acts, Version: last, Error: err}
		close(r.ResChan)
		return true
	}
	return false
}

func (r *watchReq) Abort() {
	r.ResChan <- &watchRes{Actions: nil, Version: r.Version, Error: nil}
	close(r.ResChan)
}
