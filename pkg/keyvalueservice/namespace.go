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
	"sort"
	"sync"
)

type kvNsValue struct {
	Value   interface{}
	Version uint64
}

type kvChange struct {
	Key    string
	Value  *kvNsValue
	Action uint
}

type kvNamespace struct {
	Name        string
	Store       map[string]*kvNsValue
	ChangeLog   []*kvChange
	LastVersion uint64
	rwLock      sync.RWMutex
	maxRetained int

	lastExpiredChange uint64
}

func newKvNamespace(name string, maxRetained int) *kvNamespace {
	return &kvNamespace{
		Name:        name,
		Store:       make(map[string]*kvNsValue),
		ChangeLog:   make([]*kvChange, 0),
		maxRetained: maxRetained}
}

func (n *kvNamespace) Set(key string, value interface{}) {
	n.rwLock.Lock()
	defer n.rwLock.Unlock()

	n.LastVersion = n.LastVersion + 1
	oldv, ok := n.Store[key]
	oldver := uint64(0)
	if ok {
		oldver = oldv.Version
	}
	newv := &kvNsValue{Value: value, Version: n.LastVersion}
	n.Store[key] = newv
	n.logChange(key, newv, oldver, OP_SET)
}

func (n *kvNamespace) Get(key string) (KvItem, error) {
	n.rwLock.RLock()
	defer n.rwLock.RUnlock()

	v, ok := n.Store[key]
	if !ok {
		return KvItem{}, KvErrorNotFound
	}
	return KvItem{Key: key, Value: v.Value}, nil
}

func (n *kvNamespace) Delete(key string) (bool, interface{}, uint64) {
	n.rwLock.Lock()
	defer n.rwLock.Unlock()

	oldv, ok := n.Store[key]
	if !ok {
		return false, nil, 0
	}
	delete(n.Store, key)
	oldver := oldv.Version
	n.LastVersion = n.LastVersion + 1
	n.logChange(key,
		&kvNsValue{Version: n.LastVersion, Value: oldv.Value},
		oldver, OP_DELETE)
	return true, oldv.Value, n.LastVersion
}

func (n *kvNamespace) FindUpdatedAfter(version uint64) (uint64,
	[]KvAction, error) {
	n.rwLock.RLock()
	defer n.rwLock.RUnlock()

	if n.LastVersion <= version {
		return n.LastVersion, nil, nil
	}
	if n.lastExpiredChange > 0 && version <= n.lastExpiredChange {
		return 0, nil, KvErrorVersionTooOld
	}
	res := make([]KvAction, 0)
	start := sort.Search(len(n.ChangeLog),
		func(i int) bool { return n.ChangeLog[i].Value.Version > version })
	for ; start < len(n.ChangeLog); start++ {
		c := n.ChangeLog[start]
		res = append(res,
			KvAction{Action: c.Action,
				Item: KvItem{Key: c.Key, Value: c.Value.Value}})
	}
	return n.LastVersion, res, nil
}

func (n *kvNamespace) GetAll() (uint64, []KvItem) {
	n.rwLock.RLock()
	defer n.rwLock.RUnlock()

	res := make([]KvItem, 0)
	for k, v := range n.Store {
		res = append(res, KvItem{Key: k, Value: v.Value})
	}
	return n.LastVersion, res
}

// must be called with rwLock.Lock()
func (n *kvNamespace) logChange(key string, val *kvNsValue,
	oldver uint64, op uint) {

	// check if oldver or key is in the log, if so remove that change
	sz := len(n.ChangeLog)
	oldi := sz
	if oldver != 0 {
		oldi = sort.Search(sz,
			func(i int) bool {
				return n.ChangeLog[i].Value.Version >= oldver
			})
		if oldi < sz && n.ChangeLog[oldi].Value.Version != oldver {
			// not a match
			oldi = sz
		}
	} else {
		// check all keys in changelog since we don't know old version
		for i := sz - 1; i >= 0; i-- {
			if n.ChangeLog[i].Key == key {
				oldi = i
				break
			}
		}
	}
	if oldi < sz {
		if oldi < sz-1 { // move elements to left one position
			copy(n.ChangeLog[oldi:], n.ChangeLog[oldi+1:])
		}
		// truncate last element
		n.ChangeLog = n.ChangeLog[0 : sz-1]
	}

	// purge older half of change log if it has become too long
	if len(n.ChangeLog) >= 2*n.maxRetained {
		n.lastExpiredChange = n.ChangeLog[n.maxRetained-1].Value.Version
		n.ChangeLog = n.ChangeLog[n.maxRetained:]
	}
	n.ChangeLog = append(n.ChangeLog,
		&kvChange{Key: key, Value: val, Action: op})
	/*
		fmt.Printf("LastVersion: %v, ChangeLog: ", n.LastVersion)
		for i := 0; i < len(n.ChangeLog); i++ {
			fmt.Printf("%v:%v(%d) ", n.ChangeLog[i].Key,
				n.ChangeLog[i].Value.Version, n.ChangeLog[i].Action)
		}
		fmt.Printf("\n")
	*/
}
