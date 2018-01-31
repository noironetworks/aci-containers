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

// Fake etcd client structures for unit-tests

package cf_etcd_fakes

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Sirupsen/logrus"
	etcdclient "github.com/coreos/etcd/client"
	"golang.org/x/net/context"
)

type FakeEtcdKeysApi struct {
	data        map[string]string
	log         *logrus.Logger
	FakeWatcher *FakeEtcdWatcher
}

type FakeEtcdWatcher struct {
	blockFor time.Duration
	queue    chan *etcdclient.Response
}

func NewFakeEtcdKeysApi(log *logrus.Logger) *FakeEtcdKeysApi {
	return &FakeEtcdKeysApi{
		data:        make(map[string]string),
		log:         log,
		FakeWatcher: NewFakeEtcdWatcher()}
}

func NewFakeEtcdWatcher() *FakeEtcdWatcher {
	return &FakeEtcdWatcher{blockFor: 5 * time.Second,
		queue: make(chan *etcdclient.Response, 100)}
}

func (k *FakeEtcdKeysApi) Get(ctx context.Context, key string, opts *etcdclient.GetOptions) (*etcdclient.Response, error) {
	v, ok := k.data[key]
	if ok {
		parent := &etcdclient.Node{Key: key, Value: v}
		if opts != nil && opts.Recursive {
			for ik, iv := range k.data {
				if strings.HasPrefix(ik, key+"/") {
					parent.Nodes = append(parent.Nodes, &etcdclient.Node{Key: ik, Value: iv})
				}
			}
		}
		return &etcdclient.Response{Node: parent}, nil
	}
	return nil, etcdclient.Error{Code: etcdclient.ErrorCodeKeyNotFound}
}

func (k *FakeEtcdKeysApi) Set(ctx context.Context, key, value string, opts *etcdclient.SetOptions) (*etcdclient.Response, error) {
	k.log.Debug(fmt.Sprintf("Setting %s = %s", key, value))
	k.data[key] = value
	return nil, nil
}

func (k *FakeEtcdKeysApi) Delete(ctx context.Context, key string, opts *etcdclient.DeleteOptions) (*etcdclient.Response, error) {
	if opts != nil && opts.Recursive {
		for ik := range k.data {
			if strings.HasPrefix(ik, key) {
				delete(k.data, ik)
			}
		}
	} else {
		delete(k.data, key)
	}
	return nil, nil
}

func (k *FakeEtcdKeysApi) Create(ctx context.Context, key, value string) (*etcdclient.Response, error) {
	return k.Set(ctx, key, value, nil)
}

func (k *FakeEtcdKeysApi) CreateInOrder(ctx context.Context, dir, value string, opts *etcdclient.CreateInOrderOptions) (*etcdclient.Response, error) {
	return nil, fmt.Errorf("Not Implemented")
}

func (k *FakeEtcdKeysApi) Update(ctx context.Context, key, value string) (*etcdclient.Response, error) {
	return k.Set(ctx, key, value, nil)
}

func (k *FakeEtcdKeysApi) Watcher(key string, opts *etcdclient.WatcherOptions) etcdclient.Watcher {
	return k.FakeWatcher
}

func (k *FakeEtcdKeysApi) Equals(key string, expectedValue interface{}) bool {
	str, ok := expectedValue.(string)
	if !ok {
		bytes, err := json.Marshal(expectedValue)
		if err != nil {
			panic(err.Error())
		}
		str = string(bytes)
	}
	found, ok := k.data[key]
	return ok && found == str
}

func (w *FakeEtcdWatcher) Next(ctx context.Context) (*etcdclient.Response, error) {
	timer := time.NewTimer(w.blockFor)
	for {
		select {
		case <-timer.C:
			return nil, nil
		case resp := <-w.queue:
			return resp, nil
		case <-ctx.Done():
			return nil, context.Canceled
		}
	}
	return nil, nil
}

func (w *FakeEtcdWatcher) Enqueue(resp *etcdclient.Response) {
	w.queue <- resp
}
