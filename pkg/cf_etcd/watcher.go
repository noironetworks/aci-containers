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

package cf_etcd

import (
	"fmt"
	"time"

	"github.com/Sirupsen/logrus"
	etcdclient "github.com/coreos/etcd/client"
	"golang.org/x/net/context"
)

type HandleNodeFunc func(*string, *etcdclient.Node) error

type CfEtcdWatcher struct {
	key         string
	etcdKeysApi etcdclient.KeysAPI
	synced      bool
	err         error
	log         *logrus.Logger
	delayOnErr  time.Duration

	nodeHandler func(*string, *etcdclient.Node) error
}

func NewEtcdWatcher(kapi etcdclient.KeysAPI, key string,
	f HandleNodeFunc, log *logrus.Logger) *CfEtcdWatcher {
	return &CfEtcdWatcher{key: key, etcdKeysApi: kapi, synced: false,
		log: log, delayOnErr: 10 * time.Second, nodeHandler: f}
}

func (w *CfEtcdWatcher) Run(stopCh <-chan struct{}) {
	ctx, cancelFunc := context.WithCancel(context.Background())
	cancelled := false

	// monitor stop channel
	go func() {
		for {
			select {
			case <-stopCh:
				cancelled = true
				cancelFunc()
				return
			}
		}
	}()

	// watch subtree
	for !cancelled {
		kapi := w.etcdKeysApi
		etcd_w := kapi.Watcher(w.key, &etcdclient.WatcherOptions{Recursive: true})

		w.log.Debug("Fetching all etcd nodes under ", w.key)
		var nodes etcdclient.Nodes
		resp, err := kapi.Get(ctx, w.key,
			&etcdclient.GetOptions{Recursive: true})
		if err != nil {
			if IsKeyNotFoundError(err) {
				w.log.Info(fmt.Sprintf("Etcd subtree %s doesn't exist yet", w.key))
				w.err = nil
			} else {
				w.log.Error("Error fetching etcd subtree: ", err)
				w.synced = true // to unblock waiters
				w.err = err
				time.Sleep(w.delayOnErr) // TODO exponential backoff
				continue
			}
		} else {
			w.err = nil
			FlattenNodes(resp.Node, &nodes)
		}
		act := "set"
		for _, nd := range nodes {
			w.nodeHandler(&act, nd)
		}
		w.log.Debug(fmt.Sprintf("Handled %d initial etcd nodes under %s", len(nodes), w.key))
		w.synced = true

		w.log.Debug("Watching etcd events under ", w.key)
		for !cancelled {
			resp, err := etcd_w.Next(ctx)
			if err != nil {
				w.log.Error("Error in etcd watcher: ", err)
				break
			}
			w.log.Debug("Etcd event: ", resp)
			w.nodeHandler(&resp.Action, resp.Node)
		}
	}
	w.log.Debug("Etcd watch terminated for ", w.key)
}

func (w *CfEtcdWatcher) Synced() bool {
	return w.synced
}

func (w *CfEtcdWatcher) Error() error {
	return w.err
}

func (w *CfEtcdWatcher) NodeHandler() HandleNodeFunc {
	return w.nodeHandler
}
