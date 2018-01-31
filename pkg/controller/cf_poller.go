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

package controller

import (
	"fmt"
	"reflect"
	"time"

	"github.com/Sirupsen/logrus"
)

type PollFunc func() (map[string]interface{}, interface{}, error)
type HandleFunc func(updates map[string]interface{}, deletes map[string]interface{})

type CfPoller struct {
	name         string
	pollInterval time.Duration
	errorDelay   time.Duration
	poller       PollFunc
	handler      HandleFunc
	data         map[string]interface{}
	synced       bool
	log          *logrus.Logger
}

func NewCfPoller(name string, interval, errDelay time.Duration, pf PollFunc, hf HandleFunc,
	log *logrus.Logger) *CfPoller {
	p := &CfPoller{name: name, pollInterval: interval, errorDelay: errDelay, poller: pf,
		handler: hf, data: make(map[string]interface{}), synced: false, log: log}
	return p
}

func (p *CfPoller) Run(immediate bool, stopCh <-chan struct{}) {
	initDelay := p.pollInterval
	if immediate {
		initDelay = 1 * time.Millisecond
	}
	timer := time.NewTimer(initDelay)
	var oldRespHash interface{}

	p.synced = false
	p.data = make(map[string]interface{})
	for {
		select {
		case <-stopCh:
			p.log.Debug(fmt.Sprintf("%s polling terminated", p.name))
			return

		case <-timer.C:
			pollRes, newRespHash, err := p.poller()
			if err != nil {
				p.log.Error(fmt.Sprintf("%s polling error: %s", p.name, err))
				if p.errorDelay > 0 {
					timer.Reset(p.errorDelay)
				} else {
					timer.Reset(p.pollInterval)
				}
				continue
			}
			if newRespHash != nil && reflect.DeepEqual(newRespHash, oldRespHash) {
				// no change
				timer.Reset(p.pollInterval)
				continue
			}
			p.log.Debug(fmt.Sprintf("%s polling got updates - fetched %d objects, oldHash %v newHash %v",
				p.name, len(pollRes), oldRespHash, newRespHash))

			updated := make(map[string]interface{})
			deleted := make(map[string]interface{})
			to_delete := make(map[string]struct{})
			for k := range p.data {
				to_delete[k] = struct{}{}
			}
			for k, v := range pollRes {
				old_v, ok := p.data[k]
				if !ok || !reflect.DeepEqual(old_v, v) {
					updated[k] = v
				}
				p.data[k] = v
				delete(to_delete, k)
			}
			for k := range to_delete {
				deleted[k] = p.data[k]
				delete(p.data, k)
			}
			p.handler(updated, deleted)
			if !p.synced {
				p.synced = true
			}
			oldRespHash = newRespHash
			timer.Reset(p.pollInterval)
		}
	}
}

func (p *CfPoller) Synced() bool {
	return p.synced
}

func (p *CfPoller) Poller() PollFunc {
	return p.poller
}

func (p *CfPoller) Handler() HandleFunc {
	return p.handler
}
