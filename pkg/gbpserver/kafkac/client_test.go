/***
Copyright 2019 Cisco Systems Inc. All rights reserved.

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
package kafkac

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/Shopify/sarama"
	"github.com/Shopify/sarama/mocks"
	log "github.com/sirupsen/logrus"
	"github.com/noironetworks/aci-containers/pkg/gbpcrd/apis/acipolicy/v1"
	tu "github.com/noironetworks/aci-containers/pkg/testutil"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

const (
	testMarkerID = "088877000"
)

type suite struct {
	sync.Mutex
	mocks.SyncProducer
	mocks.PartitionConsumer
	messageq   []*sarama.ConsumerMessage
	store      map[string]int // index to messageq
	lastOffset int64
	prodErr    bool
	consErr    bool
	consChan   chan *sarama.ConsumerMessage
}

func (ts *suite) setup() {
	ts.messageq = make([]*sarama.ConsumerMessage, 0, 4)
	ts.store = make(map[string]int)
}

func (ts *suite) epPresent(ep *v1.PodIFStatus) bool {
	key := getEPName(ep)
	index, present := ts.store[key]
	if !present {
		return false
	}

	msg := ts.messageq[index]
	m := &CapicEPMsg{}

	if msg.Value == nil {
		// delete means not present
		return false
	}

	err := json.Unmarshal(msg.Value, m)
	if err != nil {
		log.Errorf("Unmarshal %v", err)
		return false
	}

	if m.Name == key && m.IPAddr == ep.IPAddr {
		return true
	}
	return false
}

func (ts *suite) epMsgPresent(ep *CapicEPMsg) bool {
	key := ep.Name
	index, present := ts.store[key]
	if !present {
		return false
	}

	msg := ts.messageq[index]
	m := &CapicEPMsg{}

	if msg.Value == nil {
		// delete means not present
		return false
	}

	err := json.Unmarshal(msg.Value, m)
	if err != nil {
		log.Errorf("Unmarshal %v", err)
		return false
	}

	if m.Name == key && m.IPAddr == ep.IPAddr {
		return true
	}
	return false
}
func (ts *suite) Close() error {
	return nil
}

func (ts *suite) SendMessage(msg *sarama.ProducerMessage) (partition int32, offset int64, err error) {
	if ts.prodErr {
		return 0, 0, fmt.Errorf("Error set")
	}

	ts.Lock()
	ts.lastOffset++
	msg.Offset = ts.lastOffset

	// compact, and preserve order
	key, err := msg.Key.Encode()
	if err != nil {
		return 0, 0, errors.Wrap(err, "Key Encode")
	}

	var v []byte
	var del bool

	if msg.Value == nil {
		del = true
	} else {
		v, err = msg.Value.Encode()
		if err != nil {
			return 0, 0, errors.Wrap(err, "Value Encode")
		}

	}

	cm := &sarama.ConsumerMessage{
		Key:    key,
		Value:  v,
		Offset: ts.lastOffset,
		Topic:  msg.Topic,
	}

	ix, ok := ts.store[string(key)]
	if ok {
		copy(ts.messageq[ix:], ts.messageq[ix+1:])
		// update indices
		for k, vv := range ts.store {
			if vv > ix {
				ts.store[k] = vv - 1
			}
		}
		if del {
			ts.messageq = ts.messageq[:len(ts.messageq)-1]
		} else {
			ts.messageq[len(ts.messageq)-1] = cm
		}
	} else {
		// allow delete retention
		ts.messageq = append(ts.messageq, cm)
	}

	if ok && del {
		// delete from store
		delete(ts.store, string(key))
	} else {
		ts.store[string(key)] = len(ts.messageq) - 1
	}

	if ts.consChan != nil {
		ts.consChan <- cm
	}

	ts.Unlock()

	return 0, ts.lastOffset, nil
}

func (ts *suite) Messages() <-chan *sarama.ConsumerMessage {
	ts.Lock()
	defer ts.Unlock()
	ts.consChan = make(chan *sarama.ConsumerMessage, 256)
	for _, m := range ts.messageq {
		ts.consChan <- m
	}

	return ts.consChan
}

var testEP1 = &v1.PodIFStatus{
	PodNS:   "testNS",
	PodName: "pod1",
	IFName:  "veth100",
	IPAddr:  "22.2.2.2",
	EPG:     "epgA",
}

var testEP2 = &v1.PodIFStatus{
	PodNS:   "testNS",
	PodName: "pod2",
	IFName:  "veth101",
	IPAddr:  "22.2.2.3",
	EPG:     "epgB",
}

// empty kafka, empty cni
func TestNew(t *testing.T) {
	ts := &suite{}
	ts.setup() // empty kafka

	loge := log.WithField("mod", "test")
	cfg := &KafkaCfg{
		Topic: "clusterA",
	}

	cloud := &CloudInfo{
		Account:     "testAccount",
		Subnet:      "testSubnet",
		ClusterName: "clusterA",
	}

	// setup an empty cni cache
	cCache := &podIFCache{
		log:       loge,
		cache:     make(map[string]*CapicEPMsg),
		state:     markerSet,
		markerID:  testMarkerID,
		readyChan: make(chan bool),
	}
	// inject marker
	res := cCache.ReadyToFwd("m", &CapicEPMsg{ContainerID: testMarkerID})
	assert.Equal(t, res, false)
	assert.Equal(t, cCache.state, markerReceived)

	kc := &KafkaClient{
		log:        loge,
		cfg:        cfg,
		cloudInfo:  cloud,
		producer:   ts,
		consumer:   ts,
		cniCache:   cCache,
		kafkaCache: &epCache{log: loge},
		inbox:      make(chan *CapicEPMsg, inboxSize),
	}

	go kc.run()

	// random concurrency
	if rand.Intn(100) > 50 {
		time.Sleep(10 * time.Millisecond)
	}

	// Inject ep's.
	err := kc.AddEP(testEP1)
	assert.Equal(t, err, nil)
	err = kc.AddEP(testEP2)
	assert.Equal(t, err, nil)

	tu.WaitFor(t, "ep1 in kafka", time.Second, func(last bool) (bool, error) {
		return ts.epPresent(testEP1), nil
	})

	tu.WaitFor(t, "ep2 in kafka", time.Second, func(last bool) (bool, error) {
		return ts.epPresent(testEP2), nil
	})

	// delete ep1
	kc.DeleteEP(testEP1)
	tu.WaitFor(t, "ep1 not in kafka", time.Second, func(last bool) (bool, error) {
		return !ts.epPresent(testEP1), nil
	})

	tu.WaitFor(t, "ep2 in kafka", time.Second, func(last bool) (bool, error) {
		return ts.epPresent(testEP2), nil
	})

	// delete ep2
	kc.DeleteEP(testEP2)

	tu.WaitFor(t, "ep2 not in kafka", time.Second, func(last bool) (bool, error) {
		return !ts.epPresent(testEP2), nil
	})
}

// cni and kafka have pre-existing endpoints, out of sync
func TestExisting(t *testing.T) {
	ts := &suite{}
	ts.setup() // empty kafka

	loge := log.WithField("mod", "test")
	cfg := &KafkaCfg{
		Topic: "clusterA",
	}

	cloud := &CloudInfo{
		Account:     "testAccount",
		Subnet:      "testSubnet",
		ClusterName: "clusterA",
	}

	// setup an cni cache
	cCache := &podIFCache{
		log:       loge,
		cache:     make(map[string]*CapicEPMsg),
		state:     markerSet,
		markerID:  testMarkerID,
		readyChan: make(chan bool),
	}

	// add some ep's to cni cache
	cniSet1 := getEPEntries(cloud, 5, 5)
	for k, v := range cniSet1 {
		res := cCache.ReadyToFwd(k, v)
		assert.Equal(t, res, false)
	}

	cniSet2 := getEPEntries(cloud, 10, 5)
	for k, v := range cniSet2 {
		res := cCache.ReadyToFwd(k, v)
		assert.Equal(t, res, false)
	}

	// send a delete for one ep from the cniSet1
	for k, v := range cniSet1 {
		v.delete = true
		res := cCache.ReadyToFwd(k, v)
		assert.Equal(t, res, false)
		delete(cniSet1, k)
		break
	}

	// inject marker
	res := cCache.ReadyToFwd("m", &CapicEPMsg{ContainerID: testMarkerID})
	assert.Equal(t, res, false)
	assert.Equal(t, cCache.state, markerReceived)

	// verify the cni map is as expected
	cniMap := mapUnion(cniSet1, cniSet2)
	assert.Equal(t, reflect.DeepEqual(cniMap, cCache.cache), true)

	// preload kafka with some ep's
	kset1 := getEPEntries(cloud, 3, 5)
	kset2 := getEPEntries(cloud, 12, 6)
	// change one msg in kset2 to a delete
	for _, v := range kset2 {
		v.delete = true
		break
	}

	for _, v := range kset1 {
		var m *sarama.ProducerMessage
		m = epMsgToProdMsg(v)
		_, _, err := ts.SendMessage(m)
		assert.Equal(t, err, nil)
	}

	for _, v := range kset2 {
		var m *sarama.ProducerMessage
		m = epMsgToProdMsg(v)
		_, _, err := ts.SendMessage(m)
		assert.Equal(t, err, nil)
	}

	kc := &KafkaClient{
		log:        loge,
		cfg:        cfg,
		cloudInfo:  cloud,
		producer:   ts,
		consumer:   ts,
		cniCache:   cCache,
		kafkaCache: &epCache{log: loge},
		inbox:      make(chan *CapicEPMsg, inboxSize),
	}

	go kc.run()

	// random concurrency
	if rand.Intn(200) > 95 {
		time.Sleep(10 * time.Millisecond)
	}

	tu.WaitFor(t, "cniMap matches kafka bus", time.Second, func(last bool) (bool, error) {
		for _, m := range cniMap {
			if m == nil {
				continue
			}

			if !ts.epMsgPresent(m) {
				return false, nil
			}
		}

		return true, nil
	})

	// create a new consumer
	consChan := ts.Messages()
	consCache := make(map[string]*CapicEPMsg)
	go func() {
		for {
			m, ok := <-consChan
			if !ok {
				return
			}

			if m.Value == nil {
				log.Infof("Delete %s", m.Key)
				delete(consCache, string(m.Key))
				continue
			}

			msg := new(CapicEPMsg)
			err := json.Unmarshal(m.Value, msg)
			if err != nil {
				log.Errorf("json.Unmarshal: %v", err)
				continue
			}

			consCache[string(m.Key)] = msg
		}
	}()

	tu.WaitFor(t, "cniMap matches kafka cache", time.Second, func(last bool) (bool, error) {
		// all epCache entries must match cniCache
		for k, m := range consCache {
			cniM := cniMap[k]
			if !reflect.DeepEqual(m, cniM) {
				return false, nil
			}
		}

		// all cniMap entries should be in epCache
		for kk, mm := range cniMap {
			if mm != nil {
				_, found := consCache[kk]
				if !found {
					return false, nil
				}
			}
		}

		return true, nil
	})
}

func getEPEntries(ci *CloudInfo, start, count int) map[string]*CapicEPMsg {
	res := make(map[string]*CapicEPMsg, count)
	for ix := start; ix < start+count; ix++ {
		msg := new(CapicEPMsg)
		epName := fmt.Sprintf("testNS%d.pod%d.veth%d", ix, ix, 200+ix)
		msg.Name = epName
		msg.IPAddr = fmt.Sprintf("23.3.3.%d", ix)
		msg.EpgDN = fmt.Sprintf("epg%d", ix)
		msg.SubnetDN = ci.Subnet
		msg.ClusterName = ci.ClusterName
		res[epName] = msg
	}

	return res
}

func mapUnion(m1, m2 map[string]*CapicEPMsg) map[string]*CapicEPMsg {
	u := make(map[string]*CapicEPMsg, len(m1)+len(m2))
	for k, v := range m1 {
		u[k] = v
	}
	for k, v := range m2 {
		u[k] = v
	}

	return u
}

func epMsgToProdMsg(em *CapicEPMsg) *sarama.ProducerMessage {
	k := sarama.StringEncoder(em.Name)
	var v sarama.Encoder

	if !em.delete {
		jVal, err := json.Marshal(em)
		if err != nil {
			panic(fmt.Sprintf("json.Marshal: %v, unrecoverable", err))
		}

		v = sarama.StringEncoder(jVal)
	}

	return &sarama.ProducerMessage{Topic: "clusterA", Key: k, Value: v}
}
