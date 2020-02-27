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
	"time"

	"github.com/Shopify/sarama"
	crdv1 "github.com/noironetworks/aci-containers/pkg/gbpcrd/apis/acipolicy/v1"
	crdclientset "github.com/noironetworks/aci-containers/pkg/gbpcrd/clientset/versioned"
	aciv1 "github.com/noironetworks/aci-containers/pkg/gbpcrd/clientset/versioned/typed/acipolicy/v1"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	restclient "k8s.io/client-go/rest"
)

const (
	markerName = "marker.marker"
	initial    = iota
	markerSet
	markerReceived
)

// implements the k8s side sync cache
type podIFCache struct {
	log       *logrus.Entry
	cache     map[string]*CapicEPMsg
	crdClient aciv1.AciV1Interface
	state     int
	markerID  string
	readyChan chan bool
}

func (pc *podIFCache) Init() error {
	pc.cache = make(map[string]*CapicEPMsg)
	pc.markerID = fmt.Sprintf("%04d%08d", rand.Intn(10000), rand.Intn(100000))
	pc.state = markerSet

	k8sCfg, err := restclient.InClusterConfig()
	if err != nil {
		return errors.Wrap(err, "InClusterConfig()")
	}

	aciawClient, err := crdclientset.NewForConfig(k8sCfg)
	if err != nil {
		return errors.Wrap(err, "crdclientset.NewForConfig()")
	}

	pc.crdClient = aciawClient.AciV1()

	marker := &crdv1.PodIF{Status: crdv1.PodIFStatus{ContainerID: pc.markerID}}
	marker.ObjectMeta.Name = markerName

	go func() {

		for {
			podif, err := pc.crdClient.PodIFs("kube-system").Get(markerName, metav1.GetOptions{})
			if err != nil {
				// create podif
				_, err = pc.crdClient.PodIFs("kube-system").Create(marker)
				if err == nil {
					break
				}

				pc.log.Errorf("Create podif marker - %v, will retry", err)
				time.Sleep(retryTime)
				continue
			}

			// update with new markerID
			podif.Status.ContainerID = pc.markerID
			_, err = pc.crdClient.PodIFs("kube-system").Update(podif)
			if err == nil {
				break
			}

			pc.log.Errorf("Update podif marker - %v, will retry", err)
		}
		pc.log.Infof("Marker with ID: %s set", pc.markerID)
	}()

	pc.readyChan = make(chan bool)
	return nil
}

func (pc *podIFCache) Ready() chan bool {
	return pc.readyChan
}

// Updates the cache, returns true if cache is ready
func (pc *podIFCache) ReadyToFwd(key string, msg *CapicEPMsg) bool {
	if msg.ContainerID == pc.markerID {
		if pc.state == markerSet { // ignore duplicates
			pc.state = markerReceived
			pc.log.Infof("PodIF marker received")
			close(pc.readyChan)
		}

		return false
	}

	if msg.delete {
		delete(pc.cache, key)
	} else if msg.IPAddr != "" { // ignore old markers
		pc.cache[key] = msg
	}

	return pc.state == markerReceived
}

func (pc *podIFCache) Read() map[string]*CapicEPMsg {
	return pc.cache
}

type epCache struct {
	log          *logrus.Entry
	cache        map[string]*CapicEPMsg
	consumer     sarama.PartitionConsumer
	markerOffset int64
	readyChan    chan bool
}

func (ec *epCache) Init(markerOffset int64, consumer sarama.PartitionConsumer) chan bool {
	ec.cache = make(map[string]*CapicEPMsg)
	ec.consumer = consumer
	ec.markerOffset = markerOffset
	ec.readyChan = make(chan bool)

	go func() {
		consChan := consumer.Messages()
		for {

			m, ok := <-consChan
			if !ok {
				ec.log.Infof("Consumer closed")
				return
			}

			if m.Offset == markerOffset {
				ec.log.Infof("Marker received")
				close(ec.readyChan)
				return
			}

			if m.Value == nil { // delete
				delete(ec.cache, string(m.Key))
				ec.log.Debugf(">>>> epCache: Received delete: %s", m.Key)
				continue
			}

			epMsg := new(CapicEPMsg)
			err := json.Unmarshal(m.Value, epMsg)
			if err != nil {
				ec.log.Errorf("epcache.Init : %v, unmarshaling %s", err, m.Value)
				continue
			}

			ec.cache[string(m.Key)] = epMsg
		}
	}()

	return ec.readyChan
}

func (ec *epCache) MsgDiff(desired map[string]*CapicEPMsg) map[string]*CapicEPMsg {
	curr := ec.cache

	diff := make(map[string]*CapicEPMsg)
	// insert delete msgs for items present in curr, but not in desired
	// note that in kafka terms, delete means key present with nil value
	for k := range curr {
		_, present := desired[k]
		if !present {
			diff[k] = nil
			ec.log.Debugf("Delete %s", k)
		}
	}

	// insert create msgs for items present in desired and either
	// missing, or different in curr

	for k, v := range desired {
		currV := curr[k]
		if reflect.DeepEqual(v, currV) {
			ec.log.Debugf("%s already exists", k)
			continue
		}

		diff[k] = v
		ec.log.Debugf("%s added", k)
	}

	ec.log.Debugf(">>>> Diff: %+v", diff)
	return diff
}
