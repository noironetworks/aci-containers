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
	"fmt"
	"testing"

	"github.com/Shopify/sarama"
	"github.com/noironetworks/aci-containers/pkg/gbpcrd/apis/acipolicy/v1"
	"github.com/stretchr/testify/assert"
)

func TestClient(t *testing.T) {
	testBroker := sarama.NewMockBroker(t, 1)
	testLeader := sarama.NewMockBroker(t, 2)

	metadataResponse := new(sarama.MetadataResponse)
	metadataResponse.AddBroker(testLeader.Addr(), testLeader.BrokerID())
	metadataResponse.AddTopicPartition("clusterA", 0, testLeader.BrokerID(), nil, nil, nil, sarama.ErrNoError)
	testBroker.Returns(metadataResponse)

	prodSuccess := new(sarama.ProduceResponse)
	prodSuccess.AddTopicPartition("clusterA", 0, sarama.ErrNoError)
	testLeader.Returns(prodSuccess)

	defer testBroker.Close()
	defer testLeader.Close()

	cfg := &KafkaCfg{
		Brokers:   []string{testBroker.Addr()},
		Topic:     "clusterA",
		BatchSize: 20,
	}

	cloud := &CloudInfo{
		Account:     "testAccount",
		Region:      "testRegion",
		CIDR:        "testCIDR",
		Subnet:      "testSubnet",
		VRF:         "testVRF",
		ClusterName: "clusterA",
	}

	c, err := InitKafkaClient(cfg, cloud)
	assert.Equal(t, err, nil)

	for ix := 0; ix < 10; ix++ {
		ep := &v1.PodIFStatus{
			PodName: fmt.Sprintf("testPod%d", ix),
			PodNS:   "default",
			IPAddr:  fmt.Sprintf("10.1.1.%d", ix),
			EPG:     "testEPG",
			IFName:  fmt.Sprintf("veth10%d", ix),
		}

		err = c.AddEP(ep)
		assert.Equal(t, err, nil)
	}

	assert.Equal(t, c.errCount, uint64(0))
	assert.Equal(t, c.addCount, uint64(10))
	assert.Equal(t, c.delCount, uint64(0))

	for ix := 0; ix < 10; ix++ {
		ep := &v1.PodIFStatus{
			PodName: fmt.Sprintf("testPod%d", ix),
			PodNS:   "default",
			IPAddr:  fmt.Sprintf("10.1.1.%d", ix),
			EPG:     "testEPG",
			IFName:  fmt.Sprintf("veth10%d", ix),
		}

		c.DeleteEP(ep)
	}
	assert.Equal(t, c.errCount, uint64(0))
	assert.Equal(t, c.addCount, uint64(10))
	assert.Equal(t, c.delCount, uint64(10))
	c.producer.Close()
}
