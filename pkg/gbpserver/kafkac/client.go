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
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/Shopify/sarama"
	log "github.com/Sirupsen/logrus"
	"github.com/noironetworks/aci-containers/pkg/gbpcrd/apis/acipolicy/v1"
	"github.com/pkg/errors"
)

type KafkaClient struct {
	cfg       *KafkaCfg
	cloudInfo *CloudInfo
	producer  sarama.AsyncProducer
	addCount  uint64
	delCount  uint64
	errCount  uint64
}

type CloudInfo struct {
	Account     string `json:"account,omitempty"`
	Region      string `json:"region,omitempty"`
	CIDR        string `json:"cidr,omitempty"`
	Subnet      string `json:"subnet,omitempty"`
	VRF         string `json:"vrf,omitempty"`
	ClusterName string `json:"cluster-name,omitempty"`
}

type KafkaCfg struct {
	Brokers        []string `json:"brokers,omitempty"`
	ClientKeyPath  string   `json:"client-key-path,omitempty"`
	ClientCertPath string   `json:"client-cert-path,omitempty"`
	CACertPath     string   `json:"ca-cert-path,omitempty"`
	Topic          string   `json:"topic,omitempty"`
	Username       string   `json:"username,omitempty"`
	Password       string   `json:"password,omitempty"`
	BatchSize      int      `json:"-"`
}

type CapicEPMsg struct {
	Name        string `json:"name,omitempty"`
	IPAddr      string `json:"ip-addr,omitempty"`
	EPG         string `json:"epg,omitempty"`
	Subnet      string `json:"subnet,omitempty"`
	CIDR        string `json:"cidr,omitempty"`
	VRF         string `json:"vrf,omitempty"`
	Region      string `json:"region,omitempty"`
	Account     string `json:"account,omitempty"`
	PodDN       string `json:"pod-dn,omitempty"`
	ClusterName string `json:"cluster-name,omitempty"`
}

func InitKafkaClient(cfg *KafkaCfg, ci *CloudInfo) (*KafkaClient, error) {
	c := &KafkaClient{
		cfg:       cfg,
		cloudInfo: ci,
	}

	prod, err := c.producerSetup()
	if err != nil {
		return nil, err
	}

	c.producer = prod
	go func() {
		// read errors
		for err := range prod.Errors() {
			c.errCount++
			log.Error(errors.Wrap(err, "Kafka producer:"))
		}
	}()

	return c, nil
}

func (kc *KafkaClient) AddEP(ep *v1.PodIFStatus) error {
	epName := getEPName(ep)
	msg := &CapicEPMsg{
		Name:    epName,
		IPAddr:  ep.IPAddr,
		EPG:     ep.EPG,
		Subnet:  kc.cloudInfo.Subnet,
		CIDR:    kc.cloudInfo.CIDR,
		VRF:     kc.cloudInfo.VRF,
		Region:  kc.cloudInfo.Region,
		Account: kc.cloudInfo.Account,
		//PodDN: tbd,
		ClusterName: kc.cloudInfo.ClusterName,
	}
	val, err := json.Marshal(msg)
	if err != nil {
		return errors.Wrap(err, "AddEP:json.Marshal")
	}

	key := epName
	k := sarama.StringEncoder(key)
	v := sarama.StringEncoder(val)
	kc.producer.Input() <- &sarama.ProducerMessage{Topic: kc.cfg.Topic, Key: k, Value: v}
	kc.addCount++
	return nil
}

func (kc *KafkaClient) DeleteEP(ep *v1.PodIFStatus) {
	key := getEPName(ep)
	k := sarama.StringEncoder(key)
	kc.producer.Input() <- &sarama.ProducerMessage{Topic: kc.cfg.Topic, Key: k, Value: nil}
	kc.delCount++
}

func getEPName(ep *v1.PodIFStatus) string {
	return fmt.Sprintf("%s.%s.%s", ep.PodNS, ep.PodName, ep.IFName)
}

func newTLSConfig(clientCertFile, clientKeyFile, caCertFile string) (*tls.Config, error) {
	tlsConfig := tls.Config{}

	// Load client cert
	cert, err := tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
	if err != nil {
		return &tlsConfig, err
	}
	tlsConfig.Certificates = []tls.Certificate{cert}

	// Load CA cert
	caCert, err := ioutil.ReadFile(caCertFile)
	if err != nil {
		return &tlsConfig, err
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	tlsConfig.RootCAs = caCertPool

	tlsConfig.BuildNameToCertificate()
	return &tlsConfig, err
}

func (kc *KafkaClient) producerSetup() (sarama.AsyncProducer, error) {

	producerConfig := sarama.NewConfig()
	if kc.cfg.ClientKeyPath != "" {
		tlsConfig, err := newTLSConfig(kc.cfg.ClientCertPath,
			kc.cfg.ClientKeyPath,
			kc.cfg.CACertPath)

		if err != nil {
			return nil, err
		}

		// This can be used on test server if domain does not match cert:
		//tlsConfig.InsecureSkipVerify = true

		producerConfig.Net.TLS.Enable = true
		producerConfig.Net.TLS.Config = tlsConfig
	}

	// if sasl is provided, enable it
	if kc.cfg.Username != "" {
		producerConfig.Net.SASL.Enable = true
		producerConfig.Net.SASL.User = kc.cfg.Username
		producerConfig.Net.SASL.Password = kc.cfg.Password
	}

	producerConfig.Producer.Flush.Messages = kc.cfg.BatchSize

	return sarama.NewAsyncProducer(kc.cfg.Brokers, producerConfig)
}
