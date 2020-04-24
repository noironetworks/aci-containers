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
	"strings"
	"time"

	"github.com/Shopify/sarama"
	"github.com/sirupsen/logrus"
	"github.com/noironetworks/aci-containers/pkg/gbpcrd/apis/acipolicy/v1"
	"github.com/pkg/errors"
)

const (
	inboxSize = 256
	retryTime = 2 * time.Second
)

type KafkaClient struct {
	log       *logrus.Entry
	cfg       *KafkaCfg
	cloudInfo *CloudInfo
	producer  sarama.SyncProducer
	// used for initial sync
	consumer sarama.PartitionConsumer
	epgToDn  map[string]string

	// cache of ep's received from k8s/cni
	cniCache *podIFCache

	// cache of ep's received from kafka
	kafkaCache *epCache

	syncComplete bool
	// to be sent to kafka
	inbox    chan *CapicEPMsg
	addCount uint64
	delCount uint64
	errCount uint64
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
	KafkaLogLevel  string   `json:"kafka-log-level,omitempty"`
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
	EpgDN       string `json:"epg-dn,omitempty"`
	ContainerID string `json:"containerid,omitempty"`
	SubnetDN    string `json:"subnet-dn,omitempty"`
	VrfDN       string `json:"vrf-dn,omitempty"`
	// this needs to be the DN of the pod, for gui
	PodNameDN   string `json:"pod-name,omitempty"`
	ClusterName string `json:"cluster-name,omitempty"`
	delete      bool   // internal use
}

func InitKafkaClient(cfg *KafkaCfg, ci *CloudInfo) (*KafkaClient, error) {
	level, err := logrus.ParseLevel(cfg.KafkaLogLevel)
	if err != nil {
		level = logrus.InfoLevel
	}
	logger := logrus.New()
	logger.Level = level
	log := logger.WithField("mod", "KAFKA")
	sarama.Logger = log
	c := &KafkaClient{
		log:        log,
		cfg:        cfg,
		cloudInfo:  ci,
		cniCache:   &podIFCache{log: log},
		kafkaCache: &epCache{log: log},
		inbox:      make(chan *CapicEPMsg, inboxSize),
		epgToDn:    make(map[string]string),
	}

	err = c.cniCache.Init()
	if err != nil {
		return nil, errors.Wrap(err, "cniCache.Init()")
	}

	go func() {
		for {
			err = c.kafkaSetup()
			if err != nil {
				log.Errorf("kafkaSetup(): %v -- will retry", err)
				time.Sleep(retryTime)
				continue
			}

			break
		}

		log.Infof("kafkaSetup succeeded, running...")
		c.run()
	}()

	return c, nil
}

func (kc *KafkaClient) UpdateEpgDN(name, dn string) {
	kc.epgToDn[name] = dn
}

func (kc *KafkaClient) getEpgDN(name string) string {
	dn, found := kc.epgToDn[name]
	if found {
		return dn
	}
	kc.log.Warnf("epg %s dn not found, generating", name)
	tenant := dnToTenant(kc.cloudInfo.VRF)
	return fmt.Sprintf("uni/tn-%s/cloudapp-%s/cloudepg-%s", tenant, kc.cloudInfo.ClusterName, name)
}

func (kc *KafkaClient) getPodDN(ep *v1.PodIFStatus) string {
	return fmt.Sprintf("comp/prov-Kubernetes/ctrlr-[%s]-%s/ns-%s/grp-%s",
		kc.cloudInfo.ClusterName, kc.cloudInfo.ClusterName, ep.PodNS, ep.PodName)
}

func (kc *KafkaClient) AddEP(ep *v1.PodIFStatus) error {
	epName := getEPName(ep)
	kc.log.Debugf("kc.AddEP: %s", epName)
	msg := &CapicEPMsg{
		Name:        epName,
		IPAddr:      ep.IPAddr,
		EpgDN:       kc.getEpgDN(ep.EPG),
		SubnetDN:    kc.cloudInfo.Subnet,
		VrfDN:       kc.cloudInfo.VRF,
		ContainerID: ep.ContainerID,
		PodNameDN:   kc.getPodDN(ep),
		ClusterName: kc.cloudInfo.ClusterName,
	}

	kc.log.Debugf("kc.AddEP: %+v", msg)

	key := epName
	if !kc.cniCache.ReadyToFwd(key, msg) {
		// still syncing cni cache
		return nil
	}

	kc.inbox <- msg
	kc.addCount++
	return nil
}

func (kc *KafkaClient) DeleteEP(ep *v1.PodIFStatus) {
	epName := getEPName(ep)
	msg := &CapicEPMsg{
		Name:   epName,
		delete: true,
	}

	if !kc.cniCache.ReadyToFwd(epName, msg) {
		// still syncing cni cache
		return
	}

	kc.inbox <- msg
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

func (kc *KafkaClient) kafkaSetup() error {

	kc.log.Infof("cfg is: %+v", kc.cfg)
	producerConfig := sarama.NewConfig()
	if kc.cfg.ClientKeyPath != "" {
		tlsConfig, err := newTLSConfig(kc.cfg.ClientCertPath,
			kc.cfg.ClientKeyPath,
			kc.cfg.CACertPath)

		if err != nil {
			return err
		}

		// This can be used on test server if domain does not match cert:
		tlsConfig.InsecureSkipVerify = true

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
	producerConfig.Producer.Return.Successes = true

	p, err := sarama.NewSyncProducer(kc.cfg.Brokers, producerConfig)
	if err != nil {
		return errors.Wrap(err, "NewSyncProducer")
	}

	kc.producer = p

	c, err := sarama.NewConsumer(kc.cfg.Brokers, producerConfig)
	if err != nil {
		return errors.Wrap(err, "NewConsumer")
	}

	pc, err := c.ConsumePartition(kc.cfg.Topic, 0, sarama.OffsetOldest)
	if err != nil {
		return errors.Wrap(err, "ConsumePartition")
	}
	kc.consumer = pc
	return nil
}

func (kc *KafkaClient) run() {
	// wait for cniCache to sync
	<-kc.cniCache.Ready()

	kc.log.Infof("cniCache is ready")

	// send a marker msg
	offset := kc.sendOneMsg(markerName, nil, 2*time.Second)
	kafkaReady := kc.kafkaCache.Init(offset, kc.consumer)
	<-kafkaReady

	diff := kc.kafkaCache.MsgDiff(kc.cniCache.Read())

	// apply the diff to bring kafka into sync. the order is
	// irrelevant here, so we walk the map.
	kc.log.Debugf("Applying diff")
	for k, v := range diff {
		kc.sendOneMsg(k, v, time.Second)
	}
	kc.log.Infof("Sync complete")

	// process inbox -- forever
	for m := range kc.inbox {
		var v *CapicEPMsg
		if !m.delete {
			v = m
		}

		kc.sendOneMsg(m.Name, v, time.Second)
		if m.delete {
			logrus.Infof("Sent delete for %s", m.Name)
		} else {
			logrus.Infof("Sent create for %s", m.Name)
		}
	}

}

func (kc *KafkaClient) sendOneMsg(key string, val *CapicEPMsg, delay time.Duration) int64 {
	k := sarama.StringEncoder(key)
	var v sarama.Encoder
	if val != nil {
		jVal, err := json.Marshal(val)
		if err != nil {
			panic(fmt.Sprintf("json.Marshal: %v, unrecoverable", err))
		}

		v = sarama.StringEncoder(jVal)
	}
	msg := &sarama.ProducerMessage{Topic: kc.cfg.Topic, Key: k, Value: v}
	for {
		_, offset, err := kc.producer.SendMessage(msg)
		if err != nil {
			kc.log.Infof("producer.SendMessage - %v, will retry", err)
			time.Sleep(delay)
			continue
		}

		return offset
	}
}

func dnToTenant(dn string) string {
	s := strings.TrimPrefix(dn, "acct-[")
	parts := strings.Split(s, "]")
	if len(parts) > 1 {
		return parts[0]
	}

	return ""
}
