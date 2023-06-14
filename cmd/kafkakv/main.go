package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/Shopify/sarama"
)

func NewTLSConfig(clientCertFile, clientKeyFile, caCertFile string) (*tls.Config, error) {
	tlsConfig := tls.Config{}

	// Load client cert
	cert, err := tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
	if err != nil {
		return &tlsConfig, err
	}
	tlsConfig.Certificates = []tls.Certificate{cert}

	// Load CA cert
	caCert, err := os.ReadFile(caCertFile)
	if err != nil {
		return &tlsConfig, err
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	tlsConfig.RootCAs = caCertPool

	tlsConfig.BuildNameToCertificate()
	return &tlsConfig, err
}

func main() {
	brokerList := flag.String("broker-list", "ut-kafka-0.ut-kafka-headless.default.svc.cluster.local:9092", "Comma separated list of brokers")
	topic := flag.String("kafka-topic", "clusterA", "Topic name")
	debug := flag.String("debug", "no", "debug yes/no")
	dumpkv := flag.String("dump-kv", "no", "dump kv yes/no")
	user := flag.String("user", "bitnami", "dump kv yes/no")
	key := flag.String("key", "", "Key to lookup")
	keyList := flag.String("key-list", "", "Comma separated list of keys to lookup")
	timeout := flag.Int("time-out", 15, "timeout in seconds")
	flag.Parse()
	if *key == "" && *keyList == "" {
		log.Fatalf("Need to specify key or key-list")
	}

	keySet := strings.Split(*keyList, ",")
	if *debug == "yes" {
		sarama.Logger = log.New(os.Stdout, "[Sarama] ", log.LstdFlags)
	}
	brokers := strings.Split(*brokerList, ",")
	tlsConfig, err := NewTLSConfig("/certs/kafka-client.crt",
		"/certs/kafka-client.key",
		"/certs/ca.crt")

	if err != nil {
		log.Fatal(err)
	}

	tlsConfig.InsecureSkipVerify = true
	consumerConfig := sarama.NewConfig()
	consumerConfig.Net.TLS.Enable = true
	if *user != "none" {
		consumerConfig.Net.SASL.Enable = true
		consumerConfig.Net.SASL.User = "user"
		consumerConfig.Net.SASL.Password = "bitnami"
	}

	consumerConfig.Net.TLS.Config = tlsConfig

	client, err := sarama.NewClient(brokers, consumerConfig)
	if err != nil {
		log.Fatalf("unable to create kafka client: %q", err)
	}

	consumer, err := sarama.NewConsumerFromClient(client)
	if err != nil {
		log.Fatal(err)
	}
	defer consumer.Close()
	partitionConsumer, err := consumer.ConsumePartition(*topic, 0, sarama.OffsetOldest)
	if err != nil {
		log.Fatal(err)
	}

	kv := make(map[string]bool)
	to := time.Duration(*timeout)
looper:
	for {
		select {
		case <-time.After(to * time.Second):
			break looper
		case m, ok := <-partitionConsumer.Messages():
			if !ok {
				break looper
			}

			if m.Value == nil || string(m.Value) == "" {
				delete(kv, string(m.Key))
			} else {
				kv[string(m.Key)] = true
			}

		}
	}

	if *key != "" {
		if kv[*key] {
			fmt.Printf("%s found\n", *key)
		} else {
			fmt.Printf("%s missing\n", *key)
		}
		return
	}

	for _, k := range keySet {
		if !kv[k] {
			fmt.Printf("%s missing\n", k)
			return
		}
	}

	if len(keySet) == len(kv) {
		fmt.Printf("Got exact match with %d items\n", len(keySet))
		return
	}

	fmt.Printf("%d items found\n", len(keySet))
	if *dumpkv == "yes" {
		fmt.Printf("All items: %+v\n", kv)
	}
}
