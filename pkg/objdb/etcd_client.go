/***
Copyright 2018 Cisco Systems Inc. All rights reserved.

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

package objdb

import (
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"time"

	"golang.org/x/net/context"

	log "github.com/sirupsen/logrus"
	clientv3 "go.etcd.io/etcd/client/v3"
)

type API interface {
	// Get a Key from conf store
	GetObj(key string, retValue interface{}) error
	GetRaw(key string) ([]byte, error)

	// Set a key in conf store
	SetObj(key string, value interface{}) error
	SetRaw(key string, value []byte) error

	// Remove an object
	DelObj(key string) error
}

// EtcdClient has etcd client state
type EtcdClient struct {
	client *clientv3.Client // etcd client
	kv     clientv3.KV
	root   string
}

// Initialize the etcd client
func NewClient(endpoints []string, root string) (API, error) {
	var err error
	var ec = new(EtcdClient)

	// Setup default url
	if len(endpoints) == 0 {
		return nil, errors.New("No endpoint specified")
	}

	etcdConfig := clientv3.Config{
		Endpoints: endpoints,
	}

	// Create a new client
	ec.client, err = clientv3.New(etcdConfig)
	if err != nil {
		log.Fatalf("Error creating etcd client. Err: %v", err)
		return nil, err
	}

	// create key-value
	ec.kv = clientv3.NewKV(ec.client)

	// Make sure we can read from etcd
	_, err = ec.kv.Get(context.Background(), "/", clientv3.WithSort(clientv3.SortByKey, clientv3.SortAscend))
	if err != nil {
		log.Errorf("Failed to connect to etcd. Err: %v", err)
		return nil, err
	}

	ec.root = root
	return ec, nil
}

// GetObj Get an object
func (ec *EtcdClient) GetObj(key string, retVal interface{}) error {
	keyName := path.Join(ec.root, key)

	// Get the object from etcd client
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	resp, err := ec.kv.Get(ctx, keyName)
	if err != nil {
		log.Errorf("Error getting key %s. Err: %v", keyName, err)
		return err
	}

	if len(resp.Kvs) <= 0 {
		log.Errorf("Returned empty value for key : %s", keyName)
		return fmt.Errorf("Returned empty value for key : %s", keyName)
	}
	// Parse JSON response
	if err := json.Unmarshal(resp.Kvs[0].Value, retVal); err != nil {
		log.Errorf("Error parsing object %s, Err %v", resp.Kvs[0].Value, err)
		return err
	}

	return nil
}

func (ec *EtcdClient) GetRaw(key string) ([]byte, error) {
	keyName := path.Join(ec.root, key)

	// Get the object from etcd client
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	resp, err := ec.kv.Get(ctx, keyName)
	if err != nil {
		log.Errorf("Error getting key %s. Err: %v", keyName, err)
		return nil, err
	}

	if len(resp.Kvs) <= 0 {
		log.Errorf("Returned empty value for key : %s", keyName)
		return nil, fmt.Errorf("Returned empty value for key : %s", keyName)
	}

	return resp.Kvs[0].Value, nil
}

// Recursive function to look thru each directory and get the files
// SetObj Save an object, create if it doesnt exist
func (ec *EtcdClient) SetObj(key string, value interface{}) error {
	// JSON format the object
	jsonVal, err := json.Marshal(value)
	if err != nil {
		log.Errorf("Json conversion error. Err %v", err)
		return err
	}

	return ec.SetRaw(key, jsonVal)
}

func (ec *EtcdClient) SetRaw(key string, jsonVal []byte) error {
	keyName := path.Join(ec.root, key)

	log.Infof("=== key: %s val: %s ===", key, jsonVal)

	// Set it via etcd client
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := ec.kv.Put(ctx, keyName, string(jsonVal), nil)
	if err != nil {
		log.Errorf("Error setting key %s, Err: %v", keyName, err)
		return err
	}

	return nil
}

// DelObj Remove an object
func (ec *EtcdClient) DelObj(key string) error {
	keyName := path.Join(ec.root, key)

	// Remove it via etcd client
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := ec.kv.Delete(ctx, keyName, nil)
	if err != nil {
		log.Errorf("Error removing key %s, Err: %v", keyName, err)
		return err
	}

	return nil
}
