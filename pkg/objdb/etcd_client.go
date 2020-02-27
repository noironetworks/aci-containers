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
	"path"
	"time"

	"golang.org/x/net/context"

	log "github.com/sirupsen/logrus"
	"github.com/coreos/etcd/client"
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
	client client.Client // etcd client
	kapi    client.KeysAPI
	root   string
}

// Max retry count
const maxEtcdRetries = 10

// Initialize the etcd client
func NewClient(endpoints []string, root string) (API, error) {
	var err error
	var ec = new(EtcdClient)

	// Setup default url
	if len(endpoints) == 0 {
		return nil, errors.New("No endpoint specified")
	}

	etcdConfig := client.Config{
		Endpoints:   endpoints,
	}

	// Create a new client
	ec.client, err = client.New(etcdConfig)
	if err != nil {
		log.Fatalf("Error creating etcd client. Err: %v", err)
		return nil, err
	}

	// create keys api
	ec.kapi = client.NewKeysAPI(ec.client)

	// Make sure we can read from etcd
	_, err = ec.kapi.Get(context.Background(), "/", &client.GetOptions{Recursive: true, Sort: true})
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
	resp, err := ec.kapi.Get(ctx, keyName, &client.GetOptions{})
	if err != nil {
		log.Errorf("Error getting key %s. Err: %v", keyName, err)
		return err
	}

	// Parse JSON response
	if err := json.Unmarshal([]byte(resp.Node.Value), retVal); err != nil {
		log.Errorf("Error parsing object %s, Err %v", resp.Node.Value, err)
		return err
	}

	return nil
}

func (ec *EtcdClient) GetRaw(key string) ([]byte, error) {
	keyName := path.Join(ec.root, key)

	// Get the object from etcd client
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	resp, err := ec.kapi.Get(ctx, keyName, &client.GetOptions{})
	if err != nil {
		log.Errorf("Error getting key %s. Err: %v", keyName, err)
		return nil, err
	}

	return []byte(resp.Node.Value), nil
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
	_, err := ec.kapi.Set(ctx, keyName, string(jsonVal), nil)
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
	_, err := ec.kapi.Delete(ctx, keyName, nil)
	if err != nil {
		// Retry few times if cluster is unavailable
		if err != nil {
			log.Errorf("Error removing key %s, Err: %v", keyName, err)
			return err
		}
	}

	return nil
}
