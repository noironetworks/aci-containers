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
	"net"
	"net/http"
	"time"

	"code.cloudfoundry.org/cfhttp"
	"github.com/coreos/etcd/client"
)

func NewEtcdClient(etcdUrl string, caCertFile string, clientCertFile string,
	clientKeyFile string) (client.Client, error) {
	tlsConfig, err := cfhttp.NewTLSConfig(clientCertFile, clientKeyFile, caCertFile)
	if err != nil {
		return nil, err
	}
	t := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		Dial: (&net.Dialer{
			// values taken from http.DefaultTransport
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).Dial,
		// value taken from http.DefaultTransport
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig:     tlsConfig,
	}
	cfg := client.Config{
		Endpoints: []string{etcdUrl},
		Transport: t,
		// set timeout per request to fail fast when the target endpoint is unavailable
		HeaderTimeoutPerRequest: time.Second,
	}
	return client.New(cfg)
}

const (
	ACI_KEY_BASE              = "/aci"
	APP_KEY_BASE              = "/aci/apps"
	CELL_KEY_BASE             = "/aci/cells"
	CONTROLLER_KEY_BASE       = "/aci/controller"
)

func FlattenNodes(nd *client.Node, nodes *client.Nodes) {
	if nd == nil {
		return
	}

	*nodes = append(*nodes, nd)
	for _, n := range nd.Nodes {
		FlattenNodes(n, nodes)
	}
}

func IsDeleteAction(action *string) bool {
	return (*action == "delete" || *action == "compareAndDelete" || *action == "expire")
}

func IsKeyNotFoundError(err error) bool {
	keyerr, ok := err.(client.Error)
	return ok && keyerr.Code == client.ErrorCodeKeyNotFound
}
