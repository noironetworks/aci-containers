// Copyright 2020 Cisco Systems, Inc.
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

package main

import (
	log "github.com/sirupsen/logrus"
	operatorclientset "github.com/noironetworks/aci-containers/pkg/acicontainersoperator/clientset/versioned"
	"github.com/noironetworks/aci-containers/pkg/controller"
	restclient "k8s.io/client-go/rest"
	"os"
	"os/signal"
	"syscall"
)

// Create K8s Client
func getOperatorClient() operatorclientset.Interface {

	restconfig, err := restclient.InClusterConfig()
	if err != nil {
		return nil
	}

	kubeClient, err := operatorclientset.NewForConfig(restconfig)
	if err != nil {
		log.Fatalf("Failed to intialize kube client %v", err)
	}

	log.Info("Successfully constructed k8s client")
	return kubeClient
}


func main() {
	// get the Kubernetes client for connectivity
	log.Debug("Initializing kubernetes client")
	client := getOperatorClient()
	if client == nil{
		log.Fatalf("Failed to intialize kube client", )
		return
	}

	cont := controller.NewAciContainersOperator(client)

	stopCh := make(chan struct{})
	defer close(stopCh)
	go cont.Run(stopCh)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM)
	signal.Notify(sig, syscall.SIGINT)
	<-sig
}