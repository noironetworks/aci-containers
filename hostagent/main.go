// Copyright 2016 Cisco Systems, Inc.
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
	"errors"
	"flag"
	"net"
	"net/rpc"
	goruntime "runtime"
	"sync"
	"time"

	"github.com/Sirupsen/logrus"

	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/client/cache"
	clientset "k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset"
	"k8s.io/kubernetes/pkg/client/restclient"
	"k8s.io/kubernetes/pkg/client/unversioned/clientcmd"
	"k8s.io/kubernetes/pkg/controller"
	"k8s.io/kubernetes/pkg/controller/informers"
	"k8s.io/kubernetes/pkg/runtime"
	"k8s.io/kubernetes/pkg/util/wait"
	"k8s.io/kubernetes/pkg/watch"
)

var (
	log        = logrus.New()
	kubeconfig = flag.String("kubeconfig", "", "absolute path to the kubeconfig file")
	nodename   = flag.String("node", "", "Name of current node")
	network    = flag.String("cninetwork", "opflex-k8s-network", "Name of CNI network")

	metadataDir = flag.String("cnimetadatadir", "/var/lib/aci-containers/", "Directory containing OpFlex CNI metadata")
	endpointDir = flag.String("endpointdir", "/var/lib/opflex-agent-ovs/endpoints/", "Directory for writing OpFlex endpoint metadata")
	serviceDir  = flag.String("servicedir", "/var/lib/opflex-agent-ovs/services/", "Directory for writing OpFlex anycast service metadata")

	vrfTenant = flag.String("vrftenant", "common", "ACI tenant containing the VRF for kubernetes")
	vrf       = flag.String("vrf", "kubernetes-vrf", "ACI VRF name for for kubernetes")
	defaultEg = flag.String("default-endpoint-group", "", "Default endpoint group annotation value")
	defaultSg = flag.String("default-security-group", "", "Default security group annotation value")

	serviceIface     = flag.String("serviceIface", "eth2", "Interface for external service traffic")
	serviceIfaceVlan = flag.Uint("serviceIfaceVlan", 4003, "VLAN for service interface traffic")
	serviceIfaceMac  = flag.String("serviceIfaceMac", "", "MAC address to advertise in response to service interface IP address discovery requests")
	serviceIfaceIp   = flag.String("serviceIfaceIp", "", "IP address to advertise on the service interface")

	ovsDbSock    = flag.String("ovsDbSock", "/var/run/openvswitch/db.sock", "OVS DB socket to connect to")
	intBrName    = flag.String("intBridge", "br-int", "Integration bridge")
	accessBrName = flag.String("accessBridge", "br-access", "Access bridge")
	mtu          = flag.Int("mtu", 1500, "Interface MTU for interface configuration")

	indexMutex     = &sync.Mutex{}
	opflexEps      = make(map[string]*opflexEndpoint)
	opflexServices = make(map[string]*opflexService)

	podInformer       cache.SharedIndexInformer
	endpointsInformer cache.SharedIndexInformer
	serviceInformer   cache.SharedIndexInformer

	syncEnabled = false
)

func init() {
	// this ensures that main runs only on main thread (thread group leader).
	// since namespace ops (unshare, setns) are done for a single thread, we
	// must ensure that the goroutine does not jump from OS thread to thread
	goruntime.LockOSThread()
}

func initPodInformer(kubeClient *clientset.Clientset) {
	podInformer = informers.NewPodInformer(kubeClient,
		controller.NoResyncPeriodFunc())
	podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    podAdded,
		UpdateFunc: podUpdated,
		DeleteFunc: podDeleted,
	})

	go podInformer.GetController().Run(wait.NeverStop)
	go podInformer.Run(wait.NeverStop)
}

func initEndpointsInformer(kubeClient *clientset.Clientset) {
	endpointsInformer = cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options api.ListOptions) (runtime.Object, error) {
				return kubeClient.Core().Endpoints(api.NamespaceAll).List(options)
			},
			WatchFunc: func(options api.ListOptions) (watch.Interface, error) {
				return kubeClient.Core().Endpoints(api.NamespaceAll).Watch(options)
			},
		},
		&api.Endpoints{},
		controller.NoResyncPeriodFunc(),
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	endpointsInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    endpointsChanged,
		UpdateFunc: endpointsUpdated,
		DeleteFunc: endpointsChanged,
	})

	go endpointsInformer.GetController().Run(wait.NeverStop)
	go endpointsInformer.Run(wait.NeverStop)
}

func initServiceInformer(kubeClient *clientset.Clientset) {
	serviceInformer = cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options api.ListOptions) (runtime.Object, error) {
				return kubeClient.Core().Services(api.NamespaceAll).List(options)
			},
			WatchFunc: func(options api.ListOptions) (watch.Interface, error) {
				return kubeClient.Core().Services(api.NamespaceAll).Watch(options)
			},
		},
		&api.Service{},
		controller.NoResyncPeriodFunc(),
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	serviceInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    serviceAdded,
		UpdateFunc: serviceUpdated,
		DeleteFunc: serviceDeleted,
	})

	go serviceInformer.GetController().Run(wait.NeverStop)
	go serviceInformer.Run(wait.NeverStop)
}

func initEpRPC() error {
	rpc.Register(NewEpRPC())

	l, err := net.Listen("tcp", "127.0.0.1:4242")
	if err != nil {
		log.Error("Could not listen to rpc port: ", err)
		return err
	}

	go rpc.Accept(l)
	return nil
}

func main() {
	flag.Parse()

	if nodename == nil || *nodename == "" {
		err := errors.New("Node Name not specified")
		log.Error(err.Error())
		panic(err.Error())
	}

	log.WithFields(logrus.Fields{
		"kubeconfig": *kubeconfig,
		"nodename":   *nodename,
	}).Info("Starting")

	var config *restclient.Config
	var err error
	if kubeconfig != nil {
		// use kubeconfig file from command line
		config, err = clientcmd.BuildConfigFromFlags("", *kubeconfig)
		if err != nil {
			panic(err.Error())
		}
	} else {
		// creates the in-cluster config
		config, err = restclient.InClusterConfig()
		if err != nil {
			panic(err.Error())
		}
	}

	// creates the client
	kubeClient, err := clientset.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}

	var wg sync.WaitGroup
	wg.Add(1)

	initPodInformer(kubeClient)

	initEndpointsInformer(kubeClient)
	initServiceInformer(kubeClient)

	err = initEpRPC()
	if err != nil {
		panic(err.Error())
	}

	go func() {
		time.Sleep(time.Second * 5)
		syncEnabled = true
		indexMutex.Lock()
		defer indexMutex.Unlock()
		syncServices()
		syncEps()
	}()

	wg.Wait()
}
