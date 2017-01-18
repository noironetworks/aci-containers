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
	"flag"
	"sync"

	"github.com/Sirupsen/logrus"

	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/apis/extensions"
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
	defaultEg  = flag.String("default-endpoint-group", "", "Default endpoint group annotation value")
	defaultSg  = flag.String("default-security-group", "", "Default security group annotation value")

	indexMutex = &sync.Mutex{}
	depPods    = make(map[string]string)

	kubeClient         *clientset.Clientset
	namespaceInformer  cache.SharedIndexInformer
	podInformer        cache.SharedIndexInformer
	endpointsInformer  cache.SharedIndexInformer
	serviceInformer    cache.SharedIndexInformer
	deploymentInformer cache.SharedIndexInformer
)

func initNamespaceInformer() {
	namespaceInformer = cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options api.ListOptions) (runtime.Object, error) {
				return kubeClient.Core().Namespaces().List(options)
			},
			WatchFunc: func(options api.ListOptions) (watch.Interface, error) {
				return kubeClient.Core().Namespaces().Watch(options)
			},
		},
		&api.Namespace{},
		controller.NoResyncPeriodFunc(),
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	namespaceInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    namespaceChanged,
		UpdateFunc: namespaceUpdated,
		DeleteFunc: namespaceChanged,
	})

	go namespaceInformer.GetController().Run(wait.NeverStop)
	go namespaceInformer.Run(wait.NeverStop)
}

func initPodInformer() {
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

func initEndpointsInformer() {
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

func initServiceInformer() {
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

func initDeploymentInformer() {
	deploymentInformer = cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options api.ListOptions) (runtime.Object, error) {
				return kubeClient.Extensions().Deployments(api.NamespaceAll).List(options)
			},
			WatchFunc: func(options api.ListOptions) (watch.Interface, error) {
				return kubeClient.Extensions().Deployments(api.NamespaceAll).Watch(options)
			},
		},
		&extensions.Deployment{},
		controller.NoResyncPeriodFunc(),
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	deploymentInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    deploymentAdded,
		UpdateFunc: deploymentUpdated,
		DeleteFunc: deploymentDeleted,
	})

	go deploymentInformer.GetController().Run(wait.NeverStop)
	go deploymentInformer.Run(wait.NeverStop)
}

func main() {
	flag.Parse()

	log.WithFields(logrus.Fields{
		"kubeconfig": *kubeconfig,
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
	kubeClient, err = clientset.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}

	var wg sync.WaitGroup
	wg.Add(1)

	initNamespaceInformer()
	initDeploymentInformer()
	initPodInformer()

	initEndpointsInformer()
	initServiceInformer()

	//	go func() {
	//		time.Sleep(time.Second * 5)
	//		syncEnabled = true
	//		indexMutex.Lock()
	//		defer indexMutex.Unlock()
	//		syncServices()
	//		syncEps()
	//	}()

	wg.Wait()
}
