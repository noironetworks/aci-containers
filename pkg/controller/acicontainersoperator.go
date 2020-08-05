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

package controller

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"reflect"
	"sync"
	"time"

	operators "github.com/noironetworks/aci-containers/pkg/acicontainersoperator/apis/aci.ctrl/v1alpha1"
	operatorclientset "github.com/noironetworks/aci-containers/pkg/acicontainersoperator/clientset/versioned"
	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	routesv1 "github.com/openshift/api/route/v1"
	routesClientset "github.com/openshift/client-go/route/clientset/versioned"
	log "github.com/sirupsen/logrus"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
)

// AciResources is a struct for handeling the resources of aci fabric
type AciResources struct {
	Deployment    *appsv1.Deployment
	HostDaemonset *appsv1.DaemonSet
	OvsDaemonset  *appsv1.DaemonSet
}

// Controller  here defines the Operator code handler which list watch the AciContainerOperator
// Object and apply the aci_deployment.yaml in the cluster after creation/updation

type Controller struct {
	Logger              *log.Entry
	indexMutex          sync.Mutex
	Operator_Clientset  operatorclientset.Interface
	K8s_Clientset       kubernetes.Interface
	Operator_Queue      workqueue.RateLimitingInterface
	Deployment_Queue    workqueue.RateLimitingInterface
	Daemonset_Queue     workqueue.RateLimitingInterface
	Node_Queue          workqueue.RateLimitingInterface
	Route_Queue         workqueue.RateLimitingInterface
	Informer_Operator   cache.SharedIndexInformer
	Informer_Deployment cache.SharedIndexInformer
	Informer_Daemonset  cache.SharedIndexInformer
	Informer_Node       cache.SharedIndexInformer
	Informer_Route      cache.SharedIndexInformer
	Resources           AciResources
	DnsOperatorClient   client.Client             // This client is specific dnsopenshift operator
	RoutesClient        routesClientset.Interface // This client is specific routes openshift operator
	Openshiftflavor     bool
	routes              map[string]bool // local cache to check the routes
}

var Version = map[string]bool{
	"openshift-4.3": true,
	"cloud": true,
	"openshift-4.4-esx": true,
	"openshift-4.4-openstack": true,
}
var Dnsoper = map[string]bool{
	"openshift-4.3": true,
}
const aciContainersController = "aci-containers-controller"
const aciContainersHostDaemonset = "aci-containers-host"
const aciContainersOvsDaemonset = "aci-containers-openvswitch"

func NewAciContainersOperator(
	acicnioperatorclient operatorclientset.Interface,
	k8sclient kubernetes.Interface) *Controller {

	log.Info("Setting up the Queue")
	operator_queue := workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter())
	deployment_queue := workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter())
	daemonset_queue := workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter())
	node_queue := workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter())
	route_queue := workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter())

	log.Info("Intializing Informer")

	aci_operator_informer := cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				return acicnioperatorclient.AciV1alpha1().AciContainersOperators(os.Getenv("SYSTEM_NAMESPACE")).List(options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				return acicnioperatorclient.AciV1alpha1().AciContainersOperators(os.Getenv("SYSTEM_NAMESPACE")).Watch(options)
			},
		},
		&operators.AciContainersOperator{},
		0,
		cache.Indexers{},
	)

	aci_deployment_informer := cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				return k8sclient.AppsV1().Deployments(os.Getenv("SYSTEM_NAMESPACE")).List(options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				return k8sclient.AppsV1().Deployments(os.Getenv("SYSTEM_NAMESPACE")).Watch(options)
			},
		},
		&appsv1.Deployment{},
		0,
		cache.Indexers{},
	)

	aci_daemonset_informer := cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				return k8sclient.AppsV1().DaemonSets(os.Getenv("SYSTEM_NAMESPACE")).List(options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				return k8sclient.AppsV1().DaemonSets(os.Getenv("SYSTEM_NAMESPACE")).Watch(options)
			},
		},
		&appsv1.DaemonSet{},
		0,
		cache.Indexers{},
	)
	node_informer := cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				return k8sclient.CoreV1().Nodes().List(options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				return k8sclient.CoreV1().Nodes().Watch(options)
			},
		},
		&v1.Node{},
		0,
		cache.Indexers{},
	)
	var routesClient routesClientset.Interface
	var route_informer cache.SharedIndexInformer
	flavor := os.Getenv("ACC_PROVISION_FLAVOR")
	opflavor := false
	// intializes route watchers for Openshift flavor
	if Dnsoper[flavor] {
		restconfig, err := restclient.InClusterConfig()
		if err != nil {
			log.Error("Failed to intialize the restConfig: ", err)
		} else {
			routesClient, err = routesClientset.NewForConfig(restconfig)
			if err != nil {
				log.Error("Failed to intialize OpenshiftRoute client: ", err)
			} else {
				opflavor = true
				log.Info("Intializing the route informer")
				route_informer = cache.NewSharedIndexInformer(
					&cache.ListWatch{
						ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
							return routesClient.RouteV1().Routes(metav1.NamespaceAll).List(options)
						},
						WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
							return routesClient.RouteV1().Routes(metav1.NamespaceAll).Watch(options)
						},
					},
					&routesv1.Route{},
					time.Duration(5)*time.Minute,
					cache.Indexers{},
				)
			}
		}

	}

	controller := &Controller{
		Logger:              log.NewEntry(log.New()),
		Operator_Clientset:  acicnioperatorclient,
		K8s_Clientset:       k8sclient,
		Informer_Operator:   aci_operator_informer,
		Informer_Deployment: aci_deployment_informer,
		Informer_Daemonset:  aci_daemonset_informer,
		Informer_Node:       node_informer,
		Informer_Route:      route_informer,
		Operator_Queue:      operator_queue,
		Deployment_Queue:    deployment_queue,
		Daemonset_Queue:     daemonset_queue,
		Node_Queue:          node_queue,
		Route_Queue:         route_queue,
		Resources:           AciResources{},
		DnsOperatorClient:   nil,
		RoutesClient:        routesClient,
		Openshiftflavor:     opflavor,
		routes:              make(map[string]bool),
	}

	log.Info("Adding Event Handlers")
	aci_operator_informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			key, err := cache.MetaNamespaceKeyFunc(obj)
			log.Debug("Added acicontainersoperator  key: ", key)
			if err == nil {
				operator_queue.Add(key)
			}
		},
		UpdateFunc: func(prevObj, currentObj interface{}) {
			key, err := cache.MetaNamespaceKeyFunc(currentObj)
			log.Debug("Updated acicontainersoperator key: ", key)
			if err == nil {
				operator_queue.Add(key)
			}
		},
		DeleteFunc: func(obj interface{}) {
			key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
			log.Debug("Deleted acicontainersoperator key: ", key)
			if err == nil {
				operator_queue.Add(key)
			}
		},
	})

	aci_deployment_informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			dep_obj := obj.(*appsv1.Deployment)
			if dep_obj.Name == aciContainersController {
				key, err := cache.MetaNamespaceKeyFunc(obj)
				log.Debug("Added Deployment key	:", key)
				if err == nil {
					deployment_queue.Add(key)
				}
			}
		},
		UpdateFunc: func(prevObj, currentObj interface{}) {
			dep_obj := currentObj.(*appsv1.Deployment)
			if dep_obj.Name == aciContainersController {
				log.Debug("In UpdateFunc for Deployment")
				controller.handledeploymentUpdate(prevObj, currentObj, deployment_queue)
			}
		},
		DeleteFunc: func(obj interface{}) {
			dep_obj := obj.(*appsv1.Deployment)
			if dep_obj.Name == aciContainersController {
				key, err := cache.MetaNamespaceKeyFunc(obj)
				log.Debug("Deleted Deployment key is :", key)
				if err == nil {
					deployment_queue.Add(key)
				}
			}
		},
	})

	aci_daemonset_informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			key, err := cache.MetaNamespaceKeyFunc(obj)
			log.Debug("The daemonset key: ", key)
			if err == nil {
				daemonset_queue.Add(key)
			}
		},
		UpdateFunc: func(prevObj, currentObj interface{}) {
			log.Debug("In UpdateFunc for Daemonset")
			controller.handledaemonsetUpdate(prevObj, currentObj, daemonset_queue)
		},
		DeleteFunc: func(obj interface{}) {
			key, err := cache.MetaNamespaceKeyFunc(obj)
			log.Debug("Deleted daemonset key is :", key)
			if err == nil {
				daemonset_queue.Add(key)
			}
		},
	})
	node_informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			key, err := cache.MetaNamespaceKeyFunc(obj)
			log.Debug("The Node key: ", key)
			if err == nil {
				node_queue.Add(key)
			}
		},
		UpdateFunc: func(prevObj, currentObj interface{}) {
			//@TODO need to handle update
			log.Debug("In UpdateFunc for Node")
			controller.handleNodeUpdate(prevObj, currentObj, node_queue)
		},
		DeleteFunc: func(obj interface{}) {
			key, err := cache.MetaNamespaceKeyFunc(obj)
			log.Debug("Deleted Node key is :", key)
			if err == nil {
				node_queue.Add(key)
			}
		},
	})
	if opflavor { //openshift flavor
		route_informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				key, err := cache.MetaNamespaceKeyFunc(obj)
				log.Debug("Add Route key: ", key)
				if err == nil {
					route_queue.Add(key)
				}
			},
			UpdateFunc: func(prevObj, currentObj interface{}) {
				//@TODO need to handle update
				log.Debug("In UpdateFunc for Route")
			},
			DeleteFunc: func(obj interface{}) {
				key, err := cache.MetaNamespaceKeyFunc(obj)
				log.Debug("Deleted route key: ", key)
				if err == nil {
					route_queue.Add(key)
				}
			},
		})
	}

	return controller
}

func (c *Controller) handledeploymentUpdate(oldobj interface{}, newobj interface{}, queue workqueue.RateLimitingInterface) {
	old_dep := oldobj.(*appsv1.Deployment)
	new_dep := newobj.(*appsv1.Deployment)

	if !reflect.DeepEqual(old_dep.OwnerReferences, new_dep.OwnerReferences) {
		key, err := cache.MetaNamespaceKeyFunc(newobj)
		if err == nil {
			queue.Add(key)
		}
	} else {
		log.Info("Owner Reference is intact for ", new_dep.Name)
	}
}

func (c *Controller) handledaemonsetUpdate(oldobj interface{}, newobj interface{}, queue workqueue.RateLimitingInterface) {
	old_ds := oldobj.(*appsv1.DaemonSet)
	new_ds := newobj.(*appsv1.DaemonSet)

	if !reflect.DeepEqual(old_ds.OwnerReferences, new_ds.OwnerReferences) {
		key, err := cache.MetaNamespaceKeyFunc(newobj)
		if err == nil {
			queue.Add(key)
		}
	} else {
		log.Info("Owner Reference is intact for ", new_ds.Name)
	}
}

func (c *Controller) GetAciContainersOperatorCR() (*operators.AciContainersOperator, error) {
	var options metav1.GetOptions
	acicnioperator, er := c.Operator_Clientset.AciV1alpha1().AciContainersOperators(os.Getenv("SYSTEM_NAMESPACE")).Get("acicnioperator", options)
	if er != nil {
		return acicnioperator, er
	}
	return acicnioperator, nil
}

func (c *Controller) CreateAciContainersOperatorCR() error {
	log.Info("Reading the Config Map providing CR")

	obj := &operators.AciContainersOperator{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "acicnioperator",
			Namespace: os.Getenv("SYSTEM_NAMESPACE")},
	}

	obj.Status.Status = true //Setting it default true

	raw, err := ioutil.ReadFile("/usr/local/etc/aci-containers/aci-operator.conf")
	if err != nil {
		log.Error(err)
		return err
	}

	log.Debug("acicnioperator CR is ", string(raw))


	log.Info("Unmarshalling the Config-Map...")
	err = json.Unmarshal(raw, &obj.Spec)
	if err != nil {
		log.Error(err)
		return err
	}

	log.Info("Unmarshalling Successful....")
	log.Debug("acicnioperator CR recieved is", (obj.Spec))
	if err = wait.PollInfinite(time.Second*2, func() (bool, error) {
		_, er := c.Operator_Clientset.AciV1alpha1().AciContainersOperators(os.Getenv("SYSTEM_NAMESPACE")).Create(obj)
		if er != nil {
			if errors.IsAlreadyExists(er) { //Happens due to etcd timeout
				log.Info(er)
				return true, nil
			} else {
				log.Info("Waiting for CRD to get registered to etcd....: ", err)
				return false, nil
			}
		}
		return true, nil
	}); err != nil {
		return err
	}
	return nil
}

func (c *Controller) Run(stopCh <-chan struct{}) {
	c.Logger.Info("Controller.Run: initiating")

	log.Info("Checking if acicnioperator CR already present")
	_, err := c.GetAciContainersOperatorCR()
	if err != nil {
		log.Info("Not Present ..Creating acicnioperator CR")

		er := c.CreateAciContainersOperatorCR()
		if er != nil {
			log.Error(err)
		}
	}
	if err == nil {

		log.Info("acicnioperator CR already present")
	}

	// Run informer to start watching and listening
	go c.Informer_Operator.Run(stopCh)
	go c.Informer_Deployment.Run(stopCh)
	go c.Informer_Daemonset.Run(stopCh)
	go c.Informer_Node.Run(stopCh)
	// Sync the current resources
	if !cache.WaitForCacheSync(stopCh, c.Informer_Operator.HasSynced,
		c.Informer_Deployment.HasSynced, c.Informer_Daemonset.HasSynced, c.Informer_Node.HasSynced) {
		utilruntime.HandleError(fmt.Errorf("Controller.Sync: Error syncing the cache"))
	}

	c.Logger.Info("Controller.Sync: Cache sync complete")

	// Run queue for each Informer
	go c.processQueue(c.Operator_Queue, c.Informer_Operator.GetIndexer(),
		func(obj interface{}) bool {
			return c.handleOperatorCreate(obj)
		},
		func(obj interface{}) bool {
			return c.handleOperatorDelete(obj)
		},
		stopCh)

	go c.processQueue(c.Deployment_Queue, c.Informer_Deployment.GetIndexer(),
		func(obj interface{}) bool {
			return c.handleDeploymentCreate(obj)
		}, func(obj interface{}) bool {
			return c.handleDeploymentDelete(obj)
		},
		stopCh)

	go c.processQueue(c.Daemonset_Queue, c.Informer_Daemonset.GetIndexer(),
		func(obj interface{}) bool {
			return c.handleDaemonsetCreate(obj)
		}, func(obj interface{}) bool {
			return c.handleDaemonsetDelete(obj)
		},
		stopCh)
	go c.processQueue(c.Node_Queue, c.Informer_Node.GetIndexer(),
		func(obj interface{}) bool {
			return c.handleNodeCreate(obj)
		}, func(obj interface{}) bool {
			return c.handleNodeDelete(obj)
		},
		stopCh)
	if c.Openshiftflavor {
		c.enableRouteInformer(stopCh)
	}
}

func (c *Controller) processQueue(queue workqueue.RateLimitingInterface,
	store cache.Store, createhandler func(interface{}) bool,
	deletehandler func(interface{}) bool,
	stopCh <-chan struct{}) {
	go wait.Until(func() {
		log.Info("Starting the handlers....")
		for {
			key, quit := queue.Get()
			if quit {
				break
			}
			var requeue bool
			switch key := key.(type) {
			case chan struct{}:
				close(key)
			case string:
				obj, exists, err := store.GetByKey(key)
				if err == nil && exists {
					log.Info("Controller.processNextItem: object Creation detected:", key)
					requeue = createhandler(obj)
				}

				if !exists {
					log.Info("Controller.processNextItem: object deleted detected:", key)
					deletehandler(key)
				}

			}
			if requeue {
				log.Info("Adding the key back to the queue ", key)
				queue.AddRateLimited(key)
			} else {
				queue.Forget(key)
			}
			queue.Done(key)
		}
	}, time.Second, stopCh)
	<-stopCh
	queue.ShutDown()
}

func (c *Controller) CheckOwnerReference(reference []metav1.OwnerReference) bool {
	for _, ownerRef := range reference {
		if ownerRef.Kind == "AciContainersOperator" {
			log.Debug("OwnerReference Already Present")
			return true
		}
	}
	return false
}

func (c *Controller) UpdateDeploymentOwnerReference(acicontainersoperator *operators.AciContainersOperator) bool {
	deploymentsClient := c.K8s_Clientset.AppsV1().Deployments(os.Getenv("SYSTEM_NAMESPACE"))
	if deploymentsClient == nil {
		log.Info("Error in Fetching deploymentsClient...")
		return true
	}

	c.Resources.Deployment, _ = deploymentsClient.Get(aciContainersController, metav1.GetOptions{})
	if c.Resources.Deployment == nil {
		log.Infof("%s deployment is nil..returning", aciContainersController)
		return false
	}

	if !c.CheckOwnerReference(c.Resources.Deployment.ObjectMeta.OwnerReferences) {
		c.Resources.Deployment.OwnerReferences = []metav1.OwnerReference{
			*metav1.NewControllerRef(acicontainersoperator, operators.SchemeGroupVersion.WithKind("AciContainersOperator")),
		}
		_, err := deploymentsClient.Update(c.Resources.Deployment)
		if err != nil {
			log.Error(err.Error())
			return false
		}
		log.Infof("Successfully updated owner reference to the %s deployment", aciContainersController)
	} else {
		log.Infof("Owner reference is intact for %s", aciContainersController)
	}

	return true
}

func (c *Controller) UpdateHostDaemonsetOwnerReference(acicontainersoperator *operators.AciContainersOperator) bool {
	hostdaemonsetclient := c.K8s_Clientset.AppsV1().DaemonSets(os.Getenv("SYSTEM_NAMESPACE"))
	if hostdaemonsetclient == nil {
		log.Info("Error in Fetching hostdaemonsetclient...")
		return true
	}

	c.Resources.HostDaemonset, _ = hostdaemonsetclient.Get(aciContainersHostDaemonset, metav1.GetOptions{})
	if c.Resources.HostDaemonset == nil {
		log.Infof("%s daemonset is nil.....returning", aciContainersHostDaemonset)
		return false
	}

	if !c.CheckOwnerReference(c.Resources.HostDaemonset.OwnerReferences) {
		c.Resources.HostDaemonset.OwnerReferences = []metav1.OwnerReference{
			*metav1.NewControllerRef(acicontainersoperator, operators.SchemeGroupVersion.WithKind("AciContainersOperator")),
		}

		_, err := hostdaemonsetclient.Update(c.Resources.HostDaemonset)
		if err != nil {
			log.Error(err.Error())
			return false
		}
		log.Infof("Successfully updated owner reference to the %s daemonset", aciContainersHostDaemonset)
	} else {
		log.Infof("Owner reference is intact for %s", aciContainersHostDaemonset)
	}

	return true

}

func (c *Controller) UpdateOvsDaemonsetOwnerReference(acicontainersoperator *operators.AciContainersOperator) bool {
	ovsdaemonsetclient := c.K8s_Clientset.AppsV1().DaemonSets(os.Getenv("SYSTEM_NAMESPACE"))
	if ovsdaemonsetclient == nil {
		log.Infof("Error in Fetching ovsdaemonsetclient...")
		return true
	}

	c.Resources.OvsDaemonset, _ = ovsdaemonsetclient.Get(aciContainersOvsDaemonset, metav1.GetOptions{})
	if c.Resources.OvsDaemonset == nil {
		log.Infof("%s daemonset is nil.....returning", aciContainersOvsDaemonset)
		return false
	}

	if !c.CheckOwnerReference(c.Resources.OvsDaemonset.OwnerReferences) {
		c.Resources.OvsDaemonset.OwnerReferences = []metav1.OwnerReference{
			*metav1.NewControllerRef(acicontainersoperator, operators.SchemeGroupVersion.WithKind("AciContainersOperator")),
		}

		_, err := ovsdaemonsetclient.Update(c.Resources.OvsDaemonset)
		if err != nil {
			log.Error(err.Error())
			return false
		}
		log.Infof("Successfully updated owner reference to the %s daemonset", aciContainersOvsDaemonset)
	} else {
		log.Infof("Owner reference is intact for %s", aciContainersOvsDaemonset)
	}
	return true
}

func (c *Controller) handleOperatorCreate(obj interface{}) bool {

	log.Info("OperatorHandler.ObjectCreated")

	acicontainersoperator := obj.(*operators.AciContainersOperator)

	log.Debug(acicontainersoperator.Spec.Config)

	if acicontainersoperator.Spec.Config == "" {
		log.Info("acicnioperator CR config is Nil...Exiting")
		acicontainersoperator.Status.Status = false
		_, er := c.Operator_Clientset.AciV1alpha1().AciContainersOperators(os.Getenv("SYSTEM_NAMESPACE")).Update(acicontainersoperator)
		if er != nil{
			log.Error(er)
		}
		return false
	}

	dec, err := base64.StdEncoding.DecodeString(acicontainersoperator.Spec.Config)
	if err != nil {
		log.Error(err)
		return true
	}

	f, err := os.Create("aci-deployment.yaml")
	if err != nil {
		log.Error(err)
		return true
	}
	if _, err := f.Write(dec); err != nil {
		log.Error(err)
		return true
	}
	if err := f.Sync(); err != nil {
		log.Error(err)
		return true
	}
	if err := f.Close(); err != nil {
		log.Error(err)
		return true
	}

	log.Info("Platform flavor is ", acicontainersoperator.Spec.Flavor)

	if Version[acicontainersoperator.Spec.Flavor] {

		clusterConfig := &configv1.Network{
			TypeMeta:   metav1.TypeMeta{APIVersion: configv1.GroupVersion.String(), Kind: "Network"},
			ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
		}

		cfg, err := config.GetConfig()
		scheme := runtime.NewScheme()
		err = configv1.Install(scheme)
		if err != nil {
			log.Error(err)
			return true
		}

		rclient, err := client.New(cfg, client.Options{Scheme: scheme})
		if err != nil {
			return true
		}

		err = rclient.Get(context.TODO(), types.NamespacedName{
			Name: "cluster",
		}, clusterConfig)

		if err != nil {
			log.Info(err)
			return true
		}

		log.Info("Current Configuration Spec of type Network is  ", clusterConfig.Spec)

		log.Info("Current status of type Network is ", clusterConfig.Status)

		if !reflect.DeepEqual(clusterConfig.Status.ClusterNetwork, clusterConfig.Spec.ClusterNetwork) ||
			!reflect.DeepEqual(clusterConfig.Status.NetworkType, clusterConfig.Spec.NetworkType) ||
			!reflect.DeepEqual(clusterConfig.Status.NetworkType, clusterConfig.Spec.NetworkType) {

			log.Info("Updating status field of openshift resource of type network  ....")

			clusterConfig.Status.ClusterNetwork = clusterConfig.Spec.ClusterNetwork
			clusterConfig.Status.NetworkType = clusterConfig.Spec.NetworkType
			clusterConfig.Status.ServiceNetwork = clusterConfig.Spec.ServiceNetwork

			log.Info("Updated clusterConfig.Status is ", clusterConfig.Status)

			ctx := context.TODO()
			err = rclient.Update(ctx, clusterConfig)
			if err != nil {
				log.Info(err)
				return true
			}
		}

	}

	log.Info("Applying Aci Deployment")

	//Currently the Kubectl version is v.1.14. This will be updated by the acc-provision according
	//to the platform specification

	cmd := exec.Command("kubectl", "apply", "-f", "aci-deployment.yaml")
	log.Debug(cmd)
	_, err = cmd.Output()
	if err != nil {
		log.Error(err)
		return true
	}

	log.Info("Adding Aci Operator OwnerRefrence to resources ....")

	c.indexMutex.Lock()
	if !(c.UpdateDeploymentOwnerReference(acicontainersoperator)) {
		log.Info("Error Updating Deployment Owner Reference")
		c.indexMutex.Unlock()
		return true
	}

	if !(c.UpdateHostDaemonsetOwnerReference(acicontainersoperator)) {
		log.Info("Error Updating  HostAgent Daemonset Owner Reference")
		c.indexMutex.Unlock()
		return true
	}

	if !(c.UpdateOvsDaemonsetOwnerReference(acicontainersoperator)) {
		log.Info("Error Updating Ovs Daemonset Owner Reference")
		c.indexMutex.Unlock()
		return true
	}

	c.indexMutex.Unlock()
	return false
}

func (c *Controller) handleOperatorDelete(obj interface{}) bool {
	log.Info("ACI CNI OperatorHandler.ObjectDeleted")
	return false
}

func (c *Controller) handleDeploymentCreate(obj interface{}) bool {
	acicontainersoperator, err := c.GetAciContainersOperatorCR()
	if err != nil {
		log.Info("Not Present ..Creating acicnioperator CR")
		return true
	}
	c.indexMutex.Lock()
	if !(c.UpdateDeploymentOwnerReference(acicontainersoperator)) {
		log.Info("Error Updating Deployment Owner Reference")
		c.indexMutex.Unlock()
		return true
	}
	c.indexMutex.Unlock()
	return false
}

func (c *Controller) handleDeploymentDelete(obj interface{}) bool {
	log.Infof("%s Deployment Deleted", aciContainersController)
	return false
}

func (c *Controller) handleDaemonsetCreate(obj interface{}) bool {
	daemonset := obj.(*appsv1.DaemonSet)

	acicontainersoperator, err := c.GetAciContainersOperatorCR()
	if err != nil {
		log.Info("Not Present ..Creating acicnioperator CR")
		return true
	}

	c.indexMutex.Lock()
	if daemonset.Name == aciContainersHostDaemonset {
		if !(c.UpdateHostDaemonsetOwnerReference(acicontainersoperator)) {
			log.Info("Error Updating HostDaemonset Owner Reference")
			c.indexMutex.Unlock()
			return true
		}
	} else {
		if !(c.UpdateOvsDaemonsetOwnerReference(acicontainersoperator)) {
			log.Info("Error Updating OvsDaemonset Owner Reference")
			c.indexMutex.Unlock()
			return true
		}
	}
	c.indexMutex.Unlock()
	return false
}

func (c *Controller) handleDaemonsetDelete(obj interface{}) bool {
	log.Infof("aci-containers Daemonset Deleted")
	return false
}

// intialize the dnsoperator client,
// computes the dnsSpec.
// local cache for all the routes will be updated.
//  if there is change in the dns Spec, triggers the update
func (c *Controller) updatednsOperator() error {
	log.Info("Update dnsoperator cr")
	dnsInfo := &operatorv1.DNS{
		TypeMeta:   metav1.TypeMeta{APIVersion: operatorv1.GroupVersion.String(), Kind: "DNS"},
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
	}
	if c.DnsOperatorClient == nil {
		cfg, err := config.GetConfig()
		scheme := runtime.NewScheme()
		err = operatorv1.Install(scheme)
		if err != nil {
			return err
		}
		c.DnsOperatorClient, err = client.New(cfg, client.Options{Scheme: scheme})
		if err != nil {
			return err
		}
	}
	err := c.DnsOperatorClient.Get(context.TODO(), types.NamespacedName{
		Name: "default"}, dnsInfo)
	if err != nil {
		return err
	}
	if c.RoutesClient == nil {
		log.Info("Route client is nil")
		return nil
	}
	var options metav1.ListOptions
	routes, err := c.RoutesClient.RouteV1().Routes(metav1.NamespaceAll).List(options)
	if err != nil {
		return err
	}
	if len(routes.Items) == 0 {
		return nil
	}
	var nodeAddress []string
	nodeAddress, err = c.getNodeAddress()
	if err != nil {
		return err
	}
	if len(nodeAddress) == 0 {
		return nil
	}
	log.Info("NodeAddress: ", nodeAddress)
	// compute the dns servers info
	var servers []operatorv1.Server
	for _, route := range routes.Items {
		var server operatorv1.Server
		key := route.ObjectMeta.Namespace + "/" + route.ObjectMeta.Name
		server.Name = key
		server.Zones = append(server.Zones, route.Spec.Host)
		server.ForwardPlugin.Upstreams = nodeAddress
		servers = append(servers, server)
	}
	if !reflect.DeepEqual(dnsInfo.Spec.Servers, servers) {
		dnsInfo.Spec.Servers = servers
		err = c.DnsOperatorClient.Update(context.TODO(), dnsInfo)
		if err != nil {
			return err
		}
	}
	c.indexMutex.Lock()
	for _, route := range routes.Items {
		key := route.ObjectMeta.Namespace + "/" + route.ObjectMeta.Name
		log.Infof("Route added to cache: %s", key)
		c.routes[key] = true
	}
	c.indexMutex.Unlock()
	log.Infof("Updated dnsInfo: %+v", dnsInfo)
	return nil
}

func (c *Controller) getNodeAddress() ([]string, error) {
	var options metav1.ListOptions
	nodelist, err := c.K8s_Clientset.CoreV1().Nodes().List(options)
	if err != nil {
		log.Info("Failed to List the nodes: ", err)
		return []string{}, err
	}
	var nodeAddress []string
	for _, node := range nodelist.Items {
		if node.DeletionTimestamp != nil {
			continue
		}
		if _, ok := node.ObjectMeta.Labels["node-role.kubernetes.io/master"]; ok {
			continue
		}
		address := node.Status.Addresses
		for _, val := range address {
			if val.Type == v1.NodeInternalIP {
				nodeAddress = append(nodeAddress, val.Address)
			}
		}
	}
	return nodeAddress, nil
}

func (c *Controller) getDnsInfo() (*operatorv1.DNS, error) {
	dnsInfo := &operatorv1.DNS{
		TypeMeta:   metav1.TypeMeta{APIVersion: operatorv1.GroupVersion.String(), Kind: "DNS"},
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
	}
	err := c.DnsOperatorClient.Get(context.TODO(), types.NamespacedName{
		Name: "default"}, dnsInfo)
	if err != nil {
		log.Info(err)
		return nil, err
	}
	return dnsInfo, nil
}

// it reads all the node ip address.
// updates if there is any changes in the address computed
func (c *Controller) updateDnsOperatorSpec(add bool) bool {
	if c.DnsOperatorClient == nil || !c.Openshiftflavor {
		return false
	}
	dnsInfo, err := c.getDnsInfo()
	if err != nil {
		return true
	}
	// Add and no servers present compute for all the routes
	if add && len(dnsInfo.Spec.Servers) == 0 {
		err = c.updatednsOperator()
		if err != nil {
			log.Info("Failed to update the dnsOperatorCr: ", err)
			return true
		}
		return false
	}
	var nodeAddress []string
	nodeAddress, err = c.getNodeAddress()
	if err != nil {
		return true
	}

	if !reflect.DeepEqual(dnsInfo.Spec.Servers[0].ForwardPlugin.Upstreams, nodeAddress) {
		// This is node delete case when there is no worker nodes present
		// set the spec to nil
		if !add && len(nodeAddress) == 0 {
			dnsInfo.Spec = operatorv1.DNSSpec{}
		} else {
			for _, server := range dnsInfo.Spec.Servers {
				server.ForwardPlugin.Upstreams = nodeAddress
			}
		}
		err = c.DnsOperatorClient.Update(context.TODO(), dnsInfo)
		if err != nil {
			log.Info("Failed to update the dnsInfo: ", err)
			return true
		}
	}
	log.Infof("Updated dnsInfo: %+v", dnsInfo)
	return false
}

// handle node create to update the dnsOperatorSpec
func (c *Controller) handleNodeCreate(obj interface{}) bool {
	log.Infof("node created")
	return c.updateDnsOperatorSpec(true)
}

// handle node delete
func (c *Controller) handleNodeDelete(obj interface{}) bool {
	log.Infof("node Deleted")
	return c.updateDnsOperatorSpec(false)
}

// handle route create
// local route cache will be updated
// if route is already present it will ignore silently as it isupdate happend in operator create
func (c *Controller) handleRouteCreate(obj interface{}) bool {
	route := obj.(*routesv1.Route)
	log.Infof("route created: %s", route.ObjectMeta.Name)
	if c.DnsOperatorClient == nil {
		return false
	}
	key, _ := cache.MetaNamespaceKeyFunc(obj)
	c.indexMutex.Lock()
	_, ok := c.routes[key]
	c.indexMutex.Unlock()
	if ok {
		return false
	}
	dnsInfo, err := c.getDnsInfo()
	if err != nil {
		return true
	}
	// Check if already exists in dnsInfo then no need to update dnsinfo
	for _, server := range dnsInfo.Spec.Servers {
		if key == server.Name {
			return false
		}
	}
	var server operatorv1.Server
	server.Name = key
	server.Zones = append(server.Zones, route.Spec.Host)
	// if already computed update the cache
	if len(dnsInfo.Spec.Servers) > 0 {
		server.ForwardPlugin.Upstreams = dnsInfo.Spec.Servers[0].ForwardPlugin.Upstreams
	} else { // compute the node ip's fresh
		nodeaddr, err := c.getNodeAddress()
		if err != nil {
			return true
		}
		if len(nodeaddr) == 0 {
			return false
		}
		server.ForwardPlugin.Upstreams = nodeaddr
	}
	dnsInfo.Spec.Servers = append(dnsInfo.Spec.Servers, server)
	err = c.DnsOperatorClient.Update(context.TODO(), dnsInfo)
	if err != nil {
		log.Info("Failed to update the dnsInfo: ", err)
		return true
	}
	c.indexMutex.Lock()
	c.routes[key] = true
	c.indexMutex.Unlock()
	log.Infof("Route added to cache:%s", key)
	log.Infof("Updated dnsInfo: %+v", dnsInfo)
	return false
}

// handle route delete
func (c *Controller) handleRouteDelete(obj interface{}) bool {
	key := fmt.Sprintf("%v", obj)
	log.Infof("route deleted: %s", key)
	c.indexMutex.Lock()
	_, ok := c.routes[key]
	c.indexMutex.Unlock()
	if !ok {
		return false
	}
	if c.DnsOperatorClient == nil {
		return false
	}
	dnsInfo, err := c.getDnsInfo()
	if err != nil {
		return true
	}
	for i := range dnsInfo.Spec.Servers {
		if dnsInfo.Spec.Servers[i].Name == key {
			dnsInfo.Spec.Servers = append(dnsInfo.Spec.Servers[:i], dnsInfo.Spec.Servers[i+1:]...)
			break
		}
	}
	err = c.DnsOperatorClient.Update(context.TODO(), dnsInfo)
	if err != nil {
		log.Info("Failed to update the dnsInfo: ", err)
		return true
	}
	c.indexMutex.Lock()
	delete(c.routes, key)
	c.indexMutex.Unlock()
	log.Infof("Route deleted from cache:%s", key)
	log.Infof("Updated dnsInfo: %+v", dnsInfo)
	return false
}

func (c *Controller) enableRouteInformer(stopCh <-chan struct{}) {
	go func() {
		var options metav1.ListOptions
		for {
			Pods, err := c.K8s_Clientset.CoreV1().Pods("openshift-apiserver").List(options)
			if err == nil && (len(Pods.Items) > 0 && Pods.Items[0].Status.ContainerStatuses[0].Ready == true) {
				log.Info("Openshift-apiserver Pod found start router informer")
				err = c.updatednsOperator()
				if err != nil {
					log.Info("Failed to update the dnsOperatorCr: ", err)
				}
				go c.Informer_Route.Run(stopCh)
				cache.WaitForCacheSync(stopCh,
					c.Informer_Route.HasSynced)
				go c.processQueue(c.Route_Queue, c.Informer_Route.GetIndexer(),
					func(obj interface{}) bool {
						return c.handleRouteCreate(obj)
					}, func(obj interface{}) bool {
						return c.handleRouteDelete(obj)
					},
					stopCh)
				break
			}
			time.Sleep(time.Minute)
		}
	}()
}
func (c *Controller) handleNodeUpdate(oldobj interface{}, newobj interface{}, queue workqueue.RateLimitingInterface) {
	old_node := oldobj.(*v1.Node)
	new_node := newobj.(*v1.Node)
	if !reflect.DeepEqual(old_node.Status.Addresses, new_node.Status.Addresses) {
		key, err := cache.MetaNamespaceKeyFunc(newobj)
		if err == nil {
			queue.Add(key)
		}
	}
}
