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

package acioperator

import (
    "sigs.k8s.io/controller-runtime/pkg/client"
	"context"
	configv1 "github.com/openshift/api/config/v1"
	"encoding/base64"
	"fmt"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/config"

	//"github.com/pkg/errors"
	//"sigs.k8s.io/controller-runtime/pkg/reconcile"

	//"github.com/pkg/errors"
	//"reflect"
	log "github.com/Sirupsen/logrus"
	operators "github.com/noironetworks/aci-containers/pkg/acicontainersoperator/apis/aci.ctrl/v1alpha1"
	operatorclientset "github.com/noironetworks/aci-containers/pkg/acicontainersoperator/clientset/versioned"
	"io/ioutil"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	//netopv1 "github.com/openshift/cluster-network-operator/pkg/apis/networkoperator/v1"
	//"github.com/openshift/cluster-network-operator/pkg/network"
	//"github.com/openshift/cluster-network-operator/pkg/apply"
	//k8sutil "github.com/openshift/cluster-network-operator/pkg/util/k8s"
	"os"
	"os/exec"
	"time"
)

// Controller  here defines the Operator code handler which list watch the AciContainerOperator
// Object and apply the aci_deployment.yaml in the cluster after creation/updation

type Controller struct {
	Logger    *log.Entry
	Clientset operatorclientset.Interface
	Queue     workqueue.RateLimitingInterface
	Informer  cache.SharedIndexInformer
	Handlers  Handler

}


// Handler interface has methods for handeling create/update/delete events
type Handler interface {
	Init() error
	ObjectCreated(obj interface{})
	ObjectDeleted(obj interface{})
	ObjectUpdated(objOld, objNew interface{})
}

// OperatorHandler is a struct for handeling the deployment in aci fabric
type OperatorHandler struct{
	Deployment *appsv1.Deployment
	HostDaemonset *appsv1.DaemonSet
	OvsDaemonset *appsv1.DaemonSet
}


func (c *Controller) Run(stopCh <-chan struct{}) {
	// Handling Panic gracefully
	defer utilruntime.HandleCrash()
	//Shutdown queue when go routine is done for the queue
	defer c.Queue.ShutDown()

	c.Logger.Info("Controller.Run: initiating")

	// Run informer to start watching and listening
	go c.Informer.Run(stopCh)

	// Sync the current resources
	if !cache.WaitForCacheSync(stopCh, c.HasSynced) {
		utilruntime.HandleError(fmt.Errorf("Controller.Sync: Error syncing the cache"))
		return
	}
	c.Logger.Info("Controller.Sync: Cache sync complete")

	// Run worker in 1 sec interval
	wait.Until(c.runWorker, time.Second, stopCh)
}


func (c *Controller) HasSynced() bool {
	return c.Informer.HasSynced()
}

// runWorker executes new objects added to queue in loop
func (c *Controller) runWorker() {
	log.Info("Controller.runWorker: starting the controller")

	for c.processNextItem() {
		log.Info("Controller.runWorker: processing the next item")
	}

	log.Info("Controller.runWorker: completed")
}

func (c *Controller) processNextItem() bool {
	log.Info("Controller.processNextItem: starting....")

	key, quit := c.Queue.Get()

	if quit {
		return false
	}

	defer c.Queue.Done(key)

	keyRaw := key.(string)


	item, exists, err := c.Informer.GetIndexer().GetByKey(keyRaw)
	if err != nil {
		if c.Queue.NumRequeues(key) < 10 {
			c.Logger.Errorf("Controller.processNextItem: Failed to process the item with key %s with error %v, retrying", key, err)
			c.Queue.AddRateLimited(key)
		} else {
			c.Logger.Errorf("Controller.processNextItem: Failed to process the item with key %s with error %v, no more retries", key, err)
			c.Queue.Forget(key)
			utilruntime.HandleError(err)
		}
	}

	// if the item doen not exist means deleted otherwise it is created or updated.
	// After processing we will remove the key from queue
	if !exists {
		c.Logger.Infof("Controller.processNextItem: object deleted detected: %s", keyRaw)
		c.Handlers.ObjectDeleted(item)
		c.Queue.Forget(key)
	} else {
		c.Logger.Infof("Controller.processNextItem: object created detected: %s", keyRaw)
		c.Handlers.ObjectCreated(item)
		c.Queue.Forget(key)
	}

	// run.worker is continued by returning true
	return true
}

func (t *OperatorHandler) Init() error {
	log.Info("OperatorHandler.Init")
	return nil
}

func getk8sClient() kubernetes.Interface {
	restconfig, err := restclient.InClusterConfig()
	if err != nil {
		return nil
	}
	kubeClient, err := kubernetes.NewForConfig(restconfig)
	if err != nil {
		log.Fatalf("Failed to intialize kube client %v", err)
	}

	log.Info("Successfully constructed k8s client")
	return kubeClient
}


func (t *OperatorHandler) ObjectCreated(obj interface{}) {

	log.Info("OperatorHandler.ObjectCreated")

	acicontainersoperator := obj.(*operators.AciContainersOperator)
	log.Info(acicontainersoperator.Spec.Config)
	if (acicontainersoperator.Spec.Config == ""){
		log.Info("Aci Cni CR Object is not Enabled")
		return
	}
	
	dec, err := base64.StdEncoding.DecodeString(acicontainersoperator.Spec.Config)
	if err != nil {
		panic(err)
		return
	}

	f, err := os.Create("manifests")
	if err != nil {
		panic(err)
		return
	}
	if _, err := f.Write(dec); err != nil {
		panic(err)
		return
	}
	if err := f.Sync(); err != nil {
		panic(err)
	}
	if err := f.Close();err != nil{
		panic(err)
		return
	}
	log.Info("Applying Deployment")
	token, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		fmt.Println(err)
		return
	}

	cmd := exec.Command("kubectl","--token=" + string(token),"apply","-f","manifests")
	log.Println(cmd)
	stdout, err := cmd.Output()

	log.Info(string(stdout))

	k8sclient := getk8sClient()


	deploymentsClient := k8sclient.AppsV1().Deployments("aci-containers-system")
	t.Deployment, _ = deploymentsClient.Get("aci-containers-controller",metav1.GetOptions{})
	if t.Deployment == nil {
		log.Info("aci-containers-controller deployment is nil..returning")
		return
	}

	t.Deployment.OwnerReferences = []metav1.OwnerReference{
					*metav1.NewControllerRef(acicontainersoperator, operators.SchemeGroupVersion.WithKind("AciContainersOperator")),
				}

	_, err = deploymentsClient.Update(t.Deployment)
	if err != nil {
		fmt.Println(err.Error())
	}


	hostdaemonsetclient := k8sclient.AppsV1().DaemonSets("aci-containers-system")
	t.HostDaemonset, _ = hostdaemonsetclient.Get("aci-containers-host",metav1.GetOptions{})
	if t.HostDaemonset == nil {
		log.Info("aci-containers-host daemonset is nil.....returning")
		return
	}

	t.HostDaemonset.OwnerReferences = []metav1.OwnerReference{
		*metav1.NewControllerRef(acicontainersoperator, operators.SchemeGroupVersion.WithKind("AciContainersOperator")),
	}

	_, err = hostdaemonsetclient.Update(t.HostDaemonset)
	if err != nil {
		fmt.Println(err.Error())
	}

	ovsdaemonsetclient := k8sclient.AppsV1().DaemonSets("aci-containers-system")
	t.OvsDaemonset, _ = hostdaemonsetclient.Get("aci-containers-openvswitch",metav1.GetOptions{})
	if t.OvsDaemonset == nil {
		log.Info("aci-containers-openvswitch daemonset is nil.....returning")
		return
	}

	t.OvsDaemonset.OwnerReferences = []metav1.OwnerReference{
		*metav1.NewControllerRef(acicontainersoperator, operators.SchemeGroupVersion.WithKind("AciContainersOperator")),
	}

	_, err = ovsdaemonsetclient.Update(t.OvsDaemonset)
	if err != nil {
		fmt.Println(err.Error())
	}

	log.Info("Platform flavor is ",acicontainersoperator.Spec.Flavor)

	if (acicontainersoperator.Spec.Flavor == "OpenShift") {

		log.Info("Updating Network Status of the Openshift Object....")

		cfg, err := config.GetConfig()
		scheme := runtime.NewScheme()

		rclient, err := client.New(cfg, client.Options{Scheme: scheme})
		if err != nil {
			return
		}

		clusterConfig := &configv1.Network{
			TypeMeta:   metav1.TypeMeta{APIVersion: configv1.GroupVersion.String(), Kind: "Network"},
			ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
		}

		err = rclient.Get(context.TODO(), types.NamespacedName{
			Name: "cluster",
		}, clusterConfig)
		if err != nil {
			log.Info(err)
		}
		log.Info("Config Spec is  ", clusterConfig.Spec)
		clusterConfig.Status.ClusterNetwork = clusterConfig.Spec.ClusterNetwork
		clusterConfig.Status.NetworkType = clusterConfig.Spec.NetworkType
		clusterConfig.Status.ServiceNetwork = clusterConfig.Spec.ServiceNetwork

		log.Info("Status is ", clusterConfig.Status)

		ctx := context.TODO()
		err = rclient.Update(ctx, clusterConfig)
		if err != nil {
			log.Info(err)
			return
		}
	}



	//err := client.Get(context.TODO(), types.NamespacedName{
	//	Name: "cluster",
	//}, clusterConfig)
	//if err != nil {
	//	fmt.Println(err.Error())
	//	return
	//}
	//operConfig := &netopv1.NetworkConfig{TypeMeta: metav1.TypeMeta{APIVersion: netopv1.SchemeGroupVersion.String(), Kind: "Network"}}
	//status := network.StatusFromOperatorConfig(&operConfig.Spec)
	//
	//if reflect.DeepEqual(status, clusterConfig.Status) {
	//	return
	//}
	//clusterConfig.Status = status
	//clusterConfig.TypeMeta = metav1.TypeMeta{APIVersion: configv1.GroupVersion.String(), Kind: "Network"}
	//cluster_status, err :=k8sutil.ToUnstructured(clusterConfig)
	//if err != nil {
	//	log.Printf("Could not generate network status: %v", err)
	//	return
	//}



	//cluster_status, err :=k8sutil.ToUnstructured(clusterConfig)
	//if err != nil {
	//	log.Printf("Could not generate network status: %v", err)
	//	return
	//}
	//if err := apply.ApplyObject(context.TODO(), rclient, cluster_status); err != nil {
	//	err = errors.Wrapf(err, "could not apply (%s) %s/%s", cluster_status.GroupVersionKind(), cluster_status.GetNamespace(), cluster_status.GetName())
	//	log.Println(err)
	//}

	//if err := apply.ApplyObject(context.TODO(), client.Client, cluster_status); err != nil {
	//	err = errors.Wrapf(err, "could not apply (%s) %s/%s", cluster_status.GroupVersionKind(), cluster_status.GetNamespace(), cluster_status.GetName())
	//	log.Println(err)
	//}

}



func (t *OperatorHandler) ObjectDeleted(obj interface{}) {
	log.Info("OperatorHandler.ObjectDeleted")
}


func (t *OperatorHandler) ObjectUpdated(objOld, objNew interface{}) {
	log.Info("OperatorHandler.Updated")
}