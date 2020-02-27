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
	istiov1 "github.com/noironetworks/aci-containers/pkg/istiocrd/apis/aci.istio/v1"
	istioclient "github.com/noironetworks/aci-containers/pkg/istiocrd/clientset/versioned"
	log "github.com/sirupsen/logrus"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
	"os"
	"os/exec"
	"reflect"
)

func (cont *AciController) initIstioInformerFromClient(
	istioClient *istioclient.Clientset) {
	cont.initIstioInformerBase(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				return istioClient.AciV1().AciIstioOperators(metav1.NamespaceAll).List(options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				return istioClient.AciV1().AciIstioOperators(metav1.NamespaceAll).Watch(options)
			},
		})
}

func (cont *AciController) initIstioInformerBase(listWatch *cache.ListWatch) {
	cont.istioIndexer, cont.istioInformer = cache.NewIndexerInformer(
		listWatch,
		&istiov1.AciIstioOperator{}, 0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				cont.istioSpecAdded(obj)
			},
			UpdateFunc: func(oldobj interface{}, newobj interface{}) {
				cont.istioSpecUpdated(oldobj, newobj)
			},
			DeleteFunc: func(obj interface{}) {
				cont.istioSpecDeleted(obj)
			},
		},
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	cont.log.Debug("Initializing AciIstio Informers")
}

func (cont *AciController) istioSpecAdded(obj interface{}) {
	istiospec := obj.(*istiov1.AciIstioOperator)
	istiospeckey, err := cache.MetaNamespaceKeyFunc(istiospec)
	if err != nil {
		return
	}
	cont.log.Debug("AciIstio CR Added:", istiospeckey)
	cont.istioCache[istiospeckey] = istiospec
	cont.queueIstioSpecUpdateByKey(istiospeckey)
}

func (cont *AciController) queueIstioSpecUpdateByKey(key string) {
	cont.log.Debug("AciIstio Key Queued:", key)
	cont.istioQueue.Add(key)
}

func (cont *AciController) istioSpecUpdated(oldobj interface{}, newobj interface{}) {
	oldistio := oldobj.(*istiov1.AciIstioOperator)
	newistio := newobj.(*istiov1.AciIstioOperator)
	istiospeckey, err := cache.MetaNamespaceKeyFunc(newistio)
	if err != nil {
		return
	}
	if reflect.DeepEqual(oldistio.Spec, newistio.Spec) {
		return
	}
	cont.indexMutex.Lock()
	cont.istioCache[istiospeckey] = newistio
	cont.indexMutex.Unlock()
	cont.log.Debug("AciIstioCR update for:", istiospeckey)
	//ToDo: Profile change to be handled
	//cont.queueIstioSpecUpdateByKey(istiospeckey)
}

func (cont *AciController) handleIstioUpdate(istiospec *istiov1.AciIstioOperator) bool {
	istiospeckey, err := cache.MetaNamespaceKeyFunc(istiospec)
	if err != nil {
		return true
	}
	cont.log.Debug("AciIstioCR Create/Update:", istiospeckey)

	log.Info("Applying Upstream istio-operator deployment")
	cmd := exec.Command("kubectl", "apply", "-f", "/usr/local/var/lib/aci-cni/upstream-istio-operator.yaml")
	out, err := cmd.Output()
	if err != nil {
		log.Error("Failed:", err)
		return true
	}
	log.Debug("Success:", string(out))

	log.Info("Applying Upstream istio-ctrlplane CR")
	cmd = exec.Command("kubectl", "apply", "-f", "/usr/local/var/lib/aci-cni/upstream-istio-ctrlplane-resource.yaml")
	out, err = cmd.Output()
	if err != nil {
		log.Error("Failed:", err)
		return true
	}
	log.Debug("Success:", string(out))

	env := cont.env.(*K8sEnvironment)
	kubeClient := env.kubeClient
	deploymentsClient := kubeClient.AppsV1().Deployments("istio-operator")
	if deploymentsClient == nil {
		cont.log.Error("Error in Fetching deploymentsClient...")
		return true // to requeue
	}
	istioOperatorDeployment, _ := deploymentsClient.Get("istio-operator", metav1.GetOptions{})
	if istioOperatorDeployment == nil {
		cont.log.Info("istio-operator deployment is nil..returning")
		return true // to requeue
	}

	cont.log.Info("Setting Owner Reference for upstream istio-operator with AciIstioOperator")
	if !cont.isOwnerReferenceMarked(istioOperatorDeployment.ObjectMeta.OwnerReferences) {
		istioOperatorDeployment.OwnerReferences = []metav1.OwnerReference{
			*metav1.NewControllerRef(istiospec, istiov1.SchemeGroupVersion.WithKind("AciIstioOperator")),
		}
		_, err = deploymentsClient.Update(istioOperatorDeployment)
		if err != nil {
			cont.log.Error(err.Error())
			return true
		}
	}
	return false
}

func (cont *AciController) istioSpecDeleted(obj interface{}) {
	istiospec := obj.(*istiov1.AciIstioOperator)
	istiospeckey, err := cache.MetaNamespaceKeyFunc(istiospec)
	if err != nil {
		return
	}
	//ToDo: Move this "kubectl delete" to k8s API
	//env.kubeClient.CoreV1().Namespaces().Delete("istio-system", *metav1.DeleteOptions)
	log.Info("Deleting istio-system namespace")
	cmd := exec.Command("kubectl", "delete", "ns", "istio-system", "--grace-period=0", "--force")
	out, err := cmd.Output()
	if err != nil {
		cont.log.Info("Failed to delete istio-system NS:", err)
		return
	}
	log.Debug("Success:", string(out))
	delete(cont.istioCache, istiospeckey)
}

func (cont *AciController) createIstioCR() bool {
	var options metav1.GetOptions
	cont.log.Info("Check if AciIstio-CR is present")
	env := cont.env.(*K8sEnvironment)
	istioClient := env.istioClient
	if istioClient == nil {
		cont.log.Debug("CreateIstioCR: istioClient is nil")
		return false
	}
	if !cont.config.InstallIstio {
		cont.log.Debug("CreateIstioCR: InstallIstio is set to: ", cont.config.InstallIstio)
		return false
	}
	ns := os.Getenv("SYSTEM_NAMESPACE")
	_, err := istioClient.AciV1().AciIstioOperators(ns).Get("aciistiooperator", options)
	if err != nil {
		if apierrors.IsNotFound(err) {
			aciIstioCR := &istiov1.AciIstioOperator{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "aciistiooperator",
					Namespace: os.Getenv("SYSTEM_NAMESPACE"),
				},
				Spec: istiov1.AciIstioOperatorSpec{
					Profile: "demo",
				},
			}
			_, err = istioClient.AciV1().AciIstioOperators(ns).Create(aciIstioCR)
			if err != nil {
				cont.log.Debug("AciIstioCR create failed:", aciIstioCR, err)
				return true
			} else {
				cont.log.Debug("AciIstioCR is created:", aciIstioCR, err)
				return false
			}
		} else {
			cont.log.Debug("AciIstioCR create failed with apierror:", err)
			return true
		}
	}
	cont.log.Debug("AciIstioCR Exist")
	return false
}

func (cont *AciController) isOwnerReferenceMarked(reference []metav1.OwnerReference) bool {
	for _, ownerRef := range reference {
		if ownerRef.Kind == "AciIstioOperator" {
			log.Debug("The deployment istio-operator is already marked with owner-reference")
			return true
		}
	}
	return false
}
