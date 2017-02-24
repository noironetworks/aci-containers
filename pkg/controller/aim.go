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

// Handlers for AIM ThirdPartyResource updates.  Allows creating
// objects in Kubernetes API that will be automatically synced into an
// APIC controller

package controller

import (
	"bytes"
	"fmt"

	"github.com/Sirupsen/logrus"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/pkg/api"
	"k8s.io/client-go/pkg/apis/extensions/v1beta1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/kubernetes/pkg/controller"
)

func InitAimThirdPartyResource(kubeClient kubernetes.Interface,
	log *logrus.Logger) error {
	_, err := kubeClient.ExtensionsV1beta1().
		ThirdPartyResources().Get("aci.acicontainers.cisco.com", metav1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			tpr := &v1beta1.ThirdPartyResource{
				ObjectMeta: metav1.ObjectMeta{
					Name: "aci.acicontainers.cisco.com",
				},
				Versions: []v1beta1.APIVersion{
					{Name: "v1"},
				},
				Description: "ACI policy model objects to be synchronized with ACI",
			}

			_, err := kubeClient.ExtensionsV1beta1().
				ThirdPartyResources().Create(tpr)
			if err != nil {
				return err
			}
			log.Info("Initialized ACI third party object")
		} else {
			return err
		}
	} else {
		log.Debug("ACI third party object already exists")
	}
	return nil
}

func ConfigureAimClient(config *rest.Config) {
	groupversion := schema.GroupVersion{
		Group:   "acicontainers.cisco.com",
		Version: "v1",
	}

	config.GroupVersion = &groupversion
	config.APIPath = "/apis"
	config.ContentType = runtime.ContentTypeJSON
	config.NegotiatedSerializer = serializer.DirectCodecFactory{CodecFactory: api.Codecs}

	schemeBuilder := runtime.NewSchemeBuilder(
		func(scheme *runtime.Scheme) error {
			scheme.AddKnownTypes(
				groupversion,
				&Aci{},
				&AciList{},
			)
			return nil
		})
	metav1.AddToGroupVersion(api.Scheme, groupversion)
	schemeBuilder.AddToScheme(api.Scheme)
}

func (cont *AciController) initAimInformerFromRest(
	tprClient rest.Interface) {

	cont.initAimInformerBase(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				result := &AciList{}
				err := tprClient.Get().
					Namespace("kube-system").
					Resource("acis").
					VersionedParams(&options, api.ParameterCodec).
					Do().
					Into(result)
				return result, err
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				return tprClient.Get().
					Prefix("watch").
					Namespace("kube-system").
					Resource("acis").
					VersionedParams(&options, api.ParameterCodec).
					Watch()
			},
		})
}

func (cont *AciController) initAimInformerBase(listWatch *cache.ListWatch) {
	cont.aimInformer = cache.NewSharedIndexInformer(
		listWatch,
		&Aci{},
		controller.NoResyncPeriodFunc(),
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	cont.aimInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			cont.aimChanged(obj)
		},
		UpdateFunc: func(_ interface{}, obj interface{}) {
			cont.aimChanged(obj)
		},
		DeleteFunc: func(obj interface{}) {
			cont.aimDeleted(obj)
		},
	})

}

func generateUniqueName(components ...string) string {
	var buffer bytes.Buffer
	for _, component := range components {
		if buffer.Len() > 0 {
			buffer.WriteString("-")
		}
		for _, rune := range component {
			if rune >= '0' && rune <= '0' ||
				rune >= 'a' && rune <= 'z' ||
				rune >= 'Z' && rune <= 'Z' {
				buffer.WriteRune(rune)
			} else {
				buffer.WriteString(fmt.Sprintf("--%x-", rune))
			}
		}
	}
	return buffer.String()
}

func (cont *AciController) aimChanged(obj interface{}) {
	aci := obj.(*Aci)
	if aci.Spec.Type == "SecurityGroup" {

	}
}

func (cont *AciController) aimDeleted(obj interface{}) {
}
