// Copyright 2019 Cisco Systems, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRATIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// creates snat crs.

package controller

import (
	"context"
	rdConfigv1 "github.com/noironetworks/aci-containers/pkg/rdconfig/apis/aci.snat/v1"
	rdconfigclset "github.com/noironetworks/aci-containers/pkg/rdconfig/clientset/versioned"
	"github.com/noironetworks/aci-containers/pkg/util"
	"github.com/sirupsen/logrus"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
	"os"
	"reflect"
)

func (cont *AciController) initRdConfigInformerFromClient(
	rdConfigClient *rdconfigclset.Clientset) {
	ns := os.Getenv("ACI_SNAT_NAMESPACE")
	name := os.Getenv("ACI_RDCONFIG_NAME")
	cont.initRdConfigInformerBase(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				options.FieldSelector = fields.Set{"metadata.name": name}.String()
				obj, err := rdConfigClient.AciV1().RdConfigs(ns).List(context.TODO(), options)
				if err != nil {
					cont.log.Fatalf("Failed to list RdConfigs during initialization of RdConfigInformer with err: %v", err)
				}
				return obj, err
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				options.FieldSelector = fields.Set{"metadata.name": name}.String()
				obj, err := rdConfigClient.AciV1().RdConfigs(ns).Watch(context.TODO(), options)
				if err != nil {
					cont.log.Fatalf("Failed to watch RdConfigs during initialization RdConfigsInformer with err: %v", err)
				}
				return obj, err
			},
		})
}

func (cont *AciController) initRdConfigInformerBase(listWatch *cache.ListWatch) {
	cont.rdConfigIndexer, cont.rdConfigInformer = cache.NewIndexerInformer(
		listWatch,
		&rdConfigv1.RdConfig{}, 0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				cont.RdConfigAdded(obj)
			},
			UpdateFunc: func(oldobj interface{}, newobj interface{}) {
				cont.RdConfigUpdated(oldobj, newobj)
			},
			DeleteFunc: func(obj interface{}) {
				cont.RdConfigDeleted(obj)
			},
		},
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	cont.log.Debug("Initializing RdConfig Informers")
}

func (cont *AciController) RdConfigAdded(obj interface{}) {
	rdcon := obj.(*rdConfigv1.RdConfig)
	rdconkey, err := cache.MetaNamespaceKeyFunc(rdcon)
	if err != nil {
		RdConfigLogger(cont.log, rdcon).Error("Could not create key:" + err.Error())
		return
	}
	cont.log.Infof("RdConfig: %s added", rdconkey)
	cont.indexMutex.Lock()
	cont.rdConfigCache[rdcon.ObjectMeta.Name] = rdcon
	cont.indexMutex.Unlock()
	cont.queueRdConfigUpdateByKey(rdconkey)
}

func (cont *AciController) RdConfigUpdated(oldobj, newobj interface{}) {
	oldrdcon := oldobj.(*rdConfigv1.RdConfig)
	newrdcon := newobj.(*rdConfigv1.RdConfig)
	rdconkey, err := cache.MetaNamespaceKeyFunc(newrdcon)
	if err != nil {
		RdConfigLogger(cont.log, newrdcon).Error("Could not create key:" + err.Error())
		return
	}
	if reflect.DeepEqual(oldrdcon.Spec, newrdcon.Spec) {
		return
	}
	cont.log.Infof("Updating RdConfig:%s, from: %v, to: %v", rdconkey, oldrdcon, newrdcon)
	cont.indexMutex.Lock()
	cont.rdConfigCache[newrdcon.ObjectMeta.Name] = newrdcon
	cont.indexMutex.Unlock()
	cont.queueRdConfigUpdateByKey(rdconkey)
}

func (cont *AciController) RdConfigDeleted(obj interface{}) {
	rdcon, isRdCon := obj.(*rdConfigv1.RdConfig)
	if !isRdCon {
		deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			cont.log.Error("Received unexpected object: ", obj)
			return
		}
		rdcon, ok = deletedState.Obj.(*rdConfigv1.RdConfig)
		if !ok {
			cont.log.Error("DeletedFinalStateUnknown contained non-RdConfig object: ", deletedState.Obj)
			return
		}
	}
	rdconkey, err := cache.MetaNamespaceKeyFunc(rdcon)
	if err != nil {
		RdConfigLogger(cont.log, rdcon).Error("Could not create key:" + err.Error())
		return
	}
	cont.indexMutex.Lock()
	cont.log.Info("Deleting RdConfig object with name: ", rdcon.ObjectMeta.Name)
	delete(cont.rdConfigCache, rdcon.ObjectMeta.Name)
	cont.indexMutex.Unlock()
	cont.queueRdConfigUpdateByKey(rdconkey)
}

func (cont *AciController) queueRdConfigUpdateByKey(key string) {
	cont.log.Debug("RdConfig key Queued: ", key)
	cont.rdConfigQueue.Add(key)
}

func (cont *AciController) postDelHandleRdConfig() bool {
	name := os.Getenv("ACI_RDCONFIG_NAME")
	cont.log.Debugf("RdConfig %s should not be deleted Re-Creating...", name)
	//gatekeeping against before init RdConfig Sync
	if spec, ok := cont.rdConfigSubnetCache[name]; ok {
		err := util.CreateRdConfigCR(*cont.env.(*K8sEnvironment).rdConfigClient, *spec)
		if err != nil {
			cont.log.Debugf("Unable to RE-Create RDConfig: %s, err: %v, spec: %+v", name, err, spec)
			return true
		}
		cont.log.Debugf("RdConfig: %s RE-Created with spec: %v, Please update this resource and refrain from deleting it.", name, spec)
	}
	cont.scheduleRdConfig()
	return false
}

func (cont *AciController) handleRdConfig(rdconfig *rdConfigv1.RdConfig) bool {
	//store discovered subnets and user subnets in a cache to recreate on delete
	cont.log.Debug("handle RdConfig: ", rdconfig)
	_, err := cache.MetaNamespaceIndexFunc(rdconfig)
	if err != nil {
		cont.log.Debugf("Could not create key: %s", err)
		return false
	}
	if spec, ok := cont.rdConfigSubnetCache[rdconfig.ObjectMeta.Name]; ok && reflect.DeepEqual(rdconfig.Spec.UserSubnets, spec.UserSubnets) {
		//no update necessary
		return false
	} else {
		cont.indexMutex.Lock()
		cont.rdConfigSubnetCache[rdconfig.ObjectMeta.Name] = &rdconfig.Spec
		cont.indexMutex.Unlock()
	}
	return true
}

func (cont *AciController) syncRdConfig() bool {
	cont.log.Debug("Syncing RdConfig")
	var options metav1.GetOptions
	var discoveredSubnets []string
	var userSubnets []string
	cont.indexMutex.Lock()
	for _, v := range cont.apicConn.CachedSubnetDns {
		discoveredSubnets = append(discoveredSubnets, v)
	}
	userSubnets = append(userSubnets, cont.config.ExternStatic...)
	userSubnets = append(userSubnets, cont.config.ExternDynamic...)
	cont.indexMutex.Unlock()
	env := cont.env.(*K8sEnvironment)
	rdConfigClient := env.rdConfigClient
	if rdConfigClient == nil || cont.config.ChainedMode {
		return false
	}
	ns := os.Getenv("ACI_SNAT_NAMESPACE")
	name := os.Getenv("ACI_RDCONFIG_NAME")
	rdCon, err := rdConfigClient.AciV1().RdConfigs(ns).Get(context.TODO(), name, options)
	if err != nil {
		if apierrors.IsNotFound(err) {
			cont.log.Debugf("RDConfig {name: %s, namespace: %s} not found. Creating...", name, ns)
			spec := rdConfigv1.RdConfigSpec{
				DiscoveredSubnets: discoveredSubnets,
			}
			if cont.config.AddExternalSubnetsToRdconfig {
				spec.UserSubnets = userSubnets
			}
			err := util.CreateRdConfigCR(*rdConfigClient, spec)
			if err != nil {
				cont.log.Debugf("Unable to create RDConfig: %s, err: %v, spec: %+v", name, err, spec)
				return true
			}
			cont.log.Debugf("RdConfig: %s Created with spec: %v", name, spec)
		} else {
			cont.log.Debugf("Unable to get RDConfig: %s, err: %v", name, err)
		}
	} else {
		cont.log.Debug("Comparing existing rdconfig DiscoveredSubnets with cached values")

		var isUpdated = false

		if !reflect.DeepEqual(rdCon.Spec.DiscoveredSubnets, discoveredSubnets) {
			rdCon.Spec.DiscoveredSubnets = discoveredSubnets
			isUpdated = true
		}
		if !reflect.DeepEqual(rdCon.Spec.UserSubnets, userSubnets) && cont.config.AddExternalSubnetsToRdconfig {
			// add new usersubnet to already present subnets
			prev_userSubnets := rdCon.Spec.UserSubnets
			for _, new_user_subnet := range userSubnets {
				var isPresent = false
				for _, prev_user_subnet := range prev_userSubnets {
					if new_user_subnet == prev_user_subnet {
						isPresent = true
						break
					}
				}
				if !isPresent {
					prev_userSubnets = append(prev_userSubnets, new_user_subnet)
					isUpdated = true
				}
			}

			rdCon.Spec.UserSubnets = prev_userSubnets
		}

		if isUpdated {
			_, err = rdConfigClient.AciV1().RdConfigs(ns).Update(context.TODO(), rdCon, metav1.UpdateOptions{})
			if err != nil {
				cont.log.Debugf("Unable to Update RDConfig: %s, err: %v", name, err)
				return true
			}
			cont.log.Debug("RdConfig  DiscoveredSubnets Updated: ", discoveredSubnets)
			cont.log.Debug("RdConfig  UserSubnets Updated: ", rdCon.Spec.UserSubnets)
		}
	}
	return false
}

func RdConfigLogger(log *logrus.Logger, r *rdConfigv1.RdConfig) *logrus.Entry {
	return log.WithFields((logrus.Fields{
		"name":      r.ObjectMeta.Name,
		"namespace": r.ObjectMeta.Namespace,
		"spec":      r.Spec,
	}))
}
