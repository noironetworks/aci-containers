/***
Copyright 2019 Cisco Systems Inc. All rights reserved.

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

package watchers

import (
	log "github.com/sirupsen/logrus"
	restclient "k8s.io/client-go/rest"

	aciv1 "github.com/noironetworks/aci-containers/pkg/gbpcrd/apis/acipolicy/v1"
	aciclientset "github.com/noironetworks/aci-containers/pkg/gbpcrd/clientset/versioned"
	aciclientsetv1 "github.com/noironetworks/aci-containers/pkg/gbpcrd/clientset/versioned/typed/acipolicy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	stateObject  = "gbp-server"
	inboxSize    = 32
	FieldClassID = iota
	FieldTunnelID
)

// K8sStateDriver implements gbpserver.StateDriver
type K8sStateDriver struct {
	gsi    aciclientsetv1.GBPSStateInterface
	inbox  chan *aciv1.GBPSState
	curr   *aciv1.GBPSState
	copier func(s, d *aciv1.GBPSState)
}

func (ks *K8sStateDriver) Init(wrField int) error {
	cfg, err := restclient.InClusterConfig()
	if err != nil {
		return err
	}

	aciClient, err := aciclientset.NewForConfig(cfg)
	if err != nil {
		return err
	}
	ks.gsi = aciClient.AciV1().GBPSStates(sysNs)
	// if the state object doesn't exist, create it now
	s, err := ks.gsi.Get(stateObject, metav1.GetOptions{})
	if err != nil || s == nil {
		log.Infof("%s object not found, creating", stateObject)
		s = &aciv1.GBPSState{}
		s.Kind = "GBPSState"
		s.APIVersion = "aci.aw/v1"
		s.ObjectMeta.Name = stateObject
		s, err = ks.gsi.Create(s)
		if err != nil {
			log.Errorf("Failed to create %s CRD - %v", stateObject, err)
			return err
		}
	}

	ks.inbox = make(chan *aciv1.GBPSState, inboxSize)
	ks.curr = s
	switch wrField {
	case FieldClassID:
		ks.copier = copyClassID
	case FieldTunnelID:
		ks.copier = copyTunnelID
	}

	go ks.run()

	return nil
}

func copyClassID(src, dest *aciv1.GBPSState) {
	dest.Kind = "GBPSState"
	dest.APIVersion = "aci.aw/v1"
	dest.Status.ClassIDs = src.Status.ClassIDs
}

func copyTunnelID(src, dest *aciv1.GBPSState) {
	dest.Kind = "GBPSState"
	dest.APIVersion = "aci.aw/v1"
	dest.Status.TunnelIDs = src.Status.TunnelIDs
}

func (ks *K8sStateDriver) Get() (*aciv1.GBPSState, error) {
	s, err := ks.gsi.Get(stateObject, metav1.GetOptions{})
	if err == nil {
		ks.curr = s
	} else {
		log.Errorf("Failed to get %s CRD - %v", stateObject, err)
	}

	return s, err
}

func (ks *K8sStateDriver) Update(s *aciv1.GBPSState) error {
	ks.inbox <- s
	return nil
}

func (ks *K8sStateDriver) run() {
	for {
		// wait for an incoming request
		s := <-ks.inbox

		// pick up latest update
	latest:
		for {
			select {
			case s = <-ks.inbox:
			default:
				break latest
			}
		}

		c := *ks.curr
		ks.copier(s, &c)

		newS, err := ks.gsi.UpdateStatus(&c)
		if err == nil {
			ks.curr = newS
		} else {
			log.Warnf("State driver Update failed(will retry): %v, %+v", err, c)
			ks.Get() // refresh current
			goto latest
		}
	}
}
