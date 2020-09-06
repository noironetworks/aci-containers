/***
Copyright 2020 Cisco Systems Inc. All rights reserved.

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

package gbpserver

import (
	crdv1 "github.com/noironetworks/aci-containers/pkg/gbpcrd/apis/acipolicy/v1"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"testing"
)

const (
	vtep1 = "21.32.43.54"
	vtep2 = "21.32.43.55"
	vtep3 = "21.32.43.56"
	singleVTEP = "21.32.43.54"
	zeroVTEP   = "00.00.00.00"
	nullVTEP   = ""
	multiVTEP  = "13.32.43.54,13.24.35.45"
)

type fakeSD struct {
}

func (sd *fakeSD) Init(unused int) error {
	return nil
}

func (sd *fakeSD) Get() (*crdv1.GBPSState, error) {
	return &crdv1.GBPSState{}, nil
}

func (sd *fakeSD) Update(*crdv1.GBPSState) error {
	return nil
}

var fsd = &fakeSD{}

func TestInvXform(t *testing.T) {
	cfg := &GBPServerConfig{}
	InitConfig(cfg)
	gs := &Server{
		config:        cfg,
		usedClassIDs:  make(map[uint]bool),
		instToClassID: make(map[string]uint),
		driver:        fsd,
		tunnels: map[string]int64{vtep1: 1, vtep2: 2},
		bounceList: []string{vtep1, vtep2},
	}
	gs.InitDB()

	// create an inventory ep mo with a single vtep
	ep1 := &Endpoint{
		Uuid:      "0123",
		MacAddr:   "00:11:22:33:44:55",
		IPAddr:    []string{"12.23.34.45"},
		EPG:       "epg1",
		VTEP:      vtep1,
		IFName:    "if1",
		Namespace: "ns1",
		PodName:   "pod1",
	}

	uri, err := ep1.Add()
	assert.Equal(t, err, nil)
	log.Infof("uri: %s", uri)

	idb := getInvDB(vtep1)
	epMo := idb[uri]
	assert.NotEqual(t, epMo, nil)

	st := getInvSubTree(uri, nullVTEP)
	assert.Equal(t, len(st), 3)
	root_mo := st[0]
	cmo := &gbpCommonMo{
		*root_mo,
		false,
		false,
	}
	nht := cmo.GetStringProperty(propNht)
	assert.NotEqual(t, nht, "")

	ep2 := &Endpoint{
		Uuid:      "01234",
		MacAddr:   "00:11:22:33:44:56",
		IPAddr:    []string{"12.23.34.46"},
		EPG:       "epg1",
		VTEP:      multiVTEP,
		IFName:    "if2",
		Namespace: "ns2",
		PodName:   "pod2",
	}

	uri, err = ep2.Add()
	assert.Equal(t, err, nil)
	log.Infof("uri: %s", uri)

	idb = getInvDB(vtep2)
	epMo = idb[uri]
	assert.NotEqual(t, epMo, nil)
	st = getInvSubTree(uri, vtep1)
	assert.Equal(t, len(st), 5)
	root_mo = st[0]
	cmo = &gbpCommonMo{
		*root_mo,
		false,
		false,
	}
	nht = cmo.GetStringProperty(propNht)
	assert.Equal(t, nht, "")
	addBounce := cmo.GetIntProperty(propAddBounce)
	assert.Equal(t, 1, addBounce)

	// verify there are 4 children
	assert.Equal(t, len(cmo.Children), 4)

	lookUpMo := func(uri string) *GBPObject {
		for _, mo := range st {
			if mo.Uri == uri {
				return mo
			}
		}

		return nil
	}
	// validate children
	for _, cUri := range cmo.Children {
		child := lookUpMo(cUri)
		assert.NotEqual(t, nil, child)
		assert.NotEqual(t, "", child.ParentSubject)
		assert.NotEqual(t, "", child.ParentUri)
		assert.NotEqual(t, "", child.ParentRelation)
	}

	st = getInvSubTree(uri, vtep3)
	assert.Equal(t, len(st), 5)
	root_mo = st[0]
	cmo = &gbpCommonMo{
		*root_mo,
		false,
		false,
	}
	nht = cmo.GetStringProperty(propNht)
	assert.Equal(t, nht, "")
	addBounce = cmo.GetIntProperty(propAddBounce)
	assert.Equal(t, 0, addBounce)
	// verify there are 4 children
	assert.Equal(t, len(cmo.Children), 4)

	// validate children
	bounceVteps := map[string]bool{vtep1: true, vtep2: true}
	for _, cUri := range cmo.Children {
		child := lookUpMo(cUri)
		assert.NotEqual(t, nil, child)
		assert.NotEqual(t, "", child.ParentSubject)
		assert.NotEqual(t, "", child.ParentUri)
		assert.NotEqual(t, "", child.ParentRelation)
		if child.Subject == subjNhl {
			ccmo := &gbpCommonMo{
				*child,
				false,
				false,
			}

			vtep := ccmo.GetStringProperty("ip")
			delete(bounceVteps, vtep)
		}
	}

	assert.Equal(t, 0, len(bounceVteps))
}
