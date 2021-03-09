/***
Copyright 2018 Cisco Systems Inc. All rights reserved.

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
	"context"
	"fmt"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
)

const (
	testCRDSub       = "GbpTestMo"
	testCRDParentSub = ""
	testCRDParentUri = ""
)

type testCRD struct {
	Prop1 string `json:"prop1,omitempty"`
	Prop2 int    `json:"prop2,omitempty"`
}

var uriTenant string

func (tc *testCRD) Subject() string {
	return testCRDSub
}

func (tc *testCRD) URI(s *Server) string {
	return fmt.Sprintf("%s%s/", uriTenant, testCRDSub)
}

func (tc *testCRD) Properties() map[string]interface{} {
	return map[string]interface{}{
		"prop1": tc.Prop1,
		"prop2": tc.Prop2,
	}
}

func (tc *testCRD) ParentSub() string {
	return testCRDParentSub
}

func (tc *testCRD) ParentURI(s *Server) string {
	return testCRDParentUri
}

func (tc *testCRD) Children() []string {
	return []string{}
}

func TestGBPCustomMo(t *testing.T) {
	suite := &testSuite{}
	s := suite.setupGBPServer(t)
	uriTenant = s.GetTenantURI()
	defer s.Stop()
	defer suite.tearDown()
	// setup a connection to grpc server

	conn, err := grpc.Dial("localhost:19999", grpc.WithInsecure())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	listCh := make(chan *GBPOperation)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	listVerify := func(lCh chan *GBPOperation, uri string, present bool) {
		c := NewGBPClient(conn)

		lc, err := c.ListObjects(ctx, &Version{}, grpc.WaitForReady(true))
		if err != nil {
			t.Fatal(err)
		}

		go func() {
			for {
				gbpOp, err := lc.Recv()
				if err != nil {
					log.Info(err)
					break
				}
				lCh <- gbpOp
			}
		}()

		rcv := <-lCh
		log.Infof("List opcode: %+v, count:% d", rcv.Opcode, len(rcv.ObjectList))
		moMap := make(map[string]*GBPObject)
		for _, o := range rcv.ObjectList {
			moMap[o.Uri] = o
		}
		_, found := moMap[uri]
		assert.Equal(t, present, found)
	}

	crd1 := &testCRD{
		Prop1: "strProp",
		Prop2: 100,
	}
	s.AddGBPCustomMo(crd1)
	listVerify(listCh, crd1.URI(s), true)

	s.DelGBPCustomMo(crd1)

rcvLoop:
	for {
		select {
		case rcv := <-listCh:
			assert.Equal(t, 1, len(rcv.ObjectList))
			log.Infof("Update opcode: %+v, count:% d", rcv.Opcode, len(rcv.ObjectList))
			break rcvLoop
		case <-ctx.Done():
			t.Error("Update not received")
			break rcvLoop
		}
	}

	listVerify(listCh, crd1.URI(s), false)
}

func TestGetURIBySubject(t *testing.T) {
	testData := []struct {
		sub string
		uri string
	}{
		{"DomainConfig", "/DomainConfig/"},
		{"PlatformConfig", "/PolicyUniverse/PlatformConfig/comp%2fprov-Kubernetes%2fctrlr-%5btestDom%5d-testDom%2fsw-InsiemeLSOid/"},
	}

	suite := &testSuite{}
	s := suite.setupGBPServer(t)
	defer s.Stop()
	defer suite.tearDown()

	for _, td := range testData {
		uri := s.GetURIBySubject(td.sub)
		assert.Equal(t, td.uri, uri)
	}
}
