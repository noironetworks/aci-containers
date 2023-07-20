// Copyright 2021 Cisco Systems, Inc.
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
	"os"
	"reflect"
	"testing"
	"time"

	rdconfig "github.com/noironetworks/aci-containers/pkg/rdconfig/apis/aci.snat/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func rdConfigdata(usersubnets, discoveredsubnets []string) *rdconfig.RdConfig {
	ns := os.Getenv("ACI_SNAT_NAMESPACE")
	name := os.Getenv("ACI_RDCONFIG_NAME")
	rdcon := &rdconfig.RdConfig{
		Spec: rdconfig.RdConfigSpec{
			UserSubnets:       usersubnets,
			DiscoveredSubnets: discoveredsubnets,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
		},
	}
	return rdcon
}

func checkRdConfig(c *testAciController, expected *rdconfig.RdConfig, op string) bool {
	sleep := time.Duration(100)
	time.Sleep(time.Millisecond * sleep)
	name := os.Getenv("ACI_RDCONFIG_NAME")
	ret := false
	if rdConCached, ok := c.rdConfigCache[name]; !ok || !reflect.DeepEqual(expected, rdConCached) {
		c.log.Panicf("RdConfig %s Failed", op)
	} else {
		c.log.Debugf("Cached: %+v", rdConCached)
		ret = true
	}
	time.Sleep(time.Millisecond * sleep)
	spec := &expected.Spec
	if rdConSub, ok := c.rdConfigSubnetCache[name]; !ok || !reflect.DeepEqual(spec, rdConSub) {
		c.log.Debugf("spec: %+v, rdConSub:%+v", spec, rdConSub)
		c.log.Panicf("RdConfig Subnet Cache incorrect after %s operation", op)
	} else {
		c.log.Debugf("Subnet Correct: %+v", rdConSub)
		ret = true
	}
	return ret
}

func TestRdConfig(t *testing.T) {
	//setting ACI_SNAT_NAMESPACE, ACI_RDCONFIG_NAME for rdconfig listerwatcher
	os.Setenv("ACI_SNAT_NAMESPACE", "aci-test")
	os.Setenv("ACI_RDCONFIG_NAME", "rdconfig-test")
	cont := testController()
	rdcon := rdConfigdata([]string{"10.10.10.0/24"}, []string{"20.20.20.0/24"})
	cont.fakeRdConfigSource.Add(rdcon)
	cont.run()
	if checkRdConfig(cont, rdcon, "Add") {
		//Test update
		rdconNew := rdConfigdata([]string{"10.10.10.0/24", "30.30.30.0/24", "40.40.40.40/24"}, []string{"20.20.20.0/24"})
		cont.fakeRdConfigSource.Modify(rdconNew)
		checkRdConfig(cont, rdconNew, "Update")
		//TODO: Test Post-Delete by facilitating fake clientset
	}
}
