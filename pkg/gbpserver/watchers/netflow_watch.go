/***
Copyright 2021 Cisco Systems Inc. All rights reserved.

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
	"fmt"
	"github.com/noironetworks/aci-containers/pkg/gbpserver"
	netflowpolicy "github.com/noironetworks/aci-containers/pkg/netflowpolicy/apis/aci.netflow/v1alpha"
	netflowclientset "github.com/noironetworks/aci-containers/pkg/netflowpolicy/clientset/versioned"
	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

const (
	netflowCRDSub       = "NetflowExporterConfig"
	netflowCRDParentSub = "PlatformConfig"
)

type netflowCRD struct {
	DstAddr           string `json:"destIp"`
	DstPort           int    `json:"destPort"`
	FlowType          string `json:"flowType,omitempty"`
	ActiveFlowTimeOut int    `json:"activeFlowTimeOut,omitempty"`
	IdleFlowTimeOut   int    `json:"idleFlowTimeOut,omitempty"`
	SamplingRate      int    `json:"samplingRate,omitempty"`
	Name              string `json:"name,omitempty"`
}

type NetflowWatcher struct {
	log *log.Entry
	gs  *gbpserver.Server
	rc  restclient.Interface
}

func NewNetflowWatcher(gs *gbpserver.Server) (*NetflowWatcher, error) {
	gcfg := gs.Config()
	level, err := log.ParseLevel(gcfg.WatchLogLevel)
	if err != nil {
		panic(err.Error())
	}
	logger := log.New()
	logger.Level = level
	log := logger.WithField("mod", "NETFLOW-W")
	cfg, err := restclient.InClusterConfig()
	if err != nil {
		return nil, err
	}

	netflowclient, err := netflowclientset.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	restClient := netflowclient.AciV1alpha().RESTClient()
	return &NetflowWatcher{
		log: log,
		rc:  restClient,
		gs:  gs,
	}, nil
}

func (nfw *NetflowWatcher) InitNetflowInformer(stopCh <-chan struct{}) {
	nfw.watchNetflow(stopCh)
}

func (nfw *NetflowWatcher) watchNetflow(stopCh <-chan struct{}) {

	NetflowLw := cache.NewListWatchFromClient(nfw.rc, "netflowpolicies", metav1.NamespaceAll, fields.Everything())
	_, netflowInformer := cache.NewInformer(NetflowLw, &netflowpolicy.NetflowPolicy{}, 0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				nfw.netflowAdded(obj)
			},
			UpdateFunc: func(oldobj interface{}, newobj interface{}) {
				nfw.netflowAdded(newobj)
			},
			DeleteFunc: func(obj interface{}) {
				nfw.netflowDeleted(obj)
			},
		})
	go netflowInformer.Run(stopCh)
}

func (nfw *NetflowWatcher) netflowAdded(obj interface{}) {
	netflow, ok := obj.(*netflowpolicy.NetflowPolicy)
	if !ok {
		nfw.log.Errorf("netflowAdded: Bad object type")
		return
	}

	nfw.log.Infof("netflowAdded - %s", netflow.ObjectMeta.Name)
	netflowMO := &netflowCRD{
		DstAddr:           netflow.Spec.FlowSamplingPolicy.DstAddr,
		DstPort:           netflow.Spec.FlowSamplingPolicy.DstPort,
		FlowType:          netflow.Spec.FlowSamplingPolicy.FlowType,
		ActiveFlowTimeOut: netflow.Spec.FlowSamplingPolicy.ActiveFlowTimeOut,
		IdleFlowTimeOut:   netflow.Spec.FlowSamplingPolicy.IdleFlowTimeOut,
		SamplingRate:      netflow.Spec.FlowSamplingPolicy.SamplingRate,
		Name:              netflow.ObjectMeta.Name,
	}
	nfw.gs.AddGBPCustomMo(netflowMO)
}

func (nfw *NetflowWatcher) netflowDeleted(obj interface{}) {
	netflow, ok := obj.(*netflowpolicy.NetflowPolicy)
	if !ok {
		nfw.log.Errorf("netflowDeleted: Bad object type")
		return
	}

	nfw.log.Infof("netflowDeleted - %s", netflow.ObjectMeta.Name)
	netflowMO := &netflowCRD{
		DstAddr:           netflow.Spec.FlowSamplingPolicy.DstAddr,
		DstPort:           netflow.Spec.FlowSamplingPolicy.DstPort,
		FlowType:          netflow.Spec.FlowSamplingPolicy.FlowType,
		ActiveFlowTimeOut: netflow.Spec.FlowSamplingPolicy.ActiveFlowTimeOut,
		IdleFlowTimeOut:   netflow.Spec.FlowSamplingPolicy.IdleFlowTimeOut,
		SamplingRate:      netflow.Spec.FlowSamplingPolicy.SamplingRate,
		Name:              netflow.ObjectMeta.Name,
	}
	nfw.gs.DelGBPCustomMo(netflowMO)
}

func (nf *netflowCRD) convertFlowType() {
	if nf.FlowType == "netflow" {
		nf.FlowType = "v5"
	} else if nf.FlowType == "ipfix" {
		nf.FlowType = "v9"
	}
}

func (nf *netflowCRD) Subject() string {
	return netflowCRDSub
}

func (nf *netflowCRD) URI(gs *gbpserver.Server) string {
	platformURI := gs.GetPlatformURI()
	return fmt.Sprintf("%s%s/%s/", platformURI, netflowCRDSub, nf.Name)
}

func (nf *netflowCRD) Properties() map[string]interface{} {

	nf.convertFlowType()
	return map[string]interface{}{
		"dstAddr":           nf.DstAddr,
		"dstPort":           nf.DstPort,
		"version":           nf.FlowType,
		"activeFlowTimeOut": nf.ActiveFlowTimeOut,
		"idleFlowTimeOut":   nf.IdleFlowTimeOut,
		"samplingRate":      nf.SamplingRate,
		"name":              nf.Name,
	}
}

func (nf *netflowCRD) ParentSub() string {
	return netflowCRDParentSub
}

func (nf *netflowCRD) ParentURI(gs *gbpserver.Server) string {
	nfParentURI := gs.GetPlatformURI()
	return nfParentURI
}

func (nf *netflowCRD) Children() []string {
	return []string{}
}
