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

package hostagent

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/noironetworks/aci-containers/pkg/util"
	configv1 "github.com/openshift/api/config/v1"
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/kubernetes/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
)

type opflexServiceMapping struct {
	ServiceIp    string `json:"service-ip,omitempty"`
	ServiceProto string `json:"service-proto,omitempty"`
	ServicePort  uint16 `json:"service-port,omitempty"`

	NextHopIps  []string `json:"next-hop-ips"`
	NextHopPort uint16   `json:"next-hop-port,omitempty"`

	Conntrack       bool                         `json:"conntrack-enabled"`
	NodePort        uint16                       `json:"node-port,omitempty"`
	SessionAffinity *opflexSessionAffinityConfig `json:"session-affinity,omitempty"`
}

type opflexService struct {
	Uuid string `json:"uuid"`

	DomainPolicySpace string `json:"domain-policy-space,omitempty"`
	DomainName        string `json:"domain-name,omitempty"`

	ServiceMode   string `json:"service-mode,omitempty"`
	ServiceMac    string `json:"service-mac,omitempty"`
	InterfaceName string `json:"interface-name,omitempty"`
	InterfaceIp   string `json:"interface-ip,omitempty"`
	InterfaceVlan uint16 `json:"interface-vlan,omitempty"`
	ServiceType   string `json:"service-type,omitempty"`

	ServiceMappings []opflexServiceMapping `json:"service-mapping"`

	Attributes map[string]string `json:"attributes,omitempty"`
}

type opflexSessionAffinityConfig struct {
	// clientIP contains the configurations of Client IP based session affinity.
	ClientIP opflexClientIPConfig `json:"client-ip,omitempty"`
}

// ClientIPConfig represents the configurations of Client IP based session affinity.
type opflexClientIPConfig struct {
	// timeoutSeconds specifies the seconds of ClientIP type session sticky time.
	// The value must be >0 && <=86400(for 1 day) if ServiceAffinity == "ClientIP".
	// Default value is 10800(for 3 hours).
	TimeoutSeconds int32 `json:"timeout-seconds,omitempty"`
}

// Default Session value is 10800(for 3 hours)
const (
	DefaultSessionAffinityTimer = 10800
	TempSessionAffinityTimer    = 1
)

// Name of the Openshift Service
const (
	RouterInternalDefault string = "router-internal-default"
)

// Namespace of Openshift Service
const (
	OpenShiftIngressNs string = "openshift-ingress"
)

// Represent the Openshift services
type opflexOcService struct {
	Name      string
	Namespace string
}

var Version = map[string]bool{
	"openshift-4.6-baremetal":  true,
	"openshift-4.7-baremetal":  true,
	"openshift-4.8-baremetal":  true,
	"openshift-4.9-baremetal":  true,
	"openshift-4.10-baremetal": true,
	"openshift-4.11-baremetal": true,
	"openshift-4.12-baremetal": true,
	"openshift-4.4-esx":        true,
	"openshift-4.5-esx":        true,
	"openshift-4.6-esx":        true,
	"openshift-4.7-esx":        true,
	"openshift-4.8-esx":        true,
	"openshift-4.9-esx":        true,
	"openshift-4.10-esx":       true,
	"openshift-4.11-esx":       true,
	"openshift-4.12-esx":       true,
}

func (agent *HostAgent) initEndpointsInformerFromClient(
	kubeClient *kubernetes.Clientset) {
	agent.initEndpointsInformerBase(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				obj, err := kubeClient.CoreV1().Endpoints(metav1.NamespaceAll).List(context.TODO(), options)
				if err != nil {
					agent.log.Fatalf("Failed to list Endpoints during initialization of EndpointsInformer: %s", err)
				}
				return obj, err
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				obj, err := kubeClient.CoreV1().Endpoints(metav1.NamespaceAll).Watch(context.TODO(), options)
				if err != nil {
					agent.log.Fatalf("Failed to watch Endpoints during initialization of EndpointsInformer: %s", err)
				}
				return obj, err
			},
		})
}

func (agent *HostAgent) initEndpointsInformerBase(listWatch *cache.ListWatch) {
	agent.endpointsInformer = cache.NewSharedIndexInformer(
		listWatch,
		&v1.Endpoints{},
		controller.NoResyncPeriodFunc(),
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	agent.endpointsInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			agent.endpointsChanged(obj)
		},
		UpdateFunc: func(_ interface{}, obj interface{}) {
			agent.endpointsChanged(obj)
		},
		DeleteFunc: func(obj interface{}) {
			agent.endpointsChanged(obj)
		},
	})
}

func (agent *HostAgent) initEndpointSliceInformerFromClient(
	kubeClient *kubernetes.Clientset) {
	agent.initEndpointSliceInformerBase(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				obj, err := kubeClient.DiscoveryV1().EndpointSlices(metav1.NamespaceAll).List(context.TODO(), options)
				if err != nil {
					agent.log.Fatalf("Failed to list EndpointSlices during initialization of EndpointSliceInformer: %s", err)
				}
				return obj, err
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				obj, err := kubeClient.DiscoveryV1().EndpointSlices(metav1.NamespaceAll).Watch(context.TODO(), options)
				if err != nil {
					agent.log.Fatalf("Failed to watch EndpointSlices during initialization of EndpointSliceInformer: %s", err)
				}
				return obj, err
			},
		})
}

func (agent *HostAgent) initEndpointSliceInformerBase(listWatch *cache.ListWatch) {
	agent.endpointSliceInformer = cache.NewSharedIndexInformer(
		listWatch,
		&discovery.EndpointSlice{},
		controller.NoResyncPeriodFunc(),
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	agent.endpointSliceInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			agent.endpointSliceChanged(obj)
		},
		UpdateFunc: func(_ interface{}, obj interface{}) {
			agent.endpointSliceChanged(obj)
		},
		DeleteFunc: func(obj interface{}) {
			agent.endpointSliceChanged(obj)
		},
	})
}

func (agent *HostAgent) initServiceInformerFromClient(
	kubeClient *kubernetes.Clientset) {
	agent.initServiceInformerBase(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				obj, err := kubeClient.CoreV1().Services(metav1.NamespaceAll).List(context.TODO(), options)
				if err != nil {
					agent.log.Fatalf("Failed to list Services during initialization of ServiceInformer: %s", err)
				}
				return obj, err
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				obj, err := kubeClient.CoreV1().Services(metav1.NamespaceAll).Watch(context.TODO(), options)
				if err != nil {
					agent.log.Fatalf("Failed to watch Services during initialization of ServiceInformer: %s", err)
				}
				return obj, err
			},
		})
}

func (agent *HostAgent) initServiceInformerBase(listWatch *cache.ListWatch) {
	agent.serviceInformer = cache.NewSharedIndexInformer(
		listWatch,
		&v1.Service{},
		controller.NoResyncPeriodFunc(),
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	agent.serviceInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			agent.serviceChanged(obj)
		},
		UpdateFunc: func(_ interface{}, obj interface{}) {
			agent.serviceChanged(obj)
		},
		DeleteFunc: func(obj interface{}) {
			agent.serviceDeleted(obj)
		},
	})
}

func writeAs(asfile string, as *opflexService) (bool, error) {
	newdata, err := json.MarshalIndent(as, "", "  ")
	if err != nil {
		return true, err
	}
	existingdata, err := os.ReadFile(asfile)
	if err == nil && reflect.DeepEqual(existingdata, newdata) {
		return false, nil
	}

	err = os.WriteFile(asfile, newdata, 0644)
	return true, err
}

func serviceLogger(log *logrus.Logger, as *v1.Service) *logrus.Entry {
	return log.WithFields(logrus.Fields{
		"namespace": as.ObjectMeta.Namespace,
		"name":      as.ObjectMeta.Name,
		"type":      as.Spec.Type,
	})
}

func opflexServiceLogger(log *logrus.Logger, as *opflexService) *logrus.Entry {
	return log.WithFields(logrus.Fields{
		"namespace": as.Attributes["namespace"],
		"name":      as.Attributes["name"],
		"uuid":      as.Uuid,
		"tenant":    as.DomainPolicySpace,
		"vrf":       as.DomainName,
	})
}

func (agent *HostAgent) syncServices() bool {
	if !agent.syncEnabled {
		return false
	}

	agent.log.Debug("Syncing services")
	agent.indexMutex.Lock()
	opflexServices := make(map[string]*opflexService)
	for k, v := range agent.opflexServices {
		val := &opflexService{}
		err := util.DeepCopyObj(v, val)
		if err != nil {
			continue
		}
		opflexServices[k] = val
	}
	agent.indexMutex.Unlock()

	files, err := os.ReadDir(agent.config.OpFlexServiceDir)
	if err != nil {
		agent.log.WithFields(
			logrus.Fields{"serviceDir": agent.config.OpFlexServiceDir},
		).Error("Could not read directory " + err.Error())
		return true
	}
	seen := make(map[string]bool)
	for _, f := range files {
		uuid := f.Name()
		if strings.HasSuffix(uuid, ".as") {
			uuid = uuid[:len(uuid)-3]
		} else if strings.HasSuffix(f.Name(), ".service") {
			uuid = uuid[:len(uuid)-8]
		} else {
			continue
		}

		asfile := filepath.Join(agent.config.OpFlexServiceDir, f.Name())
		logger := agent.log.WithFields(
			logrus.Fields{"Uuid": uuid},
		)
		existing, ok := opflexServices[uuid]
		if ok {
			wrote, err := writeAs(asfile, existing)
			if err != nil {
				opflexServiceLogger(agent.log, existing).
					Error("Error writing service file: ", err)
			} else if wrote {
				opflexServiceLogger(agent.log, existing).Info("Updated service")
			}
			seen[uuid] = true
		} else {
			logger.Info("Removing service")
			os.Remove(asfile)
		}
	}

	for _, as := range opflexServices {
		if seen[as.Uuid] {
			continue
		}

		opflexServiceLogger(agent.log, as).Info("Adding service")
		asfile :=
			filepath.Join(agent.config.OpFlexServiceDir, as.Uuid+".service")
		_, err = writeAs(asfile, as)
		if err != nil {
			opflexServiceLogger(agent.log, as).
				Error("Error writing service file: ", err)
		}
	}

	agent.log.Debug("Finished service sync")
	return false
}

// Must have index lock
func (agent *HostAgent) updateServiceDesc(external bool, as *v1.Service, key string) bool {
	if as.Spec.ClusterIP == "None" {
		agent.log.Debugf("ClusterIP of service %s is set to None", as.ObjectMeta.Name)
		return true
	}

	ofas := &opflexService{
		Uuid:              string(as.ObjectMeta.UID),
		DomainPolicySpace: agent.config.AciVrfTenant,
		DomainName:        agent.config.AciVrf,
		ServiceMode:       "loadbalancer",
		ServiceMappings:   make([]opflexServiceMapping, 0),
	}
	switch as.Spec.Type {
	case v1.ServiceTypeClusterIP:
		ofas.ServiceType = "clusterIp"
	case v1.ServiceTypeNodePort:
		ofas.ServiceType = "nodePort"
	case v1.ServiceTypeLoadBalancer:
		ofas.ServiceType = "loadBalancer"
	case v1.ServiceTypeExternalName:
		ofas.ServiceType = "externalName"
	}

	if external {
		if agent.config.UplinkIface == "" ||
			agent.serviceEp.Ipv4 == nil ||
			agent.serviceEp.Mac == "" {
			return false
		}

		ofas.InterfaceName = agent.config.UplinkIface
		ofas.InterfaceVlan = uint16(agent.config.ServiceVlan)
		// Directly using the Uplink MacAdress instead of using Opflex injected mac
		ofas.ServiceMac = agent.config.UplinkMacAdress
		ofas.InterfaceIp = agent.serviceEp.Ipv4.String()
		ofas.Uuid = ofas.Uuid + "-external"
	}
	hasValidMapping := false
	for _, sp := range as.Spec.Ports {
		hasValidMapping = agent.serviceEndPoints.SetOpflexService(ofas, as, external, key, sp)
	}

	id := fmt.Sprintf("%s_%s", as.ObjectMeta.Namespace, as.ObjectMeta.Name)
	ofas.Attributes = as.ObjectMeta.Labels
	if ofas.Attributes == nil {
		ofas.Attributes = make(map[string]string)
	}
	ofas.Attributes["namespace"] = as.ObjectMeta.Namespace
	ofas.Attributes["name"] = as.ObjectMeta.Name
	ofas.Attributes["service-name"] = id

	existing, ok := agent.opflexServices[ofas.Uuid]
	if hasValidMapping {
		if (ok && !reflect.DeepEqual(existing, ofas)) || !ok {
			agent.opflexServices[ofas.Uuid] = ofas
			// Check matching oc serivce and create a extra service file.
			// This Change is specfic to Openshfit domain
			agent.setOpenShfitService(as, external, ofas)
		}
		return true
	}
	if ok {
		delete(agent.opflexServices, ofas.Uuid)
		return true
	}

	return false
}

// must have index lock
func (agent *HostAgent) doUpdateService(key string) {
	asobj, exists, err := agent.serviceInformer.GetStore().GetByKey(key)
	if err != nil {
		agent.log.Error("Could not lookup service for " +
			key + ": " + err.Error())
		return
	}
	if !exists || asobj == nil {
		return
	}
	as := asobj.(*v1.Service)
	doSync := false
	doSync = agent.updateServiceDesc(false, as, key) || doSync
	doSync = agent.updateServiceDesc(true, as, key) || doSync
	if doSync {
		agent.scheduleSyncServices()
		agent.updateEpFileWithClusterIp(as, false)
		agent.scheduleSyncEps()
	}
}

func (agent *HostAgent) endpointsChanged(obj interface{}) {
	agent.indexMutex.Lock()
	defer agent.indexMutex.Unlock()

	endpoints := obj.(*v1.Endpoints)
	agent.log.Debugf("Endpoint changed: name=%s namespace=%s",
		endpoints.ObjectMeta.Name, endpoints.ObjectMeta.Namespace)

	key, err := cache.MetaNamespaceKeyFunc(endpoints)
	if err != nil {
		agent.log.Error("Could not create key:" + err.Error())
		return
	}
	agent.doUpdateService(key)
}
func getServiceKey(endPointSlice *discovery.EndpointSlice) (string, bool) {
	serviceName, ok := endPointSlice.Labels[discovery.LabelServiceName]
	if !ok {
		return "", false
	}
	return endPointSlice.ObjectMeta.Namespace + "/" + serviceName, true
}

func (agent *HostAgent) endpointSliceChanged(obj interface{}) {
	agent.indexMutex.Lock()
	defer agent.indexMutex.Unlock()
	endpointslice := obj.(*discovery.EndpointSlice)
	agent.log.Debugf("endpointslice changed: name=%s namespace=%s",
		endpointslice.ObjectMeta.Name, endpointslice.ObjectMeta.Namespace)
	servicekey, ok := getServiceKey(endpointslice)
	if !ok {
		return
	}
	agent.doUpdateService(servicekey)
}

func (agent *HostAgent) serviceChanged(obj interface{}) {
	agent.indexMutex.Lock()
	defer agent.indexMutex.Unlock()

	as := obj.(*v1.Service)
	agent.log.Debugf("Service changed: name=%s namespace=%s",
		as.ObjectMeta.Name, as.ObjectMeta.Namespace)

	key, err := cache.MetaNamespaceKeyFunc(as)
	if err != nil {
		serviceLogger(agent.log, as).
			Error("Could not create service object key:" + err.Error())
		return
	}
	agent.doUpdateService(key)
	agent.handleObjectUpdateForSnat(obj)
}

func (agent *HostAgent) serviceDeleted(obj interface{}) {
	agent.indexMutex.Lock()
	defer agent.indexMutex.Unlock()

	as, isService := obj.(*v1.Service)
	if !isService {
		deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			agent.log.Error("Received unexpected object: ", obj)
			return
		}
		as, ok = deletedState.Obj.(*v1.Service)
		if !ok {
			agent.log.Error("DeletedFinalStateUnknown contained non-Services object: ", deletedState.Obj)
			return
		}
	}
	agent.log.Debugf("Service deleted: name=%s namespace=%s",
		as.ObjectMeta.Name, as.ObjectMeta.Namespace)

	u := string(as.ObjectMeta.UID)
	if _, ok := agent.opflexServices[u]; ok {
		delete(agent.opflexServices, u)
		delete(agent.opflexServices, u+"-external")
		for _, v := range agent.ocServices {
			if v.Name == as.ObjectMeta.Name &&
				v.Namespace == as.ObjectMeta.Namespace {
				delete(agent.opflexServices, u+"-"+v.Name)
			}
		}
		agent.scheduleSyncServices()
		agent.deleteServIpFromEp(u)
		agent.scheduleSyncEps()
	}
	agent.handleObjectDeleteForSnat(obj)
}

func (agent *HostAgent) updateAllServices() {
	if agent.serviceInformer == nil {
		return
	}
	store := agent.serviceInformer.GetStore()
	if store == nil {
		return
	}
	keys := agent.serviceInformer.GetStore().ListKeys()
	if keys == nil {
		return
	}

	agent.indexMutex.Lock()
	defer agent.indexMutex.Unlock()
	for _, key := range keys {
		agent.doUpdateService(key)
	}
}

// This API is get the OpenShift InfrastructreIp's
func (agent *HostAgent) getInfrastucreIp(serviceName string) string {
	if _, ok := Version[agent.config.Flavor]; ok {
		if serviceName == RouterInternalDefault {
			return agent.config.InstallerProvlbIp
		}
		return ""
	}
	infraStructureInfo := &configv1.Infrastructure{
		TypeMeta:   metav1.TypeMeta{APIVersion: configv1.GroupVersion.String(), Kind: "Infrastructure"},
		ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
	}
	cfg, _ := config.GetConfig()
	scheme := runtime.NewScheme()
	scheme.AddKnownTypes(configv1.SchemeGroupVersion, &configv1.Infrastructure{})
	scheme.AddKnownTypes(configv1.SchemeGroupVersion, &metav1.GetOptions{})
	rclient, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		agent.log.Error(err.Error())
		return ""
	}
	if rclient == nil {
		agent.log.Error("client is nil")
		return ""
	}
	err = rclient.Get(context.TODO(), types.NamespacedName{
		Name: "cluster"}, infraStructureInfo)
	if err != nil {
		agent.log.Error(err.Error())
		return ""
	}
	if infraStructureInfo.Status.Platform == configv1.OpenStackPlatformType {
		if infraStructureInfo.Status.PlatformStatus != nil &&
			infraStructureInfo.Status.PlatformStatus.OpenStack != nil {
			switch serviceName {
			case RouterInternalDefault:
				return infraStructureInfo.Status.PlatformStatus.OpenStack.IngressIP
			}
		}
	}
	return ""
}

func (agent *HostAgent) setOpenShfitService(as *v1.Service, external bool, ofas *opflexService) {
	if agent.config.AciVmmDomainType == "OpenShift" {
		if !external {
			for _, v := range agent.ocServices {
				// Check for Namespace is equal
				if v.Namespace != as.ObjectMeta.Namespace {
					continue
				}
				// Check Service Name is equal
				if v.Name != as.ObjectMeta.Name {
					continue
				}
				InfraIp := agent.getInfrastucreIp(as.ObjectMeta.Name)
				agent.log.Debug("InfraIp: ", InfraIp)
				if InfraIp == "" {
					continue
				}
				ocas := &opflexService{
					Uuid:              string(as.ObjectMeta.UID),
					DomainPolicySpace: agent.config.AciVrfTenant,
					DomainName:        agent.config.AciVrf,
					ServiceMode:       "loadbalancer",
					ServiceMappings:   make([]opflexServiceMapping, 0),
				}
				ocas.Uuid = ocas.Uuid + "-" + as.ObjectMeta.Name
				for _, val := range ofas.ServiceMappings {
					val.ServiceIp = InfraIp
					ocas.ServiceMappings = append(ocas.ServiceMappings, val)
				}
				ocas.ServiceType = ofas.ServiceType
				ocas.Attributes = ofas.Attributes
				agent.opflexServices[ocas.Uuid] = ocas
			}
		}
	}

}

func (sep *serviceEndpoint) SetOpflexService(ofas *opflexService, as *v1.Service,
	external bool, key string, sp v1.ServicePort) bool {
	agent := sep.agent
	endpointsobj, exists, err :=
		agent.endpointsInformer.GetStore().GetByKey(key)
	if err != nil {
		agent.log.Error("Could not lookup endpoints for " +
			key + ": " + err.Error())
		return false
	}
	if !exists || endpointsobj == nil {
		agent.log.Debugf("no endpoints for service %s/%s", as.Namespace, as.Name)
		return false
	}
	endpoints := endpointsobj.(*v1.Endpoints)
	hasValidMapping := false

	type void struct{}
	var ipexists void
	clusterIPs := make(map[string]void)
	clusterIPs[as.Spec.ClusterIP] = ipexists
	clusterIPsField := reflect.ValueOf(as.Spec).FieldByName("ClusterIPs")
	if clusterIPsField.IsValid() {
		for _, ip := range as.Spec.ClusterIPs {
			clusterIPs[ip] = ipexists
		}
	}

	for clusterIP := range clusterIPs {
		for _, e := range endpoints.Subsets {
			if len(e.Addresses) == 0 {
				continue

			}
			parsedClusterIp := net.ParseIP(clusterIP)
			parsedPodIp := net.ParseIP(e.Addresses[0].IP)

			if parsedClusterIp == nil || parsedPodIp == nil {
				agent.log.Info("Not a valid IP address..", parsedClusterIp, parsedPodIp)
				continue
			}
			if parsedClusterIp.To4() != nil && parsedPodIp.To4() != nil {
				agent.log.Info("Both are IPv4 addresses..", parsedClusterIp, parsedPodIp, "Adding to map..")
			} else if parsedClusterIp.To4() == nil && parsedPodIp.To4() == nil {
				agent.log.Info("Both are IPv6 addresses..", parsedClusterIp, parsedPodIp, "Adding to map..")
			} else {
				continue
			}
			for _, p := range e.Ports {
				if p.Protocol != sp.Protocol {
					continue
				}
				if p.Name != sp.Name {
					continue
				}

				sm := &opflexServiceMapping{
					ServicePort:  uint16(sp.Port),
					ServiceProto: strings.ToLower(string(sp.Protocol)),
					NextHopIps:   make([]string, 0),
					NextHopPort:  uint16(p.Port),
					Conntrack:    true,
					NodePort:     uint16(sp.NodePort),
				}

				if external {
					if as.Spec.Type == v1.ServiceTypeLoadBalancer &&
						len(as.Status.LoadBalancer.Ingress) > 0 {
						for _, ip := range as.Status.LoadBalancer.Ingress {
							LBIp := net.ParseIP(ip.IP)
							if (LBIp.To4() != nil) == (parsedPodIp.To4() != nil) {
								sm.ServiceIp = ip.IP
								break
							}
						}
					}
				} else {
					sm.ServiceIp = clusterIP
				}
				sm.SessionAffinity = getSessionAffinity(as)
				for _, a := range e.Addresses {
					if !external ||
						(a.NodeName != nil && *a.NodeName == agent.config.NodeName) {
						sm.NextHopIps = append(sm.NextHopIps, a.IP)
					}
				}
				if sm.ServiceIp != "" && len(sm.NextHopIps) > 0 {
					hasValidMapping = true
				}

				ofas.ServiceMappings = append(ofas.ServiceMappings, *sm)
			}
		}
	}
	return hasValidMapping
}

func getSessionAffinity(as *v1.Service) *opflexSessionAffinityConfig {
	if as.Spec.SessionAffinityConfig != nil && as.Spec.SessionAffinity == "ClientIP" {
		config := as.Spec.SessionAffinityConfig
		if config.ClientIP != nil && config.ClientIP.TimeoutSeconds != nil {
			return &opflexSessionAffinityConfig{ClientIP: opflexClientIPConfig{TimeoutSeconds: *config.ClientIP.TimeoutSeconds}}
		} else {
			return &opflexSessionAffinityConfig{ClientIP: opflexClientIPConfig{TimeoutSeconds: DefaultSessionAffinityTimer}}
		}
	}
	return &opflexSessionAffinityConfig{ClientIP: opflexClientIPConfig{TimeoutSeconds: TempSessionAffinityTimer}}
}

func checkKeyMatch(topology, nodelabels map[string]string, key string) bool {
	val1, ok1 := topology[key]
	val2, ok2 := nodelabels[key]
	if ok1 && ok2 {
		if val1 == val2 {
			return true
		}
	}
	return false
}

func (seps *serviceEndpointSlice) SetOpflexService(ofas *opflexService, as *v1.Service,
	external bool, key string, sp v1.ServicePort) bool {
	agent := seps.agent
	hasValidMapping := false
	var endpointSlices []*discovery.EndpointSlice
	label := map[string]string{"kubernetes.io/service-name": as.ObjectMeta.Name}
	selector := labels.SelectorFromSet(labels.Set(label))
	cache.ListAllByNamespace(agent.endpointSliceInformer.GetIndexer(), as.ObjectMeta.Namespace, selector,
		func(endpointSliceobj interface{}) {
			endpointSlices = append(endpointSlices, endpointSliceobj.(*discovery.EndpointSlice))
		})

	type void struct{}
	var ipexists void
	clusterIPs := make(map[string]void)
	clusterIPs[as.Spec.ClusterIP] = ipexists
	clusterIPsField := reflect.ValueOf(as.Spec).FieldByName("ClusterIPs")
	if clusterIPsField.IsValid() {
		for _, ip := range as.Spec.ClusterIPs {
			clusterIPs[ip] = ipexists
		}
	}

	for clusterIP := range clusterIPs {
		for _, endpointSlice := range endpointSlices {
			if !(len(endpointSlice.Endpoints) > 0 && len(endpointSlice.Endpoints[0].Addresses) > 0) {
				continue
			}
			parsedClusterIp := net.ParseIP(clusterIP)
			parsedPodIp := net.ParseIP(endpointSlice.Endpoints[0].Addresses[0])
			if parsedClusterIp == nil || parsedPodIp == nil {
				agent.log.Info("Not a valid IP address..", parsedClusterIp, parsedPodIp)
				continue
			}
			if parsedClusterIp.To4() != nil && parsedPodIp.To4() != nil {
				agent.log.Info("Both are IPv4 addresses..", parsedClusterIp, parsedPodIp, "Adding to map..")
			} else if parsedClusterIp.To4() == nil && parsedPodIp.To4() == nil {
				agent.log.Info("Both are IPv6 addresses..", parsedClusterIp, parsedPodIp, "Adding to map..")
			} else {
				continue
			}
			for _, p := range endpointSlice.Ports {
				if p.Protocol != nil && *p.Protocol != sp.Protocol {
					continue
				}

				if p.Name != nil && *p.Name != sp.Name {
					continue
				}

				sm := &opflexServiceMapping{
					ServicePort:  uint16(sp.Port),
					ServiceProto: strings.ToLower(string(sp.Protocol)),
					NextHopIps:   make([]string, 0),
					NextHopPort:  uint16(*p.Port),
					Conntrack:    true,
					NodePort:     uint16(sp.NodePort),
				}

				if external {
					if as.Spec.Type == v1.ServiceTypeLoadBalancer &&
						len(as.Status.LoadBalancer.Ingress) > 0 {
						for _, ip := range as.Status.LoadBalancer.Ingress {
							LBIp := net.ParseIP(ip.IP)
							if (LBIp.To4() != nil) == (parsedPodIp.To4() != nil) {
								sm.ServiceIp = ip.IP
								break
							}
						}
					}
				} else {
					sm.ServiceIp = clusterIP
				}
				nexthops := make(map[string][]string)
				var nodeZone string
				for _, e := range endpointSlice.Endpoints {
					for _, a := range e.Addresses {
						if !external || (e.NodeName != nil && *e.NodeName == agent.config.NodeName) {
							obj, exists, err := agent.nodeInformer.GetStore().GetByKey(agent.config.NodeName)
							if err != nil {
								agent.log.Error("Could not lookup node: ", err)
								continue
							}
							if !exists && obj == nil {
								agent.log.Error("Object nil")
								continue
							}
							node := obj.(*v1.Node)
							// Services need an annotation to inform the
							// endpointslice controller to add hints
							// Currently-1.22 only zones are used as hints.
							// https://github.com/kubernetes/enhancements/tree/master/keps/sig-network/2433-topology-aware-hints
							var hintsEnabled bool = false
							if val1, ok1 := as.ObjectMeta.Annotations["service.kubernetes.io/topology-aware-routing"]; ok1 && (val1 == "auto") {
								hintsEnabled = true
							}
							if val2, ok2 := as.ObjectMeta.Annotations["service.kubernetes.io/topology-aware-hints"]; ok2 && (val2 == "auto") {
								hintsEnabled = true
							}
							zone, zoneOk := node.ObjectMeta.Labels["kubernetes.io/zone"]
							nodeZone = zone
							if !external && zoneOk && hintsEnabled && e.Hints != nil {
								for _, hintZone := range e.Hints.ForZones {
									if nodeZone == hintZone.Name {
										nexthops["topologyawarehints"] =
											append(nexthops["topologyawarehints"], a)
									}
								}
							} else {
								nexthops["any"] = append(nexthops["any"], a)
							}
						}
					}
				}
				// Select the high priority keys as datapath doesn't have support for fallback
				if _, ok := nexthops["topologyawarehints"]; ok {
					sm.NextHopIps = append(sm.NextHopIps, nexthops["topologyawarehints"]...)
					agent.log.Debugf("Topology matching hint: %s Nexthops: %s", nodeZone, sm.NextHopIps)
				} else {
					sm.NextHopIps = append(sm.NextHopIps, nexthops["any"]...)
				}
				if sm.ServiceIp != "" && len(sm.NextHopIps) > 0 {
					hasValidMapping = true
				}
				sm.SessionAffinity = getSessionAffinity(as)
				ofas.ServiceMappings = append(ofas.ServiceMappings, *sm)
			}
		}
	}
	return hasValidMapping
}

func (agent *HostAgent) updateEpFileWithClusterIp(as *v1.Service, deleted bool) {
	suid := string(as.ObjectMeta.UID)
	ofas, ok := agent.opflexServices[suid]
	var dummy struct{}
	if ok {
		if as.Spec.ClusterIP == "None" {
			return
		}
		podKeys := agent.getPodKeysFromSm(ofas.ServiceMappings)
		current := make(map[string]struct{})
		for _, key := range podKeys {
			obj, exists, err := agent.podInformer.GetStore().GetByKey(key)
			if err == nil && exists && (obj != nil) {
				pod := obj.(*v1.Pod)
				if agent.config.NodeName != pod.Spec.NodeName {
					continue
				}
				poduid := string(pod.ObjectMeta.UID)
				if _, sok := agent.servicetoPodUids[suid]; !sok {
					agent.servicetoPodUids[suid] = make(map[string]struct{})
				}
				agent.servicetoPodUids[suid][poduid] = dummy
				if _, podok := agent.podtoServiceUids[poduid]; !podok {
					agent.podtoServiceUids[poduid] = make(map[string][]string)
				}

				type void struct{}
				var ipexists void
				clusterIPs := make(map[string]void)
				clusterIPs[as.Spec.ClusterIP] = ipexists
				clusterIPsField := reflect.ValueOf(as.Spec).FieldByName("ClusterIPs")
				if clusterIPsField.IsValid() {
					for _, ip := range as.Spec.ClusterIPs {
						clusterIPs[ip] = ipexists
					}
				}

				var listClusterIPs []string
				for ip := range clusterIPs {
					listClusterIPs = append(listClusterIPs, ip)
				}
				agent.podtoServiceUids[poduid][suid] = listClusterIPs
				agent.log.Info("EpUpdated: ", poduid, " with ClusterIp: ", listClusterIPs)
				current[poduid] = dummy
			}
		}
		// reconcile with the current pods matching the service
		// if there is any stale info remove that from service matching the pods
		// update the revese map for the pod to service
		poduids, _ := agent.servicetoPodUids[suid]
		for id := range poduids {
			if _, ok := current[id]; !ok {
				delete(agent.servicetoPodUids[suid], id)
				delete(agent.podtoServiceUids[id], suid)
				if len(agent.podtoServiceUids[id]) == 0 {
					delete(agent.podtoServiceUids, id)
				}
			}
		}
	} else {
		agent.deleteServIpFromEp(suid)
	}

}

func (agent *HostAgent) getPodKeysFromSm(sm []opflexServiceMapping) []string {
	var podkeys []string
	if len(sm) > 0 {
		podIps := sm[0].NextHopIps
		for _, ip := range podIps {
			podkey, ok := agent.podIpToName[ip]
			if ok {
				podkeys = append(podkeys, podkey)
			}
		}
	}
	return podkeys
}

func (agent *HostAgent) getServiceIPs(poduid string) []string {
	var ips []string
	agent.indexMutex.Lock()
	v, ok := agent.podtoServiceUids[poduid]
	if ok {
		for _, service_ips := range v {
			ips = append(ips, service_ips...)
		}
	}
	agent.indexMutex.Unlock()
	return ips
}

func (agent *HostAgent) deleteServIpFromEp(suid string) {
	v, ok := agent.servicetoPodUids[suid]
	if ok {
		for poduid := range v {
			if _, ok := agent.podtoServiceUids[poduid]; ok {
				delete(agent.podtoServiceUids[poduid], suid)
				if len(agent.podtoServiceUids[poduid]) == 0 {
					delete(agent.podtoServiceUids, poduid)
				}
			}
		}
		delete(agent.servicetoPodUids, suid)
	}
}
