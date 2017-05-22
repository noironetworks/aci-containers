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

package controller

import (
	"fmt"
	"net"
	"reflect"
	"sort"
	"strconv"

	"github.com/Sirupsen/logrus"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	v1 "k8s.io/client-go/pkg/api/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/kubernetes/pkg/controller"

	"github.com/noironetworks/aci-containers/pkg/apicapi"
	"github.com/noironetworks/aci-containers/pkg/metadata"
)

func (cont *AciController) initEndpointsInformerFromClient(
	kubeClient kubernetes.Interface) {

	cont.initEndpointsInformerBase(&cache.ListWatch{
		ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
			return kubeClient.CoreV1().Endpoints(metav1.NamespaceAll).List(options)
		},
		WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
			return kubeClient.CoreV1().Endpoints(metav1.NamespaceAll).Watch(options)
		},
	})
}

func (cont *AciController) initEndpointsInformerBase(listWatch *cache.ListWatch) {
	cont.endpointsInformer = cache.NewSharedIndexInformer(
		listWatch,
		&v1.Endpoints{},
		controller.NoResyncPeriodFunc(),
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	cont.endpointsInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			cont.endpointsChanged(obj)
		},
		UpdateFunc: func(_ interface{}, obj interface{}) {
			cont.endpointsChanged(obj)
		},
		DeleteFunc: func(obj interface{}) {
			cont.endpointsChanged(obj)
		},
	})

}

func (cont *AciController) initServiceInformerFromClient(
	kubeClient *kubernetes.Clientset) {

	cont.initServiceInformerBase(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				return kubeClient.CoreV1().Services(metav1.NamespaceAll).List(options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				return kubeClient.CoreV1().Services(metav1.NamespaceAll).Watch(options)
			},
		})
}

func (cont *AciController) initServiceInformerBase(listWatch *cache.ListWatch) {
	cont.serviceInformer = cache.NewSharedIndexInformer(
		listWatch,
		&v1.Service{},
		controller.NoResyncPeriodFunc(),
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	cont.serviceInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			cont.serviceChanged(obj)
		},
		UpdateFunc: func(_ interface{}, obj interface{}) {
			cont.serviceChanged(obj)
		},
		DeleteFunc: func(obj interface{}) {
			cont.serviceDeleted(obj)
		},
	})
}

func serviceLogger(log *logrus.Logger, as *v1.Service) *logrus.Entry {
	return log.WithFields(logrus.Fields{
		"namespace": as.ObjectMeta.Namespace,
		"name":      as.ObjectMeta.Name,
		"type":      as.Spec.Type,
	})
}

func (cont *AciController) endpointsChanged(obj interface{}) {
	servicekey, err := cache.MetaNamespaceKeyFunc(obj.(*v1.Endpoints))
	if err != nil {
		cont.log.Error("Could not create service key: ", err)
		return
	}
	cont.queueServiceUpdateByKey(servicekey)
}

func returnIps(pool *netIps, ips []net.IP) {
	for _, ip := range ips {
		if ip.To4() != nil {
			pool.V4.AddIp(ip)
		} else if ip.To16() != nil {
			pool.V6.AddIp(ip)
		}
	}
}

func (cont *AciController) staticServiceObjs() apicapi.ApicSlice {
	// Service bridge domain
	bdName := cont.aciNameForKey("bd", "kubernetes-service")

	bd := apicapi.NewBridgeDomain(cont.config.AciVrfTenant, bdName)
	bd.SetAttr("arpFlood", "yes")
	bd.SetAttr("ipLearning", "no")
	bd.SetAttr("unkMacUcastAct", "flood")
	bdToOut := apicapi.NewRsBdToOut(bd.GetDn(), cont.config.AciL3Out)
	bd.AddChild(bdToOut)
	bdToVrf := apicapi.NewRsCtx(bd.GetDn(), cont.config.AciVrf)
	bd.AddChild(bdToVrf)

	bdn := bd.GetDn()
	for _, cidr := range cont.config.NodeServiceSubnets {
		sn := apicapi.NewSubnet(bdn, cidr)
		bd.AddChild(sn)
	}

	return apicapi.ApicSlice{bd}
}

func (cont *AciController) initStaticServiceObjs() {
	cont.apicConn.WriteApicObjects(cont.config.AciPrefix+"_service_static",
		cont.staticServiceObjs())
}

// can be called with index lock
func (cont *AciController) updateServicesForNode(nodename string) {
	cache.ListAll(cont.endpointsInformer.GetIndexer(), labels.Everything(),
		func(endpointsobj interface{}) {
			endpoints := endpointsobj.(*v1.Endpoints)
			for _, subset := range endpoints.Subsets {
				for _, addr := range subset.Addresses {
					if addr.NodeName != nil && *addr.NodeName == nodename {

						servicekey, err :=
							cache.MetaNamespaceKeyFunc(endpointsobj.(*v1.Endpoints))
						if err != nil {
							cont.log.Error("Could not create endpoints key: ", err)
							return
						}
						cont.queueServiceUpdateByKey(servicekey)
						return
					}
				}
			}
		})
}

// must have index lock
func (cont *AciController) fabricPathForNode(name string) (string, bool) {
	for _, device := range cont.nodeOpflexDevice[name] {
		return device.GetAttrStr("fabricPathDn"), true
	}
	return "", false
}

func apicRedirectPol(name string, tenantName string, nodes []string,
	nodeMap map[string]*metadata.ServiceEndpoint) (apicapi.ApicObject, string) {
	rp := apicapi.NewVnsSvcRedirectPol(tenantName, name)
	rpDn := rp.GetDn()
	for _, node := range nodes {
		serviceEp, ok := nodeMap[node]
		if !ok {
			continue
		}
		if serviceEp.Ipv4 != nil {
			rp.AddChild(apicapi.NewVnsRedirectDest(rpDn,
				serviceEp.Ipv4.String(), serviceEp.Mac))
		}
		if serviceEp.Ipv6 != nil {
			rp.AddChild(apicapi.NewVnsRedirectDest(rpDn,
				serviceEp.Ipv6.String(), serviceEp.Mac))
		}
	}
	return rp, rpDn
}

func apicExtNet(name string, tenantName string, l3Out string,
	ingresses []string) apicapi.ApicObject {

	en := apicapi.NewL3extInstP(tenantName, l3Out, name)
	enDn := en.GetDn()
	en.AddChild(apicapi.NewFvRsProv(enDn, name))
	for _, ingress := range ingresses {
		en.AddChild(apicapi.NewL3extSubnet(enDn, ingress+"/32"))
	}
	return en
}

func apicExtNetCons(conName string, tenantName string,
	l3Out string, net string) apicapi.ApicObject {

	enDn := fmt.Sprintf("uni/tn-%s/out-%s/instP-%s", tenantName, l3Out, net)
	return apicapi.NewFvRsCons(enDn, conName)
}

func apicContract(conName string, tenantName string,
	graphName string) apicapi.ApicObject {
	con := apicapi.NewVzBrCP(tenantName, conName)
	cs := apicapi.NewVzSubj(con.GetDn(), "loadbalancedservice")
	csDn := cs.GetDn()
	cs.AddChild(apicapi.NewVzRsSubjGraphAtt(csDn, graphName))
	cs.AddChild(apicapi.NewVzRsSubjFiltAtt(csDn, conName))
	con.AddChild(cs)
	return con
}

func apicDevCtx(name string, tenantName string,
	graphName string, bdName string, rpDn string) apicapi.ApicObject {

	cc := apicapi.NewVnsLDevCtx(tenantName, name, graphName, "loadbalancer")
	ccDn := cc.GetDn()
	graphDn := fmt.Sprintf("uni/tn-%s/lDevVip-%s", tenantName, graphName)
	lifDn := fmt.Sprintf("%s/lIf-%s", graphDn, "interface")
	bdDn := fmt.Sprintf("uni/tn-%s/BD-%s", tenantName, bdName)
	cc.AddChild(apicapi.NewVnsRsLDevCtxToLDev(ccDn, graphDn))
	for _, ctxConn := range []string{"consumer", "provider"} {
		lifCtx := apicapi.NewVnsLIfCtx(ccDn, ctxConn)
		lifCtxDn := lifCtx.GetDn()
		lifCtx.AddChild(apicapi.NewVnsRsLIfCtxToSvcRedirectPol(lifCtxDn,
			rpDn))
		lifCtx.AddChild(apicapi.NewVnsRsLIfCtxToBD(lifCtxDn, bdDn))
		lifCtx.AddChild(apicapi.NewVnsRsLIfCtxToLIf(lifCtxDn, lifDn))
		cc.AddChild(lifCtx)
	}

	return cc
}

func (cont *AciController) updateServiceDeviceInstance(key string,
	service *v1.Service) {

	endpointsobj, exists, err :=
		cont.endpointsInformer.GetStore().GetByKey(key)
	if err != nil {
		cont.log.Error("Could not lookup endpoints for " +
			key + ": " + err.Error())
		return
	}

	cont.indexMutex.Lock()
	nodeMap := make(map[string]*metadata.ServiceEndpoint)

	if exists && endpointsobj != nil {
		endpoints := endpointsobj.(*v1.Endpoints)
		for _, subset := range endpoints.Subsets {
			for _, addr := range subset.Addresses {
				if addr.NodeName == nil {
					continue
				}
				nodeMeta, ok := cont.nodeServiceMetaCache[*addr.NodeName]
				if !ok {
					continue
				}
				_, ok = cont.fabricPathForNode(*addr.NodeName)
				if !ok {
					continue
				}
				nodeMap[*addr.NodeName] = &nodeMeta.serviceEp
			}
		}
	}
	cont.indexMutex.Unlock()

	var nodes []string
	for node, _ := range nodeMap {
		nodes = append(nodes, node)
	}
	sort.Strings(nodes)

	name := cont.aciNameForKey("service", key)
	graphName := cont.aciNameForKey("service", "global")
	var serviceObjs apicapi.ApicSlice
	if len(nodes) > 0 {

		// 1. Service redirect policy
		// The service redirect policy contains the MAC address
		// and IP address of each of the service endpoints for
		// each node that hosts a pod for this service.  The
		// example below shows the case of two nodes.
		rp, rpDn :=
			apicRedirectPol(name, cont.config.AciVrfTenant, nodes, nodeMap)
		serviceObjs = append(serviceObjs, rp)

		// 2. Service graph contract and external network
		// The service graph contract must be bound to the service
		// graph.  This contract must be consumed by the default
		// layer 3 network and provided by the service layer 3
		// network.
		{
			var ingresses []string
			for _, ingress := range service.Status.LoadBalancer.Ingress {
				ingresses = append(ingresses, ingress.IP)
			}
			serviceObjs = append(serviceObjs,
				apicExtNet(name, cont.config.AciVrfTenant,
					cont.config.AciL3Out, ingresses))
		}

		serviceObjs = append(serviceObjs,
			apicContract(name, cont.config.AciVrfTenant, graphName))

		for _, net := range cont.config.AciExtNetworks {
			serviceObjs = append(serviceObjs,
				apicExtNetCons(name, cont.config.AciVrfTenant,
					cont.config.AciL3Out, net))
		}
		{
			filter := apicapi.NewVzFilter(cont.config.AciVrfTenant, name)
			filterDn := filter.GetDn()

			for i, port := range service.Spec.Ports {
				fe := apicapi.NewVzEntry(filterDn, strconv.Itoa(i))
				fe.SetAttr("etherT", "ip")
				if port.Protocol == v1.ProtocolUDP {
					fe.SetAttr("prot", "udp")
				} else {
					fe.SetAttr("prot", "tcp")
				}
				pstr := strconv.Itoa(int(port.Port))
				fe.SetAttr("dFromPort", pstr)
				fe.SetAttr("dToPort", pstr)
				filter.AddChild(fe)
			}
			serviceObjs = append(serviceObjs, filter)
		}

		// 3. Device cluster context
		// The logical device context binds the service contract
		// to the redirect policy and the device cluster and
		// bridge domain for the device cluster.
		serviceObjs = append(serviceObjs,
			apicDevCtx(name, cont.config.AciVrfTenant, graphName,
				cont.aciNameForKey("bd", "kubernetes-service"), rpDn))
	}

	cont.apicConn.WriteApicObjects(name, serviceObjs)
}

func (cont *AciController) queueServiceUpdateByKey(key string) {
	cont.serviceQueue.Add(key)
}

func (cont *AciController) queueServiceUpdate(service *v1.Service) {
	key, err := cache.MetaNamespaceKeyFunc(service)
	if err != nil {
		serviceLogger(cont.log, service).
			Error("Could not create service key: ", err)
		return
	}
	cont.serviceQueue.Add(key)
}

func apicDeviceCluster(name string, vrfTenant string,
	physDom string, encap string,
	nodes []string, nodeMap map[string]string) (apicapi.ApicObject, string) {

	dc := apicapi.NewVnsLDevVip(vrfTenant, name)
	dc.SetAttr("managed", "no")
	dcDn := dc.GetDn()
	dc.AddChild(apicapi.NewVnsRsALDevToPhysDomP(dcDn,
		fmt.Sprintf("uni/phys-%s", physDom)))
	lif := apicapi.NewVnsLIf(dcDn, "interface")
	lif.SetAttr("encap", encap)
	lifDn := lif.GetDn()

	for _, node := range nodes {
		path, ok := nodeMap[node]
		if !ok {
			continue
		}

		cdev := apicapi.NewVnsCDev(dcDn, node)
		cif := apicapi.NewVnsCif(cdev.GetDn(), "interface")
		cif.AddChild(apicapi.NewVnsRsCIfPathAtt(cif.GetDn(), path))
		cdev.AddChild(cif)
		lif.AddChild(apicapi.NewVnsRsCIfAttN(lifDn, cif.GetDn()))
		dc.AddChild(cdev)
	}

	dc.AddChild(lif)

	return dc, dcDn
}

func apicServiceGraph(name string, tenantName string,
	dcDn string) apicapi.ApicObject {

	sg := apicapi.NewVnsAbsGraph(tenantName, name)
	sgDn := sg.GetDn()
	var provDn string
	var consDn string
	var cTermDn string
	var pTermDn string
	{
		an := apicapi.NewVnsAbsNode(sgDn, "loadbalancer")
		an.SetAttr("managed", "no")
		an.SetAttr("routingMode", "Redirect")
		anDn := an.GetDn()
		cons := apicapi.NewVnsAbsFuncConn(anDn, "consumer")
		consDn = cons.GetDn()
		an.AddChild(cons)
		prov := apicapi.NewVnsAbsFuncConn(anDn, "provider")
		provDn = prov.GetDn()
		an.AddChild(prov)
		an.AddChild(apicapi.NewVnsRsNodeToLDev(anDn, dcDn))
		sg.AddChild(an)
	}
	{
		tnc := apicapi.NewVnsAbsTermNodeCon(sgDn, "T1")
		tncDn := tnc.GetDn()
		cTerm := apicapi.NewVnsAbsTermConn(tncDn)
		cTermDn = cTerm.GetDn()
		tnc.AddChild(cTerm)
		tnc.AddChild(apicapi.NewVnsInTerm(tncDn))
		tnc.AddChild(apicapi.NewVnsOutTerm(tncDn))
		sg.AddChild(tnc)
	}
	{
		tnp := apicapi.NewVnsAbsTermNodeProv(sgDn, "T2")
		tnpDn := tnp.GetDn()
		pTerm := apicapi.NewVnsAbsTermConn(tnpDn)
		pTermDn = pTerm.GetDn()
		tnp.AddChild(pTerm)
		tnp.AddChild(apicapi.NewVnsInTerm(tnpDn))
		tnp.AddChild(apicapi.NewVnsOutTerm(tnpDn))
		sg.AddChild(tnp)
	}
	{
		acc := apicapi.NewVnsAbsConnection(sgDn, "C1")
		acc.SetAttr("connDir", "provider")
		accDn := acc.GetDn()
		acc.AddChild(apicapi.NewVnsRsAbsConnectionConns(accDn, consDn))
		acc.AddChild(apicapi.NewVnsRsAbsConnectionConns(accDn, cTermDn))
		sg.AddChild(acc)
	}
	{
		acp := apicapi.NewVnsAbsConnection(sgDn, "C2")
		acp.SetAttr("connDir", "provider")
		acpDn := acp.GetDn()
		acp.AddChild(apicapi.NewVnsRsAbsConnectionConns(acpDn, provDn))
		acp.AddChild(apicapi.NewVnsRsAbsConnectionConns(acpDn, pTermDn))
		sg.AddChild(acp)
	}
	return sg
}
func (cont *AciController) updateDeviceCluster() {
	nodeMap := make(map[string]string)

	cont.indexMutex.Lock()
	for node, _ := range cont.nodeServiceMetaCache {
		fabricPath, ok := cont.fabricPathForNode(node)
		if !ok {
			continue
		}
		nodeMap[node] = fabricPath
	}
	cont.indexMutex.Unlock()

	var nodes []string
	for node, _ := range nodeMap {
		nodes = append(nodes, node)
	}
	sort.Strings(nodes)

	name := cont.aciNameForKey("service", "global")
	var serviceObjs apicapi.ApicSlice

	// 1. Device cluster:
	// The device cluster is a set of physical paths that need to be
	// created for each node in the cluster, that correspond to the
	// service interface for each node.
	dc, dcDn := apicDeviceCluster(name, cont.config.AciVrfTenant,
		cont.config.AciServicePhysDom, cont.config.AciServiceEncap,
		nodes, nodeMap)
	serviceObjs = append(serviceObjs, dc)

	// 2. Service graph template
	// The service graph controls how the traffic will be redirected.
	// A service graph must be created for each device cluster.
	serviceObjs = append(serviceObjs,
		apicServiceGraph(name, cont.config.AciVrfTenant, dcDn))

	cont.apicConn.WriteApicObjects(name, serviceObjs)
}

func (cont *AciController) fabricPathLogger(node string,
	obj apicapi.ApicObject) *logrus.Entry {

	return cont.log.WithFields(logrus.Fields{
		"fabricPath": obj.GetAttr("fabricPathDn"),
		"node":       node,
	})
}

func (cont *AciController) opflexDeviceChanged(obj apicapi.ApicObject) {
	var nodeUpdates []string

	cont.indexMutex.Lock()
	nodefound := false
	for node, devices := range cont.nodeOpflexDevice {
		found := false

		if node == obj.GetAttrStr("hostName") {
			nodefound = true
		}

		for i, device := range devices {
			if device.GetDn() != obj.GetDn() {
				continue
			}
			found = true

			if obj.GetAttrStr("hostName") != node {
				cont.fabricPathLogger(node, device).
					Debug("Moving opflex device path from node")

				devices = append(devices[:i], devices[i+1:]...)
				cont.nodeOpflexDevice[node] = devices
				nodeUpdates = append(nodeUpdates, node)
				break
			} else if device.GetAttrStr("fabricPathDn") !=
				obj.GetAttrStr("fabricPathDn") {
				cont.fabricPathLogger(node, obj).
					Debug("Updating opflex device path")

				devices = append(append(devices[:i], devices[i+1:]...), obj)
				cont.nodeOpflexDevice[node] = devices
				nodeUpdates = append(nodeUpdates, node)
				break
			}
		}
		if !found && obj.GetAttrStr("hostName") == node {
			cont.fabricPathLogger(node, obj).
				Debug("Appending opflex device path")

			devices = append(devices, obj)
			cont.nodeOpflexDevice[node] = devices
			nodeUpdates = append(nodeUpdates, node)
		}
	}
	if !nodefound {
		node := obj.GetAttrStr("hostName")
		cont.fabricPathLogger(node, obj).Debug("Adding opflex device path")
		cont.nodeOpflexDevice[node] = apicapi.ApicSlice{obj}
		nodeUpdates = append(nodeUpdates, node)
	}
	cont.indexMutex.Unlock()

	cont.updateDeviceCluster()
	for _, node := range nodeUpdates {
		cont.updateServicesForNode(node)
	}
}

func (cont *AciController) opflexDeviceDeleted(dn string) {
	cont.log.Debug("odev Deleted ", dn)

	var nodeUpdates []string

	cont.indexMutex.Lock()
	for node, devices := range cont.nodeOpflexDevice {
		for i, device := range devices {
			if device.GetDn() != dn {
				continue
			}

			cont.fabricPathLogger(node, device).
				Debug("Deleting opflex device path")
			devices = append(devices[:i], devices[i+1:]...)
			cont.nodeOpflexDevice[node] = devices
			nodeUpdates = append(nodeUpdates, node)
			break
		}
		if len(devices) == 0 {
			delete(cont.nodeOpflexDevice, node)
		}
	}
	cont.indexMutex.Unlock()

	cont.updateDeviceCluster()
	for _, node := range nodeUpdates {
		cont.updateServicesForNode(node)
	}
}

func (cont *AciController) serviceChanged(obj interface{}) {
	cont.queueServiceUpdate(obj.(*v1.Service))
}

func (cont *AciController) serviceFullSync() {
	cache.ListAll(cont.serviceInformer.GetIndexer(), labels.Everything(),
		func(sobj interface{}) {
			cont.queueServiceUpdate(sobj.(*v1.Service))
		})
}

func (cont *AciController) handleServiceUpdate(service *v1.Service) bool {
	cont.indexMutex.Lock()
	logger := serviceLogger(cont.log, service)

	servicekey, err := cache.MetaNamespaceKeyFunc(service)
	if err != nil {
		logger.Error("Could not create service key: ", err)
		cont.indexMutex.Unlock()
		return false
	}
	meta, ok := cont.serviceMetaCache[servicekey]
	isLoadBalancer := service.Spec.Type == v1.ServiceTypeLoadBalancer
	if ok && !isLoadBalancer {
		cont.indexMutex.Unlock()
		cont.serviceDeleted(service)
		return false
	}
	if !isLoadBalancer {
		cont.indexMutex.Unlock()
		return false
	}
	if !ok {
		meta = &serviceMeta{}
		cont.serviceMetaCache[servicekey] = meta

		// Read any existing IPs and attempt to allocate them to the pod
		for _, ingress := range service.Status.LoadBalancer.Ingress {
			ip := net.ParseIP(ingress.IP)
			if ip == nil {
				continue
			}
			if ip.To4() != nil {
				if cont.serviceIps.V4.RemoveIp(ip) {
					meta.ingressIps = append(meta.ingressIps, ip)
				} else if cont.staticServiceIps.V4.RemoveIp(ip) {
					meta.staticIngressIps = append(meta.staticIngressIps, ip)
				}
			} else if ip.To16() != nil {
				if cont.serviceIps.V6.RemoveIp(ip) {
					meta.ingressIps = append(meta.ingressIps, ip)
				} else if cont.staticServiceIps.V6.RemoveIp(ip) {
					meta.staticIngressIps = append(meta.staticIngressIps, ip)
				}
			}
		}
	}

	if !cont.serviceSyncEnabled {
		cont.indexMutex.Unlock()
		return false
	}

	// try to give the requested load balancer IP to the pod
	requestedIp := net.ParseIP(service.Spec.LoadBalancerIP)
	if requestedIp != nil {
		hasRequestedIp := false
		for _, ip := range meta.ingressIps {
			if reflect.DeepEqual(requestedIp, ip) {
				hasRequestedIp = true
			}
		}
		if !hasRequestedIp {
			if requestedIp.To4() != nil &&
				cont.staticServiceIps.V4.RemoveIp(requestedIp) {
				hasRequestedIp = true
			} else if requestedIp.To16() != nil &&
				cont.staticServiceIps.V6.RemoveIp(requestedIp) {
				hasRequestedIp = true
			}
		}
		if hasRequestedIp {
			returnIps(cont.serviceIps, meta.ingressIps)
			meta.ingressIps = nil
			meta.staticIngressIps = []net.IP{requestedIp}
			meta.requestedIp = requestedIp
		}
	} else if meta.requestedIp != nil {
		meta.requestedIp = nil
		returnIps(cont.staticServiceIps, meta.staticIngressIps)
		meta.staticIngressIps = nil
	}

	if len(meta.ingressIps) == 0 && len(meta.staticIngressIps) == 0 {
		ipv4, err := cont.serviceIps.V4.GetIp()
		if err != nil {
			logger.Error("No IP addresses available for service")
		} else {
			meta.ingressIps = []net.IP{ipv4}
		}
	}

	cont.indexMutex.Unlock()

	var newIngress []v1.LoadBalancerIngress
	for _, ip := range meta.ingressIps {
		newIngress = append(newIngress, v1.LoadBalancerIngress{IP: ip.String()})
	}
	for _, ip := range meta.staticIngressIps {
		newIngress = append(newIngress, v1.LoadBalancerIngress{IP: ip.String()})
	}

	if !reflect.DeepEqual(newIngress, service.Status.LoadBalancer.Ingress) {
		service.Status.LoadBalancer.Ingress = newIngress

		_, err := cont.updateServiceStatus(service)
		if err != nil {
			logger.Error("Failed to update service: ", err)
		} else {
			logger.WithFields(logrus.Fields{
				"status": service.Status.LoadBalancer.Ingress,
			}).Info("Updated service load balancer status")
		}
	}

	cont.updateServiceDeviceInstance(servicekey, service)
	return false
}

func (cont *AciController) serviceDeleted(obj interface{}) {
	service := obj.(*v1.Service)
	logger := serviceLogger(cont.log, service)

	servicekey, err := cache.MetaNamespaceKeyFunc(service)
	if err != nil {
		logger.Error("Could not create service key: ", err)
		return
	}
	cont.indexMutex.Lock()
	if meta, ok := cont.serviceMetaCache[servicekey]; ok {
		returnIps(cont.serviceIps, meta.ingressIps)
		returnIps(cont.staticServiceIps, meta.staticIngressIps)
		delete(cont.serviceMetaCache, servicekey)
	}
	cont.indexMutex.Unlock()
	cont.apicConn.ClearApicObjects(cont.aciNameForKey("service", servicekey))
}
