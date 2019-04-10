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
	"errors"
	"fmt"
	"github.com/Sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"net"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/noironetworks/aci-containers/pkg/apicapi"
	"github.com/noironetworks/aci-containers/pkg/metadata"
)

// Default service contract scope value 
const DefaultServiceContractScope = "context"

// Default service ext subnet scope - enable shared security
const DefaultServiceExtSubNetShared = false

func (cont *AciController) initEndpointsInformerFromClient(
	kubeClient kubernetes.Interface) {

	cont.initEndpointsInformerBase(
		cache.NewListWatchFromClient(
			kubeClient.CoreV1().RESTClient(), "endpoints",
			metav1.NamespaceAll, fields.Everything()))
}

func (cont *AciController) initEndpointsInformerBase(listWatch *cache.ListWatch) {
	cont.endpointsIndexer, cont.endpointsInformer = cache.NewIndexerInformer(
		listWatch, &v1.Endpoints{}, 0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				cont.endpointsAdded(obj)
			},
			UpdateFunc: func(old interface{}, new interface{}) {
				cont.endpointsUpdated(old, new)
			},
			DeleteFunc: func(obj interface{}) {
				cont.endpointsDeleted(obj)
			},
		},
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
}

func (cont *AciController) initServiceInformerFromClient(
	kubeClient *kubernetes.Clientset) {

	cont.initServiceInformerBase(
		cache.NewListWatchFromClient(
			kubeClient.CoreV1().RESTClient(), "services",
			metav1.NamespaceAll, fields.Everything()))
}

func (cont *AciController) initServiceInformerBase(listWatch *cache.ListWatch) {
	cont.serviceIndexer, cont.serviceInformer = cache.NewIndexerInformer(
		listWatch, &v1.Service{}, 0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				cont.serviceAdded(obj)
			},
			UpdateFunc: func(old interface{}, new interface{}) {
				cont.serviceUpdated(old, new)
			},
			DeleteFunc: func(obj interface{}) {
				cont.serviceDeleted(obj)
			},
		},
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
}

func serviceLogger(log *logrus.Logger, as *v1.Service) *logrus.Entry {
	return log.WithFields(logrus.Fields{
		"namespace": as.ObjectMeta.Namespace,
		"name":      as.ObjectMeta.Name,
		"type":      as.Spec.Type,
	})
}

func (cont *AciController) queueIPNetPolUpdates(ips map[string]bool) {
	for ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		entries, err := cont.netPolSubnetIndex.ContainingNetworks(ip)
		if err != nil {
			cont.log.Error("Corrupted network policy IP index")
			return
		}
		for _, entry := range entries {
			for npkey := range entry.(*ipIndexEntry).keys {
				cont.queueNetPolUpdateByKey(npkey)
			}
		}
	}
}

func (cont *AciController) queuePortNetPolUpdates(ports map[string]targetPort) {
	for portkey := range ports {
		entry, _ := cont.targetPortIndex[portkey]
		if entry == nil {
			continue
		}
		for npkey := range entry.networkPolicyKeys {
			cont.queueNetPolUpdateByKey(npkey)
		}
	}
}

func (cont *AciController) queueNetPolForEpAddrs(addrs []v1.EndpointAddress) {
	for _, addr := range addrs {
		if addr.TargetRef == nil || addr.TargetRef.Kind != "Pod" ||
			addr.TargetRef.Namespace == "" || addr.TargetRef.Name == "" {
			continue
		}
		podkey := addr.TargetRef.Namespace + "/" + addr.TargetRef.Name
		npkeys := cont.netPolEgressPods.GetObjForPod(podkey)
		for _, npkey := range npkeys {
			cont.queueNetPolUpdateByKey(npkey)
		}
	}
}

func (cont *AciController) queueEndpointsNetPolUpdates(endpoints *v1.Endpoints) {
	for _, subset := range endpoints.Subsets {
		cont.queueNetPolForEpAddrs(subset.Addresses)
		cont.queueNetPolForEpAddrs(subset.NotReadyAddresses)
	}
}

func (cont *AciController) returnServiceIps(ips []net.IP) {
	for _, ip := range ips {
		if ip.To4() != nil {
			cont.serviceIps.DeallocateIp(ip)
		} else if ip.To16() != nil {
			cont.serviceIps.DeallocateIp(ip)
		}
	}
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

func (cont *AciController) staticMonPolName() string {
	return cont.aciNameForKey("monPol", cont.env.ServiceBd())
}

func (cont *AciController) staticMonPolDn() string {
	if cont.config.AciServiceMonitorInterval > 0 {
		return fmt.Sprintf("uni/tn-%s/ipslaMonitoringPol-%s",
			cont.config.AciVrfTenant, cont.staticMonPolName())
	}
	return ""
}

func (cont *AciController) staticServiceObjs() apicapi.ApicSlice {
	var serviceObjs apicapi.ApicSlice

	// Service bridge domain
	bdName := cont.aciNameForKey("bd", cont.env.ServiceBd())
	bd := apicapi.NewFvBD(cont.config.AciVrfTenant, bdName)
	bd.SetAttr("arpFlood", "yes")
	bd.SetAttr("ipLearning", "no")
	bd.SetAttr("unkMacUcastAct", "flood")
	bdToOut := apicapi.NewRsBdToOut(bd.GetDn(), cont.config.AciL3Out)
	bd.AddChild(bdToOut)
	bdToVrf := apicapi.NewRsCtx(bd.GetDn(), cont.config.AciVrf)
	bd.AddChild(bdToVrf)

	bdn := bd.GetDn()
	for _, cidr := range cont.config.NodeServiceSubnets {
		sn := apicapi.NewFvSubnet(bdn, cidr)
		bd.AddChild(sn)
	}
	serviceObjs = append(serviceObjs, bd)

	// Service IP SLA monitoring policy
	if cont.config.AciServiceMonitorInterval > 0 {
		monPol := apicapi.NewFvIPSLAMonitoringPol(cont.config.AciVrfTenant,
			cont.staticMonPolName())
		monPol.SetAttr("slaFrequency",
			strconv.Itoa(cont.config.AciServiceMonitorInterval))
		serviceObjs = append(serviceObjs, monPol)
	}

	return serviceObjs
}

func (cont *AciController) initStaticServiceObjs() {
	cont.apicConn.WriteApicObjects(cont.config.AciPrefix+"_service_static",
		cont.staticServiceObjs())
}

// can be called with index lock
func (cont *AciController) updateServicesForNode(nodename string) {
	cache.ListAll(cont.endpointsIndexer, labels.Everything(),
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

// must have index lock
func (cont *AciController) deviceMacForNode(name string) (string, bool) {
	sz := len(cont.nodeOpflexDevice[name])
	if sz > 0 {
		// When the opflex-device for a node changes, for example when the
		// node is recreated, we end up with both the old and the new
		// device objects till the old object ages out on APIC. The
		// new object is at end of the devices list (see
		// opflexDeviceChanged), so we return the MAC address of the
		// last opflex-device.
		return cont.nodeOpflexDevice[name][sz-1].GetAttrStr("mac"), true
	}
	return "", false
}

func apicRedirectDst(rpDn string, ip string, mac string,
	descr string, healthGroupDn string) apicapi.ApicObject {
	dst := apicapi.NewVnsRedirectDest(rpDn, ip, mac).SetAttr("descr", descr)
	if healthGroupDn != "" {
		dst.AddChild(apicapi.NewVnsRsRedirectHealthGroup(dst.GetDn(),
			healthGroupDn))
	}
	return dst
}

func apicRedirectPol(name string, tenantName string, nodes []string,
	nodeMap map[string]*metadata.ServiceEndpoint,
	monPolDn string, healthGroupDn string) (apicapi.ApicObject, string) {

	rp := apicapi.NewVnsSvcRedirectPol(tenantName, name)
	rp.SetAttr("thresholdDownAction", "deny")
	rpDn := rp.GetDn()
	for _, node := range nodes {
		serviceEp, ok := nodeMap[node]
		if !ok {
			continue
		}
		if serviceEp.Ipv4 != nil {
			rp.AddChild(apicRedirectDst(rpDn, serviceEp.Ipv4.String(),
				serviceEp.Mac, node, healthGroupDn))
		}
		if serviceEp.Ipv6 != nil {
			rp.AddChild(apicRedirectDst(rpDn, serviceEp.Ipv6.String(),
				serviceEp.Mac, node, healthGroupDn))
		}
	}
	if monPolDn != "" {
		rp.AddChild(apicapi.NewVnsRsIPSLAMonitoringPol(rpDn, monPolDn))
	}
	return rp, rpDn
}

func apicExtNet(name string, tenantName string, l3Out string,
	ingresses []string, sharedSecurity bool) apicapi.ApicObject {

	en := apicapi.NewL3extInstP(tenantName, l3Out, name)
	enDn := en.GetDn()
	en.AddChild(apicapi.NewFvRsProv(enDn, name))

	sharedSecurityString := "import-security,shared-security"
	for _, ingress := range ingresses {
		ip := net.ParseIP(ingress)
		if ip != nil && ip.To4() != nil {
			subnet := apicapi.NewL3extSubnet(enDn, ingress+"/32")
			if sharedSecurity {
				subnet.SetAttr("scope", sharedSecurityString)
			}
			en.AddChild(subnet)
		} else if ip != nil && ip.To16() != nil {
			subnet := apicapi.NewL3extSubnet(enDn, ingress+"/128")
			if sharedSecurity {
				subnet.SetAttr("scope", sharedSecurityString)
			}
                        en.AddChild(subnet)
		}
	}
	return en
}

func apicExtNetCons(conName string, tenantName string,
	l3Out string, net string) apicapi.ApicObject {

	enDn := fmt.Sprintf("uni/tn-%s/out-%s/instP-%s", tenantName, l3Out, net)
	return apicapi.NewFvRsCons(enDn, conName)
}

//Helper function to check if a string item exists in a slice
func stringInSlice(str string, list []string) bool {
	for _, v := range list {
		if v == str {
			return true
		}
	}
	return false
}

func validScope(scope string) bool {
	validValues := []string{"", "context", "tenant", "global"}
	return stringInSlice(scope, validValues)
}

func apicContract(conName string, tenantName string,
	graphName string, scopeName string) apicapi.ApicObject {
	con := apicapi.NewVzBrCP(tenantName, conName)
	if scopeName != "" && scopeName != "context" {
		con.SetAttr("scope", scopeName)
	}
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
	service *v1.Service) error {

	endpointsobj, exists, err := cont.endpointsIndexer.GetByKey(key)
	if err != nil {
		cont.log.Error("Could not lookup endpoints for " +
			key + ": " + err.Error())
		return err
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
	for node := range nodeMap {
		nodes = append(nodes, node)
	}
	sort.Strings(nodes)
	name := cont.aciNameForKey("svc", key)
	var conScope string
	scopeVal, ok := service.ObjectMeta.Annotations[metadata.ServiceContractScopeAnnotation]
	if ok {
		normScopeVal := strings.ToLower(scopeVal)
		if !validScope(normScopeVal) {
			errString := "Invalid service contract scope value provided " + scopeVal
			err = errors.New(errString)
			serviceLogger(cont.log, service).Error("Could not create contract: ", err)
			return err

		} else {
			conScope = normScopeVal
		}
	} else {
		conScope = DefaultServiceContractScope
	}

	var sharedSecurity bool
	if conScope == "global" {
		sharedSecurity = true
	} else {
		sharedSecurity = DefaultServiceExtSubNetShared
	}

	graphName := cont.aciNameForKey("svc", "global")
	var serviceObjs apicapi.ApicSlice
	if len(nodes) > 0 {

		// 1. Service redirect policy
		// The service redirect policy contains the MAC address
		// and IP address of each of the service endpoints for
		// each node that hosts a pod for this service.  The
		// example below shows the case of two nodes.
		var healthGroupDn string
		if cont.config.AciServiceMonitorInterval > 0 {
			healthGroup :=
				apicapi.NewVnsRedirectHealthGroup(cont.config.AciVrfTenant,
					name)
			healthGroupDn = healthGroup.GetDn()
			serviceObjs = append(serviceObjs, healthGroup)
		}

		rp, rpDn :=
			apicRedirectPol(name, cont.config.AciVrfTenant, nodes,
				nodeMap, cont.staticMonPolDn(), healthGroupDn)
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
					cont.config.AciL3Out, ingresses, sharedSecurity))
		}

		contract := apicContract(name, cont.config.AciVrfTenant, graphName, conScope)
		serviceObjs = append(serviceObjs, contract)

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
				cont.aciNameForKey("bd", cont.env.ServiceBd()), rpDn))
	}

	cont.apicConn.WriteApicObjects(name, serviceObjs)
	return nil
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
	for node := range cont.nodeOpflexDevice {
		fabricPath, ok := cont.fabricPathForNode(node)
		if !ok {
			continue
		}
		nodeMap[node] = fabricPath
	}
	cont.indexMutex.Unlock()

	var nodes []string
	for node := range nodeMap {
		nodes = append(nodes, node)
	}
	sort.Strings(nodes)

	name := cont.aciNameForKey("svc", "global")
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
		"mac":        obj.GetAttr("mac"),
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
					Debug("Moving opflex device from node")

				devices = append(devices[:i], devices[i+1:]...)
				cont.nodeOpflexDevice[node] = devices
				nodeUpdates = append(nodeUpdates, node)
				break
			} else if (device.GetAttrStr("mac") != obj.GetAttrStr("mac")) ||
				(device.GetAttrStr("fabricPathDn") !=
					obj.GetAttrStr("fabricPathDn")) {

				cont.fabricPathLogger(node, obj).
					Debug("Updating opflex device")

				devices = append(append(devices[:i], devices[i+1:]...), obj)
				cont.nodeOpflexDevice[node] = devices
				nodeUpdates = append(nodeUpdates, node)
				break
			}
		}
		if !found && obj.GetAttrStr("hostName") == node {
			cont.fabricPathLogger(node, obj).
				Debug("Appending opflex device")

			devices = append(devices, obj)
			cont.nodeOpflexDevice[node] = devices
			nodeUpdates = append(nodeUpdates, node)
		}
	}
	if !nodefound {
		node := obj.GetAttrStr("hostName")
		cont.fabricPathLogger(node, obj).Debug("Adding opflex device")
		cont.nodeOpflexDevice[node] = apicapi.ApicSlice{obj}
		nodeUpdates = append(nodeUpdates, node)
	}
	cont.indexMutex.Unlock()

	for _, node := range nodeUpdates {
		cont.env.NodeServiceChanged(node)
	}
	cont.updateDeviceCluster()
}

func (cont *AciController) opflexDeviceDeleted(dn string) {
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
		cont.env.NodeServiceChanged(node)
	}
}

func (cont *AciController) writeApicSvc(key string, service *v1.Service) {
	endpointsobj, _, err := cont.endpointsIndexer.GetByKey(key)
	if err != nil {
		cont.log.Error("Could not lookup endpoints for " +
			key + ": " + err.Error())
		return
	}

	aobj := apicapi.NewVmmInjectedSvc(cont.vmmDomainProvider(),
		cont.config.AciVmmDomain, cont.config.AciVmmController,
		service.Namespace, service.Name)
	aobjDn := aobj.GetDn()
	aobj.SetAttr("guid", string(service.UID))
	// APIC model only allows one of these
	for _, ingress := range service.Status.LoadBalancer.Ingress {
		aobj.SetAttr("lbIp", ingress.IP)
		break
	}
	if service.Spec.ClusterIP != "" && service.Spec.ClusterIP != "None" {
		aobj.SetAttr("clusterIp", string(service.Spec.ClusterIP))
	}
	var t string
	switch service.Spec.Type {
	case v1.ServiceTypeClusterIP:
		t = "clusterIp"
	case v1.ServiceTypeNodePort:
		t = "nodePort"
	case v1.ServiceTypeLoadBalancer:
		t = "loadBalancer"
	case v1.ServiceTypeExternalName:
		t = "externalName"
	}
	if t != "" {
		aobj.SetAttr("type", t)
	}
	for _, port := range service.Spec.Ports {
		var proto string
		if port.Protocol == v1.ProtocolUDP {
			proto = "udp"
		} else {
			proto = "tcp"
		}
		p := apicapi.NewVmmInjectedSvcPort(aobjDn,
			strconv.Itoa(int(port.Port)), proto, port.TargetPort.String())
		p.SetAttr("nodePort", strconv.Itoa(int(port.NodePort)))
		aobj.AddChild(p)
	}
	if endpointsobj != nil {
		for _, subset := range endpointsobj.(*v1.Endpoints).Subsets {
			for _, addr := range subset.Addresses {
				if addr.TargetRef == nil || addr.TargetRef.Kind != "Pod" {
					continue
				}
				aobj.AddChild(apicapi.NewVmmInjectedSvcEp(aobjDn,
					addr.TargetRef.Name))
			}
		}
	}

	name := cont.aciNameForKey("service-vmm", key)
	cont.apicConn.WriteApicObjects(name, apicapi.ApicSlice{aobj})
}

func (cont *AciController) allocateServiceIps(servicekey string,
	service *v1.Service) bool {
	logger := serviceLogger(cont.log, service)

	cont.indexMutex.Lock()
	meta, ok := cont.serviceMetaCache[servicekey]
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
				if cont.serviceIps.GetV4IpCache()[0].RemoveIp(ip) {
					meta.ingressIps = append(meta.ingressIps, ip)
				} else if cont.staticServiceIps.V4.RemoveIp(ip) {
					meta.staticIngressIps = append(meta.staticIngressIps, ip)
				}
			} else if ip.To16() != nil {
				if cont.serviceIps.GetV6IpCache()[0].RemoveIp(ip) {
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
			cont.returnServiceIps(meta.ingressIps)
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
		meta.ingressIps = []net.IP{}

		ipv4, _ := cont.serviceIps.AllocateIp(true)
		if ipv4 != nil {
			meta.ingressIps = append(meta.ingressIps, ipv4)
		}
		ipv6, _ := cont.serviceIps.AllocateIp(false)
		if ipv6 != nil {
			meta.ingressIps = append(meta.ingressIps, ipv6)
		}
		if ipv4 == nil && ipv6 == nil {
			logger.Error("No IP addresses available for service")
			cont.indexMutex.Unlock()
			return true
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
			return true
		} else {
			logger.WithFields(logrus.Fields{
				"status": service.Status.LoadBalancer.Ingress,
			}).Info("Updated service load balancer status")
		}
	}
	return false
}

func (cont *AciController) handleServiceUpdate(service *v1.Service) bool {
	servicekey, err := cache.MetaNamespaceKeyFunc(service)
	if err != nil {
		serviceLogger(cont.log, service).
			Error("Could not create service key: ", err)
		return false
	}

	var requeue bool
	isLoadBalancer := service.Spec.Type == v1.ServiceTypeLoadBalancer
	if isLoadBalancer {
		if *cont.config.AllocateServiceIps {
			requeue = cont.allocateServiceIps(servicekey, service)
		}
		cont.indexMutex.Lock()
		if cont.serviceSyncEnabled {
			cont.indexMutex.Unlock()
			err = cont.updateServiceDeviceInstance(servicekey, service)
			if err != nil {
				return false
			}
		} else {
			cont.indexMutex.Unlock()
		}
	} else {
		cont.clearLbService(servicekey)
	}

	cont.writeApicSvc(servicekey, service)
	return requeue
}

func (cont *AciController) clearLbService(servicekey string) {
	cont.indexMutex.Lock()
	if meta, ok := cont.serviceMetaCache[servicekey]; ok {
		cont.returnServiceIps(meta.ingressIps)
		returnIps(cont.staticServiceIps, meta.staticIngressIps)
		delete(cont.serviceMetaCache, servicekey)
	}
	cont.indexMutex.Unlock()
	cont.apicConn.ClearApicObjects(cont.aciNameForKey("svc", servicekey))
}

func getEndpointsIps(endpoints *v1.Endpoints) map[string]bool {
	ips := make(map[string]bool)
	for _, subset := range endpoints.Subsets {
		for _, addr := range subset.Addresses {
			ips[addr.IP] = true
		}
		for _, addr := range subset.NotReadyAddresses {
			ips[addr.IP] = true
		}
	}
	return ips
}

func servicePortKey(p *v1.ServicePort) string {
	return portProto(&p.Protocol) + "-num-" + strconv.Itoa(int(p.Port))
}

func getServiceTargetPorts(service *v1.Service) map[string]targetPort {
	ports := make(map[string]targetPort)
	for _, port := range service.Spec.Ports {
		portNum := port.TargetPort.IntValue()
		if portNum <= 0 {
			portNum = int(port.Port)
		}
		key := portProto(&port.Protocol) + "-num-" + strconv.Itoa(int(portNum))
		ports[key] = targetPort{
			proto: port.Protocol,
			port:  portNum,
		}
	}
	return ports
}

func (cont *AciController) endpointsAdded(obj interface{}) {
	endpoints := obj.(*v1.Endpoints)
	servicekey, err := cache.MetaNamespaceKeyFunc(obj.(*v1.Endpoints))
	if err != nil {
		cont.log.Error("Could not create service key: ", err)
		return
	}

	ips := getEndpointsIps(endpoints)
	cont.indexMutex.Lock()
	cont.updateIpIndex(cont.endpointsIpIndex, nil, ips, servicekey)
	cont.queueIPNetPolUpdates(ips)
	cont.indexMutex.Unlock()

	cont.queueEndpointsNetPolUpdates(endpoints)

	cont.queueServiceUpdateByKey(servicekey)
}

func (cont *AciController) endpointsDeleted(obj interface{}) {
	endpoints := obj.(*v1.Endpoints)
	servicekey, err := cache.MetaNamespaceKeyFunc(endpoints)
	if err != nil {
		cont.log.Error("Could not create service key: ", err)
		return
	}

	ips := getEndpointsIps(endpoints)
	cont.indexMutex.Lock()
	cont.updateIpIndex(cont.endpointsIpIndex, ips, nil, servicekey)
	cont.queueIPNetPolUpdates(ips)
	cont.indexMutex.Unlock()

	cont.queueEndpointsNetPolUpdates(endpoints)

	cont.queueServiceUpdateByKey(servicekey)
}

func (cont *AciController) endpointsUpdated(old interface{}, new interface{}) {
	oldendpoints := old.(*v1.Endpoints)
	newendpoints := new.(*v1.Endpoints)
	servicekey, err := cache.MetaNamespaceKeyFunc(newendpoints)
	if err != nil {
		cont.log.Error("Could not create service key: ", err)
		return
	}

	oldIps := getEndpointsIps(oldendpoints)
	newIps := getEndpointsIps(newendpoints)
	if !reflect.DeepEqual(oldIps, newIps) {
		cont.indexMutex.Lock()
		cont.queueIPNetPolUpdates(oldIps)
		cont.updateIpIndex(cont.endpointsIpIndex, oldIps, newIps, servicekey)
		cont.queueIPNetPolUpdates(newIps)
		cont.indexMutex.Unlock()
	}

	if !reflect.DeepEqual(oldendpoints.Subsets, newendpoints.Subsets) {
		cont.queueEndpointsNetPolUpdates(oldendpoints)
		cont.queueEndpointsNetPolUpdates(newendpoints)
	}

	cont.queueServiceUpdateByKey(servicekey)
}

func (cont *AciController) serviceAdded(obj interface{}) {
	service := obj.(*v1.Service)
	servicekey, err := cache.MetaNamespaceKeyFunc(service)
	if err != nil {
		serviceLogger(cont.log, service).
			Error("Could not create service key: ", err)
		return
	}

	ports := getServiceTargetPorts(service)
	cont.indexMutex.Lock()
	cont.queuePortNetPolUpdates(ports)
	cont.updateTargetPortIndex(true, servicekey, nil, ports)
	cont.indexMutex.Unlock()

	cont.queueServiceUpdateByKey(servicekey)
}

func (cont *AciController) serviceUpdated(old interface{}, new interface{}) {
	oldservice := old.(*v1.Service)
	newservice := new.(*v1.Service)
	servicekey, err := cache.MetaNamespaceKeyFunc(newservice)
	if err != nil {
		serviceLogger(cont.log, newservice).
			Error("Could not create service key: ", err)
		return
	}

	oldPorts := getServiceTargetPorts(oldservice)
	newPorts := getServiceTargetPorts(newservice)
	if !reflect.DeepEqual(oldPorts, newPorts) {
		cont.indexMutex.Lock()
		cont.queuePortNetPolUpdates(oldPorts)
		cont.updateTargetPortIndex(true, servicekey, oldPorts, newPorts)
		cont.queuePortNetPolUpdates(newPorts)
		cont.indexMutex.Unlock()
	}

	cont.queueServiceUpdateByKey(servicekey)
}

func (cont *AciController) serviceDeleted(obj interface{}) {
	service := obj.(*v1.Service)
	servicekey, err := cache.MetaNamespaceKeyFunc(service)
	if err != nil {
		serviceLogger(cont.log, service).
			Error("Could not create service key: ", err)
		return
	}
	cont.clearLbService(servicekey)
	cont.apicConn.ClearApicObjects(cont.aciNameForKey("service-vmm",
		servicekey))

	ports := getServiceTargetPorts(service)
	cont.indexMutex.Lock()
	cont.updateTargetPortIndex(true, servicekey, ports, nil)
	cont.queuePortNetPolUpdates(ports)
	cont.indexMutex.Unlock()
}

func (cont *AciController) serviceFullSync() {
	cache.ListAll(cont.serviceIndexer, labels.Everything(),
		func(sobj interface{}) {
			cont.queueServiceUpdate(sobj.(*v1.Service))
		})
}
