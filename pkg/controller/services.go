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
	"net"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/noironetworks/aci-containers/pkg/apicapi"
	"github.com/noironetworks/aci-containers/pkg/metadata"
	"github.com/noironetworks/aci-containers/pkg/util"
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
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

func (cont *AciController) initEndpointSliceInformerFromClient(
	kubeClient kubernetes.Interface) {

	cont.initEndpointSliceInformerBase(
		cache.NewListWatchFromClient(
			kubeClient.DiscoveryV1().RESTClient(), "endpointslices",
			metav1.NamespaceAll, fields.Everything()))
}

func (cont *AciController) initEndpointSliceInformerBase(listWatch *cache.ListWatch) {
	cont.endpointSliceIndexer, cont.endpointSliceInformer = cache.NewIndexerInformer(
		listWatch, &discovery.EndpointSlice{}, 0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				cont.endpointSliceAdded(obj)
			},
			UpdateFunc: func(oldobj interface{}, newobj interface{}) {
				cont.endpointSliceUpdated(oldobj, newobj)
			},
			DeleteFunc: func(obj interface{}) {
				cont.endpointSliceDeleted(obj)
			},
		},
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
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
			cont.log.Error("Corrupted network policy IP index, err: ", err)
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
		ps := make(map[string]bool)
		for _, npkey := range npkeys {
			cont.queueNetPolUpdateByKey(npkey)
			ps[npkey] = true
		}
		// Process if the  any matching namedport wildcard policy is present
		// ignore np already processed policies
		cont.queueMatchingNamedNp(ps, podkey)
	}
}

func (cont *AciController) queueMatchingNamedNp(served map[string]bool, podkey string) {
	cont.indexMutex.Lock()
	for npkey := range cont.nmPortNp {
		if _, ok := served[npkey]; !ok {
			if cont.checkPodNmpMatchesNp(npkey, podkey) {
				cont.queueNetPolUpdateByKey(npkey)
			}
		}
	}
	cont.indexMutex.Unlock()

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

func (cont *AciController) updateServicesForNode(nodename string) {
	cont.serviceEndPoints.UpdateServicesForNode(nodename)
}

// must have index lock
func (cont *AciController) getActiveFabricPathDn(node string) string {
	var fabricPathDn string
	sz := len(cont.nodeOpflexDevice[node])
	for i := range cont.nodeOpflexDevice[node] {
		device := cont.nodeOpflexDevice[node][sz-1-i]
		if device.GetAttrStr("state") == "connected" {
			fabricPathDn = device.GetAttrStr("fabricPathDn")
			break
		}
	}
	return fabricPathDn
}

func deleteDevicesFromList(delDevices apicapi.ApicSlice, devices apicapi.ApicSlice) apicapi.ApicSlice {
	var newDevices apicapi.ApicSlice
	for delDev := range delDevices {
		for _, device := range devices {
			if !reflect.DeepEqual(delDev, device) {
				newDevices = append(newDevices, device)
			}
		}
	}
	return newDevices
}
func (cont *AciController) getNodeName(nodeName string) string {
	nodeList := cont.nodeIndexer.List()
	for _, nodeItem := range nodeList {
		node := nodeItem.(*v1.Node)
		if nodeName == node.ObjectMeta.Name {
			ip := getNodeIP(node, v1.NodeInternalIP)
			return ip
		}
	}
	return ""
}

func (cont *AciController) getfvRsCEpToPathEptDn(node string) (string, error) {
	ipFilter := fmt.Sprintf("query-target-filter=and(eq(fvCEp.ip,\"%s\"))", node)
	args := []string{
		ipFilter,
		"rsp-subtree-class=fvRsCEpToPathEp",
		"rsp-subtree=children",
	}
	url := fmt.Sprintf("/api/node/class/fvCEp.json?%s", strings.Join(args, "&"))
	apicresp, err := cont.apicConn.GetApicResponse(url)
	if err != nil {
		cont.log.Debug("Failed to get APIC response, err: ", err.Error())
		return "", err
	}
	for _, obj := range apicresp.Imdata {
		for _, body := range obj {
			dn, dnok := body.Attributes["dn"].(string)
			if !dnok {
				continue
			}
			dnSlices := strings.Split(dn, "/")
			if len(dnSlices) < 2 {
				cont.log.Error("Invalid dn ", dn)
				continue
			}
			tenant := "tn-" + cont.config.AciPolicyTenant
			if dnSlices[1] != tenant {
				continue
			}
			for _, child := range body.Children {
				for class, cbody := range child {
					if class == "fvRsCEpToPathEp" {
						tDn, ok := cbody.Attributes["tDn"].(string)
						if ok {
							return tDn, nil
						}
					}
				}
			}
		}
	}
	return "", fmt.Errorf("tDn missing in fvRsCEpToPathEp")
}

func (cont *AciController) getAciPodSubnet(pod string) (string, error) {
	podslice := strings.Split(pod, "-")
	if len(podslice) < 2 {
		return "", fmt.Errorf("Failed to get podid from pod")
	}
	podid := podslice[1]
	var subnet string
	args := []string{
		"query-target=self",
	}
	url := fmt.Sprintf("/api/node/mo/uni/controller/setuppol/setupp-%s.json?%s", podid, strings.Join(args, "&"))
	apicresp, err := cont.apicConn.GetApicResponse(url)
	if err != nil {
		cont.log.Debug("Failed to get APIC response, err: ", err.Error())
		return subnet, err
	}
	for _, obj := range apicresp.Imdata {
		for _, body := range obj {
			tepPool, ok := body.Attributes["tepPool"].(string)
			if ok {
				subnet = tepPool
				break
			}
		}
	}
	return subnet, nil
}

func (cont *AciController) createAciPodAnnotation(fabricPathDn, node string) (string, error) {
	if fabricPathDn == "" {
		// for a multipod vm migration, when there is no opflex device connected
		// get tDn from fvRsCEpToPathEp (which has info of new pod)
		// and update annotation (pod-<podid>-<subnet of pod>) on node
		path, err := cont.getfvRsCEpToPathEptDn(node)
		if err != nil {
			return "", err
		} else {
			pathSlice := strings.Split(path, "/")
			if len(pathSlice) > 1 {
				pod := pathSlice[1]
				subnet, err := cont.getAciPodSubnet(pod)
				if err != nil {
					cont.log.Error("Failed to get subnet of aci pod ", err.Error())
					return "", err
				} else {
					annot := pod + "-" + subnet
					return annot, nil
				}
			}
		}
	} else {
		// when there is already a connected opflex device,
		// fabricPathDn will have latest pod iformation
		nodeAciPod := cont.nodeACIPod[node]
		path := fabricPathDn
		pathSlice := strings.Split(path, "/")
		if len(pathSlice) > 1 {
			pod := pathSlice[1]
			// when there is difference in pod info avaliable from fabricPathDn
			// and what we have in cache, update info in cache and change annotation on node
			if !strings.Contains(nodeAciPod, pod) {
				subnet, err := cont.getAciPodSubnet(pod)
				if err != nil {
					cont.log.Error("Failed to get subnet of aci pod ", err.Error())
					return "", err
				} else {
					annot := pod + "-" + subnet
					return annot, nil
				}
			} else {
				return nodeAciPod, nil
			}
		}
	}
	return "", fmt.Errorf("Failed to extract pod from path")
}

func (cont *AciController) deleteOldOpflexDevices() {
	var nodeUpdates []string
	var nodeAnnotationUpdates []string
	cont.indexMutex.Lock()
	for node, devices := range cont.nodeOpflexDevice {
		var delDevices apicapi.ApicSlice
		fabricPathDn := cont.getActiveFabricPathDn(node)
		annot, err := cont.createAciPodAnnotation(fabricPathDn, node)
		if err == nil {
			cont.nodeACIPod[node] = annot
			nodeAnnotationUpdates = append(nodeAnnotationUpdates, node)
		} else {
			cont.log.Error(err.Error())
		}
		if fabricPathDn != "" {
			for _, device := range devices {
				if device.GetAttrStr("delete") == "true" && device.GetAttrStr("fabricPathDn") != fabricPathDn {
					deleteTimeStr := device.GetAttrStr("deleteTime")
					deleteTime, err := time.Parse(time.RFC3339, deleteTimeStr)
					if err != nil {
						cont.log.Error("Failed to parse opflex device delete time: ", err)
						continue
					}
					now := time.Now()
					diff := now.Sub(deleteTime)
					if diff.Seconds() >= cont.config.OpflexDeviceDeleteTimeout {
						delDevices = append(delDevices, device)
					}
				}
			}
			if len(delDevices) > 0 {
				newDevices := deleteDevicesFromList(delDevices, devices)
				cont.nodeOpflexDevice[node] = newDevices
				if len(newDevices) == 0 {
					delete(cont.nodeOpflexDevice, node)
				}
				nodeUpdates = append(nodeUpdates, node)
			}
		}
	}
	cont.indexMutex.Unlock()
	if len(nodeUpdates) > 0 {
		cont.postOpflexDeviceDelete(nodeUpdates)
	} else if len(nodeAnnotationUpdates) > 0 {
		for _, updatednode := range nodeAnnotationUpdates {
			go cont.env.NodeAnnotationChanged(updatednode)
		}
	}
}

// must have index lock
func (cont *AciController) setDeleteFlagForOldDevices(node, fabricPathDn string) {
	for _, device := range cont.nodeOpflexDevice[node] {
		if device.GetAttrStr("fabricPathDn") != fabricPathDn {
			t := time.Now()
			device.SetAttr("delete", "true")
			device.SetAttr("deleteTime", t.Format(time.RFC3339))
		}
	}
}

// must have index lock
func (cont *AciController) fabricPathForNode(name string) (string, bool) {
	sz := len(cont.nodeOpflexDevice[name])
	for i := range cont.nodeOpflexDevice[name] {
		device := cont.nodeOpflexDevice[name][sz-1-i]
		deviceState := device.GetAttrStr("state")
		if deviceState == "connected" {
			if deviceState != device.GetAttrStr("prevState") {
				cont.fabricPathLogger(device.GetAttrStr("hostName"), device).Info("Processing fabric path for node ",
					"when connected device state is found")
				device.SetAttr("prevState", deviceState)
			}
			fabricPathDn := device.GetAttrStr("fabricPathDn")
			cont.setDeleteFlagForOldDevices(name, fabricPathDn)
			return fabricPathDn, true
		} else {
			device.SetAttr("prevState", deviceState)
		}
	}
	if sz > 0 {
		// When the opflex-device for a node changes, for example during a live migration,
		// we end up with both the old and the new device objects till the old object
		// ages out on APIC. The new object is at end of the devices list (see opflexDeviceChanged),
		// so we return the fabricPathDn of the last opflex-device.
		cont.fabricPathLogger(cont.nodeOpflexDevice[name][sz-1].GetAttrStr("hostName"),
			cont.nodeOpflexDevice[name][sz-1]).Info("Processing fabricPathDn for node")
		return cont.nodeOpflexDevice[name][sz-1].GetAttrStr("fabricPathDn"), true
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
	descr string, healthGroupDn string, enablePbrTracking bool) apicapi.ApicObject {
	dst := apicapi.NewVnsRedirectDest(rpDn, ip, mac).SetAttr("descr", descr)
	if healthGroupDn != "" && enablePbrTracking {
		dst.AddChild(apicapi.NewVnsRsRedirectHealthGroup(dst.GetDn(),
			healthGroupDn))
	}
	return dst
}

func (cont *AciController) apicRedirectPol(name string, tenantName string, nodes []string,
	nodeMap map[string]*metadata.ServiceEndpoint,
	monPolDn string, enablePbrTracking bool) (apicapi.ApicObject, string) {
	rp := apicapi.NewVnsSvcRedirectPol(tenantName, name)
	rp.SetAttr("thresholdDownAction", "deny")
	rpDn := rp.GetDn()
	for _, node := range nodes {
		cont.indexMutex.Lock()
		serviceEp, ok := nodeMap[node]
		if !ok {
			continue
		}
		if serviceEp.Ipv4 != nil {
			rp.AddChild(apicRedirectDst(rpDn, serviceEp.Ipv4.String(),
				serviceEp.Mac, node, serviceEp.HealthGroupDn, enablePbrTracking))
		}
		if serviceEp.Ipv6 != nil {
			rp.AddChild(apicRedirectDst(rpDn, serviceEp.Ipv6.String(),
				serviceEp.Mac, node, serviceEp.HealthGroupDn, enablePbrTracking))
		}
		cont.indexMutex.Unlock()
	}
	if monPolDn != "" && enablePbrTracking {
		rp.AddChild(apicapi.NewVnsRsIPSLAMonitoringPol(rpDn, monPolDn))
	}
	return rp, rpDn
}

func apicExtNetCreate(enDn string, ingress string, ipv4 bool,
	cidr bool, sharedSec bool) apicapi.ApicObject {

	if !cidr {
		if ipv4 {
			ingress = ingress + "/32"
		} else {
			ingress = ingress + "/128"
		}
	}
	subnet := apicapi.NewL3extSubnet(enDn, ingress)
	if sharedSec {
		subnet.SetAttr("scope", "import-security,shared-security")
	}
	return subnet
}

func apicExtNet(name string, tenantName string, l3Out string,
	ingresses []string, sharedSecurity bool, snat bool) apicapi.ApicObject {

	en := apicapi.NewL3extInstP(tenantName, l3Out, name)
	enDn := en.GetDn()
	if snat {
		en.AddChild(apicapi.NewFvRsCons(enDn, name))
	} else {
		en.AddChild(apicapi.NewFvRsProv(enDn, name))
	}

	for _, ingress := range ingresses {
		ip, _, _ := net.ParseCIDR(ingress)
		// If ingress is a subnet
		if ip != nil {
			if ip != nil && ip.To4() != nil {
				subnet := apicExtNetCreate(enDn, ingress, true, true, sharedSecurity)
				en.AddChild(subnet)
			} else if ip != nil && ip.To16() != nil {
				subnet := apicExtNetCreate(enDn, ingress, false, true, sharedSecurity)
				en.AddChild(subnet)
			}
		} else {
			// If ingress is an IP address
			ip := net.ParseIP(ingress)
			if ip != nil && ip.To4() != nil {
				subnet := apicExtNetCreate(enDn, ingress, true, false, sharedSecurity)
				en.AddChild(subnet)
			} else if ip != nil && ip.To16() != nil {
				subnet := apicExtNetCreate(enDn, ingress, false, false, sharedSecurity)
				en.AddChild(subnet)
			}
		}
	}
	return en
}

func apicExtNetCons(conName string, tenantName string,
	l3Out string, net string) apicapi.ApicObject {

	enDn := fmt.Sprintf("uni/tn-%s/out-%s/instP-%s", tenantName, l3Out, net)
	return apicapi.NewFvRsCons(enDn, conName)
}

func apicExtNetProv(conName string, tenantName string,
	l3Out string, net string) apicapi.ApicObject {

	enDn := fmt.Sprintf("uni/tn-%s/out-%s/instP-%s", tenantName, l3Out, net)
	return apicapi.NewFvRsProv(enDn, conName)
}

// Helper function to check if a string item exists in a slice
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

func (cont *AciController) getGraphNameFromContract(name, tenantName string) (string, error) {
	var graphName string
	args := []string{
		"query-target=subtree",
	}
	url := fmt.Sprintf("/api/node/mo/uni/tn-%s/brc-%s.json?%s", tenantName, name, strings.Join(args, "&"))
	apicresp, err := cont.apicConn.GetApicResponse(url)
	if err != nil {
		cont.log.Debug("Failed to get APIC response, err: ", err.Error())
		return graphName, err
	}
	for _, obj := range apicresp.Imdata {
		for class, body := range obj {
			if class == "vzRsSubjGraphAtt" {
				tnVnsAbsGraphName, ok := body.Attributes["tnVnsAbsGraphName"].(string)
				if ok {
					graphName = tnVnsAbsGraphName
				}
				break
			}
		}
	}
	cont.log.Debug("graphName: ", graphName)
	return graphName, err
}

func apicContract(conName string, tenantName string,
	graphName string, scopeName string, isSnatPbrFltrChain bool,
	customSGAnnot bool) apicapi.ApicObject {
	con := apicapi.NewVzBrCP(tenantName, conName)
	if scopeName != "" && scopeName != "context" {
		con.SetAttr("scope", scopeName)
	}
	cs := apicapi.NewVzSubj(con.GetDn(), "loadbalancedservice")
	csDn := cs.GetDn()
	if isSnatPbrFltrChain {
		cs.SetAttr("revFltPorts", "no")
		inTerm := apicapi.NewVzInTerm(csDn)
		outTerm := apicapi.NewVzOutTerm(csDn)
		inTerm.AddChild(apicapi.NewVzRsInTermGraphAtt(inTerm.GetDn(), graphName))
		inTerm.AddChild(apicapi.NewVzRsFiltAtt(inTerm.GetDn(), conName+"_fromCons-toProv"))
		outTerm.AddChild(apicapi.NewVzRsOutTermGraphAtt(outTerm.GetDn(), graphName))
		outTerm.AddChild(apicapi.NewVzRsFiltAtt(outTerm.GetDn(), conName+"_fromProv-toCons"))
		cs.AddChild(inTerm)
		cs.AddChild(outTerm)
	} else {
		cs.AddChild(apicapi.NewVzRsSubjGraphAtt(csDn, graphName, customSGAnnot))
		cs.AddChild(apicapi.NewVzRsSubjFiltAtt(csDn, conName))
	}
	con.AddChild(cs)
	return con
}

func apicDevCtx(name string, tenantName string,
	graphName string, deviceName string, bdName string, rpDn string, isSnatPbrFltrChain bool) apicapi.ApicObject {

	cc := apicapi.NewVnsLDevCtx(tenantName, name, graphName, "loadbalancer")
	ccDn := cc.GetDn()
	graphDn := fmt.Sprintf("uni/tn-%s/lDevVip-%s", tenantName, deviceName)
	lifDn := fmt.Sprintf("%s/lIf-%s", graphDn, "interface")
	bdDn := fmt.Sprintf("uni/tn-%s/BD-%s", tenantName, bdName)
	cc.AddChild(apicapi.NewVnsRsLDevCtxToLDev(ccDn, graphDn))
	rpDnBase := rpDn
	for _, ctxConn := range []string{"consumer", "provider"} {
		lifCtx := apicapi.NewVnsLIfCtx(ccDn, ctxConn)
		if isSnatPbrFltrChain {
			if ctxConn == "consumer" {
				rpDn = rpDnBase + "_Cons"
			} else {
				rpDn = rpDnBase + "_Prov"
			}
		}
		lifCtxDn := lifCtx.GetDn()
		lifCtx.AddChild(apicapi.NewVnsRsLIfCtxToSvcRedirectPol(lifCtxDn, rpDn))
		lifCtx.AddChild(apicapi.NewVnsRsLIfCtxToBD(lifCtxDn, bdDn))
		lifCtx.AddChild(apicapi.NewVnsRsLIfCtxToLIf(lifCtxDn, lifDn))
		cc.AddChild(lifCtx)
	}
	return cc
}

func apicFilterEntry(filterDn string, count string, p_start string,
	p_end string, protocol string, stateful string, snat bool, outTerm bool) apicapi.ApicObject {

	fe := apicapi.NewVzEntry(filterDn, count)
	fe.SetAttr("etherT", "ip")
	fe.SetAttr("prot", protocol)
	if snat {
		if outTerm {
			if protocol == "tcp" {
				fe.SetAttr("tcpRules", "est")
			}
			// Reverse the ports for outTerm
			fe.SetAttr("dFromPort", p_start)
			fe.SetAttr("dToPort", p_end)
		} else {
			fe.SetAttr("sFromPort", p_start)
			fe.SetAttr("sToPort", p_end)
		}
	} else {
		fe.SetAttr("dFromPort", p_start)
		fe.SetAttr("dToPort", p_end)
	}
	fe.SetAttr("stateful", stateful)
	return fe
}
func apicFilter(name string, tenantName string,
	portSpec []v1.ServicePort, snat bool, snatRange portRangeSnat) apicapi.ApicObject {

	filter := apicapi.NewVzFilter(tenantName, name)
	filterDn := filter.GetDn()

	var i int
	var port v1.ServicePort
	for i, port = range portSpec {
		pstr := strconv.Itoa(int(port.Port))
		proto := getProtocolStr(port.Protocol)
		fe := apicFilterEntry(filterDn, strconv.Itoa(i), pstr,
			pstr, proto, "no", false, false)
		filter.AddChild(fe)
	}

	if snat {
		portSpec := []portRangeSnat{snatRange}
		p_start := strconv.Itoa(int(portSpec[0].start))
		p_end := strconv.Itoa(int(portSpec[0].end))

		fe1 := apicFilterEntry(filterDn, strconv.Itoa(i+1), p_start,
			p_end, "tcp", "no", false, false)
		filter.AddChild(fe1)
		fe2 := apicFilterEntry(filterDn, strconv.Itoa(i+2), p_start,
			p_end, "udp", "no", false, false)
		filter.AddChild(fe2)
	}
	return filter
}

func apicFilterSnat(name string, tenantName string,
	portSpec []portRangeSnat, outTerm bool) apicapi.ApicObject {

	filter := apicapi.NewVzFilter(tenantName, name)
	filterDn := filter.GetDn()

	p_start := strconv.Itoa(int(portSpec[0].start))
	p_end := strconv.Itoa(int(portSpec[0].end))

	fe := apicFilterEntry(filterDn, "0", p_start,
		p_end, "tcp", "no", true, outTerm)
	filter.AddChild(fe)
	fe1 := apicFilterEntry(filterDn, "1", p_start,
		p_end, "udp", "no", true, outTerm)
	filter.AddChild(fe1)

	return filter
}

func (cont *AciController) updateServiceDeviceInstance(key string,
	service *v1.Service) error {
	cont.indexMutex.Lock()
	nodeMap := make(map[string]*metadata.ServiceEndpoint)
	cont.serviceEndPoints.GetnodesMetadata(key, service, nodeMap)
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
			err := errors.New(errString)
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
	deviceName := cont.aciNameForKey("svc", "global")
	_, customSGAnnPresent := service.ObjectMeta.Annotations[metadata.ServiceGraphNameAnnotation]
	if customSGAnnPresent {
		customSG, err := cont.getGraphNameFromContract(name, cont.config.AciVrfTenant)
		if err == nil {
			graphName = customSG
		}
	}
	cont.log.Debug("Using service graph ", graphName, " for service ", key)

	var serviceObjs apicapi.ApicSlice
	if len(nodes) > 0 {

		// 1. Service redirect policy
		// The service redirect policy contains the MAC address
		// and IP address of each of the service endpoints for
		// each node that hosts a pod for this service.  The
		// example below shows the case of two nodes.
		rp, rpDn :=
			cont.apicRedirectPol(name, cont.config.AciVrfTenant, nodes,
				nodeMap, cont.staticMonPolDn(), cont.config.AciPbrTrackingNonSnat)
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
					cont.config.AciL3Out, ingresses, sharedSecurity, false))
		}

		contract := apicContract(name, cont.config.AciVrfTenant, graphName, conScope, false, customSGAnnPresent)
		serviceObjs = append(serviceObjs, contract)
		for _, net := range cont.config.AciExtNetworks {
			serviceObjs = append(serviceObjs,
				apicExtNetCons(name, cont.config.AciVrfTenant,
					cont.config.AciL3Out, net))
		}

		defaultPortRange := portRangeSnat{start: cont.config.SnatDefaultPortRangeStart,
			end: cont.config.SnatDefaultPortRangeEnd}

		_, snat := cont.snatServices[key]
		filter := apicFilter(name, cont.config.AciVrfTenant,
			service.Spec.Ports, snat, defaultPortRange)
		serviceObjs = append(serviceObjs, filter)

		// 3. Device cluster context
		// The logical device context binds the service contract
		// to the redirect policy and the device cluster and
		// bridge domain for the device cluster.
		serviceObjs = append(serviceObjs,
			apicDevCtx(name, cont.config.AciVrfTenant, graphName, deviceName,
				cont.aciNameForKey("bd", cont.env.ServiceBd()), rpDn, false))
	}

	cont.apicConn.WriteApicObjects(name, serviceObjs)
	return nil
}

func (cont *AciController) updateServiceDeviceInstanceSnat(key string) error {
	nodeList := cont.nodeIndexer.List()
	cont.indexMutex.Lock()
	if len(cont.nodeServiceMetaCache) == 0 {
		cont.indexMutex.Unlock()
		return nil
	}
	nodeMap := make(map[string]*metadata.ServiceEndpoint)
	for itr, nodeItem := range nodeList {
		if itr == cont.config.MaxSvcGraphNodes {
			break
		}
		node := nodeItem.(*v1.Node)
		nodeName := node.ObjectMeta.Name
		nodeMeta, ok := cont.nodeServiceMetaCache[nodeName]
		if !ok {
			continue
		}
		_, ok = cont.fabricPathForNode(nodeName)
		if !ok {
			continue
		}
		nodeMap[nodeName] = &nodeMeta.serviceEp
	}
	cont.indexMutex.Unlock()

	var nodes []string
	for node := range nodeMap {
		nodes = append(nodes, node)
	}
	sort.Strings(nodes)
	name := cont.aciNameForKey("snat", key)
	var conScope = cont.config.SnatSvcContractScope
	sharedSecurity := true

	graphName := cont.aciNameForKey("svc", "global")
	var serviceObjs apicapi.ApicSlice
	if len(nodes) > 0 {

		// 1. Service redirect policy
		// The service redirect policy contains the MAC address
		// and IP address of each of the service endpoints for
		// each node that hosts a pod for this service.
		// For SNAT with the introduction of filter-chain usage, to work-around
		// an APIC limitation, creating two PBR policies with same nodes.
		var rpDn string
		var rp apicapi.ApicObject
		if cont.apicConn.SnatPbrFltrChain {
			rpCons, rpDnCons :=
				cont.apicRedirectPol(name+"_Cons", cont.config.AciVrfTenant, nodes,
					nodeMap, cont.staticMonPolDn(), true)
			serviceObjs = append(serviceObjs, rpCons)
			rpProv, _ :=
				cont.apicRedirectPol(name+"_Prov", cont.config.AciVrfTenant, nodes,
					nodeMap, cont.staticMonPolDn(), true)
			serviceObjs = append(serviceObjs, rpProv)
			rpDn = strings.TrimSuffix(rpDnCons, "_Cons")
		} else {
			rp, rpDn =
				cont.apicRedirectPol(name, cont.config.AciVrfTenant, nodes,
					nodeMap, cont.staticMonPolDn(), true)
			serviceObjs = append(serviceObjs, rp)
		}
		// 2. Service graph contract and external network
		// The service graph contract must be bound to the
		// service
		// graph.  This contract must be consumed by the default
		// layer 3 network and provided by the service layer 3
		// network.
		{
			var ingresses []string
			for _, policy := range cont.snatPolicyCache {
				ingresses = append(ingresses, policy.SnatIp...)
			}
			serviceObjs = append(serviceObjs,
				apicExtNet(name, cont.config.AciVrfTenant,
					cont.config.AciL3Out, ingresses, sharedSecurity, true))
		}

		contract := apicContract(name, cont.config.AciVrfTenant, graphName, conScope, cont.apicConn.SnatPbrFltrChain, false)
		serviceObjs = append(serviceObjs, contract)

		for _, net := range cont.config.AciExtNetworks {
			serviceObjs = append(serviceObjs,
				apicExtNetProv(name, cont.config.AciVrfTenant,
					cont.config.AciL3Out, net))
		}

		defaultPortRange := portRangeSnat{start: cont.config.SnatDefaultPortRangeStart,
			end: cont.config.SnatDefaultPortRangeEnd}
		portSpec := []portRangeSnat{defaultPortRange}
		if cont.apicConn.SnatPbrFltrChain {
			filterIn := apicFilterSnat(name+"_fromCons-toProv", cont.config.AciVrfTenant, portSpec, false)
			serviceObjs = append(serviceObjs, filterIn)
			filterOut := apicFilterSnat(name+"_fromProv-toCons", cont.config.AciVrfTenant, portSpec, true)
			serviceObjs = append(serviceObjs, filterOut)
		} else {
			filter := apicFilterSnat(name, cont.config.AciVrfTenant, portSpec, false)
			serviceObjs = append(serviceObjs, filter)
		}
		// 3. Device cluster context
		// The logical device context binds the service contract
		// to the redirect policy and the device cluster and
		// bridge domain for the device cluster.
		serviceObjs = append(serviceObjs,
			apicDevCtx(name, cont.config.AciVrfTenant, graphName, graphName,
				cont.aciNameForKey("bd", cont.env.ServiceBd()), rpDn, cont.apicConn.SnatPbrFltrChain))
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
		cont.log.Debug("Processing node in nodeOpflexDevice cache : ", node)
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
		"obj":        obj,
	})
}

func (cont *AciController) opflexDeviceChanged(obj apicapi.ApicObject) {

	devType := obj.GetAttrStr("devType")
	domName := obj.GetAttrStr("domName")
	ctrlrName := obj.GetAttrStr("ctrlrName")

	if (devType == cont.env.OpFlexDeviceType()) && (domName == cont.config.AciVmmDomain) && (ctrlrName == cont.config.AciVmmController) {
		cont.fabricPathLogger(obj.GetAttrStr("hostName"), obj).Debug("Processing opflex device update")
		if obj.GetAttrStr("state") == "disconnected" {
			cont.fabricPathLogger(obj.GetAttrStr("hostName"), obj).Debug("Opflex device disconnected")
			cont.indexMutex.Lock()
			for node, devices := range cont.nodeOpflexDevice {
				if node == obj.GetAttrStr("hostName") {
					for _, device := range devices {
						if device.GetDn() == obj.GetDn() {
							device.SetAttr("state", "disconnected")
							cont.fabricPathLogger(device.GetAttrStr("hostName"), device).Debug("Opflex device cache updated for disconnected node")
						}
					}
					cont.log.Info("Opflex device list for node ", obj.GetAttrStr("hostName"), ": ", devices)
					break
				}
			}
			cont.indexMutex.Unlock()
			cont.updateDeviceCluster()
			return
		}
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
					(device.GetAttrStr("fabricPathDn") != obj.GetAttrStr("fabricPathDn")) ||
					(device.GetAttrStr("state") != obj.GetAttrStr("state")) {

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
		cont.log.Info("Opflex device list for node ", obj.GetAttrStr("hostName"), ": ", cont.nodeOpflexDevice[obj.GetAttrStr("hostName")])
		cont.indexMutex.Unlock()

		for _, node := range nodeUpdates {
			cont.env.NodeServiceChanged(node)
			cont.erspanSyncOpflexDev()
		}
		cont.updateDeviceCluster()

	}
}

func (cont *AciController) postOpflexDeviceDelete(nodes []string) {
	cont.updateDeviceCluster()
	for _, node := range nodes {
		cont.env.NodeServiceChanged(node)
		cont.erspanSyncOpflexDev()
	}
}

func (cont *AciController) opflexDeviceDeleted(dn string) {
	var nodeUpdates []string
	var dnFound bool //to check if the dn belongs to this cluster
	cont.indexMutex.Lock()
	for node, devices := range cont.nodeOpflexDevice {
		for i, device := range devices {
			if device.GetDn() != dn {
				continue
			}
			dnFound = true
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

	if dnFound {
		cont.postOpflexDeviceDelete(nodeUpdates)
	}
}

func (cont *AciController) writeApicSvc(key string, service *v1.Service) {
	aobj := apicapi.NewVmmInjectedSvc(cont.vmmDomainProvider(),
		cont.config.AciVmmDomain, cont.config.AciVmmController,
		service.Namespace, service.Name)
	aobjDn := aobj.GetDn()
	aobj.SetAttr("guid", string(service.UID))

	svcns := service.ObjectMeta.Namespace
	_, exists, err := cont.namespaceIndexer.GetByKey(svcns)
	if err != nil {
		cont.log.Error("Failed to lookup ns : ", svcns, " ", err)
		return
	}
	if !exists {
		cont.log.Debug("Namespace of service ", service.ObjectMeta.Name, ": ", svcns, " doesn't exist, hence not sending an update to the APIC")
		return
	}

	if !cont.serviceEndPoints.SetServiceApicObject(aobj, service) {
		return
	}
	var setApicSvcDnsName bool
	if len(cont.config.ApicHosts) != 0 && apicapi.ApicVersion >= "5.1" {
		setApicSvcDnsName = true
	}
	// APIC model only allows one of these
	for _, ingress := range service.Status.LoadBalancer.Ingress {
		if ingress.IP != "" && ingress.IP != "0.0.0.0" {
			aobj.SetAttr("lbIp", ingress.IP)
		} else if ingress.Hostname != "" {
			ipList, err := net.LookupHost(ingress.Hostname)
			if err == nil && len(ipList) > 0 {
				aobj.SetAttr("lbIp", ipList[0])
			} else {
				cont.log.Errorf("Lookup: err: %v, ipList: %+v", err, ipList)
			}
		}
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

	if setApicSvcDnsName || cont.config.Flavor == "k8s-overlay" {
		dnsName := fmt.Sprintf("%s.%s.svc.cluster.local", service.Name, service.Namespace)

		for _, ingress := range service.Status.LoadBalancer.Ingress {
			if ingress.Hostname != "" {
				aobj.SetAttr("dnsName", ingress.Hostname)
			} else if ingress.IP != "" && ingress.IP != "0.0.0.0" {
				aobj.SetAttr("dnsName", dnsName)
			}
		}
		if t == "clusterIp" || t == "nodePort" || t == "externalName" {
			aobj.SetAttr("dnsName", dnsName)
		}
	}
	for _, port := range service.Spec.Ports {
		proto := getProtocolStr(port.Protocol)
		p := apicapi.NewVmmInjectedSvcPort(aobjDn,
			strconv.Itoa(int(port.Port)), proto, port.TargetPort.String())
		p.SetAttr("nodePort", strconv.Itoa(int(port.NodePort)))
		aobj.AddChild(p)
	}
	if cont.config.EnableVmmInjectedLabels && service.ObjectMeta.Labels != nil && apicapi.ApicVersion >= "5.2" {
		for key, val := range service.ObjectMeta.Labels {
			newLabelKey := cont.aciNameForKey("label", key)
			label := apicapi.NewVmmInjectedLabel(aobj.GetDn(),
				newLabelKey, val)
			aobj.AddChild(label)
		}
	}
	name := cont.aciNameForKey("service-vmm", key)
	cont.log.Debug("Write Service Object: ", aobj)
	cont.apicConn.WriteApicObjects(name, apicapi.ApicSlice{aobj})
	cont.log.Debugf("svcObject: %+v", aobj)
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
	aciLB := cont.config.LBType == lbTypeAci
	if isLoadBalancer && aciLB {
		if *cont.config.AllocateServiceIps {
			requeue = cont.allocateServiceIps(servicekey, service)
		}
		cont.indexMutex.Lock()
		if cont.serviceSyncEnabled {
			cont.indexMutex.Unlock()
			err = cont.updateServiceDeviceInstance(servicekey, service)
			if err != nil {
				serviceLogger(cont.log, service).
					Error("Failed to update service device Instance: ", err)
				return true
			}
		} else {
			cont.indexMutex.Unlock()
		}
	} else if aciLB {
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
			ports: []int{portNum},
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
	endpoints, isEndpoints := obj.(*v1.Endpoints)
	if !isEndpoints {
		deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			cont.log.Error("Received unexpected object: ", obj)
			return
		}
		endpoints, ok = deletedState.Obj.(*v1.Endpoints)
		if !ok {
			cont.log.Error("DeletedFinalStateUnknown contained non-Endpoints object: ", deletedState.Obj)
			return
		}
	}
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
	service, isService := obj.(*v1.Service)
	if !isService {
		deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			serviceLogger(cont.log, service).
				Error("Received unexpected object: ", obj)
			return
		}
		service, ok = deletedState.Obj.(*v1.Service)
		if !ok {
			serviceLogger(cont.log, service).
				Error("DeletedFinalStateUnknown contained non-Services object: ", deletedState.Obj)
			return
		}
	}
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
	delete(cont.snatServices, servicekey)
	cont.indexMutex.Unlock()
}

func (cont *AciController) serviceFullSync() {
	cache.ListAll(cont.serviceIndexer, labels.Everything(),
		func(sobj interface{}) {
			cont.queueServiceUpdate(sobj.(*v1.Service))
		})
}

func (cont *AciController) getEndpointSliceIps(endpointSlice *discovery.EndpointSlice) map[string]bool {
	ips := make(map[string]bool)
	for _, endpoints := range endpointSlice.Endpoints {
		for _, addr := range endpoints.Addresses {
			ips[addr] = true
		}
	}
	return ips
}

func (cont *AciController) notReadyEndpointPresent(endpointSlice *discovery.EndpointSlice) bool {
	for _, endpoints := range endpointSlice.Endpoints {
		if (endpoints.Conditions.Ready != nil && !*endpoints.Conditions.Ready) &&
			(endpoints.Conditions.Terminating == nil || !*endpoints.Conditions.Terminating) {
			return true
		}
	}
	return false
}

func (cont *AciController) getEndpointSliceEpIps(endpoints discovery.Endpoint) map[string]bool {
	ips := make(map[string]bool)
	for _, addr := range endpoints.Addresses {
		ips[addr] = true
	}
	return ips
}

func (cont *AciController) processDelayedEpSlices() {
	var processEps []DelayedEpSlice
	cont.indexMutex.Lock()
	for i := 0; i < len(cont.delayedEpSlices); i++ {
		delayedepslice := cont.delayedEpSlices[i]
		if time.Now().After(delayedepslice.DelayedTime) {
			var toprocess DelayedEpSlice
			err := util.DeepCopyObj(&delayedepslice, &toprocess)
			if err != nil {
				cont.log.Error(err)
				continue
			}
			processEps = append(processEps, toprocess)
			cont.delayedEpSlices = append(cont.delayedEpSlices[:i], cont.delayedEpSlices[i+1:]...)
		}
	}

	cont.indexMutex.Unlock()
	for _, epslice := range processEps {
		//ignore the epslice if newly added endpoint is not ready
		if cont.notReadyEndpointPresent(epslice.NewEpSlice) {
			cont.log.Debug("Ignoring the update as the new endpoint is not ready : ", epslice.NewEpSlice)
		} else {
			cont.log.Debug("Processing update of epslice : ", epslice.NewEpSlice)
			cont.doendpointSliceUpdated(epslice.OldEpSlice, epslice.NewEpSlice)
		}
	}
}

func (cont *AciController) endpointSliceAdded(obj interface{}) {
	endpointslice, ok := obj.(*discovery.EndpointSlice)
	if !ok {
		cont.log.Error("error processing Endpointslice object: ", obj)
		return
	}
	servicekey, valid := getServiceKey(endpointslice)
	if !valid {
		return
	}
	ips := cont.getEndpointSliceIps(endpointslice)
	cont.indexMutex.Lock()
	cont.updateIpIndex(cont.endpointsIpIndex, nil, ips, servicekey)
	cont.queueIPNetPolUpdates(ips)
	cont.indexMutex.Unlock()

	cont.queueEndpointSliceNetPolUpdates(endpointslice)

	cont.queueServiceUpdateByKey(servicekey)
	cont.log.Info("EndPointSlice Object Added: ", servicekey)
}

func (cont *AciController) endpointSliceDeleted(obj interface{}) {
	endpointslice, isEndpointslice := obj.(*discovery.EndpointSlice)
	if !isEndpointslice {
		deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			cont.log.Error("Received unexpected object: ", obj)
			return
		}
		endpointslice, ok = deletedState.Obj.(*discovery.EndpointSlice)
		if !ok {
			cont.log.Error("DeletedFinalStateUnknown contained non-Endpointslice object: ", deletedState.Obj)
			return
		}
	}
	servicekey, valid := getServiceKey(endpointslice)
	if !valid {
		return
	}
	ips := cont.getEndpointSliceIps(endpointslice)
	cont.indexMutex.Lock()
	cont.updateIpIndex(cont.endpointsIpIndex, ips, nil, servicekey)
	cont.queueIPNetPolUpdates(ips)
	cont.indexMutex.Unlock()
	cont.queueEndpointSliceNetPolUpdates(endpointslice)
	cont.queueServiceUpdateByKey(servicekey)
}

// Checks if the given service is present in the user configured list of services
// for pbr delay and if present, returns the servie specific delay if configured
func (cont *AciController) svcInAddDelayList(name, ns string) (int, bool) {
	for _, svc := range cont.config.ServiceGraphEndpointAddDelay.Services {
		if svc.Name == name && svc.Namespace == ns {
			return svc.Delay, true
		}
	}
	return 0, false
}

// Check if the endpointslice update notification has any deletion of enpoint
func (cont *AciController) isDeleteEndpointSlice(oldendpointslice, newendpointslice *discovery.EndpointSlice) bool {
	del := false

	// if any endpoint is removed from endpontslice
	if len(newendpointslice.Endpoints) < len(newendpointslice.Endpoints) {
		del = true
	}

	if !del {
		// if any one of the endpoint is in terminating state
		for _, endpoint := range newendpointslice.Endpoints {
			if endpoint.Conditions.Terminating != nil && *endpoint.Conditions.Terminating {
				del = true
				break
			}
		}
	}
	if !del {
		// if any one of endpoint moved from ready state to not-ready state
		for _, oldendpoint := range oldendpointslice.Endpoints {
			oldips := cont.getEndpointSliceEpIps(oldendpoint)
			for _, newendpoint := range newendpointslice.Endpoints {
				newips := cont.getEndpointSliceEpIps(newendpoint)
				if reflect.DeepEqual(oldips, newips) {
					if (oldendpoint.Conditions.Ready != nil && *oldendpoint.Conditions.Ready) &&
						(newendpoint.Conditions.Ready != nil && !*newendpoint.Conditions.Ready) {
						del = true
					}
					break
				}
			}
		}
	}
	return del
}

func (cont *AciController) doendpointSliceUpdatedDelay(oldendpointslice *discovery.EndpointSlice,
	newendpointslice *discovery.EndpointSlice) {
	svc, ns, valid := getServiceNameAndNs(newendpointslice)
	if !valid {
		return
	}
	svckey, valid := getServiceKey(newendpointslice)
	if !valid {
		return
	}
	delay := cont.config.ServiceGraphEndpointAddDelay.Delay
	svcDelay, exists := cont.svcInAddDelayList(svc, ns)
	if svcDelay > 0 {
		delay = svcDelay
	}
	var delayedsvc bool
	delayedsvc = exists && delay > 0
	if delayedsvc {
		cont.log.Debug("Delay of ", delay, " seconds is applicable for svc :", svc, " in ns: ", ns)
		var delayedepslice DelayedEpSlice
		delayedepslice.OldEpSlice = oldendpointslice
		delayedepslice.ServiceKey = svckey
		delayedepslice.NewEpSlice = newendpointslice
		currentTime := time.Now()
		delayedepslice.DelayedTime = currentTime.Add(time.Duration(delay) * time.Second)
		cont.indexMutex.Lock()
		cont.delayedEpSlices = append(cont.delayedEpSlices, &delayedepslice)
		cont.indexMutex.Unlock()
	} else {
		cont.doendpointSliceUpdated(oldendpointslice, newendpointslice)
	}

	if delayedsvc && cont.isDeleteEndpointSlice(oldendpointslice, newendpointslice) {
		cont.log.Debug("Proceeding by ignoring delay as the update is due to delete of endpoint")
		cont.doendpointSliceUpdated(oldendpointslice, newendpointslice)
	}
	return
}
func (cont *AciController) endpointSliceUpdated(oldobj interface{}, newobj interface{}) {
	oldendpointslice, ok := oldobj.(*discovery.EndpointSlice)
	if !ok {
		cont.log.Error("error processing Endpointslice object: ", oldobj)
		return
	}
	newendpointslice, ok := newobj.(*discovery.EndpointSlice)
	if !ok {
		cont.log.Error("error processing Endpointslice object: ", newobj)
		return
	}
	if cont.config.ServiceGraphEndpointAddDelay.Delay > 0 {
		cont.doendpointSliceUpdatedDelay(oldendpointslice, newendpointslice)
	} else {
		cont.doendpointSliceUpdated(oldendpointslice, newendpointslice)
	}
}

func (cont *AciController) doendpointSliceUpdated(oldendpointslice *discovery.EndpointSlice,
	newendpointslice *discovery.EndpointSlice) {
	servicekey, valid := getServiceKey(newendpointslice)
	if !valid {
		return
	}
	oldIps := cont.getEndpointSliceIps(oldendpointslice)
	newIps := cont.getEndpointSliceIps(newendpointslice)
	if !reflect.DeepEqual(oldIps, newIps) {
		cont.indexMutex.Lock()
		cont.queueIPNetPolUpdates(oldIps)
		cont.updateIpIndex(cont.endpointsIpIndex, oldIps, newIps, servicekey)
		cont.queueIPNetPolUpdates(newIps)
		cont.indexMutex.Unlock()
	}

	if !reflect.DeepEqual(oldendpointslice.Endpoints, newendpointslice.Endpoints) {
		cont.queueEndpointSliceNetPolUpdates(oldendpointslice)
		cont.queueEndpointSliceNetPolUpdates(newendpointslice)
	}
	cont.log.Debug("EndPointSlice Object Update: ", servicekey)
	cont.queueServiceUpdateByKey(servicekey)
}

func (cont *AciController) queueEndpointSliceNetPolUpdates(endpointslice *discovery.EndpointSlice) {
	for _, endpoint := range endpointslice.Endpoints {
		if endpoint.TargetRef == nil || endpoint.TargetRef.Kind != "Pod" ||
			endpoint.TargetRef.Namespace == "" || endpoint.TargetRef.Name == "" {
			continue
		}
		if endpoint.Conditions.Ready != nil && !*endpoint.Conditions.Ready {
			continue
		}
		podkey := endpoint.TargetRef.Namespace + "/" + endpoint.TargetRef.Name
		npkeys := cont.netPolEgressPods.GetObjForPod(podkey)
		ps := make(map[string]bool)
		for _, npkey := range npkeys {
			cont.queueNetPolUpdateByKey(npkey)
		}
		// Process if the  any matching namedport wildcard policy is present
		// ignore np already processed policies
		cont.queueMatchingNamedNp(ps, podkey)
	}
}

func getServiceKey(endPointSlice *discovery.EndpointSlice) (string, bool) {
	serviceName, ok := endPointSlice.Labels[discovery.LabelServiceName]
	if !ok {
		return "", false
	}
	return endPointSlice.ObjectMeta.Namespace + "/" + serviceName, true
}

func getServiceNameAndNs(endPointSlice *discovery.EndpointSlice) (string, string, bool) {
	serviceName, ok := endPointSlice.Labels[discovery.LabelServiceName]
	if !ok {
		return "", "", false
	}
	return serviceName, endPointSlice.ObjectMeta.Namespace, true
}

// can be called with index lock
func (sep *serviceEndpoint) UpdateServicesForNode(nodename string) {
	cont := sep.cont
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

func (seps *serviceEndpointSlice) UpdateServicesForNode(nodename string) {
	// 1. List all the endpointslice and check for matching nodename
	// 2. if it matches trigger the Service update and mark it visited
	cont := seps.cont
	visited := make(map[string]bool)
	cache.ListAll(cont.endpointSliceIndexer, labels.Everything(),
		func(endpointSliceobj interface{}) {
			endpointSlices := endpointSliceobj.(*discovery.EndpointSlice)
			for _, endpoint := range endpointSlices.Endpoints {
				if endpoint.NodeName != nil && *endpoint.NodeName == nodename {
					servicekey, valid := getServiceKey(endpointSlices)
					if !valid {
						return
					}
					if _, ok := visited[servicekey]; !ok {
						cont.queueServiceUpdateByKey(servicekey)
						visited[servicekey] = true
						return
					}
				}
			}
		})
}
func (cont *AciController) setNodeMap(nodeMap map[string]*metadata.ServiceEndpoint, nodeName string) {
	nodeMeta, ok := cont.nodeServiceMetaCache[nodeName]
	if !ok {
		return
	}
	_, ok = cont.fabricPathForNode(nodeName)
	if !ok {
		return
	}
	nodeMap[nodeName] = &nodeMeta.serviceEp

}

// 2 cases when epslices corresponding to given service is presnt in delayedEpSlices:
//  1. endpoint not present in delayedEpSlices of the service
//  2. endpoint present in delayedEpSlices of the service but in not ready state
//
// indexMutex lock must be acquired before calling the function
func (cont *AciController) isDelayedEndpoint(endpoint discovery.Endpoint, svckey string) bool {
	delayed := false
	endpointips := cont.getEndpointSliceEpIps(endpoint)
	for _, delayedepslices := range cont.delayedEpSlices {
		if delayedepslices.ServiceKey == svckey {
			var found bool
			epslice := delayedepslices.OldEpSlice
			for _, ep := range epslice.Endpoints {
				epips := cont.getEndpointSliceEpIps(ep)
				if reflect.DeepEqual(endpointips, epips) {
					// case 2
					if ep.Conditions.Ready != nil && !*ep.Conditions.Ready {
						delayed = true
					}
					found = true
				}
			}
			// case 1
			if !found {
				delayed = true
			}
		}
	}
	return delayed
}

// set nodemap only if endoint is ready and not in delayedEpSlices
func (cont *AciController) setNodeMapDelay(nodeMap map[string]*metadata.ServiceEndpoint,
	endpoint discovery.Endpoint, service *v1.Service) {

	svckey, err := cache.MetaNamespaceKeyFunc(service)
	if err != nil {
		cont.log.Error("Could not create service key: ", err)
		return
	}
	if cont.config.NoWaitForServiceEpReadiness ||
		(endpoint.Conditions.Ready != nil && *endpoint.Conditions.Ready) {

		if endpoint.NodeName != nil && *endpoint.NodeName != "" {
			// donot setNodeMap for endpoint if:
			//   endpoint is newly added
			//   endpoint status changed from not ready to ready
			if !cont.isDelayedEndpoint(endpoint, svckey) {
				cont.setNodeMap(nodeMap, *endpoint.NodeName)
			}
		}
	}
}

func (sep *serviceEndpoint) GetnodesMetadata(key string,
	service *v1.Service, nodeMap map[string]*metadata.ServiceEndpoint) {
	cont := sep.cont
	endpointsobj, exists, err := cont.endpointsIndexer.GetByKey(key)
	if err != nil {
		cont.log.Error("Could not lookup endpoints for " +
			key + ": " + err.Error())
	}
	if exists && endpointsobj != nil {
		endpoints := endpointsobj.(*v1.Endpoints)
		for _, subset := range endpoints.Subsets {
			for _, addr := range subset.Addresses {
				if addr.NodeName == nil {
					continue
				}
				cont.setNodeMap(nodeMap, *addr.NodeName)
			}
		}
	}
	cont.log.Info("NodeMap: ", nodeMap)
}

func (seps *serviceEndpointSlice) GetnodesMetadata(key string,
	service *v1.Service, nodeMap map[string]*metadata.ServiceEndpoint) {
	cont := seps.cont
	// 1. Get all the Endpoint slices matching the label service-name
	// 2. update the node map matching with endpoints nodes name
	label := map[string]string{"kubernetes.io/service-name": service.ObjectMeta.Name}
	selector := labels.SelectorFromSet(labels.Set(label))
	cache.ListAllByNamespace(cont.endpointSliceIndexer, service.ObjectMeta.Namespace, selector,
		func(endpointSliceobj interface{}) {
			endpointSlices := endpointSliceobj.(*discovery.EndpointSlice)
			for _, endpoint := range endpointSlices.Endpoints {
				if cont.config.ServiceGraphEndpointAddDelay.Delay > 0 {
					cont.setNodeMapDelay(nodeMap, endpoint, service)
				} else if cont.config.NoWaitForServiceEpReadiness ||
					(endpoint.Conditions.Ready != nil && *endpoint.Conditions.Ready) {
					if endpoint.NodeName != nil && *endpoint.NodeName != "" {
						cont.setNodeMap(nodeMap, *endpoint.NodeName)
					}
				}
			}
		})
	cont.log.Debug("NodeMap: ", nodeMap)
}

func (sep *serviceEndpoint) SetServiceApicObject(aobj apicapi.ApicObject, service *v1.Service) bool {
	cont := sep.cont
	key, err := cache.MetaNamespaceKeyFunc(service)
	if err != nil {
		serviceLogger(cont.log, service).
			Error("Could not create service key: ", err)
		return false
	}
	endpointsobj, _, err := cont.endpointsIndexer.GetByKey(key)
	if err != nil {
		cont.log.Error("Could not lookup endpoints for " +
			key + ": " + err.Error())
		return false
	}
	if endpointsobj != nil {
		for _, subset := range endpointsobj.(*v1.Endpoints).Subsets {
			for _, addr := range subset.Addresses {
				if addr.TargetRef == nil || addr.TargetRef.Kind != "Pod" {
					continue
				}
				aobj.AddChild(apicapi.NewVmmInjectedSvcEp(aobj.GetDn(),
					addr.TargetRef.Name))
			}
		}
	}
	return true
}

func (seps *serviceEndpointSlice) SetServiceApicObject(aobj apicapi.ApicObject, service *v1.Service) bool {
	cont := seps.cont
	label := map[string]string{"kubernetes.io/service-name": service.ObjectMeta.Name}
	selector := labels.SelectorFromSet(labels.Set(label))
	epcount := 0
	cache.ListAllByNamespace(cont.endpointSliceIndexer, service.ObjectMeta.Namespace, selector,
		func(endpointSliceobj interface{}) {
			endpointSlices := endpointSliceobj.(*discovery.EndpointSlice)
			for _, endpoint := range endpointSlices.Endpoints {
				if endpoint.TargetRef == nil || endpoint.TargetRef.Kind != "Pod" {
					continue
				}
				epcount++
				aobj.AddChild(apicapi.NewVmmInjectedSvcEp(aobj.GetDn(),
					endpoint.TargetRef.Name))
				cont.log.Debug("EndPoint added: ", endpoint.TargetRef.Name)
			}
		})
	return epcount != 0
}
func getProtocolStr(proto v1.Protocol) string {
	var protostring string
	switch proto {
	case v1.ProtocolUDP:
		protostring = "udp"
	case v1.ProtocolTCP:
		protostring = "tcp"
	case v1.ProtocolSCTP:
		protostring = "sctp"
	default:
		protostring = "tcp"
	}
	return protostring
}
