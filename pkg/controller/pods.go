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

// Handlers for pod updates.  Pods map to opflex endpoints

package controller

import (
	"fmt"
	"github.com/sirupsen/logrus"
	"reflect"
	"strconv"

	"github.com/noironetworks/aci-containers/pkg/apicapi"
	"github.com/noironetworks/aci-containers/pkg/metadata"
	v1netpol "github.com/noironetworks/aci-containers/pkg/networkpolicy/apis/netpolicy/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

type Severity int

const (
	cleared  Severity = iota
	info              = iota
	warning           = iota
	minor             = iota
	major             = iota
	critical          = iota
)

const (
	podFaultCode = 10
	nsFaultCode  = 11
	depFaultCode = 12
)

func (cont *AciController) initPodInformerFromClient(
	kubeClient kubernetes.Interface) {

	cont.initPodInformerBase(
		cache.NewListWatchFromClient(
			kubeClient.CoreV1().RESTClient(), "pods",
			metav1.NamespaceAll, fields.Everything()))
}

func (cont *AciController) initPodInformerBase(listWatch *cache.ListWatch) {
	cont.podIndexer, cont.podInformer = cache.NewIndexerInformer(
		listWatch, &v1.Pod{}, 0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				cont.podAdded(obj)
			},
			UpdateFunc: func(oldobj interface{}, newobj interface{}) {
				cont.podUpdated(oldobj, newobj)
			},
			DeleteFunc: func(obj interface{}) {
				cont.podDeleted(obj)
			},
		},
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
}

func podLogger(log *logrus.Logger, pod *v1.Pod) *logrus.Entry {
	return log.WithFields(logrus.Fields{
		"namespace": pod.ObjectMeta.Namespace,
		"name":      pod.ObjectMeta.Name,
		"node":      pod.Spec.NodeName,
	})
}

func podFilter(pod *v1.Pod) bool {
	return !(pod.Spec.HostNetwork)
}

func (cont *AciController) queuePodUpdate(pod *v1.Pod) {
	podkey, err := cache.MetaNamespaceKeyFunc(pod)
	if err != nil {
		podLogger(cont.log, pod).Error("Could not create pod key: ", err)
		return
	}
	cont.podQueue.Add(podkey)
}

func (cont *AciController) checkIfEpgExistPod(pod *v1.Pod) {

	podkey, err := cache.MetaNamespaceKeyFunc(pod)
	if err != nil {
		podLogger(cont.log, pod).Error("Could not create pod key: ", err)
		return
	}

	key := cont.aciNameForKey("podfs", podkey)
	epGroup, ok := pod.ObjectMeta.Annotations[metadata.EgAnnotation]
	if ok {
		severity := major
		cont.handleEpgAnnotationUpdate(key, podFaultCode, severity, pod.Name, epGroup)
	}

	return
}

func (cont *AciController) handleEpgAnnotationUpdate(key string, faultCode int, severity int, entity string, epGroup string) bool {
	var egval metadata.OpflexGroup
	epgExist, egval, setFaultInst := cont.checkEpgCache(epGroup, "EpgAnnotation")

	if epgExist {
		//clearing existing faults upon correct annotation
		cont.apicConn.ClearApicObjects(key)
	} else if !epgExist {

		if setFaultInst {
			desc := fmt.Sprintf("Annotation failed on Ns/Dep/Pod for the entity %s, Reason being: Cannot resolve the EPG:%s for the tenant:%s and app-profile:%s",

				entity, egval.Name, egval.Tenant, egval.AppProfile)

			cont.log.Error(desc)
			faultcode := strconv.Itoa(faultCode)
			severity := strconv.Itoa(severity)

			aPrObj := apicapi.NewVmmInjectedClusterInfo(cont.vmmDomainProvider(),
				cont.config.AciVmmDomain, cont.config.AciVmmController)
			aPrObjDn := aPrObj.GetDn()
			aObj := apicapi.NewVmmClusterFaultInfo(aPrObjDn, faultcode)
			aObj.SetAttr("faultDesc", desc)
			aObj.SetAttr("faultCode", faultcode)
			aObj.SetAttr("faultSeverity", severity)

			if faultCode == nsFaultCode {
				cont.apicConn.WriteApicContainer(key, apicapi.ApicSlice{aObj})
			} else {
				cont.apicConn.WriteApicObjects(key, apicapi.ApicSlice{aObj})
			}
			return true
		}
	}
	return false
}

func (cont *AciController) handlePodUpdate(pod *v1.Pod) bool {
	if !podFilter(pod) {
		return false
	}
	logger := podLogger(cont.log, pod)

	podkey, err := cache.MetaNamespaceKeyFunc(pod)
	if err != nil {
		logger.Error("Could not create pod key: ", err)
		return false
	}

	cont.indexMutex.Lock()
	if pod.Spec.NodeName != "" {
		// note here we're assuming pods do not change nodes
		cont.addPodToNode(pod.Spec.NodeName, podkey)

	}
	cont.indexMutex.Unlock()
	go cont.updateCtrNmPortForPod(pod, podkey)
	return false
}

func (cont *AciController) writeApicPod(pod *v1.Pod) {
	podkey, err := cache.MetaNamespaceKeyFunc(pod)
	if err != nil {
		podLogger(cont.log, pod).Error("Could not create pod key: ", err)
		return
	}
	key := cont.aciNameForKey("pod", podkey)
	if !podFilter(pod) || pod.Spec.NodeName == "" {
		cont.apicConn.ClearApicObjects(key)
		return
	}

	aobj := apicapi.NewVmmInjectedContGrp(cont.vmmDomainProvider(),
		cont.config.AciVmmDomain, cont.config.AciVmmController,
		pod.Namespace, pod.Name)
	aobj.SetAttr("guid", string(pod.UID))
	aobj.SetAttr("hostName", pod.Spec.NodeName)
	aobj.SetAttr("computeNodeName", pod.Spec.NodeName)
	for _, or := range pod.OwnerReferences {
		if or.Kind == "ReplicaSet" && or.Name != "" {
			aobj.SetAttr("replicaSetName", or.Name)
			break
		}
	}
	if pod.ObjectMeta.Labels != nil && apicapi.ApicVersion >= "5.0" {
		for key, val := range pod.ObjectMeta.Labels {
			label := apicapi.NewVmmInjectedLabel(aobj.GetDn(),
				key, val)
			aobj.AddChild(label)
		}
	}
	cont.apicConn.WriteApicObjects(key, apicapi.ApicSlice{aobj})
}

func (cont *AciController) podAdded(obj interface{}) {
	pod := obj.(*v1.Pod)
	cont.writeApicPod(pod)
	cont.depPods.UpdatePodNoCallback(pod)
	cont.erspanPolPods.UpdatePodNoCallback(pod)
	cont.netPolPods.UpdatePodNoCallback(pod)
	cont.netPolIngressPods.UpdatePodNoCallback(pod)
	cont.netPolEgressPods.UpdatePodNoCallback(pod)
	cont.queuePodUpdate(pod)
	cont.checkIfEpgExistPod(pod)
}

func (cont *AciController) podUpdated(oldobj interface{}, newobj interface{}) {
	oldpod := oldobj.(*v1.Pod)
	newpod := newobj.(*v1.Pod)

	cont.writeApicPod(newpod)

	shouldqueue := false
	if oldpod.Status.PodIP != newpod.Status.PodIP ||
		!reflect.DeepEqual(oldpod.ObjectMeta.Labels, newpod.ObjectMeta.Labels) {
		shouldqueue =
			cont.depPods.UpdatePodNoCallback(newpod) || shouldqueue
		shouldqueue =
			cont.erspanPolPods.UpdatePodNoCallback(newpod) || shouldqueue
		shouldqueue =
			cont.netPolPods.UpdatePodNoCallback(newpod) || shouldqueue
		shouldqueue =
			cont.netPolIngressPods.UpdatePodNoCallback(newpod) || shouldqueue
		shouldqueue =
			cont.netPolEgressPods.UpdatePodNoCallback(newpod) || shouldqueue
	}
	if !reflect.DeepEqual(oldpod.ObjectMeta.Annotations,
		newpod.ObjectMeta.Annotations) {
		shouldqueue = true
	} else if oldpod.Spec.NodeName != newpod.Spec.NodeName {
		shouldqueue = true
	}

	if shouldqueue {
		cont.queuePodUpdate(newpod)
	}
	cont.checkIfEpgExistPod(newpod)
}

func (cont *AciController) podDeleted(obj interface{}) {
	pod, isPod := obj.(*v1.Pod)
	if !isPod {
		deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			cont.log.Error("Received unexpected object: ", obj)
			return
		}
		pod, ok = deletedState.Obj.(*v1.Pod)
		if !ok {
			cont.log.Error("DeletedFinalStateUnknown contained non-Pod object: ", deletedState.Obj)
			return
		}
	}
	logger := podLogger(cont.log, pod)
	podkey, err := cache.MetaNamespaceKeyFunc(pod)
	if err != nil {
		logger.Error("Could not create pod key:" + err.Error())
		return
	}

	cont.apicConn.ClearApicObjects(cont.aciNameForKey("pod", podkey))
	cont.apicConn.ClearApicObjects(cont.aciNameForKey("podfs", podkey))
	cont.depPods.DeletePod(pod)
	cont.erspanPolPods.DeletePod(pod)
	cont.netPolPods.DeletePod(pod)
	cont.netPolIngressPods.DeletePod(pod)
	cont.netPolEgressPods.DeletePod(pod)

	cont.indexMutex.Lock()
	cont.removePodFromNode(pod.Spec.NodeName, podkey)
	cont.indexMutex.Unlock()
	go cont.deleteCtrNmPortForPod(pod, podkey)
	logger.Debug("Pod deleted")
}

func (cont *AciController) updateCtrNmPortForPod(pod *v1.Pod, podkey string) {
	cont.indexMutex.Lock()
	nmport := false
	for _, ctr := range pod.Spec.Containers {
		for _, ctrportspec := range ctr.Ports {
			if ctrportspec.Name != "" {
				key := portProto(&ctrportspec.Protocol) + "-" + strconv.Itoa(int(ctrportspec.ContainerPort))
				ctrNmpEntry, ok := cont.ctrPortNameCache[ctrportspec.Name]
				if !ok {
					ctrNmpEntry := &ctrPortNameEntry{}
					ctrNmpEntry.ctrNmpToPods = make(map[string]map[string]bool)
					ctrNmpEntry.ctrNmpToPods[key] = make(map[string]bool)
					ctrNmpEntry.ctrNmpToPods[key][podkey] = true
					cont.ctrPortNameCache[ctrportspec.Name] = ctrNmpEntry
				} else {
					if _, present := ctrNmpEntry.ctrNmpToPods[key]; !present {
						ctrNmpEntry.ctrNmpToPods[key] = make(map[string]bool)
					}
					ctrNmpEntry.ctrNmpToPods[key][podkey] = true
				}
				nmport = true
			}
		}
	}
	cont.indexMutex.Unlock()
	if nmport {
		for npkey := range cont.nmPortNp {
			obj, exists, err := cont.networkPolicyIndexer.GetByKey(npkey)
			if exists && err == nil {
				np := obj.(*v1netpol.NetworkPolicy)
				if !cont.checkPodNmpMatchesNp(npkey, podkey) {
					continue
				}
				cont.indexMutex.Lock()
				ports := cont.getNetPolTargetPorts(np)
				cont.updateTargetPortIndex(false, npkey, nil, ports)
				cont.indexMutex.Unlock()
				cont.log.Debug("Added Ports: ", ports, "For Network Policy: ", npkey)
				cont.queueNetPolUpdateByKey(npkey)
			}
		}
	}
}

func (cont *AciController) deleteCtrNmPortForPod(pod *v1.Pod, podkey string) {
	cont.indexMutex.Lock()
	cont.removePodFromNode(pod.Spec.NodeName, podkey)
	nmport := false
	for _, ctr := range pod.Spec.Containers {
		for _, ctrportspec := range ctr.Ports {
			if ctrportspec.Name != "" {
				ctrNmpEntry, ok := cont.ctrPortNameCache[ctrportspec.Name]
				if ok {
					key := portProto(&ctrportspec.Protocol) + "-" + strconv.Itoa(int(ctrportspec.ContainerPort))
					pods, present := ctrNmpEntry.ctrNmpToPods[key]
					if present {
						delete(pods, podkey)
						if len(pods) == 0 {
							delete(ctrNmpEntry.ctrNmpToPods, key)
						}
					}
					if len(ctrNmpEntry.ctrNmpToPods) == 0 {
						delete(cont.ctrPortNameCache, ctrportspec.Name)
					}
				}
				nmport = true
			}
		}
	}
	cont.indexMutex.Unlock()
	if nmport {
		for npkey := range cont.nmPortNp {
			if !cont.checkPodNmpMatchesNp(npkey, podkey) {
				continue
			}
			cont.queueNetPolUpdateByKey(npkey)
		}
	}
}
