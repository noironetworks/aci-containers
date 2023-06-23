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

package hostagent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/sirupsen/logrus"

	aciv1 "github.com/noironetworks/aci-containers/pkg/gbpcrd/apis/acipolicy/v1"
	nodepodif "github.com/noironetworks/aci-containers/pkg/nodepodif/apis/acipolicy/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"k8s.io/kubernetes/pkg/controller"

	"github.com/google/uuid"
	"github.com/noironetworks/aci-containers/pkg/metadata"
	cnimeta "github.com/noironetworks/aci-containers/pkg/metadata"
	"github.com/noironetworks/aci-containers/pkg/util"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

const NullMac = "null-mac"

type opflexEndpoint struct {
	Uuid string `json:"uuid"`

	EgPolicySpace string                 `json:"eg-policy-space,omitempty"`
	EndpointGroup string                 `json:"endpoint-group-name,omitempty"`
	SecurityGroup []metadata.OpflexGroup `json:"security-group,omitempty"`
	QosPolicy     metadata.OpflexGroup   `json:"qos-policy,omitempty"`

	IpAddress  []string `json:"ip,omitempty"`
	MacAddress string   `json:"mac,omitempty"`

	AccessIface       string `json:"access-interface,omitempty"`
	AccessUplinkIface string `json:"access-uplink-interface,omitempty"`
	IfaceName         string `json:"interface-name,omitempty"`

	Attributes        map[string]string `json:"attributes,omitempty"`
	SnatUuid          []string          `json:"snat-uuids,omitempty"`
	ServiceClusterIps []string          `json:"service-ip,omitempty"`
	registered        bool
}

func (agent *HostAgent) getPodIFName(ns, podName string) string {
	return fmt.Sprintf("%s.%s.%s", ns, podName, agent.vtepIP)
}

func (agent *HostAgent) EPRegAdd(ep *opflexEndpoint) bool {

	if agent.crdClient == nil {
		ep.registered = true
		return false // crd not used
	}

	// force the mask to /32
	ipRemEP := strings.Split(ep.IpAddress[0], "/")[0] + "/32"
	remEP := &aciv1.PodIF{
		Status: aciv1.PodIFStatus{
			PodNS:       ep.Attributes["namespace"],
			PodName:     ep.Attributes["vm-name"],
			ContainerID: ep.Uuid,
			MacAddr:     ep.MacAddress,
			IPAddr:      ipRemEP,
			EPG:         ep.EndpointGroup,
			VTEP:        agent.vtepIP,
			IFName:      ep.IfaceName,
		},
	}
	remEP.ObjectMeta.Name = agent.getPodIFName(ep.Attributes["namespace"], ep.Attributes["vm-name"])

	podif, err := agent.crdClient.PodIFs("kube-system").Get(context.TODO(), remEP.ObjectMeta.Name, metav1.GetOptions{})
	if err != nil {
		// create podif
		_, err := agent.crdClient.PodIFs("kube-system").Create(context.TODO(), remEP, metav1.CreateOptions{})
		if err != nil {
			logrus.Errorf("Create error %v, podif: %+v", err, remEP)
			return true
		}

	} else {
		// update it
		podif.Status = remEP.Status
		_, err := agent.crdClient.PodIFs("kube-system").Update(context.TODO(), podif, metav1.UpdateOptions{})
		if err != nil {
			logrus.Errorf("Update error %v, podif: %+v", err, remEP)
			return true
		}
	}
	ep.registered = true
	opflexEpLogger(agent.log, ep).Info("Updated podif")
	return false
}

func (agent *HostAgent) EPRegDelEP(name string) {
	if agent.crdClient == nil {
		return // crd not used
	}
	err := agent.crdClient.PodIFs("kube-system").Delete(context.TODO(), name, metav1.DeleteOptions{})
	if err != nil {
		agent.log.Errorf("Error %v, podif: %s", err, name)
		return
	}
	agent.log.Infof("podif: %s deleted", name)
}

func (agent *HostAgent) getNodePodIFName(nodeName string) string {
	return fmt.Sprintf("%s.%s", nodeName, agent.vtepIP)
}

func (agent *HostAgent) NodeEPRegAdd(nodePodIfEPs map[string]*opflexEndpoint) bool {

	if agent.nodePodIFClient == nil {
		agent.log.Debug("NodePodIF client or Kube clients are not intialized")
		return false // crd not used
	}

	var podifs []nodepodif.PodIF
	for _, ep := range nodePodIfEPs {
		ipRemEP := strings.Split(ep.IpAddress[0], "/")[0] + "/32"
		opflexEpLogger(agent.log, ep).Debug("ipRemEP")
		var podif nodepodif.PodIF
		podif.PodNS = ep.Attributes["namespace"]
		podif.PodName = ep.Attributes["vm-name"]
		podif.ContainerID = ep.Uuid
		podif.MacAddr = ep.MacAddress
		podif.IPAddr = ipRemEP
		// could change
		podif.EPG = ep.EndpointGroup
		podif.VTEP = agent.vtepIP
		podif.IFName = ep.IfaceName
		podifs = append(podifs, podif)
	}

	nodePodif, err := agent.nodePodIFClient.NodePodIFs("kube-system").Get(context.TODO(), agent.getNodePodIFName(agent.config.NodeName), metav1.GetOptions{})
	if err != nil {
		// create nodepodif
		if apierrors.IsNotFound(err) {
			remEP := &nodepodif.NodePodIF{
				ObjectMeta: metav1.ObjectMeta{
					Name:      agent.getNodePodIFName(agent.config.NodeName),
					Namespace: "kube-system",
				},
				Spec: nodepodif.NodePodIFSpec{
					PodIFs: podifs,
				},
			}

			_, err := agent.nodePodIFClient.NodePodIFs("kube-system").Create(context.TODO(), remEP, metav1.CreateOptions{})
			agent.log.Debugf("nodepodif: %s created for node", remEP.ObjectMeta.Name)
			if err != nil {
				logrus.Errorf("Create error %v, nodepodif: %+v", err, remEP)
				return true
			}
		}

	} else {
		// update nodepodif
		if !reflect.DeepEqual(nodePodif.Spec.PodIFs, podifs) {
			nodePodif.Spec.PodIFs = podifs
			_, err := agent.nodePodIFClient.NodePodIFs("kube-system").Update(context.TODO(), nodePodif, metav1.UpdateOptions{})
			if err != nil {
				logrus.Errorf("Update error %v, nodepodif: %+v", err, nodePodif)
				return true
			}
		}
	}
	if err == nil {
		agent.log.Debugf("nodepodif: %s updated for node", nodePodif.ObjectMeta.Name)
		return true
	}
	return false
}

func (agent *HostAgent) initPodInformerFromClient(
	kubeClient *kubernetes.Clientset) {

	agent.initPodInformerBase(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				options.FieldSelector =
					fields.Set{"spec.nodeName": agent.config.NodeName}.String()
				obj, err := kubeClient.CoreV1().Pods(metav1.NamespaceAll).List(context.TODO(), options)
				if err != nil {
					agent.log.Fatal("Failed to list Pods during initialization of PodInformer")
				}
				return obj, err
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				options.FieldSelector =
					fields.Set{"spec.nodeName": agent.config.NodeName}.String()
				obj, err := kubeClient.CoreV1().Pods(metav1.NamespaceAll).Watch(context.TODO(), options)
				if err != nil {
					agent.log.Fatal("Failed to watch Pods during initialization of PodInformer")
				}
				return obj, err
			},
		})

	agent.initControllerInformerBase(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				options.LabelSelector = labels.Set{"name": "aci-containers-controller"}.String()
				//options.LabelSelector = "name=aci-containers-controller"
				obj, err := kubeClient.CoreV1().Pods(metav1.NamespaceAll).List(context.TODO(), options)
				if err != nil {
					agent.log.Fatal("Failed to list Pods during initialization of ControllerInformer")
				}
				return obj, err
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				options.LabelSelector = labels.Set{"name": "aci-containers-controller"}.String()
				//options.LabelSelector = "name=aci-containers-controller"
				obj, err := kubeClient.CoreV1().Pods(metav1.NamespaceAll).Watch(context.TODO(), options)
				if err != nil {
					agent.log.Fatal("Failed to watch Pods during initialization of ControllerInformer")
				}
				return obj, err
			},
		})
}

func (agent *HostAgent) initPodInformerBase(listWatch *cache.ListWatch) {
	agent.podInformer = cache.NewSharedIndexInformer(
		listWatch,
		&v1.Pod{},
		controller.NoResyncPeriodFunc(),
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	agent.podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			agent.podUpdated(obj)
		},
		UpdateFunc: func(_ interface{}, obj interface{}) {
			agent.podUpdated(obj)
		},
		DeleteFunc: func(obj interface{}) {
			agent.podDeleted(obj)
		},
	})
}

func (agent *HostAgent) initControllerInformerBase(listWatch *cache.ListWatch) {
	agent.controllerInformer = cache.NewSharedIndexInformer(
		listWatch,
		&v1.Pod{},
		controller.NoResyncPeriodFunc(),
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	agent.controllerInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			agent.updateGbpServerInfo(obj.(*v1.Pod))
		},
		UpdateFunc: func(_ interface{}, obj interface{}) {
			agent.updateGbpServerInfo(obj.(*v1.Pod))
		},
		DeleteFunc: func(obj interface{}) {
		},
	})
}

func getEp(epfile string) (string, error) {
	raw, err := os.ReadFile(epfile)
	if err != nil {
		return "", err
	}
	return string(raw), err
}

func readEp(epfile string) (*opflexEndpoint, error) {
	epStr, err := getEp(epfile)
	if err != nil {
		return nil, err
	}

	ep := &opflexEndpoint{}
	err = json.Unmarshal([]byte(epStr), ep)
	return ep, err
}

func writeEp(epfile string, ep *opflexEndpoint) (bool, error) {
	newdata, err := json.MarshalIndent(ep, "", "  ")
	if err != nil {
		return true, err
	}
	existingdata, err := os.ReadFile(epfile)
	if err == nil && reflect.DeepEqual(existingdata, newdata) {
		return false, nil
	}
	err = os.WriteFile(epfile, newdata, 0644)
	return true, err
}

func podLogger(log *logrus.Logger, pod *v1.Pod) *logrus.Entry {
	return log.WithFields(logrus.Fields{
		"namespace": pod.ObjectMeta.Namespace,
		"name":      pod.ObjectMeta.Name,
		"node":      pod.Spec.NodeName,
	})
}

func opflexEpLogger(log *logrus.Logger, ep *opflexEndpoint) *logrus.Entry {
	return log.WithFields(logrus.Fields{
		"Uuid":      ep.Uuid,
		"name":      ep.Attributes["vm-name"],
		"namespace": ep.Attributes["namespace"],
	})
}

func (agent *HostAgent) FormEPFilePath(uuid string) string {
	return filepath.Join(agent.config.OpFlexEndpointDir, uuid+".ep")
}

func (agent *HostAgent) syncOpflexServer() bool {
	grpcAddr := fmt.Sprintf("%s:%d", agent.gbpServerIP, agent.config.GRPCPort)
	srvCfg := &OpflexServerConfig{GRPCAddress: grpcAddr}

	err := os.MkdirAll(filepath.Dir(agent.config.OpFlexServerConfigFile), os.ModeDir|0664)
	if err != nil {
		agent.log.Errorf("Failed to create directory: %s", filepath.Dir(agent.config.OpFlexServerConfigFile))
	}

	data, _ := json.MarshalIndent(srvCfg, "", "  ")
	err = os.WriteFile(agent.config.OpFlexServerConfigFile, data, 0644)
	if err != nil {
		agent.log.Errorf("Failed to create file: %s", agent.config.OpFlexServerConfigFile)
	} else {
		agent.log.Infof("Updated grpc addr to %s", grpcAddr)
	}

	return false
}

func (agent *HostAgent) syncEps() bool {
	if !agent.syncEnabled {
		return false
	}

	agent.log.Debug("Syncing endpoints")
	agent.indexMutex.Lock()
	opflexEps := make(map[string][]*opflexEndpoint)
	for k, v := range agent.opflexEps {
		ep := []*opflexEndpoint{}
		for _, op := range v {
			val := &opflexEndpoint{}
			err := util.DeepCopyObj(op, val)
			if err != nil {
				continue
			}
			ep = append(ep, val)
		}
		opflexEps[k] = ep
	}
	agent.indexMutex.Unlock()

	files, err := os.ReadDir(agent.config.OpFlexEndpointDir)
	if err != nil {
		agent.log.WithFields(
			logrus.Fields{"endpointDir": agent.config.OpFlexEndpointDir},
		).Error("Could not read directory ", err)
		return true
	}

	needRetry := false
	seen := make(map[string]bool)
	nullMacFile := false
	nullMacCheck := agent.getEpFileName(agent.config.DefaultEg.Name)
	for _, f := range files {
		if !strings.HasSuffix(f.Name(), ".ep") ||
			strings.Contains(f.Name(), "veth_host_ac") {
			continue
		}

		if f.Name() == nullMacCheck {
			nullMacFile = true
			continue
		}

		epfile := filepath.Join(agent.config.OpFlexEndpointDir, f.Name())
		epidstr := f.Name()
		epidstr = epidstr[:len(epidstr)-3]
		epid := strings.Split(epidstr, "_")

		if len(epid) < 3 {
			agent.log.Warn("Removing invalid endpoint:", f.Name())
			os.Remove(epfile)
			continue
		}
		poduuid := epid[0]
		contid := epid[1]
		contiface := epid[2]

		logger := agent.log.WithFields(
			logrus.Fields{
				"PodUuid":   poduuid,
				"ContId":    contid,
				"ContIFace": contiface,
			},
		)

		existing, ok := opflexEps[poduuid]
		if ok {
			for _, ep := range existing {
				if ep.Uuid != epidstr {
					continue
				}
				ep.SnatUuid, err = agent.getSnatUuids(poduuid, epfile)
				if err != nil {
					agent.log.Error("Error while getting snat uuids")
					needRetry = true
					continue
				}
				ep.ServiceClusterIps = agent.getServiceIPs(poduuid)
				wrote, err := writeEp(epfile, ep)
				if err != nil {
					opflexEpLogger(agent.log, ep).
						Error("Error writing EP file: ", err)
				} else if wrote || !ep.registered {
					needRetry = agent.EPRegAdd(ep)
				}
				if _, ok := agent.nodePodIfEPs[ep.Uuid]; !ok {
					agent.nodePodIfEPs[ep.Uuid] = ep
				}
				seen[epidstr] = true
			}
		}

		if !ok || (ok && !seen[epidstr]) {
			staleEp, err := readEp(epfile)
			if err == nil {
				k := agent.getPodIFName(staleEp.Attributes["namespace"], staleEp.Attributes["vm-name"])
				agent.EPRegDelEP(k)
				delete(agent.nodePodIfEPs, staleEp.Uuid)
			}
			logger.Info("Removing endpoint")
			os.Remove(epfile)
		}
	}

	for _, eps := range opflexEps {
		for _, ep := range eps {
			if seen[ep.Uuid] {
				continue
			}
			epfile := agent.FormEPFilePath(ep.Uuid)
			poduuid := strings.Split(ep.Uuid, "_")[0]
			ep.SnatUuid, err = agent.getSnatUuids(poduuid, epfile)
			if err != nil {
				agent.log.Error("Error while getting snat uuids")
				needRetry = true
				continue
			}
			ep.ServiceClusterIps = agent.getServiceIPs(poduuid)
			opflexEpLogger(agent.log, ep).Info("Adding endpoint")
			_, err = writeEp(epfile, ep)
			if err != nil {
				opflexEpLogger(agent.log, ep).
					Error("Error writing EP file: ", err)
				needRetry = true
			} else {
				needRetry = agent.EPRegAdd(ep)
				agent.nodePodIfEPs[ep.Uuid] = ep
			}
		}
	}

	if !nullMacFile {
		agent.creatNullMacEp()
	}
	agent.log.Debug("Finished endpoint sync")
	return needRetry
}

// syncNodePodIfs syncs the NodePodIfs with Eps
func (agent *HostAgent) syncNodePodIfs() bool {
	if !agent.syncEnabled {
		return false
	}
	agent.log.Debug("Syncing NodePodIfs")
	agent.indexMutex.Lock()
	defer agent.indexMutex.Unlock()
	agent.NodeEPRegAdd(agent.nodePodIfEPs)
	agent.log.Debug("Finished NodePodIfs sync")
	return false
}

func (agent *HostAgent) getEpFileName(epGroupName string) string {
	temp := strings.Split(epGroupName, "|")
	var EpFileName string
	if len(temp) == 1 {
		EpFileName = epGroupName + "_" + NullMac + ".ep"
	} else {
		EpFileName = temp[1] + "_" + NullMac + ".ep"
	}
	return EpFileName
}

func (agent *HostAgent) creatNullMacEp() {
	epGroup := agent.config.DefaultEg
	EpFileName := agent.getEpFileName(epGroup.Name)
	EpFilePath := filepath.Join(agent.config.OpFlexEndpointDir, EpFileName)
	ep_file_exists := fileExists(EpFilePath)
	if ep_file_exists {
		return
	}
	ep := &opflexEndpoint{
		Uuid:          uuid.New().String(),
		EgPolicySpace: epGroup.PolicySpace,
		EndpointGroup: epGroup.Name,
		MacAddress:    "00:00:00:00:00:00",
	}
	wrote, err := writeEp(EpFilePath, ep)
	if err != nil {
		agent.log.Debug("Unable to write null mac Ep file")
	} else if wrote {
		agent.log.Debug("Created null mac Ep file")
	}

}

func podFilter(pod *v1.Pod) bool {
	return !(pod.Spec.HostNetwork)
}

func (agent *HostAgent) podUpdated(obj interface{}) {
	agent.log.Infof("Pod updated: namespace=%s name=%s", obj.(*v1.Pod).Namespace, obj.(*v1.Pod).Name)
	agent.indexMutex.Lock()
	defer agent.indexMutex.Unlock()
	agent.depPods.UpdatePodNoCallback(obj.(*v1.Pod))
	agent.rcPods.UpdatePodNoCallback(obj.(*v1.Pod))
	agent.netPolPods.UpdatePodNoCallback(obj.(*v1.Pod))
	agent.qosPolPods.UpdatePodNoCallback(obj.(*v1.Pod))
	agent.handleObjectUpdateForSnat(obj)
	agent.podChangedLocked(obj)
}

func (agent *HostAgent) podChanged(podkey *string) {
	podobj, exists, err := agent.podInformer.GetStore().GetByKey(*podkey)
	if err != nil {
		agent.log.Error("Could not lookup pod: ", err)
	}
	if !exists || podobj == nil {
		agent.log.Debug("Object doesn't exist yet ", *podkey)
		return
	}

	agent.indexMutex.Lock()
	defer agent.indexMutex.Unlock()
	agent.podChangedLocked(podobj)
}

// Must have index lock
func (agent *HostAgent) podChangedPostLock(podkey *string) {
	podobj, exists, err := agent.podInformer.GetStore().GetByKey(*podkey)
	if err != nil {
		agent.log.Error("Could not lookup pod: ", err)
	}
	if !exists || podobj == nil {
		agent.log.Debug("Object doesn't exist yet ", *podkey)
		return
	}

	agent.podChangedLocked(podobj)
}

func (agent *HostAgent) podChangedLocked(podobj interface{}) {
	pod := podobj.(*v1.Pod)
	logger := podLogger(agent.log, pod)

	epMetaKey := fmt.Sprintf("%s/%s", pod.ObjectMeta.Namespace, pod.ObjectMeta.Name)
	epUuid := string(pod.ObjectMeta.UID)

	if !podFilter(pod) {
		agent.epDeleted(&epUuid)
		return
	}
	agent.cniToPodID[epMetaKey] = epUuid
	if pod.Status.PodIP != "" {
		type void struct{}
		var ipexists void
		podIPs := make(map[string]void)
		podIPs[pod.Status.PodIP] = ipexists
		podIPsField := reflect.ValueOf(pod.Status).FieldByName("PodIPs")
		if podIPsField.IsValid() {
			for _, ip := range pod.Status.PodIPs {
				podIPs[ip.IP] = ipexists
			}
		}
		for ip := range podIPs {
			agent.podIpToName[ip] = epMetaKey
		}
	}
	agent.podUidToName[epUuid] = epMetaKey
	epGroup, secGroup, qpGroup, _ := agent.assignGroups(pod)
	epAttributes := pod.ObjectMeta.Labels
	if epAttributes == nil {
		epAttributes = make(map[string]string)
	}
	epAttributes["vm-name"] = pod.ObjectMeta.Name
	epAttributes["namespace"] = pod.ObjectMeta.Namespace

	agent.epChanged(&epUuid, &epMetaKey, &epGroup, secGroup, qpGroup, epAttributes, logger)
	var netAttachDef []string
	if pod.ObjectMeta.Annotations[metadata.NetAttDefAnnotation] != "" {
		netAttachDef = strings.Split(pod.ObjectMeta.Annotations[metadata.NetAttDefAnnotation], ",")
	} else if pod.ObjectMeta.Annotations[metadata.MultusNetAnnotation] != "" {
		netAttachDef = strings.Split(pod.ObjectMeta.Annotations[metadata.MultusNetAnnotation], ",")
	}
	if netAttachDef != nil {
		podKey := pod.ObjectMeta.Name + "-" + pod.ObjectMeta.Namespace
		agent.podToNetAttachDef[podKey] = netAttachDef
	}
}

func (agent *HostAgent) epChanged(epUuid *string, epMetaKey *string, epGroup *metadata.OpflexGroup,
	epSecGroups []metadata.OpflexGroup, epQosPolicy metadata.OpflexGroup, epAttributes map[string]string,
	logger *logrus.Entry) {
	if logger == nil {
		logger = agent.log.WithFields(logrus.Fields{})
	}

	logger.Debug("epChanged...")
	epmetadata, ok := agent.epMetadata[*epMetaKey]
	if !ok {
		logger.Debug("No metadata found for ep: ")
		delete(agent.opflexEps, *epUuid)
		agent.scheduleSyncEps()
		return
	}

	var neweps []*opflexEndpoint

	for _, epmeta := range epmetadata {
		for _, iface := range epmeta.Ifaces {
			patchIntName, patchAccessName :=
				metadata.GetIfaceNames(iface.HostVethName)

			ips := make([]string, 0)
			for _, ip := range iface.IPs {
				if ip.Address.IP == nil {
					continue
				}
				ips = append(ips, ip.Address.IP.String())
			}

			epidstr := *epUuid + "_" + epmeta.Id.ContId + "_" + iface.HostVethName
			ep := &opflexEndpoint{
				Uuid:              epidstr,
				MacAddress:        iface.Mac,
				IpAddress:         ips,
				AccessIface:       iface.HostVethName,
				AccessUplinkIface: patchAccessName,
				IfaceName:         patchIntName,
			}

			ep.Attributes = make(map[string]string)
			if epAttributes != nil {
				for k, v := range epAttributes {
					ep.Attributes[k] = v
				}
			}

			ep.Attributes["interface-name"] = iface.HostVethName
			if epGroup.Tenant != "" {
				ep.EgPolicySpace = epGroup.Tenant
			} else {
				ep.EgPolicySpace = epGroup.PolicySpace
			}
			if epGroup.AppProfile != "" {
				ep.EndpointGroup = epGroup.AppProfile + "|" + epGroup.Name
			} else {
				ep.EndpointGroup = epGroup.Name
			}
			ep.SecurityGroup = epSecGroups
			ep.QosPolicy = epQosPolicy

			neweps = append(neweps, ep)
		}
	}

	existing, ok := agent.opflexEps[*epUuid]
	for ix, ep := range existing { // TODO - fixme
		neweps[ix].registered = ep.registered
	}

	if (ok && !reflect.DeepEqual(existing, neweps)) || !ok {
		logger.WithFields(logrus.Fields{
			"id": *epMetaKey,
			"ep": neweps,
		}).Debug("Updated endpoints for pod")
		logger.Infof("EP updated: %+v", neweps[0])

		agent.opflexEps[*epUuid] = neweps
		agent.scheduleSyncEps()
	}
}

func (agent *HostAgent) epDeleted(epUuid *string) {
	if _, ok := agent.opflexEps[*epUuid]; ok {
		delete(agent.opflexEps, *epUuid)
		agent.scheduleSyncEps()
	}
}

func (agent *HostAgent) podDeleted(obj interface{}) {
	pod, isPod := obj.(*v1.Pod)
	if !isPod {
		deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			agent.log.Error("Received unexpected object: ", obj)
			return
		}
		pod, ok = deletedState.Obj.(*v1.Pod)
		if !ok {
			agent.log.Error("DeletedFinalStateUnknown contained non-Pod object: ", deletedState.Obj)
			return
		}
	}
	agent.log.Infof("Pod deleted: name %s namespace %s", pod.ObjectMeta.Name, pod.ObjectMeta.Namespace)
	podns, podname := pod.ObjectMeta.Namespace, pod.ObjectMeta.Name
	podid := podns + "/" + podname
	mdmap, ok := agent.epMetadata[podid]
	if ok {
		for contid, v := range mdmap {
			metadata := cnimeta.ContainerMetadata{
				Id: cnimeta.ContainerId{
					ContId:    contid,
					Namespace: podns,
					Pod:       podname,
				},
				Network: cnimeta.ContainerNetworkMetadata{
					NetworkName: v.Network.NetworkName,
					ChainedMode: agent.config.ChainedMode,
				},
			}
			err := agent.unconfigureContainerIfaces(&metadata)
			if err != nil {
				agent.log.Warnf("Could not unconfigure container:%s, %s ", contid, err)
			}
		}
	}
	agent.indexMutex.Lock()
	defer agent.indexMutex.Unlock()
	agent.podDeletedLocked(obj)
	agent.depPods.DeletePod(obj.(*v1.Pod))
	agent.rcPods.DeletePod(obj.(*v1.Pod))
	agent.qosPolPods.DeletePod(obj.(*v1.Pod))
	agent.netPolPods.DeletePod(obj.(*v1.Pod))
	agent.handleObjectDeleteForSnat(obj)
}

func (agent *HostAgent) podDeletedLocked(obj interface{}) {
	pod := obj.(*v1.Pod)
	u := string(pod.ObjectMeta.UID)
	if _, ok := agent.opflexEps[u]; ok {
		agent.log.Infof("podDeletedLocked: delete %s/%s", pod.ObjectMeta.Namespace, pod.ObjectMeta.Name)
		delete(agent.opflexEps, u)
		agent.scheduleSyncEps()
	}
	if pod.Status.PodIP != "" {
		delete(agent.podIpToName, pod.Status.PodIP)
	}
	delete(agent.podUidToName, u)
	agent.epDeleted(&u)
}

func (agent *HostAgent) cniEpDelete(cniKey string) {
	agent.indexMutex.Lock()
	defer agent.indexMutex.Unlock()

	epUuid, ok := agent.cniToPodID[cniKey]
	if !ok {
		agent.log.Warnf("cniEpDelete: PodID not found for %s", cniKey)
		return
	}
	delete(agent.cniToPodID, cniKey)

	if _, ok := agent.opflexEps[epUuid]; ok {
		agent.log.Infof("cniEpDelete: delete %s", cniKey)
		delete(agent.opflexEps, epUuid)
		agent.scheduleSyncEps()
	}
}

func (agent *HostAgent) updateGbpServerInfo(pod *v1.Pod) {
	if pod.ObjectMeta.Labels == nil {
		return
	}
	agent.indexMutex.Lock()
	nameVal := pod.ObjectMeta.Labels["name"]
	if nameVal == "aci-containers-controller" {
		if agent.gbpServerIP != pod.Status.PodIP {
			agent.log.Infof("gbpServerIPChanged to %s", pod.Status.PodIP)
			agent.gbpServerIP = pod.Status.PodIP
			agent.scheduleSyncOpflexServer()
		}
	}
	agent.indexMutex.Unlock()
}
