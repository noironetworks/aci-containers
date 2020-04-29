// Copyright 2020 Cisco Systems, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package hostagent

import (
	"fmt"
	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/tools/reference"
	"strings"
	"time"
)

type EventPoster struct {
	recorder           record.EventRecorder
	eventSubmitTimeMap map[string]time.Time // (srcIP+dstIP) as key, posted time as value
}

// Init Poster and return its pointer
func (agent *HostAgent) initEventPoster(kubeClient *kubernetes.Clientset) {
	recorder := agent.initEventRecorder(kubeClient)
	agent.poster = &EventPoster{
		recorder:           recorder,
		eventSubmitTimeMap: make(map[string]time.Time),
	}
}

// Init Event Recorder for poster object
func (agent *HostAgent) initEventRecorder(kubeClient *kubernetes.Clientset) record.EventRecorder {
	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartRecordingToSink(
		&typedcorev1.EventSinkImpl{Interface: kubeClient.CoreV1().Events("")})
	component := "aci-containers-host"
	recorder := eventBroadcaster.NewRecorder(scheme.Scheme, v1.EventSource{Component: component})
	return recorder
}

func (agent *HostAgent) translateDropReason(reason string) string {
	switch {
	case reason == "":
		return "Unspecified"
	case strings.Contains(reason, "POL_TABLE"):
		return reason + "(Policy Drop)"
	case (strings.Contains(reason, "PORT_SECURITY_TABLE") || strings.Contains(reason, "SEC_GROUP_IN_TABLE") || strings.Contains(reason, "SEC_GROUP_OUT_TABLE")):
		return reason + "(Security Drop)"
	}
	return reason + "(Networking Drop)"
}

// Submit an event using kube API with message attached
func (agent *HostAgent) submitEvent(pod *v1.Pod, message string, dropReason string) error {
	agent.log.Debug("Posting event ", message)
	ref, err := reference.GetReference(scheme.Scheme, pod)
	if err != nil {
		agent.log.Error("Returning ", err)
		return err
	}
	dropReason = agent.translateDropReason(dropReason)
	if agent.poster != nil && agent.poster.recorder != nil {
		agent.poster.recorder.Event(ref, v1.EventTypeWarning, dropReason, message)
	}
	return nil
}

// Check if given PacketEvent should be ignored
func (agent *HostAgent) shouldIgnore(packetEvent PacketEvent, currTime time.Time) bool {
	// ignore if the given packetDrop is out of date
	logTime, err := time.Parse(time.UnixDate, packetEvent.TimeStamp)
	if (err != nil) || (currTime.Sub(logTime).Minutes() > float64(agent.config.DropLogExpiryTime)) {
		agent.log.Trace("Ignoring expired event")
		return true
	}
	// ignore if the event has been posted within the defined time period
	key := packetEvent.SourceIP + packetEvent.DestinationIP
	lastPostedTime := agent.poster.eventSubmitTimeMap[key]
	repeatEventIntervalMinutes := float64(agent.config.DropLogRepeatIntervalTime)
	if !lastPostedTime.IsZero() && (logTime.Sub(lastPostedTime).Minutes() <= repeatEventIntervalMinutes) {
		agent.log.Trace("Ignoring event as it occurred within repeatInterval")
		return true
	}
	return false
}

// Construct packet drop message
func getPacketDropMessage(etherType string, srcIp string, dstIp string) string {
	return fmt.Sprintf("%s packet from %s to %s was dropped", etherType, srcIp, dstIp)
}

// Handle the given PacketDrop, return error if api server does not work
func (agent *HostAgent) processPacketEvent(packetEvent PacketEvent, currTime time.Time) error {
	if packetEvent.SourceIP == "" || packetEvent.DestinationIP == "" {
		return nil
	}
	if agent.shouldIgnore(packetEvent, currTime) {
		return nil
	}
	var srcEventPosted bool = false
	agent.indexMutex.Lock()
	srcPodKey, srcOk := agent.podIpToName[packetEvent.SourceIP]
	agent.indexMutex.Unlock()
	if !srcOk {
		agent.log.Trace("srcPodKey for ", packetEvent.SourceIP, ": ", srcPodKey,
				", may not be a pod or not a local pod")
	} else {
		obj1, srcExists, err := agent.podInformer.GetStore().GetByKey(srcPodKey)
		if err == nil {
			if srcExists && (obj1 != nil) {
				srcPod := obj1.(*v1.Pod)
				// post events
				if srcPod != nil && (srcPod.Status.Phase == "Running") &&
					!srcPod.Spec.HostNetwork {
					if err := agent.submitEvent(srcPod,
						getPacketDropMessage(
							packetEvent.EtherType,
							packetEvent.SourceIP,
							packetEvent.DestinationIP),
						packetEvent.DropReason); err != nil {
						return err
					}
					srcEventPosted = true
				}
			}
		} else {
			srcExists = false
		}
		srcOk = srcExists
	}
	agent.indexMutex.Lock()
	dstPodKey, dstOk := agent.podIpToName[packetEvent.DestinationIP]
	agent.indexMutex.Unlock()
	if !dstOk {
		agent.log.Trace("dstPodKey for ", packetEvent.DestinationIP, ": ", dstPodKey,
				", may not be a pod or not a local pod")
	} else {
		obj2, dstExists, err := agent.podInformer.GetStore().GetByKey(dstPodKey)
		if err == nil {
			//Avoid posting to both src and dst pods, if src has already been posted
			if dstExists && (obj2 != nil) && !srcEventPosted {
				dstPod := obj2.(*v1.Pod)
				if dstPod != nil && (dstPod.Status.Phase == "Running") &&
					!dstPod.Spec.HostNetwork {
					if err := agent.submitEvent(dstPod,
						getPacketDropMessage(
							packetEvent.EtherType,
							packetEvent.SourceIP,
							packetEvent.DestinationIP),
						packetEvent.DropReason); err != nil {
						return err
					}
				}
			}
		} else {
			dstExists = false
		}
		dstOk = dstExists
	}

	if !srcOk && !dstOk {
		return nil
	}

	// update poster's eventSubmitTimeMap
	agent.poster.eventSubmitTimeMap[packetEvent.SourceIP+packetEvent.DestinationIP] = currTime
	return nil
}
