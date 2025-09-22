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

package controller

import (
	nadapi "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/record"
)

var (
	scheme = runtime.NewScheme()
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(nadapi.AddToScheme(scheme))
	// +kubebuilder:scaffold:scheme
}

type EventPoster struct {
	recorder record.EventRecorder
}

// Init Poster and return its pointer
func (cont *AciController) initEventPoster(kubeClient *kubernetes.Clientset) {
	recorder := cont.initEventRecorder(kubeClient)
	cont.poster = &EventPoster{
		recorder: recorder,
	}
}

// Init Event Recorder for poster object
func (cont *AciController) initEventRecorder(kubeClient *kubernetes.Clientset) record.EventRecorder {
	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartRecordingToSink(
		&typedcorev1.EventSinkImpl{Interface: kubeClient.CoreV1().Events("")})
	component := "aci-containers-controller"
	recorder := eventBroadcaster.NewRecorder(scheme, v1.EventSource{Component: component})
	return recorder
}

// Submit an event using kube API with message attached
func (cont *AciController) submitEvent(nad *nadapi.NetworkAttachmentDefinition, reason, message string) error {
	cont.log.Debug("Posting event ", message)

	if cont.poster != nil && cont.poster.recorder != nil {
		cont.poster.recorder.Event(nad, v1.EventTypeWarning, reason, message)
	}
	return nil
}
