// Copyright 2023,2024 Cisco Systems, Inc.
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

package main

import (
	"flag"
	"os"
	"sync"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	cnicncfv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	fabattv1 "github.com/noironetworks/aci-containers/pkg/fabricattachment/apis/aci.fabricattachment/v1"
	aciwebhooks "github.com/noironetworks/aci-containers/pkg/webhook"
	aciwebhooktypes "github.com/noironetworks/aci-containers/pkg/webhook/types"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/source"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(cnicncfv1.AddToScheme(scheme))
	utilruntime.Must(fabattv1.AddToScheme(scheme))
	//+kubebuilder:scaffold:scheme
}

func main() {
	var metricsAddr string
	var enableLeaderElection, requireNadAnnotation bool
	var probeAddr string
	var certDir string
	var containerName string
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.StringVar(&certDir, "certs-directory", "/tmp/k8s-webhook-server/serving-certs", "The path where tls crt/key pair is located.")
	flag.BoolVar(&requireNadAnnotation, "require-nad-annotation", false, "Whether NADs need to be annotated to enable insertion of netop-cni in chain")
	flag.StringVar(&containerName, "container-name-for-envvars", "fabric-peer", "name of the container that needs peering environment variables inserted")
	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))
	ws := webhook.NewServer(webhook.Options{
		Port:    8443,
		CertDir: certDir,
	})

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress: metricsAddr},
		WebhookServer:          ws,
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "8a8c25e9.aci.fabricattachment",
		// LeaderElectionReleaseOnCancel defines if the leader should step down voluntarily
		// when the Manager ends. This requires the binary to immediately end when the
		// Manager is stopped, otherwise, this setting is unsafe. Setting this significantly
		// speeds up voluntary leader transitions as the new leader don't have to wait
		// LeaseDuration time first.
		//
		// In the default scaffold provided, the program ends immediately after
		// the manager stops, so would be fine to enable this option. However,
		// if you are doing or is intended to do any operation such as perform cleanups
		// after the manager stops then its usage might be unsafe.
		// LeaderElectionReleaseOnCancel: true,
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	webhookMgr := &aciwebhooktypes.Manager{
		Mgr: mgr,
		Config: aciwebhooktypes.Config{
			RequireNADAnnotation: requireNadAnnotation,
			ContainerName:        containerName,
			RunTimeData: aciwebhooktypes.RunTimeData{
				CommonMutex:    sync.Mutex{},
				FabricAdjs:     make(map[string]map[string]map[int][]int),
				FabricPeerInfo: make(map[int]*aciwebhooktypes.FabricPeeringInfo),
			},
		},
	}

	// Setup a new controller to reconcile NodeFabricL3Peers
	setupLog.Info("Setting up controller")
	c, err := controller.New("nodefabricl3peers-controller", mgr, controller.Options{
		Reconciler: &aciwebhooks.ReconcileNFL3Peers{
			Client: mgr.GetClient(),
			Config: &webhookMgr.Config.RunTimeData,
		}})
	if err != nil {
		setupLog.Error(err, "unable to set up individual controller")
		os.Exit(1)
	}

	// Watch NodeFabricL3Peers and enqueue NodeFabricL3Peers object key
	if err := c.Watch(source.Kind(mgr.GetCache(), &fabattv1.NodeFabricNetworkL3Peer{}), &handler.EnqueueRequestForObject{}); err != nil {
		setupLog.Error(err, "unable to watch NodeFabricNetworkL3Peer")
		os.Exit(1)
	}

	// Register the webhooks in the server.
	aciwebhooks.AddWebHookHandlerToManager(webhookMgr)

	//+kubebuilder:scaffold:builder

	if err := mgr.AddHealthzCheck("/healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("/readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
