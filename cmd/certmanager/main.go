package main

import (
	"flag"
	"fmt"
	"os"
	"time"
	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	cnicncfv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	"github.com/qinqon/kube-admission-webhook/pkg/certificate"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(cnicncfv1.AddToScheme(scheme))
	//+kubebuilder:scaffold:scheme
}

func lookupEnvAsDuration(varName string) (time.Duration, error) {
	duration := time.Duration(0)
	varValue, ok := os.LookupEnv(varName)
	if !ok {
		return duration, fmt.Errorf("Failed to load %s from environment", varName)
	}

	duration, err := time.ParseDuration(varValue)
	if err != nil {
		return duration, fmt.Errorf("Failed to convert %s value to time.Duration: %v", varName, err)
	}
	return duration, nil
}

func retrieveCertAndCAIntervals() (certificate.Options, error) {
	certManagerOpts := certificate.Options{
		Namespace:   os.Getenv("POD_NAMESPACE"),
		WebhookName: "aci-containers-webhook",
		WebhookType: certificate.MutatingWebhook,
	}

	var err error
	certManagerOpts.CARotateInterval, err = lookupEnvAsDuration("CA_ROTATE_INTERVAL")
	if err != nil {
		setupLog.Error(err, "Failed retrieving ca rotate interval")
		return certificate.Options{}, err
	}

	certManagerOpts.CAOverlapInterval, err = lookupEnvAsDuration("CA_OVERLAP_INTERVAL")
	if err != nil {
		setupLog.Error(err, "Failed retrieving ca overlap interval")
		return certificate.Options{}, err
	}

	certManagerOpts.CertRotateInterval, err = lookupEnvAsDuration("CERT_ROTATE_INTERVAL")
	if err != nil {
		setupLog.Error(err, "Failed retrieving cert rotate interval")
		return certificate.Options{}, err
	}

	certManagerOpts.CertOverlapInterval, err = lookupEnvAsDuration("CERT_OVERLAP_INTERVAL")
	if err != nil {
		setupLog.Error(err, "Failed retrieving cert overlap interval")
		return certificate.Options{}, err
	}

	return certManagerOpts, nil
}

func setupCertManager(mgr manager.Manager, certManagerOpts certificate.Options) error {
	certManager, err := certificate.NewManager(mgr.GetClient(), &certManagerOpts)
	if err != nil {
		setupLog.Error(err, "unable to create cert-manager", "controller", "cert-manager")
		return err
	}
	err = certManager.Add(mgr)
	if err != nil {
		setupLog.Error(err, "unable to add cert-manager to controller-runtime manager", "controller", "cert-manager")
		return err
	}
	return nil
}

func main() {
	var metricsAddr string
	var enableLeaderElection bool
	var probeAddr string
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		MetricsBindAddress:     metricsAddr,
		Port:                   9443,
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "8a8c25e9.aci.certmanager",
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

	var certManagerOpts certificate.Options
	if certManagerOpts, err = retrieveCertAndCAIntervals(); err != nil {
		os.Exit(1)
	}
	if err = setupCertManager(mgr, certManagerOpts); err != nil {
		os.Exit(1)
	}

	//+kubebuilder:scaffold:builder

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
