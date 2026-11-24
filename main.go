package main

import (
	"os"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"

	"github.com/example/ssh-tunnel-gateway/internal/config"
	"github.com/example/ssh-tunnel-gateway/internal/controller"
	"github.com/example/ssh-tunnel-gateway/internal/tunnel"
)

var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(gatewayv1.Install(scheme))
	utilruntime.Must(gatewayv1alpha2.Install(scheme))
}

func main() {
	ctrl.SetLogger(zap.New(zap.UseDevMode(false)))
	logger := ctrl.Log.WithName("setup")

	cfg := config.LoadFromEnv()
	if err := cfg.Validate(); err != nil {
		logger.Error(err, "invalid configuration")
		os.Exit(1)
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress: cfg.MetricsBindAddr,
		},
		HealthProbeBindAddress: cfg.HealthProbeAddr,
	})
	if err != nil {
		logger.Error(err, "unable to create controller manager")
		os.Exit(1)
	}

	tunnelMgr := tunnel.NewManager(cfg, ctrl.Log.WithName("tunnel"))

	if err := (&controller.GatewayClassReconciler{
		Client:         mgr.GetClient(),
		ControllerName: cfg.ControllerName,
	}).SetupWithManager(mgr); err != nil {
		logger.Error(err, "unable to setup GatewayClass controller")
		os.Exit(1)
	}

	if err := (&controller.GatewayReconciler{
		Client:        mgr.GetClient(),
		Config:        cfg,
		TunnelManager: tunnelMgr,
	}).SetupWithManager(mgr); err != nil {
		logger.Error(err, "unable to setup Gateway controller")
		os.Exit(1)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		logger.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		logger.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	ctx := ctrl.SetupSignalHandler()
	defer tunnelMgr.Shutdown()

	logger.Info("starting ssh-tunnel-gateway controller",
		"controllerName", cfg.ControllerName,
		"defaultProvider", cfg.Provider,
		"defaultTLSTunnelMode", cfg.TLSTunnelMode,
	)
	if err := mgr.Start(ctx); err != nil {
		logger.Error(err, "controller manager exited with error")
		os.Exit(1)
	}
}
