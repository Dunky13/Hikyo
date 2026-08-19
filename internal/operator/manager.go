package operator

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	hikyov1 "github.com/Hikyo-Org/hikyo/internal/operator/api/v1alpha1"
)

// resyncPeriod is the informer full resync, set EXPLICITLY to 10h (ops-spec §
// 7) rather than inherited — missed-event insurance, not a delivery mechanism.
// controller-runtime applies ±10% jitter to it.
const resyncPeriod = 10 * time.Hour

const (
	backoffBase = 1 * time.Second
	backoffMax  = 5 * time.Minute
	// maxConcurrentReconciles > 1 is safe: controller-runtime serializes per
	// object key and HikyoSecrets are distinct keys (§ 0.5).
	maxConcurrentReconciles = 4
	leaderElectionID        = "hikyo-operator.hikyo.dev"
)

// Run boots the operator: loads config, builds the manager, registers the
// HikyoSecret controller, and blocks until the context is cancelled. It is the
// entrypoint cmd/hikyo wires the `operator` mode to.
func Run(ctx context.Context, log *slog.Logger) error {
	cfg, err := LoadConfig(getenvOS)
	if err != nil {
		return fmt.Errorf("operator config: %w", err)
	}

	restCfg, err := ctrl.GetConfig()
	if err != nil {
		return fmt.Errorf("operator: load kubeconfig: %w", err)
	}

	mgr, err := NewManager(restCfg, cfg)
	if err != nil {
		return err
	}

	if err := (&HikyoSecretReconciler{
		Client:          mgr.GetClient(),
		Scheme:          mgr.GetScheme(),
		Recorder:        mgr.GetEventRecorderFor("hikyo-operator"),
		Config:          cfg,
		Log:             log,
		NewClientForURL: nil, // nil ⇒ default HTTPS client; tests inject a stub
	}).SetupWithManager(mgr); err != nil {
		return err
	}

	log.Info("hikyo operator starting",
		"namespaces", cfg.Namespaces, "triggerRollouts", cfg.TriggerRollouts,
		"ownNamespace", cfg.OwnNamespace, "version", Version)
	if err := mgr.Start(ctx); err != nil {
		return fmt.Errorf("operator: manager exited: %w", err)
	}
	return nil
}

// NewManager builds the controller-runtime manager per § 0.7: leader election
// on, health/readyz on :8081, metrics on :8080, informer resync 10h explicit,
// and the cache restricted to the configured namespaces when set.
func NewManager(restCfg *rest.Config, cfg Config) (manager.Manager, error) {
	sch := runtime.NewScheme()
	utilruntime.Must(scheme.AddToScheme(sch))
	utilruntime.Must(hikyov1.AddToScheme(sch))

	sync := resyncPeriod
	cacheOpts := cache.Options{SyncPeriod: &sync}
	if len(cfg.Namespaces) > 0 {
		// Restrict informers to the bound namespaces. Effective reach is still
		// the intersection with RBAC (ADR § Scoping) — this only stops the
		// operator watching namespaces it was never given.
		cacheOpts.DefaultNamespaces = map[string]cache.Config{}
		for _, ns := range cfg.Namespaces {
			cacheOpts.DefaultNamespaces[ns] = cache.Config{}
		}
		// The stamp-root Secret lives in the operator's own namespace, which may
		// be outside the watch set; include it so the cache can serve it.
		if _, ok := cacheOpts.DefaultNamespaces[cfg.OwnNamespace]; !ok {
			cacheOpts.DefaultNamespaces[cfg.OwnNamespace] = cache.Config{}
		}
	}

	mgr, err := manager.New(restCfg, manager.Options{
		Scheme:                  sch,
		Cache:                   cacheOpts,
		Metrics:                 metricsserver.Options{BindAddress: cfg.MetricsAddr},
		HealthProbeBindAddress:  cfg.HealthAddr,
		LeaderElection:          true,
		LeaderElectionID:        leaderElectionID,
		LeaderElectionNamespace: cfg.OwnNamespace,
	})
	if err != nil {
		return nil, fmt.Errorf("operator: build manager: %w", err)
	}
	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return nil, fmt.Errorf("operator: add healthz: %w", err)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return nil, fmt.Errorf("operator: add readyz: %w", err)
	}
	return mgr, nil
}

// SetupWithManager registers the reconciler and its watches. The managed Secret
// and the referenced workloads are Owns/Watches sources where cheap; the
// periodic resync is the floor that catches everything else (§ 0.4 refresh).
func (r *HikyoSecretReconciler) SetupWithManager(mgr manager.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&hikyov1.HikyoSecret{}).
		Owns(&corev1.Secret{}). // requeue the CR when its managed Secret changes
		Watches(&hikyov1.HikyoInstance{}, r.instanceHandler()).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: maxConcurrentReconciles,
			RateLimiter:             jitteredExponential(),
		}).
		Complete(r)
}

// jitteredExponential is the § 0.4 error backoff: exponential 1s → 5min,
// jittered. controller-runtime's per-item exponential limiter provides the
// 1s→5min curve; the jitter wrapper spreads retries so a fleet of CRs failing
// against one unreachable server does not thunder.
func jitteredExponential() workqueue.TypedRateLimiter[reconcile.Request] {
	return &jitterLimiter{
		inner: workqueue.NewTypedItemExponentialFailureRateLimiter[reconcile.Request](backoffBase, backoffMax),
	}
}

// getenvOS is the production env source; tests call LoadConfig with their own.
func getenvOS(k string) string { return os.Getenv(k) }
