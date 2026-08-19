package operator

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"
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

	// The federation path mints ServiceAccount tokens via the TokenRequest
	// subresource, which the controller-runtime cache/client does not serve — so
	// it needs a typed clientset. Without this the SA credential path would hit
	// the reconciler's nil-minter hard error at runtime.
	cs, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return fmt.Errorf("operator: build clientset for token minting: %w", err)
	}

	if err := (&HikyoSecretReconciler{
		Client:          mgr.GetClient(),
		Reader:          mgr.GetAPIReader(), // uncached: Secret/SA reads, post-write verify, stamp root
		Scheme:          mgr.GetScheme(),
		Recorder:        mgr.GetEventRecorderFor("hikyo-operator"),
		Config:          cfg,
		Log:             log,
		NewClientForURL: nil, // nil ⇒ default HTTPS client; tests inject a stub
		TokenMinter:     clientsetMinter{cs: cs},
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

// ManagerOption tweaks NewManager. Production passes none; the seam exists so
// the kind e2e harness can run a real manager without leader election (a single
// in-process manager per test needs no lease, and acquiring one would only add
// startup latency and a lingering Lease object).
type ManagerOption func(*managerOptions)

type managerOptions struct{ leaderElection bool }

// WithLeaderElection overrides the default (on). Only the e2e harness sets it.
func WithLeaderElection(on bool) ManagerOption {
	return func(o *managerOptions) { o.leaderElection = on }
}

// NewManager builds the controller-runtime manager per § 0.7: leader election
// on, health/readyz on :8081, metrics on :8080, informer resync 10h explicit,
// and the cache restricted to the configured namespaces when set.
func NewManager(restCfg *rest.Config, cfg Config, opts ...ManagerOption) (manager.Manager, error) {
	mo := managerOptions{leaderElection: true}
	for _, o := range opts {
		o(&mo)
	}
	sch := runtime.NewScheme()
	utilruntime.Must(scheme.AddToScheme(sch))
	utilruntime.Must(hikyov1.AddToScheme(sch))

	sync := resyncPeriod
	cacheOpts := cache.Options{SyncPeriod: &sync}
	if len(cfg.Namespaces) > 0 {
		// Restrict informers to EXACTLY the bound namespaces — the single-input
		// authority model (ADR § Scoping). The operator's own namespace is
		// deliberately NOT added: the stamp-root Secret (and every other Secret)
		// is read through the uncached APIReader, so the watch set never needs to
		// widen for it. Adding OwnNamespace here would expand every namespaced
		// informer beyond HIKYO_OPERATOR_NAMESPACES.
		cacheOpts.DefaultNamespaces = map[string]cache.Config{}
		for _, ns := range cfg.Namespaces {
			cacheOpts.DefaultNamespaces[ns] = cache.Config{}
		}
	}

	mgr, err := manager.New(restCfg, manager.Options{
		Scheme:                  sch,
		Cache:                   cacheOpts,
		Metrics:                 metricsserver.Options{BindAddress: cfg.MetricsAddr},
		HealthProbeBindAddress:  cfg.HealthAddr,
		LeaderElection:          mo.leaderElection,
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
	// No Owns(&Secret{}): the operator holds no list/watch on Secrets (§ 0.7),
	// so it cannot run a Secret informer. A deleted/tampered managed Secret is
	// caught instead by the cursor-eligibility check on each reconcile (which
	// reads the Secret uncached and recomputes its stamp) plus the 5m periodic
	// requeue — no cached Secret ever exists to leak values or to lag ownership.
	b := ctrl.NewControllerManagedBy(mgr).
		For(&hikyov1.HikyoSecret{}).
		Watches(&hikyov1.HikyoInstance{}, r.instanceHandler())
	if r.Config.TriggerRollouts {
		// Watch opted-in workloads so a Rollout=False/Stalled state is observed
		// from the workload controller's own status (§ 0.3), not only re-derived
		// on the next resync. Mapped via the hikyo.dev/secrets annotation to the
		// HikyoSecrets in that namespace whose target the workload names.
		h := r.workloadHandler()
		b = b.Watches(&appsv1.Deployment{}, h).
			Watches(&appsv1.StatefulSet{}, h).
			Watches(&appsv1.DaemonSet{}, h)
	}
	return b.
		WithOptions(controller.Options{
			MaxConcurrentReconciles: maxConcurrentReconciles,
			RateLimiter:             jitteredExponential(),
			// Off in production (nil ⇒ strict). The e2e sets it so a second
			// in-process manager can register the same controller name.
			SkipNameValidation: skipNameValidation(r.SkipControllerNameValidation),
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

// skipNameValidation maps the reconciler flag to controller-runtime's *bool
// option: nil (strict) unless the e2e explicitly opts out.
func skipNameValidation(skip bool) *bool {
	if !skip {
		return nil
	}
	return &skip
}

// getenvOS is the production env source; tests call LoadConfig with their own.
func getenvOS(k string) string { return os.Getenv(k) }
