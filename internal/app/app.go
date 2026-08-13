// Package app wires config, store, migrations, service, and the HTTP layer
// into the runnable subcommands.
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/Dunky13/hikyo/internal/admission"
	"github.com/Dunky13/hikyo/internal/config"
	"github.com/Dunky13/hikyo/internal/crypto"
	"github.com/Dunky13/hikyo/internal/oidcfed"
	"github.com/Dunky13/hikyo/internal/remotefetch"
	"github.com/Dunky13/hikyo/internal/server"
	"github.com/Dunky13/hikyo/internal/service"
	"github.com/Dunky13/hikyo/internal/store"
	"github.com/Dunky13/hikyo/internal/store/keyring"
	"github.com/Dunky13/hikyo/internal/store/migrate"
	"github.com/Dunky13/hikyo/internal/webui"
)

// ClientVerbs are the fixed not-yet-implemented client-side subcommands from
// the system-architecture component set. Implemented verbs move to cli.Verbs;
// both lists are enumerated by the classification-totality invariant.
var ClientVerbs = []string{"run", "render", "sync", "adopt", "definitions", "import"}

// Version is the build's version string, set from main's linker-stamped
// value. It is what /api/v1/meta advertises, so a client that refuses an
// operation above the server's API revision can name the version it refused.
var Version = "dev"

// Logger builds the process logger: text in dev, JSON in production.
func Logger(dev bool) *slog.Logger {
	if dev {
		return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	return slog.New(slog.NewJSONHandler(os.Stderr, nil))
}

func storeConfig(cfg *config.Config) store.Config {
	return store.Config{
		Engine: store.Engine(cfg.Store.Engine),
		Path:   cfg.Store.Path,
		DSN:    cfg.Store.DSN,
	}
}

// RunMigrate is `hikyo migrate`: explicit migration application. Loads no
// keyring (DDL only).
func RunMigrate(ctx context.Context, cfg *config.Config, log *slog.Logger) error {
	sc := storeConfig(cfg)
	log.Info("applying migrations", "engine", sc.Engine)
	rec, err := beforeMigration(ctx, cfg, log, sc)
	if err != nil {
		return err
	}
	if err := migrate.Run(ctx, sc); err != nil {
		return err
	}
	recordPreMigration(ctx, cfg, log, rec)
	log.Info("migrations current")
	return nil
}

// beforeMigration runs the automatic pre-migration export, but only when this
// binary actually has a migration to apply: an export per ordinary restart is
// a backup policy nobody asked for.
func beforeMigration(ctx context.Context, cfg *config.Config, log *slog.Logger, sc store.Config) (preMigrationRecord, error) {
	pending, err := migrate.HasPending(ctx, sc)
	if err != nil {
		// Fail TOWARD the backup: a check that errors while the migration
		// then succeeds would silently skip the one export standing between
		// a bad migration and a rebuilt instance. Attempting the export costs
		// at worst one unneeded artifact; if the store is truly down, the
		// export preflight and the migration both say so.
		log.Warn("pre-migration pending check failed; attempting the export anyway", "err", err)
		return preMigrationExport(ctx, cfg, log)
	}
	if !pending {
		return preMigrationRecord{}, nil
	}
	return preMigrationExport(ctx, cfg, log)
}

// Server is a booted, listening server that has not started serving yet.
type Server struct {
	Addr    string
	db      *store.DB
	keyring *crypto.Keyring // held for the process lifetime
	ln      net.Listener
	handler http.Handler
	log     *slog.Logger
}

// devRootKeyName sits beside the dev sqlite database (cwd when no sqlite
// path exists). Dev bootstrap only; a production start never generates a
// root key.
const devRootKeyName = "hikyo-dev.rootkey"

func devRootKeyPath(cfg *config.Config) string {
	if cfg.Store.Engine == config.EngineSQLite && cfg.Store.Path != "" {
		return filepath.Join(filepath.Dir(cfg.Store.Path), devRootKeyName)
	}
	return devRootKeyName
}

// resolveRootKey reads the operator root key, or — in --dev with no source
// configured — generates and persists a development root key beside the dev
// database.
//
// The dev generation is a recorded deviation from the encryption ADR's
// refusal 1 ("the server never auto-generates a root key on first run"),
// forced by the architecture ADR's zero-config `--dev` evaluation mode: an
// ephemeral key would brick hikyo-dev.db on every restart, and refusing would
// make --dev not zero-config. The rationale behind refusal 1 (a silent key
// nobody backed up, discovered at restore) does not bite an evaluation
// database sitting next to its own key file, and the generation is loud.
func resolveRootKey(cfg *config.Config, log *slog.Logger) ([]byte, error) {
	file := cfg.RootKeyFile
	if file == "" && !cfg.RootKeyFromEnv && cfg.Dev {
		devPath := devRootKeyPath(cfg)
		if _, err := os.Stat(devPath); errors.Is(err, os.ErrNotExist) {
			key, err := crypto.GenerateRootKey()
			if err != nil {
				return nil, err
			}
			defer crypto.Zero(key)
			if err := os.WriteFile(devPath, []byte(crypto.EncodeRootKey(key)+"\n"), 0o600); err != nil {
				return nil, fmt.Errorf("write dev root key: %w", err)
			}
			log.Warn("generated development root key — evaluation only, back it up with the dev database or lose the data",
				"path", devPath)
		} else if err != nil {
			return nil, fmt.Errorf("dev root key: %w", err)
		} else {
			log.Warn("using development root key", "path", devPath)
		}
		file = devPath
	}
	var envValue string
	if cfg.RootKeyFromEnv {
		envValue = os.Getenv("HIKYO_ROOT_KEY")
		log.Warn("root key delivered via HIKYO_ROOT_KEY: the value stays readable in the process environment for the whole lifetime; prefer --root-key-file or a systemd credential")
	}
	return crypto.ReadRootKey(file, envValue)
}

// Boot runs the fail-closed startup sequence: process hardening before any
// key material exists, migrations (auto-apply by default; with auto-apply
// disabled a pending migration state refuses to serve), datastore open with
// the boot-enforced pragma policy, keyring load (root key read, master key
// unwrapped or minted, root key zeroed — `hikyo server` is the only mode that
// does this), then the listener. Any error means the process must exit
// without serving.
func Boot(ctx context.Context, cfg *config.Config, log *slog.Logger) (*Server, error) {
	if err := crypto.HardenProcess(); err != nil {
		return nil, fmt.Errorf("boot: refusing to serve: %w", err)
	}
	sc := storeConfig(cfg)

	var migrationRecord preMigrationRecord
	if cfg.AutoMigrate {
		var err error
		if migrationRecord, err = beforeMigration(ctx, cfg, log, sc); err != nil {
			return nil, fmt.Errorf("boot: refusing to serve: %w", err)
		}
		if err := migrate.Run(ctx, sc); err != nil {
			return nil, fmt.Errorf("boot: refusing to serve: %w", err)
		}
	}
	// Always verify exact schema match — with auto-migrate off this catches
	// pending migrations; in both modes it catches a database migrated by a
	// newer binary (Run applies nothing there and the schema stays ahead).
	if err := migrate.Check(ctx, sc); err != nil {
		return nil, fmt.Errorf("boot: refusing to serve: %w", err)
	}
	recordPreMigration(ctx, cfg, log, migrationRecord)

	root, err := resolveRootKey(cfg, log)
	if err != nil {
		return nil, fmt.Errorf("boot: refusing to serve: %w", err)
	}

	db, err := store.Open(ctx, sc)
	if err != nil {
		crypto.Zero(root)
		return nil, fmt.Errorf("boot: refusing to serve: %w", err)
	}

	// LoadKeyring consumes root: it is zeroed before this returns.
	kr, err := crypto.LoadKeyring(ctx, &keyring.Store{DB: db}, root)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("boot: refusing to serve: %w", err)
	}

	kdf, limiter, err := AuthComponents(cfg)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("boot: refusing to serve: %w", err)
	}
	authSvc := &service.Auth{DB: db, Keyring: kr, KDF: kdf, Admission: limiter, Log: log, ExternalOrigin: cfg.ExternalOrigin}
	samlProviders := &service.SAMLProviders{DB: db, Keyring: kr, ExternalOrigin: cfg.ExternalOrigin}
	// RP ID + expected origins are immutable instance config derived from the
	// configured external origin, never a request header (WebAuthn ADR §5). An
	// origin that cannot yield a valid relying party is a boot refusal, not a
	// first-ceremony surprise.
	if err := authSvc.ConfigureWebAuthnRP(); err != nil {
		db.Close()
		return nil, fmt.Errorf("boot: refusing to serve: webauthn relying party: %w", err)
	}

	proxies, err := parseCIDRs(cfg.TrustedProxyCIDRs)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("boot: refusing to serve: %w", err)
	}

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("boot: listen %s: %w", cfg.Listen, err)
	}

	federation := &service.Federation{
		DB: db, Auth: authSvc, Admission: limiter,
		Cache: &oidcfed.Cache{Limiter: limiter},
	}
	scimSvc := &service.SCIM{DB: db, Auth: authSvc}
	fetchCfg := remotefetch.DefaultConfig()
	if cfg.DirectoryProxy != "" {
		// Explicit configuration is the ONLY way egress traverses a forward
		// proxy. config.Load has already refused a non-https or hostless value,
		// so a parse failure here would be an internal inconsistency rather
		// than operator input — it still fails the boot loudly rather than
		// silently reverting to direct egress, because "the proxy I configured
		// is being bypassed" is exactly the surprise this control exists to
		// prevent.
		proxy, err := url.Parse(cfg.DirectoryProxy)
		if err != nil {
			return nil, fmt.Errorf("boot: directory proxy: %w", err)
		}
		fetchCfg.Proxy = proxy
	}
	fetcher, err := remotefetch.New(fetchCfg)
	if err != nil {
		return nil, fmt.Errorf("boot: outbound directory client: %w", err)
	}

	api := &server.API{
		Auth:     authSvc,
		SAMLAuth: authSvc,
		Orgs:     &service.Orgs{DB: db},
		Projects: &service.Projects{DB: db},
		// The keyring reaches the value surface (#50): clone-at-creation and
		// every value write re-seal under the project data key, in the
		// transaction that writes the row.
		Environments: &service.Environments{DB: db, Keyring: kr, Auth: authSvc},
		Folders:      &service.Folders{DB: db},
		Keys:         &service.Keys{DB: db},
		// The reveal ceremony (#58): the value surface's disclosure routes
		// consume the SAME reauthentication window machinery the passkey and
		// TOTP reauth endpoints open, so both sides take the one Auth. A
		// Values without it refuses every disclosure rather than disclosing
		// without a ceremony.
		Values:    &service.Values{DB: db, Keyring: kr, Auth: authSvc},
		Reveal:    &service.Reveal{DB: db, Auth: authSvc},
		KeyGroups: &service.KeyGroups{DB: db},
		// One Auth across the grant surface, the settings knob and the machine
		// identity surface: the reauthentication conjunct a machine widening
		// carries is the SAME window machinery human disclosure consumes, so
		// they cannot come from two configurations.
		Grants:     &service.Grants{DB: db, Auth: authSvc},
		Identities: &service.Identities{DB: db, Auth: authSvc},
		// One Federation across the issuer surface and the delivery surface, and
		// one JWKS cache inside it: the cache's staleness bound is an instance
		// property, so two caches would mean two answers to "are this issuer's
		// keys fresh". Its unknown-`kid` refresh rides the SAME admission limiter
		// every other pre-authentication path rides, which is what the ADR means
		// by putting the trigger under the instance-wide budget.
		Federation: federation,
		Delivery: &service.Delivery{
			DB: db, Keyring: kr, Federation: federation,
		},
		// The settings knob calls LowerEffectiveWindow, which is the Auth
		// service's library — one Auth, so the window the knob writes and the
		// window the reveal guard reads cannot come from two configurations.
		Settings:      &service.ProjectSettings{DB: db, Auth: authSvc},
		Providers:     &service.Providers{DB: db, Keyring: kr, ExternalOrigin: cfg.ExternalOrigin, Log: log},
		SAMLProviders: samlProviders,
		// ONE SCIM service behind both surfaces: the administration verbs and
		// the identity provider's wire read the same bindings, the same mapping
		// table and the same bounds. Two instances would let the wire clamp a
		// page against a different number than the one the discovery document
		// advertises.
		SCIM:     scimSvc,
		SCIMWire: scimSvc,
		// Multi-instance (#71). The outbound client is built from the
		// owner-ratified bounds table (2026-08-13) and is the ONLY door to a
		// foreign instance: with zero configured remotes it originates zero
		// connections, which is what leaves the air-gap posture unchanged.
		Remotes:        &service.Remotes{DB: db, Keyring: kr, Fetch: fetcher},
		Workspace:      &service.Workspace{DB: db, Version: Version, Reauth: authSvc},
		Admission:      limiter,
		Version:        Version,
		Log:            log,
		TrustedProxies: proxies,
	}

	log.Info("boot complete", "engine", sc.Engine, "addr", ln.Addr().String(), "dev", cfg.Dev,
		"argon2_memory_kib", cfg.Argon2MemoryKiB, "auth_concurrency", limiter.Concurrency())
	return &Server{
		Addr:    ln.Addr().String(),
		db:      db,
		keyring: kr,
		ln:      ln,
		handler: server.New(&service.System{DB: db, Store: sc}, api, webui.Assets()),
		log:     log,
	}, nil
}

// AuthComponents resolves the two authentication settings and, in doing so,
// runs two boot invariants that must fail fast rather than surface at the
// first login:
//
//   - the Argon2id parameters are checked against the floor the human-auth
//     ADR fixes, and the server refuses to start below it;
//   - the admission budget must hold at least one verification plus the
//     global headroom, so a configuration where one login cannot fit is a
//     config error caught here, never a runtime surprise.
//
// It deliberately does not build the service: the service holds the keyring,
// and the redaction analyzer bans key-bearing types from reaching a log call
// — so the caller assembles it and logs from these values instead.
func AuthComponents(cfg *config.Config) (crypto.PasswordParams, *admission.Limiter, error) {
	kdf := crypto.PasswordParams{
		MemoryKiB:   cfg.Argon2MemoryKiB,
		Time:        cfg.Argon2Time,
		Parallelism: cfg.Argon2Parallelism,
	}
	if err := kdf.CheckFloor(); err != nil {
		return crypto.PasswordParams{}, nil, err
	}
	limiter, err := admission.New(admission.Config{
		BudgetMiB:      cfg.AdmissionBudgetMiB,
		ArgonMemoryKiB: kdf.MemoryKiB,
		PerIPPerMinute: cfg.DevAdmissionPerIPPerMinute,
	})
	if err != nil {
		return crypto.PasswordParams{}, nil, err
	}
	return kdf, limiter, nil
}

func parseCIDRs(raw []string) ([]*net.IPNet, error) {
	out := make([]*net.IPNet, 0, len(raw))
	for _, s := range raw {
		_, network, err := net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("trusted proxy CIDR %q: %w", s, err)
		}
		out = append(out, network)
	}
	return out, nil
}

// newHTTPServer applies the baseline slow-client hardening: bounded header
// read, request read, idle keep-alive, and header size. WriteTimeout stays
// deliberately unset — long-lived streamed responses (SSE) arrive later.
// Tuned values belong to the ops spec.
func newHTTPServer(h http.Handler) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    1 << 20,
	}
}

// Serve blocks until ctx is cancelled, then shuts down gracefully.
func (s *Server) Serve(ctx context.Context) error {
	defer s.db.Close()
	srv := newHTTPServer(s.handler)
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(s.ln) }()
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

// Close releases resources for a booted server that never served.
func (s *Server) Close() error {
	err := s.ln.Close()
	return errors.Join(err, s.db.Close())
}
