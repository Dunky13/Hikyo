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
	"os"
	"path/filepath"
	"time"

	"github.com/Dunky13/wenv/internal/admission"
	"github.com/Dunky13/wenv/internal/config"
	"github.com/Dunky13/wenv/internal/crypto"
	"github.com/Dunky13/wenv/internal/server"
	"github.com/Dunky13/wenv/internal/service"
	"github.com/Dunky13/wenv/internal/store"
	"github.com/Dunky13/wenv/internal/store/keyring"
	"github.com/Dunky13/wenv/internal/store/migrate"
)

// ClientVerbs are the fixed client-side subcommands (system-architecture
// ADR § Component set); each is a stub until its ticket lands. Exported so
// the classification-totality invariant can enumerate them — a verb missing
// from the wire registry fails the build.
var ClientVerbs = []string{"run", "render", "sync", "adopt", "doctor", "definitions", "import"}

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

// RunMigrate is `wenv migrate`: explicit migration application. Loads no
// keyring (DDL only).
func RunMigrate(ctx context.Context, cfg *config.Config, log *slog.Logger) error {
	sc := storeConfig(cfg)
	log.Info("applying migrations", "engine", sc.Engine)
	if err := migrate.Run(ctx, sc); err != nil {
		return err
	}
	log.Info("migrations current")
	return nil
}

// Server is a booted, listening server that has not started serving yet.
type Server struct {
	Addr    string
	db      *store.DB
	keyring *crypto.Keyring // held for the process lifetime; consumed by later tickets
	ln      net.Listener
	handler http.Handler
	log     *slog.Logger
}

// devRootKeyName sits beside the dev sqlite database (cwd when no sqlite
// path exists). Dev bootstrap only; a production start never generates a
// root key.
const devRootKeyName = "wenv-dev.rootkey"

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
// ephemeral key would brick wenv-dev.db on every restart, and refusing would
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
		envValue = os.Getenv("WENV_ROOT_KEY")
		log.Warn("root key delivered via WENV_ROOT_KEY: the value stays readable in the process environment for the whole lifetime; prefer --root-key-file or a systemd credential")
	}
	return crypto.ReadRootKey(file, envValue)
}

// Boot runs the fail-closed startup sequence: process hardening before any
// key material exists, migrations (auto-apply by default; with auto-apply
// disabled a pending migration state refuses to serve), datastore open with
// the boot-enforced pragma policy, keyring load (root key read, master key
// unwrapped or minted, root key zeroed — `wenv server` is the only mode that
// does this), then the listener. Any error means the process must exit
// without serving.
func Boot(ctx context.Context, cfg *config.Config, log *slog.Logger) (*Server, error) {
	if err := crypto.HardenProcess(); err != nil {
		return nil, fmt.Errorf("boot: refusing to serve: %w", err)
	}
	sc := storeConfig(cfg)

	if cfg.AutoMigrate {
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
	authSvc := &service.Auth{DB: db, Keyring: kr, KDF: kdf, Admission: limiter}

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

	api := &server.API{
		Auth:           authSvc,
		Orgs:           &service.Orgs{DB: db},
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
		handler: server.New(&service.System{DB: db, Store: sc}, api),
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
