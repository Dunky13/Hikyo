// Package config parses flags and environment strictly and fail-fast
// (system-architecture ADR § Tooling defaults): unknown WENV_* keys warn,
// missing prod-critical keys refuse to start, nothing silently conjures a
// database.
package config

import (
	"flag"
	"fmt"
	"net"
	"net/url"
	"strings"
)

type Engine string

const (
	EngineSQLite   Engine = "sqlite"
	EnginePostgres Engine = "postgres"
)

// Datastore is the parsed, validated datastore selection.
type Datastore struct {
	Engine Engine
	Path   string // sqlite file path
	DSN    string // postgres DSN
}

type Config struct {
	Dev         bool
	Listen      string
	AutoMigrate bool
	Store       Datastore
}

// knownEnv is the closed set of WENV_* keys this build understands.
var knownEnv = map[string]bool{
	"WENV_DB":     true,
	"WENV_LISTEN": true,
}

const devSQLitePath = "wenv-dev.db"

// Load parses configuration for a subcommand. getenv supplies single keys;
// environ (os.Environ() shape) is scanned for unknown WENV_* keys and may be
// nil. Returned warnings are for the caller to log — Load itself never logs.
func Load(subcommand string, args []string, getenv func(string) string, environ []string) (*Config, []string, error) {
	fs := flag.NewFlagSet(subcommand, flag.ContinueOnError)
	dev := fs.Bool("dev", false, "development mode: zero-config sqlite, text logs")
	listen := fs.String("listen", "", "listen address (default 127.0.0.1:8080, env WENV_LISTEN)")
	autoMigrate := fs.Bool("auto-migrate", true, "apply pending migrations at boot")
	if err := fs.Parse(args); err != nil {
		return nil, nil, err
	}

	var warnings []string
	for _, kv := range environ {
		k, _, ok := strings.Cut(kv, "=")
		if ok && strings.HasPrefix(k, "WENV_") && !knownEnv[k] {
			warnings = append(warnings, fmt.Sprintf("unknown environment key %s ignored", k))
		}
	}

	cfg := &Config{
		Dev:         *dev,
		AutoMigrate: *autoMigrate,
		Listen:      *listen,
	}
	if cfg.Listen == "" {
		cfg.Listen = getenv("WENV_LISTEN")
	}
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:8080"
	}

	dbURL := getenv("WENV_DB")
	switch {
	case dbURL != "":
		ds, err := parseDatastore(dbURL)
		if err != nil {
			return nil, nil, err
		}
		cfg.Store = ds
	case cfg.Dev:
		cfg.Store = Datastore{Engine: EngineSQLite, Path: devSQLitePath}
	default:
		return nil, nil, fmt.Errorf("no datastore configured: set WENV_DB (sqlite:PATH or postgres://...) or pass --dev for zero-config sqlite evaluation")
	}
	return cfg, warnings, nil
}

func parseDatastore(raw string) (Datastore, error) {
	switch {
	case strings.HasPrefix(raw, "sqlite:"):
		path := strings.TrimPrefix(raw, "sqlite:")
		if path == "" {
			return Datastore{}, fmt.Errorf("WENV_DB sqlite: requires a file path")
		}
		return Datastore{Engine: EngineSQLite, Path: path}, nil
	case strings.HasPrefix(raw, "postgres://"), strings.HasPrefix(raw, "postgresql://"):
		if err := validatePostgresTLS(raw); err != nil {
			return Datastore{}, err
		}
		return Datastore{Engine: EnginePostgres, DSN: raw}, nil
	default:
		return Datastore{}, fmt.Errorf("WENV_DB %q: unsupported datastore (want sqlite:PATH or postgres://...)", raw)
	}
}

// validatePostgresTLS enforces the threat-model boundary restated in the
// system-architecture ADR: remote postgres requires TLS with certificate
// verification or a same-host socket; no plaintext to a non-loopback host.
func validatePostgresTLS(dsn string) error {
	u, err := url.Parse(dsn)
	if err != nil {
		return fmt.Errorf("WENV_DB: %w", err)
	}
	host := u.Hostname()
	if host == "" || host == "localhost" || strings.HasPrefix(host, "/") {
		return nil // unix socket or local resolution
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	switch u.Query().Get("sslmode") {
	case "verify-full", "verify-ca":
		return nil
	}
	return fmt.Errorf("WENV_DB: remote postgres host %q requires sslmode=verify-full or verify-ca (no plaintext on a non-loopback boundary)", host)
}
