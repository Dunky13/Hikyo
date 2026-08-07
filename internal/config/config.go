// Package config parses flags and environment strictly and fail-fast
// (system-architecture ADR § Tooling defaults): unknown WENV_* keys warn,
// missing prod-critical keys refuse to start, nothing silently conjures a
// database.
package config

import (
	"errors"
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
	Dev               bool
	Listen            string
	TrustedProxyCIDRs []string
	AutoMigrate       bool
	Store             Datastore
}

// knownEnv is the closed set of WENV_* keys this build understands.
var knownEnv = map[string]bool{
	"WENV_DB":                  true,
	"WENV_LISTEN":              true,
	"WENV_TRUSTED_PROXY_CIDRS": true,
}

const devSQLitePath = "wenv-dev.db"

// Load parses configuration for a subcommand. getenv supplies single keys;
// environ (os.Environ() shape) is scanned for unknown WENV_* keys and may be
// nil. Returned warnings are for the caller to log — Load itself never logs.
func Load(subcommand string, args []string, getenv func(string) string, environ []string) (*Config, []string, error) {
	fs := flag.NewFlagSet(subcommand, flag.ContinueOnError)
	dev := fs.Bool("dev", false, "development mode: zero-config sqlite, text logs")
	listen, autoMigrate := new(string), new(bool)
	*autoMigrate = true
	if subcommand == "server" {
		listen = fs.String("listen", "", "listen address (default 127.0.0.1:8080, env WENV_LISTEN)")
		autoMigrate = fs.Bool("auto-migrate", true, "apply pending migrations at boot")
	}
	if err := fs.Parse(args); err != nil {
		return nil, nil, err
	}
	if rest := fs.Args(); len(rest) > 0 {
		return nil, nil, fmt.Errorf("unexpected argument %q", rest[0])
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
	if subcommand == "server" {
		trustedProxyCIDRs, err := parseTrustedProxyCIDRs(getenv("WENV_TRUSTED_PROXY_CIDRS"))
		if err != nil {
			return nil, nil, err
		}
		cfg.TrustedProxyCIDRs = trustedProxyCIDRs
		if !isLoopbackListen(cfg.Listen) && len(cfg.TrustedProxyCIDRs) == 0 {
			return nil, nil, fmt.Errorf("non-loopback plaintext listen %q requires WENV_TRUSTED_PROXY_CIDRS", cfg.Listen)
		}
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

func parseTrustedProxyCIDRs(raw string) ([]string, error) {
	if raw == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	cidrs := make([]string, 0, len(parts))
	for _, part := range parts {
		cidr := strings.TrimSpace(part)
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return nil, fmt.Errorf("WENV_TRUSTED_PROXY_CIDRS: invalid CIDR %q", cidr)
		}
		cidrs = append(cidrs, cidr)
	}
	return cidrs, nil
}

func isLoopbackListen(listen string) bool {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
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
		// Never echo the raw value: an unrecognized DSN can still carry
		// credentials, and these errors reach stderr and logs.
		scheme, _, hasScheme := strings.Cut(raw, ":")
		if !hasScheme {
			scheme = "<none>"
		}
		return Datastore{}, fmt.Errorf("WENV_DB: unsupported datastore scheme %q (want sqlite:PATH or postgres://...)", scheme)
	}
}

// validatePostgresTLS enforces the threat-model boundary restated in the
// system-architecture ADR: remote postgres requires TLS with certificate
// verification or a same-host socket; no plaintext to a non-loopback host.
// The effective host may arrive as the URL authority or as a libpq-style
// ?host= parameter; both are validated, and a DSN naming no host at all is
// refused rather than left to driver/environment defaults (fail-fast, no
// silent resolution through PGHOST).
func validatePostgresTLS(dsn string) error {
	u, err := url.Parse(dsn)
	if err != nil {
		// url.Error embeds the raw URL (credentials included) — report only
		// the underlying cause.
		var uerr *url.Error
		if errors.As(err, &uerr) {
			return fmt.Errorf("WENV_DB: invalid postgres DSN: %w", uerr.Err)
		}
		return fmt.Errorf("WENV_DB: invalid postgres DSN")
	}
	host := u.Hostname()
	if hostParam := u.Query().Get("host"); hostParam != "" {
		if host != "" && host != hostParam {
			return fmt.Errorf("WENV_DB: conflicting hosts %q and ?host=%q", host, hostParam)
		}
		host = hostParam
	}
	if host == "" {
		return fmt.Errorf("WENV_DB: postgres DSN must name its host explicitly (no implicit PGHOST/default resolution)")
	}
	if strings.Contains(host, ",") {
		return fmt.Errorf("WENV_DB: multi-host DSNs are not supported")
	}
	if strings.HasPrefix(host, "/") {
		return nil // same-host unix socket
	}
	if host == "localhost" {
		return nil
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
