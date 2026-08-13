// Package config parses flags and environment strictly and fail-fast
// (system-architecture ADR § Tooling defaults): unknown HIKYO_* keys warn,
// missing prod-critical keys refuse to start, nothing silently conjures a
// database.
package config

import (
	"errors"
	"flag"
	"fmt"
	"math"
	"net"
	"net/url"
	"strconv"
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

	// DirectoryProxy is the OPTIONAL forward proxy the outbound directory
	// client tunnels through, from HIKYO_DIRECTORY_PROXY. Empty is the default
	// and means direct egress.
	//
	// It is EXPLICIT CONFIGURATION and nothing else: http.ProxyFromEnvironment
	// is deliberately not consulted anywhere, because ambient HTTP_PROXY
	// discovery would let a process's environment redirect authenticated fleet
	// traffic. https only — the CONNECT request names the remote host, so a
	// plaintext proxy publishes the fleet topology to the path.
	DirectoryProxy string

	// ExternalOrigin is the instance's public origin (scheme + host), used to
	// build per-provider OIDC redirect URIs (A1). Never derived from a request
	// header. Defaults to http://<Listen> when unset.
	ExternalOrigin string

	// Root-key source descriptor — never the key material itself; the crypto
	// package reads and validates it at boot. Only `hikyo server` consults it.
	RootKeyFile    string // --root-key-file (also covers systemd LoadCredential paths)
	RootKeyFromEnv bool   // HIKYO_ROOT_KEY is set (documented weakest tier)

	// Auth tuning. The Argon2id parameters may be raised for stronger
	// hardware and never lowered: boot verifies them against the floor the
	// human-auth ADR fixes and refuses to start below it, rather than
	// degrading quietly. AdmissionBudgetMiB derives the pre-authentication
	// concurrency, so raising the KDF memory lowers concurrency automatically
	// instead of silently doubling the memory bill.
	Argon2MemoryKiB    uint32
	Argon2Time         uint32
	Argon2Parallelism  uint8
	AdmissionBudgetMiB int

	// Backup export configuration (#76, ops spec section 11). Recipients are
	// PUBLIC age recipients; the private backup identity never touches this
	// process, this configuration or the datastore — it is a separate custody
	// store from the root key by requirement, not by convention.
	//
	// Dir is where automatic exports are published. It is REQUIRED when
	// recipients are configured: an export policy with no destination is a
	// backup that silently goes nowhere, which is the failure mode the loud
	// skip exists to prevent.
	BackupRecipients []string
	BackupDir        string

	// DevAdmissionPerIPPerMinute raises the per-source-IP pre-auth allowance.
	// Zero means the locked default.
	//
	// It exists for one caller — the browser flow suite, which drives every
	// login of every flow from one loopback address, a traffic shape the
	// default is deliberately not sized for. It is refused outside development
	// mode (see Load), so no production instance can have its ceiling raised
	// by an environment variable, and the key name says so out loud for anyone
	// who copies it into a compose file.
	DevAdmissionPerIPPerMinute int
}

// knownEnv is the closed set of HIKYO_* keys this build understands.
var knownEnv = map[string]bool{
	"HIKYO_DB":                   true,
	"HIKYO_LISTEN":               true,
	"HIKYO_EXTERNAL_ORIGIN":      true,
	"HIKYO_TRUSTED_PROXY_CIDRS":  true,
	"HIKYO_ROOT_KEY":             true,
	"HIKYO_ARGON2_MEMORY_KIB":    true,
	"HIKYO_ARGON2_TIME":          true,
	"HIKYO_ARGON2_PARALLELISM":   true,
	"HIKYO_ADMISSION_BUDGET_MIB": true,
	"HIKYO_BACKUP_RECIPIENTS":    true,
	"HIKYO_BACKUP_DIR":           true,

	// Development-only. Named so the deployment it does not belong in is
	// obvious at a glance, and refused at boot outside --dev regardless.
	"HIKYO_DEV_ADMISSION_PER_IP_PER_MINUTE": true,

	// Client-side keys. They configure no server behaviour, but they are
	// listed here because the unknown-key warning is a typo detector: a
	// mistyped HIKYO_PROJEKT that produced no warning would silently target
	// the wrong project, which is the class of mistake the explicit-first
	// context model exists to prevent.
	"HIKYO_STATE_DIR":    true,
	"HIKYO_TRUST_BUNDLE": true,
	"HIKYO_CONTEXT":      true,
	"HIKYO_INSTANCE":     true,
	"HIKYO_ORG":          true,
	"HIKYO_PROJECT":      true,
	"HIKYO_ENV":          true,
	"XDG_STATE_HOME":     true,
}

const devSQLitePath = "hikyo-dev.db"

// Load parses configuration for a subcommand. getenv supplies single keys;
// environ (os.Environ() shape) is scanned for unknown HIKYO_* keys and may be
// nil. Returned warnings are for the caller to log — Load itself never logs.
func Load(subcommand string, args []string, getenv func(string) string, environ []string) (*Config, []string, error) {
	fs := flag.NewFlagSet(subcommand, flag.ContinueOnError)
	dev := fs.Bool("dev", false, "development mode: zero-config sqlite, text logs")
	listen, autoMigrate, rootKeyFile := new(string), new(bool), new(string)
	*autoMigrate = true
	if subcommand == "server" {
		listen = fs.String("listen", "", "listen address (default 127.0.0.1:8080, env HIKYO_LISTEN)")
		autoMigrate = fs.Bool("auto-migrate", true, "apply pending migrations at boot")
		rootKeyFile = fs.String("root-key-file", "", "path to the 64-hex-char root key file (mode 0600)")
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
		if ok && strings.HasPrefix(k, "HIKYO_") && !knownEnv[k] {
			warnings = append(warnings, fmt.Sprintf("unknown environment key %s ignored", k))
		}
	}

	cfg := &Config{
		Dev:            *dev,
		AutoMigrate:    *autoMigrate,
		Listen:         *listen,
		RootKeyFile:    *rootKeyFile,
		RootKeyFromEnv: getenv("HIKYO_ROOT_KEY") != "",
	}
	if cfg.RootKeyFile != "" && cfg.RootKeyFromEnv {
		return nil, nil, fmt.Errorf("both --root-key-file and HIKYO_ROOT_KEY are set: configure exactly one root-key source")
	}
	if cfg.Listen == "" {
		cfg.Listen = getenv("HIKYO_LISTEN")
	}
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:8080"
	}
	if cfg.ExternalOrigin == "" {
		cfg.ExternalOrigin = getenv("HIKYO_EXTERNAL_ORIGIN")
	}
	if cfg.ExternalOrigin == "" {
		cfg.ExternalOrigin = "http://" + cfg.Listen
	}
	if subcommand == "server" || subcommand == "admin" {
		var err error
		if cfg.Argon2MemoryKiB, err = uintEnv(getenv, "HIKYO_ARGON2_MEMORY_KIB", 64*1024); err != nil {
			return nil, nil, err
		}
		if cfg.Argon2Time, err = uintEnv(getenv, "HIKYO_ARGON2_TIME", 3); err != nil {
			return nil, nil, err
		}
		parallelism, err := uintEnv(getenv, "HIKYO_ARGON2_PARALLELISM", 2)
		if err != nil {
			return nil, nil, err
		}
		if parallelism > 255 {
			return nil, nil, fmt.Errorf("HIKYO_ARGON2_PARALLELISM: %d exceeds the 255 Argon2id allows", parallelism)
		}
		cfg.Argon2Parallelism = uint8(parallelism)
		budget, err := uintEnv(getenv, "HIKYO_ADMISSION_BUDGET_MIB", 272)
		if err != nil {
			return nil, nil, err
		}
		// Admission consumes an int in the limiter. Keep the serialized config
		// portable across architectures instead of allowing uint32-to-int wrap on
		// a 32-bit build.
		if budget > math.MaxInt32 {
			return nil, nil, fmt.Errorf(
				"HIKYO_ADMISSION_BUDGET_MIB: %d exceeds the largest portable integer", budget)
		}
		cfg.AdmissionBudgetMiB = int(budget)

		// The dev-only override. Fail-closed twice over: a non-dev process
		// refuses to start when it is set at all, and a malformed or
		// non-positive value is an error rather than a silent fallback to the
		// default — a typo in a security ceiling must not mean "use the
		// default", which is the same rule every other tunable here follows.
		if raw := strings.TrimSpace(getenv("HIKYO_DEV_ADMISSION_PER_IP_PER_MINUTE")); raw != "" {
			if !cfg.Dev {
				return nil, nil, fmt.Errorf(
					"HIKYO_DEV_ADMISSION_PER_IP_PER_MINUTE is a development-mode override and this is not a development server: " +
						"remove it, or pass --dev if this is an evaluation instance")
			}
			perIP, err := strconv.Atoi(raw)
			if err != nil || perIP < 1 {
				return nil, nil, fmt.Errorf("HIKYO_DEV_ADMISSION_PER_IP_PER_MINUTE: %q is not a positive integer", raw)
			}
			cfg.DevAdmissionPerIPPerMinute = perIP
		}
	}
	if subcommand == "server" {
		trustedProxyCIDRs, err := parseTrustedProxyCIDRs(getenv("HIKYO_TRUSTED_PROXY_CIDRS"))
		if err != nil {
			return nil, nil, err
		}
		cfg.TrustedProxyCIDRs = trustedProxyCIDRs
		if !isLoopbackListen(cfg.Listen) && len(cfg.TrustedProxyCIDRs) == 0 {
			return nil, nil, fmt.Errorf("non-loopback plaintext listen %q requires HIKYO_TRUSTED_PROXY_CIDRS", cfg.Listen)
		}
		if raw := getenv("HIKYO_DIRECTORY_PROXY"); raw != "" {
			u, err := url.Parse(raw)
			if err != nil || u.Host == "" {
				return nil, nil, fmt.Errorf("HIKYO_DIRECTORY_PROXY: %q is not a URL naming a host", raw)
			}
			if u.Scheme != "https" {
				return nil, nil, fmt.Errorf("HIKYO_DIRECTORY_PROXY: %q must be https — a plaintext "+
					"forward proxy publishes which installations this one talks to", raw)
			}
			cfg.DirectoryProxy = raw
		}
	}

	if err := loadBackupPolicy(cfg, getenv); err != nil {
		return nil, nil, err
	}

	dbURL := getenv("HIKYO_DB")
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
		return nil, nil, fmt.Errorf("no datastore configured: set HIKYO_DB (sqlite:PATH or postgres://...) or pass --dev for zero-config sqlite evaluation")
	}
	return cfg, warnings, nil
}

// loadBackupPolicy resolves the export recipient set and destination. Both
// halves fail loudly rather than degrading: an unparseable recipient list is
// an error, and recipients without a destination are an error, because the
// only quiet alternative is an instance that believes it is taking backups.
func loadBackupPolicy(cfg *Config, getenv func(string) string) error {
	for _, part := range strings.Split(getenv("HIKYO_BACKUP_RECIPIENTS"), ",") {
		if r := strings.TrimSpace(part); r != "" {
			cfg.BackupRecipients = append(cfg.BackupRecipients, r)
		}
	}
	cfg.BackupDir = strings.TrimSpace(getenv("HIKYO_BACKUP_DIR"))
	if len(cfg.BackupRecipients) > 0 && cfg.BackupDir == "" {
		return errors.New("HIKYO_BACKUP_RECIPIENTS is set but HIKYO_BACKUP_DIR is not: an export policy with no destination writes nothing")
	}
	return nil
}

// uintEnv parses an unsigned tunable, failing loudly rather than falling back
// to the default on a malformed value: a typo in a security parameter must
// not silently mean "use the default".
func uintEnv(getenv func(string) string, key string, fallback uint64) (uint32, error) {
	raw := strings.TrimSpace(getenv(key))
	if raw == "" {
		return uint32(fallback), nil
	}
	v, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%s: %q is not a non-negative integer", key, raw)
	}
	return uint32(v), nil
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
			return nil, fmt.Errorf("HIKYO_TRUSTED_PROXY_CIDRS: invalid CIDR %q", cidr)
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
			return Datastore{}, fmt.Errorf("HIKYO_DB sqlite: requires a file path")
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
		return Datastore{}, fmt.Errorf("HIKYO_DB: unsupported datastore scheme %q (want sqlite:PATH or postgres://...)", scheme)
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
			return fmt.Errorf("HIKYO_DB: invalid postgres DSN: %w", uerr.Err)
		}
		return fmt.Errorf("HIKYO_DB: invalid postgres DSN")
	}
	host := u.Hostname()
	if hostParam := u.Query().Get("host"); hostParam != "" {
		if host != "" && host != hostParam {
			return fmt.Errorf("HIKYO_DB: conflicting hosts %q and ?host=%q", host, hostParam)
		}
		host = hostParam
	}
	if host == "" {
		return fmt.Errorf("HIKYO_DB: postgres DSN must name its host explicitly (no implicit PGHOST/default resolution)")
	}
	if strings.Contains(host, ",") {
		return fmt.Errorf("HIKYO_DB: multi-host DSNs are not supported")
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
	return fmt.Errorf("HIKYO_DB: remote postgres host %q requires sslmode=verify-full or verify-ca (no plaintext on a non-loopback boundary)", host)
}
