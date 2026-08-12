package config

import (
	"strings"
	"testing"
)

func env(pairs ...string) func(string) string {
	m := map[string]string{}
	for i := 0; i+1 < len(pairs); i += 2 {
		m[pairs[i]] = pairs[i+1]
	}
	return func(k string) string { return m[k] }
}

func environFrom(pairs ...string) []string {
	var out []string
	for i := 0; i+1 < len(pairs); i += 2 {
		out = append(out, pairs[i]+"="+pairs[i+1])
	}
	return out
}

func TestServerWithoutDatastoreRefuses(t *testing.T) {
	_, _, err := Load("server", nil, env(), nil)
	if err == nil {
		t.Fatal("production start without explicit datastore config must refuse")
	}
	if !strings.Contains(err.Error(), "HIKYO_DB") {
		t.Fatalf("error should name HIKYO_DB, got: %v", err)
	}
}

func TestDevBootsZeroConfigSQLite(t *testing.T) {
	cfg, _, err := Load("server", []string{"--dev"}, env(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Store.Engine != EngineSQLite {
		t.Fatalf("engine = %q, want sqlite", cfg.Store.Engine)
	}
	if cfg.Store.Path == "" {
		t.Fatal("dev sqlite path must be set")
	}
	if !cfg.Dev {
		t.Fatal("Dev flag not set")
	}
}

func TestExplicitSQLiteDSN(t *testing.T) {
	cfg, _, err := Load("server", nil, env("HIKYO_DB", "sqlite:/data/hikyo.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Store.Engine != EngineSQLite || cfg.Store.Path != "/data/hikyo.db" {
		t.Fatalf("got %+v", cfg.Store)
	}
}

func TestSQLiteDSNEmptyPathRefuses(t *testing.T) {
	_, _, err := Load("server", nil, env("HIKYO_DB", "sqlite:"), nil)
	if err == nil {
		t.Fatal("empty sqlite path must refuse")
	}
}

func TestPostgresLoopbackAllowed(t *testing.T) {
	for _, dsn := range []string{
		"postgres://u:p@localhost:5432/hikyo",
		"postgres://u:p@127.0.0.1/hikyo",
		"postgresql://u:p@[::1]/hikyo",
	} {
		cfg, _, err := Load("server", nil, env("HIKYO_DB", dsn), nil)
		if err != nil {
			t.Fatalf("%s: %v", dsn, err)
		}
		if cfg.Store.Engine != EnginePostgres {
			t.Fatalf("%s: engine %q", dsn, cfg.Store.Engine)
		}
	}
}

func TestPostgresRemotePlaintextRefuses(t *testing.T) {
	for _, dsn := range []string{
		"postgres://u:p@db.example.com/hikyo",
		"postgres://u:p@db.example.com/hikyo?sslmode=disable",
		"postgres://u:p@10.0.0.5/hikyo?sslmode=prefer",
	} {
		_, _, err := Load("server", nil, env("HIKYO_DB", dsn), nil)
		if err == nil {
			t.Fatalf("%s: remote postgres without verified TLS must refuse", dsn)
		}
	}
}

func TestPostgresRemoteVerifiedTLSAllowed(t *testing.T) {
	for _, dsn := range []string{
		"postgres://u:p@db.example.com/hikyo?sslmode=verify-full",
		"postgres://u:p@db.example.com/hikyo?sslmode=verify-ca",
	} {
		if _, _, err := Load("server", nil, env("HIKYO_DB", dsn), nil); err != nil {
			t.Fatalf("%s: %v", dsn, err)
		}
	}
}

func TestPostgresHostParamCannotBypassTLSCheck(t *testing.T) {
	for _, dsn := range []string{
		"postgres:///hikyo?host=remote.example.com",              // libpq-style host param
		"postgres://u:p@/hikyo?host=10.0.0.5&sslmode=prefer",     // empty authority + host param
		"postgres:///hikyo",                                      // no host at all (implicit PGHOST)
		"postgres://u:p@localhost/hikyo?host=remote.example.com", // conflicting hosts
		"postgres:///hikyo?host=a,b",                             // multi-host
	} {
		if _, _, err := Load("server", nil, env("HIKYO_DB", dsn), nil); err == nil {
			t.Errorf("%s: must refuse", dsn)
		}
	}
	// Socket path via host param stays allowed.
	if _, _, err := Load("server", nil, env("HIKYO_DB", "postgres:///hikyo?host=/var/run/postgresql"), nil); err != nil {
		t.Errorf("socket host param: %v", err)
	}
}

func TestUnknownEngineRefuses(t *testing.T) {
	_, _, err := Load("server", nil, env("HIKYO_DB", "mysql://u@localhost/db"), nil)
	if err == nil {
		t.Fatal("unknown datastore scheme must refuse")
	}
}

func TestErrorsNeverEchoCredentials(t *testing.T) {
	const secret = "hunter2sentinel"
	for _, dsn := range []string{
		"mysql://user:" + secret + "@db.example.com/db",  // unsupported scheme
		"postgres://user:" + secret + "@db\x7f.bad/db",   // url.Parse failure
		"postgres://user:" + secret + "@db.example.com/", // TLS refusal
	} {
		_, _, err := Load("server", nil, env("HIKYO_DB", dsn), nil)
		if err == nil {
			t.Fatalf("%q: expected refusal", dsn)
		}
		if strings.Contains(err.Error(), secret) {
			t.Errorf("error leaks credentials: %v", err)
		}
	}
}

func TestPositionalArgumentsRefused(t *testing.T) {
	for _, sub := range []string{"server", "migrate"} {
		_, _, err := Load(sub, []string{"--dev", "typo"}, env(), nil)
		if err == nil {
			t.Errorf("%s: stray positional argument must refuse", sub)
		}
	}
}

func TestUnknownHikyoKeysWarn(t *testing.T) {
	_, warnings, err := Load("server", []string{"--dev"}, env(), environFrom("HIKYO_TYPO", "x", "HIKYO_DB", ""))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, w := range warnings {
		if strings.Contains(w, "HIKYO_TYPO") {
			found = true
		}
	}
	if !found {
		t.Fatalf("unknown HIKYO_ key must warn, got %v", warnings)
	}
}

func TestAutoMigrateDefaultOnAndDisable(t *testing.T) {
	cfg, _, err := Load("server", []string{"--dev"}, env(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.AutoMigrate {
		t.Fatal("auto-migrate must default on")
	}
	cfg, _, err = Load("server", []string{"--dev", "--auto-migrate=false"}, env(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AutoMigrate {
		t.Fatal("--auto-migrate=false must disable")
	}
}

func TestListenPrecedenceFlagOverEnv(t *testing.T) {
	cfg, _, err := Load("server", []string{"--dev", "--listen", "127.0.0.1:9999"}, env("HIKYO_LISTEN", "127.0.0.1:8888"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != "127.0.0.1:9999" {
		t.Fatalf("listen = %q", cfg.Listen)
	}
	cfg, _, err = Load("server", []string{"--dev"}, env("HIKYO_LISTEN", "127.0.0.1:8888"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != "127.0.0.1:8888" {
		t.Fatalf("listen = %q", cfg.Listen)
	}
}

func TestNonLoopbackListenRequiresTrustedProxyCIDRs(t *testing.T) {
	_, _, err := Load("server", []string{"--dev", "--listen", "0.0.0.0:8080"}, env(), nil)
	if err == nil || !strings.Contains(err.Error(), "HIKYO_TRUSTED_PROXY_CIDRS") {
		t.Fatalf("non-loopback plaintext listen must refuse without trusted proxies, got %v", err)
	}

	cfg, warnings, err := Load("server", []string{"--dev", "--listen", "0.0.0.0:8080"},
		env("HIKYO_TRUSTED_PROXY_CIDRS", "10.42.0.0/16,fd00:42::/64"),
		environFrom("HIKYO_TRUSTED_PROXY_CIDRS", "10.42.0.0/16,fd00:42::/64"))
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 0 {
		t.Fatalf("trusted proxy setting must be recognized, got warnings %v", warnings)
	}
	if len(cfg.TrustedProxyCIDRs) != 2 {
		t.Fatalf("trusted proxy CIDRs = %v", cfg.TrustedProxyCIDRs)
	}

	_, _, err = Load("server", []string{"--dev", "--listen", "0.0.0.0:8080"},
		env("HIKYO_TRUSTED_PROXY_CIDRS", "not-a-cidr"), nil)
	if err == nil || !strings.Contains(err.Error(), "invalid CIDR") {
		t.Fatalf("invalid trusted proxy CIDR must refuse, got %v", err)
	}
}

// The per-IP pre-auth allowance is a security ceiling. It is overridable for
// exactly one traffic shape — a test harness driving every login of every flow
// from one loopback address — and the override is fail-closed twice: a
// production server refuses to start when it is set at all, and a malformed
// value is an error rather than a quiet fallback to the default.
func TestDevAdmissionOverrideIsRefusedOutsideDevMode(t *testing.T) {
	_, _, err := Load("server", nil,
		env("HIKYO_DB", "sqlite:x.db", "HIKYO_DEV_ADMISSION_PER_IP_PER_MINUTE", "200"), nil)
	if err == nil {
		t.Fatal("a production server accepted a development-only admission override")
	}
	if !strings.Contains(err.Error(), "development-mode override") {
		t.Fatalf("error should say why it is refused, got: %v", err)
	}
}

func TestDevAdmissionOverrideAppliesInDevMode(t *testing.T) {
	cfg, _, err := Load("server", []string{"--dev"},
		env("HIKYO_DEV_ADMISSION_PER_IP_PER_MINUTE", "200"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DevAdmissionPerIPPerMinute != 200 {
		t.Fatalf("override = %d, want 200", cfg.DevAdmissionPerIPPerMinute)
	}
}

func TestDevAdmissionOverrideRefusesNonsense(t *testing.T) {
	for _, raw := range []string{"0", "-1", "lots", "10.5"} {
		if _, _, err := Load("server", []string{"--dev"},
			env("HIKYO_DEV_ADMISSION_PER_IP_PER_MINUTE", raw), nil); err == nil {
			t.Fatalf("%q was accepted as an allowance", raw)
		}
	}
}

func TestAdmissionOverrideUnsetLeavesTheDefault(t *testing.T) {
	cfg, _, err := Load("server", []string{"--dev"}, env(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DevAdmissionPerIPPerMinute != 0 {
		t.Fatalf("override = %d, want 0 (meaning: the locked default)", cfg.DevAdmissionPerIPPerMinute)
	}
}
