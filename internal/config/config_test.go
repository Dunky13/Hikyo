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
	if !strings.Contains(err.Error(), "WENV_DB") {
		t.Fatalf("error should name WENV_DB, got: %v", err)
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
	cfg, _, err := Load("server", nil, env("WENV_DB", "sqlite:/data/wenv.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Store.Engine != EngineSQLite || cfg.Store.Path != "/data/wenv.db" {
		t.Fatalf("got %+v", cfg.Store)
	}
}

func TestSQLiteDSNEmptyPathRefuses(t *testing.T) {
	_, _, err := Load("server", nil, env("WENV_DB", "sqlite:"), nil)
	if err == nil {
		t.Fatal("empty sqlite path must refuse")
	}
}

func TestPostgresLoopbackAllowed(t *testing.T) {
	for _, dsn := range []string{
		"postgres://u:p@localhost:5432/wenv",
		"postgres://u:p@127.0.0.1/wenv",
		"postgresql://u:p@[::1]/wenv",
	} {
		cfg, _, err := Load("server", nil, env("WENV_DB", dsn), nil)
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
		"postgres://u:p@db.example.com/wenv",
		"postgres://u:p@db.example.com/wenv?sslmode=disable",
		"postgres://u:p@10.0.0.5/wenv?sslmode=prefer",
	} {
		_, _, err := Load("server", nil, env("WENV_DB", dsn), nil)
		if err == nil {
			t.Fatalf("%s: remote postgres without verified TLS must refuse", dsn)
		}
	}
}

func TestPostgresRemoteVerifiedTLSAllowed(t *testing.T) {
	for _, dsn := range []string{
		"postgres://u:p@db.example.com/wenv?sslmode=verify-full",
		"postgres://u:p@db.example.com/wenv?sslmode=verify-ca",
	} {
		if _, _, err := Load("server", nil, env("WENV_DB", dsn), nil); err != nil {
			t.Fatalf("%s: %v", dsn, err)
		}
	}
}

func TestPostgresHostParamCannotBypassTLSCheck(t *testing.T) {
	for _, dsn := range []string{
		"postgres:///wenv?host=remote.example.com",          // libpq-style host param
		"postgres://u:p@/wenv?host=10.0.0.5&sslmode=prefer", // empty authority + host param
		"postgres:///wenv", // no host at all (implicit PGHOST)
		"postgres://u:p@localhost/wenv?host=remote.example.com", // conflicting hosts
		"postgres:///wenv?host=a,b",                             // multi-host
	} {
		if _, _, err := Load("server", nil, env("WENV_DB", dsn), nil); err == nil {
			t.Errorf("%s: must refuse", dsn)
		}
	}
	// Socket path via host param stays allowed.
	if _, _, err := Load("server", nil, env("WENV_DB", "postgres:///wenv?host=/var/run/postgresql"), nil); err != nil {
		t.Errorf("socket host param: %v", err)
	}
}

func TestUnknownEngineRefuses(t *testing.T) {
	_, _, err := Load("server", nil, env("WENV_DB", "mysql://u@localhost/db"), nil)
	if err == nil {
		t.Fatal("unknown datastore scheme must refuse")
	}
}

func TestUnknownWenvKeysWarn(t *testing.T) {
	_, warnings, err := Load("server", []string{"--dev"}, env(), environFrom("WENV_TYPO", "x", "WENV_DB", ""))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, w := range warnings {
		if strings.Contains(w, "WENV_TYPO") {
			found = true
		}
	}
	if !found {
		t.Fatalf("unknown WENV_ key must warn, got %v", warnings)
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
	cfg, _, err := Load("server", []string{"--dev", "--listen", "127.0.0.1:9999"}, env("WENV_LISTEN", "127.0.0.1:8888"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != "127.0.0.1:9999" {
		t.Fatalf("listen = %q", cfg.Listen)
	}
	cfg, _, err = Load("server", []string{"--dev"}, env("WENV_LISTEN", "127.0.0.1:8888"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != "127.0.0.1:8888" {
		t.Fatalf("listen = %q", cfg.Listen)
	}
}
