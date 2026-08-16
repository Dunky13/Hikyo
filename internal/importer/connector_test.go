package importer

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/schema"
)

// The connector fixture contracts (api-cli-spellings.md § 3): per connector,
// (a) true-positive mapping fixtures for its named capture format,
// (b) adversarial-parser fixtures failing loudly at the named bound or code,
// (c) hostile-provider-error fixtures asserting errors are sanitized
// structurally — keys, paths, bounds and codes, never content.
//
// (c) is the one worth reading. Every refusal in this package is checked
// against the value bytes that produced it: a test that only asserted the code
// would pass on a build that helpfully wrapped the yaml decoder, which echoes
// the offending scalar. See the empirical note in k8s.go.

func read(t *testing.T, name string) Input {
	t.Helper()
	path := filepath.Join("testdata", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return Input{Path: path, Data: data}
}

func run(t *testing.T, source, fixture string, slug string) (Result, error) {
	t.Helper()
	in := read(t, fixture)
	in.EnvSlug = slug
	return Run(t.Context(), source, in)
}

// wantCode asserts the refusal's stable code and that its prose carries no
// forbidden substring.
func wantCode(t *testing.T, err error, code Code, forbidden ...string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected a refusal with code %s, got none", code)
	}
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("refusal is not a structured importer.Error: %v", err)
	}
	if e.Code != code {
		t.Fatalf("code = %s, want %s (message: %s)", e.Code, code, e.Error())
	}
	for _, bad := range forbidden {
		if strings.Contains(e.Error(), bad) {
			t.Fatalf("the refusal leaked source content %q: %s", bad, e.Error())
		}
	}
}

// ---------------------------------------------------------------------------
// k8s
// ---------------------------------------------------------------------------

func TestK8sMultiDocumentStringDataWins(t *testing.T) {
	got, err := run(t, k8sSource, "k8s-multi.yaml", "")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"app-db/DB_PASSWORD": "overlaid-wins", // stringData overlays data
		"app-db/db-host":     "db.internal",
		"app-db/DB_PORT":     "5432",
		"app-api/API_KEY":    "sk_live_abc",
	}
	if len(got.Records) != len(want) {
		t.Fatalf("record count = %d, want %d", len(got.Records), len(want))
	}
	for _, r := range got.Records {
		key := strings.Join(append(append([]string{}, r.Folder...), r.SourceName), "/")
		if want[key] != r.Value {
			t.Errorf("%s = %q, want %q", key, r.Value, want[key])
		}
		if r.Type != schema.TypeString {
			t.Errorf("%s type = %s, want string", key, r.Type)
		}
	}
	// resourceVersion rides through as the per-record source version.
	for _, r := range got.Records {
		if r.Folder[0] == "app-db" && r.Version != "8821" {
			t.Errorf("app-db version = %q, want 8821", r.Version)
		}
	}
}

func TestK8sAdversarialFixtures(t *testing.T) {
	cases := []struct {
		fixture   string
		code      Code
		forbidden []string
	}{
		{"k8s-wrong-kind.yaml", CodeKind, nil},
		{"k8s-duplicate.yaml", CodeDuplicateKey, nil},
		// The binary fixture decodes to 0x00 0x01 0x02 0x03: refused by name.
		{"k8s-binary.yaml", CodeBinaryValue, nil},
		// The hostile fixture puts a live-looking token where a map belongs.
		// yaml.v3's own error would render it; ours must not.
		{"k8s-hostile.yaml", CodeMalformed, []string{"sk_live", "LEAKMEPLEASE"}},
	}
	for _, tc := range cases {
		t.Run(tc.fixture, func(t *testing.T) {
			_, err := run(t, k8sSource, tc.fixture, "")
			wantCode(t, err, tc.code, tc.forbidden...)
		})
	}
}

// TestHostileValuesNeverReachAnyRefusal is the sanitization contract stated
// once over every fixture: no refusal this package produces may contain any
// byte run that appears only inside a value.
func TestHostileValuesNeverReachAnyRefusal(t *testing.T) {
	for _, fixture := range []string{
		"k8s-hostile.yaml", "k8s-duplicate.yaml", "k8s-wrong-kind.yaml",
		"k8s-binary.yaml", "k8s-unmappable.yaml", "k8s-collision.yaml",
		"infisical-flat.json", "infisical-no-type.json", "infisical-no-path.json",
		"sops-corrupt.yaml",
	} {
		t.Run(fixture, func(t *testing.T) {
			source := k8sSource
			slug := ""
			switch {
			case strings.HasPrefix(fixture, "infisical"):
				source, slug = infisicalSource, "dev"
			case strings.HasPrefix(fixture, "sops"):
				source = sopsSource
				withAgeIdentity(t)
			}
			_, err := run(t, source, fixture, slug)
			if err == nil {
				return
			}
			for _, leak := range []string{"sk_live", "LEAKMEPLEASE", "postgres://", "ENC[", "AES256_GCM"} {
				if strings.Contains(err.Error(), leak) {
					t.Fatalf("refusal leaked %q: %s", leak, err)
				}
			}
		})
	}
}

func TestBoundsFailLoudNamingTheBound(t *testing.T) {
	// Per-file cap: the check is at the interface, before any connector runs.
	_, err := Run(t.Context(), k8sSource, Input{Path: "big.yaml", Data: make([]byte, MaxFileBytes+1)})
	wantCode(t, err, CodeBound)
	if !strings.Contains(err.Error(), "per-file cap") {
		t.Errorf("the refusal does not name the bound: %v", err)
	}

	// Record count: the budget refuses while decoding, not after.
	b := &Budget{source: "test", maxBytes: MaxDecodedBytes, maxCount: 2}
	if err := b.Record("a"); err != nil {
		t.Fatal(err)
	}
	if err := b.Record("b"); err != nil {
		t.Fatal(err)
	}
	wantCode(t, b.Record("c"), CodeBound)

	// Decoded bytes: bounded AFTER decoding, which is the whole point.
	b = &Budget{source: "test", maxBytes: 10, maxCount: MaxRecords}
	wantCode(t, b.Bytes("a", 11), CodeBound)

	// Tree depth.
	b = &Budget{source: "test", maxBytes: MaxDecodedBytes, maxCount: MaxRecords}
	wantCode(t, b.Depth("a", MaxDepth+1), CodeBound)
}

// ---------------------------------------------------------------------------
// sops
// ---------------------------------------------------------------------------

// withAgeIdentity points the ambient SOPS keyring at the fixture's age key.
// The identity is a throwaway generated for these fixtures and used nowhere
// else; it lives in testdata because a fixture that cannot be decrypted is not
// a fixture.
func withAgeIdentity(t *testing.T) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "sops-age-identity.txt"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOPS_AGE_KEY", strings.TrimSpace(string(raw)))
}

func TestSOPSNestedMapsFoldersAndCanonicalJSON(t *testing.T) {
	withAgeIdentity(t)
	got, err := run(t, sopsSource, "sops-age.yaml", "")
	if err != nil {
		t.Fatal(err)
	}
	byPath := map[string]Record{}
	for _, r := range got.Records {
		byPath[strings.Join(append(append([]string{}, r.Folder...), r.SourceName), "/")] = r
	}
	// Scalars keep their bytes; nested maps become folder chains.
	if v := byPath["database/DB_PASSWORD"].Value; v != "s3cr3t-value" {
		t.Errorf("database/DB_PASSWORD = %q", v)
	}
	if v := byPath["api/API_KEY"].Value; v != "sk_live_abcdef" {
		t.Errorf("api/API_KEY = %q", v)
	}
	// THE canonical serialization, pinned: object keys sorted, no spaces, no
	// HTML escaping, typed `json`.
	origins := byPath["api/allowed_origins"]
	if origins.Value != `["https://a.example","https://b.example"]` {
		t.Errorf("allowed_origins = %q", origins.Value)
	}
	if origins.Type != schema.TypeJSON {
		t.Errorf("allowed_origins type = %s, want json", origins.Type)
	}
	// A nested MAP is a folder level, not a json leaf — that is the ADR's
	// split, and it is why `limits` becomes `api/limits/…` rather than one
	// serialized object. Arrays have nowhere to go but a json leaf.
	if v := byPath["api/limits/burst"].Value; v != "10" {
		t.Errorf("api/limits/burst = %q, want the scalar under a folder level", v)
	}
	if v := byPath["api/limits/steady"].Value; v != "2" {
		t.Errorf("api/limits/steady = %q", v)
	}
	if v := byPath["database/port"].Value; v != "5432" {
		t.Errorf("database/port = %q; a YAML integer scalar imports as its text", v)
	}
	// Plaintext status is a HINT and only a hint: LOG_LEVEL sat outside the
	// encrypted set, every other leaf inside it.
	if !byPath["LOG_LEVEL"].PlaintextHint {
		t.Error("LOG_LEVEL was stored in plaintext; the hint must record it")
	}
	if byPath["database/DB_PASSWORD"].PlaintextHint {
		t.Error("an encrypted leaf must not carry the plaintext hint")
	}
}

func TestSOPSRefusesUndecryptableWithoutEchoingIt(t *testing.T) {
	// No ambient key at all.
	t.Setenv("SOPS_AGE_KEY", "")
	_, err := run(t, sopsSource, "sops-age.yaml", "")
	wantCode(t, err, CodeDecrypt, "ENC[", "AES256_GCM")

	// A tampered ciphertext: the integrity check must fail, and the refusal
	// must not render either MAC.
	withAgeIdentity(t)
	_, err = run(t, sopsSource, "sops-corrupt.yaml", "")
	wantCode(t, err, CodeDecrypt, "ENC[", "AES256_GCM")
}

// ---------------------------------------------------------------------------
// infisical
// ---------------------------------------------------------------------------

func TestInfisicalPinnedExport(t *testing.T) {
	got, err := run(t, infisicalSource, "infisical-export.json", "dev")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Records) != 2 {
		t.Fatalf("records = %d, want 2 (the personal override is skipped)", len(got.Records))
	}
	if len(got.Skipped) != 1 || got.Skipped[0] != "MY_OVERRIDE" {
		t.Fatalf("skipped = %v, want the personal override listed by name", got.Skipped)
	}
	for _, r := range got.Records {
		if len(r.Folder) != 1 || r.Folder[0] != "db" {
			t.Errorf("%s folder = %v, want [db] from secretPath", r.SourceName, r.Folder)
		}
	}
}

func TestInfisicalRefusesExportsWithoutProvenance(t *testing.T) {
	cases := []struct {
		fixture string
		slug    string
		code    Code
		says    string
	}{
		{"infisical-flat.json", "dev", CodeProvenance, "scaffold"},
		{"infisical-no-type.json", "dev", CodeProvenance, "already resolved"},
		{"infisical-no-path.json", "dev", CodeProvenance, "folder provenance"},
		{"infisical-export.json", "", CodeProvenance, "--env"},
	}
	for _, tc := range cases {
		t.Run(tc.fixture+"/"+tc.slug, func(t *testing.T) {
			_, err := run(t, infisicalSource, tc.fixture, tc.slug)
			wantCode(t, err, tc.code)
			if !strings.Contains(err.Error(), tc.says) {
				t.Errorf("refusal does not say %q: %v", tc.says, err)
			}
		})
	}
}

func TestInfisicalRejectsDuplicateMembersBeforeProvenanceDecoding(t *testing.T) {
	raw := []byte(`[{"key":"MY_OVERRIDE","value":"personal","type":"personal","TYPE":"shared","secretPath":"/db","_id":"sec_1"}]`)
	_, err := Run(t.Context(), infisicalSource, Input{Path: "duplicate.json", Data: raw, EnvSlug: "dev"})
	wantCode(t, err, CodeDuplicateKey)
	if !strings.Contains(strings.ToLower(err.Error()), `"type"`) {
		t.Fatalf("duplicate-member refusal does not name type: %v", err)
	}
}

func TestVaultCaptureFixtureUsesLiveMappingContract(t *testing.T) {
	got, err := run(t, vaultSource, "vault-capture.jsonl", "")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Scope, Scope{Mount: "secret", PathPrefix: "apps", KVVersion: 2}) {
		t.Fatalf("scope = %+v", got.Scope)
	}
	if strings.Join(got.Skipped, ",") != "apps/old" {
		t.Fatalf("skipped = %v", got.Skipped)
	}
	want := []Record{
		{Folder: []string{"db", "main"}, SourceName: "DB_URL", Value: "postgres://fixture", Type: schema.TypeString, Version: "4"},
		{Folder: []string{"db", "main"}, SourceName: "OPTIONS", Value: `{"pool":5,"ssl":true}`, Type: schema.TypeJSON, Version: "4"},
		{Folder: []string{"top"}, SourceName: "API_KEY", Value: "top-secret", Type: schema.TypeString, Version: "2"},
	}
	if !reflect.DeepEqual(got.Records, want) {
		t.Fatalf("records = %#v, want %#v", got.Records, want)
	}
}

// ---------------------------------------------------------------------------
// The shared sanitized spawn path (M5 acceptance)
// ---------------------------------------------------------------------------

// TestSubprocessEnvironmentIsSanitizedAtTheSharedPath is the acceptance the
// M5 boundary names. It asserts the property where it is actually enforced —
// the one shared scope every connector's external programs inherit from — and
// it asserts it on a REAL CHILD PROCESS, because the property that matters is
// what the child sees, not what a helper returns.
func TestSubprocessEnvironmentIsSanitizedAtTheSharedPath(t *testing.T) {
	t.Setenv("HIKYO_TOKEN", "hik_live_must_not_escape")
	t.Setenv("HIKYO_INSTANCE", "https://hikyo.example")
	t.Setenv("HIKYO_TRUST_BUNDLE", "/etc/hikyo/trust.json")
	t.Setenv("HIKYO_STATE_DIR", "/tmp/state")
	// A non-Hikyo variable the connectors NEED must survive: stripping the
	// ambient keyring would break decryption, which is the failure mode a
	// blunter scrub would cause.
	t.Setenv("SOPS_AGE_KEY", "AGE-SECRET-KEY-EXAMPLE")

	var childEnv string
	err := WithSanitized(func() error {
		// In-process: nothing under the prefix survives the scope.
		for _, kv := range os.Environ() {
			name, _, _ := strings.Cut(kv, "=")
			if Stripped(name) {
				return fmt.Errorf("%s survived the sanitized scope", name)
			}
		}
		out, err := exec.CommandContext(t.Context(), "/bin/sh", "-c", "env").Output()
		if err != nil {
			return err
		}
		childEnv = string(out)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"HIKYO_TOKEN", "hik_live_must_not_escape", "HIKYO_INSTANCE", "HIKYO_TRUST_BUNDLE", "HIKYO_STATE_DIR"} {
		if strings.Contains(childEnv, leak) {
			t.Errorf("a subprocess spawned inside the sanitized scope saw %q", leak)
		}
	}
	if !strings.Contains(childEnv, "SOPS_AGE_KEY") {
		t.Error("the ambient decryption keyring was stripped; decryption would fail")
	}
	// The scope restores what it removed: a later verb in the same process
	// still has its context.
	if os.Getenv("HIKYO_TOKEN") != "hik_live_must_not_escape" {
		t.Error("the sanitized scope did not restore the environment")
	}
}

// TestHostileStructuralFieldsAreNeverEchoed is the S4 contract: a foreign
// ENUM-SHAPED field (`kind`, Infisical `type`) is refused WITHOUT rendering its
// value, and a foreign NAME — which the ADR requires errors to state — is
// rendered escaped and length-capped.
//
// The attack it closes is not only disclosure. A key literally named
// "\x1b[2J\x1b]0;pwned\x07" repaints the operator's terminal and rewrites its
// title from a refusal message; the same bytes in a log make the log lie.
func TestHostileStructuralFieldsAreNeverEchoed(t *testing.T) {
	esc := "\x1b[2J"

	_, err := run(t, k8sSource, "k8s-hostile-kind.yaml", "")
	wantCode(t, err, CodeKind, esc, "sk_live_KINDLEAK", "\x1b", "\x07")

	_, err = run(t, infisicalSource, "infisical-hostile-type.json", "dev")
	wantCode(t, err, CodeProvenance, esc, "sk_live_TYPELEAK", "\x1b", "\x07")

	// A hostile NAME must still be named — the ADR requires it — but escaped.
	res, err := run(t, k8sSource, "k8s-hostile-name.yaml", "")
	if err != nil {
		t.Fatal(err)
	}
	_, err = BuildPlan(PlanInput{Source: k8sSource, Records: res.Records, State: state()})
	wantCode(t, err, CodeUnmappableName, "\x1b", "\x07")
	if !strings.Contains(err.Error(), `\x1b`) {
		t.Errorf("the refusal does not name the key at all: %v", err)
	}

	// The length cap: a megabyte of foreign name is its own denial of service,
	// of the terminal and of the log that keeps it.
	long := quoteName(strings.Repeat("q", 10000))
	if len(long) > MaxShownNameBytes+4 {
		t.Errorf("a rendered name is %d bytes; the cap is %d", len(long), MaxShownNameBytes)
	}
}

// TestAliasBombFailsAtTheNamedBoundBeforeMaterializing is the S3 contract: a
// YAML alias graph that expands past the decoded-bytes cap is refused during
// the walk, not after Decode has allocated the expansion.
func TestAliasBombFailsAtTheNamedBoundBeforeMaterializing(t *testing.T) {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	_, err := run(t, k8sSource, "k8s-alias-bomb.yaml", "")
	wantCode(t, err, CodeBound)
	if !strings.Contains(err.Error(), "decoded-bytes cap") {
		t.Errorf("the refusal does not name the bound: %v", err)
	}

	runtime.GC()
	runtime.ReadMemStats(&after)
	// The bomb expands to ~64 MiB if materialized. Allowing four times the cap
	// leaves room for the parser's own node graph while still failing loudly if
	// the expansion is ever allocated.
	if grew := after.TotalAlloc - before.TotalAlloc; grew > 4*MaxDecodedBytes {
		t.Errorf("the refusal allocated %d bytes; the expansion was materialized before the bound ran", grew)
	}
}

func TestSOPSAliasBombFailsAtTheNamedBoundBeforeMaterializing(t *testing.T) {
	in := read(t, "sops-alias-bomb.yaml")
	b := &Budget{source: sopsSource, maxBytes: MaxDecodedBytes, maxCount: MaxRecords}
	_, err := decodeSOPSPlaintext(in.Path, in.Data, b)
	wantCode(t, err, CodeBound)
	if !strings.Contains(err.Error(), "decoded-bytes cap") {
		t.Errorf("the refusal does not name the bound: %v", err)
	}
}

// TestPersonalOverridesAreChargedBeforeTheyAreSkipped is the S5 contract: a
// skipped record still costs a decode and a record slot, so branching on type
// first would make the record cap count what it liked rather than what it
// parsed.
func TestPersonalOverridesAreChargedBeforeTheyAreSkipped(t *testing.T) {
	_, err := run(t, infisicalSource, "infisical-many-personal.json", "dev")
	wantCode(t, err, CodeBound)
	if !strings.Contains(err.Error(), "record cap") {
		t.Errorf("the refusal does not name the bound: %v", err)
	}
}

// TestReadExportBoundsBeforeTheBytesAreResident is the S2 contract: the
// per-file cap must run before the file is in memory, and it must survive a
// file that lies about its size.
func TestReadExportBoundsBeforeTheBytesAreResident(t *testing.T) {
	path := filepath.Join(t.TempDir(), "big.yaml")
	if err := os.WriteFile(path, make([]byte, MaxFileBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := ReadExport(path)
	wantCode(t, err, CodeBound)
	if !strings.Contains(err.Error(), "per-file cap") {
		t.Errorf("the refusal does not name the bound: %v", err)
	}

	// A file at the cap is fine, and the LimitReader must not truncate it.
	ok := filepath.Join(t.TempDir(), "fine.yaml")
	if err := os.WriteFile(ok, make([]byte, MaxFileBytes), 0o600); err != nil {
		t.Fatal(err)
	}
	in, err := ReadExport(ok)
	if err != nil {
		t.Fatal(err)
	}
	if len(in.Data) != MaxFileBytes {
		t.Fatalf("read %d bytes of a %d-byte file", len(in.Data), MaxFileBytes)
	}
}

func TestReadExportRefusesFIFOWithoutBlocking(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("named-pipe file modes differ on windows")
	}
	path := filepath.Join(t.TempDir(), "export.fifo")
	if err := exec.Command("mkfifo", path).Run(); err != nil {
		t.Fatalf("creating fifo: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := ReadExport(path)
		done <- err
	}()
	select {
	case err := <-done:
		wantCode(t, err, CodeMalformed)
		if !strings.Contains(err.Error(), "file mode") || !strings.Contains(err.Error(), "not regular") {
			t.Fatalf("fifo refusal does not name its mode: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("ReadExport blocked opening a fifo")
	}
}

// TestRunDeadlineInterruptsDecryption is the M5 contract: the run deadline is a
// deadline, not a number in a comment. The check is on the seam — a cancelled
// context refuses at the named bound rather than waiting for the library.
func TestRunDeadlineInterruptsDecryption(t *testing.T) {
	withAgeIdentity(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	in := read(t, "sops-age.yaml")
	_, err := sopsConnector{}.Read(ctx, in, &Budget{source: sopsSource, maxBytes: MaxDecodedBytes, maxCount: MaxRecords})
	wantCode(t, err, CodeBound)
	if !strings.Contains(err.Error(), "deadline") {
		t.Errorf("the refusal does not name the deadline: %v", err)
	}
}
