package isolation

// SS4 planted-canary sweep across the REAL operator-facing output surfaces (#74,
// ADR §§4,5,6). The existing lifecycle sweep (scanning_e2e_test.go) proved the
// canary is absent from audit-table PAYLOADS and the OpenAPI DTO SHAPE — two
// representations, not the bytes an operator actually receives. This drives the
// genuine surfaces end to end and asserts the planted credential (and any match
// offset/length/excerpt disclosure) appears in NONE of them:
//
//   - the real HTTP response body of a value write that WARNS and of a
//     declaration write that BLOCKS, and of an import — read as raw bytes off
//     the wire, never a decoded struct (decoding silently drops unknown fields
//     and would hide a leak);
//   - the real CLI output (stdout table, `-o json`, and stderr) of a warn and a
//     block, produced by driving `cli.Run` against that same live server;
//   - the audit EXPORT stream (tenant, paginated, and the instance trail).
//
// Non-disclosure has two arms and this asserts both: the canary bytes are absent
// (a leak of the value itself), AND every finding object carried on any of these
// surfaces exposes only the closed redacted key set {rule_id, surface, locator,
// acknowledgement} — so no offset/length/excerpt field can ride along even
// empty. Requests and CLI argv necessarily contain the canary; only responses
// and emitted output are swept.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Hikyo-Org/hikyo/api"
	"github.com/Hikyo-Org/hikyo/internal/cli"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/scanning"
	"github.com/Hikyo-Org/hikyo/internal/server"
	"github.com/Hikyo-Org/hikyo/internal/service"
	"github.com/Hikyo-Org/hikyo/internal/store"
	"github.com/Hikyo-Org/hikyo/internal/webauthntest"
)

// sweepAllowedFindingKeys is the closed redacted DTO key set (ADR §4). A finding
// object anywhere in any swept output may carry ONLY these; an offset, length,
// excerpt, match, value or fingerprint key is a disclosure by construction.
var sweepAllowedFindingKeys = map[string]bool{
	"rule_id": true, "surface": true, "locator": true, "acknowledgement": true,
}

var sweepForbiddenFindingKeys = map[string]bool{
	"offset": true, "length": true, "excerpt": true,
	"match": true, "value": true, "fingerprint": true,
}

type sweepFinding struct {
	ruleID  string
	locator string
}

// assertNoCanary fails if the planted credential (or a bare AWS-key prefix, which
// catches a partial echo) appears in the given output surface.
func assertNoCanary(t *testing.T, surface string, out []byte) {
	t.Helper()
	if bytes.Contains(out, []byte(plantedCredential)) {
		t.Errorf("SS4 sweep: the planted credential leaked into %s", surface)
	}
	if bytes.Contains(out, []byte("AKIA")) {
		t.Errorf("SS4 sweep: an AWS-key prefix leaked into %s", surface)
	}
}

// decodeJSONStream accepts both one JSON document and NDJSON. Audit export is
// JSON per line, so every exported line is decoded and walked instead of being
// dismissed as "not JSON".
func decodeJSONStream(t *testing.T, surface string, raw []byte) []any {
	t.Helper()
	var doc any
	if err := json.Unmarshal(raw, &doc); err == nil {
		return []any{doc}
	}
	var docs []any
	for lineNo, line := range bytes.Split(raw, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var doc any
		if err := json.Unmarshal(line, &doc); err != nil {
			t.Fatalf("SS4 sweep: %s NDJSON line %d is not valid JSON: %v", surface, lineNo+1, err)
		}
		docs = append(docs, doc)
	}
	return docs
}

// assertFindingKeysClosed walks every JSON/NDJSON document. Wire finding DTOs
// (objects with a locator) are closed to the four redacted keys. Audit finding
// payloads deliberately have their audit schema instead, so every object is
// additionally checked for the disclosure-key blacklist. Returned identities
// let each caller prove the scanner actually fired before checking absence.
func assertFindingKeysClosed(t *testing.T, surface string, raw []byte) ([]sweepFinding, int) {
	t.Helper()
	docs := decodeJSONStream(t, surface, raw)
	var findings []sweepFinding
	var walk func(v any)
	walk = func(v any) {
		switch node := v.(type) {
		case map[string]any:
			rule, hasRule := node["rule_id"]
			_, hasLoc := node["locator"]
			if hasLoc {
				for k := range node {
					if !sweepAllowedFindingKeys[k] {
						t.Errorf("SS4 sweep: a finding object in %s carries the non-redacted key %q (offset/length/excerpt disclosure is banned by construction)", surface, k)
					}
				}
			}
			for k := range node {
				if sweepForbiddenFindingKeys[strings.ToLower(k)] {
					t.Errorf("SS4 sweep: an object in %s carries the disclosure key %q", surface, k)
				}
			}
			if hasRule {
				f := sweepFinding{ruleID: fmt.Sprint(rule)}
				if locator, ok := node["locator"].(string); ok {
					f.locator = locator
				}
				findings = append(findings, f)
			}
			for _, child := range node {
				walk(child)
			}
		case []any:
			for _, child := range node {
				walk(child)
			}
		}
	}
	for _, doc := range docs {
		walk(doc)
	}
	return findings, len(docs)
}

func requireFinding(t *testing.T, surface string, findings []sweepFinding, requireLocator bool) sweepFinding {
	t.Helper()
	for _, finding := range findings {
		if finding.ruleID != "" && (!requireLocator || finding.locator != "") {
			return finding
		}
	}
	t.Fatalf("SS4 sweep: %s carried no rendered finding; the surface is vacuous", surface)
	return sweepFinding{}
}

// Text output cannot be structurally decoded, so reject the banned redaction
// field names as standalone rendered columns/attributes on every CLI stream.
func assertNoDisclosureKeysText(t *testing.T, surface, out string) {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		for _, field := range strings.FieldsFunc(strings.ToLower(line), func(r rune) bool {
			return !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_')
		}) {
			if field == "offset" || field == "length" || field == "excerpt" {
				t.Errorf("SS4 sweep: %s renders the banned finding field %q", surface, field)
			}
		}
	}
}

// assertRenderedFindingLine proves a CLI warning/refusal is non-vacuous: one
// rendered line must carry the redacted rule ID and immutable locator together.
func assertRenderedFindingLine(t *testing.T, surface, out string, want sweepFinding) {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, want.ruleID) && strings.Contains(line, want.locator) {
			assertNoDisclosureKeysText(t, surface+" finding line", line)
			// Remove the two fields the human rendering is allowed to carry, then
			// reject every other finding attribute by name. This pins the table/
			// stderr contract to rule ID + locator, not merely canary absence.
			remainder := strings.ReplaceAll(line, want.ruleID, "")
			remainder = strings.ReplaceAll(remainder, want.locator, "")
			for _, field := range strings.FieldsFunc(strings.ToLower(remainder), func(r rune) bool {
				return !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_')
			}) {
				if sweepForbiddenFindingKeys[field] || field == "surface" || field == "acknowledgement" {
					t.Errorf("SS4 sweep: %s finding line carries unexpected finding attribute %q", surface, field)
				}
			}
			return
		}
	}
	t.Fatalf("SS4 sweep: %s has no finding line carrying rule ID %q + locator %q; output=%q", surface, want.ruleID, want.locator, out)
}

// sweepEnv is the assembled real stack for the canary sweep: a live server, an
// authenticated administrator token, and the scanning-enabled Audits service.
type sweepEnv struct {
	srv               *httptest.Server
	token             string
	admin             domain.PrincipalID
	audits            *service.Audits
	org, project, env string
	stateDir          string
}

// The sweep runs dual-engine on its own freshly-seeded instance (where it can
// bootstrap the administrator it authenticates as; the shared audit suite has
// already consumed the first-admin slot). It emits its own scanning events, so
// it does not need the audit closure gate to give those types an emitter —
// runScanningLifecycle already does that.
func TestScanningCanarySweepSQLite(t *testing.T) {
	runScanningCanarySweep(t, seededDB(t, openSQLite))
}

func TestScanningCanarySweepPostgres(t *testing.T) {
	runScanningCanarySweep(t, seededDB(t, openPostgres))
}

// runScanningCanarySweep is SS4.a made real: it plants the canary, drives every
// operator-facing output surface, and proves the credential is absent from each.
func runScanningCanarySweep(t *testing.T, db *store.DB) {
	t.Helper()
	e := newSweepEnv(t, db)

	// --- surface 1: a config value write that WARNS (HTTP body) ------------
	valuePath := e.base() + "/environments/" + e.env + "/values/CONFIG_KEY"
	code, body := e.call(t, http.MethodPut, valuePath, map[string]any{"value": plantedCredential})
	if code != http.StatusOK {
		t.Fatalf("SS4 sweep: value warn write returned %d: %s", code, body)
	}
	valueFindings, _ := assertFindingKeysClosed(t, "HTTP value-warn body", body)
	valueFinding := requireFinding(t, "HTTP value-warn body", valueFindings, true)
	assertNoCanary(t, "HTTP value-warn body", body)

	// --- surface 2: a declaration write that BLOCKS (HTTP body) ------------
	blockBody := map[string]any{
		"name":           "SWEEP_BLOCKED",
		"classification": "config",
		"description":    "see the runbook token " + plantedCredential,
		"declaration":    json.RawMessage(`{"rule":{"type":"string"}}`),
		"presence":       map[string]any{"required_in": map[string]any{"mode": "none"}, "forbidden_in": map[string]any{"mode": "none"}},
	}
	code, body = e.call(t, http.MethodPost, e.base()+"/keys", blockBody)
	if code == http.StatusOK {
		t.Fatalf("SS4 sweep: a declaration carrying the canary was not blocked (got 200): %s", body)
	}
	blockFindings, _ := assertFindingKeysClosed(t, "HTTP declaration-block body", body)
	blockFinding := requireFinding(t, "HTTP declaration-block body", blockFindings, true)
	assertNoCanary(t, "HTTP declaration-block body", body)

	// --- surface 3: import output (HTTP body) ------------------------------
	importBody := map[string]any{"entries": []map[string]string{{"key": "CONFIG_KEY", "value": plantedCredential + "IMPORT"}}}
	code, body = e.call(t, http.MethodPost, e.base()+"/environments/"+e.env+"/values/import", importBody)
	if code != http.StatusOK {
		t.Fatalf("SS4 sweep: import returned %d: %s", code, body)
	}
	importFindings, _ := assertFindingKeysClosed(t, "HTTP import body", body)
	requireFinding(t, "HTTP import body", importFindings, true)
	assertNoCanary(t, "HTTP import body", body)

	// --- surface 4: CLI value set warn (stdout table + stderr) -------------
	valueFile := filepath.Join(t.TempDir(), "value")
	if err := os.WriteFile(valueFile, []byte(plantedCredential), 0o600); err != nil {
		t.Fatal(err)
	}
	target := []string{"--instance", "local", "--org", e.org, "--project", e.project, "--env", e.env}
	stdout, stderr := e.runCLI(t, append([]string{"values", "set", "CONFIG_KEY", "--value-file", valueFile}, target...)...)
	assertRenderedFindingLine(t, "CLI value-set stderr (warn)", stderr, valueFinding)
	assertNoDisclosureKeysText(t, "CLI value-set stdout (table)", stdout)
	assertNoDisclosureKeysText(t, "CLI value-set stderr (warn)", stderr)
	assertNoCanary(t, "CLI value-set stdout (table)", []byte(stdout))
	assertNoCanary(t, "CLI value-set stderr (warn)", []byte(stderr))

	// --- surface 5: CLI value set warn, `-o json` --------------------------
	stdout, stderr = e.runCLI(t, append([]string{"values", "set", "CONFIG_KEY", "--value-file", valueFile, "-o", "json"}, target...)...)
	cliJSONFindings, _ := assertFindingKeysClosed(t, "CLI value-set json", []byte(stdout))
	requireFinding(t, "CLI value-set json", cliJSONFindings, true)
	assertNoDisclosureKeysText(t, "CLI value-set stderr (json run)", stderr)
	assertNoCanary(t, "CLI value-set stdout (json)", []byte(stdout))
	assertNoCanary(t, "CLI value-set stderr (json run)", []byte(stderr))

	// --- surface 6: CLI declaration create that BLOCKS (stderr refusal) ----
	stdout, stderr = e.runCLI(t, "key", "create", "--name", "SWEEP_CLI_BLOCKED",
		"--classification", "config", "--declaration", `{"rule":{"type":"string"}}`,
		"--description", "runbook "+plantedCredential, "--instance", "local", "--org", e.org, "--project", e.project)
	assertRenderedFindingLine(t, "CLI key-create stderr (block)", stderr, blockFinding)
	assertNoDisclosureKeysText(t, "CLI key-create stdout (block)", stdout)
	assertNoDisclosureKeysText(t, "CLI key-create stderr (block)", stderr)
	assertNoCanary(t, "CLI key-create stdout (block)", []byte(stdout))
	assertNoCanary(t, "CLI key-create stderr (block)", []byte(stderr))

	// --- surface 7: the audit EXPORT stream (tenant, paginated, + instance) -
	var tenant bytes.Buffer
	// pageSize 1 forces multi-page pagination so the "export page" path is real.
	if err := e.audits.Export(tctx(t), e.admin, domain.Scope{Org: domain.OrgID(e.org)}, store.AuditFilter{}, 1, &tenant); err != nil {
		t.Fatalf("SS4 sweep: tenant audit export: %v", err)
	}
	if tenant.Len() == 0 {
		t.Fatal("SS4 sweep: the tenant audit export produced no bytes; the scanning events did not commit")
	}
	tenantFindings, _ := assertFindingKeysClosed(t, "audit tenant export stream", tenant.Bytes())
	requireFinding(t, "audit tenant export stream", tenantFindings, false)
	assertNoCanary(t, "audit tenant export stream", tenant.Bytes())
	var instance bytes.Buffer
	if err := e.audits.InstanceExport(tctx(t), e.admin, store.AuditFilter{}, 1, &instance); err != nil {
		t.Fatalf("SS4 sweep: instance audit export: %v", err)
	}
	_, instanceRecords := assertFindingKeysClosed(t, "audit instance export stream", instance.Bytes())
	if instanceRecords == 0 {
		t.Fatal("SS4 sweep: the instance audit export produced no records; the surface is vacuous")
	}
	assertNoCanary(t, "audit instance export stream", instance.Bytes())
}

// sweep ids are prefixed UUIDs because the HTTP contract validates the path
// parameters (short service-layer fixture ids do not satisfy it).
const (
	sweepOrgName = "sweep-org"
	sweepProject = "prj_0193f0b4-1f2a-7c31-9c1e-2a4b6d8e0aaa"
	sweepEnvID   = "env_0193f0b4-1f2a-7c31-9c1e-2a4b6d8e0bbb"
)

func newSweepEnv(t *testing.T, db *store.DB) sweepEnv {
	t.Helper()
	rs, err := scanning.Load()
	if err != nil {
		t.Fatalf("load ruleset: %v", err)
	}
	kr := probeKeyring(t, db)
	auth, boot, password := bootstrapWebAuthnAdminBoot(t, db)
	ctx := tctx(t)
	// A stepped-up passkey session — org creation and the tenant writes below are
	// MFA-mandatory, so a password-only session answers unauthorized.
	dev := webauthntest.New(waRPID, waOrigin)
	token := enrolPasskey(t, auth, ctx, boot.token, password, dev)
	token = stepUpPasskey(t, auth, ctx, token, dev)

	orgs := &service.Orgs{DB: db}
	org, err := orgs.Create(ctx, service.Bearer(token), sweepOrgName, true, []byte(`{}`))
	if err != nil {
		t.Fatalf("create org: %v", err)
	}

	// The administrator gets every capability the swept writes need, at org
	// scope, seeded directly as the harness seeds fixture grants elsewhere.
	for i, capability := range []string{"read", "edit", "publish", "definitions-edit", "manage-projects", "reveal", "audit-read"} {
		execRaw(t, db, fmt.Sprintf(
			"INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) VALUES ('grt_sweep_%d', '%s', '%s', '%s', NULL, NULL, %s)",
			i, boot.principal, capability, org.ID, ts))
	}
	// Instance-scope audit-read so the instance-trail export leg authorizes.
	execRaw(t, db, fmt.Sprintf(
		"INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) VALUES ('grt_sweep_iar', '%s', 'audit-read', NULL, NULL, NULL, %s)",
		boot.principal, ts))
	// Project and environment seeded directly with contract-valid ids.
	execRaw(t, db, fmt.Sprintf(
		"INSERT INTO projects (id, org_id, name, created_at) VALUES ('%s', '%s', 'sweep-project', %s)", sweepProject, org.ID, ts))
	execRaw(t, db, fmt.Sprintf(
		"INSERT INTO project_schema_revisions (org_id, project_id, revision) VALUES ('%s', '%s', 0)", org.ID, sweepProject))
	execRaw(t, db, fmt.Sprintf(
		"INSERT INTO environments (id, org_id, project_id, name, note, created_at, display_order) VALUES ('%s', '%s', '%s', 'sweep-env', '', %s, 0)",
		sweepEnvID, org.ID, sweepProject, ts))

	// A config key the value-warn surface writes to.
	keys := &service.Keys{DB: db, Keyring: kr, Scan: rs}
	scope := domain.Scope{Org: domain.OrgID(org.ID), Project: domain.ProjectID(sweepProject)}
	if _, err := keys.Create(ctx, service.LocalPrincipal(boot.principal), scope, service.KeySpec{
		Name: "CONFIG_KEY", Classification: "config", Declaration: stringDeclaration(), Presence: nonePresence()}, nil); err != nil {
		t.Fatalf("create config key: %v", err)
	}

	values := &service.Values{DB: db, Keyring: kr, Scan: rs, Auth: auth}
	srv := httptest.NewServer(server.New(&service.System{DB: db}, &server.API{
		Auth:         auth,
		Orgs:         orgs,
		Projects:     &service.Projects{DB: db},
		Environments: &service.Environments{DB: db, Keyring: kr, Scan: rs},
		Folders:      &service.Folders{DB: db, Keyring: kr, Scan: rs},
		Keys:         keys,
		Values:       values,
		Definitions:  &service.Definitions{DB: db, Keyring: kr, Advisory: service.NewAdvisory(), Scan: rs},
		Version:      "sweep",
	}, nil))
	t.Cleanup(srv.Close)

	stateDir := t.TempDir()
	writeTrustStore(t, stateDir, srv.URL)

	return sweepEnv{
		srv: srv, token: token, admin: boot.principal,
		audits: &service.Audits{DB: db},
		org:    org.ID, project: sweepProject, env: sweepEnvID,
		stateDir: stateDir,
	}
}

// base is the project path prefix on the wire.
func (e sweepEnv) base() string {
	return api.PathPrefix + "/orgs/" + e.org + "/projects/" + e.project
}

// call issues one request and returns the status plus the RAW response bytes.
func (e sweepEnv) call(t *testing.T, method, path string, body any) (int, []byte) {
	t.Helper()
	var payload io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		payload = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, e.srv.URL+path, payload)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+e.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := e.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, out
}

// runCLI drives the real CLI against the live server through the trust store,
// returning captured stdout and stderr.
func (e sweepEnv) runCLI(t *testing.T, args ...string) (string, string) {
	t.Helper()
	var stdout, stderr strings.Builder
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte(e.token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ios := cli.IO{
		Stdout:  &stdout,
		Stderr:  &stderr,
		Workdir: t.TempDir(),
		Env: cli.Env{Getenv: func(k string) string {
			if k == "HIKYO_STATE_DIR" {
				return e.stateDir
			}
			return ""
		}},
	}
	cli.Run(t.Context(), ios, append(args, "--token-file", tokenFile))
	return stdout.String(), stderr.String()
}
