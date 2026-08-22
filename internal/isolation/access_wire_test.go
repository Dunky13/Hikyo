package isolation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/Hikyo-Org/hikyo/api"
	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/server"
	"github.com/Hikyo-Org/hikyo/internal/service"
	"github.com/Hikyo-Org/hikyo/internal/store"
	"github.com/Hikyo-Org/hikyo/internal/store/authn"
	"github.com/Hikyo-Org/hikyo/internal/store/pggen"
	"github.com/Hikyo-Org/hikyo/internal/store/sqlitegen"
	"github.com/Hikyo-Org/hikyo/internal/store/tx"
	"github.com/Hikyo-Org/hikyo/internal/webauthntest"
)

// mvp-boundary A2's uniformity arm through the REAL STACK, both engines.
//
// The stub-based contract test (internal/server) proves that two identical
// sentinels render identical bytes — that is the transport's job and it is
// worth pinning — but it cannot prove that a genuinely missing scope and a
// genuinely unauthorized-but-existing scope PRODUCE the same sentinel, because
// it never runs the service or the store. The formula matrix has the opposite
// gap: it calls Authorize directly and never renders anything.
//
// This closes the seam: one bootstrapped instance, one stepped-up session, the
// real services behind a real router, and the pair driven end to end.

// accessWireEnv is the assembled real stack for these tests.
type accessWireEnv struct {
	srv   *httptest.Server
	token string
	db    *store.DB
	auth  *service.Auth
	admin domain.PrincipalID
	org   string
	// project and env genuinely EXIST under org. They are what makes the
	// "unauthorized" leg unauthorized-and-existing rather than a second kind
	// of missing: probing a child of a real org that the caller may not reach
	// is the case the acceptance row is about.
	project string
	env     string
}

// newAccessWireEnv bootstraps an administrator, steps it up to a
// WebAuthn-backed session (the grant routes are MFA-mandatory, so a
// password-only session would answer 403 and drown the comparison), creates an
// org, and hands back a live server.
func newAccessWireEnv(t *testing.T, db *store.DB) accessWireEnv {
	t.Helper()
	auth, boot, password := bootstrapWebAuthnAdminBoot(t, db)
	ctx := t.Context()
	dev := webauthntest.New(waRPID, waOrigin)
	token := enrolPasskey(t, auth, ctx, boot.token, password, dev)
	token = stepUpPasskey(t, auth, ctx, token, dev)

	orgs := &service.Orgs{DB: db}
	org, err := orgs.Create(ctx, service.Bearer(token), "wire-org", true, []byte(`{}`))
	if err != nil {
		t.Fatalf("create org: %v", err)
	}
	// Creation granted this principal org-admin access and therefore killed the
	// creating session. Re-login and present the already-enrolled passkey before
	// the wire assertions begin.
	login, err := auth.LocalLogin(ctx, waAdmin, password, service.ArtifactCLI)
	if err != nil {
		t.Fatalf("login after org create: %v", err)
	}
	token = stepUpPasskey(t, auth, ctx, login.SessionToken, dev)

	// The project and environment are seeded directly, as the harness seeds
	// every other fixture row. Creating them through the API would mean first
	// re-authenticating after the creator-admin grant invalidated the creating
	// session — churn that changes nothing about the property under test, which
	// is only that the object EXISTS when the refused leg addresses it.
	const (
		wireProject = "prj_0193f0b4-1f2a-7c31-9c1e-2a4b6d8e0fdd"
		wireEnv     = "env_0193f0b4-1f2a-7c31-9c1e-2a4b6d8e0fcc"
	)
	execRaw(t, db, fmt.Sprintf(
		`INSERT INTO projects (id, org_id, name, created_at) VALUES ('%s', '%s', 'wire-project', %s)`,
		wireProject, org.ID, ts))
	execRaw(t, db, fmt.Sprintf(
		`INSERT INTO environments (id, org_id, project_id, name, note, created_at, display_order) `+
			`VALUES ('%s', '%s', '%s', 'wire-env', '', %s, 0)`,
		wireEnv, org.ID, wireProject, ts))

	srv := httptest.NewServer(server.New(&service.System{DB: db}, &server.API{
		Auth:         auth,
		Orgs:         orgs,
		Projects:     &service.Projects{DB: db},
		Environments: &service.Environments{DB: db, Keyring: probeKeyring(t, db)},
		Folders:      &service.Folders{DB: db},
		Grants:       &service.Grants{DB: db},
		Settings:     &service.ProjectSettings{DB: db, Auth: auth},
		Delivery:     &service.Delivery{DB: db, Keyring: auth.Keyring},
		SCIMWire:     &service.SCIM{DB: db},
		Version:      "wire",
	}, nil))
	t.Cleanup(srv.Close)
	return accessWireEnv{
		srv: srv, token: token, db: db, auth: auth, admin: boot.principal,
		org: org.ID, project: wireProject, env: wireEnv,
	}
}

// bootstrapWebAuthnAdminBoot is bootstrapWebAuthnAdmin plus the principal id,
// which these tests need to revoke the administrator's own authority.
type bootInfo struct {
	token     string
	principal domain.PrincipalID
}

func bootstrapWebAuthnAdminBoot(t *testing.T, db *store.DB) (*service.Auth, bootInfo, string) {
	t.Helper()
	auth := webauthnAuthService(t, db)
	ctx := t.Context()
	boot, err := auth.BootstrapAdmin(ctx, waAdmin, "WA Admin", "terminal")
	if err != nil {
		t.Fatal(err)
	}
	const password = "a perfectly ordinary wire passphrase"
	if err := auth.EstablishCredential(ctx, boot.Authority, password); err != nil {
		t.Fatal(err)
	}
	login, err := auth.LocalLogin(ctx, waAdmin, password, service.ArtifactCLI)
	if err != nil {
		t.Fatal(err)
	}
	return auth, bootInfo{token: login.SessionToken, principal: boot.PrincipalID}, password
}

// call issues one request against the live server and returns status + body.
func (e accessWireEnv) call(t *testing.T, method, path string, body any) (int, []byte) {
	return e.callAs(t, e.token, method, path, body)
}

func (e accessWireEnv) callAs(t *testing.T, token, method, path string, body any) (int, []byte) {
	t.Helper()
	var payload io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		payload = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(t.Context(), method, e.srv.URL+path, payload)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
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

func TestAccessWireUniformitySQLite(t *testing.T) {
	runAccessWireUniformity(t, seededDB(t, openSQLite))
}
func TestAccessWireUniformityPostgres(t *testing.T) {
	runAccessWireUniformity(t, seededDB(t, openPostgres))
}

// runAccessWireUniformity drives the pair the acceptance criterion names, for
// every new access route: a scope that does not exist, and a scope that does
// exist and the caller may not reach. Both must answer the same status and the
// same bytes, and neither may carry a count or an items member.
//
// The unauthorized leg is produced by removing the administrator's own
// instance `manage-members` by raw SQL — the lockout invariant refuses to do
// it through the API, correctly, and there is no other way to make a
// bootstrapped administrator unauthorized over an org that exists.
func runAccessWireUniformity(t *testing.T, db *store.DB) {
	e := newAccessWireEnv(t, db)

	// Prove the routes WORK first, or "both answered 404" would be satisfied
	// by a surface that is simply broken.
	if code, body := e.call(t, http.MethodGet, api.PathPrefix+"/orgs/"+e.org+"/grants", nil); code != http.StatusOK {
		t.Fatalf("positive control: listing the org's grants = %d %s", code, body)
	}
	if code, body := e.call(t, http.MethodGet, api.PathPrefix+"/instance/grants", nil); code != http.StatusOK {
		t.Fatalf("positive control: listing instance grants = %d %s", code, body)
	}

	// Strip the creator's automatic org-admin grants and their instance member
	// management. Every access route below is then a genuine grant refusal
	// against an org that genuinely exists.
	clearOrgGrants(t, db, e.org)
	stripMemberManagement(t, db, e.admin)

	// Contract-shaped ids: an id outside the ID pattern is refused on SHAPE,
	// before any tenant resolution, which is a different (and also correct)
	// uniformity story than the one under test here.
	const missingOrg = "org_0193f0b4-1f2a-7c31-9c1e-2a4b6d8e0fee"
	grantBody := map[string]string{"principal": string(e.admin), "capability": "read"}
	templateBody := map[string]string{"principal": string(e.admin), "template": "viewer"}
	revokeQuery := "?principal=" + string(e.admin) + "&capability=read"

	// Every access route, paired. The `refused` leg addresses objects that
	// GENUINELY EXIST (the org, project and environment created in setup) and
	// that the caller may no longer reach; the `missing` leg addresses the
	// same shape under an org that was never created. The two must be
	// indistinguishable.
	org := "/orgs/" + e.org
	proj := org + "/projects/" + e.project
	env := proj + "/environments/" + e.env
	gone := "/orgs/" + missingOrg
	goneProj := gone + "/projects/" + e.project
	goneEnv := goneProj + "/environments/" + e.env

	for _, route := range []struct {
		name             string
		method           string
		refused, missing string
		body             any
	}{
		{"list_org_grants", http.MethodGet, org + "/grants", gone + "/grants", nil},
		{"create_org_grant", http.MethodPost, org + "/grants", gone + "/grants", grantBody},
		{"revoke_org_grant", http.MethodDelete, org + "/grants" + revokeQuery, gone + "/grants" + revokeQuery, nil},
		{"apply_org_template", http.MethodPost, org + "/grants/template", gone + "/grants/template", templateBody},

		{"list_project_grants", http.MethodGet, proj + "/grants", goneProj + "/grants", nil},
		{"create_project_grant", http.MethodPost, proj + "/grants", goneProj + "/grants", grantBody},
		{"revoke_project_grant", http.MethodDelete, proj + "/grants" + revokeQuery, goneProj + "/grants" + revokeQuery, nil},
		{"apply_project_template", http.MethodPost, proj + "/grants/template", goneProj + "/grants/template", templateBody},

		{"create_env_grant", http.MethodPost, env + "/grants", goneEnv + "/grants", grantBody},
		{"revoke_env_grant", http.MethodDelete, env + "/grants" + revokeQuery, goneEnv + "/grants" + revokeQuery, nil},
		{"apply_env_template", http.MethodPost, env + "/grants/template", goneEnv + "/grants/template", templateBody},

		{"env_settings_read", http.MethodGet, env + "/settings", goneEnv + "/settings", nil},
		{"env_settings_update", http.MethodPut, env + "/settings", goneEnv + "/settings", map[string]any{"protected": true}},
	} {
		t.Run(route.name, func(t *testing.T) {
			refusedCode, refusedBody := e.call(t, route.method, api.PathPrefix+route.refused, route.body)
			missingCode, missingBody := e.call(t, route.method, api.PathPrefix+route.missing, route.body)
			if refusedCode != http.StatusNotFound || missingCode != http.StatusNotFound {
				t.Fatalf("statuses %d (unauthorized, existing) and %d (nonexistent), want both 404\n  %s\n  %s",
					refusedCode, missingCode, refusedBody, missingBody)
			}
			if !bytes.Equal(refusedBody, missingBody) {
				t.Fatalf("bodies differ:\n  unauthorized: %s\n  nonexistent:  %s", refusedBody, missingBody)
			}
			// Counts leak nothing: a refused bulk read must not answer with an
			// empty page, which would confirm both that the scope exists and
			// that the caller may enumerate it.
			for _, member := range []string{`"count"`, `"items"`} {
				if bytes.Contains(refusedBody, []byte(member)) {
					t.Errorf("the refusal carried a %s member: %s", member, refusedBody)
				}
			}
		})
	}
}

func TestAccessWireQueryTraceSQLite(t *testing.T) {
	runAccessWireQueryTrace(t, seededDB(t, openSQLite))
}
func TestAccessWireQueryTracePostgres(t *testing.T) {
	runAccessWireQueryTrace(t, seededDB(t, openPostgres))
}

// runAccessWireQueryTrace is the STRUCTURAL timing control for the new
// operations (A3: wall-clock equality explicitly not asserted), measured
// through the REAL SERVICE PATH — the same entry the HTTP handler calls, with
// the same bearer artifact, so session resolution and everything else the
// request does is inside the measurement.
//
// Two properties, and they are the whole of the control:
//
//   - every MISS costs the same, whichever level is missing. A per-level walk
//     would make a missing environment cost more than a missing org, and a
//     caller could count its way to which level exists.
//   - a DENIAL against an object that exists costs exactly one query more —
//     the grant lookup, which a miss skips. That difference is structural and
//     is the residual the tenant-isolation ADR already accepts.
func runAccessWireQueryTrace(t *testing.T, db *store.DB) {
	e := newAccessWireEnv(t, db)
	clearOrgGrants(t, db, e.org)
	stripMemberManagement(t, db, e.admin)

	grants := &service.Grants{DB: db}
	settings := &service.ProjectSettings{DB: db, Auth: &service.Auth{DB: db}}
	actor := service.Bearer(e.token)
	const missingOrg = "org_0193f0b4-1f2a-7c31-9c1e-2a4b6d8e0fee"

	missOrg := domain.Scope{Org: domain.OrgID(missingOrg)}
	missProject := domain.Scope{Org: domain.OrgID(e.org), Project: "prj_0193f0b4-1f2a-7c31-9c1e-2a4b6d8e0f00"}
	missEnv := domain.Scope{
		Org: domain.OrgID(e.org), Project: domain.ProjectID(e.project),
		Env: "env_0193f0b4-1f2a-7c31-9c1e-2a4b6d8e0f00",
	}
	realOrg := domain.Scope{Org: domain.OrgID(e.org)}
	realProject := domain.Scope{Org: domain.OrgID(e.org), Project: domain.ProjectID(e.project)}
	realEnv := domain.Scope{
		Org: domain.OrgID(e.org), Project: domain.ProjectID(e.project), Env: domain.EnvID(e.env),
	}

	list := func(scope domain.Scope) func() error {
		return func() error { _, err := grants.List(t.Context(), actor, scope); return err }
	}
	create := func(scope domain.Scope) func() error {
		return func() error {
			_, err := grants.Create(t.Context(), actor, service.GrantSpec{
				Target: e.admin, Capability: domain.CapRead, Scope: scope,
			})
			return err
		}
	}
	readSettings := func(scope domain.Scope) func() error {
		return func() error { _, err := settings.GetEnvironment(t.Context(), actor, scope); return err }
	}

	// The baseline is a miss at the shallowest level. Everything else is
	// compared to it rather than to a hardcoded number, because the absolute
	// count includes session resolution and would move for reasons that have
	// nothing to do with the property.
	base := serviceQueryCount(t, list(missOrg))

	for _, tc := range []struct {
		name string
		run  func() error
		want int
	}{
		{"grant_list_missing_org", list(missOrg), base},
		{"grant_list_missing_project", list(missProject), base},
		{"grant_create_missing_env", create(missEnv), base},
		{"settings_read_missing_env", readSettings(missEnv), base},

		{"grant_list_denied_existing_org", list(realOrg), base + 1},
		{"grant_list_denied_existing_project", list(realProject), base + 1},
		{"grant_create_denied_existing_env", create(realEnv), base + 1},
		{"settings_read_denied_existing_env", readSettings(realEnv), base + 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n := serviceQueryCount(t, tc.run)
			if n != tc.want {
				t.Fatalf("the service path issued %d queries, want %d (miss baseline %d)", n, tc.want, base)
			}
		})
	}
}

// serviceQueryCount runs one real service call and returns the number of
// queries the resolution surface issued. On a REFUSED call that is the whole
// request: authorization runs before any store call, so a call that does not
// authorize issues nothing else — which is exactly the class of call this
// control measures. It also asserts the call was in fact refused, so a
// mis-set-up case cannot pass by succeeding cheaply.
func serviceQueryCount(t *testing.T, run func() error) int {
	t.Helper()
	var n int
	restore := authn.SetQueryObserver(func(string) { n++ })
	defer restore()
	if err := run(); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("outcome = %v, want the uniform nonexistent response", err)
	}
	return n
}

// stripMemberManagement removes all of a principal's `manage-members` grants by raw
// SQL. The lockout invariant refuses to do it through the API — correctly —
// and there is no other way to make a bootstrapped administrator unauthorized
// over an org that genuinely exists. This includes the org-scoped grant
// creation now supplies automatically.
func stripMemberManagement(t *testing.T, db *store.DB, p domain.PrincipalID) {
	t.Helper()
	execRaw(t, db, `DELETE FROM grant_origins WHERE grant_id IN (`+
		`SELECT id FROM grants WHERE principal_id = '`+string(p)+`' AND capability = 'manage-members')`)
	execRaw(t, db, `DELETE FROM grants WHERE principal_id = '`+string(p)+`' AND capability = 'manage-members'`)
}

func TestProjectListingDoesNotReadSiblingsSQLite(t *testing.T) {
	runProjectListingDoesNotReadSiblings(t, seededDB(t, openSQLite))
}
func TestProjectListingDoesNotReadSiblingsPostgres(t *testing.T) {
	runProjectListingDoesNotReadSiblings(t, seededDB(t, openPostgres))
}

// runProjectListingDoesNotReadSiblings catches the overfetch directly: a
// project-scoped membership read must not grow with membership in SIBLING
// projects of the same org. Reading the org's rows and filtering in Go passes
// every byte-shape assertion while doing work — and materializing
// administrative data — proportional to projects the caller was never
// authorized to see.
//
// The assertion is on the ROWS THE DATASTORE RETURNED, not on the query count:
// the overfetch is one query either way, so a query-count trace cannot see it.
func runProjectListingDoesNotReadSiblings(t *testing.T, db *store.DB) {
	read := func() int {
		t.Helper()
		var n int
		err := tx.Write(t.Context(), db, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
			lines, err := az.GrantLinesInProject(ctx, string(orgA), string(prjA1))
			n = len(lines)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	before := read()

	// Twenty grants in a SIBLING project of the same org. A listing scoped to
	// prj_a1 must not notice.
	for i := range 20 {
		id := fmt.Sprintf("g_sib_%02d", i)
		principal := fmt.Sprintf("usr_sib_%02d", i)
		execRaw(t, db, fmt.Sprintf(
			`INSERT INTO principals (id, kind, created_at) VALUES ('%s', 'human', %s)`, principal, ts))
		execRaw(t, db, fmt.Sprintf(
			`INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) `+
				`VALUES ('%s', '%s', 'read', 'org_a', 'prj_a2', NULL, %s)`, id, principal, ts))
		execRaw(t, db, fmt.Sprintf(
			`INSERT INTO grant_origins (id, grant_id, kind, subject, created_at) `+
				`VALUES ('gor_%s', '%s', 'manual', '%s', %s)`, id, id, principal, ts))
	}

	if after := read(); after != before {
		t.Fatalf("the project listing returned %d rows before and %d after 20 grants landed in a SIBLING project — "+
			"the query is not project-constrained, so work and disclosure scale with projects the caller cannot reach",
			before, after)
	}
	// The org listing DOES see them, which proves the sibling rows exist and
	// the assertion above is not passing because the seeding silently failed.
	var orgLines int
	if err := tx.Write(t.Context(), db, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		lines, err := az.GrantLinesInOrg(ctx, string(orgA))
		orgLines = len(lines)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if orgLines < before+20 {
		t.Fatalf("the org listing saw %d rows, want at least %d — the sibling seeding did not land", orgLines, before+20)
	}
}

// countedAuthorizeOp is countedAuthorize for an arbitrary operation.
func countedAuthorizeOp(t *testing.T, db *store.DB, principal domain.PrincipalID, op authz.Operation, scope domain.Scope) (int, error) {
	t.Helper()
	ctx := t.Context()
	count := 0
	tok := authz.NewTxToken()
	defer tok.Invalidate()

	var r *authn.Resolver
	if db.Engine() == store.EnginePostgres {
		pgtx, err := db.PG().BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = pgtx.Rollback(ctx) }()
		var dbtx pggen.DBTX = countingPGTx{tx: pgtx, n: &count}
		r = authn.NewPG(dbtx)
	} else {
		sqtx, err := db.SQLiteRead().BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = sqtx.Rollback() }()
		var dbtx sqlitegen.DBTX = countingSqliteTx{tx: sqtx, n: &count}
		r = authn.NewSQLite(dbtx)
	}
	_, err := authz.NewTxAuthorizer(r, tok).Authorize(ctx, authz.Identity{Principal: principal}, op, scope)
	return count, err
}

// TestQueryObserverIsTestOnly pins the claim each observation seam's own doc
// comment makes: no production call site. A production caller
// would install a global mutable on the resolution surface and pay a callback
// on every query — a real cost and a real shared-state hazard, for a hook that
// exists only so the acceptance suite can measure the service path.
func TestQueryObserverIsTestOnly(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		// The declaration itself lives in the package that owns the seam;
		// every other non-test mention is a production call site.
		for seam, home := range map[string]string{
			"SetQueryObserver":     filepath.Join("internal", "store", "authn", "authn.go"),
			"SetSCIMPhaseObserver": filepath.Join("internal", "service", "scim.go"),
		} {
			if bytes.Contains(body, []byte(seam)) && !strings.HasSuffix(path, home) {
				t.Errorf("%s names %s outside a test — the seam is test-only", path, seam)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
