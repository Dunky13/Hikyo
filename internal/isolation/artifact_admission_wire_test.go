package isolation

import (
	"bytes"
	"net/http"
	"testing"

	"github.com/Hikyo-Org/hikyo/api"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/service"
	"github.com/Hikyo-Org/hikyo/internal/store"
)

func TestArtifactClassAdmissionWireSQLite(t *testing.T) {
	runArtifactClassAdmissionWire(t, seededDB(t, openSQLite))
}

func TestArtifactClassAdmissionWirePostgres(t *testing.T) {
	runArtifactClassAdmissionWire(t, seededDB(t, openPostgres))
}

func runArtifactClassAdmissionWire(t *testing.T, db *store.DB) {
	e := newAccessWireEnv(t, db)
	const missingEnv = "env_0193f0b4-1f2a-7c31-9c1e-2a4b6d8e0fab"
	missingPath := api.PathPrefix + "/orgs/" + e.org + "/projects/" + e.project +
		"/environments/" + missingEnv
	missingCode, missingBody := e.call(t, http.MethodGet, missingPath, nil)
	if missingCode != http.StatusNotFound {
		t.Fatalf("nonexistent control = %d %s, want 404", missingCode, missingBody)
	}

	identities := &service.Identities{DB: db, Auth: e.auth}
	projectScope := domain.Scope{Org: domain.OrgID(e.org), Project: domain.ProjectID(e.project)}
	envScope := domain.Scope{Org: domain.OrgID(e.org), Project: domain.ProjectID(e.project), Env: domain.EnvID(e.env)}
	// Org bootstrap grants cover the hierarchy and membership surfaces, but
	// machine-identity administration is deliberately separate.
	execRaw(t, db, `INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) VALUES (`+
		`'g_artifact_admin', '`+string(e.admin)+`', 'manage-identities', '`+e.org+`', '`+e.project+`', NULL, `+ts+`)`)
	execRaw(t, db, `INSERT INTO grant_origins (id, grant_id, kind, subject, created_at) VALUES (`+
		`'gor_artifact_admin', 'g_artifact_admin', 'manual', '`+string(e.admin)+`', `+ts+`)`)
	sa, err := identities.CreateServiceAccount(t.Context(), service.Bearer(e.token),
		projectScope, "artifact-probe", domain.ClassWorkload)
	if err != nil {
		t.Fatalf("create machine identity: %v", err)
	}
	minted, err := identities.MintCredential(t.Context(), service.Bearer(e.token),
		projectScope, sa.ID, service.MintRequest{})
	if err != nil {
		t.Fatalf("mint machine credential: %v", err)
	}
	if _, err := (&service.Grants{DB: db, Auth: e.auth}).Create(t.Context(), service.Bearer(e.token),
		service.GrantSpec{Target: sa.Principal, Capability: domain.CapRead, Scope: envScope}); err != nil {
		t.Fatalf("grant machine read: %v", err)
	}

	refusedEvents := func() int64 {
		return queryInt(t, db, `SELECT COUNT(*) FROM audit_instance_events WHERE type = 'auth.artifact_class_refused'`)
	}
	before := refusedEvents()
	seedSCIMProvider(t, db, "artifact-admission", "https://artifact-admission.example.test", true)
	scim := &service.SCIM{DB: db}
	binding, err := scim.CreateBinding(t.Context(), service.LocalPrincipal(e.admin), domain.OrgID(e.org), service.SCIMBindingInput{
		ProviderKind: domain.ProviderOIDC, ProviderSlug: "artifact-admission",
		SubjectSource: domain.SubjectSourceExternalID,
	})
	if err != nil {
		t.Fatalf("create SCIM binding: %v", err)
	}
	scimMint, err := scim.MintCredential(t.Context(), service.LocalPrincipal(e.admin), domain.OrgID(e.org), binding.ID, false, "")
	if err != nil {
		t.Fatalf("mint SCIM credential: %v", err)
	}
	bindingID, scimToken := binding.ID, scimMint.Token

	// Machine credential has enough authority for this existing environment;
	// only the operation's human-session declaration may refuse it.
	humanOnlyPath := api.PathPrefix + "/orgs/" + e.org + "/projects/" + e.project +
		"/environments/" + e.env
	machineCode, machineBody := e.callAs(t, minted.Value, http.MethodGet, humanOnlyPath, nil)
	if machineCode != missingCode || !bytes.Equal(machineBody, missingBody) {
		t.Fatalf("machine on human-only route = %d %s, want nonexistent control %d %s",
			machineCode, machineBody, missingCode, missingBody)
	}

	// Operation-less account and self-scoped services still receive the exact
	// OpenAPI row from HTTP admission. Their authentication doors must resolve
	// the machine identity before applying that row, rather than rejecting its
	// bearer grammar early with a distinguishable 401.
	for _, path := range []string{
		api.PathPrefix + "/auth/whoami",
		api.PathPrefix + "/me/orgs",
	} {
		code, body := e.callAs(t, minted.Value, http.MethodGet, path, nil)
		if code != missingCode || !bytes.Equal(body, missingBody) {
			t.Fatalf("machine on human-only route %s = %d %s, want nonexistent control %d %s",
				path, code, body, missingCode, missingBody)
		}
	}

	// A provisioning credential presented to an ordinary Hikyo route must be
	// classified after live resolution, then refused by that route's
	// human-session declaration.
	scimOnHumanCode, scimOnHumanBody := e.callAs(t, scimToken, http.MethodGet, humanOnlyPath, nil)
	if scimOnHumanCode != missingCode || !bytes.Equal(scimOnHumanBody, missingBody) {
		t.Fatalf("SCIM credential on human-only route = %d %s, want nonexistent control %d %s",
			scimOnHumanCode, scimOnHumanBody, missingCode, missingBody)
	}

	// The reverse direction crosses the SCIM transport. Compare against a real
	// missing SCIM resource so both responses use the protocol's own uniform
	// 404 envelope rather than comparing two wire dialects.
	missingSCIMPath := api.PathPrefix + "/orgs/" + e.org + "/scim/v2/" + bindingID +
		"/Users/scim_0193f0b4-1f2a-7c31-9c1e-2a4b6d8e0fab"
	missingSCIMCode, missingSCIMBody := e.callAs(t, scimToken, http.MethodGet, missingSCIMPath, nil)
	if missingSCIMCode != http.StatusNotFound {
		t.Fatalf("missing SCIM control = %d %s, want 404", missingSCIMCode, missingSCIMBody)
	}
	scimOnlyPath := api.PathPrefix + "/orgs/" + e.org + "/scim/v2/" + bindingID + "/ServiceProviderConfig"
	humanOnSCIMCode, humanOnSCIMBody := e.callAs(t, e.token, http.MethodGet, scimOnlyPath, nil)
	if humanOnSCIMCode != missingSCIMCode || !bytes.Equal(humanOnSCIMBody, missingSCIMBody) {
		t.Fatalf("human on SCIM-only route = %d %s, want nonexistent control %d %s",
			humanOnSCIMCode, humanOnSCIMBody, missingSCIMCode, missingSCIMBody)
	}

	// delivery.fetch is machine-only. A human with read authority receives the
	// same nonexistent wire response, before delivery can materialize anything.
	machineOnlyPath := humanOnlyPath + "/delivery"
	humanCode, humanBody := e.call(t, http.MethodGet, machineOnlyPath, nil)
	if humanCode != missingCode || !bytes.Equal(humanBody, missingBody) {
		t.Fatalf("human on machine-only route = %d %s, want nonexistent control %d %s",
			humanCode, humanBody, missingCode, missingBody)
	}

	if got := refusedEvents() - before; got != 6 {
		t.Fatalf("artifact mismatches wrote %d named authentication events, want 6", got)
	}
}
