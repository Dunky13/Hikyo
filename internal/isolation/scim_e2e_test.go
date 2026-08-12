package isolation

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/Dunky13/hikyo/internal/domain"
	"github.com/Dunky13/hikyo/internal/scimproto"
	"github.com/Dunky13/hikyo/internal/service"
	"github.com/Dunky13/hikyo/internal/store"
)

// SCIM provisioning end-to-end (#73). Every fixture below names the ADR clause
// it proves; a clause without a fixture is a CI failure of the criteria matrix
// itself, so nothing here is a catch-all "full conversation" test.
//
// These run at the SERVICE layer, which is the chokepoint under test: every
// store call goes through authorize() and there is no test-only mint hook.

func scimSvc(db *store.DB) *service.SCIM { return &service.SCIM{DB: db} }

// seedSCIMProvider inserts the instance-configured provider a binding
// references. Provider configuration is instance-scoped under an instance
// capability; a binding holds a READ-ONLY reference to it (§1).
func seedSCIMProvider(t *testing.T, db *store.DB, slug, issuer string, enabled bool) {
	t.Helper()
	// `enabled` is an integer flag on BOTH engines (00007's postgres dialect
	// keeps it BIGINT, matching sqlite), so only the byte-string literal
	// differs. The fixture is raw SQL by design: it seeds instance
	// configuration that this ticket's surface only READS.
	secret := `X'00'`
	if db.PG() != nil {
		secret = `'\x00'::bytea`
	}
	on := "0"
	if enabled {
		on = "1"
	}
	execRaw(t, db, `INSERT INTO oidc_providers `+
		`(id, slug, display_name, kind, issuer, client_id, client_secret, scopes, redirect_uri, `+
		` enabled, dek_version, row_version, created_at, updated_at) VALUES `+
		`('idp_`+slug+`', '`+slug+`', '`+slug+`', 'oidc', '`+issuer+`', 'cid', `+secret+`, 'openid', `+
		`'https://example.test/cb', `+on+`, 1, 1, `+ts+`, `+ts+`)`)
}

// disableSCIMProvider flips the referenced provider off or back on.
func disableSCIMProvider(t *testing.T, db *store.DB, slug string, enabled bool) {
	t.Helper()
	v := "0"
	if enabled {
		v = "1"
	}
	execRaw(t, db, `UPDATE oidc_providers SET enabled = `+v+` WHERE slug = '`+slug+`'`)
}

// newSCIMBinding is the shared setup: a provider, a binding, and a live
// credential. It returns the binding id and the credential value, which exists
// exactly once and is never read back from storage.
func newSCIMBinding(t *testing.T, db *store.DB, slug string) (string, string) {
	t.Helper()
	s := scimSvc(db)
	seedSCIMProvider(t, db, slug, "https://"+slug+".example.test", true)
	binding, err := s.CreateBinding(t.Context(), service.LocalPrincipal(orgAdmin), orgA, service.SCIMBindingInput{
		ProviderKind:  domain.ProviderOIDC,
		ProviderSlug:  slug,
		SubjectSource: domain.SubjectSourceExternalID,
	})
	if err != nil {
		t.Fatalf("binding create: %v", err)
	}
	mint, err := s.MintCredential(t.Context(), service.LocalPrincipal(orgAdmin), orgA, binding.ID, false, "")
	if err != nil {
		t.Fatalf("credential mint: %v", err)
	}
	if !strings.HasPrefix(mint.Token, "hik_1_scim_") {
		t.Fatalf("credential does not carry the hik_<v>_scim_ grammar: %q", mint.Token[:12])
	}
	return binding.ID, mint.Token
}

// TestSCIMBindingLifecycle proves §1's tenancy rules and §7's structural grant.
func TestSCIMBindingLifecycleSQLite(t *testing.T) {
	runSCIMBindingLifecycle(t, seededDB(t, openSQLite))
}
func TestSCIMBindingLifecyclePostgres(t *testing.T) {
	runSCIMBindingLifecycle(t, seededDB(t, openPostgres))
}

func runSCIMBindingLifecycle(t *testing.T, db *store.DB) {
	s := scimSvc(db)
	ctx := t.Context()
	bindingID, token := newSCIMBinding(t, db, "okta")

	// §7: the provisioning connection holds `scim-provision` at its own org,
	// carrying the `structural(binding)` origin — the origin invariant holds
	// for it as for every other row.
	got := queryInt(t, db,
		`SELECT COUNT(*) FROM grants AS g INNER JOIN grant_origins AS o ON o.grant_id = g.id `+
			`WHERE g.capability = 'scim-provision' AND o.kind = 'structural' AND o.subject = '`+bindingID+`'`)
	if got != 1 {
		t.Fatalf("structural scim-provision grant: want 1 row, got %d", got)
	}

	// §1: at most one binding per (org, provider). The second create loses,
	// fails closed, and names the conflict rather than being reconciled.
	_, err := s.CreateBinding(ctx, service.LocalPrincipal(orgAdmin), orgA, service.SCIMBindingInput{
		ProviderKind: domain.ProviderOIDC, ProviderSlug: "okta",
		SubjectSource: domain.SubjectSourceExternalID,
	})
	if !errors.Is(err, store.ErrConflict) && !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate binding: want a named conflict, got %v", err)
	}

	// §5.1: `userName` is refused as a subject source BY NAME, at config time.
	seedSCIMProvider(t, db, "entra", "https://entra.example.test", true)
	_, err = s.CreateBinding(ctx, service.LocalPrincipal(orgAdmin), orgA, service.SCIMBindingInput{
		ProviderKind: domain.ProviderOIDC, ProviderSlug: "entra",
		SubjectSource: domain.SubjectSourceUserName,
	})
	if !errors.Is(err, service.ErrSCIMSubjectSource) {
		t.Fatalf("userName as subject source: want ErrSCIMSubjectSource, got %v", err)
	}

	// §8: the credential must match the binding IN THE PATH. A mismatch is an
	// authentication failure, never a SCIM 400.
	other, _ := newSCIMBinding(t, db, "keycloak")
	_, err = s.CreateUser(ctx, service.SCIMCredentialActor(token, other), orgA, other, service.SCIMUserInput{
		UserName: "wrong@example.test", SubjectRaw: "wrong",
	})
	if !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("credential vs wrong binding: want unauthenticated, got %v", err)
	}

	// §6: the deletion state machine. Credentials die first, so an in-flight
	// transaction fails at its next proof; the connection and its structural
	// grant are retired atomically with the directory and the binding row.
	if err := s.DeleteBinding(ctx, service.LocalPrincipal(orgAdmin), orgA, bindingID); err != nil {
		t.Fatalf("binding delete: %v", err)
	}
	if n := queryInt(t, db, `SELECT COUNT(*) FROM scim_bindings WHERE id = '`+bindingID+`'`); n != 0 {
		t.Fatalf("binding row survived deletion")
	}
	if n := queryInt(t, db,
		`SELECT COUNT(*) FROM grants WHERE capability = 'scim-provision'`); n != 1 {
		t.Fatalf("structural grant not retired with its binding (the other binding's should remain): got %d", n)
	}
	// The credential is dead: presenting it now is the uniform unauthenticated
	// answer, indistinguishable from an unknown one.
	_, err = s.GetUser(ctx, service.SCIMCredentialActor(token, bindingID), orgA, bindingID, "scu_none")
	if !errors.Is(err, domain.ErrUnauthenticated) && !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("credential after binding delete: want a uniform refusal, got %v", err)
	}
}

// TestSCIMUserLifecycle walks §5.4's transition table: create, attribute
// update, deactivate, reactivate, delete, re-create.
func TestSCIMUserLifecycleSQLite(t *testing.T)   { runSCIMUserLifecycle(t, seededDB(t, openSQLite)) }
func TestSCIMUserLifecyclePostgres(t *testing.T) { runSCIMUserLifecycle(t, seededDB(t, openPostgres)) }

func runSCIMUserLifecycle(t *testing.T, db *store.DB) {
	s := scimSvc(db)
	ctx := t.Context()
	bindingID, token := newSCIMBinding(t, db, "okta")
	wire := service.SCIMCredentialActor(token, bindingID)

	// §5.2: create makes an account with its external identity ALREADY BOUND,
	// and ZERO grants.
	user, err := s.CreateUser(ctx, wire, orgA, bindingID, service.SCIMUserInput{
		UserName: "dana@example.test", ExternalID: "ext-dana", SubjectRaw: "ext-dana",
	})
	if err != nil {
		t.Fatalf("user create: %v", err)
	}
	if n := queryInt(t, db, `SELECT COUNT(*) FROM external_identities WHERE subject = 'ext-dana'`); n != 1 {
		t.Fatalf("provisioned identity link: want 1, got %d", n)
	}
	if n := grantsForSCIMUser(t, db, bindingID, user.ID); n != 0 {
		t.Fatalf("a pushed user with no mapped groups must hold nothing; got %d grants", n)
	}

	// §5.2: idempotent ATTACH, no cross-org oracle. An identity that already
	// exists instance-wide — invited earlier, or provisioned by another org's
	// binding — is ATTACHED rather than duplicated, and the response is
	// byte-shape identical to a fresh create.
	//
	// The fixture is a prior invitation: an account and its identity link that
	// this binding never created, carrying the subject the IdP is about to
	// assert.
	execRaw(t, db, `INSERT INTO principals (id, kind, created_at) VALUES ('usr_invited', 'human', `+ts+`)`)
	execRaw(t, db, `INSERT INTO accounts (id, principal_id, username, display_name, created_at) `+
		`VALUES ('acc_invited', 'usr_invited', 'kim@example.test', 'Kim', `+ts+`)`)
	execRaw(t, db, `INSERT INTO external_identities (id, account_id, kind, issuer, subject, provider_id, credential_epoch, created_at) `+
		`VALUES ('eid_invited', 'acc_invited', 'oidc', 'https://okta.example.test', 'ext-kim', 'okta', 0, `+ts+`)`)

	attached, err := s.CreateUser(ctx, wire, orgA, bindingID, service.SCIMUserInput{
		UserName: "kim-scim@example.test", ExternalID: "ext-kim", SubjectRaw: "ext-kim",
	})
	if err != nil {
		t.Fatalf("attach create: %v", err)
	}
	if accountOf(t, db, attached.ID) != "acc_invited" {
		t.Fatalf("attach must reuse the existing account; got %q", accountOf(t, db, attached.ID))
	}
	if n := queryInt(t, db, `SELECT COUNT(*) FROM accounts WHERE display_name = 'kim-scim@example.test'`); n != 0 {
		t.Fatal("attach must not create a second account")
	}
	// #23's oracle criterion, asserted structurally: the two legs render the
	// same canonical shape, byte for byte, so nothing in the response says which
	// one happened.
	if got, want := userShape(attached), userShape(user); got != want {
		t.Fatalf("create and attach responses differ in shape:\n create: %s\n attach: %s", want, got)
	}

	// §5.1: the subject is WRITE-ONCE. A mutation that would move it is refused
	// by name — deprovision-and-recreate is the explicit path.
	_, err = s.ReplaceUser(ctx, wire, orgA, bindingID, user.ID, service.SCIMUserInput{
		UserName: "dana@example.test", ExternalID: "ext-dana-moved", SubjectRaw: "ext-dana-moved",
	})
	if !errors.Is(err, service.ErrSCIMSubjectWriteOnce) {
		t.Fatalf("subject change: want ErrSCIMSubjectWriteOnce, got %v", err)
	}

	// §5.4: an attribute update leaves grants untouched.
	if _, err := s.PatchUser(ctx, wire, orgA, bindingID, user.ID, service.SCIMUserInput{
		Attributes: map[string]any{"displayName": "Dana"},
	}); err != nil {
		t.Fatalf("user update: %v", err)
	}

	// §5.3, the ZERO-GRANT-DELTA fixture the acceptance row names by hand:
	// dana holds nothing, so deactivating her changes no grant row at all — and
	// the session generation MUST advance anyway, because the IdP has declared
	// this human gone and surviving sessions must re-prove. This is the one
	// assertion that distinguishes the ADR's unconditional rule from the
	// ordinary "advance when authority moved" gate every other release uses.
	principal := principalOf(t, db, accountOf(t, db, user.ID))
	generationBefore := queryInt(t, db,
		`SELECT session_generation FROM principals WHERE id = '`+string(principal)+`'`)
	grantsBefore := grantsForSCIMUser(t, db, bindingID, user.ID)

	// §5.4: `active: true -> false`, then `false -> true`. Reactivation is
	// DESIRED STATE, recreated from the current memberships and mapping rows.
	off := false
	if _, err := s.PatchUser(ctx, wire, orgA, bindingID, user.ID, service.SCIMUserInput{Active: &off}); err != nil {
		t.Fatalf("deprovision: %v", err)
	}
	if got := grantsForSCIMUser(t, db, bindingID, user.ID); got != grantsBefore {
		t.Fatalf("this fixture must have a zero grant delta; before=%d after=%d", grantsBefore, got)
	}
	generationAfter := queryInt(t, db,
		`SELECT session_generation FROM principals WHERE id = '`+string(principal)+`'`)
	if generationAfter <= generationBefore {
		t.Fatalf("deprovision must advance the session generation unconditionally: %d -> %d",
			generationBefore, generationAfter)
	}
	on := true
	if _, err := s.PatchUser(ctx, wire, orgA, bindingID, user.ID, service.SCIMUserInput{Active: &on}); err != nil {
		t.Fatalf("reactivate: %v", err)
	}

	// §5.4: DELETE removes the directory entry; the account and its identity
	// links SURVIVE, because they are instance-level and not this IdP's to kill.
	provisionedAccount := accountOf(t, db, user.ID)
	if err := s.DeleteUser(ctx, wire, orgA, bindingID, user.ID); err != nil {
		t.Fatalf("user delete: %v", err)
	}
	if n := queryInt(t, db, `SELECT COUNT(*) FROM external_identities WHERE subject = 'ext-dana'`); n != 1 {
		t.Fatalf("identity link must survive a SCIM delete; got %d", n)
	}
	if n := queryInt(t, db, `SELECT COUNT(*) FROM accounts WHERE id = '`+provisionedAccount+`'`); n != 1 {
		t.Fatalf("account must survive a SCIM delete; got %d", n)
	}
	// And the handle is OPAQUE: a binding-scoped userName must never become a
	// globally unique login handle, or two bindings pushing the same name for
	// two different humans collide — an existence oracle across orgs.
	if n := queryInt(t, db, `SELECT COUNT(*) FROM accounts WHERE username = 'dana@example.test'`); n != 0 {
		t.Fatalf("the SCIM userName must not be the account handle; got %d", n)
	}

	// §5.4: a re-create after DELETE gets a FRESH id, so a stale member
	// reference cannot exist.
	recreated, err := s.CreateUser(ctx, wire, orgA, bindingID, service.SCIMUserInput{
		UserName: "dana@example.test", ExternalID: "ext-dana", SubjectRaw: "ext-dana",
	})
	if err != nil {
		t.Fatalf("re-create: %v", err)
	}
	if recreated.ID == user.ID {
		t.Fatal("re-create reused the deleted resource id")
	}
}

// TestSCIMMappingReconciliation proves §2's overlap rules, §3's immediate
// application and blast warnings, and §4's hand-mutation refusal.
func TestSCIMMappingReconciliationSQLite(t *testing.T) {
	runSCIMMappingReconciliation(t, seededDB(t, openSQLite))
}
func TestSCIMMappingReconciliationPostgres(t *testing.T) {
	runSCIMMappingReconciliation(t, seededDB(t, openPostgres))
}

func runSCIMMappingReconciliation(t *testing.T, db *store.DB) {
	s := scimSvc(db)
	g := grantSvc(db)
	ctx := t.Context()
	bindingID, token := newSCIMBinding(t, db, "okta")
	wire := service.SCIMCredentialActor(token, bindingID)

	user, err := s.CreateUser(ctx, wire, orgA, bindingID, service.SCIMUserInput{
		UserName: "eve@example.test", ExternalID: "ext-eve", SubjectRaw: "ext-eve",
	})
	if err != nil {
		t.Fatal(err)
	}
	group, err := s.CreateGroup(ctx, wire, orgA, bindingID, service.SCIMGroupInput{
		DisplayName: "Engineering", Members: []string{user.ID}, MembersPresent: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	// §3: mapping create applies IMMEDIATELY to the group's ALREADY-POPULATED
	// membership, in the authoring transaction — no IdP round-trip, no gap.
	res, err := s.CreateMapping(ctx, service.LocalPrincipal(orgAdmin), orgA, bindingID, service.SCIMMappingSpec{
		GroupID: group.ID, Template: domain.TemplateViewer, ProjectID: string(prjA1),
	})
	if err != nil {
		t.Fatalf("mapping create: %v", err)
	}
	if res.MembersAffected != 1 || res.GrantsCreated == 0 {
		t.Fatalf("mapping create must grant to current members: %+v", res)
	}
	// §3: the blast-radius moment moved here, and the consequence language is
	// SERVER-AUTHORED — the already-populated group is named.
	if !hasWarning(res.Warnings, service.SCIMWarnPopulatedGroup) {
		t.Fatalf("populated-group warning missing: %+v", res.Warnings)
	}

	account := accountOf(t, db, user.ID)
	principal := principalOf(t, db, account)

	// §2: the origin carries (binding, mapping row, group) — the chip that
	// answers "why can they?" on the membership line.
	subject := res.Mapping.ID
	if n := queryInt(t, db,
		`SELECT COUNT(*) FROM grant_origins WHERE kind = 'scim' AND subject LIKE '%`+subject+`%'`); n == 0 {
		t.Fatal("no scim origin keyed on the mapping row")
	}

	// §4: revoking a grant whose only live origin is `scim` is REFUSED, naming
	// both remediations.
	err = g.Revoke(ctx, service.LocalPrincipal(orgAdmin), service.GrantSpec{
		Target: principal, Capability: domain.CapRead,
		Scope: domain.Scope{Org: orgA, Project: prjA1},
	})
	if !errors.Is(err, service.ErrSCIMOriginOnly) {
		t.Fatalf("hand-revoke of a SCIM-only grant: want ErrSCIMOriginOnly, got %v", err)
	}

	// §2: overlap is EXACT. A hand grant of the same triple joins the row as a
	// second origin, and revoking it removes the MANUAL origin only — the row
	// survives on the SCIM origin.
	if _, err := g.Create(ctx, service.LocalPrincipal(orgAdmin), service.GrantSpec{
		Target: principal, Capability: domain.CapRead,
		Scope: domain.Scope{Org: orgA, Project: prjA1},
	}); err != nil {
		t.Fatalf("overlap grant: %v", err)
	}
	if err := g.Revoke(ctx, service.LocalPrincipal(orgAdmin), service.GrantSpec{
		Target: principal, Capability: domain.CapRead,
		Scope: domain.Scope{Org: orgA, Project: prjA1},
	}); err != nil {
		t.Fatalf("dual-origin revoke must remove the manual origin only: %v", err)
	}
	if !held(t, db, principal, domain.CapRead, domain.Scope{Org: orgA, Project: prjA1}) {
		t.Fatal("the row must survive on its SCIM origin after a manual-origin revoke")
	}

	// §5.4: group membership removal releases EXACTLY that group's origins.
	if _, err := s.PatchGroup(ctx, wire, orgA, bindingID, group.ID, service.SCIMGroupInput{
		Members: nil, MembersPresent: true,
	}); err != nil {
		t.Fatalf("member removal: %v", err)
	}
	if held(t, db, principal, domain.CapRead, domain.Scope{Org: orgA, Project: prjA1}) {
		t.Fatal("removing the last group membership must release the grant")
	}

	// §5.4: group DELETE flips referencing mapping rows INERT with an
	// attention state, rather than deleting them behind the human's back.
	if err := s.DeleteGroup(ctx, wire, orgA, bindingID, group.ID); err != nil {
		t.Fatalf("group delete: %v", err)
	}
	if n := queryInt(t, db, `SELECT COUNT(*) FROM scim_mappings WHERE id = '`+res.Mapping.ID+`' AND inert = `+trueLit(db)); n != 1 {
		t.Fatal("the mapping row referencing a deleted group must flip inert, not vanish")
	}
	if n := queryInt(t, db, `SELECT COUNT(*) FROM scim_attention WHERE state = 'inert_mapping'`); n != 1 {
		t.Fatal("an inert mapping row must raise its attention state")
	}

	// §4: mapping delete reconciles in the AUTHORING transaction.
	if _, err := s.DeleteMapping(ctx, service.LocalPrincipal(orgAdmin), orgA, bindingID, service.SCIMMappingSpec{
		GroupID: group.ID, ProjectID: string(prjA1),
	}); err != nil {
		t.Fatalf("mapping delete: %v", err)
	}
}

// TestSCIMLockoutRetention proves §2.4: the SCIM-side release CONVERTS rather
// than refusing, and the cure releases the retention deterministically.
func TestSCIMLockoutRetentionSQLite(t *testing.T) {
	runSCIMLockoutRetention(t, seededDB(t, openSQLite))
}
func TestSCIMLockoutRetentionPostgres(t *testing.T) {
	runSCIMLockoutRetention(t, seededDB(t, openPostgres))
}

func runSCIMLockoutRetention(t *testing.T, db *store.DB) {
	s := scimSvc(db)
	g := grantSvc(db)
	ctx := t.Context()

	// The org census counts holders AT the org or ABOVE it, and bootstrap seeds
	// an instance-scope holder. Remove both existing holders so this org's LAST
	// manage-members grant can actually be the last one — the only state in
	// which the conversion is reachable at all.
	execRaw(t, db, `DELETE FROM grant_origins WHERE grant_id IN ('g_ro_mm', 'g_oa_mm')`)
	execRaw(t, db, `DELETE FROM grants WHERE id IN ('g_ro_mm', 'g_oa_mm')`)
	// orgAdmin needs manage-members back to administer the binding at all, and
	// it is instance-scope so it is NOT part of the org census this test drains.
	execRaw(t, db, `INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) `+
		`VALUES ('g_oa_mm2', 'usr_orgadmin', 'manage-members', 'org_a', NULL, NULL, `+ts+`)`)
	seedOrigins(t, db)

	bindingID, token := newSCIMBinding(t, db, "okta")
	wire := service.SCIMCredentialActor(token, bindingID)

	user, err := s.CreateUser(ctx, wire, orgA, bindingID, service.SCIMUserInput{
		UserName: "frank@example.test", ExternalID: "ext-frank", SubjectRaw: "ext-frank",
	})
	if err != nil {
		t.Fatal(err)
	}
	group, err := s.CreateGroup(ctx, wire, orgA, bindingID, service.SCIMGroupInput{
		DisplayName: "Admins", Members: []string{user.ID}, MembersPresent: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	// `admin` at org scope expands to manage-members among others.
	if _, err := s.CreateMapping(ctx, service.LocalPrincipal(orgAdmin), orgA, bindingID, service.SCIMMappingSpec{
		GroupID: group.ID, Template: domain.TemplateAdmin,
	}); err != nil {
		t.Fatalf("admin mapping: %v", err)
	}
	// Now drain the org of every other manage-members holder so the provisioned
	// user's grant is the last one.
	execRaw(t, db, `DELETE FROM grant_origins WHERE grant_id = 'g_oa_mm2'`)
	execRaw(t, db, `DELETE FROM grants WHERE id = 'g_oa_mm2'`)

	// The IdP withdraws the user from the group. A human revoke here would be
	// REFUSED; the SCIM release instead converts, so the IdP is never wedged.
	if _, err := s.PatchGroup(ctx, wire, orgA, bindingID, group.ID, service.SCIMGroupInput{
		Members: nil, MembersPresent: true,
	}); err != nil {
		t.Fatalf("member removal under lockout: %v", err)
	}
	if n := queryInt(t, db,
		`SELECT COUNT(*) FROM grant_origins WHERE kind = 'lockout-retention'`); n != 1 {
		t.Fatalf("want exactly one lockout-retention origin, got %d", n)
	}
	// Origin truth stays honest: the `scim` origin IS gone.
	if n := queryInt(t, db,
		`SELECT COUNT(*) FROM grant_origins AS o INNER JOIN grants AS g ON g.id = o.grant_id `+
			`WHERE o.kind = 'scim' AND g.capability = 'manage-members'`); n != 0 {
		t.Fatal("the scim origin must be released even when the row is retained")
	}
	if n := queryInt(t, db,
		`SELECT COUNT(*) FROM scim_attention WHERE state = 'lockout_retention'`); n != 1 {
		t.Fatal("the retention must raise its attention state")
	}

	// The cure: the moment the org gains another manage-members holder, that
	// SAME transaction releases the retention. Break-glass is the path back
	// into an org that has no member manager left — which is precisely the
	// state the retention exists to make survivable.
	if _, err := g.BreakGlassGrant(ctx, service.GrantSpec{
		Target: grantee, Capability: domain.CapManageMembers, Scope: orgAScope,
	}); err != nil {
		t.Fatalf("curing grant: %v", err)
	}
	if n := queryInt(t, db,
		`SELECT COUNT(*) FROM grant_origins WHERE kind = 'lockout-retention'`); n != 0 {
		t.Fatalf("the cure must release every retention it cures; %d remain", n)
	}
}

// TestSCIMProviderFailClosed proves §1: while the referenced provider is
// disabled or removed, the binding's ENTIRE wire surface refuses — read and
// write alike — state is preserved, and the attention state names it.
func TestSCIMProviderFailClosedSQLite(t *testing.T) {
	runSCIMProviderFailClosed(t, seededDB(t, openSQLite))
}
func TestSCIMProviderFailClosedPostgres(t *testing.T) {
	runSCIMProviderFailClosed(t, seededDB(t, openPostgres))
}

func runSCIMProviderFailClosed(t *testing.T, db *store.DB) {
	s := scimSvc(db)
	ctx := t.Context()
	bindingID, token := newSCIMBinding(t, db, "okta")
	wire := service.SCIMCredentialActor(token, bindingID)

	user, err := s.CreateUser(ctx, wire, orgA, bindingID, service.SCIMUserInput{
		UserName: "gil@example.test", ExternalID: "ext-gil", SubjectRaw: "ext-gil",
	})
	if err != nil {
		t.Fatal(err)
	}

	disableSCIMProvider(t, db, "okta", false)

	// Writes refuse.
	if _, err := s.CreateUser(ctx, wire, orgA, bindingID, service.SCIMUserInput{
		UserName: "hal@example.test", ExternalID: "ext-hal", SubjectRaw: "ext-hal",
	}); !errors.Is(err, service.ErrSCIMProviderUnavailable) {
		t.Fatalf("write under a disabled provider: want ErrSCIMProviderUnavailable, got %v", err)
	}
	// READS refuse too — the whole wire surface, not just the mutations.
	if _, err := s.GetUser(ctx, wire, orgA, bindingID, user.ID); !errors.Is(err, service.ErrSCIMProviderUnavailable) {
		t.Fatalf("read under a disabled provider: want ErrSCIMProviderUnavailable, got %v", err)
	}
	// State is PRESERVED for repair, and the administration surface still shows
	// it — a surface that refused to show the state would not be preserving it.
	view, err := s.GetBinding(ctx, service.LocalPrincipal(orgAdmin), orgA, bindingID)
	if err != nil {
		t.Fatalf("administration read under a disabled provider must still work: %v", err)
	}
	if !hasAttention(view, domain.AttentionProviderUnavailable) {
		t.Fatalf("provider_unavailable attention state missing: %+v", view.Attention)
	}
	if n := queryInt(t, db, `SELECT COUNT(*) FROM scim_users WHERE binding_id = '`+bindingID+`'`); n != 1 {
		t.Fatal("directory state must be preserved for repair")
	}

	// Re-enabling clears the state, audited on exit.
	disableSCIMProvider(t, db, "okta", true)
	view, err = s.GetBinding(ctx, service.LocalPrincipal(orgAdmin), orgA, bindingID)
	if err != nil {
		t.Fatal(err)
	}
	if hasAttention(view, domain.AttentionProviderUnavailable) {
		t.Fatal("the attention state must clear when the provider comes back")
	}
}

// runSCIMLifecycle exercises EVERY registered `scim.*` event type, so the
// audit suite's "every registered type is actually emitted" check has a real
// emitter behind each declaration rather than a promise.
func runSCIMLifecycle(t *testing.T, db *store.DB) {
	t.Helper()
	s := scimSvc(db)
	g := grantSvc(db)
	ctx := t.Context()

	bindingID, token := newSCIMBinding(t, db, "lifecycle") // binding_created, credential_minted, attention_entered
	wire := service.SCIMCredentialActor(token, bindingID)

	// credential_rotated: a mint that JOINS a live credential is the rotation.
	rotated, err := s.MintCredential(ctx, service.LocalPrincipal(orgAdmin), orgA, bindingID, false, "")
	if err != nil {
		t.Fatalf("credential rotate: %v", err)
	}
	if !rotated.Rotated {
		t.Fatal("a second live credential must be recorded as a rotation")
	}

	user, err := s.CreateUser(ctx, wire, orgA, bindingID, service.SCIMUserInput{ // user_provisioned, attention_cleared (stale)
		UserName: "ida@example.test", ExternalID: "ext-ida", SubjectRaw: "ext-ida",
	})
	if err != nil {
		t.Fatalf("scim.user_provisioned: %v", err)
	}
	if _, err := s.PatchUser(ctx, wire, orgA, bindingID, user.ID, service.SCIMUserInput{ // user_updated
		Attributes: map[string]any{"displayName": "Ida"},
	}); err != nil {
		t.Fatalf("scim.user_updated: %v", err)
	}
	group, err := s.CreateGroup(ctx, wire, orgA, bindingID, service.SCIMGroupInput{ // group_created, group_membership_changed
		DisplayName: "Lifecycle", Members: []string{user.ID}, MembersPresent: true,
	})
	if err != nil {
		t.Fatalf("scim.group_created: %v", err)
	}
	if _, err := s.PatchGroup(ctx, wire, orgA, bindingID, group.ID, service.SCIMGroupInput{ // group_updated
		DisplayName: "Lifecycle Team",
	}); err != nil {
		t.Fatalf("scim.group_updated: %v", err)
	}
	mapping, err := s.CreateMapping(ctx, service.LocalPrincipal(orgAdmin), orgA, bindingID, service.SCIMMappingSpec{ // mapping_created
		GroupID: group.ID, Template: domain.TemplatePublisher, ProjectID: string(prjA1),
	})
	if err != nil {
		t.Fatalf("scim.mapping_created: %v", err)
	}
	if _, err := s.UpdateMapping(ctx, service.LocalPrincipal(orgAdmin), orgA, bindingID, service.SCIMMappingSpec{ // mapping_updated
		GroupID: group.ID, Template: domain.TemplateViewer, ProjectID: string(prjA1),
	}); err != nil {
		t.Fatalf("scim.mapping_updated: %v", err)
	}
	if _, err := s.ListMappings(ctx, service.LocalPrincipal(orgAdmin), orgA, bindingID); err != nil { // directory_read
		t.Fatalf("scim.directory_read: %v", err)
	}
	if _, _, err := s.ListUsers(ctx, wire, orgA, bindingID,
		scimproto.Filter{Shape: scimproto.FilterNone}, scimproto.Page{StartIndex: 1, Count: 10}); err != nil {
		t.Fatalf("scim user list: %v", err)
	}
	if err := s.Discovery(ctx, wire, orgA, bindingID); err != nil {
		t.Fatalf("scim discovery: %v", err)
	}
	off := false
	if _, err := s.PatchUser(ctx, wire, orgA, bindingID, user.ID, service.SCIMUserInput{Active: &off}); err != nil { // user_deprovisioned
		t.Fatalf("scim.user_deprovisioned: %v", err)
	}
	if _, err := s.DeleteMapping(ctx, service.LocalPrincipal(orgAdmin), orgA, bindingID, service.SCIMMappingSpec{ // mapping_deleted
		GroupID: group.ID, ProjectID: string(prjA1),
	}); err != nil {
		t.Fatalf("scim.mapping_deleted: %v", err)
	}
	_ = mapping
	if err := s.DeleteUser(ctx, wire, orgA, bindingID, user.ID); err != nil { // user_deleted
		t.Fatalf("scim.user_deleted: %v", err)
	}
	if err := s.DeleteGroup(ctx, wire, orgA, bindingID, group.ID); err != nil { // group_deleted
		t.Fatalf("scim.group_deleted: %v", err)
	}
	if err := s.RevokeCredential(ctx, service.LocalPrincipal(orgAdmin), orgA, bindingID, rotated.Credential.ID); err != nil { // credential_revoked
		t.Fatalf("scim.credential_revoked: %v", err)
	}
	// scim.credential_refused: a live credential presented against the WRONG
	// binding. The response is the uniform 401; the trail is where the
	// distinction lives.
	other, _ := newSCIMBinding(t, db, "lifecycle-other")
	if _, err := s.GetUser(ctx, service.SCIMCredentialActor(token, other), orgA, other, "scu_none"); err == nil {
		t.Fatal("a credential presented against the wrong binding must be refused")
	}
	// scim.attention_cleared: the provider goes away and comes back, so the
	// state is audited on entry AND on exit.
	disableSCIMProvider(t, db, "lifecycle", false)
	if _, err := s.GetBinding(ctx, service.LocalPrincipal(orgAdmin), orgA, bindingID); err != nil {
		t.Fatal(err)
	}
	disableSCIMProvider(t, db, "lifecycle", true)
	if _, err := s.GetBinding(ctx, service.LocalPrincipal(orgAdmin), orgA, bindingID); err != nil {
		t.Fatal(err)
	}

	// The lockout pair needs an org with no other member manager, which the
	// dedicated fixture below builds and tears down inside this same datastore.
	runSCIMLockoutPair(t, db, g)

	if err := s.DeleteBinding(ctx, service.LocalPrincipal(orgAdmin), orgA, bindingID); err != nil { // binding_deleted
		t.Fatalf("scim.binding_deleted: %v", err)
	}
}

// runSCIMLockoutPair emits `scim.lockout_retention` and its paired cure event
// `scim.lockout_retention_released` — the two the ordinary lifecycle above
// cannot reach, because they require an org whose last member manager is the
// one the IdP is withdrawing.
func runSCIMLockoutPair(t *testing.T, db *store.DB, g *service.Grants) {
	t.Helper()
	s := scimSvc(db)
	ctx := t.Context()
	bindingID, token := newSCIMBinding(t, db, "lockout")
	wire := service.SCIMCredentialActor(token, bindingID)

	user, err := s.CreateUser(ctx, wire, orgA, bindingID, service.SCIMUserInput{
		UserName: "jo@example.test", ExternalID: "ext-jo", SubjectRaw: "ext-jo",
	})
	if err != nil {
		t.Fatal(err)
	}
	group, err := s.CreateGroup(ctx, wire, orgA, bindingID, service.SCIMGroupInput{
		DisplayName: "Lockout Admins", Members: []string{user.ID}, MembersPresent: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateMapping(ctx, service.LocalPrincipal(orgAdmin), orgA, bindingID, service.SCIMMappingSpec{
		GroupID: group.ID, Template: domain.TemplateAdmin,
	}); err != nil {
		t.Fatal(err)
	}
	// Drain every other org-or-above manage-members holder.
	execRaw(t, db, `DELETE FROM grant_origins WHERE grant_id IN `+
		`(SELECT id FROM grants WHERE capability = 'manage-members' AND principal_id <> '`+
		string(principalOf(t, db, accountOf(t, db, user.ID)))+`')`)
	execRaw(t, db, `DELETE FROM grants WHERE capability = 'manage-members' AND principal_id <> '`+
		string(principalOf(t, db, accountOf(t, db, user.ID)))+`'`)

	if _, err := s.PatchGroup(ctx, wire, orgA, bindingID, group.ID, service.SCIMGroupInput{
		Members: nil, MembersPresent: true,
	}); err != nil {
		t.Fatalf("lockout conversion: %v", err)
	}
	// Restore orgAdmin's authority through the break-glass path, which is the
	// cure AND the only way back into an org with no member manager.
	if _, err := g.BreakGlassGrant(ctx, service.GrantSpec{
		Target: orgAdmin, Capability: domain.CapManageMembers, Scope: orgAScope,
	}); err != nil {
		t.Fatalf("cure: %v", err)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func grantsForSCIMUser(t *testing.T, db *store.DB, bindingID, userID string) int64 {
	t.Helper()
	account := accountOf(t, db, userID)
	return queryInt(t, db, `SELECT COUNT(*) FROM grants WHERE principal_id = '`+
		string(principalOf(t, db, account))+`'`)
}

func accountOf(t *testing.T, db *store.DB, scimUserID string) string {
	t.Helper()
	return queryString(t, db, `SELECT account_id FROM scim_users WHERE id = '`+scimUserID+`'`)
}

func principalOf(t *testing.T, db *store.DB, accountID string) domain.PrincipalID {
	t.Helper()
	return domain.PrincipalID(queryString(t, db, `SELECT principal_id FROM accounts WHERE id = '`+accountID+`'`))
}

func hasWarning(warnings []service.SCIMBlastWarning, code string) bool {
	for _, w := range warnings {
		if w.Code == code {
			return true
		}
	}
	return false
}

func hasAttention(view service.SCIMBindingView, state domain.SCIMAttention) bool {
	for _, a := range view.Attention {
		if a.State == string(state) {
			return true
		}
	}
	return false
}

// trueLit is the boolean literal each engine stores. sqlite keeps 0/1 under a
// CHECK; postgres has a real boolean type.
func trueLit(db *store.DB) string {
	if db.PG() != nil {
		return "TRUE"
	}
	return "1"
}

// userShape renders a resource's SHAPE as one canonical string — #23's
// response-equality oracle criterion, compared byte for byte. It records
// presence and TYPE, never content: the two users are different people, and
// what must be indistinguishable is the shape of the answer.
//
// It is a rendered string rather than a bool comparison so a failure can be
// diffed, and it names every attribute KEY rather than counting them: comparing
// `len(a.Attributes) == len(b.Attributes)` accepted two responses carrying the
// same number of fields under different names, which is precisely the shape a
// create-versus-attach oracle would take.
//
// This is the service-layer half. The rendered-BYTES half — the wire body an
// identity provider actually receives, where omitempty makes the field set
// genuinely dynamic — is runSCIMWireAttachIsIndistinguishable.
func userShape(u service.SCIMUserResource) string {
	return strings.Join([]string{
		"id=" + present(u.ID != ""),
		"userName=" + present(u.UserName != ""),
		"externalId=" + present(u.ExternalID != ""),
		"active=" + strconv.FormatBool(u.Active),
		"groups=" + strconv.Itoa(len(u.Groups)),
		"attributes=" + attributeShape(u.Attributes),
		"createdAt=" + present(!u.CreatedAt.IsZero()),
		"updatedAt=" + present(!u.UpdatedAt.IsZero()),
	}, ",")
}

func present(ok bool) string {
	if ok {
		return "set"
	}
	return "unset"
}

// attributeShape names every key and the JSON type of its value, sorted.
func attributeShape(attrs map[string]any) string {
	keys := make([]string, 0, len(attrs))
	for k := range attrs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k+":"+jsonTypeOf(attrs[k]))
	}
	return "[" + strings.Join(out, " ") + "]"
}

func jsonTypeOf(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case bool:
		return "bool"
	case string:
		return "string"
	case float64, int, int64:
		return "number"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	default:
		return fmt.Sprintf("%T", v)
	}
}

// TestSCIMPutReplacementSemantics is SC1's PUT clause (§8): omitted mutable
// attributes clear to their defaults, an omitted `active` REACTIVATES, the
// subject source is EXEMPT from replacement, and `groups` is ignored on input.
func TestSCIMPutReplacementSemanticsSQLite(t *testing.T) {
	runSCIMPutReplacementSemantics(t, seededDB(t, openSQLite))
}
func TestSCIMPutReplacementSemanticsPostgres(t *testing.T) {
	runSCIMPutReplacementSemantics(t, seededDB(t, openPostgres))
}

func runSCIMPutReplacementSemantics(t *testing.T, db *store.DB) {
	s := scimSvc(db)
	ctx := t.Context()
	bindingID, token := newSCIMBinding(t, db, "okta")
	wire := service.SCIMCredentialActor(token, bindingID)

	user, err := s.CreateUser(ctx, wire, orgA, bindingID, service.SCIMUserInput{
		UserName: "nia@example.test", ExternalID: "ext-nia",
		Resource:   map[string]any{"userName": "nia@example.test", "externalId": "ext-nia"},
		Attributes: map[string]any{"nickName": "Nee"},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Deactivate first, so the PUT below can be shown to reactivate.
	off := false
	if _, err := s.PatchUser(ctx, wire, orgA, bindingID, user.ID, service.SCIMUserInput{Active: &off}); err != nil {
		t.Fatal(err)
	}

	// A PUT omitting everything but `userName`. On an `externalId`-source
	// binding this is the exemption's whole point: the identity material is
	// RETAINED, not cleared-then-refused, exactly as an extension-path binding
	// behaves. The other omitted mutables DO clear, and `active` defaults true.
	on := true
	replaced, err := s.ReplaceUser(ctx, wire, orgA, bindingID, user.ID, service.SCIMUserInput{
		UserName: "nia@example.test", Active: &on,
		Resource: map[string]any{"userName": "nia@example.test"},
	})
	if err != nil {
		t.Fatalf("a PUT omitting the subject source must be accepted (it is exempt): %v", err)
	}
	if replaced.ExternalID != "ext-nia" {
		t.Fatalf("the subject source must be retained across replacement, got %q", replaced.ExternalID)
	}
	if !replaced.Active {
		t.Fatal("an omitted `active` must reactivate")
	}
	if len(replaced.Attributes) != 0 {
		t.Fatalf("omitted mutable attributes must clear, got %v", replaced.Attributes)
	}
	// A REAL group the user is not a member of, so the bogus `groups` below
	// names something that actually exists — a client claiming membership of a
	// nonexistent group is the easy half.
	other, err := s.CreateGroup(ctx, wire, orgA, bindingID, service.SCIMGroupInput{
		DisplayName: "Not Mine",
	})
	if err != nil {
		t.Fatal(err)
	}
	otherGroup := other.ID

	// `groups` is response-only, and the proof has to SUPPLY some: an empty
	// response staying empty proves nothing. A PUT naming a real group the
	// user is not in, plus a group that does not exist at all, must change no
	// membership and must not become display metadata either — a readOnly
	// attribute a client can write through is an authority channel.
	bogus := map[string]any{
		"schemas":  []any{scimproto.SchemaUser},
		"userName": replaced.UserName,
		"groups": []any{
			map[string]any{"value": "scg_does_not_exist", "display": "Ghost"},
			map[string]any{"value": otherGroup, "display": "Not Mine"},
		},
	}
	raw, err := json.Marshal(bogus)
	if err != nil {
		t.Fatal(err)
	}
	decoded, derr := scimproto.DecodeUser(raw)
	if derr != nil {
		t.Fatalf("a resource carrying readOnly `groups` is well-formed, not a refusal: %v", derr)
	}
	if len(decoded.Groups) != 2 {
		t.Fatalf("the decoder must ACCEPT the readOnly member so the service can ignore it; got %d refs",
			len(decoded.Groups))
	}
	membersBefore := queryInt(t, db, `SELECT COUNT(*) FROM scim_group_members WHERE binding_id = '`+bindingID+`'`)
	afterBogus, err := s.ReplaceUser(ctx, wire, orgA, bindingID, replaced.ID, service.SCIMUserInput{
		UserName: replaced.UserName, ExternalID: replaced.ExternalID,
		SubjectRaw: replaced.ExternalID,
		Resource:   map[string]any{"userName": replaced.UserName, "groups": bogus["groups"]},
		// `groups` is handed to the service INSIDE the display map too, which
		// is stronger than relying on the transport to have stripped it: even
		// a caller that passes it through must not move a membership.
		Attributes: map[string]any{"groups": bogus["groups"]},
	})
	if err != nil {
		t.Fatalf("PUT carrying bogus groups: %v", err)
	}
	if len(afterBogus.Groups) != 0 {
		t.Fatalf("groups must be ignored on input, got %v", afterBogus.Groups)
	}
	if n := queryInt(t, db, `SELECT COUNT(*) FROM scim_group_members WHERE binding_id = '`+bindingID+`'`); n != membersBefore {
		t.Fatalf("a bogus `groups` on PUT changed stored membership: %d -> %d", membersBefore, n)
	}
	if len(replaced.Groups) != 0 {
		t.Fatalf("groups must be ignored on input, got %v", replaced.Groups)
	}

	// A PUT that EXPLICITLY supplies a different subject value is still the
	// migration attempt the identity model exists to refuse.
	if _, err := s.ReplaceUser(ctx, wire, orgA, bindingID, user.ID, service.SCIMUserInput{
		UserName: "nia@example.test",
		Resource: map[string]any{"userName": "nia@example.test", "externalId": "ext-moved"},
	}); !errors.Is(err, service.ErrSCIMSubjectWriteOnce) {
		t.Fatalf("an explicit subject change must refuse write-once, got %v", err)
	}

	// The same two cases on an EXTENSION-PATH binding, where `externalId` is an
	// ordinary attribute and the subject lives elsewhere. Omission retains;
	// an explicit different value refuses.
	seedSCIMProvider(t, db, "entra", "https://entra.example.test", true)
	ext, err := s.CreateBinding(ctx, service.LocalPrincipal(orgAdmin), orgA, service.SCIMBindingInput{
		ProviderKind: domain.ProviderOIDC, ProviderSlug: "entra",
		SubjectSource: "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber",
	})
	if err != nil {
		t.Fatal(err)
	}
	extMint, err := s.MintCredential(ctx, service.LocalPrincipal(orgAdmin), orgA, ext.ID, false, "")
	if err != nil {
		t.Fatal(err)
	}
	extWire := service.SCIMCredentialActor(extMint.Token, ext.ID)
	const extPath = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
	extUser, err := s.CreateUser(ctx, extWire, orgA, ext.ID, service.SCIMUserInput{
		UserName: "omar@example.test", ExternalID: "ext-omar",
		Resource: map[string]any{
			"userName": "omar@example.test", "externalId": "ext-omar",
			extPath: map[string]any{"employeeNumber": "E-1"},
		},
	})
	if err != nil {
		t.Fatalf("extension-path provisioning: %v", err)
	}
	if _, err := s.ReplaceUser(ctx, extWire, orgA, ext.ID, extUser.ID, service.SCIMUserInput{
		UserName: "omar@example.test",
		Resource: map[string]any{"userName": "omar@example.test"},
	}); err != nil {
		t.Fatalf("an extension-path PUT omitting the subject source must be accepted: %v", err)
	}
	if _, err := s.ReplaceUser(ctx, extWire, orgA, ext.ID, extUser.ID, service.SCIMUserInput{
		UserName: "omar@example.test",
		Resource: map[string]any{
			"userName": "omar@example.test",
			extPath:    map[string]any{"employeeNumber": "E-2"},
		},
	}); !errors.Is(err, service.ErrSCIMSubjectWriteOnce) {
		t.Fatal("an explicit extension-path subject change must refuse write-once")
	}

	// ReplaceGroup: displayName replaced, member set replaced wholesale.
	g, err := s.CreateGroup(ctx, wire, orgA, bindingID, service.SCIMGroupInput{
		DisplayName: "Before", Members: []string{user.ID}, MembersPresent: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	after, err := s.ReplaceGroup(ctx, wire, orgA, bindingID, g.ID, service.SCIMGroupInput{
		DisplayName: "After",
	})
	if err != nil {
		t.Fatal(err)
	}
	if after.DisplayName != "After" || len(after.Members) != 0 {
		t.Fatalf("PUT must replace the member set wholesale: %+v", after)
	}
}

// TestSCIMEmailNeverLinks is SC2's named fixture: email and profile attributes
// are delivery/display metadata ONLY — never matched, never a linking key
// (§5.2). A pushed email equal to an existing unrelated account's email must
// NOT attach to it.
func TestSCIMEmailNeverLinksSQLite(t *testing.T) { runSCIMEmailNeverLinks(t, seededDB(t, openSQLite)) }
func TestSCIMEmailNeverLinksPostgres(t *testing.T) {
	runSCIMEmailNeverLinks(t, seededDB(t, openPostgres))
}

func runSCIMEmailNeverLinks(t *testing.T, db *store.DB) {
	s := scimSvc(db)
	ctx := t.Context()
	bindingID, token := newSCIMBinding(t, db, "okta")
	wire := service.SCIMCredentialActor(token, bindingID)

	// An unrelated account that already exists, whose handle IS the email the
	// identity provider is about to push.
	execRaw(t, db, `INSERT INTO principals (id, kind, created_at) VALUES ('usr_unrelated', 'human', `+ts+`)`)
	execRaw(t, db, `INSERT INTO accounts (id, principal_id, username, display_name, created_at) `+
		`VALUES ('acc_unrelated', 'usr_unrelated', 'collide@example.test', 'Unrelated', `+ts+`)`)

	pushed, err := s.CreateUser(ctx, wire, orgA, bindingID, service.SCIMUserInput{
		UserName: "pushed@example.test", ExternalID: "ext-pushed", SubjectRaw: "ext-pushed",
		Attributes: map[string]any{
			"emails": []any{map[string]any{"value": "collide@example.test", "primary": true}},
		},
	})
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	if got := accountOf(t, db, pushed.ID); got == "acc_unrelated" {
		t.Fatal("a matching email attached the pushed user to an unrelated account; email is never a linking key")
	}
	if n := queryInt(t, db, `SELECT COUNT(*) FROM accounts WHERE username = 'collide@example.test'`); n != 1 {
		t.Fatalf("the unrelated account must be untouched, got %d rows", n)
	}
	// The email IS round-tripped, as delivery/display metadata.
	fresh, err := s.GetUser(ctx, wire, orgA, bindingID, pushed.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := fresh.Attributes["emails"]; !ok {
		t.Fatalf("profile attributes must round-trip: %v", fresh.Attributes)
	}
}

// TestSCIMGroupDisplayNameIsNotUnique: RFC 7643 does not make displayName
// unique and the ADR's closed uniqueness mapping names only `userName` and a
// subject-source collision, so two same-named groups coexist and the
// `displayName eq` probe answers with both.
func TestSCIMGroupDisplayNameIsNotUniqueSQLite(t *testing.T) {
	runSCIMGroupDisplayNameIsNotUnique(t, seededDB(t, openSQLite))
}
func TestSCIMGroupDisplayNameIsNotUniquePostgres(t *testing.T) {
	runSCIMGroupDisplayNameIsNotUnique(t, seededDB(t, openPostgres))
}

func runSCIMGroupDisplayNameIsNotUnique(t *testing.T, db *store.DB) {
	s := scimSvc(db)
	ctx := t.Context()
	bindingID, token := newSCIMBinding(t, db, "okta")
	wire := service.SCIMCredentialActor(token, bindingID)

	first, err := s.CreateGroup(ctx, wire, orgA, bindingID, service.SCIMGroupInput{DisplayName: "Sales and Marketing"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.CreateGroup(ctx, wire, orgA, bindingID, service.SCIMGroupInput{DisplayName: "Sales and Marketing"})
	if err != nil {
		t.Fatalf("two same-named groups must coexist: %v", err)
	}
	if first.ID == second.ID {
		t.Fatal("the second create returned the first group")
	}
	// And the discovery probe — whose value contains a logical operator, which
	// a quote-blind filter parser refused — answers with both.
	filter, e := scimproto.ParseFilter(`displayName eq "Sales and Marketing"`, scimproto.ResourceGroup)
	if e != nil {
		t.Fatalf("a quoted value containing `and` must parse: %v", e)
	}
	got, total, err := s.ListGroups(ctx, wire, orgA, bindingID, filter, scimproto.Page{StartIndex: 1, Count: 10})
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 || len(got) != 2 {
		t.Fatalf("displayName eq must answer with every match: total=%d len=%d", total, len(got))
	}
}

// TestSCIMManualRemainsMeansManual pins §5.3's flag to what it says. A user
// provisioned by TWO bindings, deprovisioned from one, with no hand-made grant
// anywhere, must NOT raise "manual grants remain": the surviving row is the
// other identity provider's assertion, and nothing about it needs a human
// decision. Widening the flag to cover it would send an operator looking for a
// manual grant that does not exist.
func TestSCIMManualRemainsMeansManualSQLite(t *testing.T) {
	runSCIMManualRemainsMeansManual(t, seededDB(t, openSQLite))
}
func TestSCIMManualRemainsMeansManualPostgres(t *testing.T) {
	runSCIMManualRemainsMeansManual(t, seededDB(t, openPostgres))
}

func runSCIMManualRemainsMeansManual(t *testing.T, db *store.DB) {
	s := scimSvc(db)
	ctx := t.Context()
	first, firstToken := newSCIMBinding(t, db, "idp-one")
	second, secondToken := newSCIMBinding(t, db, "idp-two")

	execRaw(t, db, `INSERT INTO principals (id, kind, created_at) VALUES ('usr_dual', 'human', `+ts+`)`)
	execRaw(t, db, `INSERT INTO accounts (id, principal_id, username, display_name, created_at) `+
		`VALUES ('acc_dual', 'usr_dual', 'dual@example.test', 'Dual', `+ts+`)`)
	for _, slug := range []string{"idp-one", "idp-two"} {
		execRaw(t, db, `INSERT INTO external_identities (id, account_id, kind, issuer, subject, provider_id, credential_epoch, created_at) `+
			`VALUES ('eid_dual_`+slug+`', 'acc_dual', 'oidc', 'https://`+slug+`.example.test', 'dual', '`+slug+`', 0, `+ts+`)`)
	}

	// Both bindings provision the human and grant the same triple.
	users := map[string]string{}
	for _, b := range []struct{ id, token, name string }{
		{first, firstToken, "one"}, {second, secondToken, "two"},
	} {
		wire := service.SCIMCredentialActor(b.token, b.id)
		u, err := s.CreateUser(ctx, wire, orgA, b.id, service.SCIMUserInput{
			UserName: "dual-" + b.name + "@example.test", ExternalID: "dual", SubjectRaw: "dual",
		})
		if err != nil {
			t.Fatal(err)
		}
		users[b.id] = u.ID
		g, err := s.CreateGroup(ctx, wire, orgA, b.id, service.SCIMGroupInput{
			DisplayName: "Dual " + b.name, Members: []string{u.ID}, MembersPresent: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.CreateMapping(ctx, service.LocalPrincipal(orgAdmin), orgA, b.id, service.SCIMMappingSpec{
			GroupID: g.ID, Template: domain.TemplateViewer, ProjectID: string(prjA1),
		}); err != nil {
			t.Fatal(err)
		}
	}

	// Deprovision from the FIRST binding only. The row survives on the second
	// binding's origin — and that is not a manual grant.
	off := false
	if _, err := s.PatchUser(ctx, service.SCIMCredentialActor(firstToken, first),
		orgA, first, users[first], service.SCIMUserInput{Active: &off}); err != nil {
		t.Fatal(err)
	}
	if !held(t, db, domain.PrincipalID("usr_dual"), domain.CapRead, domain.Scope{Org: orgA, Project: prjA1}) {
		t.Fatal("the second binding's origin must still hold the row")
	}
	if n := queryInt(t, db,
		`SELECT COUNT(*) FROM scim_attention WHERE state = 'manual_grants_remain'`); n != 0 {
		t.Fatal("another binding's surviving origin is not a manual grant and must not raise the flag")
	}

	// Now give the human a genuinely MANUAL grant and deprovision from the
	// second binding: THAT is the honest remainder the flag exists for.
	if _, err := grantSvc(db).Create(ctx, service.LocalPrincipal(orgAdmin), service.GrantSpec{
		Target: domain.PrincipalID("usr_dual"), Capability: domain.CapEdit,
		Scope: domain.Scope{Org: orgA, Project: prjA1},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PatchUser(ctx, service.SCIMCredentialActor(secondToken, second),
		orgA, second, users[second], service.SCIMUserInput{Active: &off}); err != nil {
		t.Fatal(err)
	}
	if n := queryInt(t, db,
		`SELECT COUNT(*) FROM scim_attention WHERE state = 'manual_grants_remain'`); n != 1 {
		t.Fatalf("a surviving MANUAL grant must raise the flag, got %d", n)
	}
}
