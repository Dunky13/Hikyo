package isolation

import (
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Dunky13/hikyo/internal/audit"
	"github.com/Dunky13/hikyo/internal/crypto"
	"github.com/Dunky13/hikyo/internal/domain"
	"github.com/Dunky13/hikyo/internal/scimproto"
	"github.com/Dunky13/hikyo/internal/service"
	"github.com/Dunky13/hikyo/internal/store"
)

// SCIM audit, origin and invariant fixtures (#73 SC3.a/c/e/f/i/n, SC4.a/i/k/m/n).

// TestSCIMOriginTupleIsExact is SC3.a: every expanded capability row carries a
// `scim` origin whose FULL (binding, mapping row, group) tuple is exact. A
// substring match on the mapping id proved only that something mentioned it.
func TestSCIMOriginTupleIsExactSQLite(t *testing.T) {
	runSCIMOriginTupleIsExact(t, seededDB(t, openSQLite))
}
func TestSCIMOriginTupleIsExactPostgres(t *testing.T) {
	runSCIMOriginTupleIsExact(t, seededDB(t, openPostgres))
}

func runSCIMOriginTupleIsExact(t *testing.T, db *store.DB) {
	s := scimSvc(db)
	ctx := t.Context()
	bindingID, token := newSCIMBinding(t, db, "okta")
	wire := service.SCIMCredentialActor(token, bindingID)

	user, err := s.CreateUser(ctx, wire, orgA, bindingID, service.SCIMUserInput{
		UserName: "tuple@example.test", ExternalID: "ext-tuple", SubjectRaw: "ext-tuple",
	})
	if err != nil {
		t.Fatal(err)
	}
	group, err := s.CreateGroup(ctx, wire, orgA, bindingID, service.SCIMGroupInput{
		DisplayName: "Tuple", Members: []string{user.ID}, MembersPresent: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	// `publisher` expands to FOUR capabilities, so "every expanded row" is a
	// real quantifier rather than a single row restated.
	res, err := s.CreateMapping(ctx, service.LocalPrincipal(orgAdmin), orgA, bindingID,
		service.SCIMMappingSpec{GroupID: group.ID, Template: domain.TemplatePublisher, ProjectID: string(prjA1)})
	if err != nil {
		t.Fatal(err)
	}
	want := domain.SCIMOriginKey{Binding: bindingID, MappingRow: res.Mapping.ID, Group: group.ID}.Subject()

	principal := principalOf(t, db, accountOf(t, db, user.ID))
	caps, err := domain.ExpandTemplate(domain.TemplatePublisher, domain.LevelProject)
	if err != nil {
		t.Fatal(err)
	}
	for _, capability := range caps {
		got := queryStrings(t, db,
			`SELECT o.subject FROM grant_origins AS o INNER JOIN grants AS g ON g.id = o.grant_id `+
				`WHERE g.principal_id = '`+string(principal)+`' AND g.capability = '`+string(capability)+`' `+
				`AND o.kind = 'scim' ORDER BY o.subject`)
		if got != want {
			t.Errorf("%s: origin subject = %q, want the exact tuple %q", capability, got, want)
		}
		// And the tuple round-trips through the decoder the chip renders with.
		key, ok := domain.ParseSCIMOriginSubject(got)
		if !ok || key.Binding != bindingID || key.MappingRow != res.Mapping.ID || key.Group != group.ID {
			t.Errorf("%s: the origin key does not decode to (binding, mapping row, group): %+v", capability, key)
		}
	}
	if len(caps) < 4 {
		t.Fatalf("the publisher template should expand to several capabilities, got %d", len(caps))
	}
}

// TestSCIMMultiGroupUnion is SC3.c: a user in several mapped groups gets the
// additive UNION, and losing one group leaves the other's grants standing.
func TestSCIMMultiGroupUnionSQLite(t *testing.T) { runSCIMMultiGroupUnion(t, seededDB(t, openSQLite)) }
func TestSCIMMultiGroupUnionPostgres(t *testing.T) {
	runSCIMMultiGroupUnion(t, seededDB(t, openPostgres))
}

func runSCIMMultiGroupUnion(t *testing.T, db *store.DB) {
	s := scimSvc(db)
	ctx := t.Context()
	bindingID, token := newSCIMBinding(t, db, "okta")
	wire := service.SCIMCredentialActor(token, bindingID)
	scope := domain.Scope{Org: orgA, Project: prjA1}

	user, err := s.CreateUser(ctx, wire, orgA, bindingID, service.SCIMUserInput{
		UserName: "union@example.test", ExternalID: "ext-union", SubjectRaw: "ext-union",
	})
	if err != nil {
		t.Fatal(err)
	}
	principal := principalOf(t, db, accountOf(t, db, user.ID))

	// Two groups, OVERLAPPING templates: `viewer` (read) and `editor`
	// (read + edit). The overlap is the point — `read` is wanted by both, so
	// one row with two origins, and losing one group must not take it away.
	groups := map[string]string{}
	for name, template := range map[string]domain.Template{
		"Readers": domain.TemplateViewer, "Editors": domain.TemplateEditor,
	} {
		g, err := s.CreateGroup(ctx, wire, orgA, bindingID, service.SCIMGroupInput{
			DisplayName: name, Members: []string{user.ID}, MembersPresent: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.CreateMapping(ctx, service.LocalPrincipal(orgAdmin), orgA, bindingID,
			service.SCIMMappingSpec{GroupID: g.ID, Template: template, ProjectID: string(prjA1)}); err != nil {
			t.Fatal(err)
		}
		groups[name] = g.ID
	}

	// UNION: read from both, edit from Editors.
	if !held(t, db, principal, domain.CapRead, scope) || !held(t, db, principal, domain.CapEdit, scope) {
		t.Fatal("a user in two mapped groups must hold the union")
	}
	if n := queryInt(t, db,
		`SELECT COUNT(*) FROM grant_origins AS o INNER JOIN grants AS g ON g.id = o.grant_id `+
			`WHERE g.principal_id = '`+string(principal)+`' AND g.capability = 'read' AND o.kind = 'scim'`); n != 2 {
		t.Fatalf("`read` is wanted by both groups: want 2 origins on one row, got %d", n)
	}

	// Deleting ONE group releases only its origins. `read` survives on the
	// other group's origin; `edit` goes with Editors.
	if err := s.DeleteGroup(ctx, wire, orgA, bindingID, groups["Editors"]); err != nil {
		t.Fatal(err)
	}
	if !held(t, db, principal, domain.CapRead, scope) {
		t.Fatal("`read` must survive on the remaining group's origin")
	}
	if held(t, db, principal, domain.CapEdit, scope) {
		t.Fatal("`edit` was only Editors', and must go with it")
	}
	// The referencing mapping row flips inert with its attention state.
	if n := queryInt(t, db, `SELECT COUNT(*) FROM scim_attention WHERE state = 'inert_mapping'`); n != 1 {
		t.Fatalf("the orphaned mapping row must raise its attention state, got %d", n)
	}
}

// TestSCIMMappingWidenAndNarrow is SC3.e and SC3.f: widening grants the newly
// covered capabilities in the AUTHORING transaction, and narrowing releases the
// no-longer-covered part — both without any sync in between.
func TestSCIMMappingWidenAndNarrowSQLite(t *testing.T) {
	runSCIMMappingWidenAndNarrow(t, seededDB(t, openSQLite))
}
func TestSCIMMappingWidenAndNarrowPostgres(t *testing.T) {
	runSCIMMappingWidenAndNarrow(t, seededDB(t, openPostgres))
}

func runSCIMMappingWidenAndNarrow(t *testing.T, db *store.DB) {
	s := scimSvc(db)
	ctx := t.Context()
	bindingID, token := newSCIMBinding(t, db, "okta")
	wire := service.SCIMCredentialActor(token, bindingID)
	scope := domain.Scope{Org: orgA, Project: prjA1}

	user, err := s.CreateUser(ctx, wire, orgA, bindingID, service.SCIMUserInput{
		UserName: "widen@example.test", ExternalID: "ext-widen", SubjectRaw: "ext-widen",
	})
	if err != nil {
		t.Fatal(err)
	}
	principal := principalOf(t, db, accountOf(t, db, user.ID))
	group, err := s.CreateGroup(ctx, wire, orgA, bindingID, service.SCIMGroupInput{
		DisplayName: "Widen", Members: []string{user.ID}, MembersPresent: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	spec := service.SCIMMappingSpec{GroupID: group.ID, ProjectID: string(prjA1)}

	// CREATE against an ALREADY-POPULATED group: the grants exist by the time
	// the call returns, with no push in between.
	spec.Template = domain.TemplateViewer
	res, err := s.CreateMapping(ctx, service.LocalPrincipal(orgAdmin), orgA, bindingID, spec)
	if err != nil {
		t.Fatal(err)
	}
	if res.MembersAffected != 1 || res.GrantsCreated == 0 {
		t.Fatalf("a mapping row must grant the group's CURRENT members: %+v", res)
	}
	if !held(t, db, principal, domain.CapRead, scope) {
		t.Fatal("the grant must exist in the authoring transaction")
	}
	mappingID := res.Mapping.ID

	// WIDEN: viewer -> publisher adds edit/publish/pin, immediately.
	spec.Template = domain.TemplatePublisher
	if _, err := s.UpdateMapping(ctx, service.LocalPrincipal(orgAdmin), orgA, bindingID, spec); err != nil {
		t.Fatal(err)
	}
	for _, capability := range []domain.Capability{domain.CapRead, domain.CapEdit, domain.CapPublish, domain.CapPin} {
		if !held(t, db, principal, capability, scope) {
			t.Fatalf("widening must grant %s in the authoring transaction", capability)
		}
	}
	// The row KEEPS its id, which is what makes narrowing precise.
	if after := queryString(t, db,
		`SELECT id FROM scim_mappings WHERE binding_id = '`+bindingID+`' AND group_id = '`+group.ID+`'`); after != mappingID {
		t.Fatalf("the mapping row must keep its id across a retarget: %s -> %s", mappingID, after)
	}

	// NARROW: publisher -> viewer releases exactly the no-longer-covered part,
	// and leaves the part it still covers.
	spec.Template = domain.TemplateViewer
	narrowed, err := s.UpdateMapping(ctx, service.LocalPrincipal(orgAdmin), orgA, bindingID, spec)
	if err != nil {
		t.Fatal(err)
	}
	if narrowed.OriginsReleased == 0 {
		t.Fatal("narrowing must release the no-longer-covered origins")
	}
	if !held(t, db, principal, domain.CapRead, scope) {
		t.Fatal("narrowing must leave the part the row still covers")
	}
	for _, capability := range []domain.Capability{domain.CapEdit, domain.CapPublish, domain.CapPin} {
		if held(t, db, principal, capability, scope) {
			t.Fatalf("narrowing must release %s, with no round-trip to the identity provider", capability)
		}
	}

	// DELETE releases the rest, still in the authoring transaction.
	if _, err := s.DeleteMapping(ctx, service.LocalPrincipal(orgAdmin), orgA, bindingID, spec); err != nil {
		t.Fatal(err)
	}
	if held(t, db, principal, domain.CapRead, scope) {
		t.Fatal("deleting the row must release its last origin")
	}
}

// TestSCIMLockoutAcrossEveryReleasePath is SC3.i: the lockout family across
// EVERY trigger — deprovision, member removal, group delete, mapping delete and
// binding delete — each converting, raising its attention state, emitting the
// audit pair, and curing deterministically.
func TestSCIMLockoutAcrossEveryReleasePathSQLite(t *testing.T) {
	runSCIMLockoutAcrossEveryReleasePath(t, openSQLite)
}
func TestSCIMLockoutAcrossEveryReleasePathPostgres(t *testing.T) {
	runSCIMLockoutAcrossEveryReleasePath(t, openPostgres)
}

// Each release path needs its own org and its own database — one case must not
// leave state that makes the next one pass — so this fixture takes the ENGINE
// OPENER rather than an open database and builds one per subtest ON THAT
// ENGINE. Taking a database and then opening SQLite inside every subtest is
// what it used to do, which made the Postgres leg of this test run SQLite six
// times while reporting as the Postgres leg.
func runSCIMLockoutAcrossEveryReleasePath(t *testing.T, open func(*testing.T) *store.DB) {
	ctx := t.Context()

	// Each trigger gets its own binding and its own human, so one case cannot
	// leave state that makes the next one pass.
	cases := []struct {
		name string
		// release performs the trigger. `self` is the provisioned human acting
		// on their own behalf — the ONLY shape in which an admin-authored
		// release can produce a lockout, since scimAdminFormula makes any
		// other admin a census holder by construction.
		release func(t *testing.T, s *service.SCIM, wire, self service.Actor, binding, user, group string)
		cause   string
	}{
		{"deprovision", func(t *testing.T, s *service.SCIM, wire, self service.Actor, binding, user, group string) {
			off := false
			if _, err := s.PatchUser(ctx, wire, orgA, binding, user, service.SCIMUserInput{Active: &off}); err != nil {
				t.Fatal(err)
			}
		}, "deprovision"},
		{"member_removed", func(t *testing.T, s *service.SCIM, wire, self service.Actor, binding, user, group string) {
			if _, err := s.PatchGroup(ctx, wire, orgA, binding, group,
				service.SCIMGroupInput{MembersPresent: true}); err != nil {
				t.Fatal(err)
			}
		}, "member_removed"},
		{"group_deleted", func(t *testing.T, s *service.SCIM, wire, self service.Actor, binding, user, group string) {
			if err := s.DeleteGroup(ctx, wire, orgA, binding, group); err != nil {
				t.Fatal(err)
			}
		}, "group_deleted"},
		{"user_deleted", func(t *testing.T, s *service.SCIM, wire, self service.Actor, binding, user, group string) {
			if err := s.DeleteUser(ctx, wire, orgA, binding, user); err != nil {
				t.Fatal(err)
			}
		}, "user_deleted"},
		{"mapping_deleted", func(t *testing.T, s *service.SCIM, wire, self service.Actor, binding, user, group string) {
			if _, err := s.DeleteMapping(ctx, self, orgA, binding,
				service.SCIMMappingSpec{GroupID: group}); err != nil {
				t.Fatal(err)
			}
		}, "mapping_deleted"},
		{"binding_deleted", func(t *testing.T, s *service.SCIM, wire, self service.Actor, binding, user, group string) {
			if err := s.DeleteBinding(ctx, self, orgA, binding); err != nil {
				t.Fatal(err)
			}
		}, "binding_deleted"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runOneLockoutPath(t, seededDB(t, open), tc.name, tc.cause, tc.release)
		})
	}
}

// runOneLockoutPath builds an org whose LAST manage-members holder is a
// provisioned human, fires one release trigger, and asserts the conversion, the
// attention state, the audit pair and the deterministic cure.
func runOneLockoutPath(
	t *testing.T, db *store.DB, name, cause string,
	release func(t *testing.T, s *service.SCIM, wire, self service.Actor, binding, user, group string),
) {
	s := scimSvc(db)
	g := grantSvc(db)
	ctx := t.Context()
	// One provider per case: these run in a shared database when the pairs
	// fixture calls in, and (kind, issuer) is unique.
	bindingID, token := newSCIMBinding(t, db, "lockout-"+name)
	wire := service.SCIMCredentialActor(token, bindingID)

	user, err := s.CreateUser(ctx, wire, orgA, bindingID, service.SCIMUserInput{
		UserName: name + "@example.test", ExternalID: "ext-" + name, SubjectRaw: "ext-" + name,
	})
	if err != nil {
		t.Fatal(err)
	}
	group, err := s.CreateGroup(ctx, wire, orgA, bindingID, service.SCIMGroupInput{
		DisplayName: "Admins " + name, Members: []string{user.ID}, MembersPresent: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	// `admin` at ORG scope expands to manage-members among others.
	if _, err := s.CreateMapping(ctx, service.LocalPrincipal(orgAdmin), orgA, bindingID,
		service.SCIMMappingSpec{GroupID: group.ID, Template: domain.TemplateAdmin}); err != nil {
		t.Fatal(err)
	}
	principal := principalOf(t, db, accountOf(t, db, user.ID))

	// Drain every OTHER manage-members holder so the provisioned human's grant
	// is genuinely the org's last one.
	execRaw(t, db, `DELETE FROM grant_origins WHERE grant_id IN `+
		`(SELECT id FROM grants WHERE capability = 'manage-members' AND principal_id <> '`+
		string(principal)+`')`)
	execRaw(t, db, `DELETE FROM grants WHERE capability = 'manage-members' AND principal_id <> '`+
		string(principal)+`'`)

	entriesBefore := auditCount(t, db, "scim.lockout_retention")
	release(t, s, wire, service.LocalPrincipal(principal), bindingID, user.ID, group.ID)

	// CONVERTED, not refused: the scim origin is gone, a retention holds the row.
	if n := queryInt(t, db, `SELECT COUNT(*) FROM grant_origins WHERE kind = 'lockout-retention'`); n != 1 {
		t.Fatalf("%s: want exactly one retention origin, got %d", name, n)
	}
	if n := queryInt(t, db,
		`SELECT COUNT(*) FROM grant_origins AS o INNER JOIN grants AS g ON g.id = o.grant_id `+
			`WHERE o.kind = 'scim' AND g.capability = 'manage-members'`); n != 0 {
		t.Fatalf("%s: origin truth must stay honest — the scim origin is released", name)
	}
	if !held(t, db, principal, domain.CapManageMembers, orgAScope) {
		t.Fatalf("%s: the retention must keep the org administrable", name)
	}
	// The retention records the CAUSE that triggered it.
	subject := queryString(t, db,
		`SELECT subject FROM grant_origins WHERE kind = 'lockout-retention'`)
	key, ok := domain.ParseSCIMRetentionSubject(subject)
	if !ok || string(key.Cause) != cause {
		t.Fatalf("%s: retention cause = %q, want %q", name, key.Cause, cause)
	}
	// The attention state, unless the binding itself is gone — §6 clears every
	// state through the audited exit path as it tears the binding down.
	if name != "binding_deleted" {
		if n := queryInt(t, db,
			`SELECT COUNT(*) FROM scim_attention WHERE state = 'lockout_retention'`); n != 1 {
			t.Fatalf("%s: the retention must raise its attention state", name)
		}
	}
	if got := auditCount(t, db, "scim.lockout_retention"); got <= entriesBefore {
		t.Fatalf("%s: the retention must be audited on entry", name)
	}

	// The CURE: the moment the org gains another holder, that same transaction
	// releases the retention and emits the paired event.
	if _, err := g.BreakGlassGrant(ctx, service.GrantSpec{
		Target: grantee, Capability: domain.CapManageMembers, Scope: orgAScope,
	}); err != nil {
		t.Fatalf("%s: cure: %v", name, err)
	}
	if n := queryInt(t, db, `SELECT COUNT(*) FROM grant_origins WHERE kind = 'lockout-retention'`); n != 0 {
		t.Fatalf("%s: the cure must release every retention it cures, %d remain", name, n)
	}
	if auditCount(t, db, "scim.lockout_retention_released") == 0 {
		t.Fatalf("%s: the cure must emit the paired event", name)
	}
}

func auditCount(t *testing.T, db *store.DB, typ string) int64 {
	t.Helper()
	return queryInt(t, db, `SELECT COUNT(*) FROM audit_tenant_events WHERE type = '`+typ+`'`) +
		queryInt(t, db, `SELECT COUNT(*) FROM audit_instance_events WHERE type = '`+typ+`'`)
}

// TestSCIMStalenessThreshold is SC4.a: staleness raises AND clears, and it is a
// THRESHOLD — a binding is not stale the moment it exists.
func TestSCIMStalenessThresholdSQLite(t *testing.T) {
	runSCIMStalenessThreshold(t, seededDB(t, openSQLite))
}
func TestSCIMStalenessThresholdPostgres(t *testing.T) {
	runSCIMStalenessThreshold(t, seededDB(t, openPostgres))
}

func runSCIMStalenessThreshold(t *testing.T, db *store.DB) {
	ctx := t.Context()
	now := time.Now().UTC()
	s := scimSvc(db)
	// A clock the fixture owns, so staleness is asserted by TIME PASSING rather
	// than by a sleep or a hand-written column value.
	s.Now = func() time.Time { return now }
	s.Staleness = time.Hour

	seedSCIMProvider(t, db, "okta", "https://okta.example.test", true)
	binding, err := s.CreateBinding(ctx, service.LocalPrincipal(orgAdmin), orgA, service.SCIMBindingInput{
		ProviderKind: domain.ProviderOIDC, ProviderSlug: "okta",
		SubjectSource: domain.SubjectSourceExternalID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if hasAttention(binding, domain.AttentionStale) {
		t.Fatal("a brand-new binding is not stale: §9 makes it a threshold")
	}

	// Past the threshold with no contact: raised, and audited on entry.
	now = now.Add(2 * time.Hour)
	view, err := s.GetBinding(ctx, service.LocalPrincipal(orgAdmin), orgA, binding.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !hasAttention(view, domain.AttentionStale) {
		t.Fatalf("past the threshold the binding must be stale: %+v", view.Attention)
	}
	if auditCount(t, db, "scim.attention_entered") == 0 {
		t.Fatal("entering the staleness state must be audited")
	}

	// The identity provider makes contact: cleared, and audited on exit.
	mint, err := s.MintCredential(ctx, service.LocalPrincipal(orgAdmin), orgA, binding.ID, false, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Discovery(ctx, service.SCIMCredentialActor(mint.Token, binding.ID), orgA, binding.ID); err != nil {
		t.Fatal(err)
	}
	view, err = s.GetBinding(ctx, service.LocalPrincipal(orgAdmin), orgA, binding.ID)
	if err != nil {
		t.Fatal(err)
	}
	if hasAttention(view, domain.AttentionStale) {
		t.Fatalf("contact must clear the staleness state: %+v", view.Attention)
	}
	if auditCount(t, db, "scim.attention_cleared") == 0 {
		t.Fatal("clearing the staleness state must be audited")
	}
	// Nothing was revoked by the outage: converting an IdP outage into
	// org-wide revocation is the scrub-on-timer failure the ADR rejects.
	if n := queryInt(t, db, `SELECT COUNT(*) FROM scim_bindings WHERE id = '`+binding.ID+`'`); n != 1 {
		t.Fatal("staleness must never delete state")
	}
}

// TestSCIMAttentionStatePairs is SC4.i: EVERY attention state is entered and
// cleared with its audit pair. A state that can be entered and not left is a
// permanent warning nobody can act on.
func TestSCIMAttentionStatePairsSQLite(t *testing.T) {
	runSCIMAttentionStatePairs(t, seededDB(t, openSQLite))
}
func TestSCIMAttentionStatePairsPostgres(t *testing.T) {
	runSCIMAttentionStatePairs(t, seededDB(t, openPostgres))
}

func runSCIMAttentionStatePairs(t *testing.T, db *store.DB) {
	s := scimSvc(db)
	ctx := t.Context()
	entered := map[string]bool{}
	cleared := map[string]bool{}
	record := func() {
		for _, row := range auditPayloadStates(t, db, "scim.attention_entered") {
			entered[row] = true
		}
		for _, row := range auditPayloadStates(t, db, "scim.attention_cleared") {
			cleared[row] = true
		}
	}

	// stale: raised by the threshold, cleared by contact.
	runSCIMStalenessThreshold(t, db)
	record()

	// provider_unavailable: raised by disabling, cleared by re-enabling.
	bindingID, token := newSCIMBinding(t, db, "second-idp")
	wire := service.SCIMCredentialActor(token, bindingID)
	user, err := s.CreateUser(ctx, wire, orgA, bindingID, service.SCIMUserInput{
		UserName: "att@example.test", ExternalID: "ext-att", SubjectRaw: "ext-att",
	})
	if err != nil {
		t.Fatal(err)
	}
	disableSCIMProvider(t, db, "second-idp", false)
	if _, err := s.GetBinding(ctx, service.LocalPrincipal(orgAdmin), orgA, bindingID); err != nil {
		t.Fatal(err)
	}
	disableSCIMProvider(t, db, "second-idp", true)
	if _, err := s.GetBinding(ctx, service.LocalPrincipal(orgAdmin), orgA, bindingID); err != nil {
		t.Fatal(err)
	}
	record()

	// manual_grants_remain: raised by a deprovision with a surviving hand
	// grant, cleared when the hand grant goes.
	principal := principalOf(t, db, accountOf(t, db, user.ID))
	scope := domain.Scope{Org: orgA, Project: prjA1}
	if _, err := grantSvc(db).Create(ctx, service.LocalPrincipal(orgAdmin), service.GrantSpec{
		Target: principal, Capability: domain.CapEdit, Scope: scope,
	}); err != nil {
		t.Fatal(err)
	}
	off, on := false, true
	if _, err := s.PatchUser(ctx, wire, orgA, bindingID, user.ID, service.SCIMUserInput{Active: &off}); err != nil {
		t.Fatal(err)
	}
	record()
	if err := grantSvc(db).Revoke(ctx, service.LocalPrincipal(orgAdmin), service.GrantSpec{
		Target: principal, Capability: domain.CapEdit, Scope: scope,
	}); err != nil {
		t.Fatal(err)
	}
	// Reactivation reconciles the flag: the remainder is gone, so the state is.
	if _, err := s.PatchUser(ctx, wire, orgA, bindingID, user.ID, service.SCIMUserInput{Active: &on}); err != nil {
		t.Fatal(err)
	}
	record()

	// inert_mapping: raised by a group delete, cleared by deleting the row.
	group, err := s.CreateGroup(ctx, wire, orgA, bindingID, service.SCIMGroupInput{
		DisplayName: "Inert", Members: []string{user.ID}, MembersPresent: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateMapping(ctx, service.LocalPrincipal(orgAdmin), orgA, bindingID,
		service.SCIMMappingSpec{GroupID: group.ID, Template: domain.TemplateViewer, ProjectID: string(prjA1)}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteGroup(ctx, wire, orgA, bindingID, group.ID); err != nil {
		t.Fatal(err)
	}
	record()
	if _, err := s.DeleteMapping(ctx, service.LocalPrincipal(orgAdmin), orgA, bindingID,
		service.SCIMMappingSpec{GroupID: group.ID, ProjectID: string(prjA1)}); err != nil {
		t.Fatal(err)
	}
	record()

	// post_restore: raised when every credential a binding has was minted under
	// an OLDER instance credential epoch — the one observable trace a restore
	// leaves in this tree, since the credentials a backup carries are
	// permanently dead by presentation (§9.1) — and cleared by re-mint plus the
	// first completed re-assertion cycle, which is the wire's own exit.
	restoreBinding, restoreToken := newSCIMBinding(t, db, "restore-idp")
	execRaw(t, db, `UPDATE auth_instance_state SET credential_epoch = credential_epoch + 1`)
	if _, err := s.GetBinding(ctx, service.LocalPrincipal(orgAdmin), orgA, restoreBinding); err != nil {
		t.Fatal(err)
	}
	record()
	if !entered[string(domain.AttentionPostRestore)] {
		t.Fatal("a binding whose every credential predates the current epoch must enter post_restore")
	}
	// The restored credential is dead by presentation, so the exit needs a
	// genuine re-mint — which is the first half of §9.1's exit condition.
	if _, err := s.GetUser(ctx, service.SCIMCredentialActor(restoreToken, restoreBinding),
		orgA, restoreBinding, "scu_none"); err == nil {
		t.Fatal("a credential from a previous epoch must be dead by presentation")
	}
	remint, err := s.MintCredential(ctx, service.LocalPrincipal(orgAdmin), orgA, restoreBinding, false, "")
	if err != nil {
		t.Fatal(err)
	}
	// …and the second half: the identity provider actually calls.
	if _, _, err := s.ListUsers(ctx, service.SCIMCredentialActor(remint.Token, restoreBinding),
		orgA, restoreBinding, scimproto.Filter{Shape: scimproto.FilterNone}, scimproto.Page{StartIndex: 1, Count: 10}); err != nil {
		t.Fatal(err)
	}
	record()

	// lockout_retention: raised when a release empties the LAST member
	// manager's row, cleared by §2.4's deterministic cure in the transaction
	// that creates another `manage-members` holder.
	runOneLockoutPath(t, db, "pairs", "deprovision",
		func(t *testing.T, s *service.SCIM, wire, self service.Actor, binding, user, group string) {
			off := false
			if _, err := s.PatchUser(ctx, wire, orgA, binding, user, service.SCIMUserInput{Active: &off}); err != nil {
				t.Fatal(err)
			}
		})
	// That cure runs through BREAK-GLASS, which has no principal and mints no
	// proof, so it cannot address the tenant's rows: the state comes down on
	// the next administration read, through the same audited exit path, under
	// the org's new member manager's own proof. Reading it here is the fixture
	// stating that the reconciliation is the exit path, not an afterthought.
	if _, err := s.ListBindings(ctx, service.LocalPrincipal(grantee), orgA); err != nil {
		t.Fatal(err)
	}
	record()

	// All SIX states, each entered AND cleared with its audit pair. A state
	// that can be entered and not left is a permanent warning nobody can act
	// on, which is why the assertion runs in both directions.
	for _, state := range domain.SCIMAttentionStates() {
		if !entered[string(state)] {
			t.Errorf("attention state %q is never entered with an audit event", state)
		}
		if !cleared[string(state)] {
			t.Errorf("attention state %q is never cleared with an audit event — "+
				"a state that cannot be left is a permanent warning", state)
		}
	}
}

// auditPayloadStates pulls the `state` member out of every event of one type.
func auditPayloadStates(t *testing.T, db *store.DB, typ string) []string {
	t.Helper()
	raw := queryStrings(t, db,
		`SELECT payload FROM audit_tenant_events WHERE type = '`+typ+`' ORDER BY id`)
	var out []string
	for _, chunk := range strings.Split(raw, "\n") {
		for _, state := range []string{
			"provider_unavailable", "lockout_retention", "manual_grants_remain",
			"inert_mapping", "stale", "post_restore",
		} {
			if strings.Contains(chunk, `"state":"`+state+`"`) {
				out = append(out, state)
			}
		}
	}
	return out
}

// TestSCIMPayloadSchemasAreValidatedOnWrite is SC4.k: every `scim.*` registry
// entry validates its payload at the write boundary — a missing required field,
// an unregistered field and a value outside a closed enum all FAIL the write.
func TestSCIMPayloadSchemasAreValidatedOnWrite(t *testing.T) {
	scimTypes := 0
	for _, typ := range audit.Types() {
		if !strings.HasPrefix(string(typ), "scim.") {
			continue
		}
		scimTypes++
		spec, ok := audit.Spec(typ)
		if !ok {
			t.Fatalf("%s is enumerated but has no registry row", typ)
		}
		if len(spec.Schema) == 0 {
			t.Errorf("%s declares no payload schema; §10 makes the field list the schema", typ)
			continue
		}
		envelope, trail, scope := scimAuditEnvelope(t, typ, spec)

		// The CONTROL: a schema-valid payload passes. Without it the negative
		// cases below could be failing for an unrelated envelope reason.
		envelope.Payload = validPayloadFor(spec.Schema)
		if err := audit.Validate(envelope, trail, scope); err != nil {
			t.Errorf("%s: a schema-valid payload was refused at the write boundary: %v", typ, err)
			continue
		}

		// A missing REQUIRED field fails.
		hasRequired := false
		for _, f := range spec.Schema {
			if f.Required {
				hasRequired = true
			}
		}
		if hasRequired {
			envelope.Payload = audit.Payload{}
			if err := audit.Validate(envelope, trail, scope); err == nil {
				t.Errorf("%s: an empty payload passed validation despite required fields", typ)
			}
		}

		// An UNREGISTERED field fails: §10 closes the field list, so a payload
		// may not smuggle an extra member past the boundary.
		envelope.Payload = validPayloadFor(spec.Schema)
		envelope.Payload["definitely_not_registered"] = "x"
		if err := audit.Validate(envelope, trail, scope); err == nil {
			t.Errorf("%s: an unregistered payload field passed validation", typ)
		}

		// A value outside a CLOSED ENUM fails.
		for name, f := range spec.Schema {
			if len(f.Enum) == 0 {
				continue
			}
			envelope.Payload = validPayloadFor(spec.Schema)
			envelope.Payload[name] = "definitely-not-in-the-enum"
			if err := audit.Validate(envelope, trail, scope); err == nil {
				t.Errorf("%s: field %q accepted a value outside its closed set %v", typ, name, f.Enum)
			}
		}

		// A WRONG-KINDED value fails, so the schema is a type declaration and
		// not merely a name list.
		for name, f := range spec.Schema {
			if f.Kind != audit.KindString || len(f.Enum) > 0 {
				continue
			}
			envelope.Payload = validPayloadFor(spec.Schema)
			envelope.Payload[name] = 12345
			if err := audit.Validate(envelope, trail, scope); err == nil {
				t.Errorf("%s: field %q accepted an int where the schema declares a string", typ, name)
			}
			break
		}
	}
	if scimTypes < 20 {
		t.Fatalf("the scim.* registry shrank to %d types; §10 closes the set", scimTypes)
	}
}

// scimAuditEnvelope builds a valid envelope for one registered type, so that
// every failure the fixture observes is attributable to the PAYLOAD.
func scimAuditEnvelope(t *testing.T, typ audit.EventType, spec audit.TypeSpec) (audit.Event, audit.Trail, domain.Scope) {
	t.Helper()
	id, err := audit.NewEventID()
	if err != nil {
		t.Fatal(err)
	}
	e := audit.Event{
		ID: id, Type: typ, SchemaVersion: spec.SchemaVersion,
		OccurredAt: time.Now().UTC(),
		Actor:      audit.Actor{Class: audit.ActorSystem},
		Origin:     audit.OriginSystem,
	}
	for outcome := range spec.Outcomes {
		e.Outcome = outcome
		break
	}
	trail := audit.TrailInstance
	scope := domain.Scope{}
	if spec.Trails[audit.TrailTenant] {
		trail, scope = audit.TrailTenant, orgAScope
	}
	return e, trail, scope
}

// validPayloadFor builds a schema-valid payload, so each negative case above
// differs from a passing one in exactly ONE way.
func validPayloadFor(schema audit.Schema) audit.Payload {
	out := audit.Payload{}
	for name, f := range schema {
		out[name] = sampleFor(f)
	}
	return out
}

// sampleFor builds a schema-valid value for one field.
func sampleFor(f audit.FieldSpec) any {
	switch f.Kind {
	case audit.KindBool:
		return true
	case audit.KindInt:
		if f.AtLeast != 0 {
			return f.AtLeast
		}
		return 1
	case audit.KindStringList:
		return []string{}
	case audit.KindObject:
		out := audit.Payload{}
		for n, sub := range f.ObjectSchema {
			out[n] = sampleFor(sub)
		}
		return out
	default:
		if len(f.Enum) > 0 {
			return f.Enum[0]
		}
		if f.Digest {
			// A real SHA-256 hex digest: the schema refuses anything else,
			// which is the point — a plaintext subject cannot be written into
			// a field declared to carry its digest.
			sum := sha256.Sum256([]byte("sample"))
			return hex.EncodeToString(sum[:])
		}
		return "sample"
	}
}

// TestSCIMRedactsIdPStrings is SC4.m: an identity-provider-supplied string that
// happens to look like a bearer token must be REDACTED before it lands in the
// trail. The identity provider is an attacker-influencable source.
func TestSCIMRedactsIdPStringsSQLite(t *testing.T) {
	runSCIMRedactsIdPStrings(t, seededDB(t, openSQLite))
}
func TestSCIMRedactsIdPStringsPostgres(t *testing.T) {
	runSCIMRedactsIdPStrings(t, seededDB(t, openPostgres))
}

func runSCIMRedactsIdPStrings(t *testing.T, db *store.DB) {
	s := scimSvc(db)
	ctx := t.Context()
	bindingID, token := newSCIMBinding(t, db, "okta")
	wire := service.SCIMCredentialActor(token, bindingID)

	// The poison is a REAL minted credential, not a token-shaped literal: the
	// claim is that the redactor recognizes what this system actually issues,
	// which a hand-written lookalike cannot establish.
	live, err := s.MintCredential(ctx, service.LocalPrincipal(orgAdmin), orgA, bindingID, false, "")
	if err != nil {
		t.Fatal(err)
	}
	poison := live.Token
	// It IS a valid SCIM artifact by the real parser — so the redaction below
	// is the redactor recognizing a genuine credential, not a coincidence.
	if err := crypto.ParseArtifact(poison, crypto.ArtifactSCIM); err != nil {
		t.Fatalf("the minted credential must parse as a SCIM artifact: %v", err)
	}
	if audit.RedactTokens(poison) != audit.RedactionMarker {
		t.Fatalf("the redactor does not recognize a real minted credential: %q", audit.RedactTokens(poison))
	}
	// Embedded in prose it is still removed COMPLETELY — a partial redaction
	// that leaves a suffix behind is a leaked secret with extra steps.
	embedded := audit.RedactTokens("before " + poison + " after")
	if strings.Contains(embedded, poison[10:]) {
		t.Fatalf("redaction left token material behind: %q", embedded)
	}
	if _, err := s.CreateGroup(ctx, wire, orgA, bindingID, service.SCIMGroupInput{
		DisplayName: poison,
	}); err != nil {
		t.Fatal(err)
	}
	payloads := queryStrings(t, db,
		`SELECT payload FROM audit_tenant_events WHERE type = 'scim.group_created' ORDER BY id`)
	if strings.Contains(payloads, poison) {
		t.Fatalf("an IdP-supplied token-shaped string reached the trail verbatim:\n%s", payloads)
	}
	if !strings.Contains(payloads, audit.RedactionMarker) {
		t.Fatalf("the token grammar must be redacted, not merely absent:\n%s", payloads)
	}
}

// TestSCIMMakesNoOutboundCalls is SC4.n: the zero-egress posture is unchanged.
// Hikyo never calls the identity provider — the provisioning connection is
// inbound-only, and no outbound trust exists.
func TestSCIMMakesNoOutboundCalls(t *testing.T) {
	// The SCIM packages must not import an HTTP CLIENT at all. A fixture that
	// asserted "no request was made during this test" would prove only that the
	// path under test did not take it; an import ban is structural.
	for _, pkg := range []string{
		"internal/scimproto", "internal/service", "internal/store",
	} {
		source := readGoFiles(t, "../../"+pkg)
		for _, banned := range []string{"http.Get(", "http.Post(", "http.DefaultClient", "(&http.Client{"} {
			if strings.Contains(source, banned) {
				t.Errorf("%s reaches outward with %q; SCIM is push-only and Hikyo never calls the identity provider", pkg, banned)
			}
		}
	}
}

// TestAuthorizeNeverReadsOrigins is SC3.n: authority is the bare
// (principal, capability, scope) triple. An origin-conditional permission
// would be a second authorization language, which §2 forbids by name — so the
// fixture proves origins are not merely unused at the decision point, but
// UNREACHABLE from it.
func TestAuthorizeNeverReadsOrigins(t *testing.T) {
	// 1. The decision VALUE carries no origin. `evaluate()` sees
	// []domain.Grant, and that type is the whole vocabulary a formula has.
	if n := reflect.TypeFor[domain.Grant]().NumField(); n != 2 {
		t.Fatalf("domain.Grant has %d fields; the decision input is the bare "+
			"(capability, scope) pair with the principal implicit", n)
	}
	for _, name := range []string{"Capability", "Scope"} {
		if _, ok := reflect.TypeFor[domain.Grant]().FieldByName(name); !ok {
			t.Fatalf("domain.Grant lost its %s field", name)
		}
	}

	// 2. The decision QUERY reads no origin. `Grants` is the only grant read
	// authorize() makes, and its SQL is the resolution surface's own.
	for _, dialect := range []string{"sqlite", "postgres"} {
		sql := grantResolutionSQL(t, dialect)
		if !strings.Contains(strings.ToLower(sql), "from grants") {
			t.Fatalf("%s: ListGrantsForPrincipal no longer reads the grants table:\n%s", dialect, sql)
		}
		if strings.Contains(strings.ToLower(sql), "grant_origins") {
			t.Fatalf("%s: the authorization query reads the origin table:\n%s", dialect, sql)
		}
	}

	// 3. The CALLER makes no other origin read. authorizeTenant and
	// authorizeInstance call exactly ResolveChain and Grants; anything origin-
	// shaped appearing there would be an origin-conditional decision.
	source := readGoFiles(t, "../../internal/authz")
	body := source[strings.Index(source, "func (a *TxAuthorizer) authorizeTenant"):]
	body = body[:strings.Index(body, "\nfunc (a *TxAuthorizer) Token()")]
	for _, banned := range []string{"GrantOrigin", "grant_origins", "OriginsFor", "Origin{"} {
		if strings.Contains(body, banned) {
			t.Fatalf("the authorization chokepoint mentions %q; authority is the triple alone", banned)
		}
	}
}

// grantResolutionSQL pulls the text of the one grant query authorize() runs.
func grantResolutionSQL(t *testing.T, dialect string) string {
	t.Helper()
	source := readGoFiles(t, "../../internal/store/"+map[string]string{
		"sqlite": "sqlitegen", "postgres": "pggen",
	}[dialect])
	const marker = "listGrantsForPrincipal = `"
	i := strings.Index(source, marker)
	if i < 0 {
		t.Fatalf("%s: the generated ListGrantsForPrincipal query is gone", dialect)
	}
	rest := source[i+len(marker):]
	return rest[:strings.Index(rest, "`")]
}
