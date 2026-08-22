package isolation

import (
	"errors"
	"fmt"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/samltest"
	"github.com/Hikyo-Org/hikyo/internal/service"
	"github.com/Hikyo-Org/hikyo/internal/store"
)

// SC2's named provision-then-login round-trips (#73 §5.1).
//
// Each drives SCIM provisioning AND the login ceremony against the SAME fixture
// identity provider, which is the only way to prove what the ADR actually
// demands: that the derived subject equals, BYTE-EXACTLY, what the login path
// computes. A test that asserted the two separately would pass while they
// disagreed, and the failure would surface as "provisioned users cannot log
// in" long after this ticket.

// TestSCIMProvisionThenLoginOIDC is the OKTA-SHAPED fixture: the subject source
// value IS the OIDC `sub`, consumed as opaque bytes.
func TestSCIMProvisionThenLoginOIDCSQLite(t *testing.T) {
	runSCIMProvisionThenLoginOIDC(t, seededDB(t, openSQLite))
}
func TestSCIMProvisionThenLoginOIDCPostgres(t *testing.T) {
	runSCIMProvisionThenLoginOIDC(t, seededDB(t, openPostgres))
}

func runSCIMProvisionThenLoginOIDC(t *testing.T, db *store.DB) {
	ctx := t.Context()
	auth, admin, _ := oidcAdmin(t, db)
	// No JIT policy: an unmatched subject must NOT be provisioned into
	// existence, or "the provisioned identity reached the known-identity path"
	// would be unfalsifiable.
	_, _ = configureProvider(t, auth, ctx, admin, "okta", service.ProviderInput{
		DisplayName: "Okta", ClientID: "c", ClientSecret: "s", Scopes: "openid", Enabled: true,
	})
	s := scimSvc(db)

	binding, err := s.CreateBinding(ctx, service.LocalPrincipal(admin), orgA, service.SCIMBindingInput{
		ProviderKind: domain.ProviderOIDC, ProviderSlug: "okta",
		SubjectSource: domain.SubjectSourceExternalID,
	})
	if err != nil {
		t.Fatalf("binding: %v", err)
	}
	mint, err := s.MintCredential(ctx, service.LocalPrincipal(admin), orgA, binding.ID, false, "")
	if err != nil {
		t.Fatal(err)
	}
	wire := service.SCIMCredentialActor(mint.Token, binding.ID)

	// The identity provider pushes a user whose `sub` will be `okta-sub-1`.
	user, err := s.CreateUser(ctx, wire, orgA, binding.ID, service.DesiredUser{Active: true,
		UserName: "lea@okta.test", ExternalID: "okta-sub-1",
	})
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	provisioned := accountOf(t, db, user.ID)
	accountsBefore := queryInt(t, db, `SELECT COUNT(*) FROM accounts`)

	// The human logs in later through that provider and matches the
	// KNOWN-IDENTITY path: the same account, and no new one.
	login := oidcLogin(t, auth, ctx, "okta", "okta-sub-1")
	if got := principalOf(t, db, provisioned); login.Principal != got {
		t.Fatalf("provisioned identity did not reach the known-identity path: login=%s provisioned=%s",
			login.Principal, got)
	}
	if after := queryInt(t, db, `SELECT COUNT(*) FROM accounts`); after != accountsBefore {
		t.Fatalf("the login created an account: %d -> %d", accountsBefore, after)
	}

	// BYTE-EXACT: a case variant is a DIFFERENT identity. With no JIT policy it
	// matches nothing and is refused, which is the observable form of "consumed
	// as opaque bytes".
	start, err := auth.OIDCStart(ctx, "okta", "login", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	code, state := driveIdP(t, start.AuthURL+"&sub=OKTA-SUB-1")
	if _, err := auth.OIDCCallback(ctx, "okta", code, state, "", "", start.BindingCookie, ""); !isUnauth(err) {
		t.Fatalf("a case-variant subject must be a distinct identity, got %v", err)
	}
	if after := queryInt(t, db, `SELECT COUNT(*) FROM accounts`); after != accountsBefore {
		t.Fatalf("the case-variant login touched the account table: %d -> %d", accountsBefore, after)
	}

	// §5.2: the provisioned account carries NO credential and NO assurance —
	// provisioning an identity and authorizing it are separate acts.
	if n := queryInt(t, db, `SELECT COUNT(*) FROM password_credentials WHERE account_id = '`+provisioned+`'`); n != 0 {
		t.Fatal("provisioning established a credential")
	}
	if n := grantsForSCIMUser(t, db, binding.ID, user.ID); n != 0 {
		t.Fatalf("a pushed user with no mapped groups must hold nothing; got %d", n)
	}
}

// TestSCIMProvisionThenLoginSAML is the ENTRA-SHAPED fixture: a scalar SCIM
// attribute cannot carry the locked SAML subject, so the binding declares the
// NameID PROFILE and the attribute supplies the value alone. This is the
// encoder-equality test: get the profile wrong — a qualifier declared absent
// that the assertion carries, say — and the two subjects differ and the login
// finds nothing.
func TestSCIMProvisionThenLoginSAMLSQLite(t *testing.T) {
	runSCIMProvisionThenLoginSAML(t, seededDB(t, openSQLite))
}
func TestSCIMProvisionThenLoginSAMLPostgres(t *testing.T) {
	runSCIMProvisionThenLoginSAML(t, seededDB(t, openPostgres))
}

const samlSPEntityID = "https://hikyo.test/api/v1/auth/saml"

func runSCIMProvisionThenLoginSAML(t *testing.T, db *store.DB) {
	ctx := t.Context()
	auth, admin, _ := oidcAdmin(t, db)
	auth.ExternalOrigin = "https://hikyo.test"
	idp := configureSAMLProvider(t, auth, admin)
	s := scimSvc(db)

	// The profile mirrors what this identity provider actually asserts: the
	// persistent Format, and BOTH qualifiers present. Presence is declared
	// separately from value because the injective encoder distinguishes an
	// absent qualifier from an empty one.
	binding, err := s.CreateBinding(ctx, service.LocalPrincipal(admin), orgA, service.SCIMBindingInput{
		ProviderKind: domain.ProviderSAML, ProviderSlug: "saml-idp",
		SubjectSource:            domain.SubjectSourceExternalID,
		NameIDFormat:             "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
		NameIDQualifier:          samltest.EntityID,
		NameIDQualifierPresent:   true,
		NameIDSPQualifier:        samlSPEntityID,
		NameIDSPQualifierPresent: true,
	})
	if err != nil {
		t.Fatalf("binding: %v", err)
	}
	mint, err := s.MintCredential(ctx, service.LocalPrincipal(admin), orgA, binding.ID, false, "")
	if err != nil {
		t.Fatal(err)
	}
	wire := service.SCIMCredentialActor(mint.Token, binding.ID)

	const nameID = "entra-user-1"
	user, err := s.CreateUser(ctx, wire, orgA, binding.ID, service.DesiredUser{Active: true,
		UserName: "mo@entra.test", ExternalID: nameID,
	})
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	provisioned := accountOf(t, db, user.ID)
	accountsBefore := queryInt(t, db, `SELECT COUNT(*) FROM accounts`)

	login := samlLoginAs(t, auth, idp, nameID)
	if got := principalOf(t, db, provisioned); login.Principal != got {
		t.Fatalf("the SCIM-derived SAML subject did not equal the login path's: login=%s provisioned=%s",
			login.Principal, got)
	}
	if after := queryInt(t, db, `SELECT COUNT(*) FROM accounts`); after != accountsBefore {
		t.Fatalf("the SAML login created an account: %d -> %d", accountsBefore, after)
	}
}

// samlLoginAs drives one SP-initiated SAML login for a NameID value.
func samlLoginAs(t *testing.T, auth *service.Auth, idp *samltest.IdP, nameID string) service.LoginResult {
	t.Helper()
	start, err := auth.SAMLStart(t.Context(), "saml-idp", "login", "", "", "")
	if err != nil {
		t.Fatalf("saml start: %v", err)
	}
	request, err := samltest.DecodeRequest(start.RedirectURL)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := idp.SignedResponse(samltest.Response{
		RequestID: request.ID, ResponseID: "res_" + nameID, AssertionID: "ass_" + nameID,
		ACSURL:     samlSPEntityID + "/saml-idp/acs",
		SPEntityID: samlSPEntityID,
		NameID:     nameID, Now: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := auth.SAMLACS(t.Context(), "saml-idp", encoded,
		samlAuditRelayState(t, start.RedirectURL), start.InitiatorCookie)
	if err != nil {
		t.Fatalf("saml acs: %v", err)
	}
	return res
}

// TestSCIMTwoBindingRace is SC3's named fixture: two bindings contending on ONE
// shared grant row. No lost origin, no premature revocation.
func TestSCIMTwoBindingRaceSQLite(t *testing.T) { runSCIMTwoBindingRace(t, seededDB(t, openSQLite)) }
func TestSCIMTwoBindingRacePostgres(t *testing.T) {
	runSCIMTwoBindingRace(t, seededDB(t, openPostgres))
}

func runSCIMTwoBindingRace(t *testing.T, db *store.DB) {
	ctx := t.Context()
	s := scimSvc(db)
	first, firstToken := newSCIMBinding(t, db, "idp-one")
	second, secondToken := newSCIMBinding(t, db, "idp-two")

	// ONE account, reached by both bindings. The second binding attaches to the
	// identity the first provisioned only if they share an issuer, which two
	// enabled providers may not — so the shared account is seeded once and both
	// bindings assert their own subject against it.
	execRaw(t, db, `INSERT INTO principals (id, kind, created_at) VALUES ('usr_shared', 'human', `+ts+`)`)
	execRaw(t, db, `INSERT INTO accounts (id, principal_id, username, display_name, created_at) `+
		`VALUES ('acc_shared', 'usr_shared', 'shared@example.test', 'Shared', `+ts+`)`)
	execRaw(t, db, `INSERT INTO external_identities (id, account_id, kind, issuer, subject, provider_id, credential_epoch, created_at) `+
		`VALUES ('eid_one', 'acc_shared', 'oidc', 'https://idp-one.example.test', 'shared', 'idp-one', 0, `+ts+`)`)
	execRaw(t, db, `INSERT INTO external_identities (id, account_id, kind, issuer, subject, provider_id, credential_epoch, created_at) `+
		`VALUES ('eid_two', 'acc_shared', 'oidc', 'https://idp-two.example.test', 'shared', 'idp-two', 0, `+ts+`)`)

	// Both bindings provision the same human and map a group to the SAME
	// template at the SAME scope, so both want one (principal, capability,
	// scope) row.
	type leg struct {
		binding string
		wire    service.Actor
		group   string
	}
	legs := make([]leg, 0, 2)
	for _, b := range []struct{ id, token, name string }{
		{first, firstToken, "one"}, {second, secondToken, "two"},
	} {
		wire := service.SCIMCredentialActor(b.token, b.id)
		u, err := s.CreateUser(ctx, wire, orgA, b.id, service.DesiredUser{Active: true,
			UserName: "shared-" + b.name + "@example.test", ExternalID: "shared", SubjectRaw: "shared",
		})
		if err != nil {
			t.Fatalf("provision on %s: %v", b.name, err)
		}
		if accountOf(t, db, u.ID) != "acc_shared" {
			t.Fatalf("binding %s did not attach the shared account", b.name)
		}
		g, err := s.CreateGroup(ctx, wire, orgA, b.id, service.DesiredGroup{
			DisplayName: "Readers " + b.name, Members: []string{u.ID},
		})
		if err != nil {
			t.Fatal(err)
		}
		legs = append(legs, leg{binding: b.id, wire: wire, group: g.ID})
	}

	// The two mappings are authored CONCURRENTLY, on separate connections,
	// released from one barrier — this is the actual race the ADR's overlap
	// rule has to survive. Authoring them one after the other would pass
	// whether or not the second transaction handles a row the first created,
	// which is the only interesting case.
	start, done := barrier(len(legs))
	raced := make([]error, len(legs))
	for i, b := range []struct{ id, name string }{{first, "one"}, {second, "two"}} {
		go func() {
			defer done.Done()
			<-start
			// A bounded retry, because two transactions inserting the same
			// (principal, capability, scope) row is exactly what the
			// uniqueness constraint arbitrates: one wins, the loser retries
			// and adds its origin to the winner's row.
			for attempt := range 8 {
				_, err := s.CreateMapping(ctx, service.LocalPrincipal(orgAdmin), orgA, b.id,
					service.SCIMMappingSpec{
						GroupID: legs[i].group, Template: domain.TemplateViewer, ProjectID: string(prjA1),
					})
				if err == nil || !errors.Is(err, store.ErrRetrySerialization) {
					raced[i] = err
					return
				}
				time.Sleep(time.Duration(attempt+1) * 2 * time.Millisecond)
			}
			raced[i] = fmt.Errorf("mapping on %s: retries exhausted", b.name)
		}()
	}
	close(start)
	done.Wait()
	for i, err := range raced {
		if err != nil {
			t.Fatalf("concurrent mapping author %d: %v", i, err)
		}
	}

	principal := domain.PrincipalID("usr_shared")
	scope := domain.Scope{Org: orgA, Project: prjA1}
	// ONE row, TWO origins: overlap is exact across bindings exactly as it is
	// between a hand grant and a sync.
	rows := queryInt(t, db, `SELECT COUNT(*) FROM grants WHERE principal_id = 'usr_shared' AND capability = 'read'`)
	if rows != 1 {
		t.Fatalf("two bindings wanting one triple must share one row; got %d", rows)
	}
	origins := queryInt(t, db,
		`SELECT COUNT(*) FROM grant_origins AS o INNER JOIN grants AS g ON g.id = o.grant_id `+
			`WHERE g.principal_id = 'usr_shared' AND g.capability = 'read' AND o.kind = 'scim'`)
	if origins != 2 {
		t.Fatalf("no origin may be lost: want 2 scim origins, got %d", origins)
	}

	// Releasing ONE binding's origin must not revoke the row: the other
	// binding still holds it, and a premature revocation here would take away
	// access the second identity provider still asserts.
	if _, err := s.PatchGroup(ctx, legs[0].wire, orgA, legs[0].binding, legs[0].group,
		[]service.GroupPatchCommand{service.GroupPatchClearMembers{}}); err != nil {
		t.Fatalf("release on the first binding: %v", err)
	}
	if !held(t, db, principal, domain.CapRead, scope) {
		t.Fatal("premature revocation: the second binding's origin still holds the row")
	}
	if origins := queryInt(t, db,
		`SELECT COUNT(*) FROM grant_origins AS o INNER JOIN grants AS g ON g.id = o.grant_id `+
			`WHERE g.principal_id = 'usr_shared' AND o.kind = 'scim'`); origins != 1 {
		t.Fatalf("exactly one origin should have been released; %d remain", origins)
	}

	// The second release is the last one, and only then does the row die.
	if _, err := s.PatchGroup(ctx, legs[1].wire, orgA, legs[1].binding, legs[1].group,
		[]service.GroupPatchCommand{service.GroupPatchClearMembers{}}); err != nil {
		t.Fatalf("release on the second binding: %v", err)
	}
	if held(t, db, principal, domain.CapRead, scope) {
		t.Fatal("the last origin's release must revoke the row")
	}
}

// TestSCIMPerBindingSerialization is SC4's "per-binding serialization under
// concurrent pushes". The property asserted is the observable one: concurrent
// pushes to ONE binding lose no write. Every wire transaction takes the binding
// row's write lock as its first act (`wireTx`), so they serialize behind it.
func TestSCIMPerBindingSerializationSQLite(t *testing.T) {
	runSCIMPerBindingSerialization(t, seededDB(t, openSQLite))
}
func TestSCIMPerBindingSerializationPostgres(t *testing.T) {
	runSCIMPerBindingSerialization(t, seededDB(t, openPostgres))
}

func runSCIMPerBindingSerialization(t *testing.T, db *store.DB) {
	s := scimSvc(db)
	bindingID, token := newSCIMBinding(t, db, "okta")
	wire := service.SCIMCredentialActor(token, bindingID)

	const pushes = 6
	var wg sync.WaitGroup
	errs := make([]error, pushes)
	for i := range pushes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			name := fmt.Sprintf("concurrent-%d@example.test", i)
			in := service.DesiredUser{
				UserName: name, ExternalID: fmt.Sprintf("ext-%d", i), SubjectRaw: fmt.Sprintf("ext-%d", i), Active: true,
			}
			// A bounded client-side retry, because that is what a connector
			// does and what the property is about. Six-way parallelism on ONE
			// binding is not the shape the ADR expects — "SCIM clients are
			// sequential in practice" — so exhausting postgres's serialization
			// budget under it is a throughput ceiling, not a lost write. What
			// must hold either way is that no push silently disappears.
			for attempt := range 4 {
				_, errs[i] = s.CreateUser(t.Context(), wire, orgA, bindingID, in)
				if errs[i] == nil {
					return
				}
				_ = attempt
			}
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("concurrent push %d failed: %v", i, err)
		}
	}
	// No lost update: every push is in the directory, with its own account.
	if n := queryInt(t, db, `SELECT COUNT(*) FROM scim_users WHERE binding_id = '`+bindingID+`'`); n != pushes {
		t.Fatalf("concurrent pushes lost a write: want %d rows, got %d", pushes, n)
	}
	if n := queryInt(t, db,
		`SELECT COUNT(DISTINCT account_id) FROM scim_users WHERE binding_id = '`+bindingID+`'`); n != pushes {
		t.Fatalf("concurrent pushes collided on one account: want %d, got %d", pushes, n)
	}
}

// TestSCIMReconcileKeepsFreshOrigins is SC4.h's other edge, and the one a
// naive filter gets wrong: the reconciliation commit must refuse ARCHIVED
// truth without destroying LIVE truth.
//
// The reachable sequence: a restore leaves every principal inert; the operator
// reconciles the binding's provisioning connection and re-mints, so the wire
// comes back; the identity provider's next cycle asserts something NEW about a
// user who is STILL unreconciled, creating fresh `scim` origins; and only then
// does the operator reconcile that user. A commit filtering on origin kind and
// principal alone would drop those fresh origins with the archived ones and
// delete the grants the IdP is asserting right now — access lost until the next
// cycle, roughly forty minutes later, for a user whose authority never lapsed.
//
// §9.1's sentence is precise about this: re-assertion "rebuilds exactly what
// the IdP currently asserts". Reconciliation refuses archived truth; it does
// not get to destroy live truth.
func TestSCIMReconcileKeepsFreshOriginsSQLite(t *testing.T) {
	runSCIMReconcileKeepsFreshOrigins(t, seededDB(t, openSQLite))
}
func TestSCIMReconcileKeepsFreshOriginsPostgres(t *testing.T) {
	runSCIMReconcileKeepsFreshOrigins(t, seededDB(t, openPostgres))
}

func runSCIMReconcileKeepsFreshOrigins(t *testing.T, db *store.DB) {
	ctx := t.Context()
	s := scimSvc(db)
	bindingID, token := newSCIMBinding(t, db, "okta")
	wire := service.SCIMCredentialActor(token, bindingID)

	user, err := s.CreateUser(ctx, wire, orgA, bindingID, service.DesiredUser{Active: true,
		UserName: "both@okta.test", ExternalID: "both", SubjectRaw: "both",
	})
	if err != nil {
		t.Fatal(err)
	}
	principal := principalOf(t, db, accountOf(t, db, user.ID))
	scope := domain.Scope{Org: orgA, Project: prjA1}

	// THE ARCHIVED HALF: a group and a mapping that existed when the backup was
	// taken, granting `read`.
	archived, err := s.CreateGroup(ctx, wire, orgA, bindingID, service.DesiredGroup{
		DisplayName: "Archived Readers", Members: []string{user.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateMapping(ctx, service.LocalPrincipal(orgAdmin), orgA, bindingID,
		service.SCIMMappingSpec{GroupID: archived.ID, Template: domain.TemplateViewer, ProjectID: string(prjA1)}); err != nil {
		t.Fatal(err)
	}
	if !held(t, db, principal, domain.CapRead, scope) {
		t.Fatal("setup: the archived mapping must have granted read")
	}

	// THE RESTORE. Every principal goes inert; the archived rows are exactly as
	// the backup left them.
	if err := runRestoreClosure(ctx, db, store.Manifest{
		Format: "hikyo-backup/1", Engine: db.Engine(), SchemaVersion: 18, CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("restore: %v", err)
	}

	// The operator reconciles the binding's provisioning CONNECTION and
	// re-mints, which is the only way the identity provider gets back on the
	// wire. The provisioned human is deliberately NOT reconciled yet — that is
	// the window this test is about.
	restoreSvc := &service.Restore{DB: db}
	connection := domain.PrincipalID(queryString(t, db,
		`SELECT connection_principal_id FROM scim_bindings WHERE id = '`+bindingID+`'`))
	for _, p := range []domain.PrincipalID{orgAdmin, connection} {
		if _, err := restoreSvc.Reconcile(ctx, p); err != nil {
			t.Fatalf("reconcile %s: %v", p, err)
		}
	}
	remint, err := s.MintCredential(ctx, service.LocalPrincipal(orgAdmin), orgA, bindingID, false, "")
	if err != nil {
		t.Fatalf("re-mint: %v", err)
	}
	rewire := service.SCIMCredentialActor(remint.Token, bindingID)

	// The identity provider's next cycle is minutes to hours later (§9 puts
	// Entra at roughly forty). The clock is moved rather than slept: this test
	// is about the PROVENANCE of an origin row, not about how many microseconds
	// two statements take, and a fixture that depends on the latter is a
	// fixture that flakes.
	s.Now = func() time.Time { return time.Now().UTC().Add(time.Hour) }

	// THE FRESH HALF: the IdP asserts something NEW about this still-inert user
	// — a second group, mapped into a DIFFERENT project — so the origins it
	// creates now are live truth, not archive. The scope is what tells the two
	// apart: same capability, same template, different chain, so a fixture that
	// discriminated on capability alone would be reading a template's expansion
	// rather than an origin's provenance.
	fresh, err := s.CreateGroup(ctx, rewire, orgA, bindingID, service.DesiredGroup{
		DisplayName: "Fresh Editors", Members: []string{user.ID},
	})
	if err != nil {
		t.Fatalf("re-assertion: %v", err)
	}
	if _, err := s.CreateMapping(ctx, service.LocalPrincipal(orgAdmin), orgA, bindingID,
		service.SCIMMappingSpec{GroupID: fresh.ID, Template: domain.TemplateViewer, ProjectID: string(prjA2)}); err != nil {
		t.Fatalf("fresh mapping: %v", err)
	}
	freshOrigins := queryInt(t, db,
		`SELECT COUNT(*) FROM grant_origins AS o INNER JOIN grants AS g ON g.id = o.grant_id `+
			`WHERE o.kind = 'scim' AND g.principal_id = '`+string(principal)+`' AND g.project_id = 'prj_a2'`)
	if freshOrigins == 0 {
		t.Fatal("setup: the re-assertion must have created a fresh scim origin")
	}

	// THE COMMIT. Archived origins go; fresh ones stay.
	if _, err := restoreSvc.Reconcile(ctx, principal); err != nil {
		t.Fatalf("reconcile the provisioned human: %v", err)
	}
	if n := queryInt(t, db,
		`SELECT COUNT(*) FROM grant_origins AS o INNER JOIN grants AS g ON g.id = o.grant_id `+
			`WHERE o.kind = 'scim' AND g.principal_id = '`+string(principal)+`' AND g.project_id = 'prj_a1'`); n != 0 {
		t.Fatal("§9.1: an ARCHIVED scim origin must still be dropped at the reconciliation commit")
	}
	if held(t, db, principal, domain.CapRead, scope) {
		t.Fatal("§9.1: a grant whose only origin was archived must not be re-activated")
	}
	if n := queryInt(t, db,
		`SELECT COUNT(*) FROM grant_origins AS o INNER JOIN grants AS g ON g.id = o.grant_id `+
			`WHERE o.kind = 'scim' AND g.principal_id = '`+string(principal)+`' AND g.project_id = 'prj_a2'`); n != freshOrigins {
		t.Fatal("§9.1: the commit must not drop origins the identity provider asserted AFTER the restore")
	}
	if !held(t, db, principal, domain.CapRead, domain.Scope{Org: orgA, Project: prjA2}) {
		t.Fatal("§9.1: re-assertion rebuilds what the IdP currently asserts — reconciliation must not destroy it")
	}
}

// TestSCIMRestoreDrill is SC4's restore drill (#73 §9.1), for every clause that
// HAS a seam in this tree. The one that does not — "restored `scim` origins are
// dropped at reconciliation commit" — is blocked on #76's quarantine/commit
// flow and is pinned by TestSCIMRestoreOriginDropIsBlockedOn76 below, which
// fails loudly the day that flow exists.
func TestSCIMRestoreDrillSQLite(t *testing.T)   { runSCIMRestoreDrill(t, seededDB(t, openSQLite)) }
func TestSCIMRestoreDrillPostgres(t *testing.T) { runSCIMRestoreDrill(t, seededDB(t, openPostgres)) }

func runSCIMRestoreDrill(t *testing.T, db *store.DB) {
	ctx := t.Context()
	auth, admin, _ := oidcAdmin(t, db)
	_, _ = configureProvider(t, auth, ctx, admin, "okta", service.ProviderInput{
		DisplayName: "Okta", ClientID: "c", ClientSecret: "s", Scopes: "openid", Enabled: true,
	})
	s := scimSvc(db)
	binding, err := s.CreateBinding(ctx, service.LocalPrincipal(admin), orgA, service.SCIMBindingInput{
		ProviderKind: domain.ProviderOIDC, ProviderSlug: "okta",
		SubjectSource: domain.SubjectSourceExternalID,
	})
	if err != nil {
		t.Fatal(err)
	}
	mint, err := s.MintCredential(ctx, service.LocalPrincipal(admin), orgA, binding.ID, false, "")
	if err != nil {
		t.Fatal(err)
	}
	wire := service.SCIMCredentialActor(mint.Token, binding.ID)

	// The backup's world: two provisioned users, one of whom is DEPROVISIONED
	// after the backup is taken.
	stays, err := s.CreateUser(ctx, wire, orgA, binding.ID, service.DesiredUser{Active: true,
		UserName: "stays@okta.test", ExternalID: "stays", SubjectRaw: "stays",
	})
	if err != nil {
		t.Fatal(err)
	}
	goes, err := s.CreateUser(ctx, wire, orgA, binding.ID, service.DesiredUser{Active: true,
		UserName: "goes@okta.test", ExternalID: "goes", SubjectRaw: "goes",
	})
	if err != nil {
		t.Fatal(err)
	}
	group, err := s.CreateGroup(ctx, wire, orgA, binding.ID, service.DesiredGroup{
		DisplayName: "Restored Readers", Members: []string{stays.ID, goes.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateMapping(ctx, service.LocalPrincipal(orgAdmin), orgA, binding.ID, service.SCIMMappingSpec{
		GroupID: group.ID, Template: domain.TemplateViewer, ProjectID: string(prjA1),
	}); err != nil {
		t.Fatal(err)
	}
	linkEpochBefore := queryInt(t, db,
		`SELECT credential_epoch FROM external_identities WHERE subject = 'stays'`)
	goesPrincipal := principalOf(t, db, accountOf(t, db, goes.ID))
	staysPrincipal := principalOf(t, db, accountOf(t, db, stays.ID))
	scope := domain.Scope{Org: orgA, Project: prjA1}
	if !held(t, db, goesPrincipal, domain.CapRead, scope) {
		t.Fatal("setup: the soon-to-be-deprovisioned user should hold the mapped grant")
	}

	// `goes` LOGS IN before the backup is taken, so the drill has a REAL
	// session to carry across it — the artifact a stale backup would restore
	// alongside the stale grant, and the one thing a human actually holds.
	// A fabricated token proves only that nonsense is refused.
	goesStart, err := auth.OIDCStart(ctx, "okta", "login", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	goesCode, goesState := driveIdP(t, goesStart.AuthURL+"&sub=goes")
	login, err := auth.OIDCCallback(ctx, "okta", goesCode, goesState, "", "", goesStart.BindingCookie, "")
	if err != nil {
		t.Fatalf("pre-backup login: %v", err)
	}
	goesSession := login.Login.SessionToken
	if goesSession == "" {
		t.Fatal("the pre-backup login must mint a real session")
	}
	// It works, and it reaches the object the mapping's `read` grant covers.
	// Without this control the denials below would prove nothing.
	_, projects, _ := services(t, db)
	protectedOp := func(token string) error {
		_, err := projects.Get(ctx, service.Bearer(token), scopeProject(orgA, prjA1))
		return err
	}
	if err := protectedOp(goesSession); err != nil {
		t.Fatalf("the pre-backup session must reach a protected operation: %v", err)
	}
	generationBefore := queryInt(t, db,
		`SELECT session_generation FROM principals WHERE id = '`+string(goesPrincipal)+`'`)

	// THE BACKUP. A snapshot of exactly what a restore would bring back for
	// `goes`: the grant row the mapping created and the `scim` origin holding
	// it. Taking it as ROWS rather than as a flag is what makes the restore
	// below a restore rather than a re-run of the sync.
	// `stays` also holds a HAND grant, so the commit's affirmative half — manual
	// origins DO commit — has something to be true about.
	if _, err := grantSvc(db).Create(ctx, service.LocalPrincipal(admin), service.GrantSpec{
		Target: staysPrincipal, Capability: domain.CapEdit, Scope: scope,
	}); err != nil {
		t.Fatalf("hand grant: %v", err)
	}
	backupGrant := queryString(t, db,
		`SELECT id FROM grants WHERE principal_id = '`+string(goesPrincipal)+`' AND capability = 'read'`)
	backupOrigin := queryString(t, db,
		`SELECT subject FROM grant_origins WHERE grant_id = '`+backupGrant+`' AND kind = 'scim'`)
	if backupGrant == "" || backupOrigin == "" {
		t.Fatal("setup: the backup must carry a real grant row and its scim origin")
	}

	// AFTER THE BACKUP, the identity provider withdraws `goes`. This is the
	// state the world is really in when the restore happens.
	offGoes := false
	if _, err := s.PatchUser(ctx, wire, orgA, binding.ID, goes.ID,
		[]service.UserPatchCommand{service.UserPatchSetActive{Active: offGoes}}); err != nil {
		t.Fatalf("post-backup deprovision: %v", err)
	}
	if held(t, db, goesPrincipal, domain.CapRead, scope) {
		t.Fatal("the post-backup deprovision must release the grant it authorized")
	}
	// §5.3: the deprovision advances the generation UNCONDITIONALLY, so the
	// session minted before it is already dead — and this is the exact denial
	// the restore must not undo.
	if after := queryInt(t, db,
		`SELECT session_generation FROM principals WHERE id = '`+string(goesPrincipal)+`'`); after <= generationBefore {
		t.Fatalf("the deprovision must advance the generation: %d -> %d", generationBefore, after)
	}
	if err := protectedOp(goesSession); !isUnauth(err) {
		t.Fatalf("the pre-backup session must die with the deprovision, got %v", err)
	}

	// THE RESTORE. Two things happen at once, and the drill needs both:
	//
	//  1. the STALE ROWS come back — the backup's grant and its `scim` origin
	//     are re-inserted, which is the window §9.1 is written about;
	//  2. every credential verifier becomes permanently dead and every restored
	//     identity link inert, because the instance credential epoch moved.
	execRaw(t, db, `INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) `+
		`VALUES ('`+backupGrant+`', '`+string(goesPrincipal)+`', 'read', 'org_a', 'prj_a1', NULL, `+ts+`)`)
	execRaw(t, db, `INSERT INTO grant_origins (id, grant_id, kind, subject, created_at) `+
		`VALUES ('gor_restored', '`+backupGrant+`', 'scim', '`+backupOrigin+`', `+ts+`)`)
	// `active` is BOOLEAN on postgres and an integer flag on sqlite, so the
	// literal differs; the restore it models does not.
	trueLit := "1"
	if db.PG() != nil {
		trueLit = "TRUE"
	}
	execRaw(t, db, `UPDATE scim_users SET active = `+trueLit+` WHERE id = '`+goes.ID+`'`)
	// …and the RESTORE ITSELF: #76's own closure, the same act the restore
	// transaction runs against restored state. It advances the restore epoch
	// (every verifier, session and identity link becomes inert by predicate)
	// and strips every principal's reconciliation stamp, so nothing authorizes
	// until an operator commits it back one principal at a time.
	if err := runRestoreClosure(ctx, db, store.Manifest{
		Format: "hikyo-backup/1", Engine: db.Engine(), SchemaVersion: 17, CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("restore: %v", err)
	}

	if _, err := s.GetUser(ctx, wire, orgA, binding.ID, stays.ID); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("a restored credential verifier must be permanently dead, got %v", err)
	}
	// Re-assertion does NOT re-bless a link: a login through the provider is
	// still refused, because the link's epoch is the operator's to reconcile.
	start, err := auth.OIDCStart(ctx, "okta", "login", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	code, state := driveIdP(t, start.AuthURL+"&sub=stays")
	if _, err := auth.OIDCCallback(ctx, "okta", code, state, "", "", start.BindingCookie, ""); !isUnauth(err) {
		t.Fatalf("a restored identity link must stay inert until operator reconciliation, got %v", err)
	}

	// THE WINDOW between the restore and the operator's reconciliation is where
	// a stale backup is dangerous: `goes` was withdrawn at the identity
	// provider AFTER the backup was taken, so the restored rows still show them
	// authorized. The drill's claim is that they are never AUTHORIZED at any
	// point in the window — the epoch bump makes every restored session and
	// every restored link inert, so there is no door left to reach the grant
	// through.
	//
	// The REAL pre-backup session first: a restore brings the session row back
	// with everything else, and it must still be refused.
	execRaw(t, db, `UPDATE sessions SET session_generation = `+
		strconv.FormatInt(generationBefore, 10)+` WHERE principal_id = '`+string(goesPrincipal)+`'`)
	if err := protectedOp(goesSession); !isUnauth(err) {
		t.Fatalf("a RESTORED session of a post-backup-deprovisioned user must be refused, got %v", err)
	}
	relogin, err := auth.OIDCStart(ctx, "okta", "login", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	reCode, reState := driveIdP(t, relogin.AuthURL+"&sub=goes")
	if _, err := auth.OIDCCallback(ctx, "okta", reCode, reState, "", "", relogin.BindingCookie, ""); !isUnauth(err) {
		t.Fatalf("a user withdrawn after the backup must not be able to log in during the restore window, got %v", err)
	}
	// And no wire push can re-bless them either: every credential is dead.
	if _, err := s.PatchUser(ctx, wire, orgA, binding.ID, goes.ID,
		nil); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("the restore window must refuse the whole wire surface, got %v", err)
	}
	// A PROTECTED OPERATION attempted as `goes`, through every door a human
	// has: the restored session above, a fresh login above, and the degenerate
	// artifacts below. All are refused, so the restored grant row is
	// unreachable for the whole window.
	//
	// The stale ROW is genuinely back — that is what a restore does, and it is
	// what §9.1's rule is about. Nothing can reach it: every principal is
	// unreconciled, so no grant authorizes at all yet.
	if n := queryInt(t, db, `SELECT COUNT(*) FROM grant_origins WHERE grant_id = '`+backupGrant+
		`' AND kind = 'scim'`); n != 1 {
		t.Fatal("the restore must actually have brought the stale scim origin back, or this window proves nothing")
	}
	for _, artifact := range []string{"", "hik_1_ses_restored_nonsense"} {
		if err := protectedOp(artifact); !isUnauth(err) {
			t.Fatalf("a protected operation during the restore window must fail authentication, got %v", err)
		}
	}

	// ---------------------------------------------------------------------
	// SC4.h — the reconciliation commit (#73 §9.1, on #76's flow)
	// ---------------------------------------------------------------------
	//
	// The operator commits one principal at a time. The commit covers `manual`
	// origins ONLY: every restored `scim` origin is dropped in the same act,
	// and a row whose only restored origins were `scim` is not re-activated.
	restoreSvc := &service.Restore{DB: db}

	// `goes` first — the user the identity provider withdrew after the backup.
	// Their grant's only origin was `scim`, so the commit drops the origin AND
	// the row, and the user is not authorized at this point either.
	if _, err := restoreSvc.Reconcile(ctx, goesPrincipal); err != nil {
		t.Fatalf("reconcile goes: %v", err)
	}
	if n := queryInt(t, db, `SELECT COUNT(*) FROM grant_origins WHERE grant_id = '`+backupGrant+
		`' AND kind = 'scim'`); n != 0 {
		t.Fatal("§9.1: a restored `scim` origin must be DROPPED at reconciliation commit, not committed")
	}
	if n := queryInt(t, db, `SELECT COUNT(*) FROM grants WHERE id = '`+backupGrant+`'`); n != 0 {
		t.Fatal("§9.1: a row whose only restored origins were `scim` must not be re-activated")
	}
	if held(t, db, goesPrincipal, domain.CapRead, scope) {
		t.Fatal("a post-backup-deprovisioned user must not be authorized by the reconciliation commit")
	}

	// `stays` next — the user the identity provider still asserts. Their HAND
	// grant commits, because manual origins are exactly what the commit covers;
	// their SCIM-held grant does not, because it awaits re-assertion.
	if _, err := restoreSvc.Reconcile(ctx, staysPrincipal); err != nil {
		t.Fatalf("reconcile stays: %v", err)
	}
	if !held(t, db, staysPrincipal, domain.CapEdit, scope) {
		t.Fatal("§9.1: the operator's commit covers `manual` origins — a hand grant must come back")
	}
	if held(t, db, staysPrincipal, domain.CapRead, scope) {
		t.Fatal("§9.1: a SCIM-held grant must not be re-activated by the commit; re-assertion rebuilds it")
	}

	// The administrator is reconciled too — the restore made everybody inert,
	// including whoever has to repair the binding — and so is the binding's
	// own provisioning connection, whose structural `scim-provision` grant is
	// what lets the identity provider back onto the wire at all. Its structural
	// origin SURVIVES the commit: it was created with the binding, not asserted
	// by the IdP, so nothing would ever recreate it.
	if _, err := restoreSvc.Reconcile(ctx, admin); err != nil {
		t.Fatalf("reconcile admin: %v", err)
	}
	connection := domain.PrincipalID(queryString(t, db,
		`SELECT connection_principal_id FROM scim_bindings WHERE id = '`+binding.ID+`'`))
	if _, err := restoreSvc.Reconcile(ctx, connection); err != nil {
		t.Fatalf("reconcile the provisioning connection: %v", err)
	}
	if !held(t, db, connection, domain.CapSCIMProvision, orgAScope) {
		t.Fatal("§9.1 drops `scim` origins, not `structural` ones: the connection's own grant must survive")
	}

	// The org admin RE-MINTS, which is the only way back onto the wire.
	remint, err := s.MintCredential(ctx, service.LocalPrincipal(admin), orgA, binding.ID, false, "")
	if err != nil {
		t.Fatalf("re-mint: %v", err)
	}
	rewire := service.SCIMCredentialActor(remint.Token, binding.ID)

	// The identity provider's next cycle asserts LIVE TRUTH: `goes` is gone
	// from the group, `stays` is not. This is the half of §9.1 that DOES work
	// today — re-assertion rebuilds exactly what the IdP currently asserts, and
	// what it no longer asserts is released.
	if _, err := s.PatchGroup(ctx, rewire, orgA, binding.ID, group.ID,
		[]service.GroupPatchCommand{service.GroupPatchReplaceMembers{Members: []string{stays.ID}}}); err != nil {
		t.Fatalf("re-assertion: %v", err)
	}
	if held(t, db, goesPrincipal, domain.CapRead, scope) {
		t.Fatal("a user the identity provider no longer asserts must not be authorized after restore")
	}
	if !held(t, db, staysPrincipal, domain.CapRead, scope) {
		t.Fatal("re-assertion must rebuild exactly what the identity provider currently asserts")
	}
	// Re-assertion rebuilt ORIGINS, never links: the link's epoch is untouched,
	// so the operator's per-principal reconciliation is still owed.
	if after := queryInt(t, db,
		`SELECT credential_epoch FROM external_identities WHERE subject = 'stays'`); after != linkEpochBefore {
		t.Fatalf("re-assertion must not re-bless a restored identity link: epoch %d -> %d",
			linkEpochBefore, after)
	}
	// The restored session is STILL refused after re-assertion — SCIM rebuilt
	// origins, and origins are not authentication.
	if err := protectedOp(goesSession); !isUnauth(err) {
		t.Fatalf("re-assertion must not revive a restored session, got %v", err)
	}
	// And the link is still inert: the login is refused after re-assertion too.
	postStart, err := auth.OIDCStart(ctx, "okta", "login", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	postCode, postState := driveIdP(t, postStart.AuthURL+"&sub=stays")
	if _, err := auth.OIDCCallback(ctx, "okta", postCode, postState, "", "", postStart.BindingCookie, ""); !isUnauth(err) {
		t.Fatalf("SCIM re-assertion must not substitute for operator reconciliation, got %v", err)
	}
}
