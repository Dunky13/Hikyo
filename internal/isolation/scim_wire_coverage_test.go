package isolation

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/crypto"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/samltest"
	"github.com/Hikyo-Org/hikyo/internal/scimproto"
	"github.com/Hikyo-Org/hikyo/internal/service"
	"github.com/Hikyo-Org/hikyo/internal/store"
)

// SCIM wire-coverage fixtures (#73 SC1.d/f/n/o, SC2.b/c/g/i, SC4.c).

// TestSCIMWirePaging is SC1.d: the RFC ListResponse fields, 1-based paging, and
// an out-of-range page answering an EMPTY resource list with a TRUTHFUL total.
func TestSCIMWirePagingSQLite(t *testing.T)   { runSCIMWirePaging(t, seededDB(t, openSQLite)) }
func TestSCIMWirePagingPostgres(t *testing.T) { runSCIMWirePaging(t, seededDB(t, openPostgres)) }

func runSCIMWirePaging(t *testing.T, db *store.DB) {
	s := scimSvc(db)
	ctx := t.Context()
	bindingID, token := newSCIMBinding(t, db, "okta")
	wire := service.SCIMCredentialActor(token, bindingID)

	const total = 5
	for i := range total {
		if _, err := s.CreateUser(ctx, wire, orgA, bindingID, service.DesiredUser{Active: true,
			UserName:   fmt.Sprintf("page-%d@example.test", i),
			ExternalID: fmt.Sprintf("page-%d", i), SubjectRaw: fmt.Sprintf("page-%d", i),
		}); err != nil {
			t.Fatal(err)
		}
	}

	none := scimproto.Filter{Shape: scimproto.FilterNone}
	// A page in the middle: 1-BASED, so startIndex 2 skips exactly one.
	got, reported, err := s.ListUsers(ctx, wire, orgA, bindingID, none,
		scimproto.Page{StartIndex: 2, Count: 2})
	if err != nil {
		t.Fatal(err)
	}
	if reported != total || len(got) != 2 {
		t.Fatalf("page 2..3 of %d: total=%d len=%d", total, reported, len(got))
	}
	all, _, err := s.ListUsers(ctx, wire, orgA, bindingID, none, scimproto.Page{StartIndex: 1, Count: total})
	if err != nil {
		t.Fatal(err)
	}
	if got[0].ID != all[1].ID {
		t.Fatalf("startIndex is 1-based: page 2 must begin at the SECOND resource")
	}

	// Out of range: empty Resources, truthful totalResults. A connector pages
	// until it runs out, and a lying total makes it loop or stop early.
	empty, reported, err := s.ListUsers(ctx, wire, orgA, bindingID, none,
		scimproto.Page{StartIndex: 99, Count: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(empty) != 0 || reported != total {
		t.Fatalf("out-of-range page: len=%d total=%d, want 0 and %d", len(empty), reported, total)
	}
	body := scimproto.ListResponse(reported, scimproto.Page{StartIndex: 99, Count: 10}, nil)
	for _, field := range []string{"schemas", "totalResults", "startIndex", "itemsPerPage", "Resources"} {
		if _, ok := body[field]; !ok {
			t.Fatalf("the ListResponse envelope omits %q", field)
		}
	}

	// A filter narrows the TOTAL too, not just the page.
	one, reported, err := s.ListUsers(ctx, wire, orgA, bindingID,
		scimproto.Filter{Shape: scimproto.FilterUserNameEq, Value: "page-3@example.test"},
		scimproto.Page{StartIndex: 1, Count: 10})
	if err != nil {
		t.Fatal(err)
	}
	if reported != 1 || len(one) != 1 {
		t.Fatalf("a filtered list must report the filtered total: total=%d len=%d", reported, len(one))
	}
}

// TestSCIMWireAdmission is SC4.c: bounded page and body refusals by name, and
// the uniform unknown-versus-revoked answer.
func TestSCIMWireAdmissionSQLite(t *testing.T)   { runSCIMWireAdmission(t, seededDB(t, openSQLite)) }
func TestSCIMWireAdmissionPostgres(t *testing.T) { runSCIMWireAdmission(t, seededDB(t, openPostgres)) }

func runSCIMWireAdmission(t *testing.T, db *store.DB) {
	s := scimSvc(db)
	ctx := t.Context()
	bindingID, token := newSCIMBinding(t, db, "okta")

	// The page bound CLAMPS rather than refusing: RFC 7644 makes `count` a
	// request, and the server's bound is the answer.
	page, e := scimproto.ParsePage("1", "100000", s.PageBound())
	if e != nil {
		t.Fatalf("an over-large count must clamp, not refuse: %v", e)
	}
	if page.Count != s.PageBound() {
		t.Fatalf("count = %d, want the bound %d", page.Count, s.PageBound())
	}

	// The BODY bound refuses by name, at the protocol boundary.
	oversized := make([]byte, (1<<20)+1)
	for i := range oversized {
		oversized[i] = ' '
	}
	if _, err := scimproto.DecodeUser(oversized); err == nil {
		t.Fatal("an over-large body must be refused")
	} else if err.Status != 413 {
		t.Fatalf("over-large body: status = %d, want 413", err.Status)
	}

	// Unknown versus revoked: indistinguishable. A caller that could tell them
	// apart could enumerate which credentials have ever existed.
	unknown, _, err := crypto.NewArtifact(crypto.ArtifactSCIM)
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := s.ListCredentials(ctx, service.LocalPrincipal(orgAdmin), orgA, bindingID)
	if err != nil || len(credentials) != 1 {
		t.Fatalf("setup: %v (%d credentials)", err, len(credentials))
	}
	if err := s.RevokeCredential(ctx, service.LocalPrincipal(orgAdmin), orgA, bindingID, credentials[0].ID); err != nil {
		t.Fatal(err)
	}
	revokedErr := probeSCIMCredential(t, s, token, bindingID)
	unknownErr := probeSCIMCredential(t, s, unknown, bindingID)
	if revokedErr.Error() != unknownErr.Error() {
		t.Fatalf("revoked and unknown credentials must be indistinguishable:\n  revoked: %q\n  unknown: %q",
			revokedErr, unknownErr)
	}
	if !errors.Is(revokedErr, domain.ErrUnauthenticated) {
		t.Fatalf("a revoked credential must answer the uniform authentication failure, got %v", revokedErr)
	}
}

func probeSCIMCredential(t *testing.T, s *service.SCIM, token, bindingID string) error {
	t.Helper()
	_, err := s.GetUser(t.Context(), service.SCIMCredentialActor(token, bindingID),
		orgA, bindingID, "scu_absent")
	if err == nil {
		t.Fatal("a dead credential must not authenticate")
	}
	return err
}

// TestSCIMPatchAtomicityOverTheWire is SC1.f through the SERVICE, not only the
// parser: a request whose first operation is valid and whose second is not must
// commit NOTHING.
func TestSCIMPatchAtomicityOverTheWireSQLite(t *testing.T) {
	runSCIMPatchAtomicityOverTheWire(t, seededDB(t, openSQLite))
}
func TestSCIMPatchAtomicityOverTheWirePostgres(t *testing.T) {
	runSCIMPatchAtomicityOverTheWire(t, seededDB(t, openPostgres))
}

func runSCIMPatchAtomicityOverTheWire(t *testing.T, db *store.DB) {
	s := scimSvc(db)
	ctx := t.Context()
	bindingID, token := newSCIMBinding(t, db, "okta")
	wire := service.SCIMCredentialActor(token, bindingID)

	user, err := s.CreateUser(ctx, wire, orgA, bindingID, service.DesiredUser{Active: true,
		UserName: "atomic@example.test", ExternalID: "ext-atomic", SubjectRaw: "ext-atomic",
		Attributes: map[string]any{"nickName": "before"},
	})
	if err != nil {
		t.Fatal(err)
	}

	// The parser rejects the WHOLE request, so the valid first operation never
	// reaches the service at all.
	body := []byte(`{"schemas":["` + scimproto.SchemaPatchOp + `"],"Operations":[` +
		`{"op":"replace","path":"nickName","value":"after"},` +
		`{"op":"remove","path":"userName"}]}`)
	if _, e := scimproto.ParsePatch(body, scimproto.ResourceUser); e == nil {
		t.Fatal("one invalid operation must fail the whole request")
	} else if e.SCIMType != scimproto.TypeInvalidPath {
		t.Fatalf("scimType = %q, want invalidPath", e.SCIMType)
	}

	fresh, err := s.GetUser(ctx, wire, orgA, bindingID, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if fresh.Attributes["nickName"] != "before" {
		t.Fatalf("the valid operation must not have been applied: %v", fresh.Attributes["nickName"])
	}

	// And ORDER is preserved for a request that IS valid: two `active`
	// operations must leave the LAST one's state, not an arbitrary one.
	off, on := false, true
	if _, err := s.PatchUser(ctx, wire, orgA, bindingID, user.ID,
		[]service.UserPatchCommand{
			service.UserPatchSetActive{Active: off},
			service.UserPatchSetActive{Active: on},
		}); err != nil {
		t.Fatal(err)
	}
	fresh, err = s.GetUser(ctx, wire, orgA, bindingID, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !fresh.Active {
		t.Fatal("the last operation's state must win")
	}
}

// TestSCIMTransitionTable is SC2.g: every §5.4 row with a real POSTCONDITION.
// The earlier fixtures walked the transitions with nothing mapped, so update,
// reactivate and delete were no-ops that could not fail.
func TestSCIMTransitionTableSQLite(t *testing.T) { runSCIMTransitionTable(t, seededDB(t, openSQLite)) }
func TestSCIMTransitionTablePostgres(t *testing.T) {
	runSCIMTransitionTable(t, seededDB(t, openPostgres))
}

func runSCIMTransitionTable(t *testing.T, db *store.DB) {
	s := scimSvc(db)
	ctx := t.Context()
	bindingID, token := newSCIMBinding(t, db, "okta")
	wire := service.SCIMCredentialActor(token, bindingID)
	scope := domain.Scope{Org: orgA, Project: prjA1}

	user, err := s.CreateUser(ctx, wire, orgA, bindingID, service.DesiredUser{Active: true,
		UserName: "tt@example.test", ExternalID: "ext-tt", SubjectRaw: "ext-tt",
	})
	if err != nil {
		t.Fatal(err)
	}
	group, err := s.CreateGroup(ctx, wire, orgA, bindingID, service.DesiredGroup{
		DisplayName: "TT", Members: []string{user.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateMapping(ctx, service.LocalPrincipal(orgAdmin), orgA, bindingID,
		service.SCIMMappingSpec{GroupID: group.ID, Template: domain.TemplateViewer, ProjectID: string(prjA1)}); err != nil {
		t.Fatal(err)
	}
	principal := principalOf(t, db, accountOf(t, db, user.ID))
	if !held(t, db, principal, domain.CapRead, scope) {
		t.Fatal("setup: the mapped member must hold the grant")
	}
	originsBefore := scimOriginCount(t, db, principal)

	// ROW: user update (attributes). Grants UNTOUCHED — the postcondition the
	// earlier fixture had none of.
	if _, err := s.PatchUser(ctx, wire, orgA, bindingID, user.ID,
		[]service.UserPatchCommand{service.UserPatchMergeAttributes{
			Attributes: map[string]any{"nickName": "Tee"},
		}}); err != nil {
		t.Fatal(err)
	}
	if !held(t, db, principal, domain.CapRead, scope) || scimOriginCount(t, db, principal) != originsBefore {
		t.Fatal("an attribute update must leave grants and origins untouched")
	}

	// ROW: active true -> false. Origins released.
	off, on := false, true
	if _, err := s.PatchUser(ctx, wire, orgA, bindingID, user.ID,
		[]service.UserPatchCommand{service.UserPatchSetActive{Active: off}}); err != nil {
		t.Fatal(err)
	}
	if held(t, db, principal, domain.CapRead, scope) {
		t.Fatal("deactivation must release the mapped grant")
	}

	// ROW: active false -> true recreates from CURRENT desired state. The
	// desired state is changed WHILE INACTIVE — a second mapping row — so
	// reactivation must produce the new set, not restore the old one.
	if _, err := s.CreateMapping(ctx, service.LocalPrincipal(orgAdmin), orgA, bindingID,
		service.SCIMMappingSpec{GroupID: group.ID, Template: domain.TemplateRevealer, ProjectID: string(prjA1)}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PatchUser(ctx, wire, orgA, bindingID, user.ID,
		[]service.UserPatchCommand{service.UserPatchSetActive{Active: on}}); err != nil {
		t.Fatal(err)
	}
	if !held(t, db, principal, domain.CapRead, scope) {
		t.Fatal("reactivation must recreate the first mapping's grant")
	}
	if !held(t, db, principal, domain.CapReveal, scope) {
		t.Fatal("reactivation is DESIRED STATE: the row added while inactive must apply too")
	}

	// ROW: group rename. Mapping rows key on the ID, so grants do not move.
	if _, err := s.PatchGroup(ctx, wire, orgA, bindingID, group.ID,
		[]service.GroupPatchCommand{service.GroupPatchSetDisplayName{DisplayName: "TT renamed"}}); err != nil {
		t.Fatal(err)
	}
	if !held(t, db, principal, domain.CapRead, scope) {
		t.Fatal("a group rename must not move grants: mapping rows key on the id")
	}

	// ROW: DELETE scrubs member references IN-TRANSACTION.
	memberships := queryInt(t, db,
		`SELECT COUNT(*) FROM scim_group_members WHERE user_id = '`+user.ID+`'`)
	if memberships != 1 {
		t.Fatalf("setup: want one membership, got %d", memberships)
	}
	if err := s.DeleteUser(ctx, wire, orgA, bindingID, user.ID); err != nil {
		t.Fatal(err)
	}
	if n := queryInt(t, db,
		`SELECT COUNT(*) FROM scim_group_members WHERE user_id = '`+user.ID+`'`); n != 0 {
		t.Fatal("DELETE must remove every member reference in the same transaction")
	}
	if held(t, db, principal, domain.CapRead, scope) {
		t.Fatal("DELETE must release the mapped grants")
	}

	// ROW: re-create after DELETE gets a FRESH id, and picks the desired state
	// up again from zero memberships.
	again, err := s.CreateUser(ctx, wire, orgA, bindingID, service.DesiredUser{Active: true,
		UserName: "tt@example.test", ExternalID: "ext-tt", SubjectRaw: "ext-tt",
	})
	if err != nil {
		t.Fatal(err)
	}
	if again.ID == user.ID {
		t.Fatal("a re-create must mint a fresh resource id")
	}
	if held(t, db, principal, domain.CapRead, scope) {
		t.Fatal("a re-created user belongs to no group yet and must hold nothing")
	}
}

func scimOriginCount(t *testing.T, db *store.DB, p domain.PrincipalID) int64 {
	t.Helper()
	return queryInt(t, db,
		`SELECT COUNT(*) FROM grant_origins AS o INNER JOIN grants AS g ON g.id = o.grant_id `+
			`WHERE g.principal_id = '`+string(p)+`' AND o.kind = 'scim'`)
}

// TestSCIMZeroAuthorityOnCreate is SC2.c: a provisioned account has NO session,
// NO assurance and NO credential — asserted by ATTEMPTING authenticated
// operations, not by counting rows.
func TestSCIMZeroAuthorityOnCreateSQLite(t *testing.T) {
	runSCIMZeroAuthorityOnCreate(t, seededDB(t, openSQLite))
}
func TestSCIMZeroAuthorityOnCreatePostgres(t *testing.T) {
	runSCIMZeroAuthorityOnCreate(t, seededDB(t, openPostgres))
}

func runSCIMZeroAuthorityOnCreate(t *testing.T, db *store.DB) {
	ctx := t.Context()
	auth, admin, _ := oidcAdmin(t, db)
	_, _ = configureProvider(t, auth, ctx, admin, "okta", service.ProviderInput{
		DisplayName: "Okta", ClientID: "c", ClientSecret: "s", Scopes: "openid", Enabled: true,
	})
	s := scimSvc(db)
	s.Auth = auth
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

	user, err := s.CreateUser(ctx, wire, orgA, binding.ID, service.DesiredUser{Active: true,
		UserName: "zero@okta.test", ExternalID: "zero-sub", SubjectRaw: "zero-sub",
	})
	if err != nil {
		t.Fatal(err)
	}
	account := accountOf(t, db, user.ID)
	principal := principalOf(t, db, account)

	// NO session exists for the provisioned human.
	if n := queryInt(t, db, `SELECT COUNT(*) FROM sessions WHERE principal_id = '`+string(principal)+`'`); n != 0 {
		t.Fatalf("provisioning must create no session, got %d", n)
	}
	// NO local credential, so a local login cannot succeed — and the account
	// handle is opaque, so there is not even a name to try.
	if n := queryInt(t, db, `SELECT COUNT(*) FROM password_credentials WHERE account_id = '`+account+`'`); n != 0 {
		t.Fatal("provisioning must establish no credential")
	}
	handle := queryString(t, db, `SELECT username FROM accounts WHERE id = '`+account+`'`)
	if _, err := auth.LocalLogin(ctx, handle, "any password at all", service.ArtifactCLI); !isUnauth(err) {
		t.Fatalf("a provisioned account must not admit a local login, got %v", err)
	}

	// After a federated login it has a session — and STILL no authority: a
	// protected operation is refused, which is the "zero grants" half asserted
	// by attempting one rather than by counting.
	login := oidcLogin(t, auth, ctx, "okta", "zero-sub")
	if login.Principal != principal {
		t.Fatalf("the login must reach the provisioned principal")
	}
	if _, err := grantSvc(db).List(ctx, service.Bearer(login.SessionToken), orgAScope); err == nil {
		t.Fatal("a provisioned human with no mapped groups must be refused a protected operation")
	}
}

// TestSCIMProvisionThenLoginSAMLEmailCarve is the other half of SC2.b: the
// Entra shape admitted under the `emailAddress` NameID carve, proving the
// carve COMPOSES with the subject derivation unchanged.
func TestSCIMProvisionThenLoginSAMLEmailCarveSQLite(t *testing.T) {
	runSCIMProvisionThenLoginSAMLEmailCarve(t, seededDB(t, openSQLite))
}
func TestSCIMProvisionThenLoginSAMLEmailCarvePostgres(t *testing.T) {
	runSCIMProvisionThenLoginSAMLEmailCarve(t, seededDB(t, openPostgres))
}

const samlEmailFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"

func runSCIMProvisionThenLoginSAMLEmailCarve(t *testing.T, db *store.DB) {
	ctx := t.Context()
	auth, admin, _ := oidcAdmin(t, db)
	auth.ExternalOrigin = "https://hikyo.test"
	idp := configureSAMLProviderWithEmailCarve(t, auth, admin)
	s := scimSvc(db)

	binding, err := s.CreateBinding(ctx, service.LocalPrincipal(admin), orgA, service.SCIMBindingInput{
		ProviderKind: domain.ProviderSAML, ProviderSlug: "saml-idp",
		SubjectSource: domain.SubjectSourceExternalID,
		// The carve's own Format, and both qualifiers present exactly as the
		// fixture IdP asserts them. Get any of the four wrong and the derived
		// subject differs from the login path's, and the login finds nothing.
		NameIDFormat:             samlEmailFormat,
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

	const nameID = "pat@entra.test"
	user, err := s.CreateUser(ctx, wire, orgA, binding.ID, service.DesiredUser{Active: true,
		UserName: nameID, ExternalID: nameID,
	})
	if err != nil {
		t.Fatalf("provision under the email carve: %v", err)
	}
	provisioned := accountOf(t, db, user.ID)
	accountsBefore := queryInt(t, db, `SELECT COUNT(*) FROM accounts`)

	login := samlLoginAsFormat(t, auth, idp, nameID, samlEmailFormat)
	if got := principalOf(t, db, provisioned); login.Principal != got {
		t.Fatalf("the emailAddress carve must compose with the encoder: login=%s provisioned=%s",
			login.Principal, got)
	}
	if after := queryInt(t, db, `SELECT COUNT(*) FROM accounts`); after != accountsBefore {
		t.Fatalf("the carved login created an account: %d -> %d", accountsBefore, after)
	}
}

// configureSAMLProviderWithEmailCarve installs the fixture IdP with the
// `emailAddress` NameID opt-in — the ADR's named carve, which a provider must
// be admitted under explicitly.
func configureSAMLProviderWithEmailCarve(t *testing.T, auth *service.Auth, admin domain.PrincipalID) *samltest.IdP {
	t.Helper()
	idp := configureSAMLProvider(t, auth, admin)
	providers := &service.SAMLProviders{
		DB: auth.DB, Keyring: auth.Keyring, ExternalOrigin: auth.ExternalOrigin,
	}
	allow := true
	if _, err := providers.Patch(t.Context(), service.LocalPrincipal(admin), "saml-idp",
		service.SAMLProviderPatch{AllowEmailNameID: &allow}); err != nil {
		t.Fatalf("opting the provider into the emailAddress carve: %v", err)
	}
	return idp
}

// samlLoginAsFormat drives one SP-initiated login asserting a given NameID
// Format, so the carve can be exercised as the IdP would send it.
func samlLoginAsFormat(t *testing.T, auth *service.Auth, idp *samltest.IdP, nameID, format string) service.LoginResult {
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
		RequestID: request.ID, ResponseID: "res_carve", AssertionID: "ass_carve",
		ACSURL:     samlSPEntityID + "/saml-idp/acs",
		SPEntityID: samlSPEntityID,
		NameID:     nameID, NameIDFormat: format, Now: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := auth.SAMLACS(t.Context(), "saml-idp", encoded,
		samlAuditRelayState(t, start.RedirectURL), start.InitiatorCookie)
	if err != nil {
		t.Fatalf("saml acs under the carve: %v", err)
	}
	return res
}

// TestSCIMManualRemainderWording is SC2.i's other half: the attention state is
// not enough — the surface must carry the HONEST wording the ADR insists on,
// that the manual grants remain usable including after a fresh login.
func TestSCIMManualRemainderWordingSQLite(t *testing.T) {
	runSCIMManualRemainderWording(t, seededDB(t, openSQLite))
}
func TestSCIMManualRemainderWordingPostgres(t *testing.T) {
	runSCIMManualRemainderWording(t, seededDB(t, openPostgres))
}

func runSCIMManualRemainderWording(t *testing.T, db *store.DB) {
	s := scimSvc(db)
	ctx := t.Context()
	bindingID, token := newSCIMBinding(t, db, "okta")
	wire := service.SCIMCredentialActor(token, bindingID)

	user, err := s.CreateUser(ctx, wire, orgA, bindingID, service.DesiredUser{Active: true,
		UserName: "rem@example.test", ExternalID: "ext-rem", SubjectRaw: "ext-rem",
	})
	if err != nil {
		t.Fatal(err)
	}
	principal := principalOf(t, db, accountOf(t, db, user.ID))
	scope := domain.Scope{Org: orgA, Project: prjA1}
	if _, err := grantSvc(db).Create(ctx, service.LocalPrincipal(orgAdmin), service.GrantSpec{
		Target: principal, Capability: domain.CapEdit, Scope: scope,
	}); err != nil {
		t.Fatal(err)
	}

	off := false
	if _, err := s.PatchUser(ctx, wire, orgA, bindingID, user.ID,
		[]service.UserPatchCommand{service.UserPatchSetActive{Active: off}}); err != nil {
		t.Fatal(err)
	}

	// The authority genuinely REMAINS — the flag is about a real thing.
	if !held(t, db, principal, domain.CapEdit, scope) {
		t.Fatal("a manual grant must survive deprovisioning: the IdP was not its source")
	}

	// And the surface says so, in the ADR's own honest terms: they remain
	// usable, INCLUDING after a fresh login, and a human must decide.
	users, err := s.DirectoryUsers(ctx, service.LocalPrincipal(orgAdmin), orgA, bindingID)
	if err != nil {
		t.Fatal(err)
	}
	var wording string
	for _, u := range users {
		if u.ID != user.ID {
			continue
		}
		for _, a := range u.Attention {
			if a.State == string(domain.AttentionManualGrantsRemain) {
				wording = a.Remediation
			}
		}
	}
	if wording == "" {
		t.Fatalf("the per-user attention flag is missing from the directory view: %+v", users)
	}
	for _, phrase := range []string{"still usable", "after a fresh login"} {
		if !strings.Contains(strings.ToLower(wording), phrase) {
			t.Errorf("the remainder wording must be honest about %q; got: %s", phrase, wording)
		}
	}
}
