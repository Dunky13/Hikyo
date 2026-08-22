package isolation

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/crypto"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/service"
	"github.com/Hikyo-Org/hikyo/internal/store"
	"github.com/Hikyo-Org/hikyo/internal/store/authn"
)

// SC1's [CI] eligibility invariants (#73). Each is a statement about the
// REGISTRY or about artifact eligibility that no end-to-end fixture can prove,
// because the thing being asserted is the absence of a path.

// TestSCIMOperationsCarryTheirFormula pins the two formulas the ADR fixes, in
// both directions: every WIRE operation is `scim-provision` at org scope and
// every ADMINISTRATION operation is `manage-members` at org scope EXACTLY.
//
// The org-scope-exactly half is the one worth a test of its own. A mapping row
// causes grants its author need not hold, and unheld-capability granting is an
// org/instance power under the locked escalation asymmetry — so an atom sitting
// at `manage-members`' own deepest level (project) would silently hand the SCIM
// surface to every project member manager.
func TestSCIMOperationsCarryTheirFormula(t *testing.T) {
	formulas := facts.Formulas()
	wantAdmin := "manage-members@org"
	wantWire := "scim-provision@org"

	levelName := map[domain.Level]string{
		domain.LevelNone: "instance", domain.LevelOrg: "org",
		domain.LevelProject: "project", domain.LevelEnv: "environment",
	}
	seenAdmin, seenWire := 0, 0
	for op, formula := range formulas {
		name := string(op)
		if !strings.HasPrefix(name, "scim-") {
			continue
		}
		if len(formula) != 1 {
			t.Errorf("%s: a SCIM operation must carry exactly one atom, got %v", name, formula)
			continue
		}
		got := string(formula[0].Cap) + "@" + levelName[formula[0].At]
		switch {
		case strings.HasPrefix(name, "scim-binding.") ||
			strings.HasPrefix(name, "scim-mapping.") ||
			strings.HasPrefix(name, "scim-credential.") ||
			strings.HasPrefix(name, "scim-directory."):
			seenAdmin++
			if got != wantAdmin {
				t.Errorf("%s: administration formula = %q, want %q", name, got, wantAdmin)
			}
		default:
			seenWire++
			if got != wantWire {
				t.Errorf("%s: wire formula = %q, want %q", name, got, wantWire)
			}
		}
		// Every SCIM operation is tenant-class at ORG depth, or a binding the
		// caller may not reach would answer differently from one that is not
		// there — a cross-org oracle on the mount.
		class, ok := facts.Operations()[op]
		if !ok {
			t.Errorf("%s: registered formula with no operation row", name)
			continue
		}
		if class != authz.ClassTenant {
			t.Errorf("%s: class = %v, want tenant", name, class)
		}
		if depth, tenant := facts.TenantOperations()[op]; !tenant || depth != domain.LevelOrg {
			t.Errorf("%s: addressed depth = %v (tenant=%v), want org", name, depth, tenant)
		}
	}
	// Guard against the whole check passing vacuously if the prefix ever moves.
	if seenAdmin < 14 || seenWire < 14 {
		t.Fatalf("the SCIM operation set shrank unexpectedly: %d administration, %d wire", seenAdmin, seenWire)
	}
}

// TestSCIMWireIsNotMFAMandatory is the other half of the formula pin. Machines
// do not reauthenticate — the MFA-mandatory rule binds HUMAN sessions — so
// `scim-provision` must not be in the mandatory set, and the administration
// atom must be, because the humans administering a binding are already under
// `manage-members`' mandate.
func TestSCIMWireIsNotMFAMandatory(t *testing.T) {
	if authz.MFAMandatory[domain.CapSCIMProvision] {
		t.Error("scim-provision is MFA-mandatory, but a provisioning connection has no second factor to present")
	}
	if !authz.MFAMandatory[domain.CapManageMembers] {
		t.Error("manage-members is not MFA-mandatory, so the SCIM administration surface lost its mandate")
	}
}

// TestSCIMCredentialIsRejectedOnNonSCIMOperations is the eligibility invariant
// the ADR states as "the `scim` credential type is rejected on every non-SCIM
// operation". A provisioning credential authenticates the IdP's wire and
// nothing else: presented as a human session artifact it must be refused, and
// refused UNIFORMLY — indistinguishable from a value that names nothing.
func TestSCIMCredentialIsRejectedOnNonSCIMOperationsSQLite(t *testing.T) {
	runSCIMCredentialRejected(t, seededDB(t, openSQLite))
}
func TestSCIMCredentialIsRejectedOnNonSCIMOperationsPostgres(t *testing.T) {
	runSCIMCredentialRejected(t, seededDB(t, openPostgres))
}

func runSCIMCredentialRejected(t *testing.T, db *store.DB) {
	ctx := t.Context()
	bindingID, token := newSCIMBinding(t, db, "okta")
	if !strings.HasPrefix(token, "hik_1_scim_") {
		t.Fatalf("the provisioning credential must carry the hik_<v>_scim_ grammar, got %q", token[:10])
	}

	// A domain operation, addressed correctly, presented with the provisioning
	// credential as if it were a session.
	grants := grantSvc(db)
	_, err := grants.List(ctx, service.Bearer(token), orgAScope)
	if !isUnauth(err) {
		t.Fatalf("a provisioning credential must not authenticate the membership surface, got %v", err)
	}
	orgs, _, _ := services(t, db)
	if _, err := orgs.List(ctx, service.Bearer(token)); !isUnauth(err) {
		t.Fatalf("a provisioning credential must not authenticate an instance operation, got %v", err)
	}
	// Uniform: a value of the SAME type that names nothing answers identically.
	unknown, _, err := crypto.NewArtifact(crypto.ArtifactSCIM)
	if err != nil {
		t.Fatal(err)
	}
	_, live := grants.List(ctx, service.Bearer(token), orgAScope)
	_, dead := grants.List(ctx, service.Bearer(unknown), orgAScope)
	if live.Error() != dead.Error() {
		t.Fatalf("a live provisioning credential and an unknown one must be indistinguishable off the wire:\n  live: %q\n  unknown: %q",
			live.Error(), dead.Error())
	}

	// And the converse: a REAL human session must not authenticate the wire.
	// The binding path is right and the session is genuinely live — an unknown
	// artifact here would prove only that nonsense is refused, which is a
	// different claim.
	s := scimSvc(db)
	_, _, human := oidcAdmin(t, db)
	if _, err := s.GetUser(ctx, service.Bearer(human), orgA, bindingID, "scu_none"); !isUnauth(err) {
		t.Fatalf("a live human session must not authenticate the provisioning wire, got %v", err)
	}
	// Uniform again in this direction: the live human session and an unknown
	// value answer identically, so the wire is not an oracle for "is this a
	// real session".
	_, humanErr := s.GetUser(ctx, service.Bearer(human), orgA, bindingID, "scu_none")
	_, noneErr := s.GetUser(ctx, service.Bearer(unknown), orgA, bindingID, "scu_none")
	if humanErr.Error() != noneErr.Error() {
		t.Fatalf("the wire distinguishes a live human session from nonsense:\n  human: %q\n  unknown: %q",
			humanErr, noneErr)
	}
}

// TestSCIMEligibilityIsRegistryDriven is the structural half of the same
// invariant, over the WHOLE operation registry rather than two hand-picked
// operations. A provisioning credential resolves to a principal of class
// `provisioning`; the normative allowlist lets that class hold exactly
// `scim-provision`; so for every operation whose formula asks for anything
// else, the refusal is total by construction and not by whichever operations a
// fixture happened to try.
func TestSCIMEligibilityIsRegistryDriven(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "operation_formulas.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		Operation string   `json:"operation"`
		Formula   []string `json:"formula"`
	}
	if err := json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) < 80 {
		t.Fatalf("the pinned operation registry has %d rows; it should be the whole surface", len(rows))
	}
	reachable, checked := 0, 0
	for _, row := range rows {
		for _, atom := range row.Formula {
			capability := domain.Capability(strings.SplitN(atom, "@", 2)[0])
			checked++
			if !domain.MachineMayHold(domain.ClassProvisioning, capability) {
				continue
			}
			// The one capability the class may hold: only SCIM wire operations
			// may ask for it, or the credential would reach past its surface.
			if capability != domain.CapSCIMProvision {
				t.Errorf("the provisioning class may hold %q, which the allowlist does not license", capability)
				continue
			}
			if !strings.HasPrefix(row.Operation, "scim-") {
				t.Errorf("non-SCIM operation %q asks for scim-provision; a provisioning credential would reach it",
					row.Operation)
			}
			reachable++
		}
	}
	if checked == 0 || reachable == 0 {
		t.Fatalf("the probe proved nothing: %d atoms checked, %d reachable", checked, reachable)
	}

	// Every OTHER machine class, and the human path, must be refused the atom
	// too — the allowlist has exactly one row, and "one row" is the claim.
	for _, class := range domain.MachineClasses() {
		if class == domain.ClassProvisioning {
			continue
		}
		if domain.MachineMayHold(class, domain.CapSCIMProvision) {
			t.Errorf("machine class %q may hold scim-provision", class)
		}
	}
}

// TestSCIMProvisionIsUngrantableThroughTheAPI restates, at the registry level,
// what grants_e2e's allowlist fixtures assert at the writer: `scim-provision`
// is machine-only AND system-created, so it is on exactly one machine class's
// allowlist and on no human path at all.
func TestSCIMProvisionIsUngrantableThroughTheAPI(t *testing.T) {
	for _, class := range domain.MachineClasses() {
		may := domain.MachineMayHold(class, domain.CapSCIMProvision)
		if class == domain.ClassProvisioning && !may {
			t.Error("the provisioning connection must be able to hold scim-provision")
		}
		if class != domain.ClassProvisioning && may {
			t.Errorf("class %q may hold scim-provision; the normative allowlist has ONE row", class)
		}
	}
	// A human is not a machine class at all, so the allowlist cannot express
	// the human refusal — that is checkPrincipalClass's ErrSystemCreatedOnly,
	// fixtured in grants_e2e_test.go. What IS checkable here is that the atom
	// is org-scoped: an instance-scope `scim-provision` would let one binding's
	// connection reach every org.
	if level, ok := domain.DeepestLevel(domain.CapSCIMProvision); !ok || level != domain.LevelOrg {
		t.Fatalf("scim-provision deepest level = %v (ok=%v), want org", level, ok)
	}
}

// TestSCIMOriginKindsAreNotHumanReleasable pins the predicate split this ticket
// turns on. `IsMintableOrigin` is the HUMAN grant surface's release gate — a
// revoke releases every kind it admits — so a SCIM kind appearing in it would
// make an administrator's revoke tear out `scim` origins, which is exactly the
// hand-mutation §4 refuses by name.
func TestSCIMOriginKindsAreNotHumanReleasable(t *testing.T) {
	for _, kind := range []domain.OriginKind{
		domain.OriginSCIM, domain.OriginStructural, domain.OriginLockoutRetention,
	} {
		if domain.IsMintableOrigin(kind) {
			t.Errorf("origin kind %q is on the human surface's release gate", kind)
		}
		if !domain.IsSystemOrigin(kind) {
			t.Errorf("origin kind %q is on neither writer's gate, so nothing can create it", kind)
		}
	}
	for _, kind := range []domain.OriginKind{domain.OriginManual, domain.OriginBreakGlass} {
		if domain.IsSystemOrigin(kind) {
			t.Errorf("origin kind %q is on the SCIM engine's gate", kind)
		}
	}
}

// TestSCIMCreateIsOneQueryPath is SC2's "single-query-path equality" half of
// the #23 cross-org oracle criteria (§5.2). The response-shape half is
// asserted in TestSCIMUserLifecycle; this is the other one.
//
// A fresh create and an ATTACH must cost the same query traffic, because an
// observer who could count the difference could ask "does this identity exist
// somewhere in this instance?" without being authorized to know. The measured
// difference is the writes an attach does not perform (principal, account,
// identity link), which is why the assertion is on the RESOLUTION path — the
// lookup that decides between them — and not on the whole transaction: the
// branch is what must be indistinguishable, not the work each branch does.
func TestSCIMCreateIsOneQueryPathSQLite(t *testing.T) {
	runSCIMCreateIsOneQueryPath(t, seededDB(t, openSQLite))
}
func TestSCIMCreateIsOneQueryPathPostgres(t *testing.T) {
	runSCIMCreateIsOneQueryPath(t, seededDB(t, openPostgres))
}

func runSCIMCreateIsOneQueryPath(t *testing.T, db *store.DB) {
	s := scimSvc(db)
	ctx := t.Context()
	bindingID, token := newSCIMBinding(t, db, "okta")
	wire := service.SCIMCredentialActor(token, bindingID)

	// Leg 1's identity already exists because a human was INVITED earlier,
	// exactly as §5.2 describes.
	execRaw(t, db, `INSERT INTO principals (id, kind, created_at) VALUES ('usr_invited_q', 'human', `+ts+`)`)
	execRaw(t, db, `INSERT INTO accounts (id, principal_id, username, display_name, created_at) `+
		`VALUES ('acc_invited_q', 'usr_invited_q', 'invited-q@example.test', 'Q', `+ts+`)`)
	execRaw(t, db, `INSERT INTO external_identities (id, account_id, kind, issuer, subject, provider_id, credential_epoch, created_at) `+
		`VALUES ('eid_invited_q', 'acc_invited_q', 'oidc', 'https://okta.example.test', 'attach-q', 'okta', 0, `+ts+`)`)

	// Leg 2's identity exists because ANOTHER ORG'S BINDING provisioned it —
	// the attach case the acceptance row names by hand, and the one an oracle
	// would be most valuable against: org A's connector must not be able to
	// learn that org B already knows this person. It is a REAL second binding on
	// the same provider row (§1 bounds binding uniqueness to (org, provider), so
	// the shared issuer is legal), driven by its own credential and authored by
	// the instance operator, because org A's administrator has no authority in
	// org B.
	otherBinding, err := s.CreateBinding(ctx, service.LocalPrincipal(root), orgB, service.SCIMBindingInput{
		ProviderKind: domain.ProviderOIDC, ProviderSlug: "okta",
		SubjectSource: domain.SubjectSourceExternalID,
	})
	if err != nil {
		t.Fatalf("other-org binding: %v", err)
	}
	otherMint, err := s.MintCredential(ctx, service.LocalPrincipal(root), orgB, otherBinding.ID, false, "")
	if err != nil {
		t.Fatalf("other-org credential: %v", err)
	}
	if _, err := s.CreateUser(ctx, service.SCIMCredentialActor(otherMint.Token, otherBinding.ID),
		orgB, otherBinding.ID, service.DesiredUser{Active: true,
			UserName: "cross-q@example.test", ExternalID: "cross-q", SubjectRaw: "cross-q",
		}); err != nil {
		t.Fatalf("other-org create: %v", err)
	}

	// The trace is ORDERED query IDENTITIES, not a count. A count lets an
	// attach-only sequence and a create-only sequence of equal length cancel
	// out — two different conversations with the database summing to the same
	// number is exactly the oracle this fixture exists to refuse.
	trace := func(subject, userName string) []string {
		t.Helper()
		var mu sync.Mutex
		var seen []string
		restore := authn.SetQueryObserver(func(sql string) {
			mu.Lock()
			seen = append(seen, queryIdentity(sql))
			mu.Unlock()
		})
		defer restore()
		if _, err := s.CreateUser(ctx, wire, orgA, bindingID, service.DesiredUser{Active: true,
			UserName: userName, ExternalID: subject, SubjectRaw: subject,
		}); err != nil {
			t.Fatalf("create %q: %v", subject, err)
		}
		mu.Lock()
		defer mu.Unlock()
		return seen
	}
	// The two attach legs run FIRST, so a fresh create cannot look cheaper
	// merely by running against a smaller table.
	invited := trace("attach-q", "invited-q@example.test")
	crossOrg := trace("cross-q", "cross-org-q@example.test")
	fresh := trace("fresh-q", "fresh-q@example.test")

	// 1. The two attach legs are the SAME conversation. A prior invitation and a
	//    prior other-org binding must be indistinguishable from each other, or
	//    the difference itself answers "which org already knows this person?".
	if strings.Join(invited, "\n") != strings.Join(crossOrg, "\n") {
		t.Fatalf("an invited attach and an other-org attach take different query paths:\n  invited:   %v\n  other-org: %v",
			invited, crossOrg)
	}

	// 2. The DECIDING lookup sits at the same index in both traces, and every
	//    query before it is identical. Up to and including the branch point
	//    there is one query path; what each branch then does may differ, because
	//    by then the answer is already known.
	const decider = "GetExternalIdentity"
	at := func(trace []string) int {
		for i, q := range trace {
			if q == decider {
				return i
			}
		}
		t.Fatalf("no %s in the trace — the fixture is no longer watching the branch point: %v", decider, trace)
		return -1
	}
	// The trace must be a REAL trace: an empty or decider-less one would make
	// every comparison below vacuously true, and this fixture's whole subject
	// is that the comparison is meaningful.
	if len(invited) < 5 || len(fresh) < 5 {
		t.Fatalf("the query traces are too short to be real: invited=%v fresh=%v", invited, fresh)
	}
	freshAt, attachAt := at(fresh), at(invited)
	if freshAt != attachAt {
		t.Fatalf("the branch point sits at index %d on the fresh leg and %d on the attach leg:\n  fresh:  %v\n  attach: %v",
			freshAt, attachAt, fresh, invited)
	}
	if got, want := strings.Join(fresh[:freshAt+1], "\n"), strings.Join(invited[:attachAt+1], "\n"); got != want {
		t.Fatalf("the two legs diverge BEFORE the branch point:\n  fresh:  %v\n  attach: %v",
			fresh[:freshAt+1], invited[:attachAt+1])
	}

	// 3. The fresh leg is the attach leg plus exactly the work a new account
	//    costs, inserted CONTIGUOUSLY: the principal, the account, the
	//    credential epoch the new link stamps itself with, and the link.
	//    Removing that run must reproduce the attach trace exactly — a "same
	//    length" or "same multiset" check would let a reordered or substituted
	//    query through.
	freshAccount := []string{
		"InsertPrincipal", "InsertAccount", "GetCredentialEpoch", "InsertExternalIdentity",
	}
	reduced, ok := removeRun(fresh, freshAccount)
	if !ok {
		t.Fatalf("the fresh leg does not contain %v as a contiguous run: %v", freshAccount, fresh)
	}
	if strings.Join(reduced, "\n") != strings.Join(invited, "\n") {
		t.Fatalf("create and attach are not one query path once the new account's own work is removed:\n"+
			"  fresh minus account: %v\n  attach:              %v", reduced, invited)
	}
}

// queryIdentity turns a generated statement into its stable name. sqlc prefixes
// every query constant with `-- name: <Query> :<kind>`, so the identity travels
// with the SQL itself and cannot drift from what actually ran.
func queryIdentity(sql string) string {
	first, _, _ := strings.Cut(strings.TrimSpace(sql), "\n")
	rest, ok := strings.CutPrefix(first, "-- name: ")
	if !ok {
		return strings.TrimSpace(first)
	}
	name, _, _ := strings.Cut(rest, " ")
	return name
}

// removeRun deletes the first contiguous occurrence of run from trace.
func removeRun(trace, run []string) ([]string, bool) {
	for i := 0; i+len(run) <= len(trace); i++ {
		if slices.Equal(trace[i:i+len(run)], run) {
			return append(append([]string{}, trace[:i]...), trace[i+len(run):]...), true
		}
	}
	return nil, false
}

// TestSCIMPushEmitsPerEvent is SC4's no-aggregation clause (§10): "a 500-user
// initial push emits 500 `scim.user_provisioned` events plus their grant
// events, per-event, durably". The aggregation licence covers
// authentication-failure floods only.
func TestSCIMPushEmitsPerEventSQLite(t *testing.T) {
	runSCIMPushEmitsPerEvent(t, seededDB(t, openSQLite))
}
func TestSCIMPushEmitsPerEventPostgres(t *testing.T) {
	runSCIMPushEmitsPerEvent(t, seededDB(t, openPostgres))
}

func runSCIMPushEmitsPerEvent(t *testing.T, db *store.DB) {
	s := scimSvc(db)
	ctx := t.Context()
	bindingID, token := newSCIMBinding(t, db, "okta")
	wire := service.SCIMCredentialActor(token, bindingID)

	count := func(typ string) int64 {
		return queryInt(t, db, `SELECT COUNT(*) FROM audit_tenant_events WHERE type = '`+typ+`'`)
	}
	provisionedBefore := count("scim.user_provisioned")
	createdBefore := count("grant.created")

	// The push: three users, then a group holding all three, then a mapping —
	// so the grant events are three users' worth and not one summary.
	ids := make([]string, 0, 3)
	for _, name := range []string{"one", "two", "three"} {
		u, err := s.CreateUser(ctx, wire, orgA, bindingID, service.DesiredUser{Active: true,
			UserName: name + "@push.test", ExternalID: "push-" + name, SubjectRaw: "push-" + name,
		})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, u.ID)
	}
	if got := count("scim.user_provisioned") - provisionedBefore; got != 3 {
		t.Fatalf("a 3-user push must emit 3 scim.user_provisioned events, got %d", got)
	}

	group, err := s.CreateGroup(ctx, wire, orgA, bindingID, service.DesiredGroup{
		DisplayName: "Pushed", Members: ids,
	})
	if err != nil {
		t.Fatal(err)
	}
	// `viewer` expands to exactly one capability, so the expected grant-event
	// count is one per member and the assertion cannot be satisfied by a
	// summary event that happens to be non-zero.
	res, err := s.CreateMapping(ctx, service.LocalPrincipal(orgAdmin), orgA, bindingID, service.SCIMMappingSpec{
		GroupID: group.ID, Template: domain.TemplateViewer, ProjectID: string(prjA1),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.GrantsCreated != 3 {
		t.Fatalf("the mapping must grant all three members, got %d", res.GrantsCreated)
	}
	if got := count("grant.created") - createdBefore; got != 3 {
		t.Fatalf("each grant is its own durable event, want 3, got %d", got)
	}
}
