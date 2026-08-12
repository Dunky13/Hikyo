package isolation

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Dunky13/hikyo/internal/domain"
	"github.com/Dunky13/hikyo/internal/service"
	"github.com/Dunky13/hikyo/internal/store"
)

// The SCIM concurrency fixtures (#73 SC1.m, SC2.f, SC3.j, SC4.d).
//
// Every race here starts BOTH goroutines behind one barrier and joins them, so
// the two transactions genuinely overlap. A sequential pair — call A, then call
// B — exercises no concurrency at all and passes whether or not the property
// holds, which is what these replace.

// barrier releases n goroutines at once. `sync.WaitGroup.Wait` on a shared
// start signal is the whole mechanism; a channel close is the release.
func barrier(n int) (start chan struct{}, done *sync.WaitGroup) {
	done = &sync.WaitGroup{}
	done.Add(n)
	return make(chan struct{}), done
}

// TestSCIMBindingUniquenessRace is SC1.m: two concurrent creates for one
// (org, provider) resolve to ONE row, and the loser is refused with the named
// conflict rather than being reconciled in application code.
func TestSCIMBindingUniquenessRaceSQLite(t *testing.T) {
	runSCIMBindingUniquenessRace(t, seededDB(t, openSQLite))
}
func TestSCIMBindingUniquenessRacePostgres(t *testing.T) {
	runSCIMBindingUniquenessRace(t, seededDB(t, openPostgres))
}

func runSCIMBindingUniquenessRace(t *testing.T, db *store.DB) {
	s := scimSvc(db)
	seedSCIMProvider(t, db, "okta", "https://okta.example.test", true)
	in := service.SCIMBindingInput{
		ProviderKind: domain.ProviderOIDC, ProviderSlug: "okta",
		SubjectSource: domain.SubjectSourceExternalID,
	}

	start, done := barrier(2)
	errs := make([]error, 2)
	for i := range 2 {
		go func(i int) {
			defer done.Done()
			<-start
			_, errs[i] = s.CreateBinding(t.Context(), service.LocalPrincipal(orgAdmin), orgA, in)
		}(i)
	}
	close(start)
	done.Wait()

	won := 0
	for i, err := range errs {
		switch {
		case err == nil:
			won++
		case errors.Is(err, domain.ErrConflict), errors.Is(err, store.ErrConflict):
			// The named conflict, which is what "fails closed" means here.
		default:
			t.Fatalf("create %d: want success or a named conflict, got %v", i, err)
		}
	}
	if won != 1 {
		t.Fatalf("exactly one concurrent create must win, %d did", won)
	}
	if n := queryInt(t, db, `SELECT COUNT(*) FROM scim_bindings WHERE org_id = 'org_a'`); n != 1 {
		t.Fatalf("the constraint must arbitrate to one row, got %d", n)
	}
	// And the losing transaction left nothing behind: a connection principal
	// without its binding would be a machine identity nothing owns.
	if n := queryInt(t, db,
		`SELECT COUNT(*) FROM principals WHERE class = 'provisioning-connection'`); n != 1 {
		t.Fatalf("the loser must roll back its provisioning principal, got %d", n)
	}
}

// TestSCIMConcurrentDuplicateCreate is SC2.f: two bindings asserting the SAME
// identity at once yield ONE account. §5.2's constraint arbitrates and "the
// loser retries and attaches" — so BOTH calls must succeed, and both resources
// must point at one account.
func TestSCIMConcurrentDuplicateCreateSQLite(t *testing.T) {
	runSCIMConcurrentDuplicateCreate(t, seededDB(t, openSQLite))
}
func TestSCIMConcurrentDuplicateCreatePostgres(t *testing.T) {
	runSCIMConcurrentDuplicateCreate(t, seededDB(t, openPostgres))
}

func runSCIMConcurrentDuplicateCreate(t *testing.T, db *store.DB) {
	s := scimSvc(db)
	bindingID, token := newSCIMBinding(t, db, "okta")
	wire := service.SCIMCredentialActor(token, bindingID)

	// ONE binding, TWO concurrent pushes of the SAME identity. This is the
	// reachable shape of §5.2's race: the schema keeps one ENABLED provider per
	// (kind, issuer), so two live bindings cannot share an issuer, and the
	// cross-binding case is an ATTACH to a link that already exists rather than
	// a create race at all (runSCIMTwoBindingRace covers that one).
	//
	// Both goroutines miss the identity lookup, both try to insert the link,
	// one wins; the loser's transaction retries, finds the identity, and is
	// then refused by (binding_id, subject) with a NAMED conflict — never a raw
	// database error.
	const subject = "race-subject"
	start, done := barrier(2)
	ids := make([]string, 2)
	errs := make([]error, 2)
	for i := range 2 {
		go func(i int) {
			defer done.Done()
			<-start
			u, err := s.CreateUser(t.Context(), wire, orgA, bindingID, service.SCIMUserInput{
				UserName:   fmt.Sprintf("race-%d@example.test", i),
				SubjectRaw: subject, ExternalID: subject,
			})
			ids[i], errs[i] = u.ID, err
		}(i)
	}
	close(start)
	done.Wait()

	won := 0
	for i, err := range errs {
		switch {
		case err == nil:
			won++
		case errors.Is(err, domain.ErrConflict), errors.Is(err, store.ErrConflict):
			// The named conflict. A raw driver error here would mean the race
			// escaped classification and reached the identity provider as a 500.
		default:
			t.Fatalf("create %d: want success or a named conflict, got %v", i, err)
		}
	}
	if won != 1 {
		t.Fatalf("exactly one concurrent duplicate create must win, %d did", won)
	}
	// ONE account, ONE identity link, ONE directory entry — the property the
	// clause is about.
	if n := queryInt(t, db,
		`SELECT COUNT(*) FROM external_identities WHERE subject = '`+subject+`'`); n != 1 {
		t.Fatalf("the identity constraint must arbitrate to one link, got %d", n)
	}
	if n := queryInt(t, db,
		`SELECT COUNT(*) FROM scim_users WHERE binding_id = '`+bindingID+`'`); n != 1 {
		t.Fatalf("one identity must yield one directory entry, got %d", n)
	}
	if n := queryInt(t, db,
		`SELECT COUNT(DISTINCT account_id) FROM scim_users WHERE binding_id = '`+bindingID+`'`); n != 1 {
		t.Fatalf("concurrent duplicate creates must share one account, got %d", n)
	}

	// The OTHER shape of the same race, and the one §5.2's retry-to-attach rule
	// is actually about: TWO BINDINGS asserting one identity at the same time.
	// Neither is a duplicate resource — each binding may hold this person once
	// — so BOTH must succeed with equivalent responses, and both must land on
	// ONE account. Before the uniqueness race was classified as a retryable
	// serialization failure, the loser here took a raw 23505 to the identity
	// provider as a 500.
	other := scimBindingInOrg(t, db, orgB, "okta")
	const shared = "cross-binding-subject"
	start, done = barrier(2)
	type leg struct {
		actor   service.Actor
		org     domain.OrgID
		binding string
	}
	legs := []leg{
		{wire, orgA, bindingID},
		{service.SCIMCredentialActor(other.token, other.id), orgB, other.id},
	}
	users := make([]service.SCIMUserResource, 2)
	errs = make([]error, 2)
	for i := range 2 {
		go func(i int) {
			defer done.Done()
			<-start
			users[i], errs[i] = s.CreateUser(t.Context(), legs[i].actor, legs[i].org, legs[i].binding,
				service.SCIMUserInput{
					UserName:   fmt.Sprintf("cross-%d@example.test", i),
					SubjectRaw: shared, ExternalID: shared,
				})
		}(i)
	}
	close(start)
	done.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("cross-binding create %d must SUCCEED (each binding may hold this identity once), got %v", i, err)
		}
	}
	// Equivalent responses: nothing in either answer says which one created the
	// account and which one attached to it — that difference would be the
	// cross-org oracle §5.2 exists to close.
	if got, want := userShape(users[0]), userShape(users[1]); got != want {
		t.Fatalf("the two concurrent creates rendered different shapes:\n  a: %s\n  b: %s", want, got)
	}
	if n := queryInt(t, db,
		`SELECT COUNT(*) FROM external_identities WHERE subject = '`+shared+`'`); n != 1 {
		t.Fatalf("one identity must arbitrate to one link, got %d", n)
	}
	if accountOf(t, db, users[0].ID) != accountOf(t, db, users[1].ID) {
		t.Fatal("two bindings asserting one identity must resolve to ONE account")
	}
}

// scimBinding is a second live binding, in another org, on the same provider.
type scimBinding struct{ id, token string }

// scimBindingInOrg builds one. §1 bounds binding uniqueness to (org, provider),
// so two orgs may bind the same identity provider — which is exactly how one
// human ends up asserted by two bindings.
func scimBindingInOrg(t *testing.T, db *store.DB, org domain.OrgID, slug string) scimBinding {
	t.Helper()
	s := scimSvc(db)
	// The instance operator: an org admin of one org has no authority in another.
	binding, err := s.CreateBinding(t.Context(), service.LocalPrincipal(root), org, service.SCIMBindingInput{
		ProviderKind: domain.ProviderOIDC, ProviderSlug: slug,
		SubjectSource: domain.SubjectSourceExternalID,
	})
	if err != nil {
		t.Fatalf("binding in %s: %v", org, err)
	}
	mint, err := s.MintCredential(t.Context(), service.LocalPrincipal(root), org, binding.ID, false, "")
	if err != nil {
		t.Fatalf("credential in %s: %v", org, err)
	}
	return scimBinding{id: binding.ID, token: mint.Token}
}

// TestSCIMTeardownPhaseOrder is SC3.j: §6's state machine runs IN ORDER —
// credentials dead first (so no new wire transaction can begin), then origins
// released, then the connection retired, then the directory and the binding
// gone. An end-state assertion cannot tell a correct order from a wrong one
// that happens to converge, so the order itself is observed.
func TestSCIMTeardownPhaseOrderSQLite(t *testing.T) {
	runSCIMTeardownPhaseOrder(t, seededDB(t, openSQLite))
}
func TestSCIMTeardownPhaseOrderPostgres(t *testing.T) {
	runSCIMTeardownPhaseOrder(t, seededDB(t, openPostgres))
}

func runSCIMTeardownPhaseOrder(t *testing.T, db *store.DB) {
	s := scimSvc(db)
	ctx := t.Context()
	bindingID, token := newSCIMBinding(t, db, "okta")
	wire := service.SCIMCredentialActor(token, bindingID)

	user, err := s.CreateUser(ctx, wire, orgA, bindingID, service.SCIMUserInput{
		UserName: "teardown@example.test", ExternalID: "ext-teardown", SubjectRaw: "ext-teardown",
	})
	if err != nil {
		t.Fatal(err)
	}
	group, err := s.CreateGroup(ctx, wire, orgA, bindingID, service.SCIMGroupInput{
		DisplayName: "Teardown", Members: []string{user.ID}, MembersPresent: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateMapping(ctx, service.LocalPrincipal(orgAdmin), orgA, bindingID,
		service.SCIMMappingSpec{GroupID: group.ID, Template: domain.TemplateViewer, ProjectID: string(prjA1)}); err != nil {
		t.Fatal(err)
	}
	account := accountOf(t, db, user.ID)
	principal := principalOf(t, db, account)
	connection := queryString(t, db,
		`SELECT connection_principal_id FROM scim_bindings WHERE id = '`+bindingID+`'`)

	var phases []string
	restore := service.SetSCIMPhaseObserver(func(p string) { phases = append(phases, p) })
	if err := s.DeleteBinding(ctx, service.LocalPrincipal(orgAdmin), orgA, bindingID); err != nil {
		restore()
		t.Fatalf("binding delete: %v", err)
	}
	restore()

	// Each mark is emitted AFTER its phase's work and carries WHAT THAT PHASE
	// DID, so the assertion is about state rather than about a label a wrong
	// implementation would emit just as happily: one credential died, the
	// provisioned human's origin was released, the structural origin went with
	// the connection, one directory user was deleted, one binding row went.
	// The teardown holds §9's per-binding lock for its whole run, so its own
	// enter/exit pair brackets the five ordered phases.
	want := []string{
		"wire-enter:" + bindingID,
		"credentials-revoked=1", "origins-released=1", "connection-retired=1",
		"directory-deleted=1", "binding-deleted=1",
		"wire-exit:" + bindingID,
	}
	if strings.Join(phases, ",") != strings.Join(want, ",") {
		t.Fatalf("teardown ran out of §6's order, or a phase did nothing:\n  got:  %v\n  want: %v", phases, want)
	}

	// Every end state the order exists to produce.
	if held(t, db, principal, domain.CapRead, domain.Scope{Org: orgA, Project: prjA1}) {
		t.Fatal("the provisioned grant must be released by teardown")
	}
	if n := queryInt(t, db, `SELECT COUNT(*) FROM principals WHERE id = '`+connection+`'`); n != 0 {
		t.Fatal("the provisioning connection must be retired")
	}
	if n := queryInt(t, db, `SELECT COUNT(*) FROM grants WHERE principal_id = '`+connection+`'`); n != 0 {
		t.Fatal("the structural grant must be retired with its connection")
	}
	for _, table := range []string{"scim_users", "scim_groups", "scim_group_members", "scim_mappings", "scim_attention"} {
		if n := queryInt(t, db, `SELECT COUNT(*) FROM `+table+` WHERE binding_id = '`+bindingID+`'`); n != 0 {
			t.Fatalf("%s survived teardown", table)
		}
	}
	// §6 step 4: identity links and accounts SURVIVE — they are account
	// property, exactly as they would be had the user been invited.
	if n := queryInt(t, db, `SELECT COUNT(*) FROM external_identities WHERE subject = 'ext-teardown'`); n != 1 {
		t.Fatal("identity links must survive a binding deletion")
	}
	if n := queryInt(t, db, `SELECT COUNT(*) FROM accounts WHERE id = '`+account+`'`); n != 1 {
		t.Fatal("the account must survive a binding deletion")
	}
	// And the credential is dead: an in-flight transaction fails at its next
	// proof, which is what "credentials first" buys.
	if _, err := s.GetUser(ctx, wire, orgA, bindingID, user.ID); err == nil {
		t.Fatal("the credential must be dead after teardown")
	}
}

// TestSCIMPerBindingSerializationOrder is SC4.b's ORDER half (§9: "per-binding
// writes serialize — one reconciliation transaction at a time per binding").
//
// runSCIMPerBindingSerialization asserts the observable CONSEQUENCE (six
// parallel pushes, no lost write), and that assertion passes whether or not the
// serialization exists: independent inserts of distinct rows do not collide.
// This one asserts the MECHANISM, on two overlapping mutations of ONE shared
// object — two PATCHes each adding a member to the same group, which is a
// read-modify-write of the same member set on both sides.
//
// The instrument is the phase observer, marked INSIDE the transaction: entry
// immediately after the binding-row lock is taken, exit as the last act before
// commit. So the assertion is that the marks strictly alternate — no second
// entry while a first is still inside. Entry requires that same row lock, which
// is held to commit, so "entered after the previous exit" is "entered after the
// previous commit"; the exit mark is simply the last moment the fixture can
// observe from inside.
//
// The observer sleeps on the first entry, holding the lock, so that a
// hypothetically unserialized second transaction has a wide window to enter and
// be caught. Without it the race would have to lose a coin flip to fail, and a
// fixture that only sometimes sees the defect is not a fixture.
func TestSCIMPerBindingSerializationOrderSQLite(t *testing.T) {
	runSCIMPerBindingSerializationOrder(t, seededDB(t, openSQLite))
}
func TestSCIMPerBindingSerializationOrderPostgres(t *testing.T) {
	runSCIMPerBindingSerializationOrder(t, seededDB(t, openPostgres))
}

func runSCIMPerBindingSerializationOrder(t *testing.T, db *store.DB) {
	s := scimSvc(db)
	ctx := t.Context()
	bindingID, token := newSCIMBinding(t, db, "okta")
	wire := service.SCIMCredentialActor(token, bindingID)

	// Setup runs BEFORE the observer is installed, so the recorded phases are
	// the two racing transactions and nothing else.
	members := make([]string, 0, 2)
	for _, name := range []string{"ser-one", "ser-two"} {
		u, err := s.CreateUser(ctx, wire, orgA, bindingID, service.SCIMUserInput{
			UserName: name + "@example.test", ExternalID: name, SubjectRaw: name,
		})
		if err != nil {
			t.Fatal(err)
		}
		members = append(members, u.ID)
	}
	group, err := s.CreateGroup(ctx, wire, orgA, bindingID, service.SCIMGroupInput{
		DisplayName: "Serialized", MembersPresent: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var phases []string
	var slept bool
	restore := service.SetSCIMPhaseObserver(func(p string) {
		mu.Lock()
		phases = append(phases, p)
		first := !slept && strings.HasPrefix(p, "wire-enter:")
		slept = slept || first
		mu.Unlock()
		if first {
			time.Sleep(50 * time.Millisecond)
		}
	})

	start, done := barrier(2)
	errs := make([]error, 2)
	for i := range 2 {
		go func(i int) {
			defer done.Done()
			<-start
			// The bounded client-side retry a connector performs: postgres may
			// answer the loser with a serialization failure rather than making it
			// wait, and that is a throughput answer, not a lost write.
			for range 4 {
				_, errs[i] = s.PatchGroup(ctx, wire, orgA, bindingID, group.ID,
					service.SCIMGroupInput{
						MemberOps: []service.SCIMMemberOp{{Kind: service.SCIMMemberAdd, Members: []string{members[i]}}},
						Patch:     true,
					})
				if errs[i] == nil {
					return
				}
			}
		}(i)
	}
	close(start)
	done.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("overlapping push %d failed: %v", i, err)
		}
	}

	// The order itself: strict alternation across BOTH surfaces, since the
	// administration mutations mark the same pair around the same lock.
	mu.Lock()
	seen := append([]string(nil), phases...)
	mu.Unlock()
	depth, entries := 0, 0
	for i, p := range seen {
		switch {
		case p == "wire-enter:"+bindingID:
			depth++
			entries++
			if depth > 1 {
				t.Fatalf("a second reconciliation entered binding %s while the first was still inside "+
					"(mark %d of %v): per-binding writes did not serialize", bindingID, i, seen)
			}
		case p == "wire-exit:"+bindingID:
			depth--
			if depth < 0 {
				t.Fatalf("an exit with no matching entry at mark %d of %v", i, seen)
			}
		default:
			t.Fatalf("unexpected phase %q from a wire transaction on another binding: %v", p, seen)
		}
	}
	if depth != 0 {
		t.Fatalf("a reconciliation never left: %v", seen)
	}
	if entries < 2 {
		t.Fatalf("only %d reconciliation(s) were observed; the fixture proved nothing: %v", entries, seen)
	}

	// And the consequence the order exists to produce: both adds survived. A
	// lost update here would be the read-modify-write race the lock prevents.
	if n := queryInt(t, db,
		`SELECT COUNT(*) FROM scim_group_members WHERE group_id = '`+group.ID+`'`); n != 2 {
		t.Fatalf("overlapping member adds lost a write: want 2 members, got %d", n)
	}

	// The ADMINISTRATION half (p7#4): mapping authoring reconciles origins in
	// its own transaction, which is the same origin arithmetic a push performs.
	// A mapping create raced against a wire PATCH on the SAME binding must
	// serialize too — the admin surface has no contact UPDATE to take the lock
	// for it, so it takes the row lock explicitly.
	mu.Lock()
	phases, slept = nil, false
	mu.Unlock()
	start, done = barrier(2)
	adminErrs := make([]error, 2)
	for i := range 2 {
		go func(i int) {
			defer done.Done()
			<-start
			for range 4 {
				if i == 0 {
					_, adminErrs[i] = s.CreateMapping(ctx, service.LocalPrincipal(orgAdmin), orgA, bindingID,
						service.SCIMMappingSpec{GroupID: group.ID, Template: domain.TemplateViewer, ProjectID: string(prjA1)})
				} else {
					_, adminErrs[i] = s.PatchGroup(ctx, wire, orgA, bindingID, group.ID,
						service.SCIMGroupInput{
							MemberOps: []service.SCIMMemberOp{{Kind: service.SCIMMemberRemoveOne, Value: members[0]}},
							Patch:     true,
						})
				}
				if adminErrs[i] == nil {
					return
				}
			}
		}(i)
	}
	close(start)
	done.Wait()
	restore()
	for i, err := range adminErrs {
		if err != nil {
			t.Fatalf("admin-versus-wire leg %d failed: %v", i, err)
		}
	}
	mu.Lock()
	mixed := append([]string(nil), phases...)
	mu.Unlock()
	depth, entries = 0, 0
	for i, p := range mixed {
		switch p {
		case "wire-enter:" + bindingID:
			depth++
			entries++
			if depth > 1 {
				t.Fatalf("an administration mutation and a wire push overlapped on binding %s "+
					"(mark %d of %v): the admin surface did not take §9's lock", bindingID, i, mixed)
			}
		case "wire-exit:" + bindingID:
			depth--
		}
	}
	if entries < 2 {
		t.Fatalf("only %d serialized sections observed in the admin-versus-wire leg: %v", entries, mixed)
	}
}

// TestSCIMSyncInvalidatesSessions is SC4.d: "being granted anything logs you
// out, and a sync is a granter". A group-driven grant advances the affected
// human's session generation and sweeps their sessions.
func TestSCIMSyncInvalidatesSessionsSQLite(t *testing.T) {
	runSCIMSyncInvalidatesSessions(t, seededDB(t, openSQLite))
}
func TestSCIMSyncInvalidatesSessionsPostgres(t *testing.T) {
	runSCIMSyncInvalidatesSessions(t, seededDB(t, openPostgres))
}

func runSCIMSyncInvalidatesSessions(t *testing.T, db *store.DB) {
	s := scimSvc(db)
	ctx := t.Context()
	bindingID, token := newSCIMBinding(t, db, "okta")
	wire := service.SCIMCredentialActor(token, bindingID)

	user, err := s.CreateUser(ctx, wire, orgA, bindingID, service.SCIMUserInput{
		UserName: "sess@example.test", ExternalID: "ext-sess", SubjectRaw: "ext-sess",
	})
	if err != nil {
		t.Fatal(err)
	}
	principal := principalOf(t, db, accountOf(t, db, user.ID))
	// A live session for the provisioned human, seeded directly: the point
	// under test is what the SYNC does to it, not how it was minted.
	execRaw(t, db, `INSERT INTO sessions `+
		`(id, principal_id, verifier, artifact, session_generation, credential_epoch, `+
		` auth_method, factors, authenticated_at, created_at, last_seen_at, `+
		` idle_expires_at, absolute_expires_at, source_ip, user_agent) VALUES `+
		`('ses_sync', '`+string(principal)+`', `+blobLit(db, []byte("verifier-sync"))+`, 'cli', 1, 0, `+
		`'local', '[]', `+ts+`, `+ts+`, `+ts+`, `+
		`'2099-01-01T00:00:00.000000Z', '2099-01-01T00:00:00.000000Z', '', '')`)

	before := queryInt(t, db,
		`SELECT session_generation FROM principals WHERE id = '`+string(principal)+`'`)

	group, err := s.CreateGroup(ctx, wire, orgA, bindingID, service.SCIMGroupInput{
		DisplayName: "Session Readers", Members: []string{user.ID}, MembersPresent: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateMapping(ctx, service.LocalPrincipal(orgAdmin), orgA, bindingID,
		service.SCIMMappingSpec{GroupID: group.ID, Template: domain.TemplateViewer, ProjectID: string(prjA1)}); err != nil {
		t.Fatal(err)
	}

	after := queryInt(t, db,
		`SELECT session_generation FROM principals WHERE id = '`+string(principal)+`'`)
	if after <= before {
		t.Fatalf("a sync-created grant must advance the generation: %d -> %d", before, after)
	}
	if n := queryInt(t, db, `SELECT COUNT(*) FROM sessions WHERE id = 'ses_sync'`); n != 0 {
		t.Fatal("a sync-created grant must sweep the grantee's sessions")
	}
}
