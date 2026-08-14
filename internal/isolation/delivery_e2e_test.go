package isolation

import (
	"context"
	"errors"
	"testing"

	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/crypto"
	"github.com/Hikyo-Org/hikyo/internal/delivery"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/schema"
	"github.com/Hikyo-Org/hikyo/internal/service"
	"github.com/Hikyo-Org/hikyo/internal/store"
	"github.com/Hikyo-Org/hikyo/internal/store/tx"
)

// The conditional fetch cursor (#62, machine-identities ADR § Authentication,
// authorization and the fetch path; revision ADR § Revision identity).
//
// The acceptance criterion these discharge is mvp-boundary M1's "cursor
// bind-tuple falsification (all four components) forces full fetch". Each
// component is falsified INDEPENDENTLY — the cursor is recomputed with exactly
// one component replaced and everything else held — because a test that changed
// two at once would pass even if the implementation ignored one of them.

func TestDeliveryCursorRoundTripSQLite(t *testing.T) {
	runDeliveryCursorRoundTrip(t, seededDB(t, openSQLite))
}

func TestDeliveryCursorRoundTripPostgres(t *testing.T) {
	runDeliveryCursorRoundTrip(t, seededDB(t, openPostgres))
}

// runDeliveryCursorRoundTrip is the base behaviour: a first fetch delivers, its
// cursor answers "current" with NO content, and each answer emits exactly one
// immutable access record with the disposition it had.
func runDeliveryCursorRoundTrip(t *testing.T, db *store.DB) {
	identityFixtures(t, db)
	seedDeliveryCatalogue(t, db)
	del := deliverySvc(t, db)
	caller := service.LocalPrincipal(identAdmin)
	env := scopeEnv(orgA, prjA1, envA1)

	first, err := del.FetchAs(t.Context(), caller, env, "")
	if err != nil {
		t.Fatalf("first fetch: %v", err)
	}
	if first.Current {
		t.Fatal("a cursor-less fetch answered `current`")
	}
	// THE DELIVERED KEY SET IS WHAT THE SNAPSHOT DELIVERS, not what the project
	// declares — "a delivered payload's key set is exactly the declared keys
	// that RESOLVE in that environment, under the schema revision that snapshot
	// pinned" (schema ADR § Closed schema). A declared key with no value
	// resolves to nothing and is therefore not delivered at all, which is why
	// this counts the snapshot's entries rather than the catalogue's rows.
	if want := queryInt(t, db,
		`SELECT COUNT(*) FROM snapshot_entries WHERE environment_id = 'env_a1'
		 AND snapshot_id = (SELECT id FROM snapshots WHERE environment_id = 'env_a1'
		                    ORDER BY revision DESC LIMIT 1)`); int64(len(first.Keys)) != want {
		t.Fatalf("delivered %d keys, want the snapshot's %d", len(first.Keys), want)
	}
	presence := map[string]delivery.Presence{}
	for _, k := range first.Keys {
		presence[k.Name] = k.Presence
	}
	// Every delivered key is `set`: it is in the snapshot because it resolved.
	// The declared presence RULE is no longer what the fetch reports, and it is
	// no longer in the manifest either — the change token covers delivered
	// content only, so tightening `required_in` must not fire a rollout wave.
	for _, name := range []string{"DATABASE_URL", "DATABASE_PASSWORD"} {
		if presence[name] != delivery.PresenceSet {
			t.Errorf("%s presence = %q, want set (the snapshot delivers it)", name, presence[name])
		}
	}
	if first.Cursor == "" || first.ChangeToken == "" {
		t.Fatal("a full delivery returned no cursor or no change token")
	}
	// Both keyed values carry the scheme's version prefix. This is a PUBLIC
	// machine contract — the change token flows into pod annotations — so a
	// consumer's comparison must be able to tell a scheme change from a content
	// change.
	if got := first.ChangeToken[:3]; got != crypto.TokenVersion+":" {
		t.Errorf("change token prefix %q, want %q", got, crypto.TokenVersion+":")
	}

	second, err := del.FetchAs(t.Context(), caller, env, first.Cursor)
	if err != nil {
		t.Fatalf("conditional fetch: %v", err)
	}
	if !second.Current {
		t.Fatal("presenting the cursor a fetch just returned did not answer `current`")
	}
	// NO CONTENT. Only a fetch that actually delivers is a disclosure, so a
	// "current" answer that carried the key names would be a disclosure wearing a
	// conditional answer's clothes.
	if len(second.Keys) != 0 {
		t.Fatalf("a `current` answer carried %d keys, want none", len(second.Keys))
	}
	if second.Cursor != first.Cursor {
		t.Fatalf("`current` answer returned cursor %q, want the unchanged %q", second.Cursor, first.Cursor)
	}

	// ONE immutable access record per fetch, with its own disposition. Never a
	// counter, never a mutable last-seen field.
	if n := queryInt(t, db,
		"SELECT COUNT(*) FROM audit_tenant_events WHERE type = 'identity.delivery_fetched' AND payload LIKE '%\"disposition\":\"full\"%'"); n != 1 {
		t.Errorf("full-delivery access records = %d, want exactly 1", n)
	}
	if n := queryInt(t, db,
		"SELECT COUNT(*) FROM audit_tenant_events WHERE type = 'identity.delivery_fetched' AND payload LIKE '%\"disposition\":\"current\"%'"); n != 1 {
		t.Errorf("conditional access records = %d, want exactly 1", n)
	}
	// And the cursor-less fetch is distinguishable from a stale-cursor one, which
	// is the signal the ADR asks to keep visible: repeated cursor-less fetching
	// by one credential is itself worth surfacing.
	if n := queryInt(t, db,
		"SELECT COUNT(*) FROM audit_tenant_events WHERE type = 'identity.delivery_fetched' AND payload LIKE '%\"cursor_presented\":false%'"); n != 1 {
		t.Errorf("cursor-less access records = %d, want exactly 1", n)
	}
}

func TestDeliveryCursorFalsificationSQLite(t *testing.T) {
	runDeliveryCursorFalsification(t, seededDB(t, openSQLite))
}

func TestDeliveryCursorFalsificationPostgres(t *testing.T) {
	runDeliveryCursorFalsification(t, seededDB(t, openPostgres))
}

// runDeliveryCursorFalsification falsifies EACH of the four components
// independently and asserts every one forces a full fetch.
//
// It forges the cursors rather than provoking real state changes, and that is the
// stronger test: provoking a change would prove the cursor moved, while forging
// proves the cursor is BOUND to that component — a component the server ignored
// would produce a cursor that still matched, and the fetch would answer
// "current" for a state it should not have.
func runDeliveryCursorFalsification(t *testing.T, db *store.DB) {
	identityFixtures(t, db)
	seedDeliveryCatalogue(t, db)
	del := deliverySvc(t, db)
	kr := del.Keyring
	caller := service.LocalPrincipal(identAdmin)
	env := scopeEnv(orgA, prjA1, envA1)

	live, err := del.FetchAs(t.Context(), caller, env, "")
	if err != nil {
		t.Fatalf("baseline fetch: %v", err)
	}

	// The server's own four-tuple, reconstructed from the same sources the
	// service reads. The baseline assertion below proves the reconstruction is
	// faithful before any component is falsified — without it, a forged cursor
	// forcing a full fetch would prove only that the test cannot build a cursor.
	// identAdmin holds `read(prj_a1)` and DELIBERATELY no disclosure capability —
	// it is #61's "manage identities without reveal" fixture — so its authorized
	// delivery projection at env_a1 is exactly `{read}`. That the projection is
	// the caller's real grant set rather than a constant is what the falsification
	// below tests.
	authority := principalGeneration(t, db, identAdmin)
	truth := delivery.Cursor{
		ChangeToken:           live.ChangeToken,
		Projection:            []string{string(domain.CapRead)},
		AuthorizationRevision: authority,
		PinGeneration:         0,
	}
	cursorOf := func(c delivery.Cursor) string {
		t.Helper()
		got, err := kr.DeliveryCursor(string(orgA), string(prjA1), string(envA1), delivery.EncodeCursor(c))
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	if cursorOf(truth) != live.Cursor {
		t.Fatalf("reconstructed cursor %q does not match the served one %q — the fixture's model of the four-tuple is wrong, so the falsifications below would prove nothing",
			cursorOf(truth), live.Cursor)
	}

	falsifications := []struct {
		component string
		mutate    func(delivery.Cursor) delivery.Cursor
	}{
		{
			// (1) CHANGE TOKEN — the delivered content moved.
			component: "change token",
			mutate: func(c delivery.Cursor) delivery.Cursor {
				c.ChangeToken = crypto.TokenVersion + ":forged-content-token"
				return c
			},
		},
		{
			// (2) AUTHORIZED DELIVERY PROJECTION — what this caller MAY SEE
			// moved. Without this component a workload granted `reveal` polls,
			// the content has not changed, the token matches, and it is told
			// "current" — so it runs indefinitely without the secrets it is now
			// entitled to, silently.
			component: "authorized delivery projection",
			mutate: func(c delivery.Cursor) delivery.Cursor {
				c.Projection = []string{string(domain.CapRead), string(domain.CapReveal)}
				return c
			},
		},
		{
			// (3) AUTHORIZATION REVISION — the principal's authority moved at
			// all: a grant added, removed or narrowed.
			component: "authorization revision",
			mutate: func(c delivery.Cursor) delivery.Cursor {
				c.AuthorizationRevision++
				return c
			},
		},
		{
			// (4) PIN GENERATION — a pin was created, reassigned or released.
			component: "pin generation",
			mutate: func(c delivery.Cursor) delivery.Cursor {
				c.PinGeneration++
				return c
			},
		},
	}
	for _, f := range falsifications {
		t.Run(f.component, func(t *testing.T) {
			forged := cursorOf(f.mutate(truth))
			if forged == live.Cursor {
				t.Fatal("falsifying this component produced the SAME cursor: it is not in the bind-tuple")
			}
			res, err := del.FetchAs(t.Context(), caller, env, forged)
			if err != nil {
				t.Fatalf("fetch with a falsified cursor: %v", err)
			}
			if res.Current {
				t.Fatal("a cursor with this component falsified was accepted as `current`")
			}
			if len(res.Keys) == 0 {
				t.Fatal("a falsified cursor produced neither `current` nor a delivery")
			}
		})
	}
}

func TestDeliveryAuthorizationMovementInvalidatesCursorSQLite(t *testing.T) {
	runAuthorizationMovementInvalidatesCursor(t, seededDB(t, openSQLite))
}

func TestDeliveryAuthorizationMovementInvalidatesCursorPostgres(t *testing.T) {
	runAuthorizationMovementInvalidatesCursor(t, seededDB(t, openPostgres))
}

// runAuthorizationMovementInvalidatesCursor is the same rule from the other
// direction: rather than forging a component, it MOVES real state and asserts the
// cursor the caller holds stops being current.
//
// Two movements, because they invalidate through different components: a grant
// mutation on the principal (authorization revision) and a pin generation change
// (pin generation). The content is untouched throughout, so a content-only cursor
// would keep answering "current" for both.
func runAuthorizationMovementInvalidatesCursor(t *testing.T, db *store.DB) {
	identityFixtures(t, db)
	seedDeliveryCatalogue(t, db)
	del := deliverySvc(t, db)
	ident := identitySvc(db)
	env := scopeEnv(orgA, prjA1, envA1)

	// A workload service account with `read(env_a1)` and a bearer credential, so
	// the caller under test is a real machine principal rather than the
	// administrator that granted it.
	sa, err := ident.CreateServiceAccount(t.Context(), service.LocalPrincipal(identAdmin),
		prjScope(), "cursor-workload", domain.ClassWorkload)
	if err != nil {
		t.Fatal(err)
	}
	minted, err := ident.MintCredential(t.Context(), service.LocalPrincipal(identAdmin),
		prjScope(), sa.ID, service.MintRequest{})
	if err != nil {
		t.Fatal(err)
	}
	grantMachineRead(t, db, sa.Principal, envA1)

	first, err := del.Fetch(t.Context(), minted.Value, env, "")
	if err != nil {
		t.Fatalf("machine fetch: %v", err)
	}
	current, err := del.Fetch(t.Context(), minted.Value, env, first.Cursor)
	if err != nil {
		t.Fatalf("machine conditional fetch: %v", err)
	}
	if !current.Current {
		t.Fatal("the cursor a machine fetch just returned was not current")
	}

	// MOVEMENT 1: a grant lands on the principal. Nothing about the delivered
	// content changed, so this is exactly the case a content-only cursor gets
	// wrong.
	if _, err := grantSvcWithAuth(db).Create(t.Context(), service.LocalPrincipal(identAdmin),
		service.GrantSpec{Target: sa.Principal, Capability: domain.CapRead, Scope: envScope(envProd)}); err != nil {
		t.Fatalf("grant read(env_prod): %v", err)
	}
	afterGrant, err := del.Fetch(t.Context(), minted.Value, env, first.Cursor)
	if err != nil {
		t.Fatalf("fetch after a grant mutation: %v", err)
	}
	if afterGrant.Current {
		t.Fatal("a grant mutation on the principal left the cursor current")
	}
	if afterGrant.ChangeToken != first.ChangeToken {
		t.Fatal("the change token moved: the fixture changed content, so it is not proving that AUTHORIZATION movement invalidates")
	}

	// MOVEMENT 2: the pin generation advances. Pin creation, reassignment and
	// release are #52's; the counter they must move exists now, and the cursor is
	// bound to it now.
	if err := advancePinGeneration(t, db, sa.Principal, envA1); err != nil {
		t.Fatalf("advance pin generation: %v", err)
	}
	afterPin, err := del.Fetch(t.Context(), minted.Value, env, afterGrant.Cursor)
	if err != nil {
		t.Fatalf("fetch after a pin-generation change: %v", err)
	}
	if afterPin.Current {
		t.Fatal("a pin-generation change left the cursor current")
	}
	if afterPin.ChangeToken != first.ChangeToken {
		t.Fatal("the change token moved: the fixture changed content rather than the pin generation")
	}
}

func TestDeliveryUnauthorizedIsIndistinguishableSQLite(t *testing.T) {
	runDeliveryUnauthorized(t, seededDB(t, openSQLite))
}

func TestDeliveryUnauthorizedIsIndistinguishablePostgres(t *testing.T) {
	runDeliveryUnauthorized(t, seededDB(t, openPostgres))
}

// runDeliveryUnauthorized is the ADR's "authorization is evaluated on the
// conditional path exactly as on the delivering path": a caller who has lost
// `read` learns nothing, and specifically is never told "current".
//
// The strongest form of the test is the one run here: the caller presents a
// cursor that WAS current, then loses `read`, then presents it again. An
// implementation that checked the cursor before authorizing would answer
// "current" — which tells the caller its cursor is still the live state, i.e.
// that the environment has not changed, which is disclosure.
func runDeliveryUnauthorized(t *testing.T, db *store.DB) {
	identityFixtures(t, db)
	seedDeliveryCatalogue(t, db)
	del := deliverySvc(t, db)
	ident := identitySvc(db)
	env := scopeEnv(orgA, prjA1, envA1)

	sa, err := ident.CreateServiceAccount(t.Context(), service.LocalPrincipal(identAdmin),
		prjScope(), "loses-read", domain.ClassWorkload)
	if err != nil {
		t.Fatal(err)
	}
	minted, err := ident.MintCredential(t.Context(), service.LocalPrincipal(identAdmin),
		prjScope(), sa.ID, service.MintRequest{})
	if err != nil {
		t.Fatal(err)
	}
	grantMachineRead(t, db, sa.Principal, envA1)

	served, err := del.Fetch(t.Context(), minted.Value, env, "")
	if err != nil {
		t.Fatalf("fetch while authorized: %v", err)
	}

	// The grant goes away. Revocation bites at the next fetch, uncached.
	if err := grantSvcWithAuth(db).Revoke(t.Context(), service.LocalPrincipal(identAdmin),
		service.GrantSpec{Target: sa.Principal, Capability: domain.CapRead, Scope: envScope(envA1)}); err != nil {
		t.Fatalf("revoke read(env_a1): %v", err)
	}

	withCursor, err := del.Fetch(t.Context(), minted.Value, env, served.Cursor)
	withoutCursor, errNoCursor := del.Fetch(t.Context(), minted.Value, env, "")
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("conditional fetch after losing read = (%+v, %v), want the uniform nonexistent response",
			withCursor, err)
	}
	if !errors.Is(errNoCursor, domain.ErrNotFound) {
		t.Fatalf("full fetch after losing read = (%+v, %v), want the uniform nonexistent response",
			withoutCursor, errNoCursor)
	}
	// The two refusals are the SAME refusal: presenting a cursor must not be a
	// way to learn anything a cursor-less caller could not learn.
	if err.Error() != errNoCursor.Error() {
		t.Fatalf("refusal shapes differ:\n  with cursor:    %q\n  without cursor: %q", err, errNoCursor)
	}

	// And an environment that genuinely does not exist answers identically.
	missing, missingErr := del.Fetch(t.Context(), minted.Value,
		scopeEnv(orgA, prjA1, domain.EnvID("env_not_there")), "")
	if !errors.Is(missingErr, domain.ErrNotFound) || missingErr.Error() != err.Error() {
		t.Fatalf("nonexistent environment = (%+v, %v), want the same shape as the unauthorized one (%v)",
			missing, missingErr, err)
	}
}

func TestDeliveryChangeTokenTracksTheManifestSQLite(t *testing.T) {
	db := seededDB(t, openSQLite)
	identityFixtures(t, db)
	seedDeliveryCatalogue(t, db)
	del := deliverySvc(t, db)
	caller := service.LocalPrincipal(identAdmin)
	env := scopeEnv(orgA, prjA1, envA1)

	before, err := del.FetchAs(t.Context(), caller, env, "")
	if err != nil {
		t.Fatal(err)
	}

	// A VALUE CHANGE moves the token. This is the leg the pre-#51 surface could
	// not express — there were no values — and it is the whole reason the token
	// exists: a rotated credential that did not move the token would never fire
	// the consumer's rollout.
	publishDeliveryValues(t, db, envA1, map[string]string{"DATABASE_URL": "postgres://dev-rotated"})
	afterValue, err := del.FetchAs(t.Context(), caller, env, "")
	if err != nil {
		t.Fatal(err)
	}
	if afterValue.ChangeToken == before.ChangeToken {
		t.Fatal("changing a value left the change token unchanged: the manifest does not cover values")
	}

	// RECLASSIFICATION moves the token even though no value changed. That is the
	// schema ADR's amendment to the revision ADR, and the reason is concrete: an
	// adapter routing `secret` to a Secret and `config` to a ConfigMap would
	// otherwise see an unchanged token across a reclassification and never fire
	// the rollout that relocates the value.
	//
	// It runs through the real ceremony rather than a raw UPDATE, because under
	// #51 the snapshot is immutable: what a revision delivered is fixed at the
	// classification it was materialized under, and only a semantic schema
	// change — which materializes every environment — can move it.
	if _, err := keySvc(t, db).Reclassify(t.Context(), caller, scopeProject(orgA, prjA1),
		"key_fed_url", "secret"); err != nil {
		t.Fatalf("reclassify: %v", err)
	}
	afterClass, err := del.FetchAs(t.Context(), caller, env, "")
	if err != nil {
		t.Fatal(err)
	}
	if afterClass.ChangeToken == afterValue.ChangeToken {
		t.Fatal("reclassifying a key left the change token unchanged: the manifest does not cover classification")
	}

	// A PRESENCE RULE change does NOT move the token, and that inversion is the
	// point. The token covers DELIVERED CONTENT ONLY (revision ADR § Revision
	// identity): `required_in` governs what a future publish may commit, not
	// what this snapshot delivers, so tightening it must not fire a rollout wave
	// across every consumer. The environment still advances to a NEW REVISION —
	// the validation guarantee moved, and that is recorded — which is exactly
	// the ADR's "an unchanged manifest yields an unchanged token and no workload
	// rollout, without disturbing anything".
	revisionBefore := latestRevision(t, db, "env_a1")
	if _, err := keySvc(t, db).UpdateDeclaration(t.Context(), caller, scopeProject(orgA, prjA1),
		"key_fed_pw", service.KeyDeclarationUpdate{
			Declaration: schema.Declaration{Rule: &schema.Rule{Type: schema.TypeString}},
			// A REAL presence change: forbidden where the key has no value, so
			// the rule is satisfiable and the only thing it moves is the
			// pinned schema revision.
			Presence: schema.PresenceRules{
				Required:  schema.Presence{Mode: schema.PresenceNone},
				Forbidden: schema.Presence{Mode: schema.PresenceExplicit, Environments: []string{string(envProd)}},
			},
		}); err != nil {
		t.Fatalf("presence-rule change: %v", err)
	}
	afterPresence, err := del.FetchAs(t.Context(), caller, env, "")
	if err != nil {
		t.Fatal(err)
	}
	if afterPresence.ChangeToken != afterClass.ChangeToken {
		t.Fatal("a presence-rule change moved the change token: the manifest must cover delivered content only")
	}
	if after := latestRevision(t, db, "env_a1"); after <= revisionBefore {
		t.Fatalf("a semantic schema change did not advance the revision: %d -> %d", revisionBefore, after)
	}

	// The token is SCOPED: the same manifest in a different environment yields a
	// different token, because the key is derived per (org, project,
	// environment). Without that, an attacker who can write values in their own
	// project could construct a candidate payload, read its token, and compare it
	// against a target environment's pod annotation.
	otherEnv, err := del.FetchAs(t.Context(), caller, scopeEnv(orgA, prjA1, envProd), "")
	if err != nil {
		t.Fatal(err)
	}
	if otherEnv.ChangeToken == afterPresence.ChangeToken {
		t.Fatal("two environments produced the same change token: the token key is not scoped")
	}
	// …and a cursor from one environment is not current in another.
	crossed, err := del.FetchAs(t.Context(), caller, scopeEnv(orgA, prjA1, envProd), afterPresence.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	if crossed.Current {
		t.Fatal("a cursor from one environment was accepted as current in another")
	}
}

// latestRevision reads one environment's newest published revision straight
// from the datastore: the assertion is about what the pipeline recorded, so
// reading it through the pipeline's own API would only prove the API agrees
// with itself.
func latestRevision(t *testing.T, db *store.DB, envID string) int64 {
	t.Helper()
	return queryInt(t, db,
		"SELECT COALESCE(MAX(revision), 0) FROM snapshots WHERE environment_id = '"+envID+"'")
}

// deliverySvc builds the delivery surface with a live keyring. The change token
// is KEYED, so there is nothing to fake: a fixture without a keyring would be
// testing a different mechanism.
func deliverySvc(t *testing.T, db *store.DB) *service.Delivery {
	t.Helper()
	return &service.Delivery{DB: db, Keyring: authService(t, db).Keyring}
}

// principalGeneration reads the AUTHORIZATION REVISION component straight from
// the table, so the fixture's model of the four-tuple is built from the same
// source the service reads rather than from a guess about its value.
//
// It is `principals.session_generation`: the counter every grant writer advances
// when EFFECTIVE authority changes, which is exactly what the cursor's third
// component has to track. #62 added no new counter because #55's already moves
// on the events the ADR names — a grant added, removed or narrowed.
func principalGeneration(t *testing.T, db *store.DB, p domain.PrincipalID) int64 {
	t.Helper()
	return queryInt(t, db,
		"SELECT session_generation FROM principals WHERE id = '"+string(p)+"'")
}

// advancePinGeneration moves the pin component. #52 owns pin creation,
// reassignment and release; this writes the counter each of those must advance,
// through the same store method they will.
func advancePinGeneration(t *testing.T, db *store.DB, p domain.PrincipalID, env domain.EnvID) error {
	t.Helper()
	return tx.Write(t.Context(), db, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		current, err := az.PinGeneration(ctx, p, env)
		if err != nil {
			return err
		}
		return az.SetPinGeneration(ctx, p, env, current+1)
	})
}
