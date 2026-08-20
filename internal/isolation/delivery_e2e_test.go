package isolation

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

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
// authorization and the fetch path; revision-model ADR § Revision identity).
//
// The acceptance criterion these discharge is mvp-boundary M1's "cursor
// bind-tuple falsification forces full fetch", extended by #64 with the
// projection-mode component. Each component is falsified INDEPENDENTLY — the
// cursor is recomputed with exactly one component replaced and everything else
// held — because a test that changed two at once would pass even if the
// implementation ignored one of them.

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
	issuedAt := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	del.Now = func() time.Time { return issuedAt }
	caller := service.LocalPrincipal(identAdmin)
	env := scopeEnv(orgA, prjA1, envA1)

	first, err := del.FetchAs(t.Context(), caller, env, "", service.FetchOptions{})
	if err != nil {
		t.Fatalf("first fetch: %v", err)
	}
	if first.Current {
		t.Fatal("a cursor-less fetch answered `current`")
	}
	// THE DELIVERED KEY SET IS WHAT THE SNAPSHOT DELIVERS, not what the project
	// declares — "a delivered payload's key set is exactly the declared keys
	// that RESOLVE in that environment, under the schema revision that snapshot
	// pinned" (schema-model ADR § Closed schema). A declared key with no value
	// resolves to nothing and is therefore not delivered at all, which is why
	// this counts the snapshot's entries rather than the catalogue's rows.
	if want := queryInt(t, db,
		`SELECT COUNT(*) FROM snapshot_entries WHERE environment_id = 'env_a1'
		 AND snapshot_id = (SELECT id FROM snapshots WHERE environment_id = 'env_a1'
		                    ORDER BY revision DESC LIMIT 1)`); int64(len(first.Keys)) != want {
		t.Fatalf("delivered %d keys, want the snapshot's %d", len(first.Keys), want)
	}
	presence := map[string]delivery.Presence{}
	values := map[string]*string{}
	for _, k := range first.Keys {
		presence[k.Name] = k.Presence
		values[k.Name] = k.Value
	}
	if values["DATABASE_URL"] == nil || *values["DATABASE_URL"] == "" {
		t.Fatal("read-only delivery omitted the config plaintext")
	}
	if values["DATABASE_PASSWORD"] != nil {
		t.Fatal("read-only delivery exposed secret plaintext")
	}
	if !first.IssuedAt.Equal(issuedAt) || !first.SnapshotExpiresAt.Equal(issuedAt.Add(delivery.SnapshotMaxAge)) {
		t.Fatalf("snapshot timestamps = (%s, %s), want issued_at %s and +7d expiry",
			first.IssuedAt, first.SnapshotExpiresAt, issuedAt)
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
	// machine contract — the change token is the consumer's change-detection
	// input — so a consumer's comparison must be able to tell a scheme change
	// from a content change.
	if got := first.ChangeToken[:3]; got != crypto.TokenVersion+":" {
		t.Errorf("change token prefix %q, want %q", got, crypto.TokenVersion+":")
	}

	second, err := del.FetchAs(t.Context(), caller, env, first.Cursor, service.FetchOptions{})
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
	// Config-only projection + per-value disclosure coverage lives in the
	// dedicated runDeliveryConfigOnlyProjection / runDeliveryDeliversValues (#64's
	// winning surface): the reconciled shape omits secrets ENTIRELY under
	// config-only and emits identity.disclosure per delivered value.
}

func TestOfflineRecordReconciliationSQLite(t *testing.T) {
	runOfflineRecordReconciliation(t, seededDB(t, openSQLite))
}

func TestOfflineRecordReconciliationPostgres(t *testing.T) {
	runOfflineRecordReconciliation(t, seededDB(t, openPostgres))
}

func runOfflineRecordReconciliation(t *testing.T, db *store.DB) {
	identityFixtures(t, db)
	ident := identitySvc(db)
	sa, err := ident.CreateServiceAccount(t.Context(), service.LocalPrincipal(identAdmin),
		prjScope(), "offline-workload", domain.ClassWorkload)
	if err != nil {
		t.Fatal(err)
	}
	served, err := ident.MintCredential(t.Context(), service.LocalPrincipal(identAdmin), prjScope(), sa.ID, service.MintRequest{})
	if err != nil {
		t.Fatal(err)
	}
	presenter, err := ident.MintCredential(t.Context(), service.LocalPrincipal(identAdmin), prjScope(), sa.ID, service.MintRequest{})
	if err != nil {
		t.Fatal(err)
	}
	grantMachineRead(t, db, sa.Principal, envA1)
	if err := ident.RevokeCredential(t.Context(), service.LocalPrincipal(identAdmin), prjScope(), sa.ID, served.Credential.ID); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	record := service.OfflineRecord{
		RecordID: "offline-001", KeyID: "key_fed_pw", KeyName: "DATABASE_PASSWORD",
		Classification: string(schema.Secret), OccurredAt: now.Add(-time.Minute),
		CredentialID: served.Credential.ID, Generation: "v1-0123456789abcdef0123456789abcdef",
		ServedFrom: now.Add(-time.Hour),
	}
	del := deliverySvc(t, db)
	first, err := del.ReconcileOfflineRecords(t.Context(), presenter.Value,
		scopeEnv(orgA, prjA1, envA1), []service.OfflineRecord{record})
	if err != nil || first.Accepted != 1 || first.Duplicates != 0 {
		t.Fatalf("first reconciliation = (%+v, %v)", first, err)
	}
	second, err := del.ReconcileOfflineRecords(t.Context(), presenter.Value,
		scopeEnv(orgA, prjA1, envA1), []service.OfflineRecord{record})
	if err != nil || second.Accepted != 0 || second.Duplicates != 1 {
		t.Fatalf("duplicate reconciliation = (%+v, %v)", second, err)
	}
	asserted := "occurred_asserted = 1"
	if db.Engine() == store.EnginePostgres {
		asserted = "occurred_asserted"
	}
	if got := queryInt(t, db, `SELECT COUNT(*) FROM audit_tenant_events
		WHERE type = 'disclosure.value_revealed' AND origin = 'offline-reconciled' AND `+asserted); got != 1 {
		t.Fatalf("offline disclosure events = %d, want 1", got)
	}
}

func TestDeliveryCursorFalsificationSQLite(t *testing.T) {
	runDeliveryCursorFalsification(t, seededDB(t, openSQLite))
}

func TestDeliveryCursorFalsificationPostgres(t *testing.T) {
	runDeliveryCursorFalsification(t, seededDB(t, openPostgres))
}

// runDeliveryCursorFalsification falsifies EACH cursor component
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

	live, err := del.FetchAs(t.Context(), caller, env, "", service.FetchOptions{})
	if err != nil {
		t.Fatalf("baseline fetch: %v", err)
	}

	// The server's own tuple, reconstructed from the same sources the
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
		t.Fatalf("reconstructed cursor %q does not match the served one %q — the fixture's model of the tuple is wrong, so the falsifications below would prove nothing",
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
		{
			// (5) PROJECTION MODE — the delivery projection moved (`full` vs
			// `config-only`). The served fetch is `full`, so a cursor claiming
			// `config-only` describes a strictly smaller delivery and must not be
			// accepted as current. This is the #64 leg: every pre-projection
			// cursor mismatches exactly once, the designed upgrade path.
			component: "projection mode",
			mutate: func(c delivery.Cursor) delivery.Cursor {
				c.Mode = delivery.ModeConfigOnly
				return c
			},
		},
		{
			// (6) PINNED HISTORICAL REVISION — the delivered snapshot became a
			// pinned NON-CURRENT revision. The baseline fetch is unpinned, so the
			// served cursor binds 0; a cursor claiming a pinned historical
			// revision describes a delivery whose secret-value authority is
			// `reveal-history` rather than `reveal`, and must not be accepted as
			// current. This is the #64 P1 leg: the transition a content-only
			// cursor gets wrong.
			component: "pinned historical revision",
			mutate: func(c delivery.Cursor) delivery.Cursor {
				c.PinnedHistoricalRevision = 1
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
			res, err := del.FetchAs(t.Context(), caller, env, forged, service.FetchOptions{})
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

	first, err := del.Fetch(t.Context(), minted.Value, env, "", service.FetchOptions{})
	if err != nil {
		t.Fatalf("machine fetch: %v", err)
	}
	current, err := del.Fetch(t.Context(), minted.Value, env, first.Cursor, service.FetchOptions{})
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
	afterGrant, err := del.Fetch(t.Context(), minted.Value, env, first.Cursor, service.FetchOptions{})
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
	afterPin, err := del.Fetch(t.Context(), minted.Value, env, afterGrant.Cursor, service.FetchOptions{})
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

	served, err := del.Fetch(t.Context(), minted.Value, env, "", service.FetchOptions{})
	if err != nil {
		t.Fatalf("fetch while authorized: %v", err)
	}

	// The grant goes away. Revocation bites at the next fetch, uncached.
	if err := grantSvcWithAuth(db).Revoke(t.Context(), service.LocalPrincipal(identAdmin),
		service.GrantSpec{Target: sa.Principal, Capability: domain.CapRead, Scope: envScope(envA1)}); err != nil {
		t.Fatalf("revoke read(env_a1): %v", err)
	}

	withCursor, err := del.Fetch(t.Context(), minted.Value, env, served.Cursor, service.FetchOptions{})
	withoutCursor, errNoCursor := del.Fetch(t.Context(), minted.Value, env, "", service.FetchOptions{})
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
		scopeEnv(orgA, prjA1, domain.EnvID("env_not_there")), "", service.FetchOptions{})
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

	before, err := del.FetchAs(t.Context(), caller, env, "", service.FetchOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// A VALUE CHANGE moves the token. This is the leg the pre-#51 surface could
	// not express — there were no values — and it is the whole reason the token
	// exists: a rotated credential that did not move the token would never fire
	// the consumer's rollout.
	publishDeliveryValues(t, db, envA1, map[string]string{"DATABASE_URL": "postgres://dev-rotated"})
	afterValue, err := del.FetchAs(t.Context(), caller, env, "", service.FetchOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if afterValue.ChangeToken == before.ChangeToken {
		t.Fatal("changing a value left the change token unchanged: the manifest does not cover values")
	}

	// RECLASSIFICATION moves the token even though no value changed. That is the
	// schema-model ADR's amendment to the revision-model ADR, and the reason is concrete: an
	// adapter routing `secret` to a Secret and `config` to a ConfigMap would
	// otherwise see an unchanged token across a reclassification and never fire
	// the rollout that relocates the value.
	//
	// It runs through the real ceremony rather than a raw UPDATE, because under
	// #51 the snapshot is immutable: what a revision delivered is fixed at the
	// classification it was materialized under, and only a semantic schema
	// change — which materializes every environment — can move it.
	if _, _, err := keySvc(t, db).Reclassify(t.Context(), caller, scopeProject(orgA, prjA1),
		"key_fed_url", "secret"); err != nil {
		t.Fatalf("reclassify: %v", err)
	}
	afterClass, err := del.FetchAs(t.Context(), caller, env, "", service.FetchOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if afterClass.ChangeToken == afterValue.ChangeToken {
		t.Fatal("reclassifying a key left the change token unchanged: the manifest does not cover classification")
	}

	// A PRESENCE RULE change does NOT move the token, and that inversion is the
	// point. The token covers DELIVERED CONTENT ONLY (revision-model ADR § Revision
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
		}, nil); err != nil {
		t.Fatalf("presence-rule change: %v", err)
	}
	afterPresence, err := del.FetchAs(t.Context(), caller, env, "", service.FetchOptions{})
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
	otherEnv, err := del.FetchAs(t.Context(), caller, scopeEnv(orgA, prjA1, envProd), "", service.FetchOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if otherEnv.ChangeToken == afterPresence.ChangeToken {
		t.Fatal("two environments produced the same change token: the token key is not scoped")
	}
	// …and a cursor from one environment is not current in another.
	crossed, err := del.FetchAs(t.Context(), caller, scopeEnv(orgA, prjA1, envProd), afterPresence.Cursor, service.FetchOptions{})
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
// the table, so the fixture's model of the tuple is built from the same
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

// The value-delivery slice (#64, k8s ADR § Refresh; machine-identities ADR §
// Audit attribution). A fetch now delivers PLAINTEXT where the caller is
// authorized, and records one disclosure per delivered value.

func TestDeliveryDeliversValuesUnderAuthoritySQLite(t *testing.T) {
	runDeliveryDeliversValues(t, seededDB(t, openSQLite))
}

func TestDeliveryDeliversValuesUnderAuthorityPostgres(t *testing.T) {
	runDeliveryDeliversValues(t, seededDB(t, openPostgres))
}

// runDeliveryDeliversValues is the per-key value rule made empirical: a config
// value crosses under `read`, a secret value only under `reveal`, and each
// delivered value leaves exactly one immutable disclosure record referencing
// the fetch.
func runDeliveryDeliversValues(t *testing.T, db *store.DB) {
	identityFixtures(t, db)
	seedDeliveryCatalogue(t, db)
	del := deliverySvc(t, db)
	ident := identitySvc(db)
	env := scopeEnv(orgA, prjA1, envA1)

	sa, err := ident.CreateServiceAccount(t.Context(), service.LocalPrincipal(identAdmin),
		prjScope(), "value-workload", domain.ClassWorkload)
	if err != nil {
		t.Fatal(err)
	}
	minted, err := ident.MintCredential(t.Context(), service.LocalPrincipal(identAdmin),
		prjScope(), sa.ID, service.MintRequest{})
	if err != nil {
		t.Fatal(err)
	}
	grantMachineRead(t, db, sa.Principal, envA1)

	// WITHOUT `reveal`: the config value crosses, the secret is presence-only.
	first, err := del.Fetch(t.Context(), minted.Value, env, "", service.FetchOptions{})
	if err != nil {
		t.Fatalf("fetch without reveal: %v", err)
	}
	got := deliveredByName(first.Keys)
	if v := got["DATABASE_URL"].Value; v == nil || *v != "postgres://dev" {
		t.Errorf("config value = %v, want the delivered plaintext under read", v)
	}
	if pw := got["DATABASE_PASSWORD"]; pw.Value != nil {
		t.Errorf("secret value delivered without reveal: %q — it must be presence-only", *pw.Value)
	}
	if got["DATABASE_PASSWORD"].Presence != delivery.PresenceSet {
		t.Errorf("presence-only secret presence = %q, want set", got["DATABASE_PASSWORD"].Presence)
	}
	// A finite credential surfaces its expiry.
	if first.CredentialExpiresAt.IsZero() {
		t.Error("a finite credential delivered no credential_expires_at")
	}
	// The record: two keys, one delivered value, projection full.
	if n := queryInt(t, db, `SELECT COUNT(*) FROM audit_tenant_events WHERE type = 'identity.delivery_fetched'
		AND payload LIKE '%"key_count":2%' AND payload LIKE '%"delivered_count":1%' AND payload LIKE '%"projection":"full"%'`); n != 1 {
		t.Errorf("delivery record with 2 keys / 1 value / full = %d, want 1", n)
	}
	// One disclosure, for the config value only, correlated to the fetch.
	if n := queryInt(t, db, `SELECT COUNT(*) FROM audit_tenant_events WHERE type = 'identity.disclosure'`); n != 1 {
		t.Errorf("disclosure rows after a config-only-authorized fetch = %d, want 1", n)
	}
	if n := queryInt(t, db, `SELECT COUNT(*) FROM audit_tenant_events WHERE type = 'identity.disclosure'
		AND payload LIKE '%"key":"DATABASE_URL"%' AND payload LIKE '%"classification":"config"%'`); n != 1 {
		t.Errorf("config disclosure row = %d, want 1", n)
	}
	// The correlation id is the fetch record's id.
	fetchID := queryString(t, db, `SELECT id FROM audit_tenant_events WHERE type = 'identity.delivery_fetched' LIMIT 1`)
	if n := queryInt(t, db, `SELECT COUNT(*) FROM audit_tenant_events WHERE type = 'identity.disclosure'
		AND correlation_id = '`+fetchID+`'`); n != 1 {
		t.Errorf("disclosure correlated to the fetch = %d, want 1", n)
	}

	// SEED `reveal` at store level, exactly as #17/#58's opt-in will (the grant
	// API refuses machine reveal today). Now the secret value crosses too.
	seedMachineReveal(t, db, "g_val_reveal", sa.Principal, domain.CapReveal, envA1)
	second, err := del.Fetch(t.Context(), minted.Value, env, "", service.FetchOptions{})
	if err != nil {
		t.Fatalf("fetch with reveal: %v", err)
	}
	got = deliveredByName(second.Keys)
	if v := got["DATABASE_PASSWORD"].Value; v == nil || *v != "dev-secret" {
		t.Errorf("secret value with reveal = %v, want the delivered plaintext", v)
	}
	// Both values delivered → delivered_count 2 → two more disclosure rows
	// (three total: one config from the first fetch, config+secret from this).
	if n := queryInt(t, db, `SELECT COUNT(*) FROM audit_tenant_events WHERE type = 'identity.delivery_fetched'
		AND payload LIKE '%"delivered_count":2%'`); n != 1 {
		t.Errorf("delivery record with 2 delivered values = %d, want 1", n)
	}
	if n := queryInt(t, db, `SELECT COUNT(*) FROM audit_tenant_events WHERE type = 'identity.disclosure'`); n != 3 {
		t.Errorf("cumulative disclosure rows = %d, want 3 (1 + config + secret)", n)
	}

	// A `current` answer delivers nothing, so it emits NO disclosure and no
	// value crosses.
	before := queryInt(t, db, `SELECT COUNT(*) FROM audit_tenant_events WHERE type = 'identity.disclosure'`)
	current, err := del.Fetch(t.Context(), minted.Value, env, second.Cursor, service.FetchOptions{})
	if err != nil {
		t.Fatalf("conditional fetch: %v", err)
	}
	if !current.Current {
		t.Fatal("the cursor a value fetch just returned was not current")
	}
	if len(current.Keys) != 0 {
		t.Fatalf("a `current` answer carried %d keys, want none", len(current.Keys))
	}
	if after := queryInt(t, db, `SELECT COUNT(*) FROM audit_tenant_events WHERE type = 'identity.disclosure'`); after != before {
		t.Errorf("a `current` answer emitted %d disclosure rows, want 0", after-before)
	}
}

func TestDeliveryConfigOnlyProjectionSQLite(t *testing.T) {
	runDeliveryConfigOnlyProjection(t, seededDB(t, openSQLite))
}

func TestDeliveryConfigOnlyProjectionPostgres(t *testing.T) {
	runDeliveryConfigOnlyProjection(t, seededDB(t, openPostgres))
}

// runDeliveryConfigOnlyProjection pins the server-side authorized term:
// `config-only` omits secret keys ENTIRELY (not presence-only), computes a
// different change token because the manifest is smaller, and yields a cursor
// that a full fetch's cursor does not answer.
func runDeliveryConfigOnlyProjection(t *testing.T, db *store.DB) {
	identityFixtures(t, db)
	seedDeliveryCatalogue(t, db)
	del := deliverySvc(t, db)
	caller := service.LocalPrincipal(identAdmin)
	env := scopeEnv(orgA, prjA1, envA1)

	full, err := del.FetchAs(t.Context(), caller, env, "", service.FetchOptions{Projection: delivery.ModeFull})
	if err != nil {
		t.Fatal(err)
	}
	confOnly, err := del.FetchAs(t.Context(), caller, env, "", service.FetchOptions{Projection: delivery.ModeConfigOnly})
	if err != nil {
		t.Fatal(err)
	}

	// The secret is GONE from config-only, not presence-only.
	if _, present := deliveredByName(confOnly.Keys)["DATABASE_PASSWORD"]; present {
		t.Error("config-only delivered the secret key; it must be omitted entirely")
	}
	if _, present := deliveredByName(confOnly.Keys)["DATABASE_URL"]; !present {
		t.Error("config-only dropped the config key")
	}
	if _, present := deliveredByName(full.Keys)["DATABASE_PASSWORD"]; !present {
		t.Error("full projection dropped the secret key")
	}

	// The manifest is smaller, so the change token differs, and the cursor is
	// mode-bound, so a config-only cursor is not current against a full fetch.
	if confOnly.ChangeToken == full.ChangeToken {
		t.Error("config-only and full produced the same change token: the manifest is not projected")
	}
	if confOnly.Cursor == full.Cursor {
		t.Error("config-only and full produced the same cursor: the mode is not bound in")
	}
	crossed, err := del.FetchAs(t.Context(), caller, env, confOnly.Cursor, service.FetchOptions{Projection: delivery.ModeFull})
	if err != nil {
		t.Fatal(err)
	}
	if crossed.Current {
		t.Error("a config-only cursor was accepted as current for a full fetch")
	}
	// The config-only cursor IS current for a repeat config-only fetch.
	same, err := del.FetchAs(t.Context(), caller, env, confOnly.Cursor, service.FetchOptions{Projection: delivery.ModeConfigOnly})
	if err != nil {
		t.Fatal(err)
	}
	if !same.Current {
		t.Error("a config-only cursor was not current for a repeat config-only fetch")
	}

	// An unrecognized projection is refused loudly BEFORE any work — the
	// exported below-the-network path has no OpenAPI enum in front of it.
	if _, err := del.FetchAs(t.Context(), caller, env, "", service.FetchOptions{Projection: delivery.Mode("bogus")}); !errors.Is(err, domain.ErrInvalid) {
		t.Errorf("bogus projection = %v, want ErrInvalid", err)
	}
}

func TestDeliveryAcknowledgedKeysAreRecordedSQLite(t *testing.T) {
	runDeliveryAcknowledgedKeys(t, seededDB(t, openSQLite))
}

func TestDeliveryAcknowledgedKeysAreRecordedPostgres(t *testing.T) {
	runDeliveryAcknowledgedKeys(t, seededDB(t, openPostgres))
}

// runDeliveryAcknowledgedKeys pins the loader-control acknowledgement's two
// server obligations: it lands on the fetch record AS PRESENTED and it is
// otherwise ignored, and a malformed list is refused as a caller error BEFORE
// any work rather than surfacing as the audit registry's fail-loud bound.
func runDeliveryAcknowledgedKeys(t *testing.T, db *store.DB) {
	identityFixtures(t, db)
	seedDeliveryCatalogue(t, db)
	del := deliverySvc(t, db)
	env := scopeEnv(orgA, prjA1, envA1)

	// The list lands on the record AS PRESENTED — order preserved, nothing
	// filtered — and it changes nothing about what is delivered.
	if _, err := del.FetchAs(t.Context(), service.LocalPrincipal(identAdmin), env, "",
		service.FetchOptions{AcknowledgedKeys: []string{"PATH", "LD_PRELOAD"}}); err != nil {
		t.Fatal(err)
	}
	if n := queryInt(t, db, `SELECT COUNT(*) FROM audit_tenant_events WHERE type = 'identity.delivery_fetched'
		AND payload LIKE '%"acknowledged_keys":["PATH","LD_PRELOAD"]%'`); n != 1 {
		t.Errorf("acknowledged_keys recorded verbatim = %d, want 1", n)
	}
	// An unacknowledged fetch records the empty list rather than omitting it.
	if _, err := del.FetchAs(t.Context(), service.LocalPrincipal(identAdmin), env, "", service.FetchOptions{}); err != nil {
		t.Fatal(err)
	}
	if n := queryInt(t, db, `SELECT COUNT(*) FROM audit_tenant_events WHERE type = 'identity.delivery_fetched'
		AND payload LIKE '%"acknowledged_keys":[]%'`); n != 1 {
		t.Errorf("empty acknowledged_keys recorded = %d, want 1", n)
	}

	// A caller-controlled list is BOUNDED and GRAMMAR-CHECKED at the service,
	// before any transaction opens: over the item bound, or an item outside the
	// key-name grammar, is a domain.ErrInvalid (400) refusal — never the audit
	// schema's fail-loud MaxLen/sanitize bound after work has already run. The
	// count of fetch records must not move across either refusal, which is what
	// proves "refused before any work" rather than "refused after recording".
	before := queryInt(t, db, `SELECT COUNT(*) FROM audit_tenant_events WHERE type = 'identity.delivery_fetched'`)
	tooMany := make([]string, delivery.MaxAcknowledgedKeys+1)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("KEY_%d", i)
	}
	if _, err := del.FetchAs(t.Context(), service.LocalPrincipal(identAdmin), env, "",
		service.FetchOptions{AcknowledgedKeys: tooMany}); !errors.Is(err, domain.ErrInvalid) {
		t.Errorf("acknowledged_keys over the bound = %v, want ErrInvalid", err)
	}
	if _, err := del.FetchAs(t.Context(), service.LocalPrincipal(identAdmin), env, "",
		service.FetchOptions{AcknowledgedKeys: []string{"PATH", "not-a-valid-name"}}); !errors.Is(err, domain.ErrInvalid) {
		t.Errorf("acknowledged_keys with a name outside the grammar = %v, want ErrInvalid", err)
	}
	if after := queryInt(t, db, `SELECT COUNT(*) FROM audit_tenant_events WHERE type = 'identity.delivery_fetched'`); after != before {
		t.Errorf("a refused acknowledgement wrote %d fetch records; a malformed list must be refused before any work", after-before)
	}
}

func TestDeliveryCredentialExpiryIsFiniteOrAbsentSQLite(t *testing.T) {
	runDeliveryCredentialExpiry(t, seededDB(t, openSQLite))
}

func TestDeliveryCredentialExpiryIsFiniteOrAbsentPostgres(t *testing.T) {
	runDeliveryCredentialExpiry(t, seededDB(t, openPostgres))
}

// runDeliveryCredentialExpiry pins the presenting credential's expiry surfacing:
// a finite bearer credential carries its expiry, an indefinite one carries the
// zero time.
func runDeliveryCredentialExpiry(t *testing.T, db *store.DB) {
	identityFixtures(t, db)
	seedDeliveryCatalogue(t, db)
	del := deliverySvc(t, db)
	ident := identitySvc(db)
	// The store keeps microseconds; pin the mint clock to a microsecond instant so
	// the in-memory ExpiresAt and the stored one compare EXACTLY on every OS.
	now := time.Now().UTC().Truncate(time.Microsecond)
	ident.Now = func() time.Time { return now }
	env := scopeEnv(orgA, prjA1, envA1)

	sa, err := ident.CreateServiceAccount(t.Context(), service.LocalPrincipal(identAdmin),
		prjScope(), "expiry-workload", domain.ClassWorkload)
	if err != nil {
		t.Fatal(err)
	}
	grantMachineRead(t, db, sa.Principal, envA1)

	// A finite credential carries its expiry.
	finite, err := ident.MintCredential(t.Context(), service.LocalPrincipal(identAdmin),
		prjScope(), sa.ID, service.MintRequest{})
	if err != nil {
		t.Fatal(err)
	}
	res, err := del.Fetch(t.Context(), finite.Value, env, "", service.FetchOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !res.CredentialExpiresAt.Equal(finite.Credential.ExpiresAt) {
		t.Errorf("finite credential_expires_at = %v, want %v", res.CredentialExpiresAt, finite.Credential.ExpiresAt)
	}

	// An indefinite credential (under the opt-in) carries none.
	policy, err := ident.Policy(t.Context(), service.LocalPrincipal(root))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ident.SetPolicy(t.Context(), service.LocalPrincipal(root), service.PolicyChange{
		MaxFiniteLifetime: policy.MaxFiniteLifetime, AllowIndefinite: true,
		MaxLiveCredentials: policy.MaxLiveCredentials,
	}); err != nil {
		t.Fatal(err)
	}
	forever, err := ident.MintCredential(t.Context(), service.LocalPrincipal(identAdmin),
		prjScope(), sa.ID, service.MintRequest{Indefinite: true})
	if err != nil {
		t.Fatal(err)
	}
	indef, err := del.Fetch(t.Context(), forever.Value, env, "", service.FetchOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !indef.CredentialExpiresAt.IsZero() {
		t.Errorf("indefinite credential_expires_at = %v, want the zero time", indef.CredentialExpiresAt)
	}
}

// deliveredByName indexes a delivered projection by key name.
func deliveredByName(keys []service.DeliveredKey) map[string]service.DeliveredKey {
	out := make(map[string]service.DeliveredKey, len(keys))
	for _, k := range keys {
		out[k.Name] = k
	}
	return out
}

func TestDeliveryPinnedNonCurrentRequiresRevealHistorySQLite(t *testing.T) {
	runDeliveryPinnedNonCurrent(t, seededDB(t, openSQLite))
}

func TestDeliveryPinnedNonCurrentRequiresRevealHistoryPostgres(t *testing.T) {
	runDeliveryPinnedNonCurrent(t, seededDB(t, openPostgres))
}

// runDeliveryPinnedNonCurrent pins the reveal-history branch of the value rule:
// a pinned delivery of a NON-CURRENT revision discloses history, so a secret
// value crosses only under `reveal-history`, and `reveal` alone leaves it
// presence-only. The disclosure record names the pinned revision, which also
// exercises the snapshot-revision-vs-schema-revision distinction.
func runDeliveryPinnedNonCurrent(t *testing.T, db *store.DB) {
	identityFixtures(t, db)
	seedDeliveryCatalogue(t, db) // env_a1 at revision 1, both keys
	del := deliverySvc(t, db)
	ident := identitySvc(db)
	env := scopeEnv(orgA, prjA1, envA1)

	// A second revision, so revision 1 is genuinely non-current.
	publishDeliveryValues(t, db, envA1, map[string]string{"DATABASE_URL": "postgres://dev-v2"})
	if latest := latestRevision(t, db, "env_a1"); latest < 2 {
		t.Fatalf("expected a second revision, latest = %d", latest)
	}

	// The pin authority (identAdmin) needs `pin` ∧ `publish` (OpPinSet) and
	// `reveal-history` (OpPinSetHistory) at env_a1 to pin to a non-current
	// revision; `publish` it already holds from the catalogue seed.
	execRaw(t, db, `INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) VALUES ('g_adm_pin','`+string(identAdmin)+`','pin','org_a','prj_a1','env_a1',`+ts+`)`)
	execRaw(t, db, `INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) VALUES ('g_adm_revh','`+string(identAdmin)+`','reveal-history','org_a','prj_a1','env_a1',`+ts+`)`)
	seedOrigins(t, db)

	sa, err := ident.CreateServiceAccount(t.Context(), service.LocalPrincipal(identAdmin),
		prjScope(), "pinned-workload", domain.ClassWorkload)
	if err != nil {
		t.Fatal(err)
	}
	minted, err := ident.MintCredential(t.Context(), service.LocalPrincipal(identAdmin),
		prjScope(), sa.ID, service.MintRequest{})
	if err != nil {
		t.Fatal(err)
	}
	grantMachineRead(t, db, sa.Principal, envA1)

	pins := &service.Pins{DB: db, Keyring: probeKeyring(t, db)}
	if _, err := pins.Set(t.Context(), service.LocalPrincipal(identAdmin), env,
		service.SetPinRequest{WorkloadPrincipalID: sa.Principal, Revision: 1}); err != nil {
		t.Fatalf("pin the workload to revision 1: %v", err)
	}

	// read only: config crosses, the secret is presence-only, pin is revision 1.
	res, err := del.Fetch(t.Context(), minted.Value, env, "", service.FetchOptions{})
	if err != nil {
		t.Fatalf("pinned fetch under read: %v", err)
	}
	if res.PinnedRevision != 1 {
		t.Fatalf("PinnedRevision = %d, want the pinned revision 1", res.PinnedRevision)
	}
	got := deliveredByName(res.Keys)
	if got["DATABASE_URL"].Value == nil {
		t.Error("the config value did not cross under read on a pinned delivery")
	}
	if got["DATABASE_PASSWORD"].Value != nil {
		t.Error("the secret crossed under read on a pinned non-current delivery")
	}

	// `reveal` is NOT sufficient for a pinned non-current revision.
	seedMachineReveal(t, db, "g_wl_reveal", sa.Principal, domain.CapReveal, envA1)
	res, err = del.Fetch(t.Context(), minted.Value, env, "", service.FetchOptions{})
	if err != nil {
		t.Fatalf("pinned fetch with reveal: %v", err)
	}
	if deliveredByName(res.Keys)["DATABASE_PASSWORD"].Value != nil {
		t.Error("`reveal` delivered a pinned non-current secret; it requires `reveal-history`")
	}

	// `reveal-history` delivers it, and the disclosure names the pinned revision.
	seedMachineReveal(t, db, "g_wl_revh", sa.Principal, domain.CapRevealHistory, envA1)
	res, err = del.Fetch(t.Context(), minted.Value, env, "", service.FetchOptions{})
	if err != nil {
		t.Fatalf("pinned fetch with reveal-history: %v", err)
	}
	pw := deliveredByName(res.Keys)["DATABASE_PASSWORD"]
	if pw.Value == nil || *pw.Value != "dev-secret" {
		t.Errorf("pinned secret with reveal-history = %v, want the revision-1 plaintext", pw.Value)
	}
	if n := queryInt(t, db, `SELECT COUNT(*) FROM audit_tenant_events WHERE type = 'identity.disclosure'
		AND payload LIKE '%"key":"DATABASE_PASSWORD"%' AND payload LIKE '%"revision":1%'`); n != 1 {
		t.Errorf("disclosure naming pinned revision 1 = %d, want 1", n)
	}
}

func TestDeliveryPinnedCurrentBecomingHistoricalInvalidatesCursorSQLite(t *testing.T) {
	runDeliveryPinnedCurrentBecomingHistorical(t, seededDB(t, openSQLite))
}

func TestDeliveryPinnedCurrentBecomingHistoricalInvalidatesCursorPostgres(t *testing.T) {
	runDeliveryPinnedCurrentBecomingHistorical(t, seededDB(t, openPostgres))
}

// runDeliveryPinnedCurrentBecomingHistorical is the #64 P1: a pin that WAS
// current, whose revision is then overtaken by a later publish, changes what the
// delivery discloses without moving any of the content/authority cursor
// components — so a content-only cursor answers "current" for a state that now
// discloses strictly less.
//
// The fixture is built so EVERY other component is held across the transition:
//   - the pinned snapshot (revision 1) is immutable, so the change token, which
//     is computed over its plaintext, does not move — asserted, not assumed;
//   - the workload's grants are seeded BEFORE the first fetch, so its authorized
//     delivery projection and authorization revision are identical on both sides;
//   - no pin is created, reassigned or released across the transition, so the pin
//     generation is identical; the mode is `full` throughout.
//
// The one thing that moves is the effective secret-value authority: pinned-current
// discloses under `reveal` (which the workload holds), pinned-non-current under
// `reveal-history` (which it does not), so the secret goes from delivered to
// presence-only. Only the pinned-historical-revision cursor component catches it;
// before the fix the stale cursor still matched and the fetch answered "current".
func runDeliveryPinnedCurrentBecomingHistorical(t *testing.T, db *store.DB) {
	identityFixtures(t, db)
	seedDeliveryCatalogue(t, db) // env_a1 at revision 1, both keys
	del := deliverySvc(t, db)
	ident := identitySvc(db)
	env := scopeEnv(orgA, prjA1, envA1)

	// The pin authority (identAdmin) needs `pin` ∧ `publish` (OpPinSet) to pin,
	// and — once the pin becomes non-current — `reveal-history` (OpPinSetHistory)
	// for the delivery's authority recheck to pass; `publish` it already holds
	// from the catalogue seed.
	execRaw(t, db, `INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) VALUES ('g_adm_pin','`+string(identAdmin)+`','pin','org_a','prj_a1','env_a1',`+ts+`)`)
	execRaw(t, db, `INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) VALUES ('g_adm_revh','`+string(identAdmin)+`','reveal-history','org_a','prj_a1','env_a1',`+ts+`)`)
	seedOrigins(t, db)

	sa, err := ident.CreateServiceAccount(t.Context(), service.LocalPrincipal(identAdmin),
		prjScope(), "transition-workload", domain.ClassWorkload)
	if err != nil {
		t.Fatal(err)
	}
	minted, err := ident.MintCredential(t.Context(), service.LocalPrincipal(identAdmin),
		prjScope(), sa.ID, service.MintRequest{})
	if err != nil {
		t.Fatal(err)
	}
	// The workload holds `read` and `reveal` — NOT `reveal-history` — and both
	// are seeded now, before any fetch, so its projection never moves across the
	// transition. A `reveal`-holder is exactly the caller that loses the secret
	// when the pin turns historical.
	grantMachineRead(t, db, sa.Principal, envA1)
	seedMachineReveal(t, db, "g_wl_reveal", sa.Principal, domain.CapReveal, envA1)

	// Pin the workload to revision 1 while it IS the environment's latest.
	pins := &service.Pins{DB: db, Keyring: probeKeyring(t, db)}
	if _, err := pins.Set(t.Context(), service.LocalPrincipal(identAdmin), env,
		service.SetPinRequest{WorkloadPrincipalID: sa.Principal, Revision: 1}); err != nil {
		t.Fatalf("pin the workload to the current revision 1: %v", err)
	}

	// Pinned-current: the secret crosses under `reveal`, and the cursor answers
	// current on a repeat.
	currentPin, err := del.Fetch(t.Context(), minted.Value, env, "", service.FetchOptions{})
	if err != nil {
		t.Fatalf("pinned-current fetch: %v", err)
	}
	if v := deliveredByName(currentPin.Keys)["DATABASE_PASSWORD"].Value; v == nil || *v != "dev-secret" {
		t.Fatalf("secret under reveal on a pinned-current delivery = %v, want the plaintext", v)
	}
	repeat, err := del.Fetch(t.Context(), minted.Value, env, currentPin.Cursor, service.FetchOptions{})
	if err != nil {
		t.Fatalf("pinned-current conditional fetch: %v", err)
	}
	if !repeat.Current {
		t.Fatal("the cursor a pinned-current fetch just returned was not current")
	}

	// A later publish makes revision 1 NON-CURRENT. The pinned snapshot is
	// untouched, so nothing the workload is served under revision 1 changed —
	// except the authority that governs its secret.
	publishDeliveryValues(t, db, envA1, map[string]string{"DATABASE_URL": "postgres://dev-v2"})
	if latest := latestRevision(t, db, "env_a1"); latest < 2 {
		t.Fatalf("expected a second revision, latest = %d", latest)
	}

	afterOvertake, err := del.Fetch(t.Context(), minted.Value, env, currentPin.Cursor, service.FetchOptions{})
	if err != nil {
		t.Fatalf("fetch after the pin turned historical: %v", err)
	}
	// The cursor the workload held is NO LONGER current: this is the P1.
	if afterOvertake.Current {
		t.Fatal("a pin becoming non-current left the cursor current: the historical transition is not bound in")
	}
	// It is a full delivery, and the secret is now presence-only — the effective
	// disclosure authority genuinely flipped, so the cursor is catching a real
	// change rather than a phantom.
	if len(afterOvertake.Keys) == 0 {
		t.Fatal("the post-transition fetch answered neither `current` nor a delivery")
	}
	if v := deliveredByName(afterOvertake.Keys)["DATABASE_PASSWORD"].Value; v != nil {
		t.Errorf("the secret still crossed under `reveal` on a pinned NON-CURRENT delivery: %q — it requires reveal-history", *v)
	}
	// The change token did NOT move: the pinned snapshot's content is immutable,
	// so this proves the cursor moved on the historical transition, not because
	// the fixture changed the delivered content.
	if afterOvertake.ChangeToken != currentPin.ChangeToken {
		t.Fatal("the change token moved across the transition: the fixture changed content, so it is not proving the HISTORICAL transition invalidates")
	}
}
