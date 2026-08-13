package conformance

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Dunky13/hikyo/internal/crypto"
	"github.com/Dunky13/hikyo/internal/domain"
	"github.com/Dunky13/hikyo/internal/schema"
	"github.com/Dunky13/hikyo/internal/service"
	"github.com/Dunky13/hikyo/internal/store"
)

// Revisions, drafts and publishing (#51) — the cross-engine acceptance corpus
// for mvp-boundary C4 and C2's publish clause.
//
// Every scenario runs through the service layer against a real datastore and a
// real keyring on BOTH engines, which is what the [E2E] class requires: no
// mocked server components, and the change token is keyed, so there is nothing
// to fake about it either.
//
//	C4  Revisions & publishing — "[E2E] concurrent publish serialization;
//	    selective publish with group closure; `rotate-token-key` changes the
//	    token without touching content, revision numbers, or pinned input
//	    revisions"                        (revision-model.md)
//	C2  Flat value model (publish clause) — "a value publish recomputes matrix
//	    signals for exactly the touched environments, a semantic schema publish
//	    for every environment; ... a `required_in` key left `absent` vetoes
//	    publish naming key and environment"          (flat-model.md)

func init() {
	corpus = append(corpus,
		scenario{"publish_is_serialized_per_project", scenarioPublishSerialization},
		scenario{"selective_publish_closes_over_key_groups", scenarioSelectivePublish},
		scenario{"rotate_token_key_moves_only_the_token", scenarioRotateTokenKey},
		scenario{"publish_recomputes_signals_for_touched_environments", scenarioPublishSignals},
		scenario{"required_in_absent_vetoes_publish", scenarioRequiredInVeto},
		scenario{"revision_ciphertext_is_owner_bound", scenarioRevisionCiphertextBinding},
		scenario{"advisory_projects_authorization_per_event", scenarioAdvisoryAuthorization},
		scenario{"historical_export_takes_reveal_history_not_reveal", scenarioHistoricalExportFormula},
	)
}

// scenarioHistoricalExportFormula pins the export half of the revision ADR's
// disclosure formula, stated separately because the capabilities imply nothing
// about each other: CURRENT material is `read AND reveal`; HISTORICAL material
// — any revision that is not the latest — is `read AND reveal-history`. The
// permission ADR makes the two independently strippable grants, so an export
// must demand exactly the one that governs the material it serves: a
// historian without current `reveal` exports old revisions and nothing else,
// and a revealer without `reveal-history` exports the present and nothing
// else.
func scenarioHistoricalExportFormula(t *testing.T, db *store.DB) {
	who, scope, values, envs, keys := valueFixture(t, db, "exporthist")
	actor := service.LocalPrincipal(who)
	dev := mustEnv(t, envs, actor, scope, "dev")
	mustKey(t, keys, actor, scope, "API_TOKEN", string(schema.Secret), schema.DefaultPresenceRules())
	publishValue(t, db, values, actor, dev, "API_TOKEN", "tok-rev-1")
	historicalRevision := latestRevisionOf(t, db, string(dev.Env))
	publishValue(t, db, values, actor, dev, "API_TOKEN", "tok-rev-2")

	revisions := revisionSvc(t, db)
	envScope := domain.Scope{Org: scope.Org}

	// The historian: `read` and `reveal-history`, NO current `reveal`.
	historian := service.LocalPrincipal(newPrincipal(t, db,
		"usr_export_historian_"+string(scope.Project), []grantSpec{
			{"read", envScope}, {"reveal-history", envScope},
		}))
	exported, served, err := revisions.Export(t.Context(), historian, dev, historicalRevision, true)
	if err != nil {
		t.Fatalf("read+reveal-history could not export a historical revision: %v", err)
	}
	if served != historicalRevision {
		t.Fatalf("served revision %d, want the historical %d", served, historicalRevision)
	}
	if len(exported) != 1 || exported[0].Value != "tok-rev-1" || !exported[0].Revealed {
		t.Fatalf("historical export under reveal-history = %+v, want tok-rev-1 revealed", exported)
	}
	// The same historian must NOT reveal the present: latest rides `reveal`.
	if _, _, err := revisions.Export(t.Context(), historian, dev, 0, true); err == nil {
		t.Fatal("reveal-history alone exported CURRENT material — the current half of the formula was not evaluated")
	}

	// The revealer: `read` and `reveal`, NO `reveal-history`.
	revealer := service.LocalPrincipal(newPrincipal(t, db,
		"usr_export_revealer_"+string(scope.Project), []grantSpec{
			{"read", envScope}, {"reveal", envScope},
		}))
	if _, _, err := revisions.Export(t.Context(), revealer, dev, historicalRevision, true); err == nil {
		t.Fatal("reveal alone exported HISTORICAL material — the historical half of the formula was not evaluated")
	}
	exported, served, err = revisions.Export(t.Context(), revealer, dev, 0, true)
	if err != nil {
		t.Fatalf("read+reveal could not export current material: %v", err)
	}
	if served != historicalRevision+1 || len(exported) != 1 || exported[0].Value != "tok-rev-2" {
		t.Fatalf("current export = rev %d %+v, want rev %d tok-rev-2", served, exported, historicalRevision+1)
	}
}

// scenarioPublishSerialization is C4's first clause.
//
// TWO PUBLISHES COMPUTED FROM THE SAME BASELINE both commit, and the second one
// must not silently revert the first. That is the failure the revision ADR
// names in full: "X publishing A=2 and Y publishing B=2 ... the later
// latest-pointer advance silently reverts the other's key, because per-entry
// freshness checks each pass and unique revision numbers alone do not linearize
// the outcome."
//
// The assertion is therefore about the OUTCOME, not about timing: after both
// publishes, BOTH keys deliver their new values, the revision numbers are
// distinct and consecutive, and the lineage records each change exactly once.
// A test that only asserted "no error" would pass against the broken
// implementation the ADR describes.
func scenarioPublishSerialization(t *testing.T, db *store.DB) {
	who, scope, values, envs, keys := valueFixture(t, db, "publishserial")
	actor := service.LocalPrincipal(who)
	dev := mustEnv(t, envs, actor, scope, "dev")
	mustKey(t, keys, actor, scope, "ALPHA", string(schema.Config), schema.DefaultPresenceRules())
	mustKey(t, keys, actor, scope, "BETA", string(schema.Config), schema.DefaultPresenceRules())
	publishValue(t, db, values, actor, dev, "ALPHA", "a1")
	publishValue(t, db, values, actor, dev, "BETA", "b1")

	baseline := latestRevisionOf(t, db, string(dev.Env))

	// Both drafts are staged against the SAME baseline before either publishes.
	// That is the precondition the ADR describes; staging them in sequence with
	// a publish in between would test nothing.
	alpha, err := values.Set(t.Context(), actor, dev, "ALPHA", "a2")
	if err != nil {
		t.Fatal(err)
	}
	beta, err := values.Set(t.Context(), actor, dev, "BETA", "b2")
	if err != nil {
		t.Fatal(err)
	}
	if alpha.StagedFromRevision != baseline || beta.StagedFromRevision != baseline {
		t.Fatalf("drafts were not staged from one baseline: %d, %d, want %d",
			alpha.StagedFromRevision, beta.StagedFromRevision, baseline)
	}

	revisions := revisionSvc(t, db)
	var wg sync.WaitGroup
	results := make([]error, 2)
	versionIDs := []string{alpha.VersionID, beta.VersionID}
	start := func(i int) {
		versionID := versionIDs[i]
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, results[i] = revisions.Publish(t.Context(), actor, dev, []string{versionID})
		}()
	}
	if db.Engine() == store.EnginePostgres {
		probe := newPublishOverlapProbe(alpha.VersionID, beta.VersionID)
		revisions.PublishProbe = probe
		start(0)
		<-probe.firstBaseline
		start(1)
		<-probe.secondBeforeLock
		select {
		case <-probe.secondBaseline:
			close(probe.release)
			wg.Wait()
			t.Fatal("second publish read the baseline while the first transaction was paused: project lock did not serialize them")
		case <-time.After(500 * time.Millisecond):
			close(probe.release)
		}
	} else {
		start(0)
		start(1)
	}
	wg.Wait()
	for i, err := range results {
		if err != nil {
			t.Fatalf("concurrent publish %d failed: %v", i, err)
		}
	}

	// NEITHER KEY WAS REVERTED. This is the whole criterion: the second
	// materialization computed its snapshot from the state the first committed,
	// not from the baseline they both started at.
	for key, want := range map[string]string{"ALPHA": "a2", "BETA": "b2"} {
		cell, err := values.Get(t.Context(), actor, dev, key, false)
		if err != nil {
			t.Fatal(err)
		}
		if !cell.Set || cell.Value != want {
			t.Fatalf("%s = %+v after two concurrent publishes, want %q — the later publish reverted the earlier one",
				key, cell, want)
		}
	}
	// Two distinct, consecutive revisions: the allocation is serialized, so
	// nothing collided and nothing was skipped.
	if got := latestRevisionOf(t, db, string(dev.Env)); got != baseline+2 {
		t.Fatalf("revision after two publishes = %d, want %d", got, baseline+2)
	}
	// …and the delivered snapshot at that revision carries both new values, so
	// the latest pointer and the payload agree.
	exported, servedRevision, err := revisions.Export(t.Context(), actor, dev, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	if servedRevision != baseline+2 {
		t.Fatalf("export served revision %d, want the latest %d", servedRevision, baseline+2)
	}
	delivered := map[string]string{}
	for _, value := range exported {
		delivered[value.Name] = value.Value
	}
	if delivered["ALPHA"] != "a2" || delivered["BETA"] != "b2" {
		t.Fatalf("the latest snapshot does not carry both publishes: %+v", delivered)
	}
}

// scenarioSelectivePublish is C4's second clause: selective publish with
// key-group closure.
//
// Three properties, each asserted separately because each fails on its own:
//
//  1. SELECTION ISOLATION — a publish carries the named versions and nothing
//     else. The publisher's own unselected draft stays pending and its cell
//     keeps delivering the published value.
//  2. CLOSURE — selecting a draft to any group member pulls the publisher's
//     drafts to the OTHER members of that group, in the same environment, into
//     the same publish. The rotated password and the matching user commit
//     together or not at all.
//  3. THE CROSS-USER REFUSAL — a group member whose pending change is owned by
//     ANOTHER principal aborts the publish, loud, naming the group and the key.
//     Never silently split, never a hand-off.
func scenarioSelectivePublish(t *testing.T, db *store.DB) {
	who, scope, values, envs, keys := valueFixture(t, db, "selective")
	actor := service.LocalPrincipal(who)
	dev := mustEnv(t, envs, actor, scope, "dev")
	groups := &service.KeyGroups{DB: db, Keyring: sharedKeyring(t, db)}
	group, err := groups.Create(t.Context(), actor, scope, "database")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"DB_USER", "DB_PASSWORD"} {
		key := mustKey(t, keys, actor, scope, name, string(schema.Config), schema.DefaultPresenceRules())
		if _, err := keys.SetGroup(t.Context(), actor, scope, key.ID, group.ID); err != nil {
			t.Fatal(err)
		}
	}
	mustKey(t, keys, actor, scope, "UNRELATED", string(schema.Config), schema.DefaultPresenceRules())
	// The two group members land in ONE publish. They must: all-or-none resolved
	// presence means an environment where one member is `set` and the other
	// `absent` is invalid, so a group cannot be populated one publish at a time.
	// That is the state half of the coupling, and it is already load-bearing
	// before the closure assertions below get to the timing half.
	seedUser, err := values.Set(t.Context(), actor, dev, "DB_USER", "app")
	if err != nil {
		t.Fatal(err)
	}
	seedPassword, err := values.Set(t.Context(), actor, dev, "DB_PASSWORD", "pw1")
	if err != nil {
		t.Fatal(err)
	}
	publishVersions(t, db, actor, dev, seedUser.VersionID, seedPassword.VersionID)
	publishValue(t, db, values, actor, dev, "UNRELATED", "keep")

	// Three drafts; the publish names ONE of them.
	user, err := values.Set(t.Context(), actor, dev, "DB_USER", "app2")
	if err != nil {
		t.Fatal(err)
	}
	password, err := values.Set(t.Context(), actor, dev, "DB_PASSWORD", "pw2")
	if err != nil {
		t.Fatal(err)
	}
	unrelated, err := values.Set(t.Context(), actor, dev, "UNRELATED", "changed")
	if err != nil {
		t.Fatal(err)
	}

	result := publishVersions(t, db, actor, dev, password.VersionID)

	// CLOSURE: the user's draft rode along, and the result says so — the caller
	// can tell what it asked for from what the coupling required.
	if len(result.Published) != 2 {
		t.Fatalf("publishing one group member committed %d versions, want 2 (closure): %+v", len(result.Published), result)
	}
	if len(result.ClosedIn) != 1 || result.ClosedIn[0] != user.VersionID {
		t.Fatalf("closure did not report pulling the sibling in: %+v", result.ClosedIn)
	}
	for name, want := range map[string]string{"DB_USER": "app2", "DB_PASSWORD": "pw2"} {
		cell, err := values.Get(t.Context(), actor, dev, name, false)
		if err != nil {
			t.Fatal(err)
		}
		if cell.Value != want {
			t.Fatalf("%s = %q after the closed publish, want %q — the group split", name, cell.Value, want)
		}
	}
	// SELECTION ISOLATION: the unrelated draft is untouched and still pending,
	// and its cell still delivers what it delivered before.
	if cell, err := values.Get(t.Context(), actor, dev, "UNRELATED", false); err != nil || cell.Value != "keep" {
		t.Fatalf("an unselected draft leaked into the publish: %+v, %v", cell, err)
	}
	signals, err := revisionSvc(t, db).Signals(t.Context(), actor, dev)
	if err != nil {
		t.Fatal(err)
	}
	if id := pendingVersionFor(signals, "UNRELATED"); id != unrelated.VersionID {
		t.Fatalf("the unselected draft is no longer pending: %q, want %q", id, unrelated.VersionID)
	}
	if id := pendingVersionFor(signals, "DB_USER"); id != "" {
		t.Fatalf("a published draft is still pending: %q", id)
	}

	// THE CROSS-USER REFUSAL. A second principal stages a change to the other
	// group member; the first principal's publish is refused by name rather
	// than splitting the group or reaching into somebody else's working state.
	other := newPrincipal(t, db, "usr_selective_other_"+string(scope.Project), []grantSpec{
		{"read", domain.Scope{Org: scope.Org}},
		{"edit", domain.Scope{Org: scope.Org}},
		{"publish", domain.Scope{Org: scope.Org}},
	})
	if _, err := values.Set(t.Context(), service.LocalPrincipal(other), dev, "DB_USER", "theirs"); err != nil {
		t.Fatal(err)
	}
	mine, err := values.Set(t.Context(), actor, dev, "DB_PASSWORD", "pw3")
	if err != nil {
		t.Fatal(err)
	}
	_, err = revisionSvc(t, db).Publish(t.Context(), actor, dev, []string{mine.VersionID})
	if !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("a group member held by another principal did not refuse the publish: %v", err)
	}
	if !strings.Contains(err.Error(), group.ID) || !strings.Contains(err.Error(), "DB_USER") {
		t.Fatalf("the refusal names neither the group nor the member: %v", err)
	}
	// It is a REFUSAL, not a split: nothing moved.
	if cell, err := values.Get(t.Context(), actor, dev, "DB_PASSWORD", false); err != nil || cell.Value != "pw2" {
		t.Fatalf("a refused publish committed anyway: %+v, %v", cell, err)
	}

	// SAME-CELL collision: remove the sibling marker used above, then let the
	// other principal stage the exact grouped cell Alice selected. Closure must
	// inspect the selected member too; skipping it is a cross-owner bypass.
	deletePendingCell(t, db, string(dev.Env), keyIDByName(t, keys, actor, scope, "DB_USER"), string(other))
	if _, err := values.Set(t.Context(), service.LocalPrincipal(other), dev, "DB_PASSWORD", "theirs-too"); err != nil {
		t.Fatal(err)
	}
	_, err = revisionSvc(t, db).Publish(t.Context(), actor, dev, []string{mine.VersionID})
	if !errors.Is(err, domain.ErrInvalid) || !strings.Contains(err.Error(), "DB_PASSWORD") {
		t.Fatalf("another owner on the selected grouped cell did not refuse by name: %v", err)
	}
}

type publishOverlapProbe struct {
	first, second    string
	firstBaseline    chan struct{}
	secondBeforeLock chan struct{}
	secondBaseline   chan struct{}
	release          chan struct{}
	firstOnce        sync.Once
	beforeOnce       sync.Once
	secondOnce       sync.Once
}

func newPublishOverlapProbe(first, second string) *publishOverlapProbe {
	return &publishOverlapProbe{
		first: first, second: second,
		firstBaseline: make(chan struct{}), secondBeforeLock: make(chan struct{}),
		secondBaseline: make(chan struct{}), release: make(chan struct{}),
	}
}

func (p *publishOverlapProbe) BeforeProjectLock(ids []string) {
	if len(ids) == 1 && ids[0] == p.second {
		p.beforeOnce.Do(func() { close(p.secondBeforeLock) })
	}
}

func (p *publishOverlapProbe) AfterBaselineRead(ids []string) {
	if len(ids) != 1 {
		return
	}
	switch ids[0] {
	case p.first:
		p.firstOnce.Do(func() { close(p.firstBaseline) })
		<-p.release
	case p.second:
		p.secondOnce.Do(func() { close(p.secondBaseline) })
		<-p.release
	}
}

func deletePendingCell(t *testing.T, db *store.DB, envID, keyID, ownerID string) {
	t.Helper()
	query := `DELETE FROM pending_changes WHERE environment_id = $1 AND owner_id = $2 AND key_id = $3`
	execConformance(t, db, query, envID, ownerID, keyID)
}

func scenarioRevisionCiphertextBinding(t *testing.T, db *store.DB) {
	who, scope, values, envs, keys := valueFixture(t, db, "revisionaad")
	actor := service.LocalPrincipal(who)
	dev := mustEnv(t, envs, actor, scope, "dev")
	prod := mustEnv(t, envs, actor, scope, "prod")
	mustKey(t, keys, actor, scope, "SOURCE", string(schema.Config), schema.DefaultPresenceRules())
	mustKey(t, keys, actor, scope, "TARGET", string(schema.Config), schema.DefaultPresenceRules())

	draft, err := values.Set(t.Context(), actor, dev, "SOURCE", "draft-material")
	if err != nil {
		t.Fatal(err)
	}
	execConformance(t, db, `UPDATE pending_changes SET environment_id = $1,
		key_id = (SELECT id FROM keys WHERE name = $2) WHERE id = $3`,
		string(prod.Env), "TARGET", draft.VersionID)
	_, err = revisionSvc(t, db).Publish(t.Context(), actor, prod, []string{draft.VersionID})
	if !errors.Is(err, crypto.ErrDecrypt) {
		t.Fatalf("relocated pending ciphertext opened under changed environment/key metadata: %v", err)
	}

	publishValue(t, db, values, actor, dev, "SOURCE", "snapshot-material")
	execConformance(t, db, `UPDATE snapshot_entries SET environment_id = $1,
		snapshot_id = (SELECT id FROM snapshots WHERE environment_id = $1 ORDER BY revision DESC LIMIT 1)
		WHERE id = (SELECT se.id FROM snapshot_entries se JOIN snapshots s ON s.id = se.snapshot_id
			WHERE se.environment_id = $2 AND se.key_name = $3 ORDER BY s.revision DESC LIMIT 1)`,
		string(prod.Env), string(dev.Env), "SOURCE")
	if _, _, err := revisionSvc(t, db).Export(t.Context(), actor, prod, 0, false); !errors.Is(err, crypto.ErrDecrypt) {
		t.Fatalf("relocated snapshot ciphertext opened under changed environment/snapshot metadata: %v", err)
	}
}

func scenarioAdvisoryAuthorization(t *testing.T, db *store.DB) {
	who, scope, values, envs, keys := valueFixture(t, db, "advisoryauthz")
	actor := service.LocalPrincipal(who)
	dev := mustEnv(t, envs, actor, scope, "dev")
	prod := mustEnv(t, envs, actor, scope, "prod")
	mustKey(t, keys, actor, scope, "NOTICE", string(schema.Config), schema.DefaultPresenceRules())

	advisory := service.NewAdvisory()
	values.Advisory = advisory
	revisions := &service.Revisions{DB: db, Keyring: sharedKeyring(t, db), Advisory: advisory}
	reader := newPrincipal(t, db, "usr_advisory_reader_"+string(scope.Project), []grantSpec{
		{"read", domain.Scope{Org: scope.Org, Project: scope.Project}},
	})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	events, err := revisions.Watch(ctx, service.LocalPrincipal(reader), scope)
	if err != nil {
		t.Fatal(err)
	}
	// Scope the live grant down AFTER connect. Per-event authorization must see
	// current state: prod references disappear; dev references still arrive.
	execConformance(t, db, `DELETE FROM grants WHERE principal_id = $1`, string(reader))
	execConformance(t, db, `INSERT INTO grants
		(id, principal_id, capability, org_id, project_id, env_id, created_at)
		VALUES ($1, $2, 'read', $3, $4, $5, '2026-01-01T00:00:00Z')`,
		"grt_advisory_scoped_"+string(scope.Project), string(reader), string(scope.Org), string(scope.Project), string(dev.Env))

	prodDraft, err := values.Set(t.Context(), actor, prod, "NOTICE", "hidden")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := revisions.Publish(t.Context(), actor, prod, []string{prodDraft.VersionID}); err != nil {
		t.Fatal(err)
	}
	devDraft, err := values.Set(t.Context(), actor, dev, "NOTICE", "visible")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := revisions.Publish(t.Context(), actor, dev, []string{devDraft.VersionID}); err != nil {
		t.Fatal(err)
	}

	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	for {
		select {
		case ev, ok := <-events:
			if !ok {
				t.Fatal("advisory stream closed before authorized event arrived")
			}
			if ev.EnvironmentID == string(prod.Env) {
				t.Fatalf("subscriber without prod read received prod event: %+v", ev)
			}
			if ev.EnvironmentID == string(dev.Env) && ev.Type == service.AdvisoryPublished {
				return
			}
		case <-deadline.C:
			t.Fatal("authorized dev advisory did not arrive")
		}
	}
}

func execConformance(t *testing.T, db *store.DB, query string, args ...any) {
	t.Helper()
	var err error
	if db.Engine() == store.EnginePostgres {
		_, err = db.PG().Exec(t.Context(), query, args...)
	} else {
		var sqliteQuery strings.Builder
		sqliteArgs := make([]any, 0, len(args))
		for i := 0; i < len(query); {
			if query[i] != '$' {
				sqliteQuery.WriteByte(query[i])
				i++
				continue
			}
			j := i + 1
			for j < len(query) && query[j] >= '0' && query[j] <= '9' {
				j++
			}
			position, convErr := strconv.Atoi(query[i+1 : j])
			if convErr != nil || position < 1 || position > len(args) {
				t.Fatalf("invalid SQL placeholder near %q", query[i:])
			}
			sqliteQuery.WriteByte('?')
			sqliteArgs = append(sqliteArgs, args[position-1])
			i = j
		}
		_, err = db.SQLiteWrite().ExecContext(t.Context(), sqliteQuery.String(), sqliteArgs...)
	}
	if err != nil {
		t.Fatal(err)
	}
}

// scenarioRotateTokenKey is C4's third clause, and the encryption ADR's CI
// invariant 15: `rotate-token-key` changes the token WITHOUT touching content,
// revision numbers, or pinned input revisions.
//
// The four negatives are what make it a real assertion. A rotation that
// re-materialized every snapshot would also "change the token" — and would
// break every pin, every history reference and every stored verdict. So the
// test pins all four facts before rotating and requires them byte-identical
// after.
func scenarioRotateTokenKey(t *testing.T, db *store.DB) {
	who, scope, values, envs, keys := valueFixture(t, db, "tokenrotate")
	actor := service.LocalPrincipal(who)
	dev := mustEnv(t, envs, actor, scope, "dev")
	mustKey(t, keys, actor, scope, "ROTATE_ME", string(schema.Config), schema.DefaultPresenceRules())
	publishValue(t, db, values, actor, dev, "ROTATE_ME", "content")

	revisions := revisionSvc(t, db)
	before, err := revisions.Show(t.Context(), actor, dev, 0)
	if err != nil {
		t.Fatal(err)
	}
	pinnedEntriesBefore := pinnedValueEntries(t, db, string(dev.Env), before.Revision)
	if len(pinnedEntriesBefore) == 0 {
		t.Fatal("fixture broken: the snapshot pinned no value entries")
	}

	// The operator capability is `rotate-dek`: the permission ADR's capability
	// set is closed and names four rotation atoms for five rotation verbs, and
	// the root token key is a tier-3 key alongside the DEKs.
	operator := newPrincipal(t, db, "usr_rotate_"+string(scope.Project), []grantSpec{
		{"rotate-dek", domain.Scope{}},
	})
	rotation, err := revisions.RotateTokenKey(t.Context(), service.LocalPrincipal(operator))
	if err != nil {
		t.Fatal(err)
	}
	if rotation.Version < 2 {
		t.Fatalf("rotation reported version %d, want a successor to the boot key", rotation.Version)
	}

	after, err := revisions.Show(t.Context(), actor, dev, 0)
	if err != nil {
		t.Fatal(err)
	}
	// 1. THE TOKEN MOVED.
	if after.ChangeToken == before.ChangeToken {
		t.Fatal("rotate-token-key left the change token unchanged")
	}
	// …and still carries the SCHEME version prefix, which is the public machine
	// contract. The KEY version is deliberately not in it: a consumer able to
	// tell key versions apart could tell a rotation from a content change.
	if !strings.HasPrefix(after.ChangeToken, "v1:") {
		t.Fatalf("rotated token lost its scheme prefix: %q", after.ChangeToken)
	}
	// 2. THE REVISION NUMBER DID NOT MOVE.
	if after.Revision != before.Revision {
		t.Fatalf("rotate-token-key moved the revision %d -> %d", before.Revision, after.Revision)
	}
	// 3. THE PINNED INPUT REVISIONS DID NOT MOVE — neither the schema revision
	//    on the snapshot nor the per-entry value-entry ids it pinned.
	if after.SchemaRevision != before.SchemaRevision {
		t.Fatalf("rotate-token-key moved the pinned schema revision %d -> %d",
			before.SchemaRevision, after.SchemaRevision)
	}
	pinnedEntriesAfter := pinnedValueEntries(t, db, string(dev.Env), after.Revision)
	if len(pinnedEntriesAfter) != len(pinnedEntriesBefore) {
		t.Fatalf("rotate-token-key changed the pinned entry set: %v -> %v", pinnedEntriesBefore, pinnedEntriesAfter)
	}
	for i := range pinnedEntriesBefore {
		if pinnedEntriesBefore[i] != pinnedEntriesAfter[i] {
			t.Fatalf("rotate-token-key moved a pinned value-entry revision: %q -> %q",
				pinnedEntriesBefore[i], pinnedEntriesAfter[i])
		}
	}
	// 4. THE CONTENT DID NOT MOVE.
	cell, err := values.Get(t.Context(), actor, dev, "ROTATE_ME", false)
	if err != nil {
		t.Fatal(err)
	}
	if !cell.Set || cell.Value != "content" {
		t.Fatalf("rotate-token-key disturbed the delivered content: %+v", cell)
	}
	// The new token is STABLE: a second read derives the same value, so the
	// rotation is a swap rather than a source of churn.
	again, err := revisions.Show(t.Context(), actor, dev, 0)
	if err != nil {
		t.Fatal(err)
	}
	if again.ChangeToken != after.ChangeToken {
		t.Fatalf("the token is not stable after rotation: %q then %q", after.ChangeToken, again.ChangeToken)
	}

	// CONCURRENT ROTATIONS AGREE WITH THE DATASTORE. Two rotations race; the
	// store's retire is a compare-and-swap on the predecessor version and the
	// in-memory adopt is version-monotonic, so whatever interleaving happens,
	// each attempt either succeeds or refuses with a CONFLICT (never a server
	// fault), and the token the process derives afterwards is the token a
	// restart would derive -- i.e. the live handle matches the committed key.
	rotator := service.LocalPrincipal(operator)
	var wg sync.WaitGroup
	raceErrs := make([]error, 2)
	for i := range raceErrs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, raceErrs[i] = revisions.RotateTokenKey(t.Context(), rotator)
		}()
	}
	wg.Wait()
	succeeded := 0
	for i, raceErr := range raceErrs {
		switch {
		case raceErr == nil:
			succeeded++
		case errors.Is(raceErr, domain.ErrConflict):
			// The loser of the compare-and-swap, refusing loudly.
		default:
			t.Fatalf("concurrent rotation %d failed with a non-conflict error: %v", i, raceErr)
		}
	}
	if succeeded == 0 {
		t.Fatal("both concurrent rotations refused: the compare-and-swap has no winner")
	}
	// The derived token is stable across reads AND consistent with the
	// committed key: deriving twice through the live handle must agree, and a
	// mismatch between memory and datastore would surface here as churn.
	first, err := revisions.Show(t.Context(), actor, dev, 0)
	if err != nil {
		t.Fatal(err)
	}
	second, err := revisions.Show(t.Context(), actor, dev, 0)
	if err != nil {
		t.Fatal(err)
	}
	if first.ChangeToken != second.ChangeToken {
		t.Fatalf("token unstable after concurrent rotations: %q then %q", first.ChangeToken, second.ChangeToken)
	}
	if first.ChangeToken == after.ChangeToken {
		t.Fatal("a successful concurrent rotation left the token unchanged")
	}
}

// scenarioPublishSignals is C2's publish clause, first half: "a value publish
// recomputes matrix signals for exactly the touched environments, a semantic
// schema publish for every environment".
//
// EXACTLY is the word under test. A value publish into `dev` must leave
// `prod`'s revision and `prod`'s changed-key signal alone; a semantic schema
// change must move BOTH.
func scenarioPublishSignals(t *testing.T, db *store.DB) {
	who, scope, values, envs, keys := valueFixture(t, db, "signals")
	actor := service.LocalPrincipal(who)
	dev := mustEnv(t, envs, actor, scope, "dev")
	prod := mustEnv(t, envs, actor, scope, "prod")
	key := mustKey(t, keys, actor, scope, "SIGNAL", string(schema.Config), schema.DefaultPresenceRules())
	publishValue(t, db, values, actor, dev, "SIGNAL", "dev-1")
	publishValue(t, db, values, actor, prod, "SIGNAL", "prod-1")

	revisions := revisionSvc(t, db)
	devBefore := latestRevisionOf(t, db, string(dev.Env))
	prodBefore := latestRevisionOf(t, db, string(prod.Env))
	prodSignalsBefore, err := revisions.Signals(t.Context(), actor, prod)
	if err != nil {
		t.Fatal(err)
	}
	prodChangedBefore := changedIn(prodSignalsBefore, "SIGNAL")

	// A VALUE PUBLISH touches exactly one environment.
	publishValue(t, db, values, actor, dev, "SIGNAL", "dev-2")

	if got := latestRevisionOf(t, db, string(dev.Env)); got != devBefore+1 {
		t.Fatalf("the touched environment advanced %d -> %d, want one revision", devBefore, got)
	}
	if got := latestRevisionOf(t, db, string(prod.Env)); got != prodBefore {
		t.Fatalf("an UNTOUCHED environment advanced %d -> %d: a value publish must not fan out",
			prodBefore, got)
	}
	devSignals, err := revisions.Signals(t.Context(), actor, dev)
	if err != nil {
		t.Fatal(err)
	}
	if changedIn(devSignals, "SIGNAL") != devBefore+1 {
		t.Fatalf("the touched cell carries no `recently changed` signal at the new revision: %+v", devSignals)
	}
	prodSignals, err := revisions.Signals(t.Context(), actor, prod)
	if err != nil {
		t.Fatal(err)
	}
	// prod's signal is UNCHANGED — still pointing at prod's own last revision,
	// not recomputed against dev's. "Recomputes for exactly the touched
	// environments" is a statement about which signals move, so the assertion
	// compares before and after rather than expecting an untouched environment
	// to carry no signal at all: prod legitimately changed in prod's own
	// revision, and that fact must survive dev publishing.
	if got := changedIn(prodSignals, "SIGNAL"); got != prodChangedBefore {
		t.Fatalf("an untouched environment's signal moved %d -> %d when another environment published",
			prodChangedBefore, got)
	}

	// A SEMANTIC SCHEMA PUBLISH does not narrow: every environment in the
	// project materializes a new snapshot at the new schema revision, even
	// where no value and no verdict changes, because its PINNED SCHEMA REVISION
	// changed and that is a pinned input.
	devBefore = latestRevisionOf(t, db, string(dev.Env))
	prodBefore = latestRevisionOf(t, db, string(prod.Env))
	if _, err := keys.Rename(t.Context(), actor, scope, key.ID, "SIGNAL_RENAMED"); err != nil {
		t.Fatal(err)
	}
	if got := latestRevisionOf(t, db, string(dev.Env)); got != devBefore+1 {
		t.Fatalf("a semantic schema publish missed dev: %d -> %d", devBefore, got)
	}
	if got := latestRevisionOf(t, db, string(prod.Env)); got != prodBefore+1 {
		t.Fatalf("a semantic schema publish did not fan out to prod: %d -> %d", prodBefore, got)
	}
	// The rename moved the delivered key set, so BOTH environments record it in
	// lineage — the fan-out materialized real snapshots, not empty ones.
	for _, env := range []domain.Scope{dev, prod} {
		detail, err := revisions.Show(t.Context(), actor, env, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(detail.Keys) != 1 || detail.Keys[0].Name != "SIGNAL_RENAMED" {
			t.Fatalf("%s's new snapshot does not carry the renamed key: %+v", env.Env, detail.Keys)
		}
	}
}

// scenarioRequiredInVeto is C2's publish clause, second half, verbatim: "a
// `required_in` key left `absent` vetoes publish naming key and environment".
//
// It also pins the half that makes the veto legitimate: SAVING IS FREE. The
// draft that would strand the key stages without complaint — a draft is the
// user's scratchpad, and blocking the save pushes work in progress into
// external notepads, which for secrets is exactly where it must not go.
func scenarioRequiredInVeto(t *testing.T, db *store.DB) {
	who, scope, values, envs, keys := valueFixture(t, db, "requiredveto")
	actor := service.LocalPrincipal(who)
	dev := mustEnv(t, envs, actor, scope, "dev")
	key := mustKey(t, keys, actor, scope, "MUST_EXIST", string(schema.Config), schema.DefaultPresenceRules())
	publishValue(t, db, values, actor, dev, "MUST_EXIST", "present")
	if _, err := keys.UpdateDeclaration(t.Context(), actor, scope, key.ID, service.KeyDeclarationUpdate{
		Declaration: decl(schema.Rule{Type: schema.TypeString}),
		Presence: schema.PresenceRules{
			Required:  schema.Presence{Mode: schema.PresenceExplicit, Environments: []string{string(dev.Env)}},
			Forbidden: schema.Presence{Mode: schema.PresenceNone},
		},
	}); err != nil {
		t.Fatal(err)
	}

	// SAVING IS FREE: the clear stages, and the environment keeps delivering.
	staged, err := values.Unset(t.Context(), actor, dev, "MUST_EXIST")
	if err != nil {
		t.Fatalf("staging a clear of a required key was refused; saving is free: %v", err)
	}
	if cell, err := values.Get(t.Context(), actor, dev, "MUST_EXIST", false); err != nil || !cell.Set {
		t.Fatalf("a staged clear stopped delivery before publish: %+v, %v", cell, err)
	}

	// PUBLISH IS THE AUTHORITY, and the veto names both.
	revisionBefore := latestRevisionOf(t, db, string(dev.Env))
	_, err = revisionSvc(t, db).Publish(t.Context(), actor, dev, []string{staged.VersionID})
	if !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("publishing a clear of a `required_in` key was accepted: %v", err)
	}
	if !strings.Contains(err.Error(), "MUST_EXIST") {
		t.Fatalf("the veto does not name the key: %v", err)
	}
	if !strings.Contains(err.Error(), string(dev.Env)) {
		t.Fatalf("the veto does not name the environment: %v", err)
	}
	// The refusal carries both to the wire as a caller-safe detail. Key names
	// are schema and environment ids are the caller's own request, so naming
	// them discloses nothing.
	var sd interface{ SafeDetail() string }
	if !errors.As(err, &sd) || !strings.Contains(sd.SafeDetail(), "MUST_EXIST") {
		t.Fatalf("the veto does not expose the key as a safe detail: %v", err)
	}
	// A REAL veto: nothing was published, and the draft is still pending, so
	// the operator can fix it rather than restage from scratch.
	if got := latestRevisionOf(t, db, string(dev.Env)); got != revisionBefore {
		t.Fatalf("a vetoed publish still advanced the revision %d -> %d", revisionBefore, got)
	}
	if cell, err := values.Get(t.Context(), actor, dev, "MUST_EXIST", false); err != nil || cell.Value != "present" {
		t.Fatalf("a vetoed publish disturbed the delivered value: %+v, %v", cell, err)
	}
	signals, err := revisionSvc(t, db).Signals(t.Context(), actor, dev)
	if err != nil {
		t.Fatal(err)
	}
	if pendingVersionFor(signals, "MUST_EXIST") != staged.VersionID {
		t.Fatalf("a vetoed publish discarded the draft: %+v", signals)
	}
}

// latestRevisionOf reads one environment's newest published revision straight
// from the datastore. The assertions above are about what the pipeline
// RECORDED, so reading it back through the pipeline's own API would only prove
// the API agrees with itself.
func latestRevisionOf(t *testing.T, db *store.DB, envID string) int64 {
	t.Helper()
	q := `SELECT COALESCE(MAX(revision), 0) FROM snapshots WHERE environment_id = $1`
	var out int64
	var err error
	if db.Engine() == store.EnginePostgres {
		err = db.PG().QueryRow(t.Context(), q, envID).Scan(&out)
	} else {
		err = db.SQLiteRead().QueryRowContext(t.Context(),
			strings.NewReplacer("$1", "?").Replace(q), envID).Scan(&out)
	}
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// pinnedValueEntries reads the value-entry revisions one snapshot pinned,
// ordered by key. This is the "pinned input revisions" half of C4's
// rotate-token-key criterion, and it is read from the rows rather than from a
// service so a rotation that quietly re-materialized could not hide behind an
// API that recomputes.
func pinnedValueEntries(t *testing.T, db *store.DB, envID string, revision int64) []string {
	t.Helper()
	query := `SELECT value_entry_id FROM snapshot_entries
	          WHERE environment_id = $1 AND snapshot_id = (
	              SELECT id FROM snapshots WHERE environment_id = $1 AND revision = $2)
	          ORDER BY key_name`
	var out []string
	if db.Engine() == store.EnginePostgres {
		rows, err := db.PG().Query(t.Context(), query, envID, revision)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				t.Fatal(err)
			}
			out = append(out, id)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}
	// sqlite has no repeated positional parameters, so the environment is bound
	// twice rather than rewritten into a join the predicate analyzer would
	// reject in production SQL.
	rows, err := db.SQLiteRead().QueryContext(t.Context(),
		strings.NewReplacer("$1", "?", "$2", "?").Replace(
			`SELECT value_entry_id FROM snapshot_entries
			 WHERE environment_id = $1 AND snapshot_id = (
			     SELECT id FROM snapshots WHERE environment_id = $1 AND revision = $2)
			 ORDER BY key_name`), envID, envID, revision)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		out = append(out, id)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func pendingVersionFor(signals service.EnvironmentSignals, name string) string {
	for _, cell := range signals.Cells {
		if cell.Name == name {
			return cell.PendingVersionID
		}
	}
	return ""
}

func changedIn(signals service.EnvironmentSignals, name string) int64 {
	for _, cell := range signals.Cells {
		if cell.Name == name {
			return cell.ChangedInRevision
		}
	}
	return 0
}
