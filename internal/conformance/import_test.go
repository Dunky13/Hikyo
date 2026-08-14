package conformance

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/importer"
	"github.com/Hikyo-Org/hikyo/internal/schema"
	"github.com/Hikyo-Org/hikyo/internal/service"
	"github.com/Hikyo-Org/hikyo/internal/store"
)

// The import path's cross-engine acceptance scenarios (#68, M5's file portion).
// Every one runs through the service layer, so tx, authorize(), the envelope
// and both engines' SQL are under test — and every one of them exercises the
// occurrence token, which is the whole binding between the two phases.

func init() {
	corpus = append(corpus,
		scenario{"import_phase1_presence_and_occurrence_tokens", scenarioImportPresence},
		scenario{"import_phase2_is_strict_and_skips_by_default", scenarioImportStrict},
		scenario{"import_phase2_rejects_moved_state_by_occurrence_token", scenarioImportMovedState},
		scenario{"import_e2e_per_source_fixtures", scenarioImportPerSourceE2E},
		scenario{"import_precondition_is_not_an_oracle", scenarioImportPreconditionOracle},
		scenario{"import_undeclared_transition_binds_declaration", scenarioImportUndeclaredTransition},
	)
}

// scenarioImportPresence: phase 1 reads declared keys, two-state presence and a
// server-minted token per (key, environment) — and the token MOVES when the
// value does, which is the property a bucket label cannot provide.
func scenarioImportPresence(t *testing.T, db *store.DB) {
	who, scope, values, envs, keys := valueFixture(t, db, "importpresence")
	actor := service.LocalPrincipal(who)
	prod := mustEnv(t, envs, actor, scope, "prod")
	mustKey(t, keys, actor, scope, "DB_URL", string(schema.Secret), schema.DefaultPresenceRules())
	mustKey(t, keys, actor, scope, "LOG_LEVEL", string(schema.Config), schema.DefaultPresenceRules())
	if _, err := keys.Create(t.Context(), actor, scope, service.KeySpec{
		Name: "PORT_OR_NAME", Classification: string(schema.Config),
		Declaration: schema.Declaration{AnyOf: []schema.Rule{
			{Type: schema.TypeInteger}, {Type: schema.TypeString},
		}},
		Presence: schema.DefaultPresenceRules(),
	}); err != nil {
		t.Fatal(err)
	}

	envOnly := newPrincipal(t, db, "usr_import_env_only_"+string(scope.Project), []grantSpec{{"read", prod}})
	denied, err := values.Occurrences(t.Context(), service.LocalPrincipal(envOnly), prod, nil)
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("an environment-only reader reached import presence: %v", err)
	}
	if len(denied.Keys) != 0 || denied.DefinitionsRevision != 0 {
		t.Fatalf("a refused presence read produced rows or revision data: %+v", denied)
	}

	first, err := values.Occurrences(t.Context(), actor, prod, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Keys) != 3 {
		t.Fatalf("occurrences returned %d keys, want the three declared", len(first.Keys))
	}
	tokens := map[string]string{}
	for _, k := range first.Keys {
		if k.Set {
			t.Errorf("%s reported `set` before anything was written", k.Name)
		}
		if k.Token == "" {
			t.Errorf("%s carries no occurrence token", k.Name)
		}
		if k.Name == "PORT_OR_NAME" && k.Type != "any_of(integer|string)" {
			t.Errorf("any_of declared type = %q, want the key catalogue expression", k.Type)
		}
		tokens[k.Name] = k.Token
	}
	if tokens["DB_URL"] == tokens["LOG_LEVEL"] {
		t.Error("two absent keys minted the same token; the token must name the KEY as well as the state")
	}

	// A write advances the occurrence: absent -> set.
	publishValue(t, db, values, actor, prod, "DB_URL", "postgres://one")
	second, err := values.Occurrences(t.Context(), actor, prod, nil)
	if err != nil {
		t.Fatal(err)
	}
	after := map[string]string{}
	for _, k := range second.Keys {
		after[k.Name] = k.Token
		if k.Name == "DB_URL" && !k.Set {
			t.Error("DB_URL reported absent after a write")
		}
	}
	if after["DB_URL"] == tokens["DB_URL"] {
		t.Error("the token did not move when the key went from absent to set")
	}
	if after["LOG_LEVEL"] != tokens["LOG_LEVEL"] {
		t.Error("an untouched key's token moved")
	}

	// THE case a bucket label cannot catch: `set` -> `set` with a CHANGED
	// value. The bucket is identical; the occurrence is not.
	publishValue(t, db, values, actor, prod, "DB_URL", "postgres://two")
	third, err := values.Occurrences(t.Context(), actor, prod, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range third.Keys {
		if k.Name == "DB_URL" && k.Token == after["DB_URL"] {
			t.Error("`set` -> `set` with a changed value left the token unchanged — the precondition would be blind to it")
		}
	}
}

// scenarioImportStrict: undeclared keys reject the run BY NAME, and a key
// already `set` is skipped by default and listed by name unless an enumerated
// overwrite names it.
func scenarioImportStrict(t *testing.T, db *store.DB) {
	who, scope, values, envs, keys := valueFixture(t, db, "importstrict")
	actor := service.LocalPrincipal(who)
	prod := mustEnv(t, envs, actor, scope, "prod")
	// `config` deliberately: this scenario asserts WHICH VALUE ended up in the
	// cell, and a `secret` cell reports write-presence only without the reveal
	// ceremony. Whether import defaults to `secret` is a different scenario's
	// question (scenarioImportPerSourceE2E), asked where it belongs.
	mustKey(t, keys, actor, scope, "DB_URL", string(schema.Config), schema.DefaultPresenceRules())
	mustKey(t, keys, actor, scope, "API_KEY", string(schema.Config), schema.DefaultPresenceRules())

	// Import carries the same per-value budget as every other plaintext write,
	// enforced in the service before schema validation or sealing.
	_, err := values.Import(t.Context(), actor, prod, service.ImportRequest{
		Entries: []service.ImportEntry{{Key: "DB_URL", Value: strings.Repeat("x", schema.MaxValueBytes+1)}},
	})
	if err == nil || !errors.Is(err, domain.ErrInvalid) || !strings.Contains(err.Error(), "65536-byte") {
		t.Fatalf("an oversized import value was not refused at the service boundary: %v", err)
	}

	// Closed schema: not conceded on the import path.
	_, err = values.Import(t.Context(), actor, prod, service.ImportRequest{
		Entries: []service.ImportEntry{{Key: "DB_URL", Value: "x"}, {Key: "DATBASE_URL", Value: "y"}},
	})
	if err == nil || !errors.Is(err, domain.ErrInvalid) || !strings.Contains(err.Error(), "DATBASE_URL") {
		t.Fatalf("an undeclared key was not rejected by name: %v", err)
	}
	cell, err := values.Get(t.Context(), actor, prod, "DB_URL", false)
	if err != nil {
		t.Fatal(err)
	}
	if cell.Set {
		t.Fatal("a rejected import left a value behind — the run is one transaction")
	}

	result, err := values.Import(t.Context(), actor, prod, service.ImportRequest{
		Entries: []service.ImportEntry{{Key: "DB_URL", Value: "one"}, {Key: "API_KEY", Value: "k1"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(result.Imported, ",") != "API_KEY,DB_URL" {
		t.Fatalf("imported = %v", result.Imported)
	}
	// Import is an immediate publish-authorized write. Its values must be in the
	// committed snapshot that delivery reads, not only in value_entries.
	exported, _, err := revisionSvc(t, db).Export(t.Context(), actor, prod, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	var snapshotted bool
	for _, value := range exported {
		if value.Name == "DB_URL" && value.Value == "one" && value.Revealed {
			snapshotted = true
		}
	}
	if !snapshotted {
		t.Fatalf("imported DB_URL was absent from committed snapshot: %+v", exported)
	}

	// Skip-by-default makes a re-run idempotent, and names what it skipped.
	again, err := values.Import(t.Context(), actor, prod, service.ImportRequest{
		Entries: []service.ImportEntry{{Key: "DB_URL", Value: "two"}, {Key: "API_KEY", Value: "k2"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(again.Imported) != 0 || strings.Join(again.Skipped, ",") != "API_KEY,DB_URL" {
		t.Fatalf("a re-run was not idempotent: imported=%v skipped=%v", again.Imported, again.Skipped)
	}
	cell, err = values.Get(t.Context(), actor, prod, "DB_URL", false)
	if err != nil || cell.Value != "one" {
		t.Fatalf("a skipped key was overwritten anyway: %+v %v", cell, err)
	}

	// Overwrite is opt-in and ENUMERATED: it moves exactly the key it names.
	over, err := values.Import(t.Context(), actor, prod, service.ImportRequest{
		Entries:   []service.ImportEntry{{Key: "DB_URL", Value: "three"}, {Key: "API_KEY", Value: "k3"}},
		Overwrite: []string{"DB_URL"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(over.Imported, ",") != "DB_URL" || strings.Join(over.Skipped, ",") != "API_KEY" {
		t.Fatalf("enumerated overwrite = imported %v skipped %v", over.Imported, over.Skipped)
	}
	cell, _ = values.Get(t.Context(), actor, prod, "API_KEY", false)
	if cell.Value != "k1" {
		t.Fatalf("an unnamed key was overwritten by an enumerated --overwrite: %q", cell.Value)
	}

	// An overwrite consent for a key the run does not carry is a typo worth
	// hearing about, not a silent no-op.
	if _, err := values.Import(t.Context(), actor, prod, service.ImportRequest{
		Entries:   []service.ImportEntry{{Key: "DB_URL", Value: "four"}},
		Overwrite: []string{"API_KEY"},
	}); err == nil || !strings.Contains(err.Error(), "API_KEY") {
		t.Fatalf("a stray overwrite consent was not refused naming it: %v", err)
	}
}

// scenarioImportMovedState is the M5 acceptance the ticket names outright:
// phase-2 replay against MOVED server state rejects by occurrence token, and
// the rejection names the key.
func scenarioImportMovedState(t *testing.T, db *store.DB) {
	who, scope, values, envs, keys := valueFixture(t, db, "importmoved")
	actor := service.LocalPrincipal(who)
	prod := mustEnv(t, envs, actor, scope, "prod")
	// `config`, for the same reason as scenarioImportStrict: the assertion that
	// matters here is that the REFUSED replay did not clobber the newer value,
	// which needs the value readable without the reveal ceremony.
	mustKey(t, keys, actor, scope, "DB_URL", string(schema.Config), schema.DefaultPresenceRules())
	mustKey(t, keys, actor, scope, "API_KEY", string(schema.Config), schema.DefaultPresenceRules())

	// Phase 1: observe, and record the manifest.
	observed, err := values.Occurrences(t.Context(), actor, prod, nil)
	if err != nil {
		t.Fatal(err)
	}
	pre := service.ImportPrecondition{
		DefinitionsRevision: observed.DefinitionsRevision,
		Environments:        []string{string(prod.Env)},
	}
	for _, k := range observed.Keys {
		pre.Occurrences = append(pre.Occurrences, service.ImportOccurrenceRef{
			Key: k.Name, Environment: string(prod.Env), Token: k.Token,
		})
	}
	entries := []service.ImportEntry{{Key: "DB_URL", Value: "imported"}, {Key: "API_KEY", Value: "imported"}}

	// A manifest-bound import against UNMOVED state lands.
	unmovedPre := pre
	if _, err := values.Import(t.Context(), actor, prod, service.ImportRequest{
		Entries: entries, Precondition: &unmovedPre,
	}); err != nil {
		t.Fatalf("a manifest-bound import against unmoved state was refused: %v", err)
	}

	// Now MOVE the state between phase 1 and phase 2, and replay the SAME
	// manifest. Both keys moved (both were absent at review and are set now),
	// so both are rejected by name and nothing is written.
	publishValue(t, db, values, actor, prod, "DB_URL", "someone-else")
	replay := pre
	_, err = values.Import(t.Context(), actor, prod, service.ImportRequest{
		Entries: entries, Overwrite: []string{"DB_URL", "API_KEY"}, Precondition: &replay,
	})
	if err == nil || !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("a replay against moved state was not refused: %v", err)
	}
	for _, name := range []string{"DB_URL", "API_KEY"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("the refusal does not name %s: %v", name, err)
		}
	}
	cell, err := values.Get(t.Context(), actor, prod, "DB_URL", false)
	if err != nil {
		t.Fatal(err)
	}
	if cell.Value != "someone-else" {
		t.Fatalf("the refused replay clobbered the newer value anyway: %q", cell.Value)
	}

	// A FABRICATED token is exactly as informative as a stale one: same error
	// class, same wording. An edited manifest cannot phrase a question about
	// someone else's state that the server answers differently.
	fresh, err := values.Occurrences(t.Context(), actor, prod, nil)
	if err != nil {
		t.Fatal(err)
	}
	forged := service.ImportPrecondition{
		DefinitionsRevision: fresh.DefinitionsRevision,
		Environments:        []string{string(prod.Env)},
		Occurrences: []service.ImportOccurrenceRef{
			{Key: "DB_URL", Environment: string(prod.Env), Token: "v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
		},
	}
	_, forgedErr := values.Import(t.Context(), actor, prod, service.ImportRequest{
		Entries: []service.ImportEntry{{Key: "DB_URL", Value: "x"}}, Overwrite: []string{"DB_URL"},
		Precondition: &forged,
	})
	stale := service.ImportPrecondition{
		DefinitionsRevision: fresh.DefinitionsRevision,
		Environments:        []string{string(prod.Env)},
		Occurrences: []service.ImportOccurrenceRef{
			{Key: "DB_URL", Environment: string(prod.Env), Token: pre.Occurrences[0].Token},
		},
	}
	_, staleErr := values.Import(t.Context(), actor, prod, service.ImportRequest{
		Entries: []service.ImportEntry{{Key: "DB_URL", Value: "x"}}, Overwrite: []string{"DB_URL"},
		Precondition: &stale,
	})
	if forgedErr == nil || staleErr == nil {
		t.Fatalf("a forged or stale token was accepted: forged=%v stale=%v", forgedErr, staleErr)
	}
	if forgedErr.Error() != staleErr.Error() {
		t.Errorf("a fabricated token is distinguishable from a stale one:\n forged: %v\n  stale: %v", forgedErr, staleErr)
	}

	// A DECLARATION THAT MOVED rejects that key by name, and it does so through
	// the token rather than through a project-wide revision: the declaration
	// digest and the classification are two of the token's four fields.
	//
	// The revision itself is deliberately NOT compared. Applying an import's own
	// definitions bundle bumps it, so a global equality check would make the
	// documented flow — plan, apply, import — a guaranteed conflict.
	reviewed, err := values.Occurrences(t.Context(), actor, prod, nil)
	if err != nil {
		t.Fatal(err)
	}
	declPre := service.ImportPrecondition{
		DefinitionsRevision: reviewed.DefinitionsRevision,
		Environments:        []string{string(prod.Env)},
	}
	for _, k := range reviewed.Keys {
		declPre.Occurrences = append(declPre.Occurrences, service.ImportOccurrenceRef{
			Key: k.Name, Environment: string(prod.Env), Token: k.Token,
		})
	}
	// An unrelated key's creation bumps the revision and must NOT refuse the run.
	mustKey(t, keys, actor, scope, "NEW_KEY", string(schema.Config), schema.DefaultPresenceRules())
	if _, err := values.Import(t.Context(), actor, prod, service.ImportRequest{
		Entries:   []service.ImportEntry{{Key: "API_KEY", Value: "unrelated-ok"}},
		Overwrite: []string{"API_KEY"}, Precondition: &declPre,
	}); err != nil {
		t.Fatalf("an unrelated declaration bumped the revision and refused the run: %v", err)
	}

	// Now move API_KEY's OWN declaration and replay the same reviewed token.
	after, err := values.Occurrences(t.Context(), actor, prod, nil)
	if err != nil {
		t.Fatal(err)
	}
	movedDecl := service.ImportPrecondition{
		DefinitionsRevision: after.DefinitionsRevision,
		Environments:        []string{string(prod.Env)},
	}
	for _, k := range after.Keys {
		movedDecl.Occurrences = append(movedDecl.Occurrences, service.ImportOccurrenceRef{
			Key: k.Name, Environment: string(prod.Env), Token: k.Token,
		})
	}
	minLength := 4
	if _, err := keys.UpdateDeclaration(t.Context(), actor, scope, keyIDOf(t, after, "API_KEY"),
		service.KeyDeclarationUpdate{
			Declaration: schema.Declaration{Rule: &schema.Rule{Type: schema.TypeString, MinLength: &minLength}},
			Presence:    schema.DefaultPresenceRules(),
		}); err != nil {
		t.Fatal(err)
	}
	_, err = values.Import(t.Context(), actor, prod, service.ImportRequest{
		Entries:   []service.ImportEntry{{Key: "API_KEY", Value: "moved-decl"}},
		Overwrite: []string{"API_KEY"}, Precondition: &movedDecl,
	})
	if err == nil || !errors.Is(err, domain.ErrConflict) || !strings.Contains(err.Error(), "API_KEY") {
		t.Fatalf("a moved declaration was not rejected by name: %v", err)
	}
}

// scenarioImportPerSourceE2E is the per-source fixture E2E: each connector's
// fixture is parsed, planned against real server state, and its values file is
// imported through phase 2 — collision buckets, renames and the classification
// matrix asserted on the way through.
func scenarioImportPerSourceE2E(t *testing.T, db *store.DB) {
	for _, tc := range []struct {
		source  string
		fixture string
		slug    string
		// wantKeys is the target key set the connector's records map onto,
		// after the rename transform.
		wantKeys []string
	}{
		{"k8s", "k8s-multi.yaml", "", []string{"API_KEY", "DB_HOST", "DB_PASSWORD", "DB_PORT"}},
		{"infisical", "infisical-export.json", "dev", []string{"API_KEY", "DB_URL"}},
		// SOPS carries the whole shape in one fixture: a folder chain from
		// nested maps, a renamed leaf (`db-host`), an array leaf through the
		// canonical serialization, and one plaintext leaf whose status is a
		// HINT that must move nothing.
		{"sops", "sops-age.yaml", "", []string{
			"ALLOWED_ORIGINS", "API_KEY", "BURST", "DB_HOST", "DB_PASSWORD", "LOG_LEVEL", "PORT", "STEADY",
		}},
	} {
		t.Run(tc.source, func(t *testing.T) {
			if tc.source == "sops" {
				// The ambient keyring, pointed at the fixture's throwaway age
				// identity. WithSanitized must leave it alone, and this is the
				// only E2E that proves decryption still works through the
				// sanitized scope.
				identity, err := os.ReadFile(filepath.Join("..", "importer", "testdata", "sops-age-identity.txt"))
				if err != nil {
					t.Fatal(err)
				}
				t.Setenv("SOPS_AGE_KEY", strings.TrimSpace(string(identity)))
			}
			who, scope, values, envs, keys := valueFixture(t, db, "importe2e"+tc.source)
			actor := service.LocalPrincipal(who)
			prod := mustEnv(t, envs, actor, scope, "prod")

			raw, err := os.ReadFile(filepath.Join("..", "importer", "testdata", tc.fixture))
			if err != nil {
				t.Fatal(err)
			}
			result, err := importer.Run(t.Context(), tc.source,
				importer.Input{Path: tc.fixture, Data: raw, EnvSlug: tc.slug})
			if err != nil {
				t.Fatal(err)
			}

			// Phase 1 against an EMPTY project: every key is `new`, and the
			// bundle proposes every declaration.
			plan := mustPlan(t, tc.source, result, values, actor, scope, prod, raw, tc.slug)
			if strings.Join(plan.New, ",") != strings.Join(tc.wantKeys, ",") {
				t.Fatalf("new bucket = %v, want %v", plan.New, tc.wantKeys)
			}
			if len(plan.Bundle.Keys) != len(tc.wantKeys) {
				t.Fatalf("bundle declares %d keys, want %d", len(plan.Bundle.Keys), len(tc.wantKeys))
			}
			// Classification matrix: EVERY imported key defaults `secret`, from
			// every source, with no exception and no downgrade.
			for _, k := range plan.Bundle.Keys {
				if k.Classification != string(schema.Secret) {
					t.Errorf("%s declared %s; every imported key defaults secret", k.Name, k.Classification)
				}
				// Flag mode declares everything `string`, including a leaf that
				// arrived as a serialized structure: anything else is the silent
				// tightening the ADR rejects.
				if k.Declaration.Rule == nil || k.Declaration.Rule.Type != schema.TypeString {
					t.Errorf("%s declared %+v; flag mode declares every value `string`", k.Name, k.Declaration.Rule)
				}
			}
			// SOPS's plaintext leaf is recorded as a HINT and downgrades
			// nothing: LOG_LEVEL sat outside the encrypted set and is still
			// declared `secret` above.
			if tc.source == "sops" && strings.Join(plan.PlaintextHints, ",") != "LOG_LEVEL" {
				t.Errorf("plaintext hints = %v, want the one unencrypted leaf", plan.PlaintextHints)
			}

			// THE DOCUMENTED FLOW, end to end, with NO RE-PLAN: apply the
			// bundle phase 1 authored (by hand — `definitions plan|apply` is
			// #70), then run phase 2 against THE ORIGINAL manifest, which is
			// exactly what the CLI's own next-steps output tells the operator
			// to do.
			//
			// This is the test that catches a precondition bound to a global
			// definitions revision: applying the bundle bumps that revision, so
			// a run that silently re-planned in between would pass here while
			// the product's documented flow failed.
			for _, k := range plan.Bundle.Keys {
				mustKey(t, keys, actor, scope, k.Name, k.Classification, schema.DefaultPresenceRules())
			}
			imported, err := values.Import(t.Context(), actor, prod, importRequestFrom(plan))
			if err != nil {
				t.Fatalf("phase 2 refused the run its own phase 1 authored: %v", err)
			}
			if strings.Join(imported.Imported, ",") != strings.Join(tc.wantKeys, ",") {
				t.Fatalf("imported = %v, want %v", imported.Imported, tc.wantKeys)
			}

			// Re-running the SAME manifest now rejects every key: the writes it
			// just made are themselves movement against the state it reviewed.
			if _, err := values.Import(t.Context(), actor, prod,
				importRequestFrom(plan)); err == nil || !errors.Is(err, domain.ErrConflict) {
				t.Fatalf("replaying a spent manifest was not refused: %v", err)
			}

			// A fresh phase 1 now buckets everything as `set`, skips it by name
			// — which is what makes a re-run idempotent — and emits no values
			// file at all, because an empty one is an artifact phase 2 refuses.
			rerun := mustPlan(t, tc.source, result, values, actor, scope, prod, raw, tc.slug)
			if strings.Join(rerun.Set, ",") != strings.Join(tc.wantKeys, ",") {
				t.Fatalf("second run's set bucket = %v, want %v", rerun.Set, tc.wantKeys)
			}
			if rerun.HasValues || len(rerun.Values.Entries) != 0 {
				t.Fatalf("a re-run proposed %d writes; skip-by-default makes it idempotent", len(rerun.Values.Entries))
			}
		})
	}
}

// scenarioImportUndeclaredTransition pins the declaration intent carried by an
// undeclared token. Applying the reviewed bundle is allowed; reclassifying the
// new key while it is still absent is a different transition and is refused.
func scenarioImportUndeclaredTransition(t *testing.T, db *store.DB) {
	who, scope, values, envs, keys := valueFixture(t, db, "importtransition")
	actor := service.LocalPrincipal(who)
	prod := mustEnv(t, envs, actor, scope, "prod")
	result := importer.Result{Records: []importer.Record{{
		Folder: []string{"source"}, SourceName: "NEW_KEY", Value: "value", Type: schema.TypeString,
	}}}
	plan := mustPlan(t, "k8s", result, values, actor, scope, prod, []byte("fixture"), "")
	if len(plan.Bundle.Keys) != 1 {
		t.Fatalf("phase 1 emitted %d bundle keys, want one", len(plan.Bundle.Keys))
	}
	created := mustKey(t, keys, actor, scope, "NEW_KEY", string(schema.Secret), schema.DefaultPresenceRules())
	if _, err := keys.Reclassify(t.Context(), actor, scope, created.ID, string(schema.Config)); err != nil {
		t.Fatal(err)
	}
	_, err := values.Import(t.Context(), actor, prod, importRequestFrom(plan))
	if err == nil || !errors.Is(err, domain.ErrConflict) || !strings.Contains(err.Error(), "NEW_KEY") {
		t.Fatalf("the reviewed undeclared transition accepted a different declaration: %v", err)
	}
}

// mustPlan mirrors the CLI exactly: transform names, ask the server about every
// candidate, then plan. Doing it any other way here would make the E2E test a
// flow the product does not have.
func mustPlan(t *testing.T, source string, result importer.Result, values *service.Values,
	actor service.Actor, scope, env domain.Scope, raw []byte, slug string) *importer.Plan {
	t.Helper()
	in := importer.PlanInput{
		Source: source, Records: result.Records, Skipped: result.Skipped,
		Scope: result.Scope, FileDigest: importer.Digest(raw), EnvSlug: slug,
	}
	planned, err := importer.PlannedCandidates(in)
	if err != nil {
		t.Fatal(err)
	}
	candidates := make([]service.ImportCandidate, 0, len(planned))
	for _, candidate := range planned {
		candidates = append(candidates, service.ImportCandidate{
			Name: candidate.Name, IntendedClassification: candidate.Classification,
			IntendedType: candidate.Type,
		})
	}
	presence, err := values.Occurrences(t.Context(), actor, env, candidates)
	if err != nil {
		t.Fatal(err)
	}
	in.State = importer.ServerState{
		Project: string(scope.Project), Environment: string(env.Env),
		DefinitionsRevision: presence.DefinitionsRevision,
	}
	for _, k := range presence.Keys {
		in.State.Keys = append(in.State.Keys, importer.KeyState{
			Name: k.Name, ID: k.KeyID, Declared: k.Declared,
			Classification: k.Classification, Type: k.Type, Set: k.Set, Token: k.Token,
		})
	}
	plan, err := importer.BuildPlan(in)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

// importRequestFrom turns phase 1's artifacts into the phase-2 call the CLI
// makes, manifest and all.
func importRequestFrom(plan *importer.Plan) service.ImportRequest {
	req := service.ImportRequest{
		Precondition: &service.ImportPrecondition{
			DefinitionsRevision: plan.Manifest.DefinitionsRevision,
			Environments:        plan.Manifest.Target.Environments,
		},
	}
	for _, e := range plan.Values.Entries {
		req.Entries = append(req.Entries, service.ImportEntry{Key: e.Key, Value: e.Value})
	}
	for _, o := range plan.Manifest.Occurrences {
		req.Precondition.Occurrences = append(req.Precondition.Occurrences,
			service.ImportOccurrenceRef{Key: o.Key, Environment: o.Environment, Token: o.Token})
	}
	return req
}

func keyIDOf(t *testing.T, presence service.ImportPresence, name string) string {
	t.Helper()
	for _, k := range presence.Keys {
		if k.Name == name {
			return k.KeyID
		}
	}
	t.Fatalf("no key %q in the presence read", name)
	return ""
}

// scenarioImportPreconditionOracle is the S1 acceptance: the precondition is
// not an oracle, and a caller cannot make it one by choosing which environments
// the manifest names.
//
// The attack: a caller who may WRITE into prod but may not READ it presents a
// manifest naming only some other environment, plus a captured token, and reads
// the match/reject answer as a one-bit probe of prod's state. The union — the
// manifest's environments AND the import's own target, always — closes it: the
// target is authorized because it is the target, never because a
// caller-supplied list happened to mention it.
func scenarioImportPreconditionOracle(t *testing.T, db *store.DB) {
	who, scope, values, envs, keys := valueFixture(t, db, "importoracle")
	actor := service.LocalPrincipal(who)
	prod := mustEnv(t, envs, actor, scope, "prod")
	other := mustEnv(t, envs, actor, scope, "other")
	mustKey(t, keys, actor, scope, "DB_URL", string(schema.Config), schema.DefaultPresenceRules())

	observed, err := values.Occurrences(t.Context(), actor, prod, nil)
	if err != nil {
		t.Fatal(err)
	}
	pre := service.ImportPrecondition{
		DefinitionsRevision: observed.DefinitionsRevision,
		// The manifest names ONLY the other environment. A precondition that
		// authorized what it was told to would never check prod at all.
		Environments: []string{string(other.Env)},
	}
	for _, k := range observed.Keys {
		pre.Occurrences = append(pre.Occurrences, service.ImportOccurrenceRef{
			Key: k.Name, Environment: string(prod.Env), Token: k.Token,
		})
	}

	// A principal holding the WRITE formula on prod and read on `other`, but no
	// read on prod. It can reach the verb; it must not get a precondition result.
	probe := newPrincipal(t, db, "usr_oracle_"+string(scope.Project), []grantSpec{
		{"edit", prod},
		{"publish", prod},
		{"read", other},
	})
	_, err = values.Import(t.Context(), service.LocalPrincipal(probe), prod, service.ImportRequest{
		Entries: []service.ImportEntry{{Key: "DB_URL", Value: "probe"}}, Precondition: &pre,
	})
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("a caller without read on the TARGET got past the precondition gate: %v", err)
	}
	cell, err := values.Get(t.Context(), actor, prod, "DB_URL", false)
	if err != nil {
		t.Fatal(err)
	}
	if cell.Set {
		t.Fatal("the refused probe wrote a value")
	}

	// The same manifest from a caller who DOES hold read on the target works,
	// which is what makes the refusal above about the missing read rather than
	// about the manifest's shape.
	if _, err := values.Import(t.Context(), actor, prod, service.ImportRequest{
		Entries: []service.ImportEntry{{Key: "DB_URL", Value: "authorized"}}, Precondition: &pre,
	}); err != nil {
		t.Fatalf("an authorized caller was refused the same manifest: %v", err)
	}
}
