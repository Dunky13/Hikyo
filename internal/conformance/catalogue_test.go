package conformance

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/schema"
	"github.com/Hikyo-Org/hikyo/internal/service"
	"github.com/Hikyo-Org/hikyo/internal/store"
)

// The key catalogue's cross-engine acceptance scenarios (#49, mvp-boundary C3
// and the key half of C1). Every one runs through the service layer, so tx,
// authorize() and both engines' SQL are under test — never against a mock.

func intp(v int) *int { return &v }

func decl(r schema.Rule) schema.Declaration { return schema.Declaration{Rule: &r} }

func keySpec(name, classification string, d schema.Declaration) service.KeySpec {
	return service.KeySpec{
		Name: name, Classification: classification,
		Declaration: d, Presence: schema.DefaultPresenceRules(),
	}
}

// scenarioKeyCatalogueCRUD is C1's key portion: a key is defined ONCE per
// project, identity is the immutable id, and the declaration survives the
// round trip through both engines byte-for-byte.
func scenarioKeyCatalogueCRUD(t *testing.T, db *store.DB) {
	keys := &service.Keys{DB: db, Keyring: sharedKeyring(t, db)}
	who, scope := tenantFixture(t, db, "catalogue")
	actor := service.LocalPrincipal(who)

	created, err := keys.Create(t.Context(), actor, scope,
		keySpec("DATABASE_URL", string(schema.Secret), decl(schema.Rule{
			Type: schema.TypeURL, Schemes: []string{"postgres"},
		})), nil)
	if err != nil {
		t.Fatal(err)
	}

	// Defined ONCE per project: a second key of the same name is a conflict,
	// answered by the UNIQUE index rather than a read-then-write nobody can
	// serialize.
	_, err = keys.Create(t.Context(), actor, scope,
		keySpec("DATABASE_URL", string(schema.Config), decl(schema.Rule{Type: schema.TypeString})), nil)
	if !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("a duplicate key name was accepted: %v", err)
	}

	// Create's response is the STORED declaration, not the request's. A
	// non-canonical declaration — members needing the write-time trim, a scheme
	// in the wrong case, a JSON Schema with its own spacing and key order — must
	// come back already normalized, byte-identical to what a later read
	// returns; echoing the request would make create the one operation whose
	// answer disagrees with the database.
	noisy, err := keys.Create(t.Context(), actor, scope, service.KeySpec{
		Name: "NOISY", Classification: string(schema.Config),
		Declaration: schema.Declaration{AnyOf: []schema.Rule{
			{Type: schema.TypeEnum, Members: []string{"  fast ", "safe"}},
			{Type: schema.TypeURL, Schemes: []string{"HTTPS"}},
			{Type: schema.TypeJSON, JSONSchema: json.RawMessage(
				"{  \"required\" : [ \"b\" ] ,\n  \"type\":\"object\"  }")},
		}},
		Presence: schema.DefaultPresenceRules(),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	noisyRead, err := keys.Get(t.Context(), actor, scope, noisy.ID)
	if err != nil {
		t.Fatal(err)
	}
	echoed, err := schema.Canonical(noisy.Declaration)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := schema.Canonical(noisyRead.Declaration)
	if err != nil {
		t.Fatal(err)
	}
	if string(echoed) != string(stored) {
		t.Fatalf("create echoed a declaration the database does not hold:\n echoed: %s\n stored: %s", echoed, stored)
	}
	if noisy.Declaration.AnyOf[0].Members[0] != "fast" || noisy.Declaration.AnyOf[1].Schemes[0] != "https" {
		t.Fatalf("create echoed the request rather than the canonical form: %+v", noisy.Declaration)
	}
	if err := keys.Delete(t.Context(), actor, scope, noisy.ID); err != nil {
		t.Fatal(err)
	}

	// The catalogue read carries the schema revision; creating a key advanced
	// it from the project's initial 0.
	list, revision, err := keys.List(t.Context(), actor, scope)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].ID != created.ID {
		t.Fatalf("key list = %+v, want exactly the created key", list)
	}
	if revision != 3 {
		t.Fatalf("schema revision = %d after a create, a create and a delete, want 3", revision)
	}
	if list[0].Declaration.Rule == nil || list[0].Declaration.Rule.Type != schema.TypeURL {
		t.Fatalf("declaration did not survive the round trip: %+v", list[0].Declaration)
	}

	// Rename changes the delivered payload's key set, so it IS a semantic
	// change and moves the revision. Identity is the id throughout.
	renamed, err := keys.Rename(t.Context(), actor, scope, created.ID, "PRIMARY_DATABASE_URL", nil)
	if err != nil {
		t.Fatal(err)
	}
	if renamed.ID != created.ID || renamed.Name != "PRIMARY_DATABASE_URL" {
		t.Fatalf("rename moved identity or missed the name: %+v", renamed)
	}
	if _, revision, err = keys.List(t.Context(), actor, scope); err != nil || revision != 4 {
		t.Fatalf("rename left the schema revision at %d (err %v), want 4", revision, err)
	}

	// Metadata does not change delivery, but it is bundle desired state. Each
	// actual metadata change advances the definitions revision without a publish
	// fan-out, so a stale exported base cannot overwrite it.
	folder, description, note, deprecated := "services/api", "primary datastore", "superseded by PRIMARY_DSN", true
	if _, err := keys.UpdateMetadata(t.Context(), actor, scope, created.ID, service.KeyMetadataUpdate{
		FolderPath: &folder, Description: &description,
		Deprecated: &deprecated, DeprecationNote: &note,
	}, nil); err != nil {
		t.Fatal(err)
	}
	got, err := keys.Get(t.Context(), actor, scope, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.FolderPath != "services/api" || !got.Deprecated || got.Description != "primary datastore" {
		t.Fatalf("metadata did not persist: %+v", got)
	}

	// A PATCH is a MERGE: setting one member must leave the others alone. A
	// zero value where a member is absent is the silent fallback this project
	// refuses, and a partial update is exactly where it hides.
	onlyDescription := "revised"
	partial, err := keys.UpdateMetadata(t.Context(), actor, scope, created.ID,
		service.KeyMetadataUpdate{Description: &onlyDescription}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if partial.Description != "revised" {
		t.Fatalf("the updated member did not land: %+v", partial)
	}
	if partial.FolderPath != "services/api" || !partial.Deprecated || partial.DeprecationNote != note {
		t.Fatalf("a partial metadata update cleared untouched members: %+v", partial)
	}
	// And the response is the COMMITTED state, not a re-read under another
	// formula in another transaction.
	reread, err := keys.Get(t.Context(), actor, scope, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if reread.FolderPath != partial.FolderPath || reread.Description != partial.Description ||
		reread.Deprecated != partial.Deprecated || reread.DeprecationNote != partial.DeprecationNote {
		t.Fatalf("the update response disagrees with the stored row:\n %+v\n %+v", partial, reread)
	}

	// The other half of the merge rule: an EXPLICIT empty value clears the
	// field. Absent and empty are different requests, and a refactor that
	// collapsed them would be silent without this.
	cleared, notDeprecated := "", false
	emptied, err := keys.UpdateMetadata(t.Context(), actor, scope, created.ID, service.KeyMetadataUpdate{
		Description: &cleared, DeprecationNote: &cleared, Deprecated: &notDeprecated,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if emptied.Description != "" || emptied.DeprecationNote != "" || emptied.Deprecated {
		t.Fatalf("an explicit empty member did not clear its field: %+v", emptied)
	}
	if emptied.FolderPath != "services/api" {
		t.Fatalf("clearing three members moved the fourth: %+v", emptied)
	}
	if _, revision, err = keys.List(t.Context(), actor, scope); err != nil || revision != 7 {
		t.Fatalf("three metadata changes left the definitions revision at %d (err %v), want 7", revision, err)
	}

	// The name is free again once the key is gone — unique among LIVE keys —
	// and the new key is a different key, because identity is the id.
	if err := keys.Delete(t.Context(), actor, scope, created.ID); err != nil {
		t.Fatal(err)
	}
	reused, err := keys.Create(t.Context(), actor, scope,
		keySpec("PRIMARY_DATABASE_URL", string(schema.Config), decl(schema.Rule{Type: schema.TypeString})), nil)
	if err != nil {
		t.Fatalf("a deleted key's name could not be reused: %v", err)
	}
	if reused.ID == created.ID {
		t.Fatal("a reused name produced the same id — identity must be allocated, never reused")
	}
	if err := keys.Delete(t.Context(), actor, scope, reused.ID); err != nil {
		t.Fatal(err)
	}
}

// scenarioDeclarationFixtures is C3's per-type fixture table, run against the
// declarations as they come BACK OUT of the database: a rule that survives the
// canonical round trip but changes meaning is exactly the failure a
// declaration-time-only test cannot see.
func scenarioDeclarationFixtures(t *testing.T, db *store.DB) {
	keys := &service.Keys{DB: db, Keyring: sharedKeyring(t, db)}
	who, scope := tenantFixture(t, db, "fixtures")
	actor := service.LocalPrincipal(who)

	cases := []struct {
		name    string
		rule    schema.Rule
		valid   []string
		invalid []string
	}{
		{"STR", schema.Rule{Type: schema.TypeString, MinLength: intp(2)},
			[]string{"ab", "multi\nline"}, []string{"a", ""}},
		{"INT", schema.Rule{Type: schema.TypeInteger, Min: i64(1), Max: i64(65535)},
			[]string{"1", "00042", "65535"}, []string{"0", "65536", "+1", "1e3", "9223372036854775808"}},
		{"BOOL", schema.Rule{Type: schema.TypeBoolean},
			[]string{"true", "false"}, []string{"TRUE", "1", "yes"}},
		{"MODE", schema.Rule{Type: schema.TypeEnum, Members: []string{"fast", "safe"}},
			[]string{"fast", " safe "}, []string{"", "SAFE"}},
		{"ENDPOINT", schema.Rule{Type: schema.TypeURL, Schemes: []string{"https", "postgres"}},
			[]string{"https://a.test/x", "POSTGRES://db/x"}, []string{"ftp://a.test", "/relative"}},
		{"DOC", schema.Rule{Type: schema.TypeJSON,
			JSONSchema: json.RawMessage(`{"type":"object","required":["a"]}`)},
			[]string{`{"a":1}`}, []string{`{"b":1}`, `{"a":1,"a":2}`, `nope`}},
		// Whole-value anchoring: the pattern is implicitly \A(?:...)\z, so a
		// value that merely CONTAINS a match is refused. An unanchored regex
		// that appears to constrain a value while matching a fragment of it is
		// the classic validation bypass.
		{"ANCHORED", schema.Rule{Type: schema.TypeString, Pattern: "[a-z]+"},
			[]string{"abc"}, []string{"abc1", "1abc", "ab c"}},
	}

	for _, tc := range cases {
		created, err := keys.Create(t.Context(), actor, scope,
			keySpec(tc.name, string(schema.Config), decl(tc.rule)), nil)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		stored, err := keys.Get(t.Context(), actor, scope, created.ID)
		if err != nil {
			t.Fatal(err)
		}
		compiled, err := schema.CompileClassified(schema.Classification(stored.Classification), stored.Declaration)
		if err != nil {
			t.Fatalf("%s: the STORED declaration no longer compiles: %v", tc.name, err)
		}
		for _, value := range tc.valid {
			if v := compiled.Validate(value); !v.Valid {
				t.Errorf("%s: %q refused: %+v", tc.name, value, v.Errors)
			}
		}
		for _, value := range tc.invalid {
			if v := compiled.Validate(value); v.Valid {
				t.Errorf("%s: %q accepted", tc.name, value)
			}
		}
		if err := keys.Delete(t.Context(), actor, scope, created.ID); err != nil {
			t.Fatal(err)
		}
	}
}

func i64(v int64) *int64 { return &v }

// scenarioDeclarationRejections is C3's "rejections by name": each of these is
// refused at SAVE and the refusal names what it refused, because a rule that
// appears to enforce something and does not is worse than no rule at all.
func scenarioDeclarationRejections(t *testing.T, db *store.DB) {
	keys := &service.Keys{DB: db, Keyring: sharedKeyring(t, db)}
	who, scope := tenantFixture(t, db, "rejections")
	actor := service.LocalPrincipal(who)

	deep := strings.Repeat(`{"properties":{"a":`, schema.MaxJSONSchemaDepth+2) + `{}` +
		strings.Repeat(`}}`, schema.MaxJSONSchemaDepth+2)

	cases := []struct {
		name  string
		rule  schema.Rule
		names string
	}{
		{"NUL_IN_ENUM_MEMBER",
			schema.Rule{Type: schema.TypeEnum, Members: []string{"ok", "bad\x00member"}}, "NUL"},
		{"ALLOWLISTED_OUT_KEYWORD",
			schema.Rule{Type: schema.TypeJSON, JSONSchema: json.RawMessage(`{"type":"string","format":"email"}`)}, "format"},
		{"DYNAMIC_REF",
			schema.Rule{Type: schema.TypeJSON, JSONSchema: json.RawMessage(`{"$dynamicRef":"#n"}`)}, "$dynamicRef"},
		{"REF_CYCLE",
			schema.Rule{Type: schema.TypeJSON, JSONSchema: json.RawMessage(
				`{"$defs":{"a":{"$ref":"#/$defs/a"}},"$ref":"#/$defs/a"}`)}, "cycle"},
		{"REMOTE_REF",
			schema.Rule{Type: schema.TypeJSON, JSONSchema: json.RawMessage(`{"$ref":"https://evil.test/s.json"}`)}, "$ref"},
		{"BUDGET_DEPTH",
			schema.Rule{Type: schema.TypeJSON, JSONSchema: json.RawMessage(deep)}, "depth"},
		{"BACKREFERENCE",
			schema.Rule{Type: schema.TypeString, Pattern: `(a)\1`}, "pattern"},
		{"LOOKAHEAD",
			schema.Rule{Type: schema.TypeString, Pattern: `(?=a)b`}, "pattern"},
	}
	for _, tc := range cases {
		_, err := keys.Create(t.Context(), actor, scope, keySpec(tc.name, string(schema.Config), decl(tc.rule)), nil)
		if !errors.Is(err, domain.ErrInvalid) {
			t.Fatalf("%s: declaration accepted or wrong class: %v", tc.name, err)
		}
		if !strings.Contains(err.Error(), tc.names) {
			t.Errorf("%s: refusal %q does not name %q", tc.name, err, tc.names)
		}
		// A refused declaration writes nothing: the key does not exist.
		list, _, err := keys.List(t.Context(), actor, scope)
		if err != nil {
			t.Fatal(err)
		}
		for _, key := range list {
			if key.Name == tc.name {
				t.Fatalf("%s: a refused declaration left a row behind", tc.name)
			}
		}
	}

	// A key name outside the canonical grammar is refused by the same
	// authority — the grammar is a delivery constraint, not a preference.
	if _, err := keys.Create(t.Context(), actor, scope,
		keySpec("lower_case", string(schema.Config), decl(schema.Rule{Type: schema.TypeString})), nil); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("a lowercase key name was accepted: %v", err)
	}
}

// scenarioSecretRuleChangeNeedsReveal is C3's load-bearing security rule.
//
// Two principals over ONE key: one holds definitions-edit alone, the other
// also holds reveal. The reveal-lacking principal must be refused a
// value-dependent rule change on a `secret` key — and refused BEFORE the new
// declaration is evaluated at all, which is asserted by handing it a
// declaration that is itself broken: if the gate ran second, the answer would
// be the validation error rather than the uniform nonexistent one.
func scenarioSecretRuleChangeNeedsReveal(t *testing.T, db *store.DB) {
	keys := &service.Keys{DB: db, Keyring: sharedKeyring(t, db)}
	editorPrincipal, scope := tenantFixture(t, db, "revealgate")
	editor := service.LocalPrincipal(editorPrincipal)

	// The grant API is #55's, so the revealing principal is seeded with raw
	// SQL exactly as the rest of this suite seeds its fixtures.
	revealer := domain.PrincipalID("usr_revealgate_revealer")
	stmts := []string{
		`INSERT INTO principals (id, kind, created_at) VALUES ('` + string(revealer) + `', 'human', '2026-01-01T00:00:00Z')`,
	}
	for i, capability := range []string{"definitions-edit", "read", "reveal"} {
		stmts = append(stmts, fmt.Sprintf(
			`INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at)
			 VALUES ('grt_revealgate_r%d', '%s', '%s', '%s', NULL, NULL, '2026-01-01T00:00:00Z')`,
			i, revealer, capability, scope.Org))
	}
	seed(t, db, stmts)
	revealing := service.LocalPrincipal(revealer)

	secret, err := keys.Create(t.Context(), editor, scope,
		keySpec("API_TOKEN", string(schema.Secret), decl(schema.Rule{Type: schema.TypeString})), nil)
	if err != nil {
		t.Fatal(err)
	}
	config, err := keys.Create(t.Context(), editor, scope,
		keySpec("LOG_LEVEL", string(schema.Config), decl(schema.Rule{Type: schema.TypeString})), nil)
	if err != nil {
		t.Fatal(err)
	}

	tighten := service.KeyDeclarationUpdate{
		Declaration: decl(schema.Rule{Type: schema.TypeString, Pattern: "A.*"}),
		Presence:    schema.DefaultPresenceRules(),
	}

	// 1. Without reveal: refused, and refused as the UNIFORM nonexistent
	// outcome. A distinguishable refusal would itself be the one-bit oracle.
	if _, err := keys.UpdateDeclaration(t.Context(), editor, scope, secret.ID, tighten, nil); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("a value-dependent rule change on a secret key without reveal answered %v, want the uniform nonexistent", err)
	}

	// 2. Rejected WITHOUT EVALUATING: the declaration below cannot compile
	// (RE2 has no lookahead), so a gate that ran after validation would answer
	// ErrInvalid. It must answer the uniform nonexistent instead.
	broken := service.KeyDeclarationUpdate{
		Declaration: decl(schema.Rule{Type: schema.TypeString, Pattern: `(?=x)y`}),
		Presence:    schema.DefaultPresenceRules(),
	}
	if _, err := keys.UpdateDeclaration(t.Context(), editor, scope, secret.ID, broken, nil); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("the gate evaluated the declaration before refusing: %v", err)
	}

	// 3. The same principal may still tighten a CONFIG key: the gate is about
	// classification, not about editing.
	if _, err := keys.UpdateDeclaration(t.Context(), editor, scope, config.ID, tighten, nil); err != nil {
		t.Fatalf("a config key's rule change was gated: %v", err)
	}

	// 4. Presence rules are NOT value-dependent — they report only whether an
	// entry is set or absent — so the reveal-lacking principal may change them
	// on the secret key.
	presenceOnly := service.KeyDeclarationUpdate{
		Declaration: decl(schema.Rule{Type: schema.TypeString}),
		Presence: schema.PresenceRules{
			Required:  schema.Presence{Mode: schema.PresenceAll},
			Forbidden: schema.Presence{Mode: schema.PresenceNone},
		},
	}
	if _, err := keys.UpdateDeclaration(t.Context(), editor, scope, secret.ID, presenceOnly, nil); err != nil {
		t.Fatalf("a presence-only change on a secret key was gated: %v", err)
	}

	// 4b. The attempt limiter, on a key of its own so exhausting a bucket does
	// not change what the rest of this matrix is testing.
	//
	// The property under test is TWO-SIDED. A caller WITHOUT reveal must see
	// the same answer forever — attempt 1 and attempt 21 identical, sentinel
	// and message — because only a `secret` key that exists reaches the gate at
	// all, so a response that changed with attempt count would answer exactly
	// the existence-and-classification question the gate refuses. Only a caller
	// who has PASSED the gate may ever observe the limit.
	probeKey, err := keys.Create(t.Context(), editor, scope,
		keySpec("RATE_PROBE", string(schema.Secret), decl(schema.Rule{Type: schema.TypeString})), nil)
	if err != nil {
		t.Fatal(err)
	}
	// Each attempt carries a DIFFERENT pattern: a repeat of the stored
	// declaration is no rule change at all, so it would never reach the gate.
	attempt := func(actor service.Actor, i int) error {
		_, err := keys.UpdateDeclaration(t.Context(), actor, scope, probeKey.ID,
			service.KeyDeclarationUpdate{
				Declaration: decl(schema.Rule{Type: schema.TypeString, Pattern: "A" + strconv.Itoa(i) + ".*"}),
				Presence:    schema.DefaultPresenceRules(),
			}, nil)
		return err
	}
	first := attempt(editor, 0)
	if !errors.Is(first, domain.ErrNotFound) {
		t.Fatalf("the first reveal-less attempt answered %v", first)
	}
	for i := 1; i <= 3*GateAttemptsPerMinuteForTest; i++ {
		err := attempt(editor, i)
		if !errors.Is(err, domain.ErrNotFound) || err.Error() != first.Error() {
			t.Fatalf("reveal-less attempt %d answered %v, want the same uniform outcome as attempt 1 (%v)",
				i, err, first)
		}
	}
	// The reveal holder — and only the reveal holder — meets the limit.
	limited := false
	for i := range 3 * GateAttemptsPerMinuteForTest {
		err := attempt(revealing, 1000+i)
		if errors.Is(err, domain.ErrLimitExceeded) {
			limited = true
			break
		}
		if err != nil {
			t.Fatalf("a reveal-holding attempt answered %v", err)
		}
	}
	if !limited {
		t.Fatal("the reveal-gate attempt limiter never fired for a gate-passing principal")
	}
	// A different key is a different bucket: the limit is per (principal, key),
	// so exhausting one must not lock the principal out of the catalogue.
	if _, err := keys.UpdateDeclaration(t.Context(), revealing, scope, config.ID, tighten, nil); err != nil {
		t.Fatalf("exhausting one key's gate bucket refused an unrelated key: %v", err)
	}
	if err := keys.Delete(t.Context(), editor, scope, probeKey.ID); err != nil {
		t.Fatal(err)
	}

	// 5. With reveal: the same tightening lands.
	tightened, err := keys.UpdateDeclaration(t.Context(), revealing, scope, secret.ID, tighten, nil)
	if err != nil {
		t.Fatalf("a reveal holder was refused: %v", err)
	}
	if tightened.Declaration.Rule.Pattern != "A.*" {
		t.Fatalf("the tightened rule did not persist: %+v", tightened.Declaration)
	}

	// 6. Declassification is likewise reveal-gated; tightening is not.
	if _, _, err := keys.Reclassify(t.Context(), editor, scope, secret.ID, string(schema.Config)); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("declassification without reveal answered %v, want the uniform nonexistent", err)
	}
	if _, _, err := keys.Reclassify(t.Context(), editor, scope, config.ID, string(schema.Secret)); err != nil {
		t.Fatalf("tightening config to secret was gated: %v", err)
	}
	declassified, _, err := keys.Reclassify(t.Context(), revealing, scope, secret.ID, string(schema.Config))
	if err != nil {
		t.Fatalf("a reveal holder could not declassify: %v", err)
	}
	if declassified.Classification != string(schema.Config) {
		t.Fatalf("declassification did not persist: %+v", declassified)
	}
	// The ceremony refuses a no-op: it would write a disclosure-class record
	// for an act that never happened.
	if _, _, err := keys.Reclassify(t.Context(), revealing, scope, secret.ID, string(schema.Config)); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("a no-op reclassification was accepted: %v", err)
	}

	for _, id := range []string{secret.ID, config.ID} {
		if err := keys.Delete(t.Context(), editor, scope, id); err != nil {
			t.Fatal(err)
		}
	}
}

// scenarioPresenceRules covers the statically decidable conflict, the explicit
// set's foreign-key confinement, and the environment-lifecycle cascade the
// schema-model ADR puts in the same serialization domain.
func scenarioPresenceRules(t *testing.T, db *store.DB) {
	keys := &service.Keys{DB: db, Keyring: sharedKeyring(t, db)}
	envs := &service.Environments{DB: db, Keyring: sharedKeyring(t, db)}
	who, scope := tenantFixture(t, db, "presence")
	actor := service.LocalPrincipal(who)

	env, err := envs.Create(t.Context(), actor, scope, "prod", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Required and forbidden in the same environment is refused at
	// DECLARATION, not discovered at publish.
	conflicted := service.KeySpec{
		Name: "CONFLICTED", Classification: string(schema.Config),
		Declaration: decl(schema.Rule{Type: schema.TypeString}),
		Presence: schema.PresenceRules{
			Required:  schema.Presence{Mode: schema.PresenceExplicit, Environments: []string{env.ID}},
			Forbidden: schema.Presence{Mode: schema.PresenceAll},
		},
	}
	if _, err := keys.Create(t.Context(), actor, scope, conflicted, nil); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("a required-and-forbidden key was accepted: %v", err)
	}

	// An explicit set naming an environment outside this project is confined by
	// the composite foreign key and surfaces as the uniform conflict.
	foreign := service.KeySpec{
		Name: "FOREIGN_ENV", Classification: string(schema.Config),
		Declaration: decl(schema.Rule{Type: schema.TypeString}),
		Presence: schema.PresenceRules{
			Required:  schema.Presence{Mode: schema.PresenceExplicit, Environments: []string{"env_not_here"}},
			Forbidden: schema.Presence{Mode: schema.PresenceNone},
		},
	}
	if _, err := keys.Create(t.Context(), actor, scope, foreign, nil); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("a foreign environment id was accepted into a presence set: %v", err)
	}

	// ORDERING, forced by #51 and worth stating because it looks like a
	// fixture detail and is not: a semantic schema change MATERIALIZES every
	// environment in the project, and a key `required_in` an environment that
	// resolves to absent VETOES that materialization (mvp-boundary C2). So the
	// requirement cannot be declared before the environment can satisfy it —
	// the key is created unconstrained, the value is published, and only then
	// does the presence rule land. That is the same order an operator must
	// follow, not a test-only dance.
	required := service.KeySpec{
		Name: "REQUIRED_IN_PROD", Classification: string(schema.Config),
		Declaration: decl(schema.Rule{Type: schema.TypeString}),
		Presence:    schema.DefaultPresenceRules(),
	}
	created, err := keys.Create(t.Context(), actor, scope, required, nil)
	if err != nil {
		t.Fatal(err)
	}
	publishValue(t, db, &service.Values{DB: db, Keyring: sharedKeyring(t, db)}, actor,
		domain.Scope{Org: scope.Org, Project: scope.Project, Env: domain.EnvID(env.ID)},
		"REQUIRED_IN_PROD", "eu-west")
	if _, err := keys.UpdateDeclaration(t.Context(), actor, scope, created.ID, service.KeyDeclarationUpdate{
		Declaration: decl(schema.Rule{Type: schema.TypeString}),
		Presence: schema.PresenceRules{
			Required:  schema.Presence{Mode: schema.PresenceExplicit, Environments: []string{env.ID}},
			Forbidden: schema.Presence{Mode: schema.PresenceNone},
		},
	}, nil); err != nil {
		t.Fatal(err)
	}
	got, err := keys.Get(t.Context(), actor, scope, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Presence.Required.Environments) != 1 || got.Presence.Required.Environments[0] != env.ID {
		t.Fatalf("the explicit presence set did not persist: %+v", got.Presence)
	}

	// Deleting the environment cascades its id out of every explicit presence
	// set IN THE SAME TRANSACTION. Without the cascade the delete would be
	// refused by the foreign key, which is why a passing delete IS the
	// assertion — plus the read below, which proves nothing dangles.
	_, revisionBefore, err := keys.List(t.Context(), actor, scope)
	if err != nil {
		t.Fatal(err)
	}
	envScope := scope
	envScope.Env = domain.EnvID(env.ID)
	if err := envs.Delete(t.Context(), actor, envScope); err != nil {
		t.Fatalf("environment delete did not cascade its presence rows: %v", err)
	}
	after, err := keys.Get(t.Context(), actor, scope, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Presence.Required.Environments) != 0 {
		t.Fatalf("a deleted environment survives in a presence set: %+v", after.Presence)
	}
	// The cascade emptied the explicit set, so the MODE collapsed with it:
	// `explicit` with zero environments is a state CheckPresence refuses, and a
	// stored declaration that cannot be round-tripped is a declaration nobody
	// can edit again.
	if after.Presence.Required.Mode != schema.PresenceNone {
		t.Fatalf("an emptied explicit set kept mode %q", after.Presence.Required.Mode)
	}
	if _, err := keys.UpdateDeclaration(t.Context(), actor, scope, created.ID,
		service.KeyDeclarationUpdate{Declaration: after.Declaration, Presence: after.Presence}, nil); err != nil {
		t.Fatalf("the post-cascade declaration cannot be saved back: %v", err)
	}
	// The cascade rewrote catalogue content, so the catalogue revision moved.
	if _, revisionAfter, err := keys.List(t.Context(), actor, scope); err != nil || revisionAfter <= revisionBefore {
		t.Fatalf("the presence cascade left the schema revision at %d (was %d, err %v)", revisionAfter, revisionBefore, err)
	}
	if err := keys.Delete(t.Context(), actor, scope, created.ID); err != nil {
		t.Fatal(err)
	}
}

// scenarioKeyGroups covers the declaration side of key groups: at most one
// group per key, the statically decidable all-or-none conflict, the inert
// flag, and the delete that dissolves a coupling without deleting what it
// coupled.
func scenarioKeyGroups(t *testing.T, db *store.DB) {
	keys := &service.Keys{DB: db, Keyring: sharedKeyring(t, db)}
	groups := &service.KeyGroups{DB: db, Keyring: sharedKeyring(t, db)}
	envs := &service.Environments{DB: db, Keyring: sharedKeyring(t, db)}
	who, scope := tenantFixture(t, db, "groups")
	actor := service.LocalPrincipal(who)

	env, err := envs.Create(t.Context(), actor, scope, "prod", nil)
	if err != nil {
		t.Fatal(err)
	}
	group, err := groups.Create(t.Context(), actor, scope, "database", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !group.Inert {
		t.Fatal("a brand-new group with no members is not flagged inert")
	}

	// THE ORDER OF THESE TWO IS LOAD-BEARING under #51, and the reason is not a
	// fixture detail. The pair asserted here is the same pair as before — one
	// member required where another is forbidden — but the FORBIDDEN one is
	// declared first now. A semantic schema change materializes every
	// environment, and a key `required_in` an environment that resolves to
	// absent vetoes that materialization; declaring the required member first
	// would abort on its own creation and never reach the static check the
	// scenario is about. Forbidden-and-absent is a valid environment, so the
	// first declaration lands and the second is refused at DECLARATION time,
	// before anything materializes — which is exactly the "statically decidable
	// conflict" the schema-model ADR requires rejected there rather than at publish.
	user, err := keys.Create(t.Context(), actor, scope, service.KeySpec{
		Name: "DB_USER", Classification: string(schema.Config),
		Declaration: decl(schema.Rule{Type: schema.TypeString}),
		Presence: schema.PresenceRules{
			Required:  schema.Presence{Mode: schema.PresenceNone},
			Forbidden: schema.Presence{Mode: schema.PresenceExplicit, Environments: []string{env.ID}},
		},
		GroupID: group.ID,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// A second member REQUIRED where the first is forbidden breaks all-or-none
	// presence statically, so the membership is refused at declaration.
	_, err = keys.Create(t.Context(), actor, scope, service.KeySpec{
		Name: "DB_PASSWORD", Classification: string(schema.Secret),
		Declaration: decl(schema.Rule{Type: schema.TypeString}),
		Presence: schema.PresenceRules{
			Required:  schema.Presence{Mode: schema.PresenceExplicit, Environments: []string{env.ID}},
			Forbidden: schema.Presence{Mode: schema.PresenceNone},
		},
		GroupID: group.ID,
	}, nil)
	if !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("a group whose members can never both resolve was accepted: %v", err)
	}
	if !strings.Contains(err.Error(), "DB_USER") {
		t.Errorf("the refusal names neither member: %v", err)
	}

	// Declared unconstrained: this member is DELETED further down, and a key
	// holding a published value refuses deletion (#50). The all-or-none STATIC
	// conflict is already asserted by the refused variant above, so nothing is
	// lost by leaving this one's presence at the default.
	password, err := keys.Create(t.Context(), actor, scope, service.KeySpec{
		Name: "DB_PASSWORD", Classification: string(schema.Secret),
		Declaration: decl(schema.Rule{Type: schema.TypeString}),
		Presence:    schema.DefaultPresenceRules(),
		GroupID:     group.ID,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	view, err := groups.Get(t.Context(), actor, scope, group.ID)
	if err != nil {
		t.Fatal(err)
	}
	if view.Inert || len(view.Members) != 2 {
		t.Fatalf("group membership = %+v, want two members and not inert", view)
	}

	// Setting the membership a key already has is an idempotent success: it
	// writes nothing and moves no revision.
	_, revisionBeforeNoop, err := keys.List(t.Context(), actor, scope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keys.SetGroup(t.Context(), actor, scope, password.ID, group.ID); err != nil {
		t.Fatalf("re-setting an unchanged group membership was refused: %v", err)
	}
	if _, revisionAfterNoop, err := keys.List(t.Context(), actor, scope); err != nil || revisionAfterNoop != revisionBeforeNoop {
		t.Fatalf("a no-op membership set moved the revision %d -> %d (err %v)", revisionBeforeNoop, revisionAfterNoop, err)
	}

	// An unknown group is the uniform nonexistent outcome, not a distinct
	// error: a group id from another project is exactly as unreachable.
	if _, err := keys.SetGroup(t.Context(), actor, scope, password.ID, "kgr_elsewhere"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("an unknown group id answered %v", err)
	}

	// Deleting a key cascades it out of its group, leaving the group inert
	// rather than deleted.
	if err := keys.Delete(t.Context(), actor, scope, password.ID); err != nil {
		t.Fatal(err)
	}
	view, err = groups.Get(t.Context(), actor, scope, group.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !view.Inert || len(view.Members) != 1 {
		t.Fatalf("after deleting a member the group is %+v, want one member and inert", view)
	}

	// Deleting the group releases its members; it never deletes them.
	if err := groups.Delete(t.Context(), actor, scope, group.ID); err != nil {
		t.Fatal(err)
	}
	survivor, err := keys.Get(t.Context(), actor, scope, user.ID)
	if err != nil {
		t.Fatalf("deleting a group deleted a key it coupled: %v", err)
	}
	if survivor.GroupID != "" {
		t.Fatalf("a deleted group is still named by %q", survivor.Name)
	}
	if err := keys.Delete(t.Context(), actor, scope, user.ID); err != nil {
		t.Fatal(err)
	}
}

// GateAttemptsPerMinuteForTest mirrors the service's allowance so the loops
// above scale with it rather than with a number that can drift from it.
const GateAttemptsPerMinuteForTest = service.GateAttemptsPerMinute
