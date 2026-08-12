package conformance

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Dunky13/hikyo/internal/audit"
	"github.com/Dunky13/hikyo/internal/crypto"
	"github.com/Dunky13/hikyo/internal/domain"
	"github.com/Dunky13/hikyo/internal/schema"
	"github.com/Dunky13/hikyo/internal/service"
	"github.com/Dunky13/hikyo/internal/store"
	"github.com/Dunky13/hikyo/internal/store/keyring"
)

// The flat value model's cross-engine acceptance scenarios (#50,
// mvp-boundary C2's value portion). Every one runs through the service layer,
// so tx, authorize(), the envelope and both engines' SQL are under test.

func init() {
	corpus = append(corpus,
		scenario{"value_set_delivers_absent_delivers_nothing", scenarioValueDelivery},
		scenario{"value_declare_into_environments", scenarioValueDeclare},
		scenario{"value_copy_runs_the_locked_formula", scenarioValueCopyFormula},
		scenario{"value_clone_at_creation", scenarioValueClone},
		scenario{"values_diff_between_environments", scenarioValueDiff},
		scenario{"value_ciphertext_is_row_bound", scenarioValueCiphertext},
	)
}

// The keyring hierarchy is minted ONCE per datastore, under the root of
// whichever scenario loads it first, so every scenario in this package shares
// one root. Without this the second loader is refused with
// ErrRootKeyMismatch — which is the keyring behaving correctly.
var (
	rootMu    sync.Mutex
	rootBytes = map[*store.DB][]byte{}
)

func sharedRoot(t *testing.T, db *store.DB) []byte {
	t.Helper()
	rootMu.Lock()
	defer rootMu.Unlock()
	if have, ok := rootBytes[db]; ok {
		return bytes.Clone(have)
	}
	root := make([]byte, crypto.KeySize)
	if _, err := rand.Read(root); err != nil {
		t.Fatal(err)
	}
	rootBytes[db] = bytes.Clone(root)
	return root
}

func sharedKeyring(t *testing.T, db *store.DB) *crypto.Keyring {
	t.Helper()
	kr, err := crypto.LoadKeyring(t.Context(), &keyring.Store{DB: db}, sharedRoot(t, db))
	if err != nil {
		t.Fatal(err)
	}
	return kr
}

// valueFixture is tenantFixture plus the capabilities the value surface needs.
// tenantFixture seeds manage-projects, definitions-edit, read and edit at ORG
// scope; a value write is `edit ∧ publish` and a copy adds `reveal`.
func valueFixture(t *testing.T, db *store.DB, label string) (domain.PrincipalID, domain.Scope, *service.Values, *service.Environments, *service.Keys) {
	t.Helper()
	who, scope := tenantFixture(t, db, label)
	grantOrg(t, db, who, scope.Org, label, "publish", "reveal")
	kr := sharedKeyring(t, db)
	return who, scope,
		&service.Values{DB: db, Keyring: kr},
		&service.Environments{DB: db, Keyring: kr},
		&service.Keys{DB: db}
}

// grantOrg seeds org-scoped grants for an existing principal.
func grantOrg(t *testing.T, db *store.DB, who domain.PrincipalID, org domain.OrgID, label string, caps ...string) {
	t.Helper()
	stmts := make([]string, 0, len(caps))
	for i, capability := range caps {
		stmts = append(stmts, fmt.Sprintf(
			`INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at)
			 VALUES ('grt_%s_%s_%d', '%s', '%s', '%s', NULL, NULL, '2026-01-01T00:00:00Z')`,
			label, capability, i, who, capability, org))
	}
	seed(t, db, stmts)
}

// newPrincipal seeds a bare principal plus the named capabilities, each at the
// scope given. It is how the formula scenarios build a caller who holds three
// of the four legs and nothing more.
func newPrincipal(t *testing.T, db *store.DB, id string, grants []grantSpec) domain.PrincipalID {
	t.Helper()
	stmts := []string{
		`INSERT INTO principals (id, kind, created_at) VALUES ('` + id + `', 'human', '2026-01-01T00:00:00Z')`,
	}
	for i, g := range grants {
		stmts = append(stmts, fmt.Sprintf(
			`INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at)
			 VALUES ('grt_%s_%d', '%s', '%s', %s, %s, %s, '2026-01-01T00:00:00Z')`,
			id, i, id, g.capability, sqlText(string(g.scope.Org)), sqlText(string(g.scope.Project)), sqlText(string(g.scope.Env))))
	}
	seed(t, db, stmts)
	return domain.PrincipalID(id)
}

type grantSpec struct {
	capability string
	scope      domain.Scope
}

func sqlText(s string) string {
	if s == "" {
		return "NULL"
	}
	return "'" + s + "'"
}

func mustEnv(t *testing.T, envs *service.Environments, actor service.Actor, scope domain.Scope, name string) domain.Scope {
	t.Helper()
	env, err := envs.Create(t.Context(), actor, scope, name)
	if err != nil {
		t.Fatal(err)
	}
	out := scope
	out.Env = domain.EnvID(env.ID)
	return out
}

func mustKey(t *testing.T, keys *service.Keys, actor service.Actor, scope domain.Scope, name, classification string, presence schema.PresenceRules) service.Key {
	t.Helper()
	key, err := keys.Create(t.Context(), actor, scope, service.KeySpec{
		Name: name, Classification: classification,
		Declaration: decl(schema.Rule{Type: schema.TypeString}),
		Presence:    presence,
	})
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// scenarioValueDelivery is C2's first clause: a `set` entry delivers, `absent`
// delivers NOTHING, and no fallback source exists.
//
// The absence half is the one that needs a real assertion rather than a
// tautology: after a clear, the key is still DECLARED, still listed, and still
// carries no value — there is no project default, no base environment and no
// other layer for it to fall back to, because none of those exist.
func scenarioValueDelivery(t *testing.T, db *store.DB) {
	who, scope, values, envs, keys := valueFixture(t, db, "delivery")
	actor := service.LocalPrincipal(who)
	dev := mustEnv(t, envs, actor, scope, "dev")
	prod := mustEnv(t, envs, actor, scope, "prod")
	mustKey(t, keys, actor, scope, "API_URL", string(schema.Config), schema.DefaultPresenceRules())

	if _, err := values.Set(t.Context(), actor, dev, "API_URL", "https://dev.example"); err != nil {
		t.Fatal(err)
	}
	cell, err := values.Get(t.Context(), actor, dev, "API_URL", false)
	if err != nil {
		t.Fatal(err)
	}
	if !cell.Set || cell.Value != "https://dev.example" {
		t.Fatalf("set did not deliver: %+v", cell)
	}
	// The same key in the OTHER environment: absent, and absent means nothing
	// is delivered — not the dev value, not a default, not an empty string
	// standing in for one.
	other, err := values.Get(t.Context(), actor, prod, "API_URL", false)
	if err != nil {
		t.Fatal(err)
	}
	if other.Set || other.Value != "" {
		t.Fatalf("an environment with no entry delivered something: %+v", other)
	}
	// A value written in one environment is INDEPENDENT: writing prod does not
	// touch dev, and no relationship is created either way.
	if _, err := values.Set(t.Context(), actor, prod, "API_URL", "https://prod.example"); err != nil {
		t.Fatal(err)
	}
	if cell, err = values.Get(t.Context(), actor, dev, "API_URL", false); err != nil || cell.Value != "https://dev.example" {
		t.Fatalf("dev moved when prod was written: %+v, %v", cell, err)
	}

	// Clearing takes the cell to `absent`. There is nothing underneath.
	if err := values.Clear(t.Context(), actor, dev, "API_URL"); err != nil {
		t.Fatal(err)
	}
	cleared, err := values.Get(t.Context(), actor, dev, "API_URL", false)
	if err != nil {
		t.Fatal(err)
	}
	if cleared.Set || cleared.Value != "" {
		t.Fatalf("a cleared cell still delivers: %+v", cleared)
	}
	// Clearing twice is not an error: `absent` is a state, and the caller
	// asked for that state.
	if err := values.Clear(t.Context(), actor, dev, "API_URL"); err != nil {
		t.Fatalf("clearing an absent cell: %v", err)
	}
	// …and it emits NOTHING the second time: value.cleared records a transition,
	// and the no-op clear transitions nothing. Exactly one event for the two
	// clears — the real one — never a second for a change that never happened.
	if n := auditEventCount(t, db, string(dev.Env), string(audit.EventValueCleared)); n != 1 {
		t.Fatalf("clearing an absent cell emitted a spurious value.cleared event: count = %d, want 1", n)
	}

	// The list view is the resolved snapshot: every declared key, each `set`
	// or `absent`, with no third state anywhere in it.
	list, err := values.List(t.Context(), actor, dev, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Set {
		t.Fatalf("resolved view after clear: %+v", list)
	}

	// A value for a key nobody declared is a KEY CREATION, which is a
	// different act somewhere else. Never an auto-declare.
	if _, err := values.Set(t.Context(), actor, dev, "NEVER_DECLARED", "x"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("an undeclared key accepted a value: %v", err)
	}
	// Validation runs on the write, because in this slice the write IS what
	// the environment delivers.
	strict := mustKey(t, keys, actor, scope, "PORT", string(schema.Config), schema.DefaultPresenceRules())
	_ = strict
	if _, err := values.Set(t.Context(), actor, dev, "PORT", strings.Repeat("x", schema.MaxValueBytes+1)); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("an over-budget value was accepted: %v", err)
	}
}

// scenarioValueDeclare is declare-into-environments: one SUPPLIED plaintext
// into several environments at once, atomic, and authorized per destination.
func scenarioValueDeclare(t *testing.T, db *store.DB) {
	who, scope, values, envs, keys := valueFixture(t, db, "declare")
	actor := service.LocalPrincipal(who)
	dev := mustEnv(t, envs, actor, scope, "dev")
	staging := mustEnv(t, envs, actor, scope, "staging")
	prod := mustEnv(t, envs, actor, scope, "prod")
	mustKey(t, keys, actor, scope, "LOG_LEVEL", string(schema.Config), schema.DefaultPresenceRules())

	ids := []string{string(dev.Env), string(staging.Env), string(prod.Env)}
	cells, err := values.Declare(t.Context(), actor, scope, ids, "LOG_LEVEL", "info")
	if err != nil {
		t.Fatal(err)
	}
	if len(cells) != 3 {
		t.Fatalf("declare into three environments returned %d cells", len(cells))
	}
	for _, env := range []domain.Scope{dev, staging, prod} {
		cell, err := values.Get(t.Context(), actor, env, "LOG_LEVEL", false)
		if err != nil {
			t.Fatal(err)
		}
		if !cell.Set || cell.Value != "info" {
			t.Fatalf("declare missed %s: %+v", env.Env, cell)
		}
	}
	// Every copy is independent: editing one leaves the others alone.
	if _, err := values.Set(t.Context(), actor, dev, "LOG_LEVEL", "debug"); err != nil {
		t.Fatal(err)
	}
	cell, err := values.Get(t.Context(), actor, prod, "LOG_LEVEL", false)
	if err != nil || cell.Value != "info" {
		t.Fatalf("editing dev moved prod: %+v, %v", cell, err)
	}

	// Authorized per destination, and ALL-OR-NOTHING: a principal holding the
	// write formula on two of three environments writes into none of them.
	partial := newPrincipal(t, db, "usr_declare_partial_"+string(scope.Project), []grantSpec{
		{"read", domain.Scope{Org: scope.Org}},
		{"edit", domain.Scope{Org: scope.Org}},
		{"publish", dev},
		{"publish", staging},
	})
	if _, err := values.Declare(t.Context(), service.LocalPrincipal(partial), scope, ids, "LOG_LEVEL", "trace"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("a partial-authority declare was not refused uniformly: %v", err)
	}

	// A duplicated environment is refused, NAMING it: one logical cell asked for
	// twice would double the write, the event and the response row.
	if _, err := values.Declare(t.Context(), actor, scope,
		[]string{string(dev.Env), string(dev.Env)}, "LOG_LEVEL", "x"); err == nil ||
		!errors.Is(err, domain.ErrInvalid) || !strings.Contains(err.Error(), string(dev.Env)) {
		t.Fatalf("a duplicated declare environment was not refused naming it: %v", err)
	}
	for _, env := range []domain.Scope{dev, staging} {
		cell, err := values.Get(t.Context(), actor, env, "LOG_LEVEL", false)
		if err != nil {
			t.Fatal(err)
		}
		if cell.Value == "trace" {
			t.Fatalf("a refused declare left a value behind in %s", env.Env)
		}
	}
}

// scenarioValueCopyFormula is C2's copy clause: copy/bulk-apply run the LOCKED
// formula, evaluated per side and per classification.
func scenarioValueCopyFormula(t *testing.T, db *store.DB) {
	who, scope, values, envs, keys := valueFixture(t, db, "copyformula")
	actor := service.LocalPrincipal(who)
	dev := mustEnv(t, envs, actor, scope, "dev")
	prod := mustEnv(t, envs, actor, scope, "prod")
	mustKey(t, keys, actor, scope, "TOKEN", string(schema.Secret), schema.DefaultPresenceRules())
	mustKey(t, keys, actor, scope, "REGION", string(schema.Config), schema.DefaultPresenceRules())
	for name, value := range map[string]string{"TOKEN": "s3cret-material", "REGION": "eu-west"} {
		if _, err := values.Set(t.Context(), actor, dev, name, value); err != nil {
			t.Fatal(err)
		}
	}

	base := []grantSpec{
		{"read", domain.Scope{Org: scope.Org}},
		{"edit", domain.Scope{Org: scope.Org}},
	}
	// No `reveal` on the SOURCE: the source-material gate refuses, uniformly.
	noSourceReveal := newPrincipal(t, db, "usr_copy_nosrc_"+string(scope.Project), append(append([]grantSpec{}, base...),
		grantSpec{"publish", prod}, grantSpec{"reveal", prod}))
	req := service.CopyRequest{
		SourceEnvironmentID:       string(dev.Env),
		KeyNames:                  []string{"TOKEN"},
		DestinationEnvironmentIDs: []string{string(prod.Env)},
	}
	if _, err := values.Copy(t.Context(), service.LocalPrincipal(noSourceReveal), scope, req); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("copy without reveal(source) was not refused uniformly: %v", err)
	}
	// No `reveal` on the DESTINATION: the destination half refuses.
	noDestReveal := newPrincipal(t, db, "usr_copy_nodst_"+string(scope.Project), append(append([]grantSpec{}, base...),
		grantSpec{"reveal", dev}, grantSpec{"publish", prod}))
	if _, err := values.Copy(t.Context(), service.LocalPrincipal(noDestReveal), scope, req); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("copy without reveal(destination) was not refused uniformly: %v", err)
	}
	// No `publish` on the DESTINATION: same.
	noDestPublish := newPrincipal(t, db, "usr_copy_nopub_"+string(scope.Project), append(append([]grantSpec{}, base...),
		grantSpec{"reveal", domain.Scope{Org: scope.Org}}))
	if _, err := values.Copy(t.Context(), service.LocalPrincipal(noDestPublish), scope, req); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("copy without publish(destination) was not refused uniformly: %v", err)
	}
	// Nothing landed under any of the three refusals.
	if cell, err := values.Get(t.Context(), actor, prod, "TOKEN", true); err != nil || cell.Set {
		t.Fatalf("a refused copy left material behind: %+v, %v", cell, err)
	}

	// `config` material copies without any reveal at all — classification is
	// the sensitivity boundary, and a value every reader of the destination
	// could already read discloses nothing by moving.
	configOnly := newPrincipal(t, db, "usr_copy_config_"+string(scope.Project), append(append([]grantSpec{}, base...),
		grantSpec{"publish", prod}))
	if _, err := values.Copy(t.Context(), service.LocalPrincipal(configOnly), scope, service.CopyRequest{
		SourceEnvironmentID:       string(dev.Env),
		KeyNames:                  []string{"REGION"},
		DestinationEnvironmentIDs: []string{string(prod.Env)},
	}); err != nil {
		t.Fatalf("a config-only copy under read+publish was refused: %v", err)
	}
	if cell, err := values.Get(t.Context(), actor, prod, "REGION", false); err != nil || cell.Value != "eu-west" {
		t.Fatalf("config copy did not land: %+v, %v", cell, err)
	}

	// The full formula: the copy lands, and the copy is an INDEPENDENT value.
	if _, err := values.Copy(t.Context(), actor, scope, req); err != nil {
		t.Fatal(err)
	}
	copied, err := values.Get(t.Context(), actor, prod, "TOKEN", true)
	if err != nil || copied.Value != "s3cret-material" {
		t.Fatalf("copy did not land: %+v, %v", copied, err)
	}
	if _, err := values.Set(t.Context(), actor, dev, "TOKEN", "rotated"); err != nil {
		t.Fatal(err)
	}
	after, err := values.Get(t.Context(), actor, prod, "TOKEN", true)
	if err != nil || after.Value != "s3cret-material" {
		t.Fatalf("editing the source changed the copy: %+v, %v", after, err)
	}
	// The ciphertexts differ even where the plaintext does not: the row id and
	// the environment are in the AAD, so nothing was copied byte-for-byte.
	devRow := ciphertextOf(t, db, string(dev.Env), "TOKEN")
	prodRow := ciphertextOf(t, db, string(prod.Env), "TOKEN")
	if bytes.Equal(devRow, prodRow) {
		t.Fatal("a copy reused the source ciphertext")
	}

	// Copying an absent key is a refusal, never a silent no-op.
	if _, err := values.Copy(t.Context(), actor, scope, service.CopyRequest{
		SourceEnvironmentID:       string(prod.Env),
		KeyNames:                  []string{"NOT_THERE"},
		DestinationEnvironmentIDs: []string{string(dev.Env)},
	}); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("copying an undeclared key: %v", err)
	}

	// Duplicate items are refused, NAMING the duplicate: a repeated key or a
	// repeated destination is one logical cell requested twice.
	if _, err := values.Copy(t.Context(), actor, scope, service.CopyRequest{
		SourceEnvironmentID:       string(dev.Env),
		KeyNames:                  []string{"TOKEN", "TOKEN"},
		DestinationEnvironmentIDs: []string{string(prod.Env)},
	}); err == nil || !errors.Is(err, domain.ErrInvalid) || !strings.Contains(err.Error(), "TOKEN") {
		t.Fatalf("a duplicated copy key was not refused naming it: %v", err)
	}
	if _, err := values.Copy(t.Context(), actor, scope, service.CopyRequest{
		SourceEnvironmentID:       string(dev.Env),
		KeyNames:                  []string{"TOKEN"},
		DestinationEnvironmentIDs: []string{string(prod.Env), string(prod.Env)},
	}); err == nil || !errors.Is(err, domain.ErrInvalid) || !strings.Contains(err.Error(), string(prod.Env)) {
		t.Fatalf("a duplicated copy destination was not refused naming it: %v", err)
	}
}

// scenarioValueClone is C2's clone clause: clone-at-creation copies what the
// caller's authority allows, ABORTS naming the keys where a `mode: all`
// required secret would be left absent, and enumerates the uncopied secrets
// otherwise.
func scenarioValueClone(t *testing.T, db *store.DB) {
	who, scope, values, envs, keys := valueFixture(t, db, "clone")
	actor := service.LocalPrincipal(who)
	source := mustEnv(t, envs, actor, scope, "source")
	mustKey(t, keys, actor, scope, "REGION", string(schema.Config), schema.DefaultPresenceRules())
	mustKey(t, keys, actor, scope, "OPTIONAL_TOKEN", string(schema.Secret), schema.DefaultPresenceRules())
	required := schema.PresenceRules{
		Required:  schema.Presence{Mode: schema.PresenceAll},
		Forbidden: schema.Presence{Mode: schema.PresenceNone},
	}
	mustKey(t, keys, actor, scope, "REQUIRED_TOKEN", string(schema.Secret), required)
	for name, value := range map[string]string{
		"REGION": "eu-west", "OPTIONAL_TOKEN": "optional-material", "REQUIRED_TOKEN": "required-material",
	} {
		if _, err := values.Set(t.Context(), actor, source, name, value); err != nil {
			t.Fatal(err)
		}
	}

	// A caller with no `reveal` anywhere: `config` copies freely, both secrets
	// are gate-blocked, and REQUIRED_TOKEN is `required_in` every environment
	// under a `mode: all` rule — so the creation ABORTS, naming it.
	noReveal := newPrincipal(t, db, "usr_clone_noreveal_"+string(scope.Project), []grantSpec{
		{"read", domain.Scope{Org: scope.Org}},
		{"edit", domain.Scope{Org: scope.Org}},
		{"publish", domain.Scope{Org: scope.Org}},
		{"definitions-edit", domain.Scope{Org: scope.Org}},
	})
	_, _, err := envs.Clone(t.Context(), service.LocalPrincipal(noReveal), scope, "clone-aborted", string(source.Env))
	if err == nil || !strings.Contains(err.Error(), "REQUIRED_TOKEN") {
		t.Fatalf("a clone stranding a required secret did not abort naming it: %v", err)
	}
	if !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("clone abort sentinel: %v", err)
	}
	// The abort is a real abort: no environment was created.
	list, err := envs.List(t.Context(), actor, scope)
	if err != nil {
		t.Fatal(err)
	}
	for _, env := range list {
		if env.Name == "clone-aborted" {
			t.Fatal("an aborted clone left the environment behind")
		}
	}

	// Same caller, once REQUIRED_TOKEN is no longer required everywhere:
	// creation proceeds, `config` lands, and the uncopied secrets come back
	// enumerated BY NAME rather than silently absent.
	if _, err := keys.UpdateDeclaration(t.Context(), actor, scope, keyIDByName(t, keys, actor, scope, "REQUIRED_TOKEN"),
		service.KeyDeclarationUpdate{
			Declaration: decl(schema.Rule{Type: schema.TypeString}),
			Presence:    schema.DefaultPresenceRules(),
		}); err != nil {
		t.Fatal(err)
	}
	env, result, err := envs.Clone(t.Context(), service.LocalPrincipal(noReveal), scope, "clone-partial", string(source.Env))
	if err != nil {
		t.Fatalf("clone with a blocked source gate should proceed: %v", err)
	}
	if len(result.UncopiedSecrets) != 2 ||
		result.UncopiedSecrets[0] != "OPTIONAL_TOKEN" || result.UncopiedSecrets[1] != "REQUIRED_TOKEN" {
		t.Fatalf("uncopied secrets not enumerated by name: %+v", result)
	}
	partial := scope
	partial.Env = domain.EnvID(env.ID)
	if cell, err := values.Get(t.Context(), actor, partial, "REGION", false); err != nil || cell.Value != "eu-west" {
		t.Fatalf("config did not copy freely: %+v, %v", cell, err)
	}
	if cell, err := values.Get(t.Context(), actor, partial, "OPTIONAL_TOKEN", true); err != nil || cell.Set {
		t.Fatalf("a gate-blocked secret landed anyway: %+v, %v", cell, err)
	}

	// The full-authority clone takes everything, re-sealed per row.
	full, result, err := envs.Clone(t.Context(), actor, scope, "clone-full", string(source.Env))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.UncopiedSecrets) != 0 || len(result.Copied) != 3 {
		t.Fatalf("full clone: %+v", result)
	}
	fullScope := scope
	fullScope.Env = domain.EnvID(full.ID)
	cell, err := values.Get(t.Context(), actor, fullScope, "REQUIRED_TOKEN", true)
	if err != nil || cell.Value != "required-material" {
		t.Fatalf("clone did not carry the secret: %+v, %v", cell, err)
	}

	// The source-absent half of the abort (the BLOCKER): a `mode: all` required
	// SECRET the source never held would leave the new environment born invalid,
	// and this actor holds full reveal — so the source gate PASSES and the abort
	// is reached purely because the secret is absent at source, not because a
	// gate blocked it. Added after the clone-full block so it does not disturb
	// that block's Copied/UncopiedSecrets counts.
	mustKey(t, keys, actor, scope, "NEVER_SET_TOKEN", string(schema.Secret), required)
	// This actor holds full reveal, so the source gate PASSES: without the
	// plan/open split the clone would OPEN the source secrets and write their
	// disclosure.value_revealed rows before the abort rolled the transaction back,
	// violating the OpValueCopySource promise (one durable event per secret opened).
	//
	// TWO assertions prove the trail was never written rather than
	// written-and-rolled-back:
	//
	//  1. The disclosure-row count before == after. This is the LITERAL check, but
	//     it cannot distinguish the regression on its own: the disclosure rows are
	//     written in the clone's own transaction, so a buggy open-before-abort
	//     rolls them back too and the count also nets zero. It becomes a real guard
	//     only if audit ever moves out of the business transaction.
	//  2. The DISCRIMINATOR: a source secret whose ciphertext is corrupted. The
	//     fixed preflight aborts without decrypting anything, so the abort still
	//     fires (assertions below pass). The buggy order decrypts first, hits
	//     ErrDecrypt, and fails with a fault instead of the abort — turning the
	//     abort assertions red. This is what actually catches the regression.
	corruptValueCiphertext(t, db, string(source.Env), keyIDByName(t, keys, actor, scope, "REQUIRED_TOKEN"))
	disclosuresBefore := disclosureEvents(t, db, string(source.Env))
	_, _, err = envs.Clone(t.Context(), actor, scope, "clone-stranded", string(source.Env))
	if err == nil || !strings.Contains(err.Error(), "NEVER_SET_TOKEN") {
		t.Fatalf("a clone stranding a source-absent required secret did not abort naming it: %v", err)
	}
	if !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("source-absent clone abort sentinel: %v", err)
	}
	if disclosuresAfter := disclosureEvents(t, db, string(source.Env)); disclosuresAfter != disclosuresBefore {
		t.Fatalf("aborted clone wrote %d disclosure row(s) then rolled them back (before %d, after %d); "+
			"the preflight must abort before opening any secret",
			disclosuresAfter-disclosuresBefore, disclosuresBefore, disclosuresAfter)
	}
	// The abort exposes the stranded key as a caller-safe detail, which is what
	// carries it to the wire (server errorBody honours detail for bad_request).
	var sd interface{ SafeDetail() string }
	if !errors.As(err, &sd) || !strings.Contains(sd.SafeDetail(), "NEVER_SET_TOKEN") {
		t.Fatalf("clone abort does not expose the stranded key as a safe detail: %v", err)
	}
	// A real abort: no environment was created.
	after, err := envs.List(t.Context(), actor, scope)
	if err != nil {
		t.Fatal(err)
	}
	for _, env := range after {
		if env.Name == "clone-stranded" {
			t.Fatal("an aborted source-absent clone left the environment behind")
		}
	}
}

// scenarioValueDiff is the on-demand comparison under #11's oracle rules:
// write-presence without the reveal gate, plaintext only with it.
func scenarioValueDiff(t *testing.T, db *store.DB) {
	who, scope, values, envs, keys := valueFixture(t, db, "diff")
	actor := service.LocalPrincipal(who)
	dev := mustEnv(t, envs, actor, scope, "dev")
	prod := mustEnv(t, envs, actor, scope, "prod")
	mustKey(t, keys, actor, scope, "REGION", string(schema.Config), schema.DefaultPresenceRules())
	mustKey(t, keys, actor, scope, "TOKEN", string(schema.Secret), schema.DefaultPresenceRules())
	mustKey(t, keys, actor, scope, "ONLY_DEV", string(schema.Config), schema.DefaultPresenceRules())
	for name, value := range map[string]string{"REGION": "eu-west", "TOKEN": "same", "ONLY_DEV": "yes"} {
		if _, err := values.Set(t.Context(), actor, dev, name, value); err != nil {
			t.Fatal(err)
		}
	}
	for name, value := range map[string]string{"REGION": "us-east", "TOKEN": "same"} {
		if _, err := values.Set(t.Context(), actor, prod, name, value); err != nil {
			t.Fatal(err)
		}
	}

	// Without the gate: `config` compares by value, `secret` reports
	// write-presence only and NO equality verdict — "are these two secrets the
	// same?" is itself material.
	rows, err := values.Diff(t.Context(), actor, scope, string(dev.Env), string(prod.Env), false)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]service.DiffRow{}
	for _, row := range rows {
		byName[row.Name] = row
	}
	if row := byName["REGION"]; row.Equal == nil || *row.Equal {
		t.Fatalf("config diff did not report a difference: %+v", row)
	}
	if row := byName["ONLY_DEV"]; row.Equal == nil || *row.Equal || row.Right.Set {
		t.Fatalf("presence difference not reported: %+v", row)
	}
	if row := byName["TOKEN"]; row.Equal != nil || row.Left.Value != "" || row.Right.Value != "" {
		t.Fatalf("an ungated diff disclosed secret material or its equality: %+v", row)
	}
	if row := byName["TOKEN"]; !row.Left.Set || !row.Right.Set {
		t.Fatalf("write-presence missing from an ungated diff: %+v", row)
	}

	// With the gate: plaintext, and therefore equality.
	revealed, err := values.Diff(t.Context(), actor, scope, string(dev.Env), string(prod.Env), true)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range revealed {
		if row.Name != "TOKEN" {
			continue
		}
		if row.Equal == nil || !*row.Equal || row.Left.Value != "same" {
			t.Fatalf("a gated diff did not disclose: %+v", row)
		}
	}
	// One disclosure event per key per side — never one row for the whole diff.
	if disclosureEvents(t, db, string(dev.Env)) == 0 {
		t.Fatal("a gated diff wrote no disclosure event")
	}

	// A caller without `reveal` cannot ask for one: the refusal is uniform.
	reader := newPrincipal(t, db, "usr_diff_reader_"+string(scope.Project), []grantSpec{
		{"read", domain.Scope{Org: scope.Org}},
	})
	if _, err := values.Diff(t.Context(), service.LocalPrincipal(reader), scope,
		string(dev.Env), string(prod.Env), true); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("a reveal-less gated diff was not refused uniformly: %v", err)
	}
	// …but the presence-only diff is theirs by right.
	if _, err := values.Diff(t.Context(), service.LocalPrincipal(reader), scope,
		string(dev.Env), string(prod.Env), false); err != nil {
		t.Fatalf("a presence-only diff under `read` was refused: %v", err)
	}
}

// scenarioValueCiphertext proves the storage properties the encryption ADR
// fixes: nothing at rest is plaintext, and a ciphertext is decryptable at
// exactly one row — transplanting it to another row, key or environment fails.
func scenarioValueCiphertext(t *testing.T, db *store.DB) {
	who, scope, values, envs, keys := valueFixture(t, db, "ciphertext")
	actor := service.LocalPrincipal(who)
	dev := mustEnv(t, envs, actor, scope, "dev")
	prod := mustEnv(t, envs, actor, scope, "prod")
	mustKey(t, keys, actor, scope, "TOKEN", string(schema.Secret), schema.DefaultPresenceRules())
	const plaintext = "known-plaintext-row-bound"
	if _, err := values.Set(t.Context(), actor, dev, "TOKEN", plaintext); err != nil {
		t.Fatal(err)
	}
	stored := ciphertextOf(t, db, string(dev.Env), "TOKEN")
	if bytes.Contains(stored, []byte(plaintext)) {
		t.Fatal("the stored value contains its plaintext")
	}

	// Rewriting the same cell with the same plaintext mints a NEW row id — the
	// id is AAD-bound, so it is never reused — and therefore new ciphertext.
	before := valueRowID(t, db, string(dev.Env), "TOKEN")
	if _, err := values.Set(t.Context(), actor, dev, "TOKEN", plaintext); err != nil {
		t.Fatal(err)
	}
	if after := valueRowID(t, db, string(dev.Env), "TOKEN"); after == before {
		t.Fatal("a rewrite reused the row id an AAD is bound to")
	}

	// Transplant resistance, cross-ENVIRONMENT (the flat-model amendment to the
	// encryption ADR): moving the ciphertext onto the same key's row in another
	// environment makes it undecryptable, so the disclosure path fails loudly
	// rather than handing over prod's material.
	kr := sharedKeyring(t, db)
	sealer, err := kr.ForProject(t.Context(), string(scope.Org), string(scope.Project))
	if err != nil {
		t.Fatal(err)
	}
	row := valueRowID(t, db, string(dev.Env), "TOKEN")
	current := ciphertextOf(t, db, string(dev.Env), "TOKEN")
	aad := crypto.ValueAAD{
		OrgID: string(scope.Org), ProjectID: string(scope.Project),
		EnvID: string(prod.Env), KeyID: keyIDByName(t, keys, actor, scope, "TOKEN"),
		RowID: row, FieldTag: "value",
	}
	if _, err := sealer.OpenValue(aad, current); !errors.Is(err, crypto.ErrDecrypt) {
		t.Fatalf("a ciphertext opened under another environment's AAD: %v", err)
	}
}

// disclosureEvents counts the per-key disclosure rows one environment
// collected — the audit ADR forbids "revealed N secrets" as a single row, so
// the count being per key is the point.
func disclosureEvents(t *testing.T, db *store.DB, envID string) int64 {
	t.Helper()
	return auditEventCount(t, db, envID, "disclosure.value_revealed")
}

// auditEventCount counts one environment's tenant audit rows of a given type.
func auditEventCount(t *testing.T, db *store.DB, envID, eventType string) int64 {
	t.Helper()
	q := `SELECT COUNT(*) FROM audit_tenant_events WHERE type = $1 AND env_id = $2`
	var out int64
	var err error
	if db.Engine() == store.EnginePostgres {
		err = db.PG().QueryRow(t.Context(), q, eventType, envID).Scan(&out)
	} else {
		err = db.SQLiteRead().QueryRowContext(t.Context(),
			strings.NewReplacer("$1", "?", "$2", "?").Replace(q), eventType, envID).Scan(&out)
	}
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// corruptValueCiphertext replaces one cell's sealed envelope with bytes no
// sealer can open. It is the discriminator the clone-abort disclosure test needs:
// the audit trail is written in the clone's OWN transaction, so an aborted clone
// rolls its disclosure rows back and a row count cannot tell "never opened" from
// "opened, recorded, rolled back". A corrupted source secret CAN: the fixed
// preflight aborts without ever decrypting (so the abort still fires), while the
// buggy open-before-abort order hits ErrDecrypt first and fails with a fault, not
// the abort — so the scenario's abort assertions go red on the regression.
func corruptValueCiphertext(t *testing.T, db *store.DB, envID, keyID string) {
	t.Helper()
	q := `UPDATE value_entries SET ciphertext = $1 WHERE environment_id = $2 AND key_id = $3`
	garbage := []byte("corrupted-not-a-valid-envelope")
	var err error
	if db.Engine() == store.EnginePostgres {
		_, err = db.PG().Exec(t.Context(), q, garbage, envID, keyID)
	} else {
		_, err = db.SQLiteWrite().ExecContext(t.Context(),
			strings.NewReplacer("$1", "?", "$2", "?", "$3", "?").Replace(q), garbage, envID, keyID)
	}
	if err != nil {
		t.Fatal(err)
	}
}

func keyIDByName(t *testing.T, keys *service.Keys, actor service.Actor, scope domain.Scope, name string) string {
	t.Helper()
	list, _, err := keys.List(t.Context(), actor, scope)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range list {
		if key.Name == name {
			return key.ID
		}
	}
	t.Fatalf("no key named %q", name)
	return ""
}

// ciphertextOf reads a stored cell's ciphertext straight out of the table —
// the fixture privilege this package holds — so the assertions above are about
// bytes at rest rather than about what the service chose to return.
func ciphertextOf(t *testing.T, db *store.DB, envID, keyName string) []byte {
	t.Helper()
	var out []byte
	q := `SELECT v.ciphertext FROM value_entries v JOIN keys k ON k.id = v.key_id
	      WHERE v.environment_id = $1 AND k.name = $2`
	var err error
	if db.Engine() == store.EnginePostgres {
		err = db.PG().QueryRow(t.Context(), q, envID, keyName).Scan(&out)
	} else {
		err = db.SQLiteRead().QueryRowContext(t.Context(),
			strings.NewReplacer("$1", "?", "$2", "?").Replace(q), envID, keyName).Scan(&out)
	}
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func valueRowID(t *testing.T, db *store.DB, envID, keyName string) string {
	t.Helper()
	var out string
	q := `SELECT v.id FROM value_entries v JOIN keys k ON k.id = v.key_id
	      WHERE v.environment_id = $1 AND k.name = $2`
	var err error
	if db.Engine() == store.EnginePostgres {
		err = db.PG().QueryRow(t.Context(), q, envID, keyName).Scan(&out)
	} else {
		err = db.SQLiteRead().QueryRowContext(t.Context(),
			strings.NewReplacer("$1", "?", "$2", "?").Replace(q), envID, keyName).Scan(&out)
	}
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestMaskedIsAbsentFromSchemaAndAPI is mvp-boundary C2's negative clause:
// `masked` is absent from the schema, the API surface and the UI.
//
// It is asserted mechanically because a deleted state comes back by accident,
// not on purpose — as an enum member somebody adds "for completeness", or a
// nullable presence column whose NULL quietly becomes a third state. The two
// places it could re-enter and not be noticed are the stored schema and the
// wire contract, so both are scanned: the migration set for a column or CHECK
// naming it, and the OpenAPI document for it appearing anywhere except the
// two prose lines that say it does not exist.
func TestMaskedIsAbsentFromSchemaAndAPI(t *testing.T) {
	for _, dir := range []string{
		filepath.Join("..", "store", "migrations", "sqlite"),
		filepath.Join("..", "store", "migrations", "postgres"),
	} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			raw, err := os.ReadFile(filepath.Join(dir, entry.Name()))
			if err != nil {
				t.Fatal(err)
			}
			for _, line := range strings.Split(string(raw), "\n") {
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "--") {
					// Prose explaining that the state is gone is not the state.
					continue
				}
				if strings.Contains(strings.ToLower(trimmed), "masked") {
					t.Errorf("%s/%s: `masked` reached the stored schema: %s", dir, entry.Name(), trimmed)
				}
			}
		}
	}

	spec, err := os.ReadFile(filepath.Join("..", "..", "api", "openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for i, line := range strings.Split(string(spec), "\n") {
		lower := strings.ToLower(line)
		if !strings.Contains(lower, "masked") {
			continue
		}
		// The only admissible occurrences are the two descriptions that state
		// the flat model deleted it. Anything else — an enum member, a
		// property, a required field — is the state itself coming back.
		if strings.Contains(lower, "appears nowhere in this contract") ||
			strings.Contains(lower, "anywhere in this contract") {
			continue
		}
		t.Errorf("api/openapi.yaml:%d: `masked` reached the contract: %s", i+1, strings.TrimSpace(line))
	}
}
